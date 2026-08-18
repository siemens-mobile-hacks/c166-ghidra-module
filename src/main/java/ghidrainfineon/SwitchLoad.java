/*
 * MIT License
 * Copyright (c) 2024 Keyhan Asadi
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 */
package ghidrainfineon;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;

/**
 * PCode injection for switch table loads.
 * 
 * Pattern: mov rX, [rX] followed by jmpi [rX]
 * 
 * When followed by jmpi, emits segment(dpp, ptr) for the load address so the
 * decompiler can properly resolve switch table entries.
 * 
 * When NOT followed by jmpi, falls back to a normal load.
 */
public class SwitchLoad extends InjectPayloadCallother {
	private final SleighLanguage language;
	private final long uniqueBase;
	private final C166PagedAddressEmitter addressEmitter;

	public SwitchLoad(String name, SleighLanguage language, long uniqueBase) {
		super(name);
		this.language = language;
		this.uniqueBase = uniqueBase;
		addressEmitter = new C166PagedAddressEmitter(language);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		Address currentAddr = con.baseAddr;
		Varnode ptrInput = con.inputlist.get(0);  // The register (pointer to table entry)
		Varnode output = con.output.get(0);        // The loaded value
		
		AddressSpace ramSpace = language.getDefaultSpace();
		AddressSpace constSpace = language.getAddressFactory().getConstantSpace();

		// Check if next instruction is jmpi
		boolean isSwitch = isFollowedByJmpi(program, currentAddr);

		if (isSwitch) {
			Integer dppIndex = getDppIndexForPointer(program, currentAddr, ptrInput);
			if (dppIndex == null && !addressEmitter.hasOverride(program, currentAddr)) {
				return emitRawLoad(currentAddr, ptrInput, output, ramSpace, constSpace);
			}

			// Use full 24-bit instruction address to create unique temp addresses
			// Shift right by 1 (instructions are 2-byte aligned) to compress range
			// Then multiply by 8 (enough for multiple varnodes) to avoid overlap
			long uniqueOffset = uniqueBase + ((currentAddr.getOffset() & 0xFFFFFF) >> 1) * 8;
			Varnode addrTemp = new Varnode(
				language.getAddressFactory().getUniqueSpace().getAddress(uniqueOffset + 0x40), 3);
			PcodeOp[] addressOps = addressEmitter.emitIndirect(program, currentAddr,
				ptrInput, dppIndex == null ? 0 : dppIndex, addrTemp, uniqueOffset);
			PcodeOp[] ops = new PcodeOp[addressOps.length + 1];
			System.arraycopy(addressOps, 0, ops, 0, addressOps.length);
			Varnode spaceId = new Varnode(constSpace.getAddress(ramSpace.getSpaceID()), 4);
			ops[addressOps.length] = new PcodeOp(currentAddr, addressOps.length,
				PcodeOp.LOAD, new Varnode[] { spaceId, addrTemp }, output);
			return ops;
		}

		return emitRawLoad(currentAddr, ptrInput, output, ramSpace, constSpace);
	}

	private PcodeOp[] emitRawLoad(Address addr, Varnode ptr, Varnode output,
			AddressSpace ramSpace, AddressSpace constSpace) {
		Varnode spaceId = new Varnode(constSpace.getAddress(ramSpace.getSpaceID()), 4);
		return new PcodeOp[] {
			new PcodeOp(addr, 0, PcodeOp.LOAD, new Varnode[] { spaceId, ptr }, output)
		};
	}

	/**
	 * Check if the next instruction is jmpi
	 */
	private boolean isFollowedByJmpi(Program program, Address currentAddr) {
		try {
			Instruction currentInstr = program.getListing().getInstructionAt(currentAddr);
			if (currentInstr == null) {
				return false;
			}
			
			Instruction nextInstr = currentInstr.getNext();
			if (nextInstr == null) {
				return false;
			}
			
			String mnemonic = nextInstr.getMnemonicString();
			return "jmpi".equalsIgnoreCase(mnemonic);
		} catch (Exception e) {
			return false;
		}
	}
	
	/**
	 * Get the DPP value for the given pointer register when no EXTP/EXTS
	 * override is active. Uses the upper two bits of the table offset to select
	 * DPP0..DPP3.
	 */
	private Integer getDppIndexForPointer(Program program, Address context,
			Varnode ptrInput) {
		// For switch tables, we need to determine which DPP based on the pointer value
		// The pointer typically comes from: add rX, #tableBase
		// We look back to find the table base and determine DPP from that
		
		try {
			Instruction currentInstr = program.getListing().getInstructionAt(context);
			if (currentInstr == null) {
				return null;
			}
			
			// Look back for the ADD instruction that set up the table pointer
			Instruction prev = currentInstr.getPrevious();
			for (int i = 0; i < 10 && prev != null; i++) {
				String mnemonic = prev.getMnemonicString().toLowerCase();
				if (mnemonic.equals("add") && writes(prev, ptrInput)) {
					// Try to get the immediate value (table base)
					for (int opIdx = 0; opIdx < prev.getNumOperands(); opIdx++) {
						if ((prev.getOperandType(opIdx) & OperandType.SCALAR) != 0) {
							Scalar scalar = operandScalar(prev, opIdx);
							if (scalar != null) {
								long tableBase = scalar.getUnsignedValue();
								return (int) ((tableBase >> 14) & 3);
							}
						}
					}
				}
				prev = prev.getPrevious();
			}
		} catch (Exception e) {
			// Fall through to default
		}
		
		return null;
	}

	private boolean writes(Instruction instruction, Varnode registerVarnode) {
		for (Object result : instruction.getResultObjects()) {
			if (result instanceof Register register &&
				register.getAddress().equals(registerVarnode.getAddress())) {
				return true;
			}
		}
		return false;
	}

	private Scalar operandScalar(Instruction instruction, int operandIndex) {
		Scalar scalar = instruction.getScalar(operandIndex);
		if (scalar != null) {
			return scalar;
		}
		for (Object object : instruction.getOpObjects(operandIndex)) {
			if (object instanceof Scalar operand) {
				return operand;
			}
		}
		return null;
	}
}
