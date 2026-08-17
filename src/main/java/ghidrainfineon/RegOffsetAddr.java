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

import java.math.BigInteger;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.symbol.Symbol;
import ghidra.app.plugin.processors.sleigh.symbol.UseropSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.pcode.*;

/**
 * PCode injection for [rwm+#offset] address calculation.
 * 
 * If register is r0 (stack pointer) and offset < STACK_THRESHOLD: emit direct zext for stack analysis
 * Other accesses use the active EXTP/EXTS override or the selected DPP register.
 * 
 * This allows stack accesses to work cleanly while still supporting DPP paging for memory.
 */
public class RegOffsetAddr extends InjectPayloadCallother {
	private static final long STACK_THRESHOLD = 0x200; // Offsets below this are stack-like
	private static final long R0_REGISTER_OFFSET = 0;  // r0 is at offset 0 in register space
	
	private final SleighLanguage language;
	private final long uniqueBase;
	private int segmentUseropIndex = -1;
	private AddressSpace registerSpace;

	public RegOffsetAddr(String name, SleighLanguage language, long uniqueBase) {
		super(name);
		this.language = language;
		this.uniqueBase = uniqueBase;
		this.registerSpace = language.getAddressFactory().getRegisterSpace();
		
		// Find the "segment" userop index
		Symbol sym = language.getSymbolTable().findGlobalSymbol("segment");
		if (sym instanceof UseropSymbol) {
			segmentUseropIndex = ((UseropSymbol) sym).getIndex();
		}
	}
	
	/**
	 * Check if the varnode is the r0 register (stack pointer)
	 */
	private boolean isStackPointer(Varnode reg) {
		return reg.getAddress().getAddressSpace().equals(registerSpace) &&
		       reg.getOffset() == R0_REGISTER_OFFSET &&
		       reg.getSize() == 2;
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		Address currentAddr = con.baseAddr;
		Varnode regInput = con.inputlist.get(0);   // The register (e.g., r0 for stack)
		Varnode offsetInput = con.inputlist.get(1); // The immediate offset
		Varnode output = con.output.get(0);         // The 3-byte address result
		
		AddressSpace constSpace = language.getAddressFactory().getConstantSpace();
		AddressSpace uniqueSpace = language.getAddressFactory().getUniqueSpace();
		
		long offset = offsetInput.getOffset();

		// Use instruction address to create unique temp addresses
		long uniqueOffset = uniqueBase + ((currentAddr.getOffset() & 0xFFFFFF) >> 1) * 32;

		// EXTP / EXTS overrides take precedence over the stack-pointer
		// special case. With a segment override active in front of a
		// register-indirect access the target is memory-mapped hardware,
		// never the stack; without honouring the override the access
		// collapses to the low-memory image of the register and creates
		// phantom references near 0x000000.
		ProgramContext progCtx = program.getProgramContext();
		boolean extActive = isContextOne(progCtx, "ExtpEn", currentAddr)
				|| isContextOne(progCtx, "ExtsEn", currentAddr);

		if (!extActive && offset < STACK_THRESHOLD && isStackPointer(regInput)) {
			// Stack access with r0 and no segment override: emit direct
			// zext for stack analysis.
			return emitDirectStackAccess(currentAddr, regInput, offset, output,
					constSpace, uniqueSpace, uniqueOffset);
		}

		// All remaining cases — register-indirect with no offset, with
		// small offset on a non-stack register, or any larger offset, and
		// in particular every access with EXTP/EXTS active — go through
		// emitDppSegment, which already resolves EXTP first, then EXTS,
		// then the matching DPP, with a raw-offset fall-through when
		// none of those are known.
		return emitDppSegment(program, currentAddr, regInput, offset, output,
				constSpace, uniqueSpace, uniqueOffset);
	}

	private boolean isContextOne(ProgramContext progCtx, String regName, Address addr) {
		Register r = progCtx.getRegister(regName);
		if (r == null) return false;
		BigInteger v = progCtx.getValue(r, addr, false);
		return v != null && v.equals(BigInteger.ONE);
	}
	
	/**
	 * Emit direct stack access: output = r0 + offset
	 * No zext - just add and copy. This keeps the simple SP + offset pattern for stack analysis.
	 */
	private PcodeOp[] emitDirectStackAccess(Address addr, Varnode reg, long offset, Varnode output,
			AddressSpace constSpace, AddressSpace uniqueSpace, long uniqueOffset) {
		
		int seqnum = 0;
		PcodeOp[] ops = new PcodeOp[2];
		
		// 1. sum = r0 + offset (2-byte result)
		Varnode offsetConst = new Varnode(constSpace.getAddress(offset), 2);
		Varnode sum = new Varnode(uniqueSpace.getAddress(uniqueOffset), 2);
		ops[0] = new PcodeOp(addr, seqnum++, PcodeOp.INT_ADD, new Varnode[] { reg, offsetConst }, sum);
		
		// 2. output = copy(sum) - COPY from 2-byte to 3-byte implicitly zero-extends
		ops[1] = new PcodeOp(addr, seqnum++, PcodeOp.COPY, new Varnode[] { sum }, output);
		
		return ops;
	}
	
	/**
	 * Emit a paged-memory address calc for [rwm + #imm] when imm >= STACK_THRESHOLD.
	 *
	 * Resolution priority — same hierarchy as the C166 hardware:
	 *   1. EXTP active + page known   -> segment(Extp, reg + (offset & 0x3FFF))
	 *   2. EXTS active + segment known -> emit (Exts << 16) | (reg + offset)  (no segment(),
	 *                                     because the segment() pcodeop is page-shift only)
	 *   3. DPP[index of offset top bits] known -> segment(DPP, reg + (offset & 0x3FFF))
	 *   4. None known -> raw fallback: zext((reg + offset) & 0xFFFF) into the 3-byte address.
	 *
	 * The previous fallback `dppValue = dppIndex` produced phantom xrefs in the
	 * 0x0000..0xFFFF window because dppIndex is just the top two bits of offset
	 * (0..3) and segment(0..3, x) maps near zero, never to the binary's loaded
	 * pages. The raw fallback at least keeps the encoded address in sync with
	 * what the disassembly listing renders.
	 */
	private PcodeOp[] emitDppSegment(Program program, Address addr, Varnode reg, long offset,
			Varnode output, AddressSpace constSpace, AddressSpace uniqueSpace, long uniqueOffset) {

		ProgramContext progCtx = program.getProgramContext();

		// 1. EXTP override (page-shift = 14)
		Long extpEnVal = readContext(progCtx, "ExtpEn", addr);
		if (extpEnVal != null && extpEnVal == 1L) {
			EffectiveExt extp = readEffectiveExt(program, addr, "Extp", "ExtpReg", "ExtpRegMode");
			if (extp != null) {
				if (extp.isImmediate()) {
					return emitPagedSegment(addr, reg, offset & 0x3FFF, extp.immValue & 0x3FFL,
							output, constSpace, uniqueSpace, uniqueOffset);
				}
				// Keep PAGE and OFFSET as separate arithmetic values.  A segmentop
				// can lose the PAGE after an analyzer-owned stale pointer is split
				// back into its two ABI words.
				return emitShiftViaReg(addr, reg, offset & 0x3ffFL,
					extp.gpRegister, 14,
						output, constSpace, uniqueSpace, uniqueOffset);
			}
			return emitRawFallback(addr, reg, offset, output, constSpace, uniqueSpace, uniqueOffset);
		}

		// 2. EXTS override (segment shift = 16 bits, full offset preserved)
		Long extsEnVal = readContext(progCtx, "ExtsEn", addr);
		if (extsEnVal != null && extsEnVal == 1L) {
			EffectiveExt exts = readEffectiveExt(program, addr, "Exts", "ExtsReg", "ExtsRegMode");
			if (exts != null) {
				if (exts.isImmediate()) {
					return emitSegmentShift16(addr, reg, offset & 0xFFFFL, exts.immValue & 0xFFL,
							output, constSpace, uniqueSpace, uniqueOffset);
				}
				return emitShiftViaReg(addr, reg, offset & 0xFFFFL, exts.gpRegister, 16,
						output, constSpace, uniqueSpace, uniqueOffset);
			}
			return emitRawFallback(addr, reg, offset, output, constSpace, uniqueSpace, uniqueOffset);
		}

		// 3. DPP-paged (default)
		int dppIndex = (int) ((offset >> 14) & 3);
		Long dppValue = getDppValue(program, addr, dppIndex);
		if (dppValue != null) {
			return emitPagedSegment(addr, reg, offset & 0x3FFF, dppValue,
					output, constSpace, uniqueSpace, uniqueOffset);
		}
		Register dppRegister = program.getRegister("DPP" + dppIndex);
		if (dppRegister != null) {
			if (segmentUseropIndex < 0) {
				return emitRawFallback(addr, reg, offset, output, constSpace, uniqueSpace,
					uniqueOffset);
			}
			return emitRuntimePagedSegment(addr, reg, offset & 0x3fffL, dppRegister,
				output, constSpace, uniqueSpace, uniqueOffset);
		}

		// 4. The language unexpectedly has no matching architectural DPP register.
		return emitRawFallback(addr, reg, offset, output, constSpace, uniqueSpace, uniqueOffset);
	}

	private PcodeOp[] emitRuntimePagedSegment(Address address, Varnode register, long offset,
			Register pageRegister, Varnode output,
			AddressSpace constantSpace, AddressSpace uniqueSpace, long uniqueOffset) {
		Varnode offsetConstant = new Varnode(constantSpace.getAddress(offset), 2);
		Varnode sum = new Varnode(uniqueSpace.getAddress(uniqueOffset), 2);
		Varnode mask = new Varnode(constantSpace.getAddress(0x3fff), 2);
		Varnode inner = new Varnode(uniqueSpace.getAddress(uniqueOffset + 4), 2);
		Varnode page = new Varnode(pageRegister.getAddress(), pageRegister.getMinimumByteSize());
		Varnode userop = new Varnode(constantSpace.getAddress(segmentUseropIndex), 4);
		return new PcodeOp[] {
			new PcodeOp(address, 0, PcodeOp.INT_ADD,
				new Varnode[] { register, offsetConstant }, sum),
			new PcodeOp(address, 1, PcodeOp.INT_AND,
				new Varnode[] { sum, mask }, inner),
			new PcodeOp(address, 2, PcodeOp.CALLOTHER,
				new Varnode[] { userop, page, inner }, output)
		};
	}

	/**
	 * Emit `output = (page << 14) + zext((reg + maskedOffset) & 0x3fff)` for
	 * paged access.
	 *
	 * The earlier implementation emitted `segment(page, reg + maskedOffset)`,
	 * which the segment() pcodeop unfolds as `(page << 14) | sum`. The
	 * decompiler can't reduce a bitwise OR across an arithmetic sum, so
	 * accesses like `*(page * 0x4000 + base + index)` rendered with the raw
	 * 16-bit base offset (e.g. `*(byte *)(uVar3 * 10 + 0x30AC)` instead of
	 * `handle_table[uVar3]`).
	 *
	 * Switching to plain INT_ADD with a constant page contribution lets the
	 * decompiler fold the constant page+base into a single resolvable
	 * address, recovering symbol references.
	 *
	 * EXTP and DPP addressing always discard address bits 15..14 after the
	 * 16-bit register addition.  Keeping the mask in p-code is required even
	 * for unusual hand-written code and exactly follows the C166 manual.
	 */
	private PcodeOp[] emitPagedSegment(Address addr, Varnode reg, long maskedOffset, long page,
			Varnode output, AddressSpace constSpace, AddressSpace uniqueSpace, long uniqueOffset) {
		int seqnum = 0;
		PcodeOp[] ops = new PcodeOp[4];

		Varnode offsetConst = new Varnode(constSpace.getAddress(maskedOffset & 0x3fffL), 2);
		Varnode sum = new Varnode(uniqueSpace.getAddress(uniqueOffset), 2);
		ops[0] = new PcodeOp(addr, seqnum++, PcodeOp.INT_ADD,
			new Varnode[] { reg, offsetConst }, sum);

		Varnode pageMask = new Varnode(constSpace.getAddress(0x3fff), 2);
		Varnode inner = new Varnode(uniqueSpace.getAddress(uniqueOffset + 4), 2);
		ops[1] = new PcodeOp(addr, seqnum++, PcodeOp.INT_AND,
			new Varnode[] { sum, pageMask }, inner);

		Varnode zinner = new Varnode(uniqueSpace.getAddress(uniqueOffset + 8), 3);
		ops[2] = new PcodeOp(addr, seqnum++, PcodeOp.INT_ZEXT,
			new Varnode[] { inner }, zinner);

		Varnode pageBase =
			new Varnode(constSpace.getAddress((page & 0x3ffL) << 14), 3);
		ops[3] = new PcodeOp(addr, seqnum++, PcodeOp.INT_ADD,
			new Varnode[] { zinner, pageBase }, output);

		return ops;
	}

	/**
	 * Emit `output = (segment << 16) + zext(reg + offset)` for EXTS-overridden
	 * access. Same arithmetic-vs-bitwise tradeoff as emitPagedSegment — the
	 * 16-bit register+offset never overflows into the segment bits in valid
	 * compiler-generated code (segment crossing requires explicit handling).
	 * Using INT_ADD instead of INT_OR keeps the address foldable for the
	 * decompiler so symbol references survive.
	 */
	private PcodeOp[] emitSegmentShift16(Address addr, Varnode reg, long offset, long segment,
			Varnode output, AddressSpace constSpace, AddressSpace uniqueSpace, long uniqueOffset) {
		int seqnum = 0;
		PcodeOp[] ops = new PcodeOp[3];

		// 1. sum:2 = reg + offset
		Varnode offsetConst = new Varnode(constSpace.getAddress(offset), 2);
		Varnode sum = new Varnode(uniqueSpace.getAddress(uniqueOffset), 2);
		ops[0] = new PcodeOp(addr, seqnum++, PcodeOp.INT_ADD,
				new Varnode[] { reg, offsetConst }, sum);

		// 2. zsum:3 = zext(sum)
		Varnode zsum = new Varnode(uniqueSpace.getAddress(uniqueOffset + 4), 3);
		ops[1] = new PcodeOp(addr, seqnum++, PcodeOp.INT_ZEXT, new Varnode[] { sum }, zsum);

		// 3. output:3 = zsum + (segment << 16)
		Varnode segConst = new Varnode(constSpace.getAddress((segment & 0xFFL) << 16), 3);
		ops[2] = new PcodeOp(addr, seqnum++, PcodeOp.INT_ADD,
				new Varnode[] { zsum, segConst }, output);

		return ops;
	}

	/**
	 * Emit `output = (zext(gpReg) << shiftAmount) +
	 * zext((reg + maskedOffset) & addressMask)`
	 * for register-mode EXTP (shift = 14) and EXTS (shift = 16).
	 *
	 * The segment/page value lives in `gpReg` at runtime, not in the
	 * ProgramContext, so it can't be folded into a constant at pcode-gen
	 * time. Emitting the GP register as a varnode lets the symbolic
	 * propagator resolve it during analysis: when the immediately
	 * preceding `mov gpReg,#imm` is constant-propagated, the address
	 * collapses to a concrete 24-bit target and a real reference is
	 * created (e.g. for `mov r5,#0x14; exts r5,#1; mov r5,[r4]` the
	 * target becomes 0x14_0000 + r4).
	 *
	 * EXTP uses a 14-bit inner-address mask; EXTS preserves all 16 bits.
	 */
	private PcodeOp[] emitShiftViaReg(Address addr, Varnode reg, long maskedOffset,
			Register gpReg, int shiftAmount,
			Varnode output, AddressSpace constSpace, AddressSpace uniqueSpace, long uniqueOffset) {
		int seqnum = 0;
		PcodeOp[] ops = new PcodeOp[6];

		Varnode gpVarnode = new Varnode(gpReg.getAddress(), gpReg.getMinimumByteSize());

		// 1. sum:2 = reg + maskedOffset
		Varnode offsetConst = new Varnode(constSpace.getAddress(maskedOffset), 2);
		Varnode sum = new Varnode(uniqueSpace.getAddress(uniqueOffset), 2);
		ops[0] = new PcodeOp(addr, seqnum++, PcodeOp.INT_ADD,
				new Varnode[] { reg, offsetConst }, sum);

		// 2. inner:2 = sum & (EXTP ? 0x3fff : 0xffff)
		long addressMask = shiftAmount == 14 ? 0x3fffL : 0xffffL;
		Varnode mask = new Varnode(constSpace.getAddress(addressMask), 2);
		Varnode inner = new Varnode(uniqueSpace.getAddress(uniqueOffset + 4), 2);
		ops[1] = new PcodeOp(addr, seqnum++, PcodeOp.INT_AND,
				new Varnode[] { sum, mask }, inner);

		// 3. zsum:3 = zext(inner)
		Varnode zsum = new Varnode(uniqueSpace.getAddress(uniqueOffset + 8), 3);
		ops[2] = new PcodeOp(addr, seqnum++, PcodeOp.INT_ZEXT,
				new Varnode[] { inner }, zsum);

		// 4. zgpReg:3 = zext(gpReg)
		Varnode zgpReg = new Varnode(uniqueSpace.getAddress(uniqueOffset + 12), 3);
		ops[3] = new PcodeOp(addr, seqnum++, PcodeOp.INT_ZEXT,
				new Varnode[] { gpVarnode }, zgpReg);

		// 5. shifted:3 = zgpReg << shiftAmount
		Varnode shiftConst = new Varnode(constSpace.getAddress(shiftAmount), 4);
		Varnode shifted = new Varnode(uniqueSpace.getAddress(uniqueOffset + 16), 3);
		ops[4] = new PcodeOp(addr, seqnum++, PcodeOp.INT_LEFT,
				new Varnode[] { zgpReg, shiftConst }, shifted);

		// 6. output:3 = zsum + shifted
		ops[5] = new PcodeOp(addr, seqnum++, PcodeOp.INT_ADD,
				new Varnode[] { zsum, shifted }, output);

		return ops;
	}

	/**
	 * Fallback when no DPP/EXTP/EXTS context is available: emit
	 * `output = zext((reg + offset) & 0xFFFF)`. Reference target then
	 * matches the disassembly operand and avoids creating phantom xrefs
	 * in the 0x0000..0xFFFF window.
	 */
	private PcodeOp[] emitRawFallback(Address addr, Varnode reg, long offset, Varnode output,
			AddressSpace constSpace, AddressSpace uniqueSpace, long uniqueOffset) {
		int seqnum = 0;
		PcodeOp[] ops = new PcodeOp[2];

		Varnode offsetConst = new Varnode(constSpace.getAddress(offset & 0xFFFFL), 2);
		Varnode sum = new Varnode(uniqueSpace.getAddress(uniqueOffset), 2);
		ops[0] = new PcodeOp(addr, seqnum++, PcodeOp.INT_ADD,
				new Varnode[] { reg, offsetConst }, sum);

		ops[1] = new PcodeOp(addr, seqnum++, PcodeOp.INT_ZEXT, new Varnode[] { sum }, output);
		return ops;
	}

	private Long readContext(ProgramContext progCtx, String regName, Address addr) {
		Register r = progCtx.getRegister(regName);
		if (r == null) return null;
		BigInteger v = progCtx.getValue(r, addr, false);
		return v == null ? null : v.longValue();
	}

	/**
	 * Resolved EXTP/EXTS at a given instruction. Either the immediate value
	 * (encoded directly in the EXTP/EXTS instruction) or the GP register that
	 * carries the segment/page at runtime (register-mode: `extp Rwm,#irang2`).
	 *
	 * Register-mode cannot be reduced to a single value at pcode-generation
	 * time because GP register contents do not live in the ProgramContext —
	 * they're propagated by the analyzer/decompiler at analysis time. The
	 * register reference is therefore preserved and emitted into the pcode
	 * so the symbolic propagator resolves it later.
	 */
	private static class EffectiveExt {
		final Long immValue;
		final Register gpRegister;

		private EffectiveExt(Long immValue, Register gpRegister) {
			this.immValue = immValue;
			this.gpRegister = gpRegister;
		}

		static EffectiveExt immediate(long value) {
			return new EffectiveExt(value, null);
		}

		static EffectiveExt registerMode(Register gpReg) {
			return new EffectiveExt(null, gpReg);
		}

		boolean isImmediate() {
			return immValue != null;
		}
	}

	/**
	 * Resolve EXTP/EXTS at addr.
	 *
	 * The disambiguation between register-mode and immediate-mode comes from
	 * the dedicated 1-bit context register (ExtpRegMode / ExtsRegMode).
	 * The earlier sentinel-based scheme (regIdx == 0xF -> immediate) collided
	 * with the legitimate register index for r15: any `extp r15,#1` was
	 * silently treated as immediate-mode and the register-mode pcode never
	 * fired, leaving phantom refs at the un-paged 16-bit offset.
	 */
	private EffectiveExt readEffectiveExt(Program program, Address addr,
			String immRegName, String regIdxName, String regModeName) {
		ProgramContext progCtx = program.getProgramContext();

		Register regModeReg = progCtx.getRegister(regModeName);
		if (regModeReg != null) {
			BigInteger regMode = progCtx.getValue(regModeReg, addr, false);
			if (regMode != null && regMode.equals(BigInteger.ONE)) {
				Register regIdxReg = progCtx.getRegister(regIdxName);
				if (regIdxReg != null) {
					BigInteger regIdx = progCtx.getValue(regIdxReg, addr, false);
					if (regIdx != null) {
						int idx = regIdx.intValue() & 0xF;
						Register gpReg = program.getRegister("r" + idx);
						if (gpReg != null) {
							return EffectiveExt.registerMode(gpReg);
						}
					}
				}
				return null;
			}
		}

		Register immReg = progCtx.getRegister(immRegName);
		if (immReg == null) return null;
		BigInteger v = progCtx.getValue(immReg, addr, false);
		return v == null ? null : EffectiveExt.immediate(v.longValue());
	}

	/**
	 * Get the DPP register value for the given index
	 */
	private Long getDppValue(Program program, Address context, int dppIndex) {
		try {
			Register dppReg = program.getRegister("DPP" + dppIndex);
			if (dppReg != null) {
				BigInteger value = program.getProgramContext().getValue(dppReg, context, false);
				if (value != null) {
					return value.longValue() & 0x3FFL;
				}
			}
		} catch (Exception e) {
			// Fall through
		}
		return null;
	}
}
