/*
 * MIT License
 * Copyright (c) 2024 Keyhan Asadi
 */
package ghidrainfineon;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/** P-code injection for a C166 {@code [Rwm + #offset]} address. */
public class RegOffsetAddr extends InjectPayloadCallother {
	private static final long STACK_THRESHOLD = 0x200;
	private static final long R0_REGISTER_OFFSET = 0;

	private final SleighLanguage language;
	private final long uniqueBase;
	private final AddressSpace registerSpace;
	private final C166PagedAddressEmitter addressEmitter;

	public RegOffsetAddr(String name, SleighLanguage language, long uniqueBase) {
		super(name);
		this.language = language;
		this.uniqueBase = uniqueBase;
		registerSpace = language.getAddressFactory().getRegisterSpace();
		addressEmitter = new C166PagedAddressEmitter(language);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext context) {
		Address address = context.baseAddr;
		Varnode base = context.inputlist.get(0);
		long offset = context.inputlist.get(1).getOffset();
		Varnode output = context.output.get(0);
		long instructionUnique = uniqueBase +
			((address.getOffset() & 0xffffffL) >>> 1) * 32;

		if (!addressEmitter.hasOverride(program, address) && offset < STACK_THRESHOLD &&
			isStackPointer(base)) {
			return emitStack(address, base, offset, output, instructionUnique);
		}
		return addressEmitter.emit(program, address, base, offset, output, instructionUnique);
	}

	private boolean isStackPointer(Varnode register) {
		return register.getAddress().getAddressSpace().equals(registerSpace) &&
			register.getOffset() == R0_REGISTER_OFFSET && register.getSize() == 2;
	}

	private PcodeOp[] emitStack(Address address, Varnode base, long offset,
			Varnode output, long instructionUnique) {
		AddressSpace constantSpace = language.getAddressFactory().getConstantSpace();
		AddressSpace uniqueSpace = language.getAddressFactory().getUniqueSpace();
		Varnode offsetConstant = new Varnode(constantSpace.getAddress(offset), 2);
		Varnode sum = new Varnode(uniqueSpace.getAddress(instructionUnique), 2);
		return new PcodeOp[] {
			new PcodeOp(address, 0, PcodeOp.INT_ADD,
				new Varnode[] { base, offsetConstant }, sum),
			new PcodeOp(address, 1, PcodeOp.COPY, new Varnode[] { sum }, output)
		};
	}
}
