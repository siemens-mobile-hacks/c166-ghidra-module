/*
 * MIT License
 * Copyright (c) 2024 Keyhan Asadi
 */
package ghidrainfineon;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;

/** P-code injection for a direct 16-bit C166 memory operand. */
public class GetPagedOffset extends InjectPayloadCallother {
	private final long uniqueBase;
	private final C166PagedAddressEmitter addressEmitter;

	public GetPagedOffset(String name, SleighLanguage language, long uniqueBase) {
		super(name);
		this.uniqueBase = uniqueBase;
		addressEmitter = new C166PagedAddressEmitter(language);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext context) {
		return addressEmitter.emit(program, context.baseAddr, null,
			context.inputlist.getFirst().getOffset(), context.output.getFirst(), uniqueBase);
	}
}
