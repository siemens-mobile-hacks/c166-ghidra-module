package ghidrainfineon;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Function;

/** Shared cheap guards for C166 analysis worklists. */
final class C166AnalysisFunctions {
	private static final long CODE_SEGMENT_SIZE = 0x10000L;

	private C166AnalysisFunctions() {
	}

	/**
	 * Reject a database artifact which claims a whole C166 code segment while its
	 * entry lies in the middle of that range.  Such bodies are not recoverable
	 * routines: walking or decompiling them treats unrelated code and data as one
	 * function and can consume a decompiler timeout in every inference phase.
	 */
	static boolean hasUsableBody(Function function) {
		if (function == null || function.isExternal()) {
			return false;
		}
		AddressSetView body = function.getBody();
		if (body.isEmpty() || !body.contains(function.getEntryPoint())) {
			return false;
		}
		long span = body.getMaxAddress().getOffset() - body.getMinAddress().getOffset() + 1;
		if (span >= CODE_SEGMENT_SIZE &&
			!function.getEntryPoint().equals(body.getMinAddress())) {
			return false;
		}

		/*
		 * A function body must include the fall-through successor of every terminal
		 * address range.  Database artifacts created over data commonly end on an
		 * ordinary instruction and leave that successor outside the body.  Sending
		 * such a truncated body to the decompiler makes it repeatedly decode one byte
		 * beyond the body (or wait for the full timeout).  Inspecting only range ends
		 * keeps this guard proportional to the number of body fragments, not to the
		 * number of instructions in a full-program analysis.
		 */
		AddressRangeIterator ranges = body.getAddressRanges();
		while (ranges.hasNext()) {
			AddressRange range = ranges.next();
			Instruction terminal = function.getProgram().getListing()
				.getInstructionContaining(range.getMaxAddress());
			if (terminal == null) {
				return false;
			}
			var fallThrough = terminal.getFallThrough();
			if (fallThrough != null && !body.contains(fallThrough)) {
				return false;
			}
		}
		return true;
	}
}
