// Deterministic headless work-count regressions for the unified analyzer.
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidrainfineon.C166TaskingTypeInferenceAnalyzer;

public class C166TypeInferencePerformanceTest extends GhidraScript {

	private long nextAddress = 0x400000;

	@Override
	protected void run() throws Exception {
		for (int index = 0; index < 256; index++) {
			Function ordinary = fixture("full_scan_non_candidate_" + index,
				bytes(0xdb, 0x00));
			lockVoidSignature(ordinary);
		}
		fixture("full_scan_single_far_candidate",
			bytes(0xdc, 0x4d, 0xa8, 0x4c, 0xdb, 0x00));
		malformedSegmentSpanningFunction();
		truncatedFallThroughFunction();

		C166TaskingTypeInferenceAnalyzer analyzer =
			new C166TaskingTypeInferenceAnalyzer();
		long firstStart = System.nanoTime();
		check(analyzer.added(currentProgram, currentProgram.getMemory(), monitor,
			new MessageLog()), "first full worklist analysis failed");
		long firstMillis = (System.nanoTime() - firstStart) / 1_000_000;
		C166TaskingTypeInferenceAnalyzer.RunStatistics first =
			analyzer.getLastRunStatistics();
		C166TaskingTypeInferenceAnalyzer.EvidenceStatistics firstEvidence =
			analyzer.getLastEvidenceStatistics();
		List<C166TaskingTypeInferenceAnalyzer.PhaseTiming> firstTimings =
			analyzer.getLastPhaseTimings();
		check(first.fullScan() && first.initialFunctions() == 259,
			"full scan did not retain the complete cheap listing scope: " + first);
		check(first.processedFunctions() == 259 && first.convergenceRounds() == 1 &&
			first.converged(), "full worklist did not converge in one round: " + first);
		check(first.heavyDecompilations() <= 6,
			"non-candidates triggered heavy decompilation: " + first);
		check(firstEvidence.functions() == 259 &&
			firstEvidence.usableFunctions() > 0 &&
			firstEvidence.usableFunctions() <= firstEvidence.functions() &&
			firstEvidence.instructions() >= 256,
			"shared evidence index did not cover the full cheap scope: " + firstEvidence);
		check(firstTimings.size() >= 10 && firstTimings.stream().allMatch(
			C166TaskingTypeInferenceAnalyzer.PhaseTiming::success),
			"phase timing ledger is incomplete or contains a failed phase: " + firstTimings);

		long secondStart = System.nanoTime();
		check(analyzer.added(currentProgram, currentProgram.getMemory(), monitor,
			new MessageLog()), "idempotent full worklist analysis failed");
		long secondMillis = (System.nanoTime() - secondStart) / 1_000_000;
		C166TaskingTypeInferenceAnalyzer.RunStatistics second =
			analyzer.getLastRunStatistics();
		check(second.convergenceRounds() == 1 && second.signatureChanges() == 0 &&
			second.converged(), "idempotent full scan did not settle immediately: " + second);
		check(second.heavyDecompilations() <= 3,
			"idempotent full scan repeated unrelated decompilation: " + second);

		println("TASKING type-inference performance work counts passed: first=" +
			firstMillis + " ms " + first + ", second=" + secondMillis + " ms " + second + ".");
	}

	private Function fixture(String name, byte[] code) throws Exception {
		Address entry = toAddr(nextAddress);
		nextAddress += 0x20;
		MemoryBlock block = createMemoryBlock(name + "_bytes", entry, code, false);
		block.setExecute(true);
		check(disassemble(entry), "failed to disassemble " + name);
		Function function = createFunction(entry, name);
		check(function != null, "failed to create " + name);
		return function;
	}

	private void malformedSegmentSpanningFunction() throws Exception {
		Address early = toAddr(0x500000);
		Address entry = toAddr(0x508000);
		Address late = toAddr(0x50fffe);
		MemoryBlock earlyBlock = createMemoryBlock("malformed_body_early", early,
			bytes(0xdb, 0x00), false);
		MemoryBlock entryBlock = createMemoryBlock("malformed_body_entry", entry,
			bytes(0xdc, 0x4d, 0xa8, 0x4c, 0xdb, 0x00), false);
		MemoryBlock lateBlock = createMemoryBlock("malformed_body_late", late,
			bytes(0xdb, 0x00), false);
		earlyBlock.setExecute(true);
		entryBlock.setExecute(true);
		lateBlock.setExecute(true);
		check(disassemble(early) && disassemble(entry) && disassemble(late),
			"failed to disassemble malformed body fixture");
		Function malformed = createFunction(entry, "segment_spanning_sparse_body");
		check(malformed != null, "failed to create malformed body fixture");
		AddressSet body = new AddressSet();
		body.addRange(early, early.add(1));
		body.addRange(entry, entry.add(5));
		body.addRange(late, late.add(1));
		malformed.setBody(body);
		check(malformed.getBody().getMaxAddress().getOffset() -
			malformed.getBody().getMinAddress().getOffset() + 1 == 0x10000,
			"malformed fixture does not span one C166 code segment");
	}

	private void truncatedFallThroughFunction() throws Exception {
		Address entry = toAddr(0x510000);
		byte[] code = bytes(0xdc, 0x4d, 0xa8, 0x4c);
		MemoryBlock block = createMemoryBlock("truncated_fallthrough_body", entry,
			code, false);
		block.setExecute(true);
		check(disassemble(entry), "failed to disassemble truncated body fixture");
		Function truncated = createFunction(entry, "truncated_fallthrough_function");
		check(truncated != null, "failed to create truncated body fixture");
		truncated.setBody(new AddressSet(entry, entry.add(code.length - 1)));
	}

	private void lockVoidSignature(Function function) throws Exception {
		function.updateFunction("__tasking_c166_classic", null, List.of(),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
		function.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
	}

	private byte[] bytes(int... values) {
		byte[] result = new byte[values.length];
		for (int index = 0; index < values.length; index++) {
			result[index] = (byte) values[index];
		}
		return result;
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
