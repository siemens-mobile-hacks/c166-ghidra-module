// Headless regression test; run via tools/test-tasking-abi.sh.
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidrainfineon.C166CallTargetAnalyzer;
import ghidrainfineon.C166FarPointerPhase;
import ghidrainfineon.C166TaskingTypeInferenceAnalyzer;

public class C166IncrementalAnalysisTest extends GhidraScript {

	private long nextAddress = 0x100000;

	@Override
	protected void run() throws Exception {
		Address seedTarget = rawCode("incremental_seed_target", pagedRead(13, 12));
		Function seedCaller = fixture("incremental_seed_caller", calls(seedTarget));
		Address oldTarget = rawCode("incremental_old_target", pagedRead(13, 12));
		Function oldCaller = fixture("incremental_old_caller", calls(oldTarget));
		check(getFunctionAt(seedTarget) == null, "seed target unexpectedly has a function");
		check(getFunctionAt(oldTarget) == null, "old target unexpectedly has a function");

		C166CallTargetAnalyzer callGraph = new C166CallTargetAnalyzer();
		check(callGraph.added(currentProgram, seedCaller.getBody(), monitor, new MessageLog()),
			"incremental call-graph analysis failed");
		check(getFunctionAt(seedTarget) != null,
			"incremental call-graph analysis missed changed target");
		check(getFunctionAt(oldTarget) == null,
			"incremental call-graph analysis scanned unrelated old code");

		callGraph.analysisEnded(currentProgram);
		check(callGraph.added(currentProgram, currentProgram.getMemory(), monitor,
			new MessageLog()), "full call-graph One Shot failed");
		check(getFunctionAt(oldTarget) != null,
			"full call-graph One Shot did not scan the whole program");
		deleteCallReferences(seedCaller.getEntryPoint());
		check(!hasCallReference(seedCaller.getEntryPoint(), seedTarget),
			"failed to clear direct call xref fixture");
		callGraph.analysisEnded(currentProgram);
		check(callGraph.added(currentProgram, currentProgram.getMemory(), monitor,
			new MessageLog()), "full call-graph xref recovery failed");
		check(hasCallReference(seedCaller.getEntryPoint(), seedTarget),
			"full call-graph scan did not recover a deleted direct call xref");

		Function changedFar = fixture("incremental_changed_far", pagedRead(13, 12));
		Function oldFar = fixture("incremental_old_far", pagedRead(13, 12));
		C166FarPointerPhase farPointers = new C166FarPointerPhase();
		check(farPointers.added(currentProgram, changedFar.getBody(), monitor,
			new MessageLog()), "incremental far-pointer analysis failed");
		check(changedFar.getParameterCount() == 1,
			"incremental far-pointer analysis missed changed function");
		check(oldFar.getParameterCount() == 0,
			"incremental far-pointer analysis touched unrelated old function");

		check(farPointers.added(currentProgram, currentProgram.getMemory(), monitor,
			new MessageLog()), "full far-pointer One Shot failed");
		check(oldFar.getParameterCount() == 1,
			"full far-pointer One Shot did not scan the whole program");

		Function[] fanoutTargets = new Function[32];
		byte[][] fanoutCalls = new byte[fanoutTargets.length + 1][];
		for (int index = 0; index < fanoutTargets.length; index++) {
			fanoutTargets[index] = fixture("incremental_fanout_target_" + index,
				bytes(0xdb, 0x00));
			lockVoidSignature(fanoutTargets[index]);
			fanoutCalls[index] = calls(fanoutTargets[index].getEntryPoint());
		}
		fanoutCalls[fanoutTargets.length] = bytes(0xdb, 0x00);
		Function fanoutRoot = fixture("incremental_fanout_root", concat(fanoutCalls));
		lockVoidSignature(fanoutRoot);
		C166TaskingTypeInferenceAnalyzer pipeline =
			new C166TaskingTypeInferenceAnalyzer();
		check(pipeline.added(currentProgram, fanoutRoot.getBody(), monitor,
			new MessageLog()), "incremental pipeline fan-out analysis failed");
		C166TaskingTypeInferenceAnalyzer.RunStatistics statistics =
			pipeline.getLastRunStatistics();
		check(statistics.initialFunctions() == 1,
			"incremental pipeline widened the initial scope: " + statistics);
		check(statistics.processedFunctions() == 1,
			"unchanged root pulled unrelated callees into the worklist: " + statistics);
		check(statistics.convergenceRounds() == 1 && statistics.converged(),
			"unchanged incremental pipeline did not converge in one round: " + statistics);
		check(statistics.heavyDecompilations() == 0,
			"unchanged fan-out root triggered heavy decompilation: " + statistics);

		println("C166 incremental/full analysis scope tests passed.");
	}

	private void lockVoidSignature(Function function) throws Exception {
		function.updateFunction("__tasking_c166_classic", null, List.of(),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
		function.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
	}

	private Function fixture(String name, byte[] code) throws Exception {
		Address entry = toAddr(nextAddress);
		nextAddress += 0x100;
		MemoryBlock block = createMemoryBlock(name + "_bytes", entry, code, false);
		block.setExecute(true);
		check(disassemble(entry), "failed to disassemble " + name);
		Function function = createFunction(entry, name);
		check(function != null, "failed to create " + name);
		return function;
	}

	private Address rawCode(String name, byte[] code) throws Exception {
		Address entry = toAddr(nextAddress);
		nextAddress += 0x100;
		MemoryBlock block = createMemoryBlock(name + "_bytes", entry, code, false);
		block.setExecute(true);
		return entry;
	}

	private byte[] calls(Address target) {
		long address = target.getOffset();
		return bytes(0xda, (int) (address >> 16), (int) address, (int) (address >> 8),
			0xdb, 0x00);
	}

	private byte[] pagedRead(int highRegister, int lowRegister) {
		return bytes(0xdc, 0x40 | highRegister, 0xa8, 0x40 | lowRegister, 0xdb, 0x00);
	}

	private byte[] bytes(int... values) {
		byte[] result = new byte[values.length];
		for (int i = 0; i < values.length; i++) {
			result[i] = (byte) values[i];
		}
		return result;
	}

	private byte[] concat(byte[]... parts) {
		int length = 0;
		for (byte[] part : parts) {
			length += part.length;
		}
		byte[] result = new byte[length];
		int offset = 0;
		for (byte[] part : parts) {
			System.arraycopy(part, 0, result, offset, part.length);
			offset += part.length;
		}
		return result;
	}

	private void deleteCallReferences(Address from) {
		ReferenceManager references = currentProgram.getReferenceManager();
		for (Reference reference : references.getReferencesFrom(from)) {
			if (reference.getReferenceType().isCall()) {
				references.delete(reference);
			}
		}
	}

	private boolean hasCallReference(Address from, Address to) {
		for (Reference reference : currentProgram.getReferenceManager().getReferencesFrom(from)) {
			if (reference.getReferenceType().isCall() && reference.isMemoryReference() &&
				reference.getToAddress().equals(to)) {
				return true;
			}
		}
		return false;
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
