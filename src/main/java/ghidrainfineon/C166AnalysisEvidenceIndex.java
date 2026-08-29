package ghidrainfineon;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Immutable listing evidence shared by one unified TASKING type-inference run.
 *
 * <p>Function bodies and instruction flow do not change while the type phases
 * update signatures.  Indexing the small subsets used by several phases avoids
 * walking the complete listing once for code pointers, several times for far
 * pointers, and again for aggregate/local candidates.  A phase invoked directly
 * (outside the unified analyzer) transparently falls back to the listing.</p>
 */
final class C166AnalysisEvidenceIndex {

	private static final ThreadLocal<Map<Program, C166AnalysisEvidenceIndex>> ACTIVE =
		ThreadLocal.withInitial(IdentityHashMap::new);

	private final Program program;
	private final Map<Function, List<Instruction>> flowInstructions = new HashMap<>();
	private final Map<Function, List<Instruction>> pagedSetups = new HashMap<>();
	private final Map<Function, Map<Integer, java.util.Set<Integer>>> pagedOffsets =
		new HashMap<>();
	private final Map<Function, java.util.Set<ghidra.program.model.address.Address>>
		globalPointerStarts = new HashMap<>();
	private final BuildStatistics statistics;

	private C166AnalysisEvidenceIndex(Program program, AddressSetView scope,
			boolean fullScan, TaskMonitor monitor) throws CancelledException {
		this.program = program;
		long start = System.nanoTime();
		Iterator<Function> functions = fullScan
			? program.getFunctionManager().getFunctions(true)
			: program.getFunctionManager().getFunctionsOverlapping(scope);
		int functionCount = 0;
		int usableFunctions = 0;
		int instructionCount = 0;
		int flowCount = 0;
		int pagedCount = 0;
		while (functions.hasNext()) {
			monitor.checkCancelled();
			Function function = functions.next();
			functionCount++;
			if (!C166AnalysisFunctions.hasUsableBody(function)) {
				continue;
			}
			usableFunctions++;
			List<Instruction> flows = new ArrayList<>();
			List<Instruction> pages = new ArrayList<>();
			InstructionIterator instructions =
				program.getListing().getInstructions(function.getBody(), true);
			while (instructions.hasNext()) {
				monitor.checkCancelled();
				Instruction instruction = instructions.next();
				instructionCount++;
				if (instruction.getFlowType().isCall() ||
					instruction.getFlowType().isJump()) {
					flows.add(instruction);
					flowCount++;
				}
				if (isPossiblePagedSetup(instruction)) {
					pages.add(instruction);
					pagedCount++;
				}
			}
			flowInstructions.put(function, List.copyOf(flows));
			pagedSetups.put(function, List.copyOf(pages));
		}
		statistics = new BuildStatistics(functionCount, usableFunctions,
			instructionCount, flowCount, pagedCount,
			(System.nanoTime() - start) / 1_000_000L);
	}

	static Session begin(Program program, AddressSetView scope, boolean fullScan,
			TaskMonitor monitor) throws CancelledException {
		C166AnalysisEvidenceIndex index =
			new C166AnalysisEvidenceIndex(program, scope, fullScan, monitor);
		Map<Program, C166AnalysisEvidenceIndex> active = ACTIVE.get();
		C166AnalysisEvidenceIndex previous = active.put(program, index);
		Msg.info(C166AnalysisEvidenceIndex.class,
			"C166 TASKING evidence index> " + index.statistics + ".");
		return new Session(program, index, previous);
	}

	static List<Instruction> flowInstructions(Program program, Function function) {
		C166AnalysisEvidenceIndex index = current(program);
		if (index != null) {
			List<Instruction> cached = index.flowInstructions.get(function);
			if (cached != null) {
				return cached;
			}
		}
		List<Instruction> result = new ArrayList<>();
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			if (instruction.getFlowType().isCall() ||
				instruction.getFlowType().isJump()) {
				result.add(instruction);
			}
		}
		return List.copyOf(result);
	}

	static List<Instruction> pagedSetups(Program program, Function function) {
		C166AnalysisEvidenceIndex index = current(program);
		if (index != null) {
			List<Instruction> cached = index.pagedSetups.get(function);
			if (cached != null) {
				return cached;
			}
		}
		List<Instruction> result = new ArrayList<>();
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			if (isPossiblePagedSetup(instruction)) {
				result.add(instruction);
			}
		}
		return List.copyOf(result);
	}

	static Map<Integer, java.util.Set<Integer>> pagedOffsets(Program program,
			Function function,
			Supplier<Map<Integer, java.util.Set<Integer>>> supplier) {
		C166AnalysisEvidenceIndex index = current(program);
		if (index == null || !index.pagedSetups.containsKey(function)) {
			return supplier.get();
		}
		return index.pagedOffsets.computeIfAbsent(function, ignored -> supplier.get());
	}

	static java.util.Set<ghidra.program.model.address.Address> globalPointerStarts(
			Program program, Function function,
			Supplier<java.util.Set<ghidra.program.model.address.Address>> supplier) {
		C166AnalysisEvidenceIndex index = current(program);
		if (index == null || !index.pagedSetups.containsKey(function)) {
			return supplier.get();
		}
		return index.globalPointerStarts.computeIfAbsent(function,
			ignored -> supplier.get());
	}

	static BuildStatistics statistics(Program program) {
		C166AnalysisEvidenceIndex index = current(program);
		return index == null ? BuildStatistics.empty() : index.statistics;
	}

	private static C166AnalysisEvidenceIndex current(Program program) {
		return ACTIVE.get().get(program);
	}

	private static boolean isPossiblePagedSetup(Instruction instruction) {
		String mnemonic = instruction.getMnemonicString().toLowerCase();
		if (mnemonic.equals("extp") || mnemonic.equals("extpr")) {
			return true;
		}
		if (!mnemonic.equals("mov")) {
			return false;
		}
		for (Object result : instruction.getResultObjects()) {
			if (result instanceof Register register &&
				"dpp0".equalsIgnoreCase(register.getName())) {
				return true;
			}
		}
		return false;
	}

	static final class Session implements AutoCloseable {
		private final Program program;
		private final C166AnalysisEvidenceIndex index;
		private final C166AnalysisEvidenceIndex previous;
		private boolean closed;

		private Session(Program program, C166AnalysisEvidenceIndex index,
				C166AnalysisEvidenceIndex previous) {
			this.program = program;
			this.index = index;
			this.previous = previous;
		}

		@Override
		public void close() {
			if (closed) {
				return;
			}
			closed = true;
			Map<Program, C166AnalysisEvidenceIndex> active = ACTIVE.get();
			if (active.get(program) != index) {
				return;
			}
			if (previous == null) {
				active.remove(program);
			}
			else {
				active.put(program, previous);
			}
			if (active.isEmpty()) {
				ACTIVE.remove();
			}
		}
	}

	record BuildStatistics(int functions, int usableFunctions, int instructions,
			int flowInstructions, int pagedSetups, long milliseconds) {
		private static BuildStatistics empty() {
			return new BuildStatistics(0, 0, 0, 0, 0, 0);
		}

		@Override
		public String toString() {
			return functions + " function(s), " + usableFunctions + " usable, " +
				instructions + " instruction(s), " + flowInstructions +
				" call/jump candidate(s), " + pagedSetups +
				" paged setup candidate(s), " + milliseconds + " ms";
		}
	}
}
