package ghidrainfineon;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Owns TASKING Classic Large type inference as one ordered analysis pass.
 *
 * <p>The individual implementations are ordinary internal phases rather than
 * Ghidra analyzers. This coordinator is therefore the sole scheduler-visible
 * owner of analyzer-generated C166 parameter, return, and variadic call-site
 * types.</p>
 */
public class C166TaskingTypeInferenceAnalyzer extends AbstractAnalyzer {
	private static final int MAX_CONVERGENCE_ROUNDS = 8;
	private static final int TRACKING_DEPENDENCY_DEPTH = 2;

	private RunStatistics lastRunStatistics = RunStatistics.empty();
	private List<PhaseTiming> activePhaseTimings = new ArrayList<>();
	private List<PhaseTiming> lastPhaseTimings = List.of();
	private EvidenceStatistics lastEvidenceStatistics = EvidenceStatistics.empty();

	public C166TaskingTypeInferenceAnalyzer() {
		super("C166 TASKING Type Inference",
			"Classifies TASKING parameters as scalars, data pointers, or function " +
				"pointers in one ordered pass.",
			AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C166ArchitectureProfile.isTaskingClassicLarge(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		activePhaseTimings = new ArrayList<>();
		lastPhaseTimings = List.of();
		lastEvidenceStatistics = EvidenceStatistics.empty();
		boolean fullScan = isFullScan(program, set);
		AddressSet initialScope = functionScope(program, set, fullScan, monitor);
		int initialFunctions = countFunctions(program, initialScope, fullScan);
		if (!fullScan && initialFunctions == 0) {
			lastRunStatistics = new RunStatistics(false, 0, 0, 0, 0, 0, true);
			lastPhaseTimings = List.of();
			return true;
		}
		/*
		 * Variadic overrides affect the CALL inputs seen by the pointer phases, so
		 * bootstrap them before collecting evidence and rebuild them after the final
		 * parameter and return types are known.  The expensive phases run on a dirty
		 * function worklist.  A disassembly event must not make every callee of the
		 * changed function an analysis root merely because an edge exists.
		 */
		boolean success = runPhase("ABI data types", new C166TaskingDataTypePhase(),
			program, initialScope, monitor, log);
		success &= runPhase("variadic bootstrap", new C166VariadicCallPhase(),
			program, initialScope, monitor, log);

		AddressSet dirty = new AddressSet(initialScope);
		AddressSet processed = new AddressSet(initialScope);
		Set<String> seenStates = new HashSet<>();
		int rounds = 1;
		int signatureChanges = 0;
		int heavyDecompilations = 0;
		boolean converged = false;

		success &= runPhase("scalar signatures", new C166ScalarSignaturePhase(),
			program, dirty, monitor, log);
		C166AnalysisEvidenceIndex.Session evidenceSession =
			C166AnalysisEvidenceIndex.begin(program, initialScope, fullScan, monitor);
		C166AnalysisEvidenceIndex.BuildStatistics evidence =
			C166AnalysisEvidenceIndex.statistics(program);
		lastEvidenceStatistics = new EvidenceStatistics(evidence.functions(),
			evidence.usableFunctions(), evidence.instructions(),
			evidence.flowInstructions(), evidence.pagedSetups(), evidence.milliseconds());
		try {
		C166FarPointerPhase farPointers;
		C166TaskingCallArguments.RecoverySession callRecovery =
			C166TaskingCallArguments.beginSharedRecovery(program);
		try (callRecovery) {
			success &= runPhase("code/scalar classification", new C166CodePointerPhase(),
				program, dirty, monitor, log);
			farPointers = new C166FarPointerPhase();
			success &= runPhase("far-data classification", farPointers, program, dirty,
				monitor, log);
		}
		Msg.info(this, "C166 TASKING call-word recovery cache> " + callRecovery.hits() +
			" hit(s), " + callRecovery.misses() + " miss(es); cache released.");
		heavyDecompilations += farPointers.getLastDecompilations();
		success &= runPhase("scalar finalization", new C166ScalarSignaturePhase(),
			program, dirty, monitor, log);
		success &= runPhase("pointer returns", new C166PointerReturnPhase(),
			program, dirty, monitor, log);

		while (!dirty.isEmpty() && rounds <= MAX_CONVERGENCE_ROUNDS) {
			monitor.checkCancelled();
			AddressSet tracked = dependencyScope(program, dirty, monitor);
			Map<Function, String> before = signatureSnapshot(program, tracked);
			C166AggregateLayoutPhase aggregates = new C166AggregateLayoutPhase();
			success &= runPhase("aggregate layouts", aggregates, program, dirty, monitor,
				log);
			heavyDecompilations += aggregates.getLastDecompilations();

			Map<Function, String> after = signatureSnapshot(program, tracked);
			Set<Function> changed = changedFunctions(before, after);
			signatureChanges += changed.size();
			if (changed.isEmpty()) {
				converged = true;
				break;
			}
			AddressSet next = propagationScope(program, functionBodies(changed), monitor);
			String state = convergenceState(after, next);
			if (!seenStates.add(state)) {
				Msg.warn(this, "C166 TASKING type inference stopped after a repeated " +
					"signature state in round " + rounds + ".");
				break;
			}
			if (rounds >= MAX_CONVERGENCE_ROUNDS) {
				Msg.warn(this, "C166 TASKING type inference reached the " +
					MAX_CONVERGENCE_ROUNDS + "-round convergence limit.");
				break;
			}
			dirty = next;
			processed.add(dirty);
			rounds++;
			farPointers = new C166FarPointerPhase(true);
			success &= runPhase("far-data layout propagation", farPointers, program,
				dirty, monitor, log);
			heavyDecompilations += farPointers.getLastDecompilations();
		}

		C166LocalObjectTypePhase localObjects = new C166LocalObjectTypePhase();
		success &= runPhase("local object types", localObjects, program, processed,
			monitor, log);
		heavyDecompilations += localObjects.getLastDecompilations();
		success &= runPhase("variadic finalization", new C166VariadicCallPhase(),
			program, processed, monitor, log);
		int processedFunctions = countFunctions(program, processed,
			fullScan && processed.contains(program.getMemory()));
		lastRunStatistics = new RunStatistics(fullScan, initialFunctions,
			processedFunctions, rounds, signatureChanges, heavyDecompilations, converged);
		Msg.info(this, "C166 TASKING Type Inference> " +
			(fullScan ? "Full" : "Incremental") + " worklist: " + initialFunctions +
			" initial function(s), " + processedFunctions + " processed function(s), " +
			rounds + " convergence round(s), " + signatureChanges +
			" changed signature(s), " + heavyDecompilations +
			" requested heavy decompilation(s), converged=" + converged + ".");
		return success;
		}
		finally {
			evidenceSession.close();
			lastPhaseTimings = List.copyOf(activePhaseTimings);
			Msg.info(this, "C166 TASKING phase timings> " + phaseTimingSummary() + ".");
		}
	}

	public RunStatistics getLastRunStatistics() {
		return lastRunStatistics;
	}

	public List<PhaseTiming> getLastPhaseTimings() {
		return lastPhaseTimings;
	}

	public EvidenceStatistics getLastEvidenceStatistics() {
		return lastEvidenceStatistics;
	}

	private boolean isFullScan(Program program, AddressSetView set) {
		return set == null || set.isEmpty() || set.contains(program.getMemory());
	}

	private AddressSet functionScope(Program program, AddressSetView set,
			boolean fullScan, TaskMonitor monitor) throws CancelledException {
		if (fullScan) {
			return new AddressSet(program.getMemory());
		}
		AddressSet functions = new AddressSet();
		Iterator<Function> iterator =
			program.getFunctionManager().getFunctionsOverlapping(set);
		while (iterator.hasNext()) {
			monitor.checkCancelled();
			functions.add(iterator.next().getBody());
		}
		return functions;
	}

	private AddressSet dependencyScope(Program program, AddressSetView roots,
			TaskMonitor monitor) throws CancelledException {
		AddressSet result = new AddressSet(roots);
		ArrayDeque<FunctionDepth> pending = new ArrayDeque<>();
		Set<Function> seen = new HashSet<>();
		for (Function function : functions(program, roots)) {
			if (seen.add(function)) {
				pending.addLast(new FunctionDepth(function, 0));
			}
		}
		while (!pending.isEmpty()) {
			monitor.checkCancelled();
			FunctionDepth current = pending.removeFirst();
			if (current.depth() >= TRACKING_DEPENDENCY_DEPTH) {
				continue;
			}
			Set<Function> neighbors = new HashSet<>(
				current.function().getCallingFunctions(monitor));
			neighbors.addAll(current.function().getCalledFunctions(monitor));
			for (Function neighbor : neighbors) {
				result.add(neighbor.getBody());
				if (seen.add(neighbor)) {
					pending.addLast(new FunctionDepth(neighbor, current.depth() + 1));
				}
			}
		}
		return result;
	}

	private AddressSet propagationScope(Program program, AddressSetView changed,
			TaskMonitor monitor) throws CancelledException {
		AddressSet result = new AddressSet(changed);
		for (Function function : functions(program, changed)) {
			monitor.checkCancelled();
			for (Function caller : function.getCallingFunctions(monitor)) {
				result.add(caller.getBody());
			}
		}
		return result;
	}

	private List<Function> functions(Program program, AddressSetView set) {
		List<Function> result = new ArrayList<>();
		FunctionIterator iterator = program.getFunctionManager().getFunctions(set, true);
		iterator.forEachRemaining(result::add);
		return result;
	}

	private int countFunctions(Program program, AddressSetView set, boolean fullScan) {
		Iterator<Function> iterator = fullScan
			? program.getFunctionManager().getFunctions(true)
			: program.getFunctionManager().getFunctionsOverlapping(set);
		int count = 0;
		while (iterator.hasNext()) {
			iterator.next();
			count++;
		}
		return count;
	}

	private Map<Function, String> signatureSnapshot(Program program,
			AddressSetView set) {
		Map<Function, String> result = new HashMap<>();
		for (Function function : functions(program, set)) {
			result.put(function, signatureState(function));
		}
		return result;
	}

	private Set<Function> changedFunctions(Map<Function, String> before,
			Map<Function, String> after) {
		Set<Function> result = new HashSet<>();
		Set<Function> functions = new HashSet<>(before.keySet());
		functions.addAll(after.keySet());
		for (Function function : functions) {
			if (!java.util.Objects.equals(before.get(function), after.get(function))) {
				result.add(function);
			}
		}
		return result;
	}

	private String signatureState(Function function) {
		StringBuilder state = new StringBuilder();
		state.append(function.getSignatureSource()).append('|')
			.append(function.getCallingConventionName()).append('|')
			.append(dataTypeState(function.getReturnType()));
		for (Parameter parameter : function.getParameters()) {
			state.append(';').append(parameter.getSource()).append('@')
				.append(parameter.getVariableStorage()).append(':')
				.append(dataTypeState(parameter.getFormalDataType()));
		}
		return state.toString();
	}

	private String dataTypeState(DataType type) {
		return dataTypeState(type, new HashSet<>(), 0);
	}

	private String dataTypeState(DataType type, Set<DataType> visited, int depth) {
		DataType current = type;
		while (current instanceof TypeDef typeDef) {
			current = typeDef.getBaseDataType();
		}
		StringBuilder state = new StringBuilder(current.getPathName());
		state.append('#').append(current.getLength());
		if (depth >= 3 || !visited.add(current)) {
			return state.toString();
		}
		if (current instanceof Pointer pointer && pointer.getDataType() != null) {
			DataType target = pointer.getDataType();
			state.append("->").append(dataTypeState(target, visited, depth + 1));
		}
		else if (current instanceof Structure structure) {
			state.append('{');
			for (DataTypeComponent component : structure.getDefinedComponents()) {
				state.append(component.getOffset()).append(':')
					.append(component.getLength()).append(':')
					.append(dataTypeState(component.getDataType(), visited, depth + 1))
					.append(';');
			}
			state.append('}');
		}
		return state.toString();
	}

	private AddressSet functionBodies(Set<Function> functions) {
		AddressSet result = new AddressSet();
		for (Function function : functions) {
			result.add(function.getBody());
		}
		return result;
	}

	private String convergenceState(Map<Function, String> signatures,
			AddressSetView next) {
		List<String> states = new ArrayList<>();
		for (Map.Entry<Function, String> entry : signatures.entrySet()) {
			if (entry.getKey().getBody().intersects(next)) {
				states.add(entry.getKey().getEntryPoint() + "=" + entry.getValue());
			}
		}
		states.sort(String::compareTo);
		return String.join("|", states);
	}

	private boolean runPhase(String name, C166TaskingTypeInferencePhase phase,
			Program program,
			AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		long start = System.nanoTime();
		boolean success = false;
		try {
			monitor.checkCancelled();
			monitor.setMessage("C166 TASKING type inference: " + name);
			success = phase.added(program, set, monitor, log);
			if (!success) {
				Msg.error(this, "C166 TASKING type inference phase failed: " + name);
			}
			return success;
		}
		finally {
			activePhaseTimings.add(new PhaseTiming(name,
				(System.nanoTime() - start) / 1_000_000L, success));
		}
	}

	private String phaseTimingSummary() {
		List<String> values = new ArrayList<>();
		for (PhaseTiming timing : activePhaseTimings) {
			values.add(timing.name() + "=" + timing.milliseconds() + " ms" +
				(timing.success() ? "" : " (failed)"));
		}
		return String.join(", ", values);
	}

	public record PhaseTiming(String name, long milliseconds, boolean success) {
	}

	public record EvidenceStatistics(int functions, int usableFunctions,
			int instructions, int flowInstructions, int pagedSetups,
			long milliseconds) {
		private static EvidenceStatistics empty() {
			return new EvidenceStatistics(0, 0, 0, 0, 0, 0);
		}
	}

	public record RunStatistics(boolean fullScan, int initialFunctions,
			int processedFunctions, int convergenceRounds, int signatureChanges,
			int heavyDecompilations, boolean converged) {
		private static RunStatistics empty() {
			return new RunStatistics(false, 0, 0, 0, 0, 0, true);
		}
	}

	private record FunctionDepth(Function function, int depth) {
	}
}
