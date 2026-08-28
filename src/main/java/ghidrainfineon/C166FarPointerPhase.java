package ghidrainfineon;

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.OperandReferenceAnalyzer;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Infers TASKING Classic far-pointer parameters from their documented memory
 * access semantics.
 * <p>
 * The C166/ST10 Classic 7.5 C compiler manual specifies four consecutive
 * parameter slots (R12-R15), a four-byte PAGE:OFFSET far pointer, stack spill
 * after the register bank is exhausted, and DPP0 as the scratch page register
 * used for far-pointer dereferences.  On targets using the extended instruction
 * set, EXTP provides the same paged access.  The decompiler normalizes both
 * forms to SEGMENTOP(page, offset).  A register or stack pair is therefore
 * joined only when its high word reaches PAGE and its adjacent low word reaches
 * OFFSET.
 * <p>
 * Constant call arguments are also accepted as a seed, but only with repeated
 * independent call-site evidence and only when the high word is a valid C166
 * data PAGE which cannot be a 24-bit code SEGMENT.  The decoded PAGE:OFFSET
 * must name mapped program memory.  No function names or firmware-specific
 * addresses are used as evidence.
 */
public class C166FarPointerPhase extends C166TaskingTypeInferencePhase {

	private static final String CALLING_CONVENTION = "__tasking_c166_classic";
	private static final String GENERIC_FUNCTION_PATH = "/c166/function";
	private static final String LEGACY_GENERIC_FUNCTION_PATH = "/__c166_far_function";
	private static final String GENERIC_FUNCTION_POINTER_PATH = "/fpointer";
	private static final int FIRST_ARGUMENT_REGISTER = 12;
	private static final int LAST_ARGUMENT_REGISTER = 15;
	private static final int DECOMPILE_TIMEOUT_SECONDS = 30;
	private static final int MAX_TRACE_DEPTH = 32;
	private static final int MAX_SETUP_SCAN_INSTRUCTIONS = 256;
	private static final int MIN_CONSTANT_CALL_SITES = 2;
	private static final int MIN_TYPED_CALL_SITES = 2;

	public C166FarPointerPhase() {
		super("C166 TASKING Far Pointer Inference");
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C166ArchitectureProfile.isTaskingClassicLarge(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		boolean fullScan = set == null || set.isEmpty() || set.contains(program.getMemory());
		int legacyReferencesRemoved =
			removeLegacyCallReferences(program, set, fullScan, monitor);
		CallSiteSeedStats seedStats = seedConstantDataPointers(program, set, fullScan,
			monitor, log);
		C166CodePointerPhase.addScalarPairEvidence(program, seedStats.scalarPairs());
		CandidateGraph graph = buildCandidateGraph(program, set, fullScan, monitor);
		SccSchedule schedule = buildSccSchedule(graph, monitor);
		monitor.initialize(Math.max(1, graph.functions().size()),
			"C166 far-pointer inference: decompiling candidates");
		if (graph.functions().isEmpty()) {
			monitor.setProgress(1);
		}
		AnalysisStats stats = new AnalysisStats();

		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(false);
		decompiler.toggleSyntaxTree(true);
		if (!decompiler.openProgram(program)) {
			report(program, "Decompiler initialization failed: " + decompiler.getLastMessage());
			return false;
		}

		try {
			for (int layerIndex = 0; layerIndex < schedule.layers().size(); layerIndex++) {
				boolean layerChanged = false;
				for (int componentIndex : schedule.layers().get(layerIndex)) {
					layerChanged |= analyzeComponent(program, decompiler,
						schedule.components().get(componentIndex), stats,
						seedStats.scalarPairs(), seedStats.strictScalarPairs(), monitor, log);
				}
				if (layerChanged && layerIndex + 1 < schedule.layers().size()) {
					decompiler.flushCache();
				}
			}
		}
		finally {
			decompiler.dispose();
		}
		// Do not mutate the listing while candidate HighFunctions are still being
		// recovered.  Clearing a false instruction/data conflict invalidates the
		// decompiler's view and can hide otherwise independent PAGE:OFFSET pairs
		// later in the same analysis batch.
		stats.globalPointersCreated +=
			defineGlobalFarPointers(program, stats.globalPointerStarts);
		scheduleReferenceAnalysis(program, stats.referenceSources);

		report(program, (fullScan ? "Full" : "Incremental") + " scan: inspected " +
			stats.inspected.size() +
			" direct or forwarding function(s) in " + stats.decompilations +
			" decompilation(s) across " + schedule.components().size() +
			" call-graph component(s); inferred " + stats.inferredPointers +
			" far-pointer parameter(s) in " + stats.inferredFunctions +
			" function(s), added or updated " + stats.referenceCount +
			" physical far-pointer reference(s), queued Reference analysis for " +
			stats.referenceSources.getNumAddresses() +
			" parameter setup instruction(s), created " + stats.globalPointersCreated +
			" global far-pointer object(s), " +
			"seeded " + seedStats.parameters() + " parameter(s) in " +
			seedStats.functions() + " function(s) from " + seedStats.occurrences() +
			" corroborated constant or typed call-site occurrence(s), rejected " +
			seedStats.scalarConflicts() + " scalar-use candidate pair(s), repaired " +
			(seedStats.repairedPointers() + stats.repairedPointers) +
			" stale analysis pointer(s), " +
			"removed " + legacyReferencesRemoved + " legacy call-site reference(s), " +
			stats.ambiguousFunctions.size() + " ambiguous, " + stats.failedFunctions.size() +
			" decompilation failure(s), " + stats.fixedPointPasses +
			" signature fixed-point pass(es), " + stats.nonConvergentComponents +
			" non-convergent component(s).");
		if (!stats.nonConvergentDetails.isEmpty()) {
			report(program, "Non-convergent component details: " +
				String.join("; ", stats.nonConvergentDetails));
		}
		return true;
	}

	private boolean analyzeComponent(Program program, DecompInterface decompiler,
			List<Function> component, AnalysisStats stats,
			Map<Function, Set<Integer>> scalarPairs,
			Map<Function, Set<Integer>> strictScalarPairs,
			TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Set<String> seenSignatures = new LinkedHashSet<>();
		boolean anyChange = false;
		boolean firstPass = true;
		while (true) {
			monitor.checkCancelled();
			String signatureState = componentSignatureState(component);
			if (!seenSignatures.add(signatureState)) {
				stats.nonConvergentComponents++;
				stats.nonConvergentDetails.add(component.stream()
					.map(function -> function.getEntryPoint() + " " +
						function.getPrototypeString(true, true))
					.collect(java.util.stream.Collectors.joining(", ")) +
					" states=" + String.join(" -> ", seenSignatures));
				break;
			}

			List<Function> passFunctions = new ArrayList<>();
			for (Function function : component) {
				if (!stats.failedFunctions.contains(function)) {
					passFunctions.add(function);
				}
			}
			if (passFunctions.isEmpty()) {
				break;
			}
			if (!firstPass) {
				stats.fixedPointPasses++;
				monitor.setMaximum(monitor.getMaximum() + passFunctions.size());
				decompiler.flushCache();
			}

			boolean passChanged = false;
			for (Function function : passFunctions) {
				passChanged |= analyzeFunction(program, decompiler, function, stats,
					scalarPairs, strictScalarPairs, monitor, log);
			}
			anyChange |= passChanged;
			if (!passChanged) {
				break;
			}
			firstPass = false;
		}
		return anyChange;
	}

	private boolean analyzeFunction(Program program, DecompInterface decompiler,
			Function function, AnalysisStats stats,
			Map<Function, Set<Integer>> scalarPairs,
			Map<Function, Set<Integer>> strictScalarPairs,
			TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		monitor.checkCancelled();
		stats.inspected.add(function);
		stats.decompilations++;
		try {
			Set<Integer> separatedScalarPairs =
				findSeparatelyStoredScalarPairs(program, function);
			Set<Integer> storedPointerPairs =
				findIndirectlyConsumedStoredPointerPairs(program, function);
			Map<Integer, DataType> storedAggregatePointers =
				forwardedAggregateFieldPointerTypes(program, function);
			Set<Integer> scalarOnlySeparated = new HashSet<>(separatedScalarPairs);
			// Exact adjacent stores into a concrete four-byte aggregate pointer field
			// are stronger than the fact that its PAGE and OFFSET source words are
			// stored separately. Splitting here and rejoining below would oscillate.
			scalarOnlySeparated.removeAll(storedAggregatePointers.keySet());
			boolean repairedSeparatedScalars = !scalarOnlySeparated.isEmpty() &&
				splitContradictedAnalysisPointers(program, function,
					scalarOnlySeparated) != 0;
			if (repairedSeparatedScalars) {
				stats.repairedPointers++;
				decompiler.flushCache();
			}
			monitor.setMessage("C166 far-pointer inference (" +
				(stats.processedCandidates + 1) + "/" + monitor.getMaximum() + "): " +
				function.getName());
			DecompileResults result = decompiler.decompileFunction(function,
				DECOMPILE_TIMEOUT_SECONDS, monitor);
			if (!result.decompileCompleted() || result.getHighFunction() == null) {
				stats.failedFunctions.add(function);
				return false;
			}

			// DecompileCallback warnings do not make a partial HighFunction
			// unusable.  Keep all recovered p-code; scheduling, not warning text,
			// determines whether a recursive component needs another pass.
			stats.referenceCount += addFarPointerReferences(program,
				result.getHighFunction().getPcodeOps(), stats.referenceSources);
			Set<Integer> forwardedScalarPairs =
				findForwardedScalarPairs(program, function, result.getHighFunction());
			Set<Integer> scalarOnlyForwarding = new HashSet<>(forwardedScalarPairs);
			scalarOnlyForwarding.removeAll(storedAggregatePointers.keySet());
			boolean repairedForwardedScalars = !scalarOnlyForwarding.isEmpty() &&
				splitContradictedAnalysisPointers(program, function,
					scalarOnlyForwarding) != 0;
			if (repairedForwardedScalars) {
				stats.repairedPointers++;
			}
			Inference inference = inferPairs(program, function, result.getHighFunction());
			stats.globalPointerStarts.addAll(inference.globalPointerStarts());
			if (inference.ambiguous()) {
				stats.ambiguousFunctions.add(function);
				return false;
			}
			Set<Integer> liveSlots = new HashSet<>(inference.liveSlots());
			Set<Integer> pairStarts = new HashSet<>(retainSupportedPairs(function,
				inference.pairStarts(), liveSlots));
			for (int start : storedPointerPairs) {
				pairStarts.add(start);
				liveSlots.add(start);
				liveSlots.add(start + 1);
			}
			Set<Integer> directPagedPairs = new HashSet<>(inference.directPagedPairs());
			// A stale generic fpointer can suppress the very PIECE/SEGMENTOP p-code
			// needed to rediscover its pair.  Seed only its exact ABI storage when the
			// listing independently proves that pair drives a paged data access.
			if (function.getSignatureSource() == SourceType.ANALYSIS) {
				for (Parameter parameter : function.getParameters()) {
					Integer start = parameterStart(parameter.getVariableStorage());
					if (start != null && isGenericFunctionPointer(
						parameter.getFormalDataType()) &&
						containsDirectPagedDataUseForPair(program, function, start)) {
						pairStarts.add(start);
						directPagedPairs.add(start);
						liveSlots.add(start);
						liveSlots.add(start + 1);
					}
				}
			}
			for (int start : pairStarts) {
				if (containsDirectPagedDataUseForPair(program, function, start) ||
					containsDynamicPagedAccessSetupForPair(program, function, start)) {
					directPagedPairs.add(start);
				}
			}
			Map<Integer, DataType> pointerTypes = preferDirectPagedDataTypes(program,
				function, inference.pointerTypes(), directPagedPairs);
			for (Map.Entry<Integer, DataType> entry : storedAggregatePointers.entrySet()) {
				int start = entry.getKey();
				pairStarts.add(start);
				liveSlots.add(start);
				liveSlots.add(start + 1);
				mergePointerType(program, pointerTypes, start, entry.getValue());
			}
			for (int start : storedPointerPairs) {
				pointerTypes.putIfAbsent(start, new PointerDataType(VoidDataType.dataType,
					program.getDataTypeManager()));
			}
			pairStarts = removeFunctionPointerConflicts(program, function, pairStarts,
				directPagedPairs, pointerTypes);
			pairStarts = removeCallSiteScalarConflicts(function, pairStarts,
				directPagedPairs, scalarPairs, strictScalarPairs);
			if (!forwardedScalarPairs.isEmpty()) {
				Set<Integer> retained = new HashSet<>(pairStarts);
				retained.removeAll(scalarOnlyForwarding);
				pairStarts = Set.copyOf(retained);
			}
			if (!scalarOnlySeparated.isEmpty()) {
				Set<Integer> retained = new HashSet<>(pairStarts);
				retained.removeAll(scalarOnlySeparated);
				pairStarts = Set.copyOf(retained);
			}
			if (pairStarts.isEmpty() || signatureMatches(function, pairStarts,
				liveSlots, pointerTypes)) {
				return repairedSeparatedScalars || repairedForwardedScalars;
			}

			updateSignature(program, function, pairStarts, liveSlots,
				pointerTypes);
			stats.inferredFunctions++;
			stats.inferredPointers += pairStarts.size();
			return true;
		}
		catch (DuplicateNameException | InvalidInputException e) {
			log.appendException(e);
			stats.failedFunctions.add(function);
			return false;
		}
		finally {
			stats.processedCandidates++;
			monitor.setProgress(stats.processedCandidates);
		}
	}

	/**
	 * A direct C166 paged load/store is data-space use even when a stale generic
	 * function-pointer HighSymbol made the decompiler type its PIECE as fpointer.
	 * Strip only that analyzer-owned circular type; concrete callback typedefs and
	 * non-analysis signatures remain protected by the conflict filter below.
	 */
	private Map<Integer, DataType> preferDirectPagedDataTypes(Program program,
			Function function, Map<Integer, DataType> inferredTypes,
			Set<Integer> directPagedPairs) {
		Map<Integer, DataType> result = new HashMap<>(inferredTypes);
		if (function.getSignatureSource() != SourceType.ANALYSIS) {
			return result;
		}
		for (int start : directPagedPairs) {
			for (Parameter parameter : function.getParameters()) {
				Integer existingStart = parameterStart(parameter.getVariableStorage());
				if (Integer.valueOf(start).equals(existingStart) &&
					isGenericFunctionPointer(parameter.getFormalDataType())) {
					result.put(start, new PointerDataType(VoidDataType.dataType,
						program.getDataTypeManager()));
					break;
				}
			}
		}
		return result;
	}

	private String componentSignatureState(List<Function> component) {
		StringBuilder state = new StringBuilder();
		for (Function function : component) {
			state.append(function.getEntryPoint()).append(':')
				.append(function.getPrototypeString(true, true));
			for (Parameter parameter : function.getParameters()) {
				state.append('|').append(parameter.getFormalDataType().getPathName())
					.append('@').append(parameter.getVariableStorage());
			}
			state.append(';');
		}
		return state.toString();
	}

	private static final class AnalysisStats {
		private final Set<Function> inspected = new HashSet<>();
		private final Set<Function> ambiguousFunctions = new HashSet<>();
		private final Set<Function> failedFunctions = new HashSet<>();
		private final Set<Address> globalPointerStarts = new HashSet<>();
		private final AddressSet referenceSources = new AddressSet();
		private int processedCandidates;
		private int decompilations;
		private int inferredFunctions;
		private int inferredPointers;
		private int referenceCount;
		private int globalPointersCreated;
		private int fixedPointPasses;
		private int nonConvergentComponents;
		private final List<String> nonConvergentDetails = new ArrayList<>();
		private int repairedPointers;
	}

	/**
	 * Seeds otherwise opaque pass-through/store functions from their callers.
	 * A PAGE above 0xff is decisive on C166: it is legal for the 10-bit data
	 * page field, but cannot be the 8-bit segment of a 24-bit code pointer.
	 * Requiring two separate calls and mapped, canonical PAGE:OFFSET values keeps
	 * ordinary adjacent scalar arguments out of the type system.
	 */
	private CallSiteSeedStats seedConstantDataPointers(Program program,
			AddressSetView set, boolean fullScan, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Iterator<Function> scoped = fullScan
			? program.getFunctionManager().getFunctions(true)
			: program.getFunctionManager().getFunctionsOverlapping(set);
		Set<Function> scopedFunctions = new HashSet<>();
		scoped.forEachRemaining(scopedFunctions::add);
		Set<Function> callers = new HashSet<>(scopedFunctions);
		if (!fullScan) {
			for (Function target : scopedFunctions) {
				callers.addAll(directCallers(program, target));
			}
		}

		BasicBlockModel blocks = new BasicBlockModel(program);
		Map<Function, Map<Integer, Set<Address>>> occurrences = new HashMap<>();
		Map<Function, Map<Integer, Set<ConstantWordPair>>> constantPairs = new HashMap<>();
		Map<Function, Map<Integer, Set<Address>>> typedOccurrences = new HashMap<>();
		Set<Address> scannedCalls = new HashSet<>();
		Set<Function> discoveredTargets = new HashSet<>();
		scanConstantCallers(program, callers, blocks, occurrences, constantPairs,
			typedOccurrences, scannedCalls, discoveredTargets, monitor);
		if (!fullScan) {
			Set<Function> corroboratingCallers = new HashSet<>();
			for (Function target : discoveredTargets) {
				corroboratingCallers.addAll(directCallers(program, target));
			}
			scanConstantCallers(program, corroboratingCallers, blocks, occurrences,
				constantPairs, typedOccurrences, scannedCalls, discoveredTargets, monitor);
		}

		int seededFunctions = 0;
		int seededParameters = 0;
		int acceptedOccurrences = 0;
		int repairedPointers = 0;
		Map<Function, Set<Integer>> scalarPairs = new HashMap<>();
		Map<Function, Set<Integer>> strictScalarPairs = new HashMap<>();
		for (Map.Entry<Function, Map<Integer, Set<Address>>> targetEntry :
				occurrences.entrySet()) {
			monitor.checkCancelled();
			Function target = targetEntry.getKey();
			for (Map.Entry<Integer, Set<Address>> pair : targetEntry.getValue().entrySet()) {
				if (pair.getValue().size() >= MIN_CONSTANT_CALL_SITES &&
					hasIndependentInputBitTest(program, target, pair.getKey())) {
					scalarPairs.computeIfAbsent(target, ignored -> new HashSet<>())
						.add(pair.getKey());
				}
			}
		}
		for (Map.Entry<Function, Map<Integer, Set<ConstantWordPair>>> targetEntry :
				constantPairs.entrySet()) {
			monitor.checkCancelled();
			Function target = targetEntry.getKey();
			for (Map.Entry<Integer, Set<ConstantWordPair>> pair :
					targetEntry.getValue().entrySet()) {
				if (!containsDynamicPagedAccessSetupForPair(program, target,
						pair.getKey()) &&
					hasIndependentConstantWords(pair.getValue())) {
					scalarPairs.computeIfAbsent(target, ignored -> new HashSet<>())
						.add(pair.getKey());
					strictScalarPairs.computeIfAbsent(target, ignored -> new HashSet<>())
						.add(pair.getKey());
				}
			}
		}
		propagateEntryForwardingScalarPairs(program, scalarPairs, monitor);
		propagateEntryForwardingScalarPairs(program, strictScalarPairs, monitor);
		for (Map.Entry<Function, Set<Integer>> conflict : scalarPairs.entrySet()) {
			monitor.checkCancelled();
			try {
				repairedPointers += splitContradictedAnalysisPointers(program,
					conflict.getKey(), conflict.getValue());
			}
			catch (DuplicateNameException | InvalidInputException e) {
				log.appendException(e);
			}
		}
		for (Map.Entry<Function, Map<Integer, Set<Address>>> targetEntry :
				occurrences.entrySet()) {
			monitor.checkCancelled();
			Function target = targetEntry.getKey();
			Set<Integer> contradicted = scalarPairs.getOrDefault(target, Set.of());
			for (Map.Entry<Integer, Set<Address>> pair : targetEntry.getValue().entrySet()) {
				try {
					boolean inferDataPointer =
						pair.getValue().size() >= MIN_CONSTANT_CALL_SITES &&
						!contradicted.contains(pair.getKey()) &&
						directlyConsumesSeedPair(program, target, pair.getKey());
					repairedPointers += replaceImpossibleGenericCodePointer(program, target,
						pair.getKey(), inferDataPointer);
				}
				catch (DuplicateNameException | InvalidInputException e) {
					log.appendException(e);
				}
			}
		}

		Set<Function> seededTargets = new HashSet<>(occurrences.keySet());
		seededTargets.addAll(typedOccurrences.keySet());
		for (Function target : orderedFunctions(seededTargets)) {
			monitor.checkCancelled();
			Set<Integer> contradicted = scalarPairs.getOrDefault(target, Set.of());
			Map<Integer, Integer> scores = new HashMap<>();
			Map<Integer, Set<Address>> constantTargetOccurrences =
				occurrences.getOrDefault(target, Map.of());
			for (Map.Entry<Integer, Set<Address>> pair :
					constantTargetOccurrences.entrySet()) {
				if (pair.getValue().size() >= MIN_CONSTANT_CALL_SITES &&
					!contradicted.contains(pair.getKey()) &&
					directlyConsumesSeedPair(program, target, pair.getKey()) &&
					!overlapsExistingPointer(target, pair.getKey())) {
					scores.put(pair.getKey(), pair.getValue().size());
				}
			}
			Map<Integer, Set<Address>> typedTargetOccurrences =
				typedOccurrences.getOrDefault(target, Map.of());
			for (Map.Entry<Integer, Set<Address>> pair :
					typedTargetOccurrences.entrySet()) {
				if (pair.getValue().size() >= MIN_TYPED_CALL_SITES &&
					!contradicted.contains(pair.getKey()) &&
					directlyConsumesSeedPair(program, target, pair.getKey()) &&
					!overlapsExistingPointer(target, pair.getKey())) {
					scores.merge(pair.getKey(), pair.getValue().size(), Integer::sum);
				}
			}
			List<Integer> candidates = new ArrayList<>(scores.keySet());
			Collections.sort(candidates);
			Selection selection = selectPairs(candidates, scores, 0, new HashMap<>());
			if (selection.ambiguous() || selection.starts().isEmpty()) {
				continue;
			}

			Set<Integer> liveSlots = existingParameterSlots(target);
			Map<Integer, DataType> pointerTypes = new HashMap<>();
			for (int start : selection.starts()) {
				for (int slot = 0; slot <= start + 1; slot++) {
					liveSlots.add(slot);
				}
				pointerTypes.put(start, new PointerDataType(VoidDataType.dataType,
					program.getDataTypeManager()));
				acceptedOccurrences +=
					constantTargetOccurrences.getOrDefault(start, Set.of()).size();
				acceptedOccurrences +=
					typedTargetOccurrences.getOrDefault(start, Set.of()).size();
			}
			Set<Integer> supported = retainSupportedPairs(target, selection.starts(), liveSlots);
			if (supported.isEmpty() || signatureMatches(target, supported, liveSlots,
				pointerTypes)) {
				continue;
			}
			try {
				updateSignature(program, target, supported, liveSlots, pointerTypes);
				seededFunctions++;
				seededParameters += supported.size();
			}
			catch (DuplicateNameException | InvalidInputException e) {
				log.appendException(e);
			}
		}
		int scalarConflicts = scalarPairs.values().stream().mapToInt(Set::size).sum();
		return new CallSiteSeedStats(seededFunctions, seededParameters,
			acceptedOccurrences, scalarConflicts, repairedPointers,
			immutableSetMap(scalarPairs), immutableSetMap(strictScalarPairs));
	}

	/**
	 * Repair a stale generic code-pointer inference before decompiling callers.
	 * A constant occurrence reaches this method only when its PAGE is greater than
	 * 0xff, its OFFSET is canonical, and the resulting data address is mapped.
	 * One such value is enough to refute a code pointer, while promotion to a data
	 * pointer still requires repeated evidence and direct consumption.  Limiting
	 * the replacement to the analyzer-owned generic fpointer types preserves
	 * concrete callback types and every USER_DEFINED or IMPORTED signature.
	 */
	private int replaceImpossibleGenericCodePointer(Program program, Function function,
			int pairStart, boolean consumed)
			throws DuplicateNameException, InvalidInputException {
		if (function.getSignatureSource() != SourceType.ANALYSIS ||
			C166CodePointerPhase.hasSemanticCodePointerEvidence(program, function,
				pairStart)) {
			return 0;
		}
		List<Variable> parameters = new ArrayList<>();
		boolean replaced = false;
		for (Parameter parameter : function.getParameters()) {
			Integer start = parameterStart(parameter.getVariableStorage());
			if (Integer.valueOf(pairStart).equals(start) &&
				parameter.getVariableStorage().size() == 4 &&
				isGenericFunctionPointer(parameter.getFormalDataType())) {
				if (consumed) {
					parameters.add(new ParameterImpl(existingName(parameter),
						new PointerDataType(VoidDataType.dataType,
							program.getDataTypeManager()), program));
				}
				else {
					parameters.add(new ParameterImpl(null,
						Undefined.getUndefinedDataType(2), program));
					parameters.add(new ParameterImpl(null,
						Undefined.getUndefinedDataType(2), program));
				}
				replaced = true;
			}
			else {
				parameters.add(new ParameterImpl(existingName(parameter),
					parameter.getFormalDataType(), program));
			}
		}
		if (!replaced) {
			return 0;
		}
		function.updateFunction(CALLING_CONVENTION, null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
		return 1;
	}

	/**
	 * Constant call-site values are meaningful only when the callee consumes the
	 * incoming words.  Registers which merely happen to be live across a no-arg
	 * call are not arguments.  Calls terminate this cheap proof: forwarding is
	 * handled later from the callee's established signature.
	 */
	private boolean directlyConsumesSeedPair(Program program, Function function,
			int pairStart) {
		if (pairStart >= 4) {
			// Stack seed support predates this register-liveness guard.  Stack words
			// are materialized by explicit loads and are validated by the semantic pass.
			return true;
		}
		Register low = program.getRegister("r" + (FIRST_ARGUMENT_REGISTER + pairStart));
		Register high =
			program.getRegister("r" + (FIRST_ARGUMENT_REGISTER + pairStart + 1));
		boolean lowLive = low != null;
		boolean highLive = high != null;
		boolean lowRead = false;
		boolean highRead = false;
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext() && (lowLive || highLive)) {
			Instruction instruction = instructions.next();
			if (instruction.getFlowType().isCall() || instruction.getFlowType().isJump()) {
				break;
			}
			for (Object input : instruction.getInputObjects()) {
				if (!(input instanceof Register register)) {
					continue;
				}
				lowRead |= lowLive && overlaps(low, register);
				highRead |= highLive && overlaps(high, register);
			}
			if (lowRead && highRead) {
				return true;
			}
			if (lowLive && writesRegister(instruction, low)) {
				lowLive = false;
			}
			if (highLive && writesRegister(instruction, high)) {
				highLive = false;
			}
		}
		return false;
	}

	/**
	 * Repeated constants which contain a complete two-by-two combination cannot
	 * describe one indivisible PAGE:OFFSET value: both words vary independently.
	 * This is common for pairs such as (result, message-id), while a real pointer
	 * remains one correlated value.  The rule repairs a generic ANALYSIS pointer
	 * or protects an already split ANALYSIS word pair; concrete and user-defined
	 * pointer types remain authoritative.
	 */
	private boolean hasIndependentConstantWords(Set<ConstantWordPair> pairs) {
		if (pairs.size() < 4) {
			return false;
		}
		Map<Long, Set<Long>> highByLow = new HashMap<>();
		for (ConstantWordPair pair : pairs) {
			highByLow.computeIfAbsent(pair.low(), ignored -> new HashSet<>()).add(pair.high());
		}
		List<Set<Long>> highSets = new ArrayList<>(highByLow.values());
		for (int left = 0; left < highSets.size(); left++) {
			for (int right = left + 1; right < highSets.size(); right++) {
				Set<Long> intersection = new HashSet<>(highSets.get(left));
				intersection.retainAll(highSets.get(right));
				if (intersection.size() >= 2) {
					return true;
				}
			}
		}
		return false;
	}

	private boolean hasRepairableAnalysisPointer(Function function, int start) {
		if (function.getSignatureSource() != SourceType.ANALYSIS) {
			return false;
		}
		for (Parameter parameter : function.getParameters()) {
			if (Integer.valueOf(start).equals(parameterStart(parameter.getVariableStorage())) &&
				parameter.getVariableStorage().size() == 4 &&
				isGenericVoidPointer(parameter.getFormalDataType())) {
				return true;
			}
		}
		return false;
	}

	private boolean hasScalarAnalysisCandidate(Function function, int start) {
		return hasRepairableAnalysisPointer(function, start) ||
			hasAnalysisWordPair(function, start);
	}

	/**
	 * Preserve an already repaired scalar pair across later analyzer passes.
	 * Code-pointer inference may split a stale four-byte pointer before this
	 * analyzer runs; forgetting the rectangle at that point would let circular
	 * decompiler type evidence join the two words again.
	 */
	private boolean hasAnalysisWordPair(Function function, int start) {
		if (function.getSignatureSource() != SourceType.ANALYSIS) {
			return false;
		}
		boolean low = false;
		boolean high = false;
		for (Parameter parameter : function.getParameters()) {
			Integer parameterSlot = parameterStart(parameter.getVariableStorage());
			if (parameterSlot == null || parameter.getVariableStorage().size() != 2 ||
				isPointerType(parameter.getFormalDataType())) {
				continue;
			}
			low |= parameterSlot == start;
			high |= parameterSlot == start + 1;
		}
		return low && high;
	}

	/**
	 * Carry a proven scalar pair through a literal entry-point forwarding call.
	 * Requiring the call/jump to be the first instruction avoids guessing across
	 * wrappers which transform, materialize, or repurpose argument registers.
	 */
	private void propagateEntryForwardingScalarPairs(Program program,
			Map<Function, Set<Integer>> scalarPairs, TaskMonitor monitor)
			throws CancelledException {
		ArrayDeque<FunctionSlot> pending = new ArrayDeque<>();
		for (Map.Entry<Function, Set<Integer>> entry : scalarPairs.entrySet()) {
			for (int start : entry.getValue()) {
				pending.addLast(new FunctionSlot(entry.getKey(), start));
			}
		}
		while (!pending.isEmpty()) {
			monitor.checkCancelled();
			FunctionSlot source = pending.removeFirst();
			Instruction first =
				program.getListing().getInstructionAt(source.function().getEntryPoint());
			if (first == null || (!first.getFlowType().isCall() &&
				!first.getFlowType().isJump())) {
				continue;
			}
			Function target = directTarget(program, first);
			if (target == null || !hasScalarAnalysisCandidate(target, source.start())) {
				continue;
			}
			Set<Integer> targetPairs =
				scalarPairs.computeIfAbsent(target, ignored -> new HashSet<>());
			if (targetPairs.add(source.start())) {
				pending.addLast(new FunctionSlot(target, source.start()));
			}
		}
	}

	private Map<Function, Set<Integer>> immutableSetMap(
			Map<Function, Set<Integer>> values) {
		Map<Function, Set<Integer>> copy = new HashMap<>();
		for (Map.Entry<Function, Set<Integer>> entry : values.entrySet()) {
			copy.put(entry.getKey(), Set.copyOf(entry.getValue()));
		}
		return Map.copyOf(copy);
	}

	/**
	 * A constant PAGE:OFFSET-shaped pair is not sufficient when the callee itself
	 * proves scalar semantics.  In particular, TASKING commonly passes a boolean
	 * in R12 followed by a 16-bit LGP/message id in R13.  If that id happens to be
	 * above 0xff, the two constants can decode to mapped data by coincidence.
	 *
	 * Only a direct bit branch on an unmodified incoming register is treated as a
	 * contradiction.  This deliberately narrow negative rule does not reject
	 * ordinary pointer copies, stores, comparisons, arithmetic, or forwarding.
	 * A function which also has real paged-memory data flow remains eligible for
	 * the semantic inference pass and can therefore regain a proven pointer.
	 */
	private boolean hasIndependentInputBitTest(Program program, Function function,
			int pairStart) {
		if (pairStart < 0 || pairStart >= 4) {
			return false;
		}
		Register low = program.getRegister("r" + (FIRST_ARGUMENT_REGISTER + pairStart));
		Register high =
			program.getRegister("r" + (FIRST_ARGUMENT_REGISTER + pairStart + 1));
		boolean lowIsInput = low != null;
		boolean highIsInput = high != null;
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext() && (lowIsInput || highIsInput)) {
			Instruction instruction = instructions.next();
			String mnemonic = instruction.getMnemonicString().toLowerCase();
			if (isBitBranch(mnemonic)) {
				Register tested = operandRegister(instruction, 0);
				if ((lowIsInput && overlaps(low, tested)) ||
					(highIsInput && overlaps(high, tested))) {
					return true;
				}
			}
			if (instruction.getFlowType().isCall()) {
				lowIsInput = false;
				highIsInput = false;
				continue;
			}
			if (lowIsInput && writesRegister(instruction, low)) {
				lowIsInput = false;
			}
			if (highIsInput && writesRegister(instruction, high)) {
				highIsInput = false;
			}
		}
		return false;
	}

	private boolean isBitBranch(String mnemonic) {
		return mnemonic.equals("jb") || mnemonic.equals("jnb") ||
			mnemonic.equals("jbc") || mnemonic.equals("jbs");
	}

	private int splitContradictedAnalysisPointers(Program program, Function function,
			Set<Integer> contradicted)
			throws DuplicateNameException, InvalidInputException {
		if (contradicted.isEmpty() || function.getSignatureSource() != SourceType.ANALYSIS) {
			return 0;
		}
		List<Variable> parameters = new ArrayList<>();
		int split = 0;
		for (Parameter parameter : function.getParameters()) {
			Integer start = parameterStart(parameter.getVariableStorage());
			boolean genericFunctionPointer =
				isGenericFunctionPointer(parameter.getFormalDataType());
			if (start != null && contradicted.contains(start) &&
				(isGenericVoidPointer(parameter.getFormalDataType()) ||
					genericFunctionPointer &&
						!C166CodePointerPhase.hasSemanticCodePointerEvidence(
							program, function, start)) &&
				parameter.getVariableStorage().size() == 4) {
				parameters.add(new ParameterImpl(null, Undefined.getUndefinedDataType(2), program));
				parameters.add(new ParameterImpl(null, Undefined.getUndefinedDataType(2), program));
				split++;
				continue;
			}
			parameters.add(new ParameterImpl(existingName(parameter),
				parameter.getFormalDataType(), program));
		}
		if (split != 0) {
			function.updateFunction(CALLING_CONVENTION, null, parameters,
				FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
		}
		return split;
	}

	private boolean isGenericVoidPointer(DataType type) {
		Pointer pointer = pointerDataType(type);
		return pointer != null && type.getLength() == 4 &&
			!isFunctionPointer(type) && isVoidType(pointer.getDataType());
	}

	private void scanConstantCallers(Program program, Set<Function> callers,
			BasicBlockModel blocks, Map<Function, Map<Integer, Set<Address>>> occurrences,
			Map<Function, Map<Integer, Set<ConstantWordPair>>> constantPairs,
			Map<Function, Map<Integer, Set<Address>>> typedOccurrences,
			Set<Address> scannedCalls, Set<Function> discoveredTargets, TaskMonitor monitor)
			throws CancelledException {
		monitor.initialize(Math.max(1, callers.size()),
			"C166 far-pointer inference: scanning constant call arguments");
		for (Function caller : orderedFunctions(callers)) {
			monitor.checkCancelled();
			InstructionIterator instructions =
				program.getListing().getInstructions(caller.getBody(), true);
			while (instructions.hasNext()) {
				Instruction call = instructions.next();
				if (!call.getFlowType().isCall() || !scannedCalls.add(call.getAddress())) {
					continue;
				}
				Function target = directTarget(program, call);
				if (target == null || !mayAnalyze(target)) {
					continue;
				}
				discoveredTargets.add(target);
				C166TaskingCallArguments.CallWords words =
					C166TaskingCallArguments.recover(program, caller, call, blocks, monitor);
				for (Map.Entry<Integer, C166TaskingCallArguments.WordValue> entry :
						words.words().entrySet()) {
					int start = entry.getKey();
					if (!isLegalPairStart(start) ||
						(start >= 4 && !words.registerBankOccupied())) {
						continue;
					}
					C166TaskingCallArguments.WordValue low = entry.getValue();
					C166TaskingCallArguments.WordValue high = words.words().get(start + 1);
					if (isTypedPointerOrigin(low, high)) {
						typedOccurrences.computeIfAbsent(target, ignored -> new HashMap<>())
							.computeIfAbsent(start, ignored -> new HashSet<>())
							.add(call.getAddress());
					}
					if (low != null && high != null && low.constant() != null &&
						high.constant() != null) {
						constantPairs.computeIfAbsent(target, ignored -> new HashMap<>())
							.computeIfAbsent(start, ignored -> new HashSet<>())
							.add(new ConstantWordPair(low.constant(), high.constant()));
					}
					if (!isUnambiguousConstantDataPointer(program, low, high)) {
						continue;
					}
					occurrences.computeIfAbsent(target, ignored -> new HashMap<>())
						.computeIfAbsent(start, ignored -> new HashSet<>())
						.add(call.getAddress());
				}
			}
			monitor.incrementProgress(1);
		}
	}

	/**
	 * A caller's already recovered data-pointer parameter is positive evidence for
	 * the corresponding callee pair.  Require both OFFSET and PAGE words to come
	 * from the same four-byte parameter in documented low/high order; a typed word
	 * on only one side, an fpointer, and two unrelated pointer parameters are not
	 * enough.  The call-site seeder additionally requires two distinct calls so a
	 * single stale signature cannot create a new formal parameter by itself.
	 */
	private boolean isTypedPointerOrigin(C166TaskingCallArguments.WordValue low,
			C166TaskingCallArguments.WordValue high) {
		if (low == null || high == null || low.parameterOrdinal() == null ||
			high.parameterOrdinal() == null ||
			!low.parameterOrdinal().equals(high.parameterOrdinal()) ||
			low.byteOffset() != 0 || high.byteOffset() != 2 ||
			low.originType() == null || high.originType() == null ||
			!low.originType().isEquivalent(high.originType())) {
			return false;
		}
		DataType type = low.originType();
		return isPointerType(type) && !isFunctionPointer(type) && type.getLength() == 4;
	}

	private boolean isUnambiguousConstantDataPointer(Program program,
			C166TaskingCallArguments.WordValue low,
			C166TaskingCallArguments.WordValue high) {
		if (low == null || high == null || low.constant() == null ||
			high.constant() == null) {
			return false;
		}
		long page = high.constant();
		long offset = low.constant();
		if (page <= 0xff || page > 0x3ff || offset > 0x3fff) {
			return false;
		}
		return physicalPointerAddress(program, page, offset) != null;
	}

	private boolean overlapsExistingPointer(Function function, int candidateStart) {
		for (Parameter parameter : function.getParameters()) {
			Integer start = parameterStart(parameter.getVariableStorage());
			if (start == null || !isPointerType(parameter.getFormalDataType())) {
				continue;
			}
			int span = Math.max(1, parameter.getVariableStorage().size() / 2);
			if (candidateStart < start + span && start < candidateStart + 2) {
				return true;
			}
		}
		return false;
	}

	private Set<Integer> existingParameterSlots(Function function) {
		Set<Integer> slots = new HashSet<>();
		for (Parameter parameter : function.getParameters()) {
			Integer start = parameterStart(parameter.getVariableStorage());
			if (start == null) {
				continue;
			}
			int span = Math.max(1, parameter.getVariableStorage().size() / 2);
			for (int slot = start; slot < start + span; slot++) {
				slots.add(slot);
			}
		}
		return slots;
	}

	private Function directTarget(Program program, Instruction instruction) {
		for (Address flow : instruction.getFlows()) {
			Function target = program.getFunctionManager().getFunctionAt(flow);
			if (target != null) {
				return target;
			}
		}
		for (Reference reference : instruction.getReferencesFrom()) {
			if (reference.getReferenceType().isCall()) {
				Function target = program.getFunctionManager()
					.getFunctionAt(reference.getToAddress());
				if (target != null) {
					return target;
				}
			}
		}
		return null;
	}

	private record CallSiteSeedStats(int functions, int parameters, int occurrences,
			int scalarConflicts, int repairedPointers,
			Map<Function, Set<Integer>> scalarPairs,
			Map<Function, Set<Integer>> strictScalarPairs) {
	}

	private record ConstantWordPair(long low, long high) {
	}

	private record FunctionSlot(Function function, int start) {
	}

	private record ScalarWordStore(Instruction instruction, Register base,
			Register page, int offset) {
	}

	private enum SymbolicWordKind {
		BASE_LOW, BASE_PAGE, FIELD_WORD
	}

	private record SymbolicWord(SymbolicWordKind kind, int parameterStart, int offset) {
	}

	private record PointerFieldUse(int parameterStart, int fieldOffset) {
	}

	private record CandidateGraph(Set<Function> functions,
			Map<Function, Set<Function>> callees) {
	}

	private record SccSchedule(List<List<Function>> components,
			List<List<Integer>> layers) {
	}

	private record DfsFrame(Function function, Iterator<Function> targets) {
	}

	private int removeLegacyCallReferences(Program program, AddressSetView set,
			boolean fullScan, TaskMonitor monitor)
			throws CancelledException {
		ReferenceManager references = program.getReferenceManager();
		InstructionIterator instructions = fullScan
				? program.getListing().getInstructions(true)
				: program.getListing().getInstructions(set, true);
		int removed = 0;
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = instructions.next();
			if (!instruction.getFlowType().isCall()) {
				continue;
			}
			for (Reference reference : instruction.getReferencesFrom()) {
				RefType type = reference.getReferenceType();
				if (reference.getOperandIndex() == Reference.MNEMONIC &&
					reference.getSource() == SourceType.ANALYSIS &&
					(type == RefType.DATA || type == RefType.READ)) {
					references.delete(reference);
					removed++;
				}
			}
		}
		return removed;
	}

	private int addFarPointerReferences(Program program, Iterator<PcodeOpAST> operations,
			AddressSet referenceSources) {
		ReferenceManager references = program.getReferenceManager();
		int added = 0;
		while (operations.hasNext()) {
			PcodeOpAST operation = operations.next();
			if (operation.getOpcode() != PcodeOp.CALL || operation.getNumInputs() < 2) {
				continue;
			}
			Function target = program.getFunctionManager()
				.getFunctionAt(operation.getInput(0).getAddress());
			if (target == null || !usesTaskingConvention(target)) {
				continue;
			}
			Parameter[] parameters = target.getParameters();
			int count = Math.min(parameters.length, operation.getNumInputs() - 1);
			for (int i = 0; i < count; i++) {
				DataType type = parameters[i].getFormalDataType();
				if (!(type instanceof Pointer) || type.getLength() != 4) {
					continue;
				}
				Address targetAddress = resolvePhysicalPointer(program, operation.getInput(i + 1),
					new HashSet<>(), 0);
				if (targetAddress == null || !program.getMemory().contains(targetAddress)) {
					continue;
				}
				Address callSource = operation.getSeqnum().getTarget();
				Address source = findPointerSetupSource(program, callSource, targetAddress,
					parameters[i].getVariableStorage());
				if (source == null) {
					source = callSource;
				}
				referenceSources.add(source);
				removeLegacyCallReference(references, callSource, targetAddress, source);
				Reference existing =
					references.getReference(source, targetAddress, Reference.MNEMONIC);
				if (existing == null) {
					references.addMemoryReference(source, targetAddress, RefType.PARAM,
						SourceType.ANALYSIS, Reference.MNEMONIC);
					added++;
				}
				else if (!existing.getReferenceType().isFlow() &&
					existing.getReferenceType() != RefType.PARAM) {
					references.updateRefType(existing, RefType.PARAM);
					added++;
				}
			}
		}
		return added;
	}

	private void removeLegacyCallReference(ReferenceManager references, Address callSource,
			Address targetAddress, Address replacementSource) {
		if (callSource.equals(replacementSource)) {
			return;
		}
		Reference legacy =
			references.getReference(callSource, targetAddress, Reference.MNEMONIC);
		if (legacy != null && legacy.getSource() == SourceType.ANALYSIS &&
			!legacy.getReferenceType().isFlow()) {
			references.delete(legacy);
		}
	}

	/**
	 * Match Ghidra's constant-propagation convention: a PARAM reference belongs
	 * to the instruction which materializes the argument, not to the call itself.
	 * A TASKING far pointer is materialized as its documented PAGE and OFFSET
	 * words, normally in the two registers assigned to the formal parameter.
	 */
	private Address findPointerSetupSource(Program program, Address callSource,
			Address targetAddress, VariableStorage storage) {
		long physical = targetAddress.getUnsignedOffset();
		long offset = physical & 0x3fff;
		long page = physical >>> 14;
		Register lowRegister = null;
		Register highRegister = null;
		List<Register> registers = storage.getRegisters();
		if (registers != null && registers.size() == 2) {
			Register first = registers.get(0);
			Register second = registers.get(1);
			Integer firstNumber = generalRegisterNumber(first);
			Integer secondNumber = generalRegisterNumber(second);
			if (firstNumber != null && secondNumber != null) {
				if (firstNumber < secondNumber) {
					lowRegister = first;
					highRegister = second;
				}
				else {
					lowRegister = second;
					highRegister = first;
				}
			}
		}

		Address source = scanPointerSetupSource(program, callSource, offset, page, lowRegister,
			highRegister);
		if (source != null || lowRegister == null || highRegister == null) {
			return source;
		}
		return scanPointerSetupSource(program, callSource, offset, page, null, null);
	}

	private Address scanPointerSetupSource(Program program, Address callSource, long offset,
			long page, Register lowRegister, Register highRegister) {
		Address lowSource = null;
		Address highSource = null;
		Function caller = program.getFunctionManager().getFunctionContaining(callSource);
		Instruction instruction = program.getListing().getInstructionBefore(callSource);
		for (int scanned = 0; instruction != null && scanned < MAX_SETUP_SCAN_INSTRUCTIONS;
				scanned++, instruction = program.getListing().getInstructionBefore(
					instruction.getAddress())) {
			if (caller != null && !caller.getBody().contains(instruction.getAddress())) {
				break;
			}
			Register destination = instruction.getRegister(0);
			Scalar immediate = instruction.getScalar(1);
			if (destination == null || immediate == null) {
				continue;
			}
			long value = immediate.getUnsignedValue();
			if (lowSource == null && value == offset &&
				(lowRegister == null || destination.equals(lowRegister))) {
				lowSource = instruction.getAddress();
			}
			if (highSource == null && value == page &&
				(highRegister == null || destination.equals(highRegister))) {
				highSource = instruction.getAddress();
			}
			if (lowSource != null && highSource != null) {
				if (lowRegister == null || highRegister == null) {
					// A stack argument has no identifying register pair and adjacent
					// far pointers commonly share the same PAGE.  OFFSET is unique;
					// anchoring there avoids borrowing a neighbour's PAGE setup.
					return lowSource;
				}
				// Anchor the reference where the second word completes the far
				// pointer, matching Ghidra's constant-propagation convention.
				return lowSource.compareTo(highSource) > 0 ? lowSource : highSource;
			}
		}
		if (lowSource != null) {
			return lowSource;
		}
		return highSource;
	}

	private Integer generalRegisterNumber(Register register) {
		if (register == null) {
			return null;
		}
		String name = register.getName().toLowerCase();
		if (!name.matches("r(?:[0-9]|1[0-5])")) {
			return null;
		}
		return Integer.parseInt(name.substring(1));
	}

	private void scheduleReferenceAnalysis(Program program, AddressSet referenceSources) {
		if (referenceSources.isEmpty()) {
			return;
		}
		AutoAnalysisManager.getAnalysisManager(program).scheduleOneTimeAnalysis(
			new OperandReferenceAnalyzer(), referenceSources);
	}

	private Address resolvePhysicalPointer(Program program, Varnode value,
			Set<Varnode> visited, int depth) {
		if (value == null || depth > MAX_TRACE_DEPTH || !visited.add(value)) {
			return null;
		}
		if (value.isConstant()) {
			return normalizePointerAddress(program, value.getOffset());
		}
		if (value.getDef() == null) {
			return null;
		}
		PcodeOp definition = value.getDef();
		switch (definition.getOpcode()) {
			case PcodeOp.COPY:
			case PcodeOp.CAST:
			case PcodeOp.INT_ZEXT:
				return resolvePhysicalPointer(program, definition.getInput(0), visited, depth + 1);
			case PcodeOp.SEGMENTOP:
				if (definition.getNumInputs() == 3) {
					Long page = constantValue(definition.getInput(1), new HashSet<>(), 0);
					Long offset = constantValue(definition.getInput(2), new HashSet<>(), 0);
					if (page != null && offset != null) {
						return physicalPointerAddress(program, page, offset);
					}
				}
				return null;
			case PcodeOp.PIECE:
				if (definition.getNumInputs() == 2) {
					Long page = constantValue(definition.getInput(0), new HashSet<>(), 0);
					Long offset = constantValue(definition.getInput(1), new HashSet<>(), 0);
					if (page != null && offset != null) {
						return physicalPointerAddress(program, page, offset);
					}
				}
				return null;
			case PcodeOp.PTRSUB:
			case PcodeOp.PTRADD:
				Address address = HighFunctionDBUtil.getSpacebaseReferenceAddress(
					program.getAddressFactory(), definition);
				if (address == null && definition.getNumInputs() > 1 &&
					definition.getInput(1).isConstant()) {
					return normalizePointerAddress(program,
						definition.getInput(1).getOffset());
				}
				return address == null ? null :
					normalizePointerAddress(program, address.getUnsignedOffset());
			default:
				return null;
		}
	}

	private Address physicalPointerAddress(Program program, long page, long offset) {
		long physical = ((page & 0x3ff) << 14) | (offset & 0x3fff);
		Address address = address(program.getLanguage().getDefaultDataSpace(), physical);
		return address != null && program.getMemory().contains(address) ? address : null;
	}

	private Long constantValue(Varnode value, Set<Varnode> visited, int depth) {
		if (value == null || depth > MAX_TRACE_DEPTH || !visited.add(value)) {
			return null;
		}
		if (value.isConstant()) {
			return value.getOffset();
		}
		PcodeOp definition = value.getDef();
		if (definition == null) {
			return null;
		}
		switch (definition.getOpcode()) {
			case PcodeOp.COPY:
			case PcodeOp.CAST:
			case PcodeOp.INT_ZEXT:
			case PcodeOp.INT_SEXT:
				return constantValue(definition.getInput(0), visited, depth + 1);
			case PcodeOp.INT_AND:
			case PcodeOp.INT_OR:
			case PcodeOp.INT_ADD:
			case PcodeOp.INT_SUB:
				Long left = constantValue(definition.getInput(0), visited, depth + 1);
				Long right = constantValue(definition.getInput(1), visited, depth + 1);
				if (left == null || right == null) {
					return null;
				}
				return switch (definition.getOpcode()) {
					case PcodeOp.INT_AND -> left & right;
					case PcodeOp.INT_OR -> left | right;
					case PcodeOp.INT_ADD -> left + right;
					default -> left - right;
				};
			default:
				return null;
		}
	}

	private Address normalizePointerAddress(Program program, long value) {
		AddressSpace space = program.getLanguage().getDefaultDataSpace();
		Address direct = address(space, value);
		if (direct != null && program.getMemory().contains(direct)) {
			return direct;
		}

		// TASKING Classic stores a far pointer as PAGE:OFFSET, while the
		// program database uses the physical 24-bit address.  Defined string
		// constants can retain the raw encoding in high p-code, so decode it
		// only when the direct value is not a mapped program address.
		long page = (value >>> 16) & 0xffff;
		long offset = value & 0xffff;
		long physical = ((page & 0x3ff) << 14) | (offset & 0x3fff);
		Address decoded = address(space, physical);
		if (decoded != null && program.getMemory().contains(decoded)) {
			return decoded;
		}
		return direct;
	}

	private Address address(AddressSpace space, long offset) {
		try {
			return space.getAddress(offset, true);
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

	private CandidateGraph buildCandidateGraph(Program program, AddressSetView set,
			boolean fullScan, TaskMonitor monitor)
			throws CancelledException {
		Set<Function> candidates = new HashSet<>();
		List<Function> typedTargets = new ArrayList<>();
		ArrayDeque<Function> frontier = new ArrayDeque<>();
		Set<Function> expanded = new HashSet<>();
		Iterator<Function> functions = fullScan
				? program.getFunctionManager().getFunctions(true)
				: program.getFunctionManager().getFunctionsOverlapping(set);
		List<Function> scopedFunctions = new ArrayList<>();
		functions.forEachRemaining(scopedFunctions::add);
		monitor.initialize(Math.max(1, scopedFunctions.size()),
			"C166 far-pointer inference: scanning functions");
		for (Function function : scopedFunctions) {
			monitor.checkCancelled();
			if (hasFarPointerParameter(function) && usesTaskingConvention(function)) {
				typedTargets.add(function);
			}
			if (mayAnalyze(function) &&
				(!fullScan || containsDynamicPagedAccessSetup(program, function))) {
				if (candidates.add(function)) {
					frontier.addLast(function);
				}
			}
			monitor.incrementProgress(1);
		}
		frontier.addAll(typedTargets);
		monitor.setMessage("C166 far-pointer inference: expanding forwarding callers");
		while (!frontier.isEmpty()) {
			monitor.checkCancelled();
			Function target = frontier.removeFirst();
			if (!expanded.add(target)) {
				continue;
			}
			for (Function caller : directCallers(program, target)) {
				if (caller != target && mayAnalyze(caller) &&
					(fullScan || caller.getBody().intersects(set)) && candidates.add(caller)) {
					frontier.addLast(caller);
				}
			}
		}

		monitor.initialize(Math.max(1, candidates.size()),
			"C166 far-pointer inference: building candidate call graph");
		Map<Function, Set<Function>> callees = new HashMap<>();
		for (Function function : orderedFunctions(candidates)) {
			monitor.checkCancelled();
			Set<Function> relevant = new HashSet<>();
			for (Function target : directTargets(program, function)) {
				if (candidates.contains(target)) {
					relevant.add(target);
				}
			}
			callees.put(function, Set.copyOf(relevant));
			monitor.incrementProgress(1);
		}
		return new CandidateGraph(Set.copyOf(candidates), Map.copyOf(callees));
	}

	private Set<Function> directCallers(Program program, Function target) {
		Set<Function> callers = new HashSet<>();
		ReferenceIterator references =
			program.getReferenceManager().getReferencesTo(target.getEntryPoint());
		while (references.hasNext()) {
			Reference reference = references.next();
			RefType type = reference.getReferenceType();
			if (!type.isCall() && !type.isJump()) {
				continue;
			}
			Function caller = program.getFunctionManager()
				.getFunctionContaining(reference.getFromAddress());
			if (caller != null) {
				callers.add(caller);
			}
		}
		return callers;
	}

	private Set<Function> directTargets(Program program, Function caller) {
		Set<Function> targets = new HashSet<>();
		InstructionIterator instructions =
			program.getListing().getInstructions(caller.getBody(), true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			if (!instruction.getFlowType().isCall() &&
				!instruction.getFlowType().isJump()) {
				continue;
			}
			for (Reference reference : instruction.getReferencesFrom()) {
				RefType type = reference.getReferenceType();
				if (!type.isCall() && !type.isJump()) {
					continue;
				}
				Function target = program.getFunctionManager()
					.getFunctionAt(reference.getToAddress());
				if (target != null) {
					targets.add(target);
				}
			}
			for (Address flow : instruction.getFlows()) {
				Function target = program.getFunctionManager().getFunctionAt(flow);
				if (target != null) {
					targets.add(target);
				}
			}
		}
		return targets;
	}

	private SccSchedule buildSccSchedule(CandidateGraph graph, TaskMonitor monitor)
			throws CancelledException {
		Map<Function, Set<Function>> reverse = new HashMap<>();
		for (Function function : graph.functions()) {
			reverse.put(function, new HashSet<>());
		}
		for (Map.Entry<Function, Set<Function>> entry : graph.callees().entrySet()) {
			for (Function target : entry.getValue()) {
				reverse.get(target).add(entry.getKey());
			}
		}

		monitor.initialize(Math.max(1, graph.functions().size()),
			"C166 far-pointer inference: ordering call graph");
		List<Function> finishOrder = new ArrayList<>();
		Set<Function> visited = new HashSet<>();
		for (Function root : orderedFunctions(graph.functions())) {
			monitor.checkCancelled();
			if (!visited.add(root)) {
				continue;
			}
			ArrayDeque<DfsFrame> stack = new ArrayDeque<>();
			stack.push(new DfsFrame(root,
				orderedFunctions(graph.callees().getOrDefault(root, Set.of())).iterator()));
			while (!stack.isEmpty()) {
				monitor.checkCancelled();
				DfsFrame frame = stack.peek();
				if (frame.targets().hasNext()) {
					Function target = frame.targets().next();
					if (visited.add(target)) {
						stack.push(new DfsFrame(target, orderedFunctions(
							graph.callees().getOrDefault(target, Set.of())).iterator()));
					}
				}
				else {
					stack.pop();
					finishOrder.add(frame.function());
					monitor.incrementProgress(1);
				}
			}
		}

		List<List<Function>> components = new ArrayList<>();
		Set<Function> assigned = new HashSet<>();
		for (int i = finishOrder.size() - 1; i >= 0; i--) {
			monitor.checkCancelled();
			Function root = finishOrder.get(i);
			if (!assigned.add(root)) {
				continue;
			}
			List<Function> component = new ArrayList<>();
			ArrayDeque<Function> stack = new ArrayDeque<>();
			stack.push(root);
			while (!stack.isEmpty()) {
				Function function = stack.pop();
				component.add(function);
				for (Function caller : reverse.getOrDefault(function, Set.of())) {
					if (assigned.add(caller)) {
						stack.push(caller);
					}
				}
			}
			component.sort(Comparator.comparing(Function::getEntryPoint));
			components.add(List.copyOf(component));
		}

		Map<Function, Integer> componentOf = new HashMap<>();
		for (int i = 0; i < components.size(); i++) {
			for (Function function : components.get(i)) {
				componentOf.put(function, i);
			}
		}
		List<Set<Integer>> dependencies = new ArrayList<>();
		List<Set<Integer>> callers = new ArrayList<>();
		for (int i = 0; i < components.size(); i++) {
			dependencies.add(new HashSet<>());
			callers.add(new HashSet<>());
		}
		for (Map.Entry<Function, Set<Function>> entry : graph.callees().entrySet()) {
			int callerComponent = componentOf.get(entry.getKey());
			for (Function target : entry.getValue()) {
				int targetComponent = componentOf.get(target);
				if (callerComponent != targetComponent &&
					dependencies.get(callerComponent).add(targetComponent)) {
					callers.get(targetComponent).add(callerComponent);
				}
			}
		}

		int[] remainingDependencies = new int[components.size()];
		List<Integer> ready = new ArrayList<>();
		for (int i = 0; i < components.size(); i++) {
			remainingDependencies[i] = dependencies.get(i).size();
			if (remainingDependencies[i] == 0) {
				ready.add(i);
			}
		}
		Comparator<Integer> componentOrder = Comparator.comparing(
			i -> components.get(i).get(0).getEntryPoint());
		List<List<Integer>> layers = new ArrayList<>();
		int scheduled = 0;
		while (!ready.isEmpty()) {
			ready.sort(componentOrder);
			List<Integer> layer = List.copyOf(ready);
			layers.add(layer);
			scheduled += layer.size();
			Set<Integer> next = new HashSet<>();
			for (int completed : layer) {
				for (int caller : callers.get(completed)) {
					remainingDependencies[caller]--;
					if (remainingDependencies[caller] == 0) {
						next.add(caller);
					}
				}
			}
			ready = new ArrayList<>(next);
		}
		if (scheduled != components.size()) {
			throw new IllegalStateException("SCC condensation graph contains a cycle");
		}
		return new SccSchedule(List.copyOf(components), List.copyOf(layers));
	}

	private List<Function> orderedFunctions(Set<Function> functions) {
		List<Function> ordered = new ArrayList<>(functions);
		ordered.sort(Comparator.comparing(Function::getEntryPoint));
		return ordered;
	}

	private boolean mayAnalyze(Function function) {
		// Recovered arguments after the fixed prefix of a variadic function are
		// call-site values, not additional formal parameters.  Extending such a
		// signature corrupts both the declared ABI and later prototype overrides.
		return !function.isExternal() && !function.isThunk() && !function.hasVarArgs() &&
			function.getCallFixup() == null &&
			mayUpdate(function) && usesTaskingConvention(function);
	}

	private boolean hasFarPointerParameter(Function function) {
		for (Parameter parameter : function.getParameters()) {
			if (parameter.getFormalDataType() instanceof Pointer &&
				parameter.getFormalDataType().getLength() == 4) {
				return true;
			}
		}
		return false;
	}

	private boolean usesTaskingConvention(Function function) {
		String name = function.getCallingConventionName();
		return CALLING_CONVENTION.equals(name) ||
			Function.DEFAULT_CALLING_CONVENTION_STRING.equals(name) ||
			Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(name);
	}

	private boolean mayUpdate(Function function) {
		SourceType source = function.getSignatureSource();
		return source == SourceType.DEFAULT || source == SourceType.ANALYSIS;
	}

	private boolean containsDynamicPagedAccessSetup(Program program, Function function) {
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			Register pageSource = dynamicPageSource(instruction);
			if (pageSource != null && pageMayCarryPointerInput(program, function,
				instruction, pageSource)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Decide whether a dynamic PAGE setup belongs to one particular incoming
	 * argument pair.  A function can dereference a returned/local far pointer and
	 * still consume two unrelated scalar arguments; an unrelated EXTP must not
	 * defeat the complete call-site rectangle proof for those arguments.
	 */
	private boolean containsDynamicPagedAccessSetupForPair(Program program,
			Function function, int pairStart) {
		if (pairStart >= 4) {
			return containsDynamicPagedAccessSetup(program, function);
		}
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			Register source = dynamicPageSource(instruction);
			Integer slot = source == null ? null : tracePageSourceToInputSlot(program,
				function, instruction, source);
			if (slot != null && slot == pairStart + 1) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Recover direct architectural data use from the listing as well as p-code.
	 * A stale fpointer HighSymbol can cause the decompiler to replace the original
	 * EXTP/DPP address construction with a typed PIECE, so p-code alone would make
	 * the old inferred type self-supporting.
	 */
	private boolean containsDirectPagedDataUseForPair(Program program,
			Function function, int pairStart) {
		if (pairStart < 0 || pairStart >= 4) {
			return false;
		}
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			Instruction setup = instructions.next();
			Register page = dynamicPageSource(setup);
			Integer pageSlot = page == null ? null : tracePageSourceToInputSlot(program,
				function, setup, page);
			if (pageSlot == null || pageSlot != pairStart + 1) {
				continue;
			}
			int remaining = pageAccessCount(setup);
			Instruction access = program.getListing().getInstructionAfter(setup.getAddress());
			while (access != null && remaining-- > 0 &&
				function.getBody().contains(access.getAddress())) {
				for (int operand = 0; operand < access.getNumOperands(); operand++) {
					String spelling = access.getDefaultOperandRepresentation(operand).trim();
					if (!spelling.startsWith("[")) {
						continue;
					}
					Register base = operandRegister(access, operand);
					Integer offsetSlot = base == null ? null : tracePageSourceToInputSlot(
						program, function, access, base);
					if (offsetSlot != null && offsetSlot == pairStart) {
						return true;
					}
				}
				access = program.getListing().getInstructionAfter(access.getAddress());
			}
		}
		return false;
	}

	private Integer tracePageSourceToInputSlot(Program program, Function function,
			Instruction setup, Register source) {
		Register traced = source;
		Instruction instruction = program.getListing().getInstructionBefore(setup.getAddress());
		for (int scanned = 0; instruction != null && scanned < MAX_SETUP_SCAN_INSTRUCTIONS;
				scanned++, instruction =
					program.getListing().getInstructionBefore(instruction.getAddress())) {
			if (!function.getBody().contains(instruction.getAddress())) {
				break;
			}
			if (instruction.getFlowType().isCall() || instruction.getFlowType().isJump()) {
				return null;
			}
			if (!writesRegister(instruction, traced)) {
				continue;
			}
			if (!instruction.getMnemonicString().equalsIgnoreCase("mov") ||
				instruction.getNumOperands() < 2 ||
				OperandType.isIndirect(instruction.getOperandType(1))) {
				return null;
			}
			Register previous = operandRegister(instruction, 1);
			if (previous == null) {
				return null;
			}
			traced = previous;
		}
		return argumentSlot(traced);
	}

	private Register dynamicPageSource(Instruction instruction) {
		String mnemonic = instruction.getMnemonicString().toLowerCase();
		if ((mnemonic.equals("extp") || mnemonic.equals("extpr")) &&
			instruction.getNumOperands() != 0) {
			Register source = operandRegister(instruction, 0);
			if (source != null) {
				return source;
			}
			// C166 EXTP's register and count are represented as one composite
			// operand by the listing API, so getOpObjects(0) may omit the register.
			for (Object input : instruction.getInputObjects()) {
				if (input instanceof Register register) {
					return register;
				}
			}
			return null;
		}
		if (!mnemonic.equals("mov") || instruction.getNumOperands() < 2) {
			return null;
		}
		for (Object result : instruction.getResultObjects()) {
			if (result instanceof Register register &&
				"dpp0".equalsIgnoreCase(register.getName())) {
				Register source = operandRegister(instruction, 1);
				// R0 is the stack pointer; MOV DPP0,[R0+] is a restore, not
				// dynamic PAGE evidence.
				return source != null && !"r0".equalsIgnoreCase(source.getName()) ?
					source : null;
			}
		}
		return null;
	}

	private Register operandRegister(Instruction instruction, int operand) {
		for (Object object : instruction.getOpObjects(operand)) {
			if (object instanceof Register register) {
				return register;
			}
		}
		return null;
	}

	/**
	 * Cheaply reject the overwhelmingly common constant/local page setups before
	 * invoking the decompiler.  Walk backwards through straight-line register
	 * copies.  Any control-flow or unrecognized definition remains a candidate;
	 * this is a conservative prefilter, not pointer evidence.
	 */
	private boolean pageMayCarryPointerInput(Program program, Function function,
			Instruction setup, Register source) {
		Register traced = source;
		Instruction instruction = program.getListing().getInstructionBefore(setup.getAddress());
		int scanned = 0;
		for (; instruction != null && scanned < MAX_SETUP_SCAN_INSTRUCTIONS;
				scanned++, instruction =
					program.getListing().getInstructionBefore(instruction.getAddress())) {
			if (!function.getBody().contains(instruction.getAddress())) {
				break;
			}
			if (instruction.getFlowType().isJump() || instruction.getFlowType().isCall()) {
				return true;
			}
			if (!writesRegister(instruction, traced)) {
				continue;
			}
			if (!instruction.getMnemonicString().equalsIgnoreCase("mov") ||
				instruction.getNumOperands() < 2) {
				// Arithmetic such as OFFSET adjustment preserves possible input
				// provenance; anything else is deliberately kept conservative.
				return true;
			}
			int sourceType = instruction.getOperandType(1);
			Register previous = operandRegister(instruction, 1);
			if (previous != null && !OperandType.isIndirect(sourceType)) {
				if ("r0".equalsIgnoreCase(previous.getName())) {
					return true;
				}
				if (previous.getName().toLowerCase().startsWith("dpp")) {
					return false;
				}
				traced = previous;
				continue;
			}
			if (OperandType.isScalar(sourceType) && !OperandType.isAddress(sourceType) &&
				!OperandType.isIndirect(sourceType)) {
				return false;
			}
			// Stack and absolute-memory loads can carry spilled parameters or
			// adjacent global PAGE:OFFSET words and require full p-code analysis.
			return true;
		}
		if (instruction != null && function.getBody().contains(instruction.getAddress())) {
			// The bounded prefilter ran out of history.  Keep the candidate so a
			// long function cannot turn this performance optimization into a
			// false negative.
			return true;
		}
		return argumentSlot(traced) != null;
	}

	private boolean writesRegister(Instruction instruction, Register expected) {
		for (Object result : instruction.getResultObjects()) {
			if (result instanceof Register actual && overlaps(expected, actual)) {
				return true;
			}
		}
		return false;
	}

	private Inference inferPairs(Program program, Function function,
			HighFunction highFunction) {
		Map<Integer, Integer> scores = new HashMap<>();
		Set<Integer> liveSlots = new HashSet<>();
		Set<Integer> directPagedPairs = new HashSet<>();
		Map<Integer, DataType> pointerTypes = new HashMap<>();
		Set<Address> globalPointerStarts = new HashSet<>();
		Iterator<PcodeOpAST> operations = highFunction.getPcodeOps();
		while (operations.hasNext()) {
			PcodeOpAST operation = operations.next();
			for (int i = 0; i < operation.getNumInputs(); i++) {
				liveSlots.addAll(traceParameterWords(program, operation.getInput(i), 0,
					new HashSet<>()));
			}
			if (operation.getOpcode() == PcodeOp.CALL) {
				scoreForwardedPointers(program, operation, scores, pointerTypes,
					globalPointerStarts);
			}
			RecoveredParameterPointer recoveredParameter =
				recoveredParameterFarPointer(operation);
			if (recoveredParameter != null) {
				int start = recoveredParameter.start();
				scores.merge(start, 1, Integer::sum);
				liveSlots.add(start);
				liveSlots.add(start + 1);
				directPagedPairs.add(start);
				mergePointerType(program, pointerTypes, start, recoveredParameter.type());
			}
			Address recoveredGlobal = recoveredGlobalFarPointerStart(operation);
			if (recoveredGlobal != null) {
				globalPointerStarts.add(recoveredGlobal);
			}
			Address directGlobal = directPagedGlobalPairStart(program, function, operation);
			if (directGlobal != null) {
				globalPointerStarts.add(directGlobal);
			}
			Varnode page;
			Varnode offset;
			boolean directPagedAccess =
				operation.getOpcode() == PcodeOp.SEGMENTOP && operation.getNumInputs() == 3;
			if (directPagedAccess) {
				page = operation.getInput(1);
				offset = operation.getInput(2);
			}
			else if (isExplicitRegisterExtpAddress(program, operation)) {
				Varnode[] pair = explicitRegisterExtpPair(operation);
				page = pair[0];
				offset = pair[1];
				directPagedAccess = true;
			}
			else if (isTypedFarPointerPiece(operation)) {
				page = operation.getInput(0);
				offset = operation.getInput(1);
			}
			else {
				continue;
			}
			Integer start = scorePairSources(program, page, offset, scores);
			if (start != null && directPagedAccess) {
				directPagedPairs.add(start);
			}
			Address globalStart = globalPairStart(program, page, offset);
			if (globalStart != null) {
				globalPointerStarts.add(globalStart);
			}
			DataType pointerType = typedPointerType(operation);
			if (start != null && pointerType != null) {
				mergePointerType(program, pointerTypes, start, pointerType);
			}
		}
		scoreRecoveredPointerParameters(program, highFunction, scores, liveSlots,
			pointerTypes);
		scoreIdentityTailCall(program, function, scores, liveSlots, pointerTypes);

		List<Integer> candidates = new ArrayList<>(scores.keySet());
		Collections.sort(candidates);
		Selection selection = selectPairs(candidates, scores, 0, new HashMap<>());
		pointerTypes.keySet().retainAll(selection.starts());
		return new Inference(selection.starts(), liveSlots, pointerTypes,
			globalPointerStarts, directPagedPairs,
			selection.ambiguous() && selection.score() != 0);
	}

	/**
	 * Recognize an incoming stack far pointer after the patched decompiler has
	 * already rejoined its two TASKING words.  A positive, aligned four-byte stack
	 * input used directly as a data LOAD/STORE address is parameter evidence; a
	 * local stack value has a definition and a scalar input is not pointer-typed.
	 * {@link #retainSupportedPairs(Function, Set, Set)} still requires all four
	 * register argument words to be occupied before accepting any stack argument.
	 */
	private RecoveredParameterPointer recoveredParameterFarPointer(PcodeOp operation) {
		if ((operation.getOpcode() != PcodeOp.LOAD &&
			operation.getOpcode() != PcodeOp.STORE) || operation.getNumInputs() < 2) {
			return null;
		}
		Varnode address = operation.getInput(1);
		Address storage = address.getAddress();
		if (!address.isInput() || address.getDef() != null || address.getSize() != 4 ||
			storage == null || !storage.isStackAddress() || storage.getOffset() < 0 ||
			(storage.getOffset() & 1) != 0 || address.getHigh() == null) {
			return null;
		}
		DataType type = address.getHigh().getDataType();
		if (!isPointerType(type) || isFunctionPointer(type) || type.getLength() != 4) {
			return null;
		}
		long word = storage.getOffset() / 2;
		if (word > Integer.MAX_VALUE - 5) {
			return null;
		}
		return new RecoveredParameterPointer(4 + (int) word, type);
	}

	/**
	 * Recognize a global far pointer after the patched decompiler has already
	 * rejoined its adjacent OFFSET/PAGE loads.  The resulting four-byte,
	 * address-tied HighVariable is used directly as the address of a data
	 * LOAD/STORE, so no SEGMENTOP or PIECE remains for the older paths below.
	 */
	private Address recoveredGlobalFarPointerStart(PcodeOp operation) {
		if ((operation.getOpcode() != PcodeOp.LOAD &&
			operation.getOpcode() != PcodeOp.STORE) || operation.getNumInputs() < 2) {
			return null;
		}
		Varnode address = operation.getInput(1);
		Address storage = address.getAddress();
		if (address.getSize() != 4 || storage == null || !storage.isMemoryAddress() ||
			address.getHigh() == null) {
			return null;
		}
		DataType type = address.getHigh().getDataType();
		return isPointerType(type) && !isFunctionPointer(type) && type.getLength() == 4
			? storage : null;
	}

	/**
	 * Recover a global PAGE:OFFSET pair from the architectural EXTP/DPP setup when
	 * the decompiler represents the following access as a plain LOAD/STORE in a
	 * context-selected space.  This form carries no SEGMENTOP page input, so the
	 * listing is the authoritative source for the page word.
	 */
	private Address directPagedGlobalPairStart(Program program, Function function,
			PcodeOpAST operation) {
		if ((operation.getOpcode() != PcodeOp.LOAD &&
			operation.getOpcode() != PcodeOp.STORE) || operation.getNumInputs() < 2) {
			return null;
		}
		Address accessAddress = operation.getSeqnum().getTarget();
		ProgramContext context = program.getProgramContext();
		if (!isContextOne(context, "ExtpEn", accessAddress)) {
			return null;
		}
		Address lowAddress = traceGlobalWordAddress(program, operation.getInput(1), 0,
			new HashSet<>());
		if (lowAddress == null) {
			return null;
		}

		Instruction setup = program.getListing().getInstructionBefore(accessAddress);
		for (int scanned = 0; setup != null && scanned < 4;
				scanned++, setup = program.getListing().getInstructionBefore(setup.getAddress())) {
			if (!function.getBody().contains(setup.getAddress()) ||
				setup.getFlowType().isCall() || setup.getFlowType().isJump()) {
				return null;
			}
			Register pageSource = dynamicPageSource(setup);
			if (pageSource == null) {
				continue;
			}
			Address highAddress = traceRegisterToGlobalWord(program, function, setup,
				pageSource);
			if (highAddress == null ||
				!highAddress.getAddressSpace().equals(lowAddress.getAddressSpace())) {
				return null;
			}
			try {
				return highAddress.equals(lowAddress.add(2)) ? lowAddress : null;
			}
			catch (AddressOutOfBoundsException e) {
				return null;
			}
		}
		return null;
	}

	private Address traceRegisterToGlobalWord(Program program, Function function,
			Instruction setup, Register source) {
		Register traced = source;
		Instruction instruction = program.getListing().getInstructionBefore(setup.getAddress());
		for (int scanned = 0; instruction != null && scanned < MAX_SETUP_SCAN_INSTRUCTIONS;
				scanned++, instruction =
					program.getListing().getInstructionBefore(instruction.getAddress())) {
			if (!function.getBody().contains(instruction.getAddress()) ||
				instruction.getFlowType().isCall() || instruction.getFlowType().isJump()) {
				return null;
			}
			if (!writesRegister(instruction, traced)) {
				continue;
			}
			if (!instruction.getMnemonicString().equalsIgnoreCase("mov") ||
				instruction.getNumOperands() < 2 ||
				OperandType.isIndirect(instruction.getOperandType(1))) {
				return null;
			}
			Address global = null;
			for (Reference reference : instruction.getReferencesFrom()) {
				if (!reference.getReferenceType().isRead() ||
					!reference.getToAddress().isMemoryAddress()) {
					continue;
				}
				if (global != null && !global.equals(reference.getToAddress())) {
					return null;
				}
				global = reference.getToAddress();
			}
			if (global != null) {
				return global;
			}
			Register previous = operandRegister(instruction, 1);
			if (previous == null) {
				return null;
			}
			traced = previous;
		}
		return null;
	}

	/**
	 * Compatibility recovery for register-mode EXTP represented as explicit
	 * {@code (page << 14) + inner} p-code.  Current TASKING Classic Large
	 * injection emits SEGMENTOP directly; retain this path for incomplete or
	 * legacy injection contexts, and require decode context to prove EXTP.
	 */
	private boolean isExplicitRegisterExtpAddress(Program program, PcodeOpAST operation) {
		if (operation.getOpcode() != PcodeOp.INT_ADD || operation.getNumInputs() != 2 ||
			explicitRegisterExtpPair(operation) == null) {
			return false;
		}
		Address address = operation.getSeqnum().getTarget();
		ProgramContext context = program.getProgramContext();
		return isContextOne(context, "ExtpEn", address) &&
			isContextOne(context, "ExtpRegMode", address);
	}

	private Varnode[] explicitRegisterExtpPair(PcodeOp operation) {
		for (int pageInput = 0; pageInput < 2; pageInput++) {
			Varnode page = shiftedPageSource(operation.getInput(pageInput));
			if (page != null) {
				return new Varnode[] { page, operation.getInput(1 - pageInput) };
			}
		}
		return null;
	}

	private Varnode shiftedPageSource(Varnode value) {
		PcodeOp definition = value == null ? null : value.getDef();
		if (definition == null || definition.getNumInputs() != 2) {
			return null;
		}
		if (definition.getOpcode() == PcodeOp.INT_LEFT &&
			definition.getInput(1).isConstant() &&
			definition.getInput(1).getOffset() == 14) {
			return definition.getInput(0);
		}
		if (definition.getOpcode() == PcodeOp.INT_MULT) {
			for (int i = 0; i < 2; i++) {
				if (definition.getInput(i).isConstant() &&
					definition.getInput(i).getOffset() == 0x4000) {
					return definition.getInput(1 - i);
				}
			}
		}
		return null;
	}

	private boolean isContextOne(ProgramContext context, String registerName,
			Address address) {
		Register register = context.getRegister(registerName);
		BigInteger value = register == null ? null : context.getValue(register, address, false);
		return BigInteger.ONE.equals(value);
	}

	/**
	 * Preserve a pointer parameter which the decompiler recovered from typed data
	 * flow even when the Program DB still describes the same ABI storage as two
	 * words.  A split candidate is accepted only if both documented adjacent
	 * PAGE:OFFSET slots are existing HighFunction parameters; this never invents
	 * a missing stack word or joins an arbitrary scalar pair.
	 */
	private void scoreRecoveredPointerParameters(Program program,
			HighFunction highFunction, Map<Integer, Integer> scores,
			Set<Integer> liveSlots, Map<Integer, DataType> pointerTypes) {
		Map<Integer, HighSymbol> symbolsBySlot = new HashMap<>();
		int count = highFunction.getLocalSymbolMap().getNumParams();
		for (int i = 0; i < count; i++) {
			HighSymbol symbol = highFunction.getLocalSymbolMap().getParamSymbol(i);
			Integer start = parameterStart(symbol.getStorage());
			if (start != null) {
				symbolsBySlot.put(start, symbol);
			}
		}

		for (Map.Entry<Integer, HighSymbol> entry : symbolsBySlot.entrySet()) {
			int start = entry.getKey();
			HighSymbol symbol = entry.getValue();
			DataType type = symbol.getDataType();
			if (!isPointerType(type) || isFunctionPointer(type) || type.getLength() != 4 ||
				!isLegalPairStart(start)) {
				continue;
			}
			int storageSize = symbol.getStorage().size();
			if (storageSize == 2) {
				HighSymbol page = symbolsBySlot.get(start + 1);
				if (page == null || page.getStorage().size() != 2) {
					continue;
				}
			}
			else if (storageSize != 4) {
				continue;
			}
			scores.merge(start, 1, Integer::sum);
			liveSlots.add(start);
			liveSlots.add(start + 1);
			DataType directMemoryType =
				directMemoryPointerType(program, symbol.getHighVariable());
			mergePointerType(program, pointerTypes, start,
				directMemoryType == null ? type : directMemoryType);
		}
	}

	/**
	 * Recover a pointee type which the decompiler placed on a representation-only
	 * cast of an otherwise generic far-pointer parameter.  Only an identity
	 * CAST/COPY used directly as the address of a LOAD or STORE is accepted;
	 * pointer arithmetic is intentionally not followed because that would turn a
	 * structure field access into a pointer-to-field declaration.
	 */
	private DataType directMemoryPointerType(Program program, HighVariable variable) {
		if (variable == null) {
			return null;
		}
		DataType recoveredTarget = null;
		for (Varnode instance : variable.getInstances()) {
			Iterator<PcodeOp> uses = instance.getDescendants();
			while (uses.hasNext()) {
				PcodeOp use = uses.next();
				DataType target = directMemoryTarget(use, instance);
				if (target == null &&
					(use.getOpcode() == PcodeOp.CAST || use.getOpcode() == PcodeOp.COPY) &&
					use.getNumInputs() == 1 && use.getInput(0) == instance &&
					use.getOutput() != null) {
					Iterator<PcodeOp> convertedUses = use.getOutput().getDescendants();
					while (convertedUses.hasNext()) {
						DataType convertedTarget =
							directMemoryTarget(convertedUses.next(), use.getOutput());
						if (convertedTarget == null) {
							continue;
						}
						if (target != null && !target.isEquivalent(convertedTarget)) {
							return null;
						}
						target = convertedTarget;
					}
				}
				if (target == null) {
					continue;
				}
				if (recoveredTarget != null && !recoveredTarget.isEquivalent(target)) {
					return null;
				}
				recoveredTarget = target;
			}
		}
		return recoveredTarget == null ? null :
			new PointerDataType(recoveredTarget, program.getDataTypeManager());
	}

	private DataType directMemoryTarget(PcodeOp use, Varnode address) {
		if (use.getNumInputs() <= 1 || use.getInput(1) != address) {
			return null;
		}
		Varnode value;
		if (use.getOpcode() == PcodeOp.LOAD) {
			value = use.getOutput();
		}
		else if (use.getOpcode() == PcodeOp.STORE && use.getNumInputs() > 2) {
			value = use.getInput(2);
		}
		else {
			return null;
		}
		if (value == null || value.getSize() <= 0) {
			return null;
		}
		DataType target = value.getHigh() == null ? null : value.getHigh().getDataType();
		return target != null && target.getLength() == value.getSize() ? target :
			Undefined.getUndefinedDataType(value.getSize());
	}

	/**
	 * A TASKING tail-call keeps the callee's argument registers live across a
	 * terminal JMPS/JMPA.  High p-code represents this as BRANCH and consequently
	 * carries no call inputs.  Propagate only identity register pairs which the
	 * wrapper never writes; copied or transformed pairs remain intentionally
	 * unsupported rather than guessed.
	 */
	private void scoreIdentityTailCall(Program program, Function function,
			Map<Integer, Integer> scores, Set<Integer> liveSlots,
			Map<Integer, DataType> pointerTypes) {
		Instruction tail = program.getListing().getInstructionContaining(
			function.getBody().getMaxAddress());
		if (tail == null || !tail.getFlowType().isJump()) {
			return;
		}
		Address[] flows = tail.getFlows();
		if (flows.length != 1) {
			return;
		}
		Function target = program.getFunctionManager().getFunctionAt(flows[0]);
		if (target == null || !usesTaskingConvention(target)) {
			return;
		}
		for (Parameter parameter : target.getParameters()) {
			DataType type = parameter.getFormalDataType();
			Integer start = parameterStart(parameter.getVariableStorage());
			if (!isPointerType(type) || isFunctionPointer(type) || type.getLength() != 4 ||
				start == null ||
				start >= 4 || writesArgumentPair(program, function, tail, start)) {
				continue;
			}
			scores.merge(start, 1, Integer::sum);
			liveSlots.add(start);
			liveSlots.add(start + 1);
			mergePointerType(program, pointerTypes, start, type);
		}
	}

	private boolean writesArgumentPair(Program program, Function function, Instruction tail,
			int start) {
		Register low = program.getRegister("r" + (FIRST_ARGUMENT_REGISTER + start));
		Register high = program.getRegister("r" + (FIRST_ARGUMENT_REGISTER + start + 1));
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			if (instruction.equals(tail)) {
				break;
			}
			for (Object result : instruction.getResultObjects()) {
				if (result instanceof Register register &&
					(overlaps(low, register) || overlaps(high, register))) {
					return true;
				}
			}
		}
		return false;
	}

	private boolean overlaps(Register expected, Register actual) {
		return expected != null && actual != null &&
			(expected.contains(actual) || actual.contains(expected));
	}

	private void scoreForwardedPointers(Program program, PcodeOp operation,
			Map<Integer, Integer> scores, Map<Integer, DataType> pointerTypes,
			Set<Address> globalPointerStarts) {
		Function target = program.getFunctionManager()
			.getFunctionAt(operation.getInput(0).getAddress());
		if (target == null || !usesTaskingConvention(target)) {
			return;
		}
		int inputIndex = 1;
		for (Parameter parameter : target.getParameters()) {
			int storageSize = parameter.getVariableStorage().size();
			if (storageSize <= 0 || inputIndex >= operation.getNumInputs()) {
				return;
			}
			List<Varnode> pieces = new ArrayList<>();
			int consumed = 0;
			while (inputIndex < operation.getNumInputs() && consumed < storageSize) {
				Varnode input = operation.getInput(inputIndex++);
				if (input.getSize() > storageSize - consumed) {
					return;
				}
				pieces.add(input);
				consumed += input.getSize();
			}
			if (consumed != storageSize) {
				return;
			}

			DataType type = parameter.getFormalDataType();
			if (!isPointerType(type) || isFunctionPointer(type) || type.getLength() != 4) {
				continue;
			}
			if (pieces.size() == 1) {
				scorePointerValue(program, pieces.get(0), scores, pointerTypes, type,
					globalPointerStarts, 0, new HashSet<>());
			}
			else if (pieces.size() == 2 && pieces.get(0).getSize() == 2 &&
				pieces.get(1).getSize() == 2) {
				// CALL inputs are ordered OFFSET then PAGE for a split TASKING
				// far pointer.  The callee's four-byte pointer storage is the
				// authoritative reason to join them; inferred caller types are not.
				Integer start = scorePairSources(program, pieces.get(1), pieces.get(0),
					scores);
				if (start != null) {
					mergePointerType(program, pointerTypes, start, type);
				}
			}
		}
	}

	/**
	 * Reject a stale generic pointer when its two input words are forwarded to
	 * two independently typed scalar parameters.  This is stronger than the
	 * circular pointer type recovered from the caller's existing DB signature.
	 */
	private Set<Integer> findForwardedScalarPairs(Program program, Function function,
			HighFunction highFunction) {
		if (function.getSignatureSource() != SourceType.ANALYSIS) {
			return Set.of();
		}
		Set<Integer> repairable = new HashSet<>();
		for (Parameter parameter : function.getParameters()) {
			Integer start = parameterStart(parameter.getVariableStorage());
			if (start != null && isLegalPairStart(start) &&
				parameter.getVariableStorage().size() == 4 &&
				isGenericVoidPointer(parameter.getFormalDataType())) {
				repairable.add(start);
			}
		}
		if (repairable.isEmpty()) {
			return Set.of();
		}

		Set<Integer> conflicts = new HashSet<>();
		Iterator<PcodeOpAST> operations = highFunction.getPcodeOps();
		while (operations.hasNext()) {
			PcodeOpAST operation = operations.next();
			if (operation.getOpcode() != PcodeOp.CALL || operation.getNumInputs() == 0) {
				continue;
			}
			Function target = program.getFunctionManager()
				.getFunctionAt(operation.getInput(0).getAddress());
			if (target == null || !usesTaskingConvention(target)) {
				continue;
			}

			int inputIndex = 1;
			Integer previousTargetSlot = null;
			Integer previousCallerSlot = null;
			for (Parameter parameter : target.getParameters()) {
				int storageSize = parameter.getVariableStorage().size();
				if (storageSize <= 0 || inputIndex >= operation.getNumInputs()) {
					break;
				}
				List<Varnode> pieces = new ArrayList<>();
				int consumed = 0;
				while (inputIndex < operation.getNumInputs() && consumed < storageSize) {
					Varnode input = operation.getInput(inputIndex++);
					if (input.getSize() > storageSize - consumed) {
						pieces.clear();
						break;
					}
					pieces.add(input);
					consumed += input.getSize();
				}

				Integer targetSlot = parameterStart(parameter.getVariableStorage());
				Integer callerSlot = null;
				if (consumed == 2 && pieces.size() == 1 && targetSlot != null &&
					parameter.getFormalDataType() instanceof AbstractIntegerDataType &&
					!isPointerType(parameter.getFormalDataType())) {
					Set<Integer> sources = traceParameterWords(program, pieces.get(0), 0,
						new HashSet<>());
					if (sources.size() == 1) {
						callerSlot = sources.iterator().next();
					}
					else if (sources.isEmpty() &&
						pieces.get(0).getAddress().isRegisterAddress() &&
						pieces.get(0).getSize() == 2) {
						Integer directSlot = argumentSlot(program.getRegister(
							pieces.get(0).getAddress(), pieces.get(0).getSize()));
						if (directSlot != null && repairable.stream().anyMatch(start ->
							directSlot == start || directSlot == start + 1)) {
							callerSlot = directSlot;
						}
					}
				}

				if (previousTargetSlot != null && previousCallerSlot != null &&
					targetSlot != null && callerSlot != null &&
					targetSlot == previousTargetSlot + 1 &&
					callerSlot == previousCallerSlot + 1 &&
					repairable.contains(previousCallerSlot)) {
					conflicts.add(previousCallerSlot);
				}
				previousTargetSlot = callerSlot == null ? null : targetSlot;
				previousCallerSlot = callerSlot;
			}
		}
		return Set.copyOf(conflicts);
	}

	/**
	 * Reject a stale generic pointer when its two saved input words are copied to
	 * separate, non-adjacent 16-bit fields.  TASKING saves R12-R15 one word at a
	 * time in the prologue, so a store alone is not evidence.  We require both
	 * values to survive the frame, reach semantic stores through the scalar frame
	 * tracer, use the same unchanged destination base, and land more than one word
	 * apart.  A real architectural PAGE:OFFSET use always wins over this negative
	 * evidence.
	 */
	private Set<Integer> findSeparatelyStoredScalarPairs(Program program,
			Function function) {
		if (function.getSignatureSource() != SourceType.ANALYSIS) {
			return Set.of();
		}
		Set<Integer> repairable = new HashSet<>();
		for (Parameter parameter : function.getParameters()) {
			Integer start = parameterStart(parameter.getVariableStorage());
			if (start != null && start < 4 && isLegalPairStart(start) &&
				parameter.getVariableStorage().size() == 4 &&
				isGenericVoidPointer(parameter.getFormalDataType()) &&
				!containsDirectPagedDataUseForPair(program, function, start) &&
				!containsDynamicPagedAccessSetupForPair(program, function, start)) {
				repairable.add(start);
			}
		}
		if (repairable.isEmpty()) {
			return Set.of();
		}

		Map<Integer, List<ScalarWordStore>> stores = new HashMap<>();
		C166CodePointerPhase tracer = new C166CodePointerPhase();
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			if (!instruction.getMnemonicString().equalsIgnoreCase("mov") ||
				instruction.getNumOperands() < 2 ||
				!isBracketMemoryOperand(instruction, 0) ||
				isBracketMemoryOperand(instruction, 1)) {
				continue;
			}
			Register base = operandRegister(instruction, 0);
			Register source = operandRegister(instruction, 1);
			if (base == null || source == null ||
				"r0".equalsIgnoreCase(base.getName()) ||
				source.getMinimumByteSize() != 2) {
				continue;
			}
			Integer slot = tracer.traceScalarInputWord(program, function,
				instruction, source);
			if (slot == null || repairable.stream().noneMatch(start ->
				slot == start || slot == start + 1)) {
				continue;
			}
			Scalar displacement = operandScalar(instruction, 0);
			int offset = displacement == null ? 0 :
				(int) displacement.getSignedValue();
			stores.computeIfAbsent(slot, ignored -> new ArrayList<>())
				.add(new ScalarWordStore(instruction, base,
					activePageRegister(program, function, instruction), offset));
		}

		Set<Integer> conflicts = new HashSet<>();
		for (int start : repairable) {
			for (ScalarWordStore low : stores.getOrDefault(start, List.of())) {
				for (ScalarWordStore high : stores.getOrDefault(start + 1, List.of())) {
					if (!overlaps(low.base(), high.base()) ||
						Math.abs(low.offset() - high.offset()) <= 2 ||
						!sameBaseValueBetween(program, function, low, high)) {
						continue;
					}
					conflicts.add(start);
				}
			}
		}
		return Set.copyOf(conflicts);
	}

	private boolean sameBaseValueBetween(Program program, Function function,
			ScalarWordStore left, ScalarWordStore right) {
		Instruction first = left.instruction().getAddress().compareTo(
			right.instruction().getAddress()) <= 0 ? left.instruction() : right.instruction();
		Instruction last = first == left.instruction() ? right.instruction() :
			left.instruction();
		Register base = first == left.instruction() ? left.base() : right.base();
		Instruction instruction =
			program.getListing().getInstructionAfter(first.getAddress());
		while (instruction != null &&
			instruction.getAddress().compareTo(last.getAddress()) < 0 &&
			function.getBody().contains(instruction.getAddress())) {
			if (instruction.getFlowType().isCall() ||
				instruction.getFlowType().isJump() || writesRegister(instruction, base)) {
				return false;
			}
			instruction = program.getListing().getInstructionAfter(
				instruction.getAddress());
		}
		return instruction != null &&
			instruction.getAddress().equals(last.getAddress());
	}

	private Scalar operandScalar(Instruction instruction, int operand) {
		for (Object object : instruction.getOpObjects(operand)) {
			if (object instanceof Scalar scalar) {
				return scalar;
			}
		}
		return null;
	}

	private int pageAccessCount(Instruction instruction) {
		for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
			Scalar count = operandScalar(instruction, operand);
			if (count != null) {
				return Math.max(1, Math.min(4, (int) count.getUnsignedValue()));
			}
		}
		return 1;
	}

	private boolean isBracketMemoryOperand(Instruction instruction, int operand) {
		if (operand < 0 || operand >= instruction.getNumOperands()) {
			return false;
		}
		return instruction.getDefaultOperandRepresentation(operand).trim()
			.startsWith("[");
	}

	/**
	 * Recover a far-pointer value which a straight-line leaf helper stores into a
	 * known four-byte pointer field.  TASKING may expose the stored OFFSET and
	 * PAGE as two scalar helper parameters even though the caller supplied one
	 * far-pointer parameter.  The known aggregate field type, two adjacent stores,
	 * and exact caller/callee ABI-word traces jointly prove both the pointer pair
	 * and its pointee type; a scalar-only callee signature cannot veto that proof.
	 */
	private Map<Integer, DataType> forwardedAggregateFieldPointerTypes(Program program,
			Function function) {
		if (function.getSignatureSource() != SourceType.ANALYSIS) {
			return Map.of();
		}
		Map<Integer, DataType> inferred = new HashMap<>();
		C166CodePointerPhase tracer = new C166CodePointerPhase();
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			Instruction call = instructions.next();
			if (!call.getFlowType().isCall()) {
				continue;
			}
			Function target = directTarget(program, call);
			if (target == null || !usesTaskingConvention(target) ||
				!isStraightLineLeaf(target, program)) {
				continue;
			}
			Map<Integer, List<ScalarWordStore>> stores = inputWordStores(program, target);
			for (int valueStart = 0; valueStart < 3; valueStart++) {
				if (!isScalarWordParameter(target, valueStart) ||
					!isScalarWordParameter(target, valueStart + 1)) {
					continue;
				}
				for (ScalarWordStore low : stores.getOrDefault(valueStart, List.of())) {
					for (ScalarWordStore high :
							stores.getOrDefault(valueStart + 1, List.of())) {
						if (low.page() == null || high.page() == null ||
							high.offset() != low.offset() + 2 ||
							!overlaps(low.base(), high.base()) ||
							!overlaps(low.page(), high.page()) ||
							!sameBaseValueBetween(program, target, low, high) ||
							!sameRegisterValueBetween(program, target,
								low.instruction(), high.instruction(), low.page())) {
							continue;
						}
						Integer targetBase = tracer.traceScalarInputWord(program, target,
							low.instruction(), low.base());
						Integer targetPage = tracer.traceScalarInputWord(program, target,
							low.instruction(), low.page());
						if (targetBase == null || targetPage == null ||
							targetPage != targetBase + 1 || !isLegalPairStart(targetBase)) {
							continue;
						}
						Integer callerBase = traceOutgoingWord(program, function, call,
							targetBase, tracer);
						Integer callerPage = traceOutgoingWord(program, function, call,
							targetBase + 1, tracer);
						if (callerBase == null || callerPage == null ||
							callerPage != callerBase + 1) {
							continue;
						}
						DataType fieldType = aggregatePointerFieldType(function, callerBase,
							low.offset());
						if (fieldType == null) {
							continue;
						}
						Integer callerLow = traceOutgoingWord(program, function, call,
							valueStart, tracer);
						Integer callerHigh = traceOutgoingWord(program, function, call,
							valueStart + 1, tracer);
						if (callerLow == null || callerHigh == null ||
							callerHigh != callerLow + 1 || !isLegalPairStart(callerLow)) {
							continue;
						}
						mergePointerType(program, inferred, callerLow, fieldType);
					}
				}
			}
		}
		return Map.copyOf(inferred);
	}

	private Integer traceOutgoingWord(Program program, Function caller,
			Instruction call, int targetSlot, C166CodePointerPhase tracer) {
		if (targetSlot < 0 || targetSlot >= 4) {
			return null;
		}
		return tracer.traceScalarInputWord(program, caller, call,
			program.getRegister("r" + (FIRST_ARGUMENT_REGISTER + targetSlot)));
	}

	private boolean isScalarWordParameter(Function function, int slot) {
		for (Parameter parameter : function.getParameters()) {
			Integer start = parameterStart(parameter.getVariableStorage());
			if (Integer.valueOf(slot).equals(start) &&
				parameter.getVariableStorage().size() == 2 &&
				!isPointerType(parameter.getFormalDataType())) {
				return true;
			}
		}
		return false;
	}

	private DataType aggregatePointerFieldType(Function function, int parameterSlot,
			int fieldOffset) {
		for (Parameter parameter : function.getParameters()) {
			if (!Integer.valueOf(parameterSlot).equals(
					parameterStart(parameter.getVariableStorage()))) {
				continue;
			}
			Pointer pointer = pointerDataType(parameter.getFormalDataType());
			if (pointer == null || pointer.getLength() != 4) {
				return null;
			}
			DataType target = pointer.getDataType();
			while (target instanceof TypeDef typeDef) {
				target = typeDef.getBaseDataType();
			}
			if (!(target instanceof Structure structure) ||
				!isOwnedAutoStructure(structure)) {
				return null;
			}
			DataTypeComponent component = structure.getComponentAt(fieldOffset);
			DataType fieldType = component == null ? null : component.getDataType();
			return component != null && component.getOffset() == fieldOffset &&
				component.getLength() == 4 && pointerDataType(fieldType) != null &&
				!isFunctionPointer(fieldType) ? fieldType : null;
		}
		return null;
	}

	private boolean isStraightLineLeaf(Function function, Program program) {
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			if (instruction.getFlowType().isCall() || instruction.getFlowType().isJump()) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Recover a pointer which a constructor-like function copies into an object
	 * and whose consumer later dereferences that exact field.  This covers code
	 * where the producer itself never dereferences the incoming pointer: the two
	 * words are stored at adjacent offsets, the same object base is passed to a
	 * typed callee, and that callee reloads the field as PAGE:OFFSET before a
	 * paged access.  Every link is machine-level data flow; names and firmware
	 * addresses are deliberately irrelevant.
	 */
	private Set<Integer> findIndirectlyConsumedStoredPointerPairs(Program program,
			Function function) {
		Map<Integer, List<ScalarWordStore>> stores = inputWordStores(program, function);
		if (stores.isEmpty()) {
			return Set.of();
		}
		Set<Integer> inferred = new HashSet<>();
		for (int start = 0; start < 3; start++) {
			if (!isLegalPairStart(start)) {
				continue;
			}
			for (ScalarWordStore low : stores.getOrDefault(start, List.of())) {
				for (ScalarWordStore high : stores.getOrDefault(start + 1, List.of())) {
					if (low.page() == null || high.page() == null ||
						high.offset() != low.offset() + 2 ||
						!overlaps(low.base(), high.base()) ||
						!overlaps(low.page(), high.page()) ||
						!sameBaseValueBetween(program, function, low, high) ||
						!sameRegisterValueBetween(program, function, low.instruction(),
							high.instruction(), low.page())) {
						continue;
					}
					Instruction after = low.instruction().getAddress().compareTo(
						high.instruction().getAddress()) > 0 ? low.instruction() :
							high.instruction();
					if (storedFieldReachesPointerConsumer(program, function, after,
							low.base(), low.page(), low.offset())) {
						inferred.add(start);
					}
				}
			}
		}
		return Set.copyOf(inferred);
	}

	private Map<Integer, List<ScalarWordStore>> inputWordStores(Program program,
			Function function) {
		Map<Integer, List<ScalarWordStore>> stores = new HashMap<>();
		C166CodePointerPhase tracer = new C166CodePointerPhase();
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			if (!instruction.getMnemonicString().equalsIgnoreCase("mov") ||
				instruction.getNumOperands() < 2 ||
				!isBracketMemoryOperand(instruction, 0) ||
				isBracketMemoryOperand(instruction, 1)) {
				continue;
			}
			Register base = operandRegister(instruction, 0);
			Register source = operandRegister(instruction, 1);
			if (base == null || source == null ||
				"r0".equalsIgnoreCase(base.getName()) ||
				source.getMinimumByteSize() != 2) {
				continue;
			}
			Integer slot = tracer.traceScalarInputWord(program, function,
				instruction, source);
			if (slot == null || slot < 0 || slot >= 4) {
				continue;
			}
			Scalar displacement = operandScalar(instruction, 0);
			int offset = displacement == null ? 0 :
				(int) displacement.getSignedValue();
			stores.computeIfAbsent(slot, ignored -> new ArrayList<>())
				.add(new ScalarWordStore(instruction, base,
					activePageRegister(program, function, instruction), offset));
		}
		return stores;
	}

	private Register activePageRegister(Program program, Function function,
			Instruction access) {
		Instruction instruction =
			program.getListing().getInstructionBefore(access.getAddress());
		for (int following = 0; instruction != null && following < 4; following++) {
			if (!function.getBody().contains(instruction.getAddress()) ||
				instruction.getFlowType().isCall() || instruction.getFlowType().isJump()) {
				return null;
			}
			String mnemonic = instruction.getMnemonicString().toLowerCase();
			if (mnemonic.equals("extp") || mnemonic.equals("extpr")) {
				Register page = dynamicPageSource(instruction);
				int range = pageAccessCount(instruction);
				return page != null && following < range ? page : null;
			}
			instruction = program.getListing().getInstructionBefore(
				instruction.getAddress());
		}
		return null;
	}

	private boolean sameRegisterValueBetween(Program program, Function function,
			Instruction left, Instruction right, Register register) {
		Instruction first = left.getAddress().compareTo(right.getAddress()) <= 0 ?
			left : right;
		Instruction last = first == left ? right : left;
		Instruction instruction =
			program.getListing().getInstructionAfter(first.getAddress());
		while (instruction != null &&
			instruction.getAddress().compareTo(last.getAddress()) < 0 &&
			function.getBody().contains(instruction.getAddress())) {
			if (instruction.getFlowType().isCall() ||
				instruction.getFlowType().isJump() || writesRegister(instruction, register)) {
				return false;
			}
			instruction = program.getListing().getInstructionAfter(
				instruction.getAddress());
		}
		return instruction != null && instruction.getAddress().equals(last.getAddress());
	}

	private boolean storedFieldReachesPointerConsumer(Program program, Function function,
			Instruction after, Register base, Register page, int fieldOffset) {
		Instruction instruction =
			program.getListing().getInstructionAfter(after.getAddress());
		for (int scanned = 0; instruction != null && scanned < MAX_SETUP_SCAN_INSTRUCTIONS;
				scanned++, instruction = program.getListing().getInstructionAfter(
					instruction.getAddress())) {
			if (!function.getBody().contains(instruction.getAddress()) ||
				instruction.getFlowType().isJump()) {
				return false;
			}
			if (!instruction.getFlowType().isCall()) {
				continue;
			}
			Function target = directTarget(program, instruction);
			if (target != null) {
				for (PointerFieldUse use : directlyDereferencedPointerFields(program,
						target)) {
					if (use.fieldOffset() == fieldOffset &&
						callPairTracesTo(program, function, instruction,
							use.parameterStart(), base, page, after)) {
						return true;
					}
				}
			}
			// A call may clobber the outgoing registers, but R6-R9 keep the object
			// base. Continue only while the exact stored base pair is callee-saved.
			if (!isTaskingCalleeSavedRegister(base) ||
				!isTaskingCalleeSavedRegister(page)) {
				return false;
			}
		}
		return false;
	}

	private boolean callPairTracesTo(Program program, Function function,
			Instruction call, int parameterStart, Register expectedLow,
			Register expectedPage, Instruction boundary) {
		if (parameterStart < 0 || parameterStart >= 3) {
			return false;
		}
		Register low = program.getRegister(
			"r" + (FIRST_ARGUMENT_REGISTER + parameterStart));
		Register page = program.getRegister(
			"r" + (FIRST_ARGUMENT_REGISTER + parameterStart + 1));
		return registerAtCallTracesTo(program, function, call, low, expectedLow,
			boundary) && registerAtCallTracesTo(program, function, call, page,
				expectedPage, boundary);
	}

	private boolean registerAtCallTracesTo(Program program, Function function,
			Instruction call, Register outgoing, Register expected,
			Instruction boundary) {
		if (outgoing == null || expected == null) {
			return false;
		}
		Register traced = outgoing;
		Instruction instruction =
			program.getListing().getInstructionBefore(call.getAddress());
		for (int scanned = 0; instruction != null && scanned < MAX_SETUP_SCAN_INSTRUCTIONS;
				scanned++, instruction = program.getListing().getInstructionBefore(
					instruction.getAddress())) {
			if (!function.getBody().contains(instruction.getAddress()) ||
				instruction.getAddress().compareTo(boundary.getAddress()) <= 0 ||
				instruction.getFlowType().isJump()) {
				break;
			}
			if (instruction.getFlowType().isCall()) {
				if (!isTaskingCalleeSavedRegister(traced)) {
					return false;
				}
				continue;
			}
			if (!writesRegister(instruction, traced)) {
				continue;
			}
			if (!instruction.getMnemonicString().equalsIgnoreCase("mov") ||
				instruction.getNumOperands() < 2 ||
				OperandType.isIndirect(instruction.getOperandType(0)) ||
				OperandType.isIndirect(instruction.getOperandType(1))) {
				return false;
			}
			Register source = operandRegister(instruction, 1);
			if (source == null) {
				return false;
			}
			traced = source;
		}
		return overlaps(traced, expected);
	}

	private boolean isTaskingCalleeSavedRegister(Register register) {
		Integer number = generalRegisterNumber(register);
		return number != null && number >= 6 && number <= 9;
	}

	private Set<PointerFieldUse> directlyDereferencedPointerFields(Program program,
			Function function) {
		Map<Register, SymbolicWord> values = new HashMap<>();
		for (Parameter parameter : function.getParameters()) {
			Integer start = parameterStart(parameter.getVariableStorage());
			DataType type = parameter.getFormalDataType();
			if (start == null || start < 0 || start >= 3 ||
				!isPointerType(type) || isFunctionPointer(type) || type.getLength() != 4) {
				continue;
			}
			values.put(program.getRegister("r" +
				(FIRST_ARGUMENT_REGISTER + start)),
				new SymbolicWord(SymbolicWordKind.BASE_LOW, start, 0));
			values.put(program.getRegister("r" +
				(FIRST_ARGUMENT_REGISTER + start + 1)),
				new SymbolicWord(SymbolicWordKind.BASE_PAGE, start, 0));
		}
		if (values.isEmpty()) {
			return Set.of();
		}

		Set<PointerFieldUse> fields = new HashSet<>();
		SymbolicWord activePage = null;
		int activeRemaining = 0;
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		for (int scanned = 0; instructions.hasNext() &&
				scanned < MAX_SETUP_SCAN_INSTRUCTIONS; scanned++) {
			Instruction instruction = instructions.next();
			if (instruction.getFlowType().isCall() || instruction.getFlowType().isJump()) {
				break;
			}
			String mnemonic = instruction.getMnemonicString().toLowerCase();
			if (mnemonic.equals("extp") || mnemonic.equals("extpr")) {
				Register source = dynamicPageSource(instruction);
				activePage = symbolicValue(values, source);
				activeRemaining = pageAccessCount(instruction);
				continue;
			}

			boolean handledDestination = false;
			if (mnemonic.equals("mov") && instruction.getNumOperands() >= 2 &&
				!OperandType.isIndirect(instruction.getOperandType(0))) {
				Register destination = operandRegister(instruction, 0);
				if (destination != null) {
					handledDestination = true;
					SymbolicWord next = null;
					if (isBracketMemoryOperand(instruction, 1) &&
						activePage != null && activeRemaining > 0) {
						Register base = operandRegister(instruction, 1);
						SymbolicWord baseValue = symbolicValue(values, base);
						Scalar displacement = operandScalar(instruction, 1);
						int offset = displacement == null ? 0 :
							(int) displacement.getSignedValue();
						if (baseValue != null &&
							baseValue.kind() == SymbolicWordKind.BASE_LOW &&
							activePage.kind() == SymbolicWordKind.BASE_PAGE &&
							baseValue.parameterStart() == activePage.parameterStart()) {
							next = new SymbolicWord(SymbolicWordKind.FIELD_WORD,
								baseValue.parameterStart(), baseValue.offset() + offset);
						}
						else if (baseValue != null &&
							baseValue.kind() == SymbolicWordKind.FIELD_WORD &&
							activePage.kind() == SymbolicWordKind.FIELD_WORD &&
							baseValue.parameterStart() == activePage.parameterStart() &&
							activePage.offset() == baseValue.offset() + 2) {
							fields.add(new PointerFieldUse(baseValue.parameterStart(),
								baseValue.offset()));
						}
					}
					else if (!OperandType.isIndirect(instruction.getOperandType(1))) {
						next = symbolicValue(values, operandRegister(instruction, 1));
					}
					putSymbolicValue(values, destination, next);
				}
			}
			else if (mnemonic.equals("add") && instruction.getNumOperands() >= 2 &&
				!OperandType.isIndirect(instruction.getOperandType(0))) {
				Register destination = operandRegister(instruction, 0);
				Scalar amount = operandScalar(instruction, 1);
				SymbolicWord current = symbolicValue(values, destination);
				if (destination != null && amount != null && current != null &&
					current.kind() == SymbolicWordKind.BASE_LOW) {
					handledDestination = true;
					putSymbolicValue(values, destination,
						new SymbolicWord(current.kind(), current.parameterStart(),
							current.offset() + (int) amount.getSignedValue()));
				}
			}

			if (!handledDestination) {
				for (Object result : instruction.getResultObjects()) {
					if (result instanceof Register register) {
						putSymbolicValue(values, register, null);
					}
				}
			}
			if (activeRemaining > 0 && --activeRemaining == 0) {
				activePage = null;
			}
		}
		return Set.copyOf(fields);
	}

	private SymbolicWord symbolicValue(Map<Register, SymbolicWord> values,
			Register register) {
		if (register == null) {
			return null;
		}
		for (Map.Entry<Register, SymbolicWord> entry : values.entrySet()) {
			if (overlaps(entry.getKey(), register)) {
				return entry.getValue();
			}
		}
		return null;
	}

	private void putSymbolicValue(Map<Register, SymbolicWord> values,
			Register register, SymbolicWord value) {
		if (register == null) {
			return;
		}
		values.keySet().removeIf(existing -> overlaps(existing, register));
		if (value != null) {
			values.put(register, value);
		}
	}

	private void scorePointerValue(Program program, Varnode value,
			Map<Integer, Integer> scores, Map<Integer, DataType> pointerTypes,
			DataType pointerType,
			Set<Address> globalPointerStarts, int depth, Set<Varnode> visited) {
		if (value == null || depth > MAX_TRACE_DEPTH || !visited.add(value)) {
			return;
		}
		PcodeOp definition = value.getDef();
		if (definition == null) {
			HighVariable high = value.getHigh();
			HighSymbol symbol = high == null ? null : high.getSymbol();
			if (symbol != null && symbol.isParameter() && symbol.getStorage().size() == 4) {
				Integer start = parameterStart(symbol.getStorage());
				if (start != null && isLegalPairStart(start)) {
					scores.merge(start, 1, Integer::sum);
					mergePointerType(program, pointerTypes, start, pointerType);
				}
			}
			return;
		}
		switch (definition.getOpcode()) {
			case PcodeOp.SEGMENTOP:
				if (definition.getNumInputs() == 3) {
					Address globalStart = globalPairStart(program, definition.getInput(1),
						definition.getInput(2));
					if (globalStart != null) {
						globalPointerStarts.add(globalStart);
					}
					Integer start = scorePairSources(program, definition.getInput(1),
						definition.getInput(2), scores);
					if (start != null) {
						mergePointerType(program, pointerTypes, start, pointerType);
					}
				}
				break;
			case PcodeOp.PIECE:
				if (definition.getNumInputs() == 2 && definition.getInput(0).getSize() == 2 &&
					definition.getInput(1).getSize() == 2) {
					Address globalStart = globalPairStart(program, definition.getInput(0),
						definition.getInput(1));
					if (globalStart != null) {
						globalPointerStarts.add(globalStart);
					}
					Integer start = scorePairSources(program, definition.getInput(0),
						definition.getInput(1), scores);
					if (start != null) {
						mergePointerType(program, pointerTypes, start, pointerType);
					}
				}
				break;
			case PcodeOp.COPY:
			case PcodeOp.CAST:
			case PcodeOp.INT_ZEXT:
				scorePointerValue(program, definition.getInput(0), scores, pointerTypes,
					pointerType, globalPointerStarts, depth + 1, visited);
				break;
			default:
				break;
		}
	}

	private Address globalPairStart(Program program, Varnode page, Varnode offset) {
		Address highAddress = traceGlobalWordAddress(program, page, 0, new HashSet<>());
		Address lowAddress = traceGlobalWordAddress(program, offset, 0, new HashSet<>());
		if (highAddress == null || lowAddress == null ||
			!highAddress.getAddressSpace().equals(lowAddress.getAddressSpace())) {
			return null;
		}
		try {
			return highAddress.equals(lowAddress.add(2)) ? lowAddress : null;
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

	private Address traceGlobalWordAddress(Program program, Varnode value, int depth,
			Set<Varnode> visited) {
		if (value == null || depth > MAX_TRACE_DEPTH || !visited.add(value)) {
			return null;
		}
		Address varnodeAddress = value.getAddress();
		if (value.getSize() == 2 && varnodeAddress != null &&
			varnodeAddress.isMemoryAddress()) {
			return varnodeAddress;
		}
		PcodeOp definition = value.getDef();
		if (definition == null) {
			return null;
		}
		switch (definition.getOpcode()) {
			case PcodeOp.LOAD:
				if (definition.getNumInputs() > 1) {
					return resolveGlobalLoadAddress(program, definition.getInput(1));
				}
				return null;
			case PcodeOp.COPY:
			case PcodeOp.CAST:
			case PcodeOp.INT_ZEXT:
			case PcodeOp.INT_SEXT:
			case PcodeOp.SUBPIECE:
				return traceGlobalWordAddress(program, definition.getInput(0), depth + 1,
					visited);
			case PcodeOp.INT_ADD:
			case PcodeOp.INT_AND:
				if (definition.getNumInputs() == 2) {
					if (definition.getInput(0).isConstant()) {
						return traceGlobalWordAddress(program, definition.getInput(1), depth + 1,
							visited);
					}
					if (definition.getInput(1).isConstant()) {
						return traceGlobalWordAddress(program, definition.getInput(0), depth + 1,
							visited);
					}
					if (definition.getOpcode() == PcodeOp.INT_ADD &&
						isScaledArrayIndex(definition.getInput(0))) {
						return traceGlobalWordAddress(program, definition.getInput(1), depth + 1,
							visited);
					}
					if (definition.getOpcode() == PcodeOp.INT_ADD &&
						isScaledArrayIndex(definition.getInput(1))) {
						return traceGlobalWordAddress(program, definition.getInput(0), depth + 1,
							visited);
					}
				}
				return null;
			default:
				return null;
		}
	}

	private boolean isScaledArrayIndex(Varnode value) {
		PcodeOp definition = value == null ? null : value.getDef();
		if (definition == null || definition.getNumInputs() != 2 ||
			value.getSize() != 2) {
			return false;
		}
		long stride;
		if (definition.getOpcode() == PcodeOp.INT_MULT) {
			Varnode first = definition.getInput(0);
			Varnode second = definition.getInput(1);
			Varnode constant = first.isConstant() ? first : second;
			Varnode index = first.isConstant() ? second : first;
			if (!constant.isConstant() || index.isConstant() || index.getSize() != 2) {
				return false;
			}
			stride = constant.getOffset();
		}
		else if (definition.getOpcode() == PcodeOp.INT_LEFT) {
			if (!definition.getInput(1).isConstant() ||
				definition.getInput(0).isConstant() ||
				definition.getInput(0).getSize() != 2) {
				return false;
			}
			long shift = definition.getInput(1).getOffset();
			if (shift >= 63) {
				return false;
			}
			stride = 1L << shift;
		}
		else {
			return false;
		}
		return stride >= 2 && stride <= 0x1000;
	}

	private Address resolveGlobalLoadAddress(Program program, Varnode pointer) {
		if (pointer == null || !pointer.isConstant()) {
			return null;
		}
		AddressSpace space = program.getLanguage().getDefaultDataSpace();
		return address(space, pointer.getOffset());
	}

	private int defineGlobalFarPointers(Program program, Set<Address> starts) {
		int created = 0;
		for (Address start : starts) {
			if (!mayReplaceGlobalWords(program, start)) {
				continue;
			}
			DataType pointer = new PointerDataType(VoidDataType.dataType,
				program.getDataTypeManager());
			int transaction = program.startTransaction(
				"Recover C166 global far pointer");
			boolean commit = false;
			try {
				clearAnalysisOwnedCode(program, new AddressSet(start, start.add(3)));
				DataUtilities.createData(program, start, pointer, pointer.getLength(), false,
					ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
				commit = true;
				created++;
			}
			catch (CodeUnitInsertionException | OverlappingFunctionException |
				RuntimeException e) {
				// A conflicting instruction or user-defined object is not analysis-owned.
			}
			finally {
				program.endTransaction(transaction, commit);
			}
		}
		return created;
	}

	private void clearAnalysisOwnedCode(Program program, AddressSet range)
			throws OverlappingFunctionException {
		InstructionIterator instructions =
			program.getListing().getInstructions(range, true);
		if (!instructions.hasNext()) {
			return;
		}

		List<Function> functions = new ArrayList<>();
		Iterator<Function> overlapping =
			program.getFunctionManager().getFunctionsOverlapping(range);
		overlapping.forEachRemaining(functions::add);
		for (Function function : functions) {
			if (range.contains(function.getEntryPoint())) {
				program.getFunctionManager().removeFunction(function.getEntryPoint());
				continue;
			}
			AddressSet remainder = new AddressSet(function.getBody());
			remainder.delete(range);
			function.setBody(remainder);
		}
		program.getListing().clearCodeUnits(range.getMinAddress(), range.getMaxAddress(), false);
	}

	private boolean mayReplaceGlobalWords(Program program, Address start) {
		Address end;
		try {
			end = start.add(3);
		}
		catch (AddressOutOfBoundsException e) {
			return false;
		}
		if (!program.getMemory().contains(start) || !program.getMemory().contains(end)) {
			return false;
		}
		AddressSet range = new AddressSet(start, end);
		InstructionIterator instructions = program.getListing().getInstructions(range, true);
		if (instructions.hasNext()) {
			do {
				Instruction instruction = instructions.next();
				if (!range.contains(instruction.getMinAddress()) ||
					!range.contains(instruction.getMaxAddress())) {
					return false;
				}
			}
			while (instructions.hasNext());
			if (!mayReplaceAnalysisCode(program, range)) {
				return false;
			}
		}
		Data existing = program.getListing().getDefinedDataAt(start);
		if (existing != null && existing.getDataType() instanceof Pointer &&
			existing.getLength() == 4) {
			return false;
		}
		for (Address address : List.of(start, start.add(2))) {
			Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
			if (symbol != null && symbol.getSource() != SourceType.DEFAULT &&
				symbol.getSource() != SourceType.ANALYSIS) {
				return false;
			}
			CodeUnit unit = program.getListing().getCodeUnitContaining(address);
			if (unit instanceof Data data && data.isDefined() &&
				!(data.getDataType() instanceof AbstractIntegerDataType) &&
				!Undefined.isUndefined(data.getDataType())) {
				return false;
			}
		}
		return true;
	}

	private boolean mayReplaceAnalysisCode(Program program, AddressSet range) {
		Address start = range.getMinAddress();
		Address end = range.getMaxAddress();
		ghidra.program.model.mem.MemoryBlock block = program.getMemory().getBlock(start);
		if (block == null || !block.isWrite() || !block.contains(end)) {
			return false;
		}
		Iterator<Function> overlappingFunctions =
			program.getFunctionManager().getFunctionsOverlapping(range);
		while (overlappingFunctions.hasNext()) {
			Function function = overlappingFunctions.next();
			Address entry = function.getEntryPoint();
			if (!range.contains(entry)) {
				continue;
			}
			ReferenceIterator incoming =
				program.getReferenceManager().getReferencesTo(entry);
			while (incoming.hasNext()) {
				RefType type = incoming.next().getReferenceType();
				if (type.isFlow() || type == RefType.PARAM) {
					return false;
				}
			}
		}
		for (Address address = start; address.compareTo(end) <= 0; address = address.next()) {
			if (address == null || program.getSymbolTable().isExternalEntryPoint(address)) {
				return false;
			}
			Function function = program.getFunctionManager().getFunctionContaining(address);
			for (Symbol symbol : program.getSymbolTable().getSymbols(address)) {
				SourceType source = symbol.getSource();
				if (source != SourceType.DEFAULT && source != SourceType.ANALYSIS) {
					return false;
				}
			}
			ReferenceIterator references =
				program.getReferenceManager().getReferencesTo(address);
			while (references.hasNext()) {
				Reference reference = references.next();
				if (function != null && address.equals(function.getEntryPoint()) &&
					(reference.getReferenceType().isFlow() ||
						reference.getReferenceType() == RefType.PARAM)) {
					return false;
				}
				SourceType source = reference.getSource();
				if (source != SourceType.DEFAULT && source != SourceType.ANALYSIS) {
					return false;
				}
			}
			if (function != null && function.getSymbol().getSource() != SourceType.DEFAULT &&
				function.getSymbol().getSource() != SourceType.ANALYSIS) {
				return false;
			}
			CodeUnit unit = program.getListing().getCodeUnitContaining(address);
			if (unit != null && hasUserComment(unit)) {
				return false;
			}
			if (address.equals(end)) {
				break;
			}
		}
		return true;
	}

	private boolean hasUserComment(CodeUnit unit) {
		for (CommentType type : CommentType.values()) {
			if (unit.getComment(type) != null) {
				return true;
			}
		}
		return false;
	}

	private Integer scorePairSources(Program program, Varnode page, Varnode offset,
			Map<Integer, Integer> scores) {
		Set<Integer> pageSlots = traceParameterWords(program, page, 0, new HashSet<>());
		if (pageSlots.size() != 1) {
			return null;
		}
		int highSlot = pageSlots.iterator().next();
		int lowSlot = highSlot - 1;
		if (!isLegalPairStart(lowSlot)) {
			return null;
		}
		Set<Integer> offsetSlots = traceParameterWords(program, offset, 0, new HashSet<>());
		if (offsetSlots.contains(lowSlot) && !offsetSlots.contains(highSlot)) {
			scores.merge(lowSlot, 1, Integer::sum);
			return lowSlot;
		}
		return null;
	}

	private boolean isTypedFarPointerPiece(PcodeOp operation) {
		if (operation.getOpcode() != PcodeOp.PIECE || operation.getNumInputs() != 2 ||
			operation.getOutput() == null || operation.getOutput().getSize() != 4 ||
			operation.getInput(0).getSize() != 2 || operation.getInput(1).getSize() != 2) {
			return false;
		}
		return typedPointerType(operation) != null;
	}

	private DataType typedPointerType(PcodeOp operation) {
		if (operation.getOutput() == null || operation.getOutput().getHigh() == null) {
			return null;
		}
		DataType type = operation.getOutput().getHigh().getDataType();
		return isPointerType(type) && !isFunctionPointer(type) && type.getLength() == 4
			? type : null;
	}

	private boolean isPointerType(DataType type) {
		return pointerDataType(type) != null;
	}

	private Pointer pointerDataType(DataType type) {
		DataType current = type;
		while (current instanceof TypeDef typeDef) {
			current = typeDef.getBaseDataType();
		}
		return current instanceof Pointer pointer ? pointer : null;
	}

	private boolean isFunctionPointer(DataType type) {
		Pointer pointer = pointerDataType(type);
		if (pointer == null) {
			return false;
		}
		DataType target = pointer.getDataType();
		while (target instanceof TypeDef typeDef) {
			target = typeDef.getBaseDataType();
		}
		return target instanceof FunctionDefinition;
	}

	private boolean isGenericFunctionPointer(DataType type) {
		if (!isFunctionPointer(type)) {
			return false;
		}
		if (type instanceof TypeDef &&
			GENERIC_FUNCTION_POINTER_PATH.equals(type.getPathName())) {
			return true;
		}
		Pointer pointer = pointerDataType(type);
		DataType target = pointer.getDataType();
		while (target instanceof TypeDef typeDef) {
			target = typeDef.getBaseDataType();
		}
		String path = target.getPathName();
		return GENERIC_FUNCTION_PATH.equals(path) ||
			LEGACY_GENERIC_FUNCTION_PATH.equals(path);
	}

	private void mergePointerType(Program program, Map<Integer, DataType> pointerTypes,
			int start, DataType candidate) {
		Pointer candidatePointer = pointerDataType(candidate);
		if (candidatePointer == null || isFunctionPointer(candidate) ||
			candidate.getLength() != 4) {
			return;
		}
		DataType existing = pointerTypes.get(start);
		if (existing == null) {
			pointerTypes.put(start, candidate);
			return;
		}
		Pointer existingPointer = pointerDataType(existing);
		DataType existingTarget = existingPointer.getDataType();
		DataType candidateTarget = candidatePointer.getDataType();
		if (existingTarget.isEquivalent(candidateTarget) || isVoidType(candidateTarget)) {
			return;
		}
		if (isVoidType(existingTarget)) {
			pointerTypes.put(start, candidate);
			return;
		}
		boolean existingLayout = isOwnedAutoStructure(existingTarget);
		boolean candidateLayout = isOwnedAutoStructure(candidateTarget);
		if (candidateLayout && !existingLayout) {
			pointerTypes.put(start, candidate);
			return;
		}
		if (existingLayout && !candidateLayout) {
			return;
		}
		pointerTypes.put(start, new PointerDataType(VoidDataType.dataType,
			program.getDataTypeManager()));
	}

	private boolean isOwnedAutoStructure(DataType type) {
		return type instanceof Structure structure &&
			"/auto_structs".equals(structure.getCategoryPath().getPath()) &&
			structure.getName().startsWith("astruct");
	}

	private boolean isVoidType(DataType type) {
		return type instanceof VoidDataType || "void".equals(type.getName());
	}

	private Selection selectPairs(List<Integer> candidates, Map<Integer, Integer> scores,
			int index, Map<Integer, Selection> memo) {
		if (index >= candidates.size()) {
			return new Selection(0, Set.of(), false);
		}
		Selection cached = memo.get(index);
		if (cached != null) {
			return cached;
		}

		int start = candidates.get(index);
		Selection skipped = selectPairs(candidates, scores, index + 1, memo);
		int next = index + 1;
		while (next < candidates.size() && candidates.get(next) <= start + 1) {
			next++;
		}
		Selection tail = selectPairs(candidates, scores, next, memo);
		Set<Integer> takenStarts = new HashSet<>(tail.starts());
		takenStarts.add(start);
		Selection taken = new Selection(scores.get(start) + tail.score(), takenStarts,
			tail.ambiguous());

		Selection result;
		if (taken.score() > skipped.score()) {
			result = taken;
		}
		else if (skipped.score() > taken.score()) {
			result = skipped;
		}
		else if (taken.score() == 0 || taken.starts().equals(skipped.starts())) {
			result = skipped;
		}
		else {
			result = new Selection(taken.score(), taken.starts(), true);
		}
		memo.put(index, result);
		return result;
	}

	private boolean isLegalPairStart(int start) {
		return (start >= 0 && start <= 2) || start >= 4;
	}

	private Set<Integer> traceParameterWords(Program program, Varnode varnode, int depth,
			Set<Varnode> visited) {
		Set<Integer> result = new HashSet<>();
		if (varnode == null || depth > MAX_TRACE_DEPTH || !visited.add(varnode) ||
			varnode.isConstant()) {
			return result;
		}
		Integer parameterWord = parameterWord(varnode);
		if (parameterWord != null) {
			result.add(parameterWord);
			return result;
		}
		HighVariable directHigh = varnode.getHigh();
		HighSymbol directSymbol = directHigh == null ? null : directHigh.getSymbol();
		if ((varnode.isInput() ||
			(directSymbol != null && directSymbol.isParameter())) &&
			varnode.getAddress().isRegisterAddress() &&
			varnode.getSize() == 2) {
			Integer slot = argumentSlot(
				program.getRegister(varnode.getAddress(), varnode.getSize()));
			if (slot != null) {
				result.add(slot);
				return result;
			}
		}

		PcodeOp definition = varnode.getDef();
		if (definition == null) {
			Register register = program.getRegister(varnode.getAddress(), varnode.getSize());
			Integer slot = argumentSlot(register);
			if (slot != null) {
				result.add(slot);
			}
			return result;
		}
		if (definition.getOpcode() == PcodeOp.SUBPIECE &&
			definition.getNumInputs() == 2 && varnode.getSize() == 2 &&
			definition.getInput(1).isConstant()) {
			Varnode whole = definition.getInput(0);
			HighVariable high = whole.getHigh();
			HighSymbol symbol = high == null ? null : high.getSymbol();
			if (symbol != null && symbol.isParameter() &&
				symbol.getStorage().size() == 4) {
				Integer start = parameterStart(symbol.getStorage());
				long byteOffset = definition.getInput(1).getOffset();
				if (start != null && (byteOffset == 0 || byteOffset == 2)) {
					result.add(start + (int) (byteOffset / 2));
					return result;
				}
			}
		}

		switch (definition.getOpcode()) {
			case PcodeOp.COPY:
			case PcodeOp.CAST:
			case PcodeOp.INT_ZEXT:
			case PcodeOp.INT_SEXT:
			case PcodeOp.SUBPIECE:
				result.addAll(traceParameterWords(program, definition.getInput(0), depth + 1,
					visited));
				break;
			case PcodeOp.INDIRECT:
				result.addAll(traceParameterWords(program, definition.getInput(0), depth + 1,
					visited));
				break;
			case PcodeOp.INT_ADD:
			case PcodeOp.INT_SUB:
			case PcodeOp.INT_AND:
			case PcodeOp.INT_OR:
			case PcodeOp.PTRADD:
			case PcodeOp.PTRSUB:
			case PcodeOp.PIECE:
			case PcodeOp.MULTIEQUAL:
				for (int i = 0; i < definition.getNumInputs(); i++) {
					result.addAll(traceParameterWords(program, definition.getInput(i), depth + 1,
						visited));
				}
				break;
			default:
				break;
		}
		return result;
	}

	private Integer parameterWord(Varnode varnode) {
		HighVariable high = varnode.getHigh();
		HighSymbol symbol = high == null ? null : high.getSymbol();
		if (symbol == null) {
			return null;
		}
		VariableStorage storage = symbol.getStorage();
		// Register inputs retain their architectural varnodes and are traced below.
		// Positive stack offsets are incoming TASKING argument words.  Until the DB
		// signature has been widened, the decompiler names these no-def inputs
		// unaff_000000XX instead of marking them as formal parameters; they are still
		// ABI parameter slots.  Refuse defined stack values (locals), negative stack
		// offsets, and compound symbols whose high/low subpiece cannot be identified
		// from the symbol's start offset alone.
		if (!symbol.isParameter() && varnode.getDef() != null) {
			return null;
		}
		if (!storage.isStackStorage() || storage.size() != 2 ||
			storage.getStackOffset() < 0 ||
			(storage.getStackOffset() & 1) != 0) {
			return null;
		}
		return 4 + storage.getStackOffset() / 2;
	}

	private Integer argumentSlot(Register register) {
		if (register == null) {
			return null;
		}
		String name = register.getName().toLowerCase();
		if (!name.matches("r1[2-5]")) {
			return null;
		}
		int number = Integer.parseInt(name.substring(1));
		if (number < FIRST_ARGUMENT_REGISTER || number > LAST_ARGUMENT_REGISTER) {
			return null;
		}
		return number - FIRST_ARGUMENT_REGISTER;
	}

	private boolean signatureMatches(Function function, Set<Integer> pairStarts,
			Set<Integer> liveSlots, Map<Integer, DataType> pointerTypes) {
		Map<Integer, Parameter> parameters = new HashMap<>();
		int lastSlot = -1;
		for (Parameter parameter : function.getParameters()) {
			Integer start = parameterStart(parameter.getVariableStorage());
			if (start != null) {
				parameters.put(start, parameter);
				lastSlot = Math.max(lastSlot,
					start + Math.max(1, parameter.getVariableStorage().size() / 2) - 1);
			}
		}
		for (int start : pairStarts) {
			lastSlot = Math.max(lastSlot, start + 1);
		}
		for (int slot : liveSlots) {
			lastSlot = Math.max(lastSlot, slot);
		}

		int expectedCount = 0;
		for (int slot = 0; slot <= lastSlot;) {
			Parameter parameter = parameters.get(slot);
			if (pairStarts.contains(slot)) {
				if (parameter == null || !isPointerType(parameter.getFormalDataType()) ||
					parameter.getVariableStorage().size() != 4 ||
					!existingPointerSatisfies(parameter.getFormalDataType(),
						pointerTypes.get(slot))) {
					return false;
				}
				slot += 2;
			}
			else {
				if (parameter == null) {
					return false;
				}
				int span = Math.max(1, parameter.getVariableStorage().size() / 2);
				if (overlapsInferredPair(slot, span, pairStarts)) {
					return false;
				}
				slot += span;
			}
			expectedCount++;
		}
		return function.getParameterCount() == expectedCount;
	}

	private Set<Integer> retainSupportedPairs(Function function, Set<Integer> pairStarts,
			Set<Integer> liveSlots) {
		if (pairStarts.stream().noneMatch(start -> start >= 4)) {
			return pairStarts;
		}

		boolean[] occupiedRegisters = new boolean[4];
		for (int start : pairStarts) {
			if (start < 4) {
				occupiedRegisters[start] = true;
				occupiedRegisters[start + 1] = true;
			}
		}
		for (int slot : liveSlots) {
			if (slot >= 0 && slot < occupiedRegisters.length) {
				occupiedRegisters[slot] = true;
			}
		}
		for (Parameter parameter : function.getParameters()) {
			Integer start = registerStart(parameter.getVariableStorage());
			if (start == null) {
				continue;
			}
			int span = Math.max(1, parameter.getVariableStorage().size() / 2);
			for (int slot = start; slot < Math.min(4, start + span); slot++) {
				occupiedRegisters[slot] = true;
			}
		}
		for (boolean occupied : occupiedRegisters) {
			if (!occupied) {
				Set<Integer> registerPairs = new HashSet<>();
				for (int start : pairStarts) {
					if (start < 4) {
						registerPairs.add(start);
					}
				}
				return Set.copyOf(registerPairs);
			}
		}
		return pairStarts;
	}

	/**
	 * Code-pointer inference runs after data inference during normal analysis, but
	 * users can rerun either one-shot analyzer independently.  Concrete callback
	 * types are always authoritative.  An analyzer-owned generic fpointer may be
	 * repaired as data only when it has no semantic marker from the code-pointer
	 * pass.  A direct or transitively forwarded far-indirect use is stronger than
	 * an apparent PAGE:OFFSET operation recovered from the same stale HighSymbol;
	 * a coincidental exact function-address constant alone is intentionally not.
	 */
	private Set<Integer> removeFunctionPointerConflicts(Program program, Function function,
			Set<Integer> pairStarts, Set<Integer> directPagedPairs,
			Map<Integer, DataType> pointerTypes) {
		Set<Integer> retained = new HashSet<>();
		for (int candidateStart : pairStarts) {
			boolean overlaps = false;
			for (Parameter parameter : function.getParameters()) {
				if (!isFunctionPointer(parameter.getFormalDataType())) {
					continue;
				}
				Integer existingStart = parameterStart(parameter.getVariableStorage());
				if (existingStart == null) {
					continue;
				}
				int span = Math.max(1, parameter.getVariableStorage().size() / 2);
				if (candidateStart < existingStart + span &&
					existingStart < candidateStart + 2) {
					DataType inferred = pointerTypes.get(candidateStart);
					boolean provenData = directPagedPairs.contains(candidateStart) ||
						(inferred != null && pointerDataType(inferred) != null &&
							!isFunctionPointer(inferred));
					boolean provenCode =
						C166CodePointerPhase.hasSemanticCodePointerEvidence(program,
							function, existingStart);
					overlaps = !(function.getSignatureSource() == SourceType.ANALYSIS &&
						isGenericFunctionPointer(parameter.getFormalDataType()) && provenData &&
						!provenCode);
					break;
				}
			}
			if (!overlaps) {
				retained.add(candidateStart);
			}
		}
		return Set.copyOf(retained);
	}

	/**
	 * A stale generic pointer can manufacture PIECE and forwarding evidence from
	 * its own DB type.  Do not let that circular evidence undo a scalar repair.
	 * An actual SEGMENTOP sourced from both input words can override the weaker
	 * input-bit-test contradiction.  It cannot override a complete two-by-two
	 * constant rectangle: the decompiler may itself manufacture SEGMENTOP from a
	 * stale pointer type, which is the circular inference this filter prevents.
	 */
	private Set<Integer> removeCallSiteScalarConflicts(Function function,
			Set<Integer> pairStarts, Set<Integer> directPagedPairs,
			Map<Function, Set<Integer>> scalarPairs,
			Map<Function, Set<Integer>> strictScalarPairs) {
		Set<Integer> conflicts = scalarPairs.get(function);
		if (conflicts == null || conflicts.isEmpty()) {
			return pairStarts;
		}
		Set<Integer> strict = strictScalarPairs.getOrDefault(function, Set.of());
		Set<Integer> retained = new HashSet<>();
		for (int start : pairStarts) {
			if (!conflicts.contains(start) ||
				(directPagedPairs.contains(start) && !strict.contains(start))) {
				retained.add(start);
			}
		}
		return Set.copyOf(retained);
	}

	private void updateSignature(Program program, Function function, Set<Integer> pairStarts,
			Set<Integer> liveSlots, Map<Integer, DataType> pointerTypes)
			throws DuplicateNameException, InvalidInputException {
		Map<Integer, Parameter> registerParameters = new HashMap<>();
		Map<Integer, Parameter> stackParameters = new HashMap<>();
		int lastRegisterSlot = -1;
		int lastStackWord = -1;
		for (Parameter parameter : function.getParameters()) {
			VariableStorage storage = parameter.getVariableStorage();
			Integer start = registerStart(storage);
			if (start != null) {
				registerParameters.put(start, parameter);
				lastRegisterSlot = Math.max(lastRegisterSlot,
					start + Math.max(1, storage.size() / 2) - 1);
			}
			else if (storage.hasStackStorage()) {
				int word = storage.getStackOffset() / 2;
				stackParameters.put(word, parameter);
				lastStackWord = Math.max(lastStackWord,
					word + Math.max(1, storage.size() / 2) - 1);
			}
		}
		for (int start : pairStarts) {
			if (start < 4) {
				lastRegisterSlot = Math.max(lastRegisterSlot, start + 1);
			}
			else {
				lastRegisterSlot = Math.max(lastRegisterSlot, 3);
				lastStackWord = Math.max(lastStackWord, start - 4 + 1);
			}
		}
		for (int slot : liveSlots) {
			if (slot < 4) {
				lastRegisterSlot = Math.max(lastRegisterSlot, slot);
			}
			else {
				lastRegisterSlot = Math.max(lastRegisterSlot, 3);
				lastStackWord = Math.max(lastStackWord, slot - 4);
			}
		}

		List<Variable> parameters = new ArrayList<>();
		for (int slot = 0; slot <= lastRegisterSlot;) {
			Parameter existing = registerParameters.get(slot);
			if (pairStarts.contains(slot)) {
				parameters.add(new ParameterImpl(existingName(existing),
					inferredPointerType(program, existing, pointerTypes.get(slot)),
					program));
				slot += 2;
				continue;
			}
			if (existing != null) {
				int span = Math.max(1, existing.getVariableStorage().size() / 2);
				if (!overlapsInferredPair(slot, span, pairStarts)) {
					parameters.add(new ParameterImpl(existingName(existing),
						existing.getFormalDataType(), program));
					slot += span;
					continue;
				}
				parameters.add(new ParameterImpl(null, Undefined.getUndefinedDataType(2), program));
				slot++;
				continue;
			}
			parameters.add(new ParameterImpl(null, Undefined.getUndefinedDataType(2), program));
			slot++;
		}
		for (int word = 0; word <= lastStackWord;) {
			int encodedStart = 4 + word;
			Parameter existing = stackParameters.get(word);
			if (pairStarts.contains(encodedStart)) {
				parameters.add(new ParameterImpl(existingName(existing),
					inferredPointerType(program, existing,
						pointerTypes.get(encodedStart)), program));
				word += 2;
				continue;
			}
			if (existing != null) {
				int span = Math.max(1, existing.getVariableStorage().size() / 2);
				if (!overlapsInferredPair(encodedStart, span, pairStarts)) {
					parameters.add(new ParameterImpl(existingName(existing),
						existing.getFormalDataType(), program));
					word += span;
					continue;
				}
			}
			parameters.add(new ParameterImpl(null, Undefined.getUndefinedDataType(2), program));
			word++;
		}

		function.updateFunction(CALLING_CONVENTION, null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
	}

	private boolean existingPointerSatisfies(DataType existing, DataType inferred) {
		if (isFunctionPointer(existing)) {
			return !(isGenericFunctionPointer(existing) && inferred != null &&
				pointerDataType(inferred) != null && !isFunctionPointer(inferred));
		}
		Pointer existingPointer = pointerDataType(existing);
		Pointer inferredPointer = isFunctionPointer(inferred) ? null : pointerDataType(inferred);
		if (existingPointer == null || inferredPointer == null) {
			return inferredPointer == null;
		}
		DataType existingTarget = existingPointer.getDataType();
		DataType inferredTarget = inferredPointer.getDataType();
		return !isVoidType(existingTarget) || isVoidType(inferredTarget) ||
			existingTarget.isEquivalent(inferredTarget);
	}

	private DataType inferredPointerType(Program program, Parameter existing,
			DataType inferred) {
		if (existing != null && isFunctionPointer(existing.getFormalDataType())) {
			if (!isGenericFunctionPointer(existing.getFormalDataType()) || inferred == null ||
				pointerDataType(inferred) == null || isFunctionPointer(inferred)) {
				return existing.getFormalDataType();
			}
		}
		if (existing != null && isPointerType(existing.getFormalDataType()) &&
			!isFunctionPointer(existing.getFormalDataType())) {
			Pointer existingPointer = pointerDataType(existing.getFormalDataType());
			if (!isVoidType(existingPointer.getDataType()) || inferred == null ||
				isVoidType(pointerDataType(inferred).getDataType())) {
				return existing.getFormalDataType();
			}
		}
		Pointer inferredPointer = isFunctionPointer(inferred) ? null : pointerDataType(inferred);
		DataType pointedTo = inferredPointer == null ? VoidDataType.dataType :
			inferredPointer.getDataType();
		return new PointerDataType(pointedTo, program.getDataTypeManager());
	}

	private boolean overlapsInferredPair(int start, int span, Set<Integer> pairStarts) {
		int end = start + span;
		for (int pairStart : pairStarts) {
			if (start < pairStart + 2 && pairStart < end) {
				return true;
			}
		}
		return false;
	}

	private String existingName(Parameter parameter) {
		if (parameter == null || parameter.getSource() == SourceType.DEFAULT) {
			return null;
		}
		return parameter.getName();
	}

	private Integer registerStart(VariableStorage storage) {
		List<Register> registers = storage.getRegisters();
		if (registers == null) {
			return null;
		}
		int minimum = Integer.MAX_VALUE;
		boolean found = false;
		for (Register register : registers) {
			Integer slot = argumentSlot(register);
			if (slot == null) {
				return null;
			}
			minimum = Math.min(minimum, slot);
			found = true;
		}
		return found ? minimum : null;
	}

	private Integer parameterStart(VariableStorage storage) {
		Integer register = registerStart(storage);
		if (register != null) {
			return register;
		}
		if (storage.isStackStorage() && storage.getStackOffset() >= 0 &&
			(storage.getStackOffset() & 1) == 0) {
			return 4 + storage.getStackOffset() / 2;
		}
		return null;
	}

	private void report(Program program, String message) {
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
		PluginTool tool = manager.getAnalysisTool();
		if (tool != null) {
			ConsoleService console = tool.getService(ConsoleService.class);
			if (console != null) {
				console.addMessage(getName(), message);
				return;
			}
		}
		Msg.info(this, getName() + "> " + message);
	}

	private record Inference(Set<Integer> pairStarts, Set<Integer> liveSlots,
			Map<Integer, DataType> pointerTypes, Set<Address> globalPointerStarts,
			Set<Integer> directPagedPairs, boolean ambiguous) {
	}

	private record RecoveredParameterPointer(int start, DataType type) {
	}

	private record Selection(int score, Set<Integer> starts, boolean ambiguous) {
	}
}
