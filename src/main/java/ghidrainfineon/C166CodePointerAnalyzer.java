package ghidrainfineon;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Joins TASKING Classic code-pointer argument words without applying the data
 * pointer PAGE:OFFSET interpretation.
 * <p>
 * A far code pointer is SEGMENT:OFFSET.  Call-site constants are accepted only
 * when that concatenation names the exact entry point of a function in
 * executable memory.  The inferred parameter is a generic function pointer;
 * the patched decompiler recognizes its TYPE_CODE target and therefore keeps
 * it out of the far-data-pointer segment operation.
 * <p>
 * A parameter which provably supplies R5:R4 at a far-indirect dispatcher is
 * also code-pointer evidence.  R12-R15 at that dispatcher are never evidence:
 * they are ordinary arguments of the runtime target and have independent
 * types.
 */
public class C166CodePointerAnalyzer extends AbstractAnalyzer {

	private static final String COMPILER_ID = "tasking-classic-large";
	private static final String CALLING_CONVENTION = "__tasking_c166_classic";
	private static final String GENERIC_FUNCTION_NAME = "function";
	private static final String GENERIC_FUNCTION_PATH = "/c166/function";
	private static final String GENERIC_FUNCTION_POINTER_NAME = "fpointer";
	private static final String LEGACY_GENERIC_FUNCTION_PATH = "/__c166_far_function";
	private static final String ANALYSIS_OPTIONS = "C166 TASKING Code Pointer Inference";
	private static final String SEMANTIC_EVIDENCE_PREFIX =
		"Semantic code-pointer parameter slots at ";
	private static final Map<Program, Map<Address, Set<Integer>>> TRANSIENT_SEMANTIC_EVIDENCE =
		Collections.synchronizedMap(new WeakHashMap<>());
	private static final int FIRST_ARGUMENT_REGISTER = 12;
	private static final int MAX_SETUP_SCAN_INSTRUCTIONS = 256;

	public C166CodePointerAnalyzer() {
		super("C166 TASKING Code Pointer Inference",
			"Joins SEGMENT:OFFSET arguments which resolve to executable function entries.",
			AnalyzerType.FUNCTION_ANALYZER);
		// Let paged-memory evidence establish true data pointers first.
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after().after().after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguageID().getIdAsString().startsWith("C166:") &&
			COMPILER_ID.equals(
				program.getCompilerSpec().getCompilerSpecID().getIdAsString());
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		boolean fullScan = set == null || set.isEmpty() || set.contains(program.getMemory());
		Iterator<Function> functions = fullScan
			? program.getFunctionManager().getFunctions(true)
			: program.getFunctionManager().getFunctionsOverlapping(set);
		List<Function> callers = new ArrayList<>();
		functions.forEachRemaining(callers::add);
		monitor.initialize(Math.max(1, callers.size()),
			"C166 code-pointer inference: scanning call sites");

		Map<Function, Map<Integer, Integer>> scoresByTarget = new HashMap<>();
		Map<Function, Map<Integer, List<CodePointerEvidence>>> evidenceByTarget =
			new HashMap<>();
		Map<Function, Map<Integer, Set<ConstantWordPair>>> constantPairsByTarget =
			new HashMap<>();
		Map<Function, List<C166TaskingCallArguments.CallWords>> callWordsByTarget =
			new HashMap<>();
		Map<Function, Set<Integer>> semanticEvidenceByTarget = new HashMap<>();
		List<DirectCallSite> directCalls = new ArrayList<>();
		Map<Function, Boolean> dispatcherCache = new HashMap<>();
		BasicBlockModel blocks = new BasicBlockModel(program);
		int callsSeen = 0;
		int evidenceCount = 0;
		int indirectUseCount = 0;
		for (Function caller : callers) {
			monitor.checkCancelled();
			InstructionIterator instructions =
				program.getListing().getInstructions(caller.getBody(), true);
			while (instructions.hasNext()) {
				monitor.checkCancelled();
				Instruction instruction = instructions.next();
				if (!instruction.getFlowType().isCall()) {
					continue;
				}
				Function target = directTarget(program, instruction);
				if (target == null) {
					continue;
				}
				boolean dispatcher = dispatcherCache.computeIfAbsent(target,
					candidate -> isFarIndirectDispatcher(program, candidate));
				callsSeen++;
				if (dispatcher) {
					if (mayUpdate(caller) && usesTaskingConvention(caller)) {
						Integer start = dispatcherTargetPair(program, caller, instruction);
						if (start != null) {
							addSemanticEvidence(scoresByTarget, semanticEvidenceByTarget,
								caller, start);
							indirectUseCount++;
						}
					}
					continue;
				}
				directCalls.add(new DirectCallSite(caller, target, instruction));
				if (!mayUpdate(target) || !usesTaskingConvention(target)) {
					continue;
				}
				C166TaskingCallArguments.CallWords words =
					C166TaskingCallArguments.recover(program, caller, instruction, blocks, monitor);
				callWordsByTarget.computeIfAbsent(target, ignored -> new ArrayList<>()).add(words);
				recordConstantWordPairs(target, words, constantPairsByTarget);
				Map<Integer, CodePointerEvidence> evidence = codePointerEvidence(program, words);
				Map<Integer, Integer> scores =
					scoresByTarget.computeIfAbsent(target, ignored -> new HashMap<>());
				Map<Integer, List<CodePointerEvidence>> occurrences =
					evidenceByTarget.computeIfAbsent(target, ignored -> new HashMap<>());
				for (Map.Entry<Integer, CodePointerEvidence> item : evidence.entrySet()) {
					int start = item.getKey();
					scores.merge(start, 1, Integer::sum);
					occurrences.computeIfAbsent(start, ignored -> new ArrayList<>())
						.add(item.getValue());
					evidenceCount++;
				}
			}
			monitor.incrementProgress(1);
		}

		Set<Function> updatedFunctions = new HashSet<>();
		int inferredParameters = 0;
		int referenceCount = 0;
		int referencesRemoved = 0;
		Set<Function> ambiguousFunctions = new HashSet<>();
		Map<Function, Set<Integer>> independentScalarPairs = independentConstantWordPairs(
			constantPairsByTarget, semanticEvidenceByTarget);
		independentScalarPairs = propagateEntryForwardingScalarPairs(program,
			independentScalarPairs, monitor);
		Map<Function, Set<Integer>> packedScalarPairs = packedScalarPairs(program, callers,
			directCalls, blocks, callWordsByTarget, semanticEvidenceByTarget, monitor);
		independentScalarPairs = removePackedScalarPairs(independentScalarPairs,
			packedScalarPairs);
		Map<Function, Set<Integer>> scalarPairs = unionScalarPairs(independentScalarPairs,
			packedScalarPairs);
		Map<Function, Set<Integer>> supportedEvidenceByTarget =
			mutableSetMap(semanticEvidenceByTarget);
		Map<Function, Set<Integer>> forwardingEvidenceByTarget =
			mutableSetMap(semanticEvidenceByTarget);
		// Register exact function-entry constants only after the independent-word
		// rectangle check above.  Every occurrence supports the local callee type;
		// only repeated occurrences become backwards-forwarding roots.  Four
		// individually valid code addresses may still be two scalar arguments.
		registerDirectEvidence(evidenceByTarget, scalarPairs,
			supportedEvidenceByTarget, forwardingEvidenceByTarget);
		int repairedPointers = repairScalarPointers(program, independentScalarPairs,
			packedScalarPairs, callWordsByTarget, log);
		UpdateStats update = applyEvidence(program, scoresByTarget, evidenceByTarget,
			semanticEvidenceByTarget, scalarPairs, updatedFunctions, ambiguousFunctions,
			monitor, log);
		inferredParameters += update.inferredParameters();
		referenceCount += update.referenceCount();
		referencesRemoved += update.referencesRemoved();

		int forwardingEvidenceCount = 0;
		int forwardingPasses = 0;
		while (true) {
			monitor.checkCancelled();
			int added = collectForwardingEvidence(program, directCalls, blocks,
				scoresByTarget, semanticEvidenceByTarget, forwardingEvidenceByTarget,
				supportedEvidenceByTarget, monitor);
			if (added == 0) {
				break;
			}
			forwardingEvidenceCount += added;
			forwardingPasses++;
			update = applyEvidence(program, scoresByTarget, evidenceByTarget,
				semanticEvidenceByTarget, scalarPairs, updatedFunctions, ambiguousFunctions,
				monitor, log);
			inferredParameters += update.inferredParameters();
			referenceCount += update.referenceCount();
			referencesRemoved += update.referencesRemoved();
		}
		publishSemanticEvidence(program, callers, semanticEvidenceByTarget, fullScan);
		if (fullScan) {
			repairedPointers += repairUnsupportedGenericFunctionPointers(program, callers,
				supportedEvidenceByTarget, log);
		}

		report(program, (fullScan ? "Full" : "Incremental") + " scan: inspected " +
			callers.size() + " caller function(s) and " + callsSeen +
			" direct call(s); found " + evidenceCount +
			" executable SEGMENT:OFFSET argument occurrence(s) and " + indirectUseCount +
			" parameter-fed far-indirect target use(s), propagated " +
			forwardingEvidenceCount + " function-pointer parameter use(s) in " +
			forwardingPasses + " fixed-point pass(es), inferred " +
			inferredParameters + " code-pointer-sized parameter(s) in " +
			updatedFunctions.size() + " function(s), added or updated " + referenceCount +
			" code-target reference(s), removed " + referencesRemoved +
			" data-conflicting reference(s), rejected " +
			scalarPairs.values().stream().mapToInt(Set::size).sum() +
			" scalar pair conflict(s) (" +
			independentScalarPairs.values().stream().mapToInt(Set::size).sum() +
			" independent-word, " +
			packedScalarPairs.values().stream().mapToInt(Set::size).sum() +
			" packed), repaired " + repairedPointers +
			" stale generic pointer(s), " + ambiguousFunctions.size() +
			" ambiguous.");
		return true;
	}

	/**
	 * Return whether the code-pointer pass proved that this exact ABI pair feeds
	 * a far-indirect call, either directly or through a typed forwarding chain.
	 * The marker is deliberately narrower than the inferred {@code fpointer}
	 * type: an exact function-address constant alone is not semantic code use and
	 * can still lose to a real PAGE:OFFSET dereference in the data-pointer pass.
	 */
	static boolean hasSemanticCodePointerEvidence(Program program, Function function,
			int start) {
		Map<Address, Set<Integer>> transientEvidence =
			TRANSIENT_SEMANTIC_EVIDENCE.get(program);
		if (transientEvidence != null && transientEvidence
			.getOrDefault(function.getEntryPoint(), Set.of()).contains(start)) {
			return true;
		}
		String slots = program.getOptions(ANALYSIS_OPTIONS).getString(
			semanticEvidenceKey(function), null);
		return slots != null && ("," + slots + ",").contains("," + start + ",");
	}

	private static String semanticEvidenceKey(Function function) {
		return SEMANTIC_EVIDENCE_PREFIX + function.getEntryPoint();
	}

	private void publishSemanticEvidence(Program program, List<Function> scannedFunctions,
			Map<Function, Set<Integer>> evidenceByFunction, boolean fullScan) {
		synchronized (TRANSIENT_SEMANTIC_EVIDENCE) {
			Map<Address, Set<Integer>> transientEvidence = fullScan ? new HashMap<>() :
				new HashMap<>(TRANSIENT_SEMANTIC_EVIDENCE.getOrDefault(program, Map.of()));
			if (!fullScan) {
				for (Function function : scannedFunctions) {
					transientEvidence.remove(function.getEntryPoint());
				}
			}
			for (Map.Entry<Function, Set<Integer>> entry : evidenceByFunction.entrySet()) {
				if (!entry.getValue().isEmpty()) {
					transientEvidence.put(entry.getKey().getEntryPoint(),
						Set.copyOf(entry.getValue()));
				}
			}
			TRANSIENT_SEMANTIC_EVIDENCE.put(program, Map.copyOf(transientEvidence));
		}

		Options evidence = program.getOptions(ANALYSIS_OPTIONS);
		if (fullScan) {
			for (String option : List.copyOf(evidence.getOptionNames())) {
				if (option.startsWith(SEMANTIC_EVIDENCE_PREFIX)) {
					evidence.removeOption(option);
				}
			}
		}
		else {
			for (Function function : scannedFunctions) {
				evidence.removeOption(semanticEvidenceKey(function));
			}
		}
		for (Map.Entry<Function, Set<Integer>> entry : evidenceByFunction.entrySet()) {
			List<Integer> starts = new ArrayList<>(entry.getValue());
			Collections.sort(starts);
			StringBuilder encoded = new StringBuilder();
			for (int start : starts) {
				if (encoded.length() != 0) {
					encoded.append(',');
				}
				encoded.append(start);
			}
			if (encoded.length() != 0) {
				evidence.setString(semanticEvidenceKey(entry.getKey()), encoded.toString());
			}
		}
	}

	private UpdateStats applyEvidence(Program program,
			Map<Function, Map<Integer, Integer>> scoresByTarget,
			Map<Function, Map<Integer, List<CodePointerEvidence>>> evidenceByTarget,
			Map<Function, Set<Integer>> semanticEvidenceByTarget,
			Map<Function, Set<Integer>> scalarPairs,
			Set<Function> updatedFunctions, Set<Function> ambiguousFunctions,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		int inferredParameters = 0;
		int referenceCount = 0;
		int referencesRemoved = 0;
		for (Map.Entry<Function, Map<Integer, Integer>> entry : scoresByTarget.entrySet()) {
			monitor.checkCancelled();
			Function function = entry.getKey();
			Map<Integer, Integer> scores = entry.getValue();
			List<Integer> candidates = new ArrayList<>(scores.keySet());
			Collections.sort(candidates);
			Selection selection = selectPairs(candidates, scores, 0, new HashMap<>());
			if (selection.ambiguous()) {
				ambiguousFunctions.add(function);
				continue;
			}
			ambiguousFunctions.remove(function);
			Map<Integer, List<CodePointerEvidence>> occurrences =
				evidenceByTarget.getOrDefault(function, Map.of());
			Set<Integer> starts = removePointerConflicts(program, function,
				selection.starts(), occurrences,
				semanticEvidenceByTarget.getOrDefault(function, Set.of()));
			starts = removeScalarConflicts(function, starts, scalarPairs);
			for (int conflict : difference(selection.starts(), starts)) {
				for (CodePointerEvidence evidence : occurrences.getOrDefault(conflict, List.of())) {
					referencesRemoved += removeCodePointerReference(program, evidence);
				}
			}
			for (int start : starts) {
				for (CodePointerEvidence evidence : occurrences.getOrDefault(start, List.of())) {
					referencesRemoved += removeConflictingPagedReference(program, evidence);
					referenceCount += addCodePointerReference(program, evidence);
				}
			}
			if (starts.isEmpty() || signatureMatches(function, starts)) {
				continue;
			}
			int newlyTyped = 0;
			for (int start : starts) {
				if (!hasFunctionPointerAt(function, start)) {
					newlyTyped++;
				}
			}
			try {
				updateSignature(program, function, starts);
				updatedFunctions.add(function);
				inferredParameters += newlyTyped;
			}
			catch (DuplicateNameException | InvalidInputException e) {
				log.appendException(e);
			}
		}
		return new UpdateStats(inferredParameters, referenceCount, referencesRemoved);
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
				Function target =
					program.getFunctionManager().getFunctionAt(reference.getToAddress());
				if (target != null) {
					return target;
				}
			}
		}
		return null;
	}

	/**
	 * A call-fixup dispatcher consumes R5:R4 as its target.  R12-R15 remain the
	 * ordinary arguments of whichever function is selected at runtime, so their
	 * values are deliberately not used to type the dispatcher's own signature.
	 */
	private boolean isFarIndirectDispatcher(Program program, Function function) {
		return C166TaskingRuntimeAnalyzer.isFarIndirectDispatcher(program, function);
	}

	private Integer dispatcherTargetPair(Program program, Function function, Instruction call) {
		// Unlike speculative constant recovery, reaching this helper already proves
		// code semantics.  The strong tracer below stops conservatively at calls and
		// control-flow boundaries, then uses only verified frame/incoming-register
		// state.  Using the whole function avoids both misleading call-delimited
		// BasicBlockModel regions and an expensive global block lookup on full flashes.
		AddressSetView setupRegion = function.getBody();
		// Reaching the dispatcher is direct code-use evidence, so it is safe to use
		// the conservative cross-block/frame fallback.  TASKING wrappers commonly
		// save an incoming callback before a branch and restore it immediately before
		// the dispatcher call (M55 FUN_740b28 is one such shape).
		Integer low = traceScalarParameterRegister(program, function, setupRegion, call,
			program.getRegister("r4"), 0, new HashSet<>());
		Integer high = traceScalarParameterRegister(program, function, setupRegion, call,
			program.getRegister("r5"), 0, new HashSet<>());
		if (low == null || high == null || high != low + 1 || !isLegalPairStart(low)) {
			return null;
		}
		return low;
	}

	private Integer traceParameterRegister(Program program, Function function,
			AddressSetView setupRegion, Instruction before, Register register, int depth,
			Set<String> visited) {
		return traceParameterRegister(program, function, setupRegion, before, register,
			depth, visited, false);
	}

	private Integer traceScalarParameterRegister(Program program, Function function,
			AddressSetView setupRegion, Instruction before, Register register, int depth,
			Set<String> visited) {
		return traceParameterRegister(program, function, setupRegion, before, register,
			depth, visited, true);
	}

	private Integer traceParameterRegister(Program program, Function function,
			AddressSetView setupRegion, Instruction before, Register register, int depth,
			Set<String> visited, boolean allowFrameBaseline) {
		if (register == null || depth > 24 ||
			!visited.add("register:" + before.getAddress() + ":" + register.getName())) {
			return null;
		}
		Instruction instruction = program.getListing().getInstructionBefore(before.getAddress());
		for (int scanned = 0; instruction != null && scanned < MAX_SETUP_SCAN_INSTRUCTIONS;
				scanned++, instruction =
					program.getListing().getInstructionBefore(instruction.getAddress())) {
			if (!function.getBody().contains(instruction.getAddress()) ||
				!setupRegion.contains(instruction.getAddress())) {
				break;
			}
			if (instruction.getFlowType().isCall()) {
				if (allowFrameBaseline && isTaskingCalleeSavedGeneralRegister(register)) {
					continue;
				}
				return null;
			}
			if (instruction.getFlowType().isJump()) {
				if (allowFrameBaseline) {
					break;
				}
				return null;
			}
			if (!writesRegister(instruction, register)) {
				continue;
			}
			if (!instruction.getMnemonicString().equalsIgnoreCase("mov") ||
				instruction.getNumOperands() < 2 ||
				OperandType.isIndirect(instruction.getOperandType(0))) {
				return null;
			}
			Register destination = operandRegister(instruction, 0);
			if (destination == null || !overlaps(register, destination)) {
				return null;
			}
			Integer stackOffset = stackOffset(instruction, 1);
			if (stackOffset != null) {
				return traceStackParameter(program, function, setupRegion, instruction,
					stackOffset, depth + 1, visited, allowFrameBaseline);
			}
			Register source = operandRegister(instruction, 1);
			if (source != null && !isMemoryOperand(instruction, 1)) {
				return traceParameterRegister(program, function, setupRegion, instruction, source,
					depth + 1, visited, allowFrameBaseline);
			}
			return null;
		}
		if (setupRegion.contains(function.getEntryPoint())) {
			Integer slot = argumentSlot(register);
			if (slot != null) {
				return slot;
			}
		}
		if (!allowFrameBaseline) {
			return null;
		}
		if (isUnmodifiedIncomingArgumentBefore(program, function, before, register)) {
			return argumentSlot(register);
		}
		return savedIncomingArgumentBefore(program, function, before, register);
	}

	/**
	 * Strong scalar or actual code-use evidence may cross a basic-block boundary
	 * only when a physical argument register has no earlier definition (or
	 * intervening call) anywhere in the function's linear prefix.
	 */
	private boolean isUnmodifiedIncomingArgumentBefore(Program program, Function function,
			Instruction before, Register register) {
		if (argumentSlot(register) == null) {
			return false;
		}
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			if (instruction.getAddress().compareTo(before.getAddress()) >= 0) {
				return true;
			}
			if (instruction.getFlowType().isCall() || writesRegister(instruction, register)) {
				return false;
			}
		}
		return false;
	}

	/**
	 * Recover a callback copied in the straight-line prologue to one of TASKING's
	 * callee-saved general registers.  The copy remains trusted only when that
	 * register has no other explicit definition before the use.  Scanning every
	 * listed instruction, including mutually exclusive branches, is deliberately
	 * conservative: a write on any path rejects the result.
	 */
	private Integer savedIncomingArgumentBefore(Program program, Function function,
			Instruction before, Register register) {
		if (!isTaskingCalleeSavedGeneralRegister(register)) {
			return null;
		}
		Integer sourceSlot = null;
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			if (instruction.getAddress().compareTo(before.getAddress()) >= 0) {
				return sourceSlot;
			}
			// R6-R9 are explicitly "saved by callee" in the TASKING ABI.  Some
			// instruction-level result-object models conservatively list more call
			// clobbers than the compiler prototype; they must not invalidate these
			// registers here.
			if (instruction.getFlowType().isCall()) {
				continue;
			}
			if (!writesRegister(instruction, register)) {
				continue;
			}
			if (sourceSlot != null ||
				!instruction.getMnemonicString().equalsIgnoreCase("mov") ||
				instruction.getNumOperands() < 2 || isMemoryOperand(instruction, 1)) {
				return null;
			}
			Register destination = operandRegister(instruction, 0);
			Register source = operandRegister(instruction, 1);
			Integer slot = source == null ? null : argumentSlot(source);
			if (destination == null || !overlaps(register, destination) || slot == null ||
				!isUnmodifiedIncomingArgumentBefore(program, function, instruction, source)) {
				return null;
			}
			sourceSlot = slot;
		}
		return null;
	}

	private boolean isTaskingCalleeSavedGeneralRegister(Register register) {
		if (register == null) {
			return false;
		}
		String name = register.getName().toLowerCase();
		return name.equals("r6") || name.equals("r7") || name.equals("r8") ||
			name.equals("r9");
	}

	private Integer traceStackParameter(Program program, Function function,
			AddressSetView setupRegion, Instruction before, int initialOffset, int depth,
			Set<String> visited) {
		return traceStackParameter(program, function, setupRegion, before, initialOffset,
			depth, visited, false);
	}

	private Integer traceScalarStackParameter(Program program, Function function,
			AddressSetView setupRegion, Instruction before, int initialOffset, int depth,
			Set<String> visited) {
		return traceStackParameter(program, function, setupRegion, before, initialOffset,
			depth, visited, true);
	}

	private Integer traceStackParameter(Program program, Function function,
			AddressSetView setupRegion, Instruction before, int initialOffset, int depth,
			Set<String> visited, boolean allowFrameBaseline) {
		if (depth > 24 ||
			!visited.add("stack:" + before.getAddress() + ":" + initialOffset)) {
			return null;
		}
		int offset = initialOffset;
		Instruction instruction = program.getListing().getInstructionBefore(before.getAddress());
		for (int scanned = 0; instruction != null && scanned < MAX_SETUP_SCAN_INSTRUCTIONS;
				scanned++, instruction =
					program.getListing().getInstructionBefore(instruction.getAddress())) {
			if (!function.getBody().contains(instruction.getAddress()) ||
				!setupRegion.contains(instruction.getAddress())) {
				break;
			}
			// A TASKING call preserves the caller's software-stack frame.  Registers
			// are clobbered across calls, but an incoming word already saved at a
			// non-negative R0 offset remains traceable until R0 itself changes.
			if (instruction.getFlowType().isJump()) {
				return allowFrameBaseline ?
					frameBackedParameterSlot(program, function, offset) : null;
			}
			Integer storeOffset = stackOffset(instruction, 0);
			if (storeOffset != null && storeOffset == offset) {
				Register source = operandRegister(instruction, 1);
				return source == null ? null : traceParameterRegister(program, function,
					setupRegion, instruction, source, depth + 1, visited,
					allowFrameBaseline);
			}
			if (isStackPush(instruction)) {
				if (offset == 0) {
					Register source = operandRegister(instruction, 1);
					return source == null ? null : traceParameterRegister(program, function,
						setupRegion, instruction, source, depth + 1, visited,
						allowFrameBaseline);
				}
				offset -= 2;
				continue;
			}
			Integer delta = stackPointerDelta(instruction);
			if (delta != null) {
				offset += delta;
				continue;
			}
			Register stackPointer = program.getRegister("r0");
			if (writesRegister(instruction, stackPointer)) {
				return null;
			}
		}
		if (setupRegion.contains(function.getEntryPoint()) && offset >= 0 && (offset & 1) == 0) {
			return 4 + offset / 2;
		}
		return allowFrameBaseline ? frameBackedParameterSlot(program, function, offset) : null;
	}

	/**
	 * Recover an incoming stack slot after a control-flow boundary.  Scalar
	 * evidence is allowed to use this fallback because it starts from a concrete
	 * carry-paired operation or a typed integer callee parameter.  General
	 * function-pointer propagation deliberately keeps the stricter block-local
	 * tracer above.
	 */
	private Integer frameBackedParameterSlot(Program program, Function function,
			int offsetFromFrame) {
		Integer frameDelta = taskingFrameDelta(program, function);
		if (frameDelta == null) {
			return null;
		}
		int incomingOffset = offsetFromFrame + frameDelta;
		return incomingOffset >= 0 && (incomingOffset & 1) == 0 ?
			4 + incomingOffset / 2 : null;
	}

	/** Return R0(current)-R0(entry) for the straight-line TASKING prologue. */
	private Integer taskingFrameDelta(Program program, Function function) {
		int delta = 0;
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			if (instruction.getFlowType().isCall() || instruction.getFlowType().isJump()) {
				return delta;
			}
			if (isStackPush(instruction)) {
				delta -= 2;
				continue;
			}
			Integer adjustment = stackPointerDelta(instruction);
			if (adjustment != null) {
				delta += adjustment;
				continue;
			}
			if (writesRegister(instruction, program.getRegister("r0"))) {
				return null;
			}
		}
		return delta;
	}

	private int collectForwardingEvidence(Program program, List<DirectCallSite> directCalls,
			BasicBlockModel blocks, Map<Function, Map<Integer, Integer>> scoresByTarget,
			Map<Function, Set<Integer>> semanticEvidenceByTarget,
			Map<Function, Set<Integer>> forwardingEvidenceByTarget,
			Map<Function, Set<Integer>> supportedEvidenceByTarget, TaskMonitor monitor)
			throws CancelledException {
		int added = 0;
		for (DirectCallSite site : directCalls) {
			monitor.checkCancelled();
			if (!mayUpdate(site.caller()) || !usesTaskingConvention(site.caller())) {
				continue;
			}
			for (int start : forwardedCodePointerPairs(program, site, blocks,
				forwardingEvidenceByTarget, monitor)) {
				if (addSemanticEvidence(scoresByTarget, semanticEvidenceByTarget,
					site.caller(), start)) {
					forwardingEvidenceByTarget.computeIfAbsent(site.caller(),
						ignored -> new HashSet<>()).add(start);
					supportedEvidenceByTarget.computeIfAbsent(site.caller(),
						ignored -> new HashSet<>()).add(start);
					added++;
				}
			}
		}
		return added;
	}

	private Set<Integer> forwardedCodePointerPairs(Program program, DirectCallSite site,
			BasicBlockModel blocks, Map<Function, Set<Integer>> trustedEvidence,
			TaskMonitor monitor) throws CancelledException {
		Set<Integer> result = new HashSet<>();
		CodeBlock setupBlock = blocks.getFirstCodeBlockContaining(site.call().getAddress(), monitor);
		AddressSetView setupRegion =
			setupBlock == null ? site.caller().getBody() : setupBlock;
		for (Parameter parameter : site.target().getParameters()) {
			if (!isFunctionPointer(parameter.getFormalDataType())) {
				continue;
			}
			Integer targetStart = parameterStart(parameter.getVariableStorage());
			if (targetStart == null) {
				continue;
			}
			// Never use an analyzer-owned generic fpointer as its own proof.  It may
			// be stale database state from an older pass.  Such a type propagates
			// only when this run traced it back to repeated exact function entries or
			// an R5:R4 far-indirect use.  A one-off exact-entry collision supports the
			// local type but must not infect its callers.  Concrete USER_DEFINED or
			// IMPORTED callbacks remain authoritative roots.
			if (site.target().getSignatureSource() == SourceType.ANALYSIS &&
				isGenericAnalysisFunctionPointer(site.target(),
					parameter.getFormalDataType()) &&
				!trustedEvidence.getOrDefault(site.target(), Set.of()).contains(targetStart)) {
				continue;
			}
			// The target slot is already trusted as a callback.  Use the same
			// conservative frame-aware tracer as scalar propagation so callbacks
			// forwarded from an incoming stack slot across validation branches are not
			// lost (for example FUN_9bc42a -> FUN_9057dc).
			Integer low = traceScalarCallArgumentWord(program, site.caller(), setupRegion,
				site.call(), targetStart);
			Integer high = traceScalarCallArgumentWord(program, site.caller(), setupRegion,
				site.call(), targetStart + 1);
			if (low != null && high != null && high == low + 1 && isLegalPairStart(low)) {
				result.add(low);
			}
		}
		return Set.copyOf(result);
	}

	private Map<Function, Set<Integer>> mutableSetMap(
			Map<Function, Set<Integer>> source) {
		Map<Function, Set<Integer>> copy = new HashMap<>();
		for (Map.Entry<Function, Set<Integer>> entry : source.entrySet()) {
			copy.put(entry.getKey(), new HashSet<>(entry.getValue()));
		}
		return copy;
	}

	private void registerDirectEvidence(
			Map<Function, Map<Integer, List<CodePointerEvidence>>> evidenceByTarget,
			Map<Function, Set<Integer>> scalarPairs,
			Map<Function, Set<Integer>> supportedEvidence,
			Map<Function, Set<Integer>> forwardingEvidence) {
		for (Map.Entry<Function, Map<Integer, List<CodePointerEvidence>>> entry :
				evidenceByTarget.entrySet()) {
			Set<Integer> scalar = scalarPairs.getOrDefault(entry.getKey(), Set.of());
			for (Map.Entry<Integer, List<CodePointerEvidence>> occurrence :
					entry.getValue().entrySet()) {
				int start = occurrence.getKey();
				if (!scalar.contains(start)) {
					supportedEvidence.computeIfAbsent(entry.getKey(), ignored -> new HashSet<>())
						.add(start);
					// A single exact-entry constant is enough to type this callee's
					// local slot, but not enough to propagate that type backwards
					// through arbitrary callers.  It may be a data value which merely
					// collides with a function entry (as in M55 FUN_9ab3d0).  Repeated
					// occurrences or semantic far-indirect evidence are stable roots.
					if (occurrence.getValue().size() >= 2) {
						forwardingEvidence.computeIfAbsent(entry.getKey(),
							ignored -> new HashSet<>()).add(start);
					}
				}
			}
		}
	}

	/**
	 * Remove generic ANALYSIS fpointers which this complete scan cannot trace to
	 * an exact function entry or an actual far-indirect call.  This is what keeps
	 * old database types from becoming circular evidence on the next One Shot.
	 * Concrete callback typedefs and non-analysis signatures are never changed.
	 */
	private int repairUnsupportedGenericFunctionPointers(Program program,
			List<Function> functions, Map<Function, Set<Integer>> trustedEvidence,
			MessageLog log) {
		int repaired = 0;
		for (Function function : functions) {
			// FunctionDB delegates updateFunction() on a thunk to its ultimate target.
			// Evidence belongs to the thunk target, not to every aliasing thunk, so
			// cleaning an unsupported type through the thunk can corrupt a proven
			// callback on the target (M55 FUN_92c0c6 -> FUN_9057dc).
			if (!mayUpdate(function) ||
				function.getSignatureSource() != SourceType.ANALYSIS) {
				continue;
			}
			try {
				Set<Integer> trusted = trustedEvidence.getOrDefault(function, Set.of());
				List<Variable> parameters = new ArrayList<>();
				boolean changed = false;
				for (Parameter parameter : function.getParameters()) {
					Integer start = parameterStart(parameter.getVariableStorage());
					if (start != null && parameter.getVariableStorage().size() == 4 &&
						isGenericAnalysisFunctionPointer(function,
							parameter.getFormalDataType()) && !trusted.contains(start)) {
						parameters.add(new ParameterImpl(null,
							Undefined.getUndefinedDataType(2), program));
						parameters.add(new ParameterImpl(null,
							Undefined.getUndefinedDataType(2), program));
						changed = true;
					}
					else {
						parameters.add(new ParameterImpl(existingName(parameter),
							parameter.getFormalDataType(), program));
					}
				}
				if (!changed) {
					continue;
				}
				function.updateFunction(CALLING_CONVENTION, null, parameters,
					FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
				repaired++;
			}
			catch (DuplicateNameException | InvalidInputException e) {
				log.appendException(e);
			}
		}
		return repaired;
	}

	private Integer traceScalarCallArgumentWord(Program program, Function caller,
			AddressSetView setupRegion, Instruction call, int targetSlot) {
		if (targetSlot < 4) {
			Register register = program.getRegister("r" + (FIRST_ARGUMENT_REGISTER + targetSlot));
			return traceScalarParameterRegister(program, caller, setupRegion, call, register, 0,
				new HashSet<>());
		}
		int stackOffset = (targetSlot - 4) * 2;
		return traceScalarStackParameter(program, caller, setupRegion, call, stackOffset, 0,
			new HashSet<>());
	}

	private boolean addSemanticEvidence(
			Map<Function, Map<Integer, Integer>> scoresByTarget,
			Map<Function, Set<Integer>> semanticEvidenceByTarget, Function function,
			int start) {
		Set<Integer> starts =
			semanticEvidenceByTarget.computeIfAbsent(function, ignored -> new HashSet<>());
		if (!starts.add(start)) {
			return false;
		}
		scoresByTarget.computeIfAbsent(function, ignored -> new HashMap<>())
			.merge(start, 1, Integer::sum);
		return true;
	}

	private Integer stackOffset(Instruction instruction, int operand) {
		if (instruction == null || operand >= instruction.getNumOperands()) {
			return null;
		}
		String representation = instruction.getDefaultOperandRepresentation(operand)
			.replace(" ", "").toLowerCase();
		if (!representation.startsWith("[r0") || representation.startsWith("[-r0")) {
			return null;
		}
		Register base = operandRegister(instruction, operand);
		if (base == null || !base.getName().equalsIgnoreCase("r0")) {
			return null;
		}
		Scalar displacement = operandScalar(instruction, operand);
		return displacement == null ? 0 : (int) displacement.getSignedValue();
	}

	private boolean isMemoryOperand(Instruction instruction, int operand) {
		if (instruction == null || operand >= instruction.getNumOperands()) {
			return false;
		}
		String representation = instruction.getDefaultOperandRepresentation(operand)
			.trim();
		return representation.startsWith("[");
	}

	private Integer stackPointerDelta(Instruction instruction) {
		if (instruction == null || instruction.getNumOperands() < 2) {
			return null;
		}
		Register destination = operandRegister(instruction, 0);
		Scalar amount = instruction.getScalar(1);
		if (destination == null || !destination.getName().equalsIgnoreCase("r0") ||
			amount == null) {
			return null;
		}
		int value = (int) amount.getUnsignedValue();
		if (instruction.getMnemonicString().equalsIgnoreCase("add")) {
			return value;
		}
		if (instruction.getMnemonicString().equalsIgnoreCase("sub")) {
			return -value;
		}
		return null;
	}

	private boolean isStackPush(Instruction instruction) {
		if (!instruction.getMnemonicString().equalsIgnoreCase("mov") ||
			instruction.getNumOperands() < 2) {
			return false;
		}
		String representation = instruction.getDefaultOperandRepresentation(0)
			.replace(" ", "").toLowerCase();
		return representation.equals("[-r0]");
	}

	private void recordConstantWordPairs(Function target,
			C166TaskingCallArguments.CallWords callWords,
			Map<Function, Map<Integer, Set<ConstantWordPair>>> pairsByTarget) {
		for (Map.Entry<Integer, C166TaskingCallArguments.WordValue> entry :
				callWords.words().entrySet()) {
			int start = entry.getKey();
			if (!isLegalPairStart(start) ||
				(start >= 4 && !callWords.registerBankOccupied())) {
				continue;
			}
			C166TaskingCallArguments.WordValue low = entry.getValue();
			C166TaskingCallArguments.WordValue high = callWords.words().get(start + 1);
			if (low == null || high == null || low.constant() == null ||
				high.constant() == null) {
				continue;
			}
			pairsByTarget.computeIfAbsent(target, ignored -> new HashMap<>())
				.computeIfAbsent(start, ignored -> new HashSet<>())
				.add(new ConstantWordPair(low.constant(), high.constant()));
		}
	}

	private Map<Function, Set<Integer>> independentConstantWordPairs(
			Map<Function, Map<Integer, Set<ConstantWordPair>>> pairsByTarget,
			Map<Function, Set<Integer>> semanticEvidenceByTarget) {
		Map<Function, Set<Integer>> result = new HashMap<>();
		for (Map.Entry<Function, Map<Integer, Set<ConstantWordPair>>> target :
				pairsByTarget.entrySet()) {
			Set<Integer> semantic =
				semanticEvidenceByTarget.getOrDefault(target.getKey(), Set.of());
			for (Map.Entry<Integer, Set<ConstantWordPair>> pair :
					target.getValue().entrySet()) {
				if (!semantic.contains(pair.getKey()) &&
					hasIndependentConstantWords(pair.getValue())) {
					result.computeIfAbsent(target.getKey(), ignored -> new HashSet<>())
						.add(pair.getKey());
				}
			}
		}
		Map<Function, Set<Integer>> immutable = new HashMap<>();
		for (Map.Entry<Function, Set<Integer>> entry : result.entrySet()) {
			immutable.put(entry.getKey(), Set.copyOf(entry.getValue()));
		}
		return Map.copyOf(immutable);
	}

	/**
	 * Find four-byte integer parameters which must retain their packed ABI shape.
	 * Direct carry-pair arithmetic and a concrete integer callee parameter are
	 * positive scalar evidence.  Four-byte evidence is propagated backwards
	 * through ordinary direct calls; narrowing into a typed word parameter can
	 * repair an already existing generic fpointer without inventing a new type.
	 */
	private Map<Function, Set<Integer>> packedScalarPairs(Program program,
			List<Function> functions, List<DirectCallSite> directCalls,
			BasicBlockModel blocks,
			Map<Function, List<C166TaskingCallArguments.CallWords>> callWordsByTarget,
			Map<Function, Set<Integer>> semanticEvidenceByTarget, TaskMonitor monitor)
			throws CancelledException {
		Map<Function, Set<Integer>> result = new HashMap<>();
		Set<Function> candidates = new HashSet<>(functions);
		for (DirectCallSite site : directCalls) {
			candidates.add(site.target());
		}
		for (Function function : candidates) {
			monitor.checkCancelled();
			for (Parameter parameter : function.getParameters()) {
				Integer start = parameterStart(parameter.getVariableStorage());
				DataType type = parameter.getFormalDataType();
				if (start != null && isLegalPairStart(start) && type.getLength() == 4 &&
					isConcreteInteger(type)) {
					result.computeIfAbsent(function, ignored -> new HashSet<>()).add(start);
				}
			}
			for (int start : directCarryScalarPairs(program, function)) {
				result.computeIfAbsent(function, ignored -> new HashSet<>()).add(start);
			}
		}

		boolean changed;
		do {
			changed = false;
			for (DirectCallSite site : directCalls) {
				monitor.checkCancelled();
				if (!mayUpdate(site.caller()) || !usesTaskingConvention(site.caller())) {
					continue;
				}
				CodeBlock setupBlock =
					blocks.getFirstCodeBlockContaining(site.call().getAddress(), monitor);
				AddressSetView setupRegion =
					setupBlock == null ? site.caller().getBody() : setupBlock;
				for (int targetStart : Set.copyOf(
					result.getOrDefault(site.target(), Set.of()))) {
					Integer low = traceScalarCallArgumentWord(program, site.caller(), setupRegion,
						site.call(), targetStart);
					Integer high = traceScalarCallArgumentWord(program, site.caller(), setupRegion,
						site.call(), targetStart + 1);
					if (low != null && high != null && high == low + 1 &&
						isLegalPairStart(low) &&
						!semanticEvidenceByTarget.getOrDefault(site.caller(), Set.of())
							.contains(low)) {
						changed |= result.computeIfAbsent(site.caller(),
							ignored -> new HashSet<>()).add(low);
					}
				}
			}
		}
		while (changed);

		for (DirectCallSite site : directCalls) {
			monitor.checkCancelled();
			if (!mayUpdate(site.caller()) || !usesTaskingConvention(site.caller())) {
				continue;
			}
			CodeBlock setupBlock =
				blocks.getFirstCodeBlockContaining(site.call().getAddress(), monitor);
			AddressSetView setupRegion =
				setupBlock == null ? site.caller().getBody() : setupBlock;
			for (Parameter targetParameter : site.target().getParameters()) {
				DataType type = targetParameter.getFormalDataType();
				Integer targetStart = parameterStart(targetParameter.getVariableStorage());
				if (targetStart == null || type.getLength() > 2 ||
					!isConcreteInteger(type)) {
					continue;
				}
				Integer source = traceScalarCallArgumentWord(program, site.caller(), setupRegion,
					site.call(), targetStart);
				Integer packedStart = source == null ? null :
					genericFunctionPointerContaining(site.caller(), source);
				if (packedStart != null &&
					!semanticEvidenceByTarget.getOrDefault(site.caller(), Set.of())
						.contains(packedStart)) {
					result.computeIfAbsent(site.caller(), ignored -> new HashSet<>())
						.add(packedStart);
				}
			}
		}

		for (Map.Entry<Function, Set<Integer>> entry : new ArrayList<>(result.entrySet())) {
			Function function = entry.getKey();
			boolean laterStackScalar = entry.getValue().stream().anyMatch(start -> start >= 6);
			if (laterStackScalar && hasPackedAnalysisCandidateAt(function, 4) &&
				hasSpillHoleEvidence(program, function,
					callWordsByTarget.getOrDefault(function, List.of()))) {
				result.computeIfAbsent(function, ignored -> new HashSet<>()).add(4);
			}
		}

		Map<Function, Set<Integer>> immutable = new HashMap<>();
		for (Map.Entry<Function, Set<Integer>> entry : result.entrySet()) {
			Set<Integer> retained = new HashSet<>(entry.getValue());
			retained.removeAll(semanticEvidenceByTarget.getOrDefault(entry.getKey(), Set.of()));
			if (!retained.isEmpty()) {
				immutable.put(entry.getKey(), Set.copyOf(retained));
			}
		}
		return Map.copyOf(immutable);
	}

	private boolean isConcreteInteger(DataType type) {
		if (Undefined.isUndefined(type)) {
			return false;
		}
		DataType current = type;
		while (current instanceof TypeDef typeDef) {
			current = typeDef.getBaseDataType();
		}
		return current instanceof AbstractIntegerDataType;
	}

	private Set<Integer> directCarryScalarPairs(Program program, Function function) {
		Set<Integer> result = new HashSet<>();
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			Instruction lowInstruction = instructions.next();
			String lowMnemonic = lowInstruction.getMnemonicString().toLowerCase();
			String highMnemonic;
			if (lowMnemonic.equals("add")) {
				highMnemonic = "addc";
			}
			else if (lowMnemonic.equals("sub")) {
				highMnemonic = "subc";
			}
			else {
				continue;
			}
			Instruction highInstruction =
				program.getListing().getInstructionAfter(lowInstruction.getAddress());
			if (highInstruction == null ||
				!function.getBody().contains(highInstruction.getAddress()) ||
				!highMnemonic.equalsIgnoreCase(highInstruction.getMnemonicString())) {
				continue;
			}
			int operands = Math.min(lowInstruction.getNumOperands(),
				highInstruction.getNumOperands());
			for (int operand = 0; operand < operands; operand++) {
				if (isMemoryOperand(lowInstruction, operand) ||
					isMemoryOperand(highInstruction, operand)) {
					continue;
				}
				Register lowRegister = operandRegister(lowInstruction, operand);
				Register highRegister = operandRegister(highInstruction, operand);
				if (lowRegister == null || highRegister == null) {
					continue;
				}
				Integer low = traceScalarParameterRegister(program, function, function.getBody(),
					lowInstruction, lowRegister, 0, new HashSet<>());
				Integer high = traceScalarParameterRegister(program, function, function.getBody(),
					lowInstruction, highRegister, 0, new HashSet<>());
				if (low != null && high != null && high == low + 1 &&
					isLegalPairStart(low)) {
					result.add(low);
				}
			}
		}
		return Set.copyOf(result);
	}

	private boolean hasGenericAnalysisFunctionPointerAt(Function function, int start) {
		for (Parameter parameter : function.getParameters()) {
			if (Integer.valueOf(start).equals(parameterStart(parameter.getVariableStorage())) &&
				parameter.getVariableStorage().size() == 4 &&
				isGenericAnalysisFunctionPointer(function, parameter.getFormalDataType())) {
				return true;
			}
		}
		return false;
	}

	private boolean hasPackedAnalysisCandidateAt(Function function, int start) {
		if (hasGenericAnalysisFunctionPointerAt(function, start)) {
			return true;
		}
		if (function.getSignatureSource() != SourceType.ANALYSIS) {
			return false;
		}
		for (Parameter parameter : function.getParameters()) {
			if (Integer.valueOf(start).equals(parameterStart(parameter.getVariableStorage())) &&
				parameter.getVariableStorage().size() == 4 &&
				Undefined.isUndefined(parameter.getFormalDataType())) {
				return true;
			}
		}
		return false;
	}

	private Integer genericFunctionPointerContaining(Function function, int slot) {
		for (Parameter parameter : function.getParameters()) {
			Integer start = parameterStart(parameter.getVariableStorage());
			if (start != null && start <= slot && slot < start + 2 &&
				parameter.getVariableStorage().size() == 4 &&
				isGenericAnalysisFunctionPointer(function, parameter.getFormalDataType())) {
				return start;
			}
		}
		return null;
	}

	private Map<Function, Set<Integer>> removePackedScalarPairs(
			Map<Function, Set<Integer>> independent,
			Map<Function, Set<Integer>> packed) {
		Map<Function, Set<Integer>> result = new HashMap<>();
		for (Map.Entry<Function, Set<Integer>> entry : independent.entrySet()) {
			Set<Integer> retained = new HashSet<>(entry.getValue());
			retained.removeAll(packed.getOrDefault(entry.getKey(), Set.of()));
			if (!retained.isEmpty()) {
				result.put(entry.getKey(), Set.copyOf(retained));
			}
		}
		return Map.copyOf(result);
	}

	private Map<Function, Set<Integer>> unionScalarPairs(
			Map<Function, Set<Integer>> first, Map<Function, Set<Integer>> second) {
		Map<Function, Set<Integer>> result = new HashMap<>();
		for (Map.Entry<Function, Set<Integer>> entry : first.entrySet()) {
			result.put(entry.getKey(), new HashSet<>(entry.getValue()));
		}
		for (Map.Entry<Function, Set<Integer>> entry : second.entrySet()) {
			result.computeIfAbsent(entry.getKey(), ignored -> new HashSet<>())
				.addAll(entry.getValue());
		}
		Map<Function, Set<Integer>> immutable = new HashMap<>();
		for (Map.Entry<Function, Set<Integer>> entry : result.entrySet()) {
			immutable.put(entry.getKey(), Set.copyOf(entry.getValue()));
		}
		return Map.copyOf(immutable);
	}

	/**
	 * Carry a proven scalar pair through a literal entry-point forwarding call.
	 * This prevents a stale pointer type on the forwarding target from feeding
	 * circular type evidence back into the wrapper on a later fixed-point pass.
	 */
	private Map<Function, Set<Integer>> propagateEntryForwardingScalarPairs(
			Program program, Map<Function, Set<Integer>> initial, TaskMonitor monitor)
			throws CancelledException {
		Map<Function, Set<Integer>> result = new HashMap<>();
		ArrayDeque<FunctionSlot> pending = new ArrayDeque<>();
		for (Map.Entry<Function, Set<Integer>> entry : initial.entrySet()) {
			Set<Integer> starts = new HashSet<>(entry.getValue());
			result.put(entry.getKey(), starts);
			for (int start : starts) {
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
			if (target == null || !mayUpdate(target) || !usesTaskingConvention(target)) {
				continue;
			}
			Set<Integer> targetStarts =
				result.computeIfAbsent(target, ignored -> new HashSet<>());
			if (targetStarts.add(source.start())) {
				pending.addLast(new FunctionSlot(target, source.start()));
			}
		}
		Map<Function, Set<Integer>> immutable = new HashMap<>();
		for (Map.Entry<Function, Set<Integer>> entry : result.entrySet()) {
			immutable.put(entry.getKey(), Set.copyOf(entry.getValue()));
		}
		return Map.copyOf(immutable);
	}

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

	private int repairScalarPointers(Program program,
			Map<Function, Set<Integer>> independentScalarPairs,
			Map<Function, Set<Integer>> packedScalarPairs,
			Map<Function, List<C166TaskingCallArguments.CallWords>> callWordsByTarget,
			MessageLog log) {
		int repaired = 0;
		Map<Function, Set<Integer>> conflicts = unionScalarPairs(independentScalarPairs,
			packedScalarPairs);
		for (Map.Entry<Function, Set<Integer>> conflict : conflicts.entrySet()) {
			Function function = conflict.getKey();
			// Updating a thunk mutates the thunk target in FunctionDB.  Scalar
			// evidence gathered for an alias must never rewrite the target signature.
			if (!mayUpdate(function) ||
				function.getSignatureSource() != SourceType.ANALYSIS) {
				continue;
			}
			try {
				List<Variable> parameters = new ArrayList<>();
				int split = 0;
				Set<Integer> packed =
					packedScalarPairs.getOrDefault(function, Set.of());
				boolean dropSpillPlaceholder = shouldDropSpillPlaceholder(program, function,
					packed, callWordsByTarget.getOrDefault(function, List.of()));
				for (Parameter parameter : function.getParameters()) {
					Integer start = parameterStart(parameter.getVariableStorage());
					if (dropSpillPlaceholder && Integer.valueOf(3).equals(start) &&
						parameter.getVariableStorage().size() == 2 &&
						Undefined.isUndefined(parameter.getFormalDataType())) {
						continue;
					}
					if (start != null && conflict.getValue().contains(start) &&
						parameter.getVariableStorage().size() == 4 &&
						isGenericAnalysisPointerForScalarRepair(function,
							parameter.getFormalDataType())) {
						if (packed.contains(start)) {
							parameters.add(new ParameterImpl(existingName(parameter),
								Undefined.getUndefinedDataType(4), program));
						}
						else {
							parameters.add(new ParameterImpl(null,
								Undefined.getUndefinedDataType(2), program));
							parameters.add(new ParameterImpl(null,
								Undefined.getUndefinedDataType(2), program));
						}
						split++;
					}
					else {
						parameters.add(new ParameterImpl(existingName(parameter),
							parameter.getFormalDataType(), program));
					}
				}
				if (split == 0) {
					continue;
				}
				function.updateFunction(CALLING_CONVENTION, null, parameters,
					FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
				repaired += split;
			}
			catch (DuplicateNameException | InvalidInputException e) {
				log.appendException(e);
			}
		}
		return repaired;
	}

	private boolean shouldDropSpillPlaceholder(Program program, Function function,
			Set<Integer> packedScalarPairs,
			List<C166TaskingCallArguments.CallWords> calls) {
		if (!packedScalarPairs.contains(4) || function.getSignatureSource() !=
			SourceType.ANALYSIS) {
			return false;
		}
		return hasSpillHoleEvidence(program, function, calls);
	}

	private boolean hasSpillHoleEvidence(Program program, Function function,
			List<C166TaskingCallArguments.CallWords> calls) {
		Parameter r15Parameter = null;
		for (Parameter parameter : function.getParameters()) {
			if (Integer.valueOf(3).equals(parameterStart(parameter.getVariableStorage())) &&
				parameter.getVariableStorage().size() == 2 &&
				Undefined.isUndefined(parameter.getFormalDataType())) {
				r15Parameter = parameter;
				break;
			}
		}
		if (incomingRegisterIsUsed(program, function, program.getRegister("r15"), 3)) {
			return false;
		}
		if (r15Parameter == null) {
			for (Parameter parameter : function.getParameters()) {
				if (Integer.valueOf(4).equals(
					parameterStart(parameter.getVariableStorage())) &&
					parameter.getVariableStorage().size() == 4 &&
					Undefined.isUndefined(parameter.getFormalDataType())) {
					return true;
				}
			}
			return false;
		}
		int duplicated = 0;
		for (C166TaskingCallArguments.CallWords call : calls) {
			C166TaskingCallArguments.WordValue register = call.words().get(3);
			C166TaskingCallArguments.WordValue low = call.words().get(4);
			C166TaskingCallArguments.WordValue high = call.words().get(5);
			if (register == null || register.constant() == null) {
				continue;
			}
			if ((low != null && register.constant().equals(low.constant())) ||
				(high != null && register.constant().equals(high.constant()))) {
				duplicated++;
			}
		}
		return duplicated >= 2;
	}

	private boolean incomingRegisterIsUsed(Program program, Function function,
			Register register, int slot) {
		if (register == null) {
			return true;
		}
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			boolean reads = false;
			for (Object input : instruction.getInputObjects()) {
				if (input instanceof Register inputRegister && overlaps(register, inputRegister)) {
					reads = true;
					break;
				}
			}
			if (!reads && instruction.getFlowType().isCall()) {
				Function target = directTarget(program, instruction);
				if (target != null) {
					for (Parameter parameter : target.getParameters()) {
						if (Integer.valueOf(slot).equals(
							parameterStart(parameter.getVariableStorage()))) {
							reads = true;
							break;
						}
					}
				}
			}
			if (reads) {
				Integer source = traceParameterRegister(program, function, function.getBody(),
					instruction, register, 0, new HashSet<>());
				if (Integer.valueOf(slot).equals(source)) {
					return true;
				}
			}
		}
		return false;
	}

	private boolean isGenericAnalysisPointerForScalarRepair(Function function,
			DataType type) {
		return isGenericAnalysisPointer(function, type) ||
			isGenericAnalysisFunctionPointer(function, type);
	}

	private boolean isGenericAnalysisFunctionPointer(Function function, DataType type) {
		return function.getSignatureSource() == SourceType.ANALYSIS &&
			isFunctionPointer(type) &&
			(isCanonicalGenericFunctionPointer(type) ||
				isLegacyGenericFunctionPointer(type));
	}

	private Map<Integer, CodePointerEvidence> codePointerEvidence(Program program,
			C166TaskingCallArguments.CallWords callWords) {
		Map<Integer, CodePointerEvidence> evidence = new HashMap<>();
		for (Map.Entry<Integer, C166TaskingCallArguments.WordValue> entry :
				callWords.words().entrySet()) {
			int start = entry.getKey();
			if (!isLegalPairStart(start) ||
				(start >= 4 && !callWords.registerBankOccupied())) {
				continue;
			}
			C166TaskingCallArguments.WordValue low = entry.getValue();
			C166TaskingCallArguments.WordValue high = callWords.words().get(start + 1);
			if (low == null || high == null || low.constant() == null ||
				high.constant() == null || high.constant() > 0xff) {
				continue;
			}
			long encoded = (high.constant() << 16) | low.constant();
			Address address = address(program, encoded);
			if (address == null) {
				continue;
			}
			MemoryBlock block = program.getMemory().getBlock(address);
			Function function = program.getFunctionManager().getFunctionAt(address);
			if (block != null && block.isExecute() && function != null) {
				Address source = later(low.source(), high.source());
				if (source != null) {
					evidence.put(start, new CodePointerEvidence(address, source));
				}
			}
		}
		return Map.copyOf(evidence);
	}

	private Address later(Address first, Address second) {
		if (first == null) {
			return second;
		}
		if (second == null) {
			return first;
		}
		return first.compareTo(second) >= 0 ? first : second;
	}

	private int addCodePointerReference(Program program, CodePointerEvidence evidence) {
		ReferenceManager references = program.getReferenceManager();
		Reference existing = references.getReference(evidence.source(), evidence.target(),
			Reference.MNEMONIC);
		if (existing == null) {
			references.addMemoryReference(evidence.source(), evidence.target(), RefType.PARAM,
				SourceType.ANALYSIS, Reference.MNEMONIC);
			return 1;
		}
		if (!existing.getReferenceType().isFlow() &&
			existing.getReferenceType() != RefType.PARAM) {
			references.updateRefType(existing, RefType.PARAM);
			return 1;
		}
		return 0;
	}

	private int removeCodePointerReference(Program program, CodePointerEvidence evidence) {
		Reference reference = program.getReferenceManager().getReference(evidence.source(),
			evidence.target(), Reference.MNEMONIC);
		if (reference == null || reference.getSource() != SourceType.ANALYSIS ||
			reference.getReferenceType() != RefType.PARAM) {
			return 0;
		}
		program.getReferenceManager().delete(reference);
		return 1;
	}

	private Set<Integer> difference(Set<Integer> all, Set<Integer> retained) {
		Set<Integer> result = new HashSet<>(all);
		result.removeAll(retained);
		return result;
	}

	private Address address(Program program, long offset) {
		try {
			return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset, true);
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

	private Set<Integer> removePointerConflicts(Program program, Function function,
			Set<Integer> starts,
			Map<Integer, List<CodePointerEvidence>> occurrences,
			Set<Integer> semanticEvidence) {
		Set<Integer> result = new HashSet<>(starts);
		for (Parameter parameter : function.getParameters()) {
			Integer start = parameterStart(parameter.getVariableStorage());
			DataType type = parameter.getFormalDataType();
			if (start == null || pointerDataType(type) == null || isFunctionPointer(type)) {
				continue;
			}
			int span = Math.max(1, parameter.getVariableStorage().size() / 2);
			result.removeIf(candidate -> candidate < start + span && start < candidate + 2 &&
				((hasDirectPagedDataUse(program, function, candidate) &&
					!semanticEvidence.contains(candidate)) ||
					(!hasPriorCodePointerReference(program,
						occurrences.getOrDefault(candidate, List.of())) &&
						!(semanticEvidence.contains(candidate) &&
							isGenericAnalysisPointer(function, type)) &&
						!isRepeatedGenericAnalysisPointer(function, type,
							occurrences.getOrDefault(candidate, List.of())))));
		}
		return Set.copyOf(result);
	}

	/**
	 * A real EXTP/DPP0 dereference sourced from both incoming words is stronger
	 * than an old PARAM reference or a coincidental exact function-address
	 * constant.  An actual far-indirect call fed by the same parameter remains
	 * stronger still: it proves code semantics even when a stale HighSymbol also
	 * manufactures an apparent paged access from those words.
	 */
	private boolean hasDirectPagedDataUse(Program program, Function function, int start) {
		if (start < 0 || start >= 4) {
			return false;
		}
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			Instruction setup = instructions.next();
			Register page = dynamicPageSource(setup);
			if (page == null) {
				continue;
			}
			Integer pageSlot = traceParameterRegister(program, function, function.getBody(),
				setup, page, 0, new HashSet<>());
			if (pageSlot == null || pageSlot != start + 1) {
				continue;
			}
			int remaining = extensionRange(setup);
			Instruction access = program.getListing().getInstructionAfter(setup.getAddress());
			while (access != null && remaining-- > 0 &&
				function.getBody().contains(access.getAddress())) {
				for (int operand = 0; operand < access.getNumOperands(); operand++) {
					if (!isMemoryOperand(access, operand)) {
						continue;
					}
					Register base = operandRegister(access, operand);
					Integer offsetSlot = base == null ? null : traceParameterRegister(program,
						function, function.getBody(), access, base, 0, new HashSet<>());
					if (offsetSlot != null && offsetSlot == start) {
						return true;
					}
				}
				access = program.getListing().getInstructionAfter(access.getAddress());
			}
		}
		return false;
	}

	private Register dynamicPageSource(Instruction instruction) {
		String mnemonic = instruction.getMnemonicString().toLowerCase();
		if ((mnemonic.equals("extp") || mnemonic.equals("extpr")) &&
			instruction.getNumOperands() != 0) {
			Register source = operandRegister(instruction, 0);
			if (source != null) {
				return source;
			}
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
				return operandRegister(instruction, 1);
			}
		}
		return null;
	}

	private int extensionRange(Instruction setup) {
		Scalar range = setup.getNumOperands() > 1 ? setup.getScalar(1) : null;
		if (range == null) {
			return 1;
		}
		return Math.max(1, Math.min(4, (int) range.getUnsignedValue()));
	}

	private Set<Integer> removeScalarConflicts(Function function, Set<Integer> starts,
			Map<Function, Set<Integer>> scalarPairs) {
		Set<Integer> conflicts = scalarPairs.get(function);
		if (conflicts == null || conflicts.isEmpty()) {
			return starts;
		}
		Set<Integer> result = new HashSet<>();
		for (int start : starts) {
			// A pair enters scalarPairs only when no direct far-indirect use exists.
			// Do not let later propagation from a stale callee type undo that proof.
			if (!conflicts.contains(start)) {
				result.add(start);
			}
		}
		return Set.copyOf(result);
	}

	private boolean isRepeatedGenericAnalysisPointer(Function function, DataType type,
			List<CodePointerEvidence> occurrences) {
		if (occurrences.size() < 2 || !isGenericAnalysisPointer(function, type)) {
			return false;
		}
		return true;
	}

	private boolean isGenericAnalysisPointer(Function function, DataType type) {
		if (function.getSignatureSource() != SourceType.ANALYSIS) {
			return false;
		}
		Pointer pointer = pointerDataType(type);
		if (pointer == null) {
			return false;
		}
		DataType target = pointer.getDataType();
		while (target instanceof TypeDef typeDef) {
			target = typeDef.getBaseDataType();
		}
		return target instanceof VoidDataType || "void".equals(target.getName());
	}

	private boolean hasFunctionPointerAt(Function function, int start) {
		for (Parameter parameter : function.getParameters()) {
			Integer actualStart = parameterStart(parameter.getVariableStorage());
			if (actualStart != null && actualStart == start &&
				isFunctionPointer(parameter.getFormalDataType())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * A previous analyzer version could let far-data inference replace an
	 * inferred callback with void *.  The PARAM reference created by this
	 * analyzer survives that signature rewrite and is a precise provenance
	 * marker, allowing the callback type to be repaired without overriding an
	 * unrelated pre-existing data pointer.
	 */
	private boolean hasPriorCodePointerReference(Program program,
			List<CodePointerEvidence> occurrences) {
		for (CodePointerEvidence evidence : occurrences) {
			Reference reference = program.getReferenceManager().getReference(
				evidence.source(), evidence.target(), Reference.MNEMONIC);
			if (reference != null && reference.getSource() == SourceType.ANALYSIS &&
				reference.getReferenceType() == RefType.PARAM) {
				return true;
			}
		}
		return false;
	}

	private int removeConflictingPagedReference(Program program,
			CodePointerEvidence evidence) {
		long encoded = evidence.target().getUnsignedOffset();
		long page = (encoded >>> 16) & 0xffff;
		long offset = encoded & 0xffff;
		Address paged = address(program, ((page & 0x3ff) << 14) | (offset & 0x3fff));
		if (paged == null || paged.equals(evidence.target())) {
			return 0;
		}
		Reference reference = program.getReferenceManager().getReference(
			evidence.source(), paged, Reference.MNEMONIC);
		if (reference == null || reference.getSource() != SourceType.ANALYSIS ||
			reference.getReferenceType().isFlow()) {
			return 0;
		}
		program.getReferenceManager().delete(reference);
		return 1;
	}

	private boolean signatureMatches(Function function, Set<Integer> starts) {
		for (int start : starts) {
			boolean found = false;
			for (Parameter parameter : function.getParameters()) {
				Integer actualStart = parameterStart(parameter.getVariableStorage());
				if (actualStart != null && actualStart == start &&
					parameter.getVariableStorage().size() == 4 &&
					isFunctionPointer(parameter.getFormalDataType()) &&
					!isLegacyGenericFunctionPointer(parameter.getFormalDataType())) {
					found = true;
					break;
				}
			}
			if (!found) {
				return false;
			}
		}
		return true;
	}

	private void updateSignature(Program program, Function function, Set<Integer> starts)
			throws DuplicateNameException, InvalidInputException {
		DataType genericFunctionPointer = genericFunctionPointer(program);
		Map<Integer, Parameter> existingByStart = new HashMap<>();
		int lastRegisterSlot = -1;
		int lastStackWord = -1;
		for (Parameter parameter : function.getParameters()) {
			Integer start = parameterStart(parameter.getVariableStorage());
			if (start == null) {
				continue;
			}
			existingByStart.put(start, parameter);
			int span = Math.max(1, parameter.getVariableStorage().size() / 2);
			if (start < 4) {
				lastRegisterSlot = Math.max(lastRegisterSlot, start + span - 1);
			}
			else {
				lastRegisterSlot = Math.max(lastRegisterSlot, 3);
				lastStackWord = Math.max(lastStackWord, start - 4 + span - 1);
			}
		}
		for (int start : starts) {
			if (start < 4) {
				lastRegisterSlot = Math.max(lastRegisterSlot, start + 1);
			}
			else {
				lastRegisterSlot = Math.max(lastRegisterSlot, 3);
				lastStackWord = Math.max(lastStackWord, start - 4 + 1);
			}
		}

		List<Variable> parameters = new ArrayList<>();
		for (int slot = 0; slot <= lastRegisterSlot;) {
			Parameter existing = existingByStart.get(slot);
			if (starts.contains(slot)) {
				parameters.add(new ParameterImpl(existingName(existing),
					codePointerType(existing, genericFunctionPointer), program));
				slot += 2;
				continue;
			}
			if (existing != null) {
				int span = Math.max(1, existing.getVariableStorage().size() / 2);
				if (!overlapsPair(slot, span, starts)) {
					parameters.add(new ParameterImpl(existingName(existing),
						existing.getFormalDataType(), program));
					slot += span;
					continue;
				}
			}
			parameters.add(new ParameterImpl(null, Undefined.getUndefinedDataType(2), program));
			slot++;
		}
		for (int word = 0; word <= lastStackWord;) {
			int start = 4 + word;
			Parameter existing = existingByStart.get(start);
			if (starts.contains(start)) {
				parameters.add(new ParameterImpl(existingName(existing),
					codePointerType(existing, genericFunctionPointer), program));
				word += 2;
				continue;
			}
			if (existing != null) {
				int span = Math.max(1, existing.getVariableStorage().size() / 2);
				if (!overlapsPair(start, span, starts)) {
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

	private DataType genericFunctionPointer(Program program) {
		DataType existing = program.getDataTypeManager()
			.getDataType("/" + GENERIC_FUNCTION_POINTER_NAME);
		if (isCanonicalGenericFunctionPointer(existing)) {
			return existing;
		}

		DataType functionType = program.getDataTypeManager().getDataType(GENERIC_FUNCTION_PATH);
		if (!(functionType instanceof FunctionDefinition)) {
			FunctionDefinitionDataType definition = new FunctionDefinitionDataType(
				new CategoryPath("/c166"), GENERIC_FUNCTION_NAME,
				program.getDataTypeManager());
			definition.setVarArgs(true);
			functionType = program.getDataTypeManager().resolve(definition,
				DataTypeConflictHandler.DEFAULT_HANDLER);
		}
		DataType pointer = new PointerDataType(functionType, program.getDataTypeManager());
		TypedefDataType typedef = new TypedefDataType(CategoryPath.ROOT,
			GENERIC_FUNCTION_POINTER_NAME, pointer, program.getDataTypeManager());
		return program.getDataTypeManager().resolve(typedef,
			DataTypeConflictHandler.DEFAULT_HANDLER);
	}

	private DataType codePointerType(Parameter existing, DataType fallback) {
		if (existing != null && isFunctionPointer(existing.getFormalDataType()) &&
			!isLegacyGenericFunctionPointer(existing.getFormalDataType())) {
			return existing.getFormalDataType();
		}
		return fallback;
	}

	private boolean isCanonicalGenericFunctionPointer(DataType type) {
		return type instanceof TypeDef typeDef &&
			GENERIC_FUNCTION_POINTER_NAME.equals(typeDef.getName()) &&
			CategoryPath.ROOT.equals(typeDef.getCategoryPath()) &&
			GENERIC_FUNCTION_PATH.equals(functionPointerTargetPath(type));
	}

	private boolean isLegacyGenericFunctionPointer(DataType type) {
		if (isCanonicalGenericFunctionPointer(type)) {
			return false;
		}
		String targetPath = functionPointerTargetPath(type);
		return LEGACY_GENERIC_FUNCTION_PATH.equals(targetPath) ||
			GENERIC_FUNCTION_PATH.equals(targetPath);
	}

	private String functionPointerTargetPath(DataType type) {
		Pointer pointer = pointerDataType(type);
		if (pointer == null) {
			return null;
		}
		DataType target = pointer.getDataType();
		while (target instanceof TypeDef typeDef) {
			target = typeDef.getBaseDataType();
		}
		return target instanceof FunctionDefinition ? target.getPathName() : null;
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

	private Pointer pointerDataType(DataType type) {
		DataType current = type;
		while (current instanceof TypeDef typeDef) {
			current = typeDef.getBaseDataType();
		}
		return current instanceof Pointer pointer ? pointer : null;
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

	private boolean overlapsPair(int start, int span, Set<Integer> pairs) {
		for (int pair : pairs) {
			if (start < pair + 2 && pair < start + span) {
				return true;
			}
		}
		return false;
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

	private Integer argumentSlot(Register register) {
		if (register == null || register.getMinimumByteSize() != 2) {
			return null;
		}
		String name = register.getName().toLowerCase();
		if (!name.matches("r1[2-5]")) {
			return null;
		}
		int number = Integer.parseInt(name.substring(1));
		return number - FIRST_ARGUMENT_REGISTER;
	}

	private boolean writesRegister(Instruction instruction, Register expected) {
		for (Object result : instruction.getResultObjects()) {
			if (result instanceof Register actual && overlaps(expected, actual)) {
				return true;
			}
		}
		return false;
	}

	private boolean overlaps(Register expected, Register actual) {
		return expected != null && actual != null &&
			(expected.contains(actual) || actual.contains(expected));
	}

	private Register operandRegister(Instruction instruction, int operand) {
		for (Object object : instruction.getOpObjects(operand)) {
			if (object instanceof Register register) {
				return register;
			}
		}
		return null;
	}

	private Scalar operandScalar(Instruction instruction, int operand) {
		for (Object object : instruction.getOpObjects(operand)) {
			if (object instanceof Scalar scalar) {
				return scalar;
			}
		}
		return null;
	}

	private boolean mayUpdate(Function function) {
		SourceType source = function.getSignatureSource();
		return !function.isExternal() && !function.isThunk() &&
			(source == SourceType.DEFAULT || source == SourceType.ANALYSIS);
	}

	private boolean usesTaskingConvention(Function function) {
		String name = function.getCallingConventionName();
		return CALLING_CONVENTION.equals(name) ||
			Function.DEFAULT_CALLING_CONVENTION_STRING.equals(name) ||
			Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(name);
	}

	private String existingName(Parameter parameter) {
		if (parameter == null || parameter.getSource() == SourceType.DEFAULT) {
			return null;
		}
		return parameter.getName();
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

	private record Selection(int score, Set<Integer> starts, boolean ambiguous) {
	}

	private record ConstantWordPair(long low, long high) {
	}

	private record DirectCallSite(Function caller, Function target, Instruction call) {
	}

	private record FunctionSlot(Function function, int start) {
	}

	private record UpdateStats(int inferredParameters, int referenceCount,
			int referencesRemoved) {
	}

	private record CodePointerEvidence(Address target, Address source) {
	}
}
