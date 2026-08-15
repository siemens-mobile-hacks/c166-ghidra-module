package ghidrainfineon;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
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
						Integer start = dispatcherTargetPair(program, caller, instruction, blocks,
							monitor);
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
		UpdateStats update = applyEvidence(program, scoresByTarget, evidenceByTarget,
			semanticEvidenceByTarget, updatedFunctions, ambiguousFunctions, monitor, log);
		inferredParameters += update.inferredParameters();
		referenceCount += update.referenceCount();
		referencesRemoved += update.referencesRemoved();

		int forwardingEvidenceCount = 0;
		int forwardingPasses = 0;
		while (true) {
			monitor.checkCancelled();
			int added = collectForwardingEvidence(program, directCalls, blocks,
				scoresByTarget, semanticEvidenceByTarget, monitor);
			if (added == 0) {
				break;
			}
			forwardingEvidenceCount += added;
			forwardingPasses++;
			update = applyEvidence(program, scoresByTarget, evidenceByTarget,
				semanticEvidenceByTarget, updatedFunctions, ambiguousFunctions, monitor, log);
			inferredParameters += update.inferredParameters();
			referenceCount += update.referenceCount();
			referencesRemoved += update.referencesRemoved();
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
			" data-conflicting reference(s), " + ambiguousFunctions.size() + " ambiguous.");
		return true;
	}

	private UpdateStats applyEvidence(Program program,
			Map<Function, Map<Integer, Integer>> scoresByTarget,
			Map<Function, Map<Integer, List<CodePointerEvidence>>> evidenceByTarget,
			Map<Function, Set<Integer>> semanticEvidenceByTarget,
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
		if ("call_far_indirect".equals(function.getCallFixup()) ||
			"__call_far_indirect".equals(function.getName())) {
			return true;
		}
		Instruction previousPrevious = null;
		Instruction previous = null;
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			Instruction current = instructions.next();
			if (current.getMnemonicString().equalsIgnoreCase("rets") &&
				isRegisterPush(previousPrevious, "r5") &&
				isRegisterPush(previous, "r4")) {
				return true;
			}
			previousPrevious = previous;
			previous = current;
		}
		return false;
	}

	private boolean isRegisterPush(Instruction instruction, String registerName) {
		if (instruction == null) {
			return false;
		}
		Register source = null;
		if (instruction.getMnemonicString().equalsIgnoreCase("push")) {
			source = operandRegister(instruction, 0);
		}
		else if (isStackPush(instruction)) {
			source = operandRegister(instruction, 1);
		}
		return source != null && source.getName().equalsIgnoreCase(registerName);
	}

	private Integer dispatcherTargetPair(Program program, Function function, Instruction call,
			BasicBlockModel blocks, TaskMonitor monitor) throws CancelledException {
		CodeBlock setupBlock = blocks.getFirstCodeBlockContaining(call.getAddress(), monitor);
		AddressSetView setupRegion = setupBlock == null ? function.getBody() : setupBlock;
		Integer low = traceParameterRegister(program, function, setupRegion, call,
			program.getRegister("r4"), 0, new HashSet<>());
		Integer high = traceParameterRegister(program, function, setupRegion, call,
			program.getRegister("r5"), 0, new HashSet<>());
		if (low == null || high == null || high != low + 1 || !isLegalPairStart(low)) {
			return null;
		}
		return low;
	}

	private Integer traceParameterRegister(Program program, Function function,
			AddressSetView setupRegion, Instruction before, Register register, int depth,
			Set<String> visited) {
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
			if (instruction.getFlowType().isCall() || instruction.getFlowType().isJump()) {
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
					stackOffset, depth + 1, visited);
			}
			Register source = operandRegister(instruction, 1);
			if (source != null && !isMemoryOperand(instruction, 1)) {
				return traceParameterRegister(program, function, setupRegion, instruction, source,
					depth + 1, visited);
			}
			return null;
		}
		return setupRegion.contains(function.getEntryPoint()) ? argumentSlot(register) : null;
	}

	private Integer traceStackParameter(Program program, Function function,
			AddressSetView setupRegion, Instruction before, int initialOffset, int depth,
			Set<String> visited) {
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
				return null;
			}
			Integer storeOffset = stackOffset(instruction, 0);
			if (storeOffset != null && storeOffset == offset) {
				Register source = operandRegister(instruction, 1);
				return source == null ? null : traceParameterRegister(program, function,
					setupRegion, instruction, source, depth + 1, visited);
			}
			if (isStackPush(instruction)) {
				if (offset == 0) {
					Register source = operandRegister(instruction, 1);
					return source == null ? null : traceParameterRegister(program, function,
						setupRegion, instruction, source, depth + 1, visited);
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
		return null;
	}

	private int collectForwardingEvidence(Program program, List<DirectCallSite> directCalls,
			BasicBlockModel blocks, Map<Function, Map<Integer, Integer>> scoresByTarget,
			Map<Function, Set<Integer>> semanticEvidenceByTarget, TaskMonitor monitor)
			throws CancelledException {
		int added = 0;
		for (DirectCallSite site : directCalls) {
			monitor.checkCancelled();
			if (!mayUpdate(site.caller()) || !usesTaskingConvention(site.caller())) {
				continue;
			}
			for (int start : forwardedCodePointerPairs(program, site, blocks, monitor)) {
				if (addSemanticEvidence(scoresByTarget, semanticEvidenceByTarget,
					site.caller(), start)) {
					added++;
				}
			}
		}
		return added;
	}

	private Set<Integer> forwardedCodePointerPairs(Program program, DirectCallSite site,
			BasicBlockModel blocks, TaskMonitor monitor) throws CancelledException {
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
			Integer low = traceCallArgumentWord(program, site.caller(), setupRegion,
				site.call(), targetStart);
			Integer high = traceCallArgumentWord(program, site.caller(), setupRegion,
				site.call(), targetStart + 1);
			if (low != null && high != null && high == low + 1 && isLegalPairStart(low)) {
				result.add(low);
			}
		}
		return Set.copyOf(result);
	}

	private Integer traceCallArgumentWord(Program program, Function caller,
			AddressSetView setupRegion, Instruction call, int targetSlot) {
		if (targetSlot < 4) {
			Register register = program.getRegister("r" + (FIRST_ARGUMENT_REGISTER + targetSlot));
			return traceParameterRegister(program, caller, setupRegion, call, register, 0,
				new HashSet<>());
		}
		int stackOffset = (targetSlot - 4) * 2;
		return traceStackParameter(program, caller, setupRegion, call, stackOffset, 0,
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
				!hasPriorCodePointerReference(program,
					occurrences.getOrDefault(candidate, List.of())) &&
				!(semanticEvidence.contains(candidate) &&
					isGenericAnalysisPointer(function, type)) &&
				!isRepeatedGenericAnalysisPointer(function, type,
					occurrences.getOrDefault(candidate, List.of())));
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

	private record DirectCallSite(Function caller, Function target, Instruction call) {
	}

	private record UpdateStats(int inferredParameters, int referenceCount,
			int referencesRemoved) {
	}

	private record CodePointerEvidence(Address target, Address source) {
	}
}
