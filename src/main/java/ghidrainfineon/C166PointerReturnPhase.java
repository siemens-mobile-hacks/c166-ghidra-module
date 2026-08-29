package ghidrainfineon;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Classifies TASKING Classic Large values returned in the documented R5:R4
 * pair as far data pointers, far function pointers, or four-byte scalars.
 * <p>
 * Merely observing both registers after a call is not type evidence: the same
 * pair also carries {@code long} and {@code float}.  This analyzer follows the
 * two words through straight-line register copies and classifies their typed
 * consumers.  Conflicting code, data, and scalar categories suppress the
 * update.  A single consumer is accepted only when every terminal block in the
 * callee explicitly defines both return words.
 */
public class C166PointerReturnPhase extends C166TaskingTypeInferencePhase {

	private static final String CALLING_CONVENTION = "__tasking_c166_classic";
	private RunStatistics lastRunStatistics = RunStatistics.empty();

	public C166PointerReturnPhase() {
		super("C166 TASKING Return Classification");
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C166ArchitectureProfile.isTaskingClassicLarge(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		lastRunStatistics = RunStatistics.empty();
		boolean fullScan = set == null || set.isEmpty() || set.contains(program.getMemory());
		Iterator<Function> iterator = fullScan
			? program.getFunctionManager().getFunctions(true)
			: program.getFunctionManager().getFunctionsOverlapping(set);
		List<Function> callers = new ArrayList<>();
		while (iterator.hasNext()) {
			Function caller = iterator.next();
			if (C166AnalysisFunctions.hasUsableBody(caller)) {
				callers.add(caller);
			}
		}
		final int maximumRounds = 4;
		monitor.initialize(Math.max(1, callers.size() * (maximumRounds + 1)),
			"C166 return classification: tracing R5:R4");
		Map<Function, ReturnEvidence> staticEvidence = new HashMap<>();
		Map<Function, List<ForwardedPairOrigin>> forwardedSources = new HashMap<>();
		for (Function caller : callers) {
			monitor.checkCancelled();
			Map<Address, TraceState> callerStates =
				traceCallerStates(program, caller, monitor);
			recordCallerEvidence(program, caller, callerStates, staticEvidence, monitor);
			List<ForwardedPairOrigin> sources =
				forwardedReturnSources(program, caller, monitor);
			if (!sources.isEmpty()) {
				forwardedSources.put(caller, sources);
			}
			monitor.incrementProgress(1);
		}
		int inferred = 0;
		int rounds = 0;
		Set<Function> conflicts = new HashSet<>();
		Set<Function> provenThisRun = new HashSet<>();
		DataType dataPointer = new PointerDataType(VoidDataType.dataType,
			program.getDataTypeManager());
		DataType codePointer = genericFunctionPointer(program);
		for (int round = 0; round < maximumRounds; round++) {
			// Consumer parameter types are stable throughout this phase.  Clone the
			// listing-derived evidence instead of walking all caller instructions in
			// every fixed-point round; only forwarded return categories are dynamic.
			Map<Function, ReturnEvidence> evidence = copyEvidence(staticEvidence);
			for (Map.Entry<Function, List<ForwardedPairOrigin>> entry :
					forwardedSources.entrySet()) {
				monitor.checkCancelled();
				Function caller = entry.getKey();
				ReturnCategory forwarded = forwardedReturnCategory(entry.getValue(),
					provenThisRun);
				if (forwarded != ReturnCategory.UNKNOWN) {
					ReturnEvidence item = evidence.computeIfAbsent(caller,
						ignored -> new ReturnEvidence());
					item.markForwardedUse(forwarded, caller.getEntryPoint());
				}
				monitor.incrementProgress(1);
			}
			int roundInferred = 0;
			for (Map.Entry<Function, ReturnEvidence> entry : evidence.entrySet()) {
				monitor.checkCancelled();
				Function function = entry.getKey();
				ReturnEvidence item = entry.getValue();
				int categories = (item.hasCodeUse() ? 1 : 0) +
					(item.hasDataUse() ? 1 : 0) + (item.hasScalarUse() ? 1 : 0);
				if (categories > 1) {
					if (mayUpdateReturn(function) && conflicts.add(function)) {
						report(program, function.getEntryPoint() +
							": conflicting R5:R4 return evidence (" +
							item.dataUses().size() + " typed data use(s), direct paged=" +
							item.directPagedUse() + ", " + item.codeUses().size() +
							" code use(s), " + item.scalarUses().size() +
							" scalar use(s))");
					}
					continue;
				}
				PairReturnState pairState = returnPairState(program, function, monitor);
				if (pairState == PairReturnState.PARTIAL) {
					continue;
				}
				boolean explicitPair = pairState == PairReturnState.EXPLICIT;
				boolean enoughData = item.directPagedUse() || item.dataUses().size() >= 2 ||
					explicitPair && !item.dataUses().isEmpty() ||
					item.hasStrongConcreteDataType() &&
						isGenericDataPointer(function.getReturnType());
				boolean enoughCode = item.codeUses().size() >= 2 ||
					explicitPair && !item.codeUses().isEmpty();
				boolean enoughScalar = item.scalarUses().size() >= 2 ||
					explicitPair && !item.scalarUses().isEmpty();
				if (!mayUpdateReturn(function) ||
					!enoughData && !enoughCode && !enoughScalar) {
					continue;
				}
				try {
					DataType inferredType = enoughCode ? codePointer :
						enoughData ? item.concreteDataType(dataPointer) : item.hasUnsignedLongUse()
							? new UnsignedLongDataType(program.getDataTypeManager())
							: Undefined.getUndefinedDataType(4);
					if (sameReturnCategory(function.getReturnType(), inferredType)) {
						provenThisRun.add(function);
						continue;
					}
					function.setCallingConvention(CALLING_CONVENTION);
					function.setReturnType(inferredType, SourceType.ANALYSIS);
					provenThisRun.add(function);
					roundInferred++;
				}
				catch (InvalidInputException e) {
					log.appendException(e);
				}
			}
			inferred += roundInferred;
			rounds++;
			if (roundInferred == 0) {
				break;
			}
		}
		report(program, (fullScan ? "Full" : "Incremental") + " scan: traced " +
			callers.size() + " caller function(s), inferred " + inferred +
			" R5:R4 return(s) in " + rounds + " fixed-point round(s), rejected " +
			conflicts.size() + " cross-category conflict(s).");
		lastRunStatistics = new RunStatistics(callers.size(), inferred, rounds,
			conflicts.size());
		return true;
	}

	public RunStatistics getLastRunStatistics() {
		return lastRunStatistics;
	}

	private Map<Function, ReturnEvidence> copyEvidence(
			Map<Function, ReturnEvidence> source) {
		Map<Function, ReturnEvidence> result = new HashMap<>();
		for (Map.Entry<Function, ReturnEvidence> entry : source.entrySet()) {
			result.put(entry.getKey(), entry.getValue().copy());
		}
		return result;
	}

	private boolean sameReturnCategory(DataType current, DataType inferred) {
		ReturnCategory currentCategory = returnCategory(current);
		ReturnCategory inferredCategory = returnCategory(inferred);
		if (currentCategory == ReturnCategory.UNKNOWN || currentCategory != inferredCategory) {
			return false;
		}
		if (currentCategory == ReturnCategory.DATA && !isGenericDataPointer(inferred)) {
			return current.isEquivalent(inferred);
		}
		// A proven unsigned-long consumer refines an analyzer-owned undefined4.
		return currentCategory != ReturnCategory.SCALAR ||
			!Undefined.isUndefined(current) || Undefined.isUndefined(inferred);
	}

	private ReturnCategory returnCategory(DataType type) {
		Pointer pointer = pointerDataType(type);
		if (pointer != null) {
			return isFunctionPointer(type) ? ReturnCategory.CODE : ReturnCategory.DATA;
		}
		return type != null && type.getLength() == 4 ? ReturnCategory.SCALAR :
			ReturnCategory.UNKNOWN;
	}

	private Map<Address, TraceState> traceCallerStates(Program program, Function caller,
			TaskMonitor monitor)
			throws CancelledException {
		Map<Address, TraceState> entryStates = new HashMap<>();
		ArrayDeque<Address> work = new ArrayDeque<>();
		entryStates.put(caller.getEntryPoint(), new TraceState());
		work.add(caller.getEntryPoint());
		while (!work.isEmpty()) {
			monitor.checkCancelled();
			Address address = work.removeFirst();
			Instruction instruction = program.getListing().getInstructionAt(address);
			if (instruction == null || !caller.getBody().contains(address)) {
				continue;
			}
			TraceState output = transferCallerInstruction(program, instruction,
				entryStates.get(address), null);
			for (Address successor : callerSuccessors(caller, instruction)) {
				TraceState previous = entryStates.get(successor);
				TraceState merged = previous == null ? output.copy() :
					previous.intersection(output);
				if (previous == null || !previous.equals(merged)) {
					entryStates.put(successor, merged);
					work.addLast(successor);
				}
			}
		}
		return entryStates;
	}

	private void recordCallerEvidence(Program program, Function caller,
			Map<Address, TraceState> entryStates,
			Map<Function, ReturnEvidence> evidence, TaskMonitor monitor)
			throws CancelledException {
		InstructionIterator instructions =
			program.getListing().getInstructions(caller.getBody(), true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = instructions.next();
			TraceState state = entryStates.get(instruction.getAddress());
			if (state != null) {
				transferCallerInstruction(program, instruction, state, evidence);
			}
		}
	}

	private TraceState transferCallerInstruction(Program program, Instruction instruction,
			TraceState input, Map<Function, ReturnEvidence> evidence) {
		TraceState output = input.copy();
		if (instruction.getFlowType().isCall()) {
			Function target = directTarget(program, instruction);
			if (evidence != null && target != null) {
				recordCallUses(program, target, instruction, output.registers(), evidence);
			}
			killCallClobbers(output.registers());
			output.setActivePage(null);
			if (target != null && mayTrackReturn(target)) {
				output.registers().put(4, new OriginWord(target, 0));
				output.registers().put(5, new OriginWord(target, 1));
			}
			return output;
		}

		Register pageRegister = dynamicPageSource(instruction);
		if (pageRegister != null) {
			Integer pageNumber = generalRegisterNumber(program, pageRegister);
			output.setActivePage(pageNumber == null ? null :
				output.registers().get(pageNumber));
		}
		OriginWord activePage = output.activePage();
		if (evidence != null && activePage != null && activePage.word() == 1) {
			for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
				if (!isMemoryOperand(instruction, operand)) {
					continue;
				}
				Integer base = generalRegisterNumber(program,
					operandRegister(instruction, operand));
				OriginWord low = base == null ? null : output.registers().get(base);
				if (samePair(low, activePage)) {
					evidence.computeIfAbsent(low.function(), ignored -> new ReturnEvidence())
						.markDirectPagedUse();
				}
			}
		}

		applyRegisterWrites(program, instruction, output.registers());
		if (instruction.getFlowType().isJump() || instruction.getFlowType().isTerminal()) {
			output.setActivePage(null);
		}
		return output;
	}

	private Set<Address> callerSuccessors(Function caller, Instruction instruction) {
		Set<Address> successors = new HashSet<>();
		Address fallThrough = instruction.getFallThrough();
		if (fallThrough != null && caller.getBody().contains(fallThrough)) {
			successors.add(fallThrough);
		}
		if (!instruction.getFlowType().isCall()) {
			for (Address flow : instruction.getFlows()) {
				if (caller.getBody().contains(flow)) {
					successors.add(flow);
				}
			}
		}
		return successors;
	}

	private void recordCallUses(Program program, Function target, Instruction instruction,
			Map<Integer, OriginWord> registers, Map<Function, ReturnEvidence> evidence) {
		if (isUnsignedLongRuntimeHelper(target)) {
			recordUnsignedLongPairUse(instruction, registers.get(4), registers.get(5),
				evidence);
			recordUnsignedLongPairUse(instruction, registers.get(10), registers.get(11),
				evidence);
		}
		if (C166TaskingRuntimeAnalyzer.isFarIndirectDispatcher(program, target)) {
			OriginWord low = registers.get(4);
			OriginWord high = registers.get(5);
			if (samePair(low, high)) {
				evidence.computeIfAbsent(low.function(), ignored -> new ReturnEvidence())
					.markCodeUse(instruction.getAddress());
			}
			return;
		}
		for (Parameter parameter : target.getParameters()) {
			DataType type = parameter.getFormalDataType();
			Pointer pointer = pointerDataType(type);
			if (type.getLength() != 4) {
				continue;
			}
			int[] pair = registerPair(program, parameter.getVariableStorage());
			if (pair == null) {
				continue;
			}
			OriginWord low = registers.get(pair[0]);
			OriginWord high = registers.get(pair[1]);
			if (!samePair(low, high)) {
				continue;
			}
			ReturnEvidence item =
				evidence.computeIfAbsent(low.function(), ignored -> new ReturnEvidence());
			if (pointer == null) {
				item.markScalarUse(instruction.getAddress());
			}
			else if (isFunctionPointer(type)) {
				// An analyzer-owned generic fpointer may itself be stale circular
				// evidence.  Only a concrete callback declaration is authoritative
				// here; generic code returns are proven separately by a direct R5:R4
				// far-indirect use above.
				if (target.getSignatureSource() != SourceType.ANALYSIS ||
					!isGenericFunctionPointer(type)) {
					item.markCodeUse(instruction.getAddress());
				}
			}
			else {
				// An analyzer-owned void * is often circular evidence propagated from
				// the return currently being classified.  Concrete pointee types and
				// user/imported declarations remain authoritative.
				if (target.getSignatureSource() != SourceType.ANALYSIS ||
					!isGenericDataPointer(type)) {
					item.markDataUse(instruction.getAddress(), type);
				}
			}
		}
	}

	private void recordUnsignedLongPairUse(Instruction instruction, OriginWord low,
			OriginWord high, Map<Function, ReturnEvidence> evidence) {
		if (samePair(low, high)) {
			evidence.computeIfAbsent(low.function(), ignored -> new ReturnEvidence())
				.markUnsignedLongUse(instruction.getAddress());
		}
	}

	private boolean isUnsignedLongRuntimeHelper(Function function) {
		String fixup = function.getCallFixup();
		return "c166_tasking_mulu4".equals(fixup) ||
			"c166_tasking_divu4".equals(fixup) ||
			"c166_tasking_modu4".equals(fixup);
	}

	private void applyRegisterWrites(Program program, Instruction instruction,
			Map<Integer, OriginWord> registers) {
		Integer destination = instruction.getNumOperands() == 0 ? null :
			generalRegisterNumber(program, operandRegister(instruction, 0));
		OriginWord copied = null;
		String mnemonic = instruction.getMnemonicString().toLowerCase();
		if (destination != null && instruction.getNumOperands() >= 2 &&
			mnemonic.equals("mov") &&
			!OperandType.isIndirect(instruction.getOperandType(0)) &&
			!OperandType.isIndirect(instruction.getOperandType(1))) {
			Integer source = generalRegisterNumber(program, operandRegister(instruction, 1));
			copied = source == null ? null : registers.get(source);
		}
		else if (destination != null && registers.containsKey(destination) &&
			instruction.getNumOperands() >= 2 &&
			(mnemonic.equals("add") || mnemonic.equals("addc") ||
				mnemonic.equals("sub") || mnemonic.equals("subc") ||
				mnemonic.equals("and")) &&
			instruction.getScalar(1) != null) {
			copied = registers.get(destination);
		}

		Set<Integer> written = new HashSet<>();
		for (Object result : instruction.getResultObjects()) {
			if (result instanceof Register register) {
				Integer number = generalRegisterNumber(program, register);
				if (number != null) {
					written.add(number);
				}
			}
		}
		for (int number : written) {
			registers.remove(number);
		}
		if (destination != null && written.contains(destination) && copied != null) {
			registers.put(destination, copied);
		}
	}

	/**
	 * Classify a complete R5:R4 return which is forwarded from another function's
	 * already trusted four-byte return.  The trace is intentionally limited to a
	 * straight-line path: both words must originate at the same call, direct
	 * register copies are followed backwards, and only TASKING's documented
	 * callee-saved R6-R9 may survive intervening calls.  This recovers wrappers
	 * and constructor-like functions whose callers consume only R4 even though
	 * the callee deliberately returns the full pointer pair.
	 */
	private List<ForwardedPairOrigin> forwardedReturnSources(Program program,
			Function function, TaskMonitor monitor)
			throws CancelledException {
		List<ForwardedPairOrigin> result = new ArrayList<>();
		boolean sawReturn = false;
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction terminal = instructions.next();
			if (!terminal.getFlowType().isTerminal()) {
				continue;
			}
			sawReturn = true;
			ForwardedWordOrigin low = traceForwardedReturnWord(program, function,
				terminal, 4, monitor);
			ForwardedWordOrigin high = traceForwardedReturnWord(program, function,
				terminal, 5, monitor);
			if (low == null || high == null || low.word() != 0 || high.word() != 1 ||
				!low.call().equals(high.call()) || !low.function().equals(high.function())) {
				return List.of();
			}
			result.add(new ForwardedPairOrigin(low.call(), low.function()));
		}
		return sawReturn ? List.copyOf(result) : List.of();
	}

	private ReturnCategory forwardedReturnCategory(List<ForwardedPairOrigin> sources,
			Set<Function> provenThisRun) {
		ReturnCategory category = null;
		for (ForwardedPairOrigin source : sources) {
			ReturnCategory candidate =
				trustedReturnCategory(source.function(), provenThisRun);
			if (candidate == ReturnCategory.UNKNOWN ||
				category != null && category != candidate) {
				return ReturnCategory.UNKNOWN;
			}
			category = candidate;
		}
		return category == null ? ReturnCategory.UNKNOWN : category;
	}

	private ForwardedWordOrigin traceForwardedReturnWord(Program program,
			Function function, Instruction terminal, int returnRegister,
			TaskMonitor monitor)
			throws CancelledException {
		int traced = returnRegister;
		Instruction instruction =
			program.getListing().getInstructionBefore(terminal.getAddress());
		for (int scanned = 0; instruction != null && scanned < 512; scanned++) {
			monitor.checkCancelled();
			if (!function.getBody().contains(instruction.getAddress()) ||
				instruction.getFlowType().isJump() || instruction.getFlowType().isTerminal()) {
				return null;
			}
			if (instruction.getFlowType().isCall()) {
				if (traced >= 6 && traced <= 9) {
					instruction = program.getListing().getInstructionBefore(
						instruction.getAddress());
					continue;
				}
				if (traced != 4 && traced != 5) {
					return null;
				}
				Function target = directTarget(program, instruction);
				return target == null ? null : new ForwardedWordOrigin(
					instruction.getAddress(), target, traced - 4);
			}
			if (writesGeneralRegister(program, instruction, traced)) {
				if (!instruction.getMnemonicString().equalsIgnoreCase("mov") ||
					instruction.getNumOperands() < 2 ||
					OperandType.isIndirect(instruction.getOperandType(0)) ||
					OperandType.isIndirect(instruction.getOperandType(1))) {
					return null;
				}
				Integer source = generalRegisterNumber(program,
					operandRegister(instruction, 1));
				if (source == null) {
					return null;
				}
				traced = source;
			}
			instruction = program.getListing().getInstructionBefore(
				instruction.getAddress());
		}
		return null;
	}

	private boolean writesGeneralRegister(Program program, Instruction instruction,
			int number) {
		for (Object result : instruction.getResultObjects()) {
			if (result instanceof Register register &&
				Integer.valueOf(number).equals(generalRegisterNumber(program, register)) &&
				register.getMinimumByteSize() >= 2) {
				return true;
			}
		}
		return false;
	}

	private ReturnCategory trustedReturnCategory(Function function,
			Set<Function> provenThisRun) {
		if (function == null) {
			return ReturnCategory.UNKNOWN;
		}
		DataType type = function.getReturnType();
		ReturnCategory category = returnCategory(type);
		if (category != ReturnCategory.DATA && category != ReturnCategory.CODE) {
			return ReturnCategory.UNKNOWN;
		}
		if (category == ReturnCategory.UNKNOWN ||
			function.getSignatureSource() != SourceType.ANALYSIS ||
			provenThisRun.contains(function)) {
			return category;
		}
		if (category == ReturnCategory.DATA && !isGenericDataPointer(type) ||
			category == ReturnCategory.CODE && !isGenericFunctionPointer(type)) {
			return category;
		}
		return ReturnCategory.UNKNOWN;
	}

	/**
	 * One typed consumer is sufficient only when the callee itself explicitly
	 * defines both ABI return words on every return represented by its terminal
	 * basic blocks.  This prevents a caller's unrelated extraout register from
	 * widening a byte or word return.
	 */
	private PairReturnState returnPairState(Program program, Function function,
			TaskMonitor monitor) throws CancelledException {
		BasicBlockModel blocks = new BasicBlockModel(program);
		boolean sawReturn = false;
		boolean sawExplicitPair = false;
		boolean sawUnknownReturn = false;
		for (Instruction instruction :
			program.getListing().getInstructions(function.getBody(), true)) {
			monitor.checkCancelled();
			if (!instruction.getFlowType().isTerminal()) {
				continue;
			}
			sawReturn = true;
			CodeBlock block = blocks.getFirstCodeBlockContaining(
				instruction.getAddress(), monitor);
			AddressSetView region = block == null ? function.getBody() : block;
			boolean low = false;
			boolean high = false;
			Instruction previous =
				program.getListing().getInstructionBefore(instruction.getAddress());
			for (int scanned = 0; previous != null && scanned < 64; scanned++) {
				if (!function.getBody().contains(previous.getAddress()) ||
					!region.contains(previous.getAddress()) ||
					previous.getFlowType().isCall() || previous.getFlowType().isJump()) {
					break;
				}
				for (Object result : previous.getResultObjects()) {
					if (!(result instanceof Register register)) {
						continue;
					}
					// A byte result such as RL4 is not an explicit definition of the
					// complete ABI return word and must not justify widening a char.
					if (register.getMinimumByteSize() < 2) {
						continue;
					}
					Integer number = generalRegisterNumber(program, register);
					low |= number != null && number == 4;
					high |= number != null && number == 5;
				}
				if (low && high) {
					break;
				}
				previous = program.getListing().getInstructionBefore(previous.getAddress());
			}
			if (low != high) {
				return PairReturnState.PARTIAL;
			}
			if (low) {
				sawExplicitPair = true;
			}
			else {
				sawUnknownReturn = true;
			}
		}
		if (!sawReturn) {
			return PairReturnState.UNKNOWN;
		}
		if (sawExplicitPair && sawUnknownReturn) {
			return PairReturnState.PARTIAL;
		}
		return sawExplicitPair ? PairReturnState.EXPLICIT : PairReturnState.UNKNOWN;
	}

	private void killCallClobbers(Map<Integer, OriginWord> registers) {
		// TASKING Classic table 3-14 and the compiler spec preserve R6-R9.
		registers.keySet().removeIf(number -> number < 6 || number > 9);
	}

	private int[] registerPair(Program program, VariableStorage storage) {
		List<Register> values = storage.getRegisters();
		if (values == null || values.size() != 2 || storage.size() != 4) {
			return null;
		}
		Integer first = generalRegisterNumber(program, values.get(0));
		Integer second = generalRegisterNumber(program, values.get(1));
		if (first == null || second == null || Math.abs(first - second) != 1) {
			return null;
		}
		return new int[] { Math.min(first, second), Math.max(first, second) };
	}

	private boolean samePair(OriginWord low, OriginWord high) {
		return low != null && high != null && low.word() == 0 && high.word() == 1 &&
			low.function().equals(high.function());
	}

	private boolean mayTrackReturn(Function function) {
		return !function.isExternal() && function.getCallFixup() == null &&
			usesTaskingConvention(function);
	}

	private boolean mayUpdateReturn(Function function) {
		SourceType source = function.getSignatureSource();
		if (!mayTrackReturn(function)) {
			return false;
		}
		DataType type = function.getReturnType();
		if (source == SourceType.DEFAULT) {
			return Undefined.isUndefined(type);
		}
		// ANALYSIS-owned four-byte categories are deliberately replaceable.  They
		// may be stale output from an earlier data/code/scalar pass.  Concrete
		// scalar types are retained by sameReturnCategory(), while USER_DEFINED
		// and IMPORTED signatures never reach this branch.
		return source == SourceType.ANALYSIS &&
			(Undefined.isUndefined(type) || type.getLength() == 4);
	}

	private boolean usesTaskingConvention(Function function) {
		String name = function.getCallingConventionName();
		return CALLING_CONVENTION.equals(name) ||
			Function.DEFAULT_CALLING_CONVENTION_STRING.equals(name) ||
			Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(name);
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

	private Register operandRegister(Instruction instruction, int operand) {
		for (Object object : instruction.getOpObjects(operand)) {
			if (object instanceof Register register) {
				return register;
			}
		}
		return null;
	}

	private boolean isMemoryOperand(Instruction instruction, int operand) {
		if (OperandType.isIndirect(instruction.getOperandType(operand))) {
			return true;
		}
		String representation = instruction.getDefaultOperandRepresentation(operand);
		return representation != null && representation.trim().startsWith("[");
	}

	private Integer generalRegisterNumber(Program program, Register register) {
		if (register == null) {
			return null;
		}
		for (int number = 0; number <= 15; number++) {
			Register general = program.getRegister("r" + number);
			if (general != null && general.getAddress().getAddressSpace()
					.equals(register.getAddress().getAddressSpace()) &&
				general.getAddress().getOffset() <= register.getAddress().getOffset() &&
				register.getAddress().getOffset() < general.getAddress().getOffset() + 2) {
				return number;
			}
		}
		return null;
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
		Pointer pointer = pointerDataType(type);
		if (pointer == null) {
			return false;
		}
		DataType target = pointer.getDataType();
		while (target instanceof TypeDef typeDef) {
			target = typeDef.getBaseDataType();
		}
		String path = target.getPathName();
		return "/c166/function".equals(path) ||
			"/__c166_far_function".equals(path);
	}

	private boolean isGenericDataPointer(DataType type) {
		Pointer pointer = pointerDataType(type);
		if (pointer == null) {
			return false;
		}
		DataType target = pointer.getDataType();
		while (target instanceof TypeDef typeDef) {
			target = typeDef.getBaseDataType();
		}
		return target instanceof VoidDataType || Undefined.isUndefined(target);
	}

	private static Pointer pointerDataType(DataType type) {
		DataType current = type;
		while (current instanceof TypeDef typeDef) {
			current = typeDef.getBaseDataType();
		}
		return current instanceof Pointer pointer ? pointer : null;
	}

	private DataType genericFunctionPointer(Program program) {
		DataType existing = program.getDataTypeManager().getDataType("/fpointer");
		if (existing != null && isFunctionPointer(existing) && existing.getLength() == 4) {
			return existing;
		}
		DataType functionType = program.getDataTypeManager().getDataType("/c166/function");
		if (!(functionType instanceof FunctionDefinition)) {
			FunctionDefinitionDataType definition = new FunctionDefinitionDataType(
				new CategoryPath("/c166"), "function", program.getDataTypeManager());
			definition.setVarArgs(true);
			functionType = program.getDataTypeManager().resolve(definition,
				DataTypeConflictHandler.DEFAULT_HANDLER);
		}
		TypedefDataType typedef = new TypedefDataType(CategoryPath.ROOT, "fpointer",
			new PointerDataType(functionType, program.getDataTypeManager()),
			program.getDataTypeManager());
		return program.getDataTypeManager().resolve(typedef,
			DataTypeConflictHandler.DEFAULT_HANDLER);
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

	private record OriginWord(Function function, int word) {
	}

	private static final class TraceState {
		private final Map<Integer, OriginWord> registers;
		private OriginWord activePage;

		private TraceState() {
			this(new HashMap<>(), null);
		}

		private TraceState(Map<Integer, OriginWord> registers, OriginWord activePage) {
			this.registers = registers;
			this.activePage = activePage;
		}

		private TraceState copy() {
			return new TraceState(new HashMap<>(registers), activePage);
		}

		private TraceState intersection(TraceState other) {
			Map<Integer, OriginWord> common = new HashMap<>();
			for (Map.Entry<Integer, OriginWord> entry : registers.entrySet()) {
				if (entry.getValue().equals(other.registers.get(entry.getKey()))) {
					common.put(entry.getKey(), entry.getValue());
				}
			}
			OriginWord commonPage = activePage != null && activePage.equals(other.activePage) ?
				activePage : null;
			return new TraceState(common, commonPage);
		}

		private Map<Integer, OriginWord> registers() {
			return registers;
		}

		private OriginWord activePage() {
			return activePage;
		}

		private void setActivePage(OriginWord activePage) {
			this.activePage = activePage;
		}

		@Override
		public boolean equals(Object object) {
			return object instanceof TraceState other &&
				registers.equals(other.registers) &&
				java.util.Objects.equals(activePage, other.activePage);
		}

		@Override
		public int hashCode() {
			return 31 * registers.hashCode() + java.util.Objects.hashCode(activePage);
		}
	}

	private record ForwardedWordOrigin(Address call, Function function, int word) {
	}

	private record ForwardedPairOrigin(Address call, Function function) {
	}

	private enum PairReturnState {
		UNKNOWN,
		EXPLICIT,
		PARTIAL
	}

	private enum ReturnCategory {
		UNKNOWN,
		SCALAR,
		DATA,
		CODE
	}

	private static final class ReturnEvidence {
		private final Set<Address> dataUses = new HashSet<>();
		private final Set<Address> codeUses = new HashSet<>();
		private final Set<Address> scalarUses = new HashSet<>();
		private final Set<Address> unsignedLongUses = new HashSet<>();
		private boolean directPagedUse;
		private DataType concreteDataType;
		private boolean concreteDataTypeConflict;

		private ReturnEvidence copy() {
			ReturnEvidence copy = new ReturnEvidence();
			copy.dataUses.addAll(dataUses);
			copy.codeUses.addAll(codeUses);
			copy.scalarUses.addAll(scalarUses);
			copy.unsignedLongUses.addAll(unsignedLongUses);
			copy.directPagedUse = directPagedUse;
			copy.concreteDataType = concreteDataType;
			copy.concreteDataTypeConflict = concreteDataTypeConflict;
			return copy;
		}

		private void markDataUse(Address address) {
			dataUses.add(address);
		}

		private void markDataUse(Address address, DataType type) {
			markDataUse(address);
			Pointer pointer = pointerDataType(type);
			if (pointer == null || pointer.getDataType() == null ||
				pointer.getDataType() instanceof VoidDataType) {
				return;
			}
			if (concreteDataType == null) {
				concreteDataType = type;
			}
			else if (!concreteDataType.isEquivalent(type)) {
				boolean existingLayout = isOwnedAutoStructurePointer(concreteDataType);
				boolean candidateLayout = isOwnedAutoStructurePointer(type);
				if (candidateLayout && !existingLayout) {
					concreteDataType = type;
					concreteDataTypeConflict = false;
				}
				else if (!existingLayout || candidateLayout) {
					concreteDataTypeConflict = true;
				}
			}
		}

		private DataType concreteDataType(DataType fallback) {
			return concreteDataTypeConflict || concreteDataType == null ? fallback :
				concreteDataType;
		}

		private boolean hasStrongConcreteDataType() {
			return !concreteDataTypeConflict &&
				isOwnedAutoStructurePointer(concreteDataType);
		}

		private static boolean isOwnedAutoStructurePointer(DataType type) {
			Pointer pointer = pointerDataType(type);
			return pointer != null && pointer.getDataType() instanceof Structure structure &&
				"/auto_structs".equals(structure.getCategoryPath().getPath()) &&
				structure.getName().startsWith("astruct");
		}

		private void markCodeUse(Address address) {
			codeUses.add(address);
		}

		private void markScalarUse(Address address) {
			scalarUses.add(address);
		}

		private void markUnsignedLongUse(Address address) {
			scalarUses.add(address);
			unsignedLongUses.add(address);
		}

		private void markForwardedUse(ReturnCategory category, Address address) {
			switch (category) {
				case DATA -> markDataUse(address);
				case CODE -> markCodeUse(address);
				case SCALAR -> markScalarUse(address);
				case UNKNOWN -> {
				}
			}
		}

		private void markDirectPagedUse() {
			directPagedUse = true;
		}

		private Set<Address> dataUses() {
			return dataUses;
		}

		private boolean directPagedUse() {
			return directPagedUse;
		}

		private boolean hasDataUse() {
			return directPagedUse || !dataUses.isEmpty();
		}

		private boolean hasCodeUse() {
			return !codeUses.isEmpty();
		}

		private boolean hasScalarUse() {
			return !scalarUses.isEmpty();
		}

		private Set<Address> codeUses() {
			return codeUses;
		}

		private Set<Address> scalarUses() {
			return scalarUses;
		}

		private boolean hasUnsignedLongUse() {
			return !unsignedLongUses.isEmpty();
		}
	}

	public record RunStatistics(int callers, int inferredReturns,
			int fixedPointRounds, int conflicts) {
		private static RunStatistics empty() {
			return new RunStatistics(0, 0, 0, 0);
		}
	}
}
