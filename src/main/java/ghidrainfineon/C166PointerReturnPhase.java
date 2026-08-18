package ghidrainfineon;

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
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Undefined;
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
		boolean fullScan = set == null || set.isEmpty() || set.contains(program.getMemory());
		Iterator<Function> iterator = fullScan
			? program.getFunctionManager().getFunctions(true)
			: program.getFunctionManager().getFunctionsOverlapping(set);
		List<Function> callers = new ArrayList<>();
		iterator.forEachRemaining(callers::add);
		final int maximumRounds = 4;
		monitor.initialize(Math.max(1, callers.size() * maximumRounds),
			"C166 return classification: tracing R5:R4");
		int inferred = 0;
		int rounds = 0;
		Set<Function> conflicts = new HashSet<>();
		DataType dataPointer = new PointerDataType(VoidDataType.dataType,
			program.getDataTypeManager());
		DataType codePointer = genericFunctionPointer(program);
		for (int round = 0; round < maximumRounds; round++) {
			Map<Function, ReturnEvidence> evidence = new HashMap<>();
			for (Function caller : callers) {
				monitor.checkCancelled();
				traceCaller(program, caller, evidence, monitor);
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
					explicitPair && !item.dataUses().isEmpty();
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
						enoughData ? dataPointer : Undefined.getUndefinedDataType(4);
					if (sameReturnCategory(function.getReturnType(), inferredType)) {
						continue;
					}
					function.setCallingConvention(CALLING_CONVENTION);
					function.setReturnType(inferredType, SourceType.ANALYSIS);
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
		return true;
	}

	private boolean sameReturnCategory(DataType current, DataType inferred) {
		ReturnCategory currentCategory = returnCategory(current);
		return currentCategory != ReturnCategory.UNKNOWN &&
			currentCategory == returnCategory(inferred);
	}

	private ReturnCategory returnCategory(DataType type) {
		Pointer pointer = pointerDataType(type);
		if (pointer != null) {
			return isFunctionPointer(type) ? ReturnCategory.CODE : ReturnCategory.DATA;
		}
		return type != null && type.getLength() == 4 ? ReturnCategory.SCALAR :
			ReturnCategory.UNKNOWN;
	}

	private void traceCaller(Program program, Function caller,
			Map<Function, ReturnEvidence> evidence, TaskMonitor monitor)
			throws CancelledException {
		Map<Integer, OriginWord> registers = new HashMap<>();
		OriginWord activePage = null;
		InstructionIterator instructions =
			program.getListing().getInstructions(caller.getBody(), true);
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = instructions.next();
			if (instruction.getFlowType().isCall()) {
				Function target = directTarget(program, instruction);
				if (target != null) {
					recordCallUses(program, target, instruction, registers, evidence);
				}
				killCallClobbers(registers);
				activePage = null;
				if (target != null && mayTrackReturn(target)) {
					registers.put(4, new OriginWord(target, 0));
					registers.put(5, new OriginWord(target, 1));
				}
				continue;
			}

			Register pageRegister = dynamicPageSource(instruction);
			if (pageRegister != null) {
				Integer pageNumber = generalRegisterNumber(program, pageRegister);
				activePage = pageNumber == null ? null : registers.get(pageNumber);
			}
			if (activePage != null && activePage.word() == 1) {
				for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
					if (!isMemoryOperand(instruction, operand)) {
						continue;
					}
					Integer base = generalRegisterNumber(program,
						operandRegister(instruction, operand));
					OriginWord low = base == null ? null : registers.get(base);
					if (samePair(low, activePage)) {
						evidence.computeIfAbsent(low.function(), ignored -> new ReturnEvidence())
							.markDirectPagedUse();
					}
				}
			}

			applyRegisterWrites(program, instruction, registers);
			if (instruction.getFlowType().isJump() || instruction.getFlowType().isTerminal()) {
				registers.clear();
				activePage = null;
			}
		}
	}

	private void recordCallUses(Program program, Function target, Instruction instruction,
			Map<Integer, OriginWord> registers, Map<Function, ReturnEvidence> evidence) {
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
				item.markDataUse(instruction.getAddress());
			}
		}
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

	private Pointer pointerDataType(DataType type) {
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
		private boolean directPagedUse;

		private void markDataUse(Address address) {
			dataUses.add(address);
		}

		private void markCodeUse(Address address) {
			codeUses.add(address);
		}

		private void markScalarUse(Address address) {
			scalarUses.add(address);
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
	}
}
