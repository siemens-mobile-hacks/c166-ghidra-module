package ghidrainfineon;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Repairs scalar TASKING signatures from ABI-visible register behavior.
 *
 * <p>Table 3-15 distinguishes byte results in RL4, word results in R4, and
 * four-byte results in R5:R4.  Section 3.6 assigns the leading parameter words
 * to R12-R15.  This phase only updates DEFAULT/ANALYSIS signatures and requires
 * machine-level evidence: a return register definition or an incoming-register
 * read before that register is overwritten.</p>
 */
public class C166ScalarSignaturePhase extends C166TaskingTypeInferencePhase {

	private static final String CALLING_CONVENTION = "__tasking_c166_classic";
	private static final int PARAMETER_FIRST = 12;
	private static final int PARAMETER_LAST = 15;
	private static final int PARAMETER_MASK = 0xf;
	private static final int RETURN_NONE = 1;
	private static final int RETURN_LOCAL_BYTE = 1 << 1;
	private static final int RETURN_LOCAL_WORD = 1 << 2;
	private static final int RETURN_LOCAL_OTHER = 1 << 3;
	private static final int RETURN_CALL_BYTE = 1 << 4;
	private static final int RETURN_CALL_WORD = 1 << 5;
	private static final int RETURN_CALL_OTHER = 1 << 6;
	private static final int RETURN_LOCAL_MASK =
		RETURN_LOCAL_BYTE | RETURN_LOCAL_WORD | RETURN_LOCAL_OTHER;
	private static final int RETURN_CALL_MASK =
		RETURN_CALL_BYTE | RETURN_CALL_WORD | RETURN_CALL_OTHER;
	private static final int MAX_RETURN_ROUNDS = 16;
	private static final int MAX_FORWARDING_EPILOGUE_INSTRUCTIONS = 64;

	public C166ScalarSignaturePhase() {
		super("C166 TASKING Scalar Signatures");
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C166ArchitectureProfile.isTaskingClassicLarge(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		boolean fullScan = set == null || set.isEmpty() || set.contains(program.getMemory());
		Iterator<Function> iterator = fullScan
			? program.getFunctionManager().getFunctions(true)
			: program.getFunctionManager().getFunctionsOverlapping(set);
		List<Function> functions = new ArrayList<>();
		iterator.forEachRemaining(functions::add);
		monitor.initialize(Math.max(1, functions.size() * MAX_RETURN_ROUNDS),
			"C166 scalar signatures: tracing ABI registers");
		int returnRepairs = 0;
		int parameterRepairs = 0;
		int thunkRepairs = 0;
		int signatureRounds = 0;
		for (; signatureRounds < MAX_RETURN_ROUNDS; signatureRounds++) {
			int roundChanges = 0;
			for (Function function : functions) {
				monitor.checkCancelled();
				if (!mayUpdate(function)) {
					monitor.incrementProgress(1);
					continue;
				}
				try {
					boolean detached = detachArgumentSettingThunk(program, function);
					boolean repairedReturn = repairReturn(program, function, monitor);
					boolean repairedParameters =
						repairRegisterParameters(program, function, monitor);
					thunkRepairs += detached ? 1 : 0;
					returnRepairs += repairedReturn ? 1 : 0;
					parameterRepairs += repairedParameters ? 1 : 0;
					roundChanges += detached || repairedReturn || repairedParameters ? 1 : 0;
				}
				catch (DuplicateNameException | InvalidInputException e) {
					log.appendException(e);
				}
				monitor.incrementProgress(1);
			}
			if (roundChanges == 0) {
				signatureRounds++;
				break;
			}
		}
		report(program, (fullScan ? "Full" : "Incremental") + " scan: repaired " +
			returnRepairs + " scalar return(s) and " + parameterRepairs +
			" register-parameter signature(s), detached " + thunkRepairs +
			" argument-setting thunk(s), in " + signatureRounds +
			" signature fixed-point round(s).");
		return true;
	}

	/**
	 * Ghidra thunks are signature-identical aliases.  A TASKING tail wrapper
	 * that overwrites an incoming argument register before JMPS is not an alias:
	 * the constant or remapped word belongs to the target call, not the wrapper's
	 * public prototype.
	 */
	private boolean detachArgumentSettingThunk(Program program, Function function) {
		if (!function.isThunk()) {
			return false;
		}
		Function target = function.getThunkedFunction(false);
		Integer targetRegisters = targetRegisterMask(program, target);
		if (targetRegisters == null || targetRegisters == 0) {
			return false;
		}
		int unreadIncoming = PARAMETER_MASK;
		int boundBeforeRead = 0;
		boolean hasExternalTail = false;
		for (Instruction instruction : program.getListing()
				.getInstructions(function.getBody(), true)) {
			if (isTailTransferCandidate(instruction)) {
				for (Address flow : instruction.getFlows()) {
					if (!function.getBody().contains(flow)) {
						hasExternalTail = true;
					}
				}
				continue;
			}
			RegisterAccess access = registerAccess(program, instruction);
			boundBeforeRead |= access.written() & unreadIncoming &
				~access.readBeforeWrite();
			unreadIncoming &= ~access.readBeforeWrite();
			unreadIncoming &= ~access.written();
		}
		if (!hasExternalTail || (targetRegisters & boundBeforeRead) == 0) {
			return false;
		}
		function.setThunkedFunction(null);
		return true;
	}

	private boolean repairReturn(Program program, Function function, TaskMonitor monitor)
			throws CancelledException, InvalidInputException {
		DataType current = function.getReturnType();
		if (current == null || current.getLength() == 4 || pointerDataType(current) != null ||
			!Undefined.isUndefined(current) && !(current instanceof VoidDataType)) {
			return false;
		}
		ScalarReturnKind kind = scalarReturnKind(program, function, monitor);
		if (kind == ScalarReturnKind.UNKNOWN) {
			return false;
		}
		if (current instanceof VoidDataType && kind != ScalarReturnKind.VOID) {
			return false;
		}
		DataType inferred = kind == ScalarReturnKind.VOID ? VoidDataType.dataType :
			Undefined.getUndefinedDataType(kind == ScalarReturnKind.BYTE ? 1 : 2);
		if (current.isEquivalent(inferred)) {
			return false;
		}
		function.setCallingConvention(CALLING_CONVENTION);
		function.setReturnType(inferred, SourceType.ANALYSIS);
		return true;
	}

	private ScalarReturnKind scalarReturnKind(Program program, Function function,
			TaskMonitor monitor) throws CancelledException {
		Map<Address, Integer> seen = new HashMap<>();
		ArrayDeque<ReturnFlowState> queue = new ArrayDeque<>();
		queue.add(new ReturnFlowState(function.getEntryPoint(), RETURN_NONE));
		int returnStates = 0;
		while (!queue.isEmpty()) {
			monitor.checkCancelled();
			ReturnFlowState state = queue.removeFirst();
			if (!function.getBody().contains(state.address())) {
				continue;
			}
			int previous = seen.getOrDefault(state.address(), 0);
			int incoming = state.possibleReturns() & ~previous;
			if (incoming == 0) {
				continue;
			}
			seen.put(state.address(), previous | incoming);
			Instruction instruction =
				program.getListing().getInstructionAt(state.address());
			if (instruction == null) {
				continue;
			}

			if (isTailTransferCandidate(instruction)) {
				returnStates |= callReturnState(
					tailReturnKind(program, function, instruction));
				continue;
			}
			int outgoing = returnStateAfter(program, function, instruction, incoming);
			if (isReturnInstruction(instruction)) {
				returnStates |= outgoing;
				continue;
			}
			if (instruction.getFlowType().isTerminal()) {
				continue;
			}

			Address fallThrough = instruction.getFallThrough();
			if (fallThrough != null && function.getBody().contains(fallThrough)) {
				queue.add(new ReturnFlowState(fallThrough, outgoing));
			}
			if (!instruction.getFlowType().isCall()) {
				for (Address flow : instruction.getFlows()) {
					if (function.getBody().contains(flow)) {
						queue.add(new ReturnFlowState(flow, outgoing));
					}
				}
				for (var reference : instruction.getReferencesFrom()) {
					if (reference.getReferenceType().isJump() &&
						function.getBody().contains(reference.getToAddress())) {
						queue.add(new ReturnFlowState(reference.getToAddress(), outgoing));
					}
				}
			}
		}
		int local = returnStates & RETURN_LOCAL_MASK;
		int calls = returnStates & RETURN_CALL_MASK;
		boolean hasEmptyPath = (returnStates & RETURN_NONE) != 0;
		if (local != 0) {
			if (hasEmptyPath || calls != 0) {
				return ScalarReturnKind.UNKNOWN;
			}
			return local == RETURN_LOCAL_BYTE ? ScalarReturnKind.BYTE :
				local == RETURN_LOCAL_WORD ? ScalarReturnKind.WORD :
				ScalarReturnKind.UNKNOWN;
		}
		if (hasEmptyPath) {
			// A function with at least one path that supplies no result and no
			// explicit local R4 definition is void.  Values left by calls on the
			// other paths are incidental caller-clobbered register contents.
			return ScalarReturnKind.VOID;
		}
		return calls == RETURN_CALL_BYTE ? ScalarReturnKind.BYTE :
			calls == RETURN_CALL_WORD ? ScalarReturnKind.WORD :
			ScalarReturnKind.UNKNOWN;
	}

	private boolean isReturnInstruction(Instruction instruction) {
		return instruction.getMnemonicString().toLowerCase().startsWith("ret");
	}

	private int returnStateAfter(Program program, Function function,
			Instruction instruction, int incoming) {
		if (instruction.getFlowType().isCall()) {
			if (!isTerminalForwardingCall(program, function, instruction)) {
				return RETURN_NONE;
			}
			ScalarReturnKind called = declaredReturnKind(program,
				directTarget(program, instruction));
			return called == ScalarReturnKind.VOID ? incoming : callReturnState(called);
		}
		R4WriteKind written = writtenR4Kind(program, instruction);
		return switch (written) {
			case NONE -> incoming;
			case BYTE -> RETURN_LOCAL_BYTE;
			case WORD -> RETURN_LOCAL_WORD;
			case OTHER -> RETURN_LOCAL_OTHER;
		};
	}

	private R4WriteKind writtenR4Kind(Program program, Instruction instruction) {
		Register r4 = program.getRegister("r4");
		if (r4 == null) {
			return R4WriteKind.NONE;
		}
		for (Object result : instruction.getResultObjects()) {
			if (!(result instanceof Register register) ||
				!Integer.valueOf(4).equals(generalRegisterNumber(program, register))) {
				continue;
			}
			if (register.getMinimumByteSize() >= 2) {
				return R4WriteKind.WORD;
			}
			return register.getAddress().equals(r4.getAddress())
				? R4WriteKind.BYTE : R4WriteKind.OTHER;
		}
		return R4WriteKind.NONE;
	}

	private int callReturnState(ScalarReturnKind kind) {
		return switch (kind) {
			case VOID -> RETURN_NONE;
			case BYTE -> RETURN_CALL_BYTE;
			case WORD -> RETURN_CALL_WORD;
			default -> RETURN_CALL_OTHER;
		};
	}

	/**
	 * A normal CALL only supplies this function's return value when every path
	 * after it consists solely of an ABI epilogue and RETS.  Otherwise R4 is a
	 * caller-clobbered temporary, not source-level return evidence.
	 */
	private boolean isTerminalForwardingCall(Program program, Function function,
			Instruction call) {
		Address fallThrough = call.getFallThrough();
		if (fallThrough == null || !function.getBody().contains(fallThrough)) {
			return false;
		}
		ArrayDeque<Address> queue = new ArrayDeque<>();
		Map<Address, Boolean> seen = new HashMap<>();
		queue.add(fallThrough);
		boolean sawReturn = false;
		int visited = 0;
		while (!queue.isEmpty()) {
			Address address = queue.removeFirst();
			if (seen.put(address, Boolean.TRUE) != null) {
				continue;
			}
			if (++visited > MAX_FORWARDING_EPILOGUE_INSTRUCTIONS) {
				return false;
			}
			Instruction instruction = program.getListing().getInstructionAt(address);
			if (instruction == null || !function.getBody().contains(address)) {
				return false;
			}
			if (isReturnInstruction(instruction)) {
				sawReturn = true;
				continue;
			}
			if (instruction.getFlowType().isJump() &&
				!instruction.getFlowType().isConditional()) {
				boolean queued = false;
				for (Address flow : instruction.getFlows()) {
					if (function.getBody().contains(flow)) {
						queue.add(flow);
						queued = true;
					}
				}
				if (!queued) {
					return false;
				}
				continue;
			}
			if (!isForwardingEpilogueInstruction(instruction)) {
				return false;
			}
			Address next = instruction.getFallThrough();
			if (next == null || !function.getBody().contains(next)) {
				return false;
			}
			queue.add(next);
		}
		return sawReturn;
	}

	private boolean isForwardingEpilogueInstruction(Instruction instruction) {
		String rendered = instruction.toString().toLowerCase().replace(" ", "");
		if (rendered.equals("nop") || rendered.startsWith("addr0,#") ||
			rendered.startsWith("addsp")) {
			return true;
		}
		if (!rendered.startsWith("mov")) {
			return false;
		}
		return rendered.matches("mov(r[6-9]|dpp[0-3]|cp|mdc|mdh|mdl),\\[r0\\+\\]");
	}

	private boolean isTailTransferCandidate(Instruction instruction) {
		String mnemonic = instruction.getMnemonicString().toLowerCase();
		return (mnemonic.equals("jmps") || mnemonic.equals("jmpa")) &&
			!instruction.getFlowType().isConditional();
	}

	/**
	 * TASKING emits tiny wrappers as a parameter setup followed by JMPS to the
	 * implementation.  JMPS does not define R4 itself: the wrapper has exactly
	 * the target's return convention, including void.  Trust only an exact
	 * function entry outside the wrapper body and only a non-default target
	 * return declaration.
	 */
	private ScalarReturnKind tailReturnKind(Program program, Function function,
			Instruction terminal) {
		String mnemonic = terminal.getMnemonicString().toLowerCase();
		if (!mnemonic.equals("jmps") && !mnemonic.equals("jmpa") ||
			terminal.getFlowType().isConditional()) {
			return ScalarReturnKind.UNKNOWN;
		}
		Function target = null;
		for (Address flow : terminal.getFlows()) {
			if (!function.getBody().contains(flow)) {
				target = program.getFunctionManager().getFunctionAt(flow);
				if (target != null) {
					break;
				}
			}
		}
		return declaredReturnKind(program, target);
	}

	private ScalarReturnKind declaredReturnKind(Program program, Function target) {
		if (target == null) {
			return ScalarReturnKind.UNKNOWN;
		}
		DataType type = target.getReturnType();
		if (type instanceof VoidDataType) {
			return ScalarReturnKind.VOID;
		}
		if (pointerDataType(type) != null || type.getLength() == 4) {
			return ScalarReturnKind.UNKNOWN;
		}
		if (type.getLength() == 2 &&
			(CALLING_CONVENTION.equals(target.getCallingConventionName()) ||
				target.getSignatureSource() != SourceType.DEFAULT)) {
			return ScalarReturnKind.WORD;
		}
		if (type.getLength() == 1 && !Undefined.isUndefined(type) &&
			target.getSignatureSource() != SourceType.DEFAULT) {
			return ScalarReturnKind.BYTE;
		}
		return ScalarReturnKind.UNKNOWN;
	}

	private Function directTarget(Program program, Instruction instruction) {
		for (Address flow : instruction.getFlows()) {
			Function target = program.getFunctionManager().getFunctionAt(flow);
			if (target != null) {
				return target;
			}
		}
		for (var reference : instruction.getReferencesFrom()) {
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

	private boolean repairRegisterParameters(Program program, Function function,
			TaskMonitor monitor) throws CancelledException, DuplicateNameException,
			InvalidInputException {
		if (function.hasVarArgs() || function.isThunk() || function.isExternal() ||
			hasStackParameter(function)) {
			return false;
		}
		int incomingPrefix = incomingRegisterPrefix(program, function, monitor);
		int requiredWords = Math.max(incomingPrefix,
			scalarPairEvidenceWords(program, function));
		if (requiredWords == 0) {
			if (function.getParameterCount() == 0 &&
				(isLeafFunction(program, function) ||
					isFullyBoundTailWrapper(program, function)) &&
				(!CALLING_CONVENTION.equals(function.getCallingConventionName()) ||
					function.getSignatureSource() == SourceType.DEFAULT)) {
				function.updateFunction(CALLING_CONVENTION, null, List.of(),
					FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
					SourceType.ANALYSIS);
				return true;
			}
			return false;
		}
		requiredWords = Math.max(requiredWords, protectedExistingPrefix(program, function));
		List<Variable> parameters = rebuiltRegisterParameters(program, function, requiredWords);
		if (sameParameterLayout(function, parameters)) {
			return false;
		}
		function.updateFunction(CALLING_CONVENTION, null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
		return true;
	}

	private boolean isFullyBoundTailWrapper(Program program, Function function) {
		int unreadIncoming = PARAMETER_MASK;
		int boundBeforeRead = 0;
		Function target = null;
		for (Instruction instruction : program.getListing()
				.getInstructions(function.getBody(), true)) {
			if (isTailTransferCandidate(instruction)) {
				if (target != null) {
					return false;
				}
				target = externalTailTarget(program, function, instruction);
				continue;
			}
			if (instruction.getFlowType().isCall()) {
				return false;
			}
			RegisterAccess access = registerAccess(program, instruction);
			boundBeforeRead |= access.written() & unreadIncoming &
				~access.readBeforeWrite();
			unreadIncoming &= ~access.readBeforeWrite();
			unreadIncoming &= ~access.written();
		}
		Integer required = targetRegisterMask(program, target);
		if (required == null) {
			return false;
		}
		return (required & ~boundBeforeRead) == 0;
	}

	private Integer targetRegisterMask(Program program, Function target) {
		if (target == null || target.getSignatureSource() == SourceType.DEFAULT) {
			return null;
		}
		int required = 0;
		for (Parameter parameter : target.getParameters()) {
			VariableStorage storage = parameter.getVariableStorage();
			if (storage.isStackStorage()) {
				return null;
			}
			for (Register register : storage.getRegisters()) {
				Integer number = generalRegisterNumber(program, register);
				if (number == null || number < PARAMETER_FIRST || number > PARAMETER_LAST) {
					return null;
				}
				required |= 1 << (number - PARAMETER_FIRST);
			}
		}
		return required;
	}

	private Function externalTailTarget(Program program, Function function,
			Instruction terminal) {
		for (Address flow : terminal.getFlows()) {
			if (!function.getBody().contains(flow)) {
				return program.getFunctionManager().getFunctionAt(flow);
			}
		}
		return null;
	}

	private boolean isLeafFunction(Program program, Function function) {
		for (Instruction instruction : program.getListing()
				.getInstructions(function.getBody(), true)) {
			if (instruction.getFlowType().isCall()) {
				return false;
			}
			if (isTailTransferCandidate(instruction)) {
				for (Address flow : instruction.getFlows()) {
					if (!function.getBody().contains(flow)) {
						return false;
					}
				}
			}
		}
		return true;
	}

	private int scalarPairEvidenceWords(Program program, Function function) {
		int words = 0;
		for (int start = 0; start < 4; start++) {
			if (C166CodePointerPhase.hasScalarPairEvidence(program, function, start)) {
				words = Math.max(words, Math.min(4, start + 2));
			}
		}
		return words;
	}

	private int incomingRegisterPrefix(Program program, Function function,
			TaskMonitor monitor) throws CancelledException {
		Map<Address, Integer> seen = new HashMap<>();
		ArrayDeque<FlowState> queue = new ArrayDeque<>();
		queue.add(new FlowState(function.getEntryPoint(), PARAMETER_MASK));
		int live = 0;
		while (!queue.isEmpty()) {
			monitor.checkCancelled();
			FlowState state = queue.removeFirst();
			if (!function.getBody().contains(state.address())) {
				continue;
			}
			int previous = seen.getOrDefault(state.address(), 0);
			int possible = state.possibleIncoming() & ~previous;
			if (possible == 0) {
				continue;
			}
			seen.put(state.address(), previous | possible);
			Instruction instruction = program.getListing().getInstructionAt(state.address());
			if (instruction == null) {
				continue;
			}
			RegisterAccess access = registerAccess(program, instruction);
			live |= possible & access.readBeforeWrite();
			possible &= ~access.written();
			if (instruction.getFlowType().isCall()) {
				possible = 0;
			}
			Address fallThrough = instruction.getFallThrough();
			if (fallThrough != null && function.getBody().contains(fallThrough)) {
				queue.add(new FlowState(fallThrough, possible));
			}
			if (!instruction.getFlowType().isCall()) {
				for (Address flow : instruction.getFlows()) {
					if (function.getBody().contains(flow)) {
						queue.add(new FlowState(flow, possible));
					}
				}
			}
		}
		return registerWordCount(live);
	}

	private int protectedExistingPrefix(Program program, Function function) {
		boolean containsWideValue = false;
		for (Parameter parameter : function.getParameters()) {
			DataType type = parameter.getFormalDataType();
			if (pointerDataType(type) != null || type.getLength() == 4) {
				containsWideValue = true;
				break;
			}
		}
		int maximum = 0;
		for (Parameter parameter : function.getParameters()) {
			VariableStorage storage = parameter.getVariableStorage();
			for (Register register : storage.getRegisters()) {
				Integer number = generalRegisterNumber(program, register);
				if (number != null && number >= PARAMETER_FIRST && number <= PARAMETER_LAST &&
					(containsWideValue || pointerDataType(parameter.getFormalDataType()) != null ||
					parameter.getFormalDataType().getLength() == 4)) {
					maximum = Math.max(maximum, number - PARAMETER_FIRST + 1);
				}
			}
		}
		return maximum;
	}

	private List<Variable> rebuiltRegisterParameters(Program program, Function function,
			int requiredWords) throws InvalidInputException {
		Map<Integer, Parameter> existing = new HashMap<>();
		for (Parameter parameter : function.getParameters()) {
			Integer start = parameterStart(program, parameter.getVariableStorage());
			if (start != null) {
				existing.put(start, parameter);
			}
		}
		List<Variable> result = new ArrayList<>();
		for (int word = 0; word < requiredWords;) {
			Parameter parameter = existing.get(word);
			int width = parameter == null ? 1 : parameterWordWidth(parameter);
			if (parameter != null && width > 0 && word + width <= requiredWords) {
				result.add(new ParameterImpl(existingName(parameter),
					parameter.getFormalDataType(), program));
				word += width;
			}
			else {
				result.add(new ParameterImpl(null, Undefined.getUndefinedDataType(2), program));
				word++;
			}
		}
		return result;
	}

	private boolean sameParameterLayout(Function function, List<Variable> rebuilt) {
		Parameter[] current = function.getParameters();
		if (current.length != rebuilt.size()) {
			return false;
		}
		for (int i = 0; i < current.length; i++) {
			if (!current[i].getFormalDataType().isEquivalent(rebuilt.get(i).getDataType())) {
				return false;
			}
		}
		return CALLING_CONVENTION.equals(function.getCallingConventionName());
	}

	private Integer parameterStart(Program program, VariableStorage storage) {
		Integer minimum = null;
		for (Register register : storage.getRegisters()) {
			Integer number = generalRegisterNumber(program, register);
			if (number == null || number < PARAMETER_FIRST || number > PARAMETER_LAST) {
				return null;
			}
			minimum = minimum == null ? number : Math.min(minimum, number);
		}
		return minimum == null ? null : minimum - PARAMETER_FIRST;
	}

	private int parameterWordWidth(Parameter parameter) {
		int size = parameter.getVariableStorage().size();
		return Math.max(1, (size + 1) / 2);
	}

	private boolean hasStackParameter(Function function) {
		for (Parameter parameter : function.getParameters()) {
			if (parameter.getVariableStorage().isStackStorage()) {
				return true;
			}
		}
		return false;
	}

	private boolean mayUpdate(Function function) {
		SourceType source = function.getSignatureSource();
		String convention = function.getCallingConventionName();
		return !function.isExternal() && (source == SourceType.DEFAULT ||
			source == SourceType.ANALYSIS) &&
			(Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(convention) ||
			Function.DEFAULT_CALLING_CONVENTION_STRING.equals(convention) ||
			CALLING_CONVENTION.equals(convention));
	}

	private RegisterAccess registerAccess(Program program, Instruction instruction) {
		int readBeforeWrite = 0;
		int written = 0;
		for (PcodeOp operation : instruction.getPcode()) {
			for (Varnode input : operation.getInputs()) {
				int mask = parameterRegisterMask(program, input);
				readBeforeWrite |= mask & ~written;
			}
			written |= parameterRegisterMask(program, operation.getOutput());
		}
		// Context-setting instructions such as EXTP encode the source register in
		// the listing but intentionally emit no p-code.  Use listing metadata only
		// for that p-code-empty case; ordinary instructions stay p-code-driven.
		if (readBeforeWrite == 0 && written == 0) {
			readBeforeWrite = parameterRegisterMask(program, instruction.getInputObjects());
			written = parameterRegisterMask(program, instruction.getResultObjects());
		}
		return new RegisterAccess(readBeforeWrite, written);
	}

	private int parameterRegisterMask(Program program, Object[] objects) {
		int mask = 0;
		for (Object object : objects) {
			if (object instanceof Register register) {
				mask |= parameterRegisterMask(program, register);
			}
		}
		return mask;
	}

	private int parameterRegisterMask(Program program, Varnode varnode) {
		if (varnode == null || !varnode.isRegister()) {
			return 0;
		}
		Integer number = generalRegisterNumber(program, program.getRegister(varnode));
		return number != null && number >= PARAMETER_FIRST && number <= PARAMETER_LAST
			? 1 << (number - PARAMETER_FIRST) : 0;
	}

	private int parameterRegisterMask(Program program, Register register) {
		Integer number = generalRegisterNumber(program, register);
		return number != null && number >= PARAMETER_FIRST && number <= PARAMETER_LAST
			? 1 << (number - PARAMETER_FIRST) : 0;
	}

	private int registerWordCount(int mask) {
		return mask == 0 ? 0 : Integer.SIZE - Integer.numberOfLeadingZeros(mask);
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

	private Pointer pointerDataType(DataType type) {
		DataType current = type;
		while (current instanceof TypeDef typeDef) {
			current = typeDef.getBaseDataType();
		}
		return current instanceof Pointer pointer ? pointer : null;
	}

	private String existingName(Parameter parameter) {
		return parameter.getSource() == SourceType.DEFAULT ? null : parameter.getName();
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

	private record FlowState(Address address, int possibleIncoming) {
	}

	private record ReturnFlowState(Address address, int possibleReturns) {
	}

	private record RegisterAccess(int readBeforeWrite, int written) {
	}

	private enum ScalarReturnKind {
		VOID,
		UNKNOWN,
		BYTE,
		WORD
	}

	private enum R4WriteKind {
		NONE,
		BYTE,
		WORD,
		OTHER
	}
}
