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
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined;
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
		monitor.initialize(Math.max(1, functions.size()),
			"C166 scalar signatures: tracing ABI registers");
		int returnRepairs = 0;
		int parameterRepairs = 0;
		for (Function function : functions) {
			monitor.checkCancelled();
			if (mayUpdate(function)) {
				try {
					returnRepairs += repairReturn(program, function, monitor) ? 1 : 0;
					parameterRepairs += repairRegisterParameters(program, function, monitor)
						? 1 : 0;
				}
				catch (DuplicateNameException | InvalidInputException e) {
					log.appendException(e);
				}
			}
			monitor.incrementProgress(1);
		}
		report(program, (fullScan ? "Full" : "Incremental") + " scan: repaired " +
			returnRepairs + " scalar return(s) and " + parameterRepairs +
			" register-parameter signature(s).");
		return true;
	}

	private boolean repairReturn(Program program, Function function, TaskMonitor monitor)
			throws CancelledException, InvalidInputException {
		DataType current = function.getReturnType();
		if (current == null || !Undefined.isUndefined(current) || current.getLength() == 4 ||
			pointerDataType(current) != null) {
			return false;
		}
		ScalarReturnKind kind = scalarReturnKind(program, function, monitor);
		if (kind == ScalarReturnKind.UNKNOWN) {
			return false;
		}
		int length = kind == ScalarReturnKind.BYTE ? 1 : 2;
		if (current.getLength() == length && Undefined.isUndefined(current)) {
			return false;
		}
		function.setCallingConvention(CALLING_CONVENTION);
		function.setReturnType(Undefined.getUndefinedDataType(length), SourceType.ANALYSIS);
		return true;
	}

	private ScalarReturnKind scalarReturnKind(Program program, Function function,
			TaskMonitor monitor) throws CancelledException {
		BasicBlockModel blocks = new BasicBlockModel(program);
		ScalarReturnKind result = null;
		boolean sawReturn = false;
		for (Instruction terminal : program.getListing().getInstructions(function.getBody(), true)) {
			monitor.checkCancelled();
			if (!terminal.getFlowType().isTerminal()) {
				continue;
			}
			sawReturn = true;
			CodeBlock block = blocks.getFirstCodeBlockContaining(terminal.getAddress(), monitor);
			AddressSetView region = block == null ? function.getBody() : block;
			ScalarReturnKind path = lastR4Definition(program, function, region, terminal);
			if (path == ScalarReturnKind.UNKNOWN) {
				return ScalarReturnKind.UNKNOWN;
			}
			if (result != null && result != path) {
				return ScalarReturnKind.UNKNOWN;
			}
			result = path;
		}
		return sawReturn && result != null ? result : ScalarReturnKind.UNKNOWN;
	}

	private ScalarReturnKind lastR4Definition(Program program, Function function,
			AddressSetView region, Instruction terminal) {
		Instruction previous = program.getListing().getInstructionBefore(terminal.getAddress());
		for (int scanned = 0; previous != null && scanned < 64; scanned++) {
			if (!function.getBody().contains(previous.getAddress()) ||
				!region.contains(previous.getAddress()) || previous.getFlowType().isCall() ||
				previous.getFlowType().isJump()) {
				break;
			}
			for (Object result : previous.getResultObjects()) {
				if (!(result instanceof Register register) ||
					!Integer.valueOf(4).equals(generalRegisterNumber(program, register))) {
					continue;
				}
				return register.getMinimumByteSize() == 1
					? ScalarReturnKind.BYTE : ScalarReturnKind.WORD;
			}
			previous = program.getListing().getInstructionBefore(previous.getAddress());
		}
		return ScalarReturnKind.UNKNOWN;
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

	private record RegisterAccess(int readBeforeWrite, int written) {
	}

	private enum ScalarReturnKind {
		UNKNOWN,
		BYTE,
		WORD
	}
}
