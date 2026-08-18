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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.TypeDef;
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
 * Infers TASKING Classic Large far-data-pointer returns in the documented
 * R5:R4 return pair.
 * <p>
 * Merely observing both registers after a call is not type evidence: the same
 * pair also carries {@code long} and {@code float}.  This analyzer follows the
 * two words through straight-line register copies and promotes the callee only
 * when the pair is either consumed by a known four-byte data-pointer formal at
 * multiple instructions or used directly as PAGE:OFFSET for paged memory.
 * Feeding the pair to a function-pointer formal or the far-indirect dispatcher
 * is contradictory evidence and suppresses the update.
 */
public class C166PointerReturnPhase extends C166TaskingTypeInferencePhase {

	private static final String CALLING_CONVENTION = "__tasking_c166_classic";

	public C166PointerReturnPhase() {
		super("C166 TASKING Far Pointer Return Inference");
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
		Map<Function, ReturnEvidence> evidence = new HashMap<>();
		monitor.initialize(Math.max(1, callers.size()),
			"C166 far-pointer return inference: tracing R5:R4");
		for (Function caller : callers) {
			monitor.checkCancelled();
			traceCaller(program, caller, evidence, monitor);
			monitor.incrementProgress(1);
		}

		int inferred = 0;
		int conflicts = 0;
		DataType dataPointer = new PointerDataType(VoidDataType.dataType,
			program.getDataTypeManager());
		for (Map.Entry<Function, ReturnEvidence> entry : evidence.entrySet()) {
			monitor.checkCancelled();
			Function function = entry.getKey();
			ReturnEvidence item = entry.getValue();
			if (item.hasCodeUse()) {
				if (item.hasDataUse()) {
					conflicts++;
					report(program, function.getEntryPoint() +
						": conflicting data/code return evidence (" +
						item.dataUses().size() + " typed data use(s), direct paged=" +
						item.directPagedUse() + ", " + item.codeUses().size() +
						" code use(s))");
				}
				continue;
			}
			if (!item.directPagedUse() && item.dataUses().size() < 2 ||
				!mayUpdateReturn(function)) {
				continue;
			}
			try {
				function.setCallingConvention(CALLING_CONVENTION);
				function.setReturnType(dataPointer, SourceType.ANALYSIS);
				inferred++;
			}
			catch (InvalidInputException e) {
				log.appendException(e);
			}
		}
		report(program, (fullScan ? "Full" : "Incremental") + " scan: traced " +
			callers.size() + " caller function(s), inferred " + inferred +
			" far-data-pointer return(s), rejected " + conflicts +
			" data/code-use conflict(s).");
		return true;
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
			if (pointer == null || type.getLength() != 4) {
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
			if (isFunctionPointer(type)) {
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
			(mnemonic.equals("add") || mnemonic.equals("sub") || mnemonic.equals("and")) &&
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
		return mayTrackReturn(function) &&
			(source == SourceType.DEFAULT || source == SourceType.ANALYSIS) &&
			Undefined.isUndefined(function.getReturnType());
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

	private static final class ReturnEvidence {
		private final Set<Address> dataUses = new HashSet<>();
		private final Set<Address> codeUses = new HashSet<>();
		private boolean directPagedUse;

		private void markDataUse(Address address) {
			dataUses.add(address);
		}

		private void markCodeUse(Address address) {
			codeUses.add(address);
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

		private Set<Address> codeUses() {
			return codeUses;
		}
	}
}
