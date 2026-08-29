package ghidrainfineon;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Recovers the 16-bit argument words prepared for a TASKING Classic call.
 *
 * Register words occupy slots 0..3 (R12..R15).  Stack words begin at slot 4
 * and are considered arguments only after all four register slots are known to
 * be occupied.  Constants retain the address of their setup instruction so
 * analyzers can attach a reference to the actual operand rather than the call.
 */
final class C166TaskingCallArguments {

	private static final int FIRST_ARGUMENT_REGISTER = 12;
	private static final int MAX_SETUP_SCAN_INSTRUCTIONS = 256;
	private static final Map<Program, RecoveryCache> ACTIVE_RECOVERY_CACHES =
		new WeakHashMap<>();

	private C166TaskingCallArguments() {
	}

	static CallWords recover(Program program, Function caller, Instruction call,
			BasicBlockModel blocks, TaskMonitor monitor) throws CancelledException {
		RecoveryCache cache;
		synchronized (ACTIVE_RECOVERY_CACHES) {
			cache = ACTIVE_RECOVERY_CACHES.get(program);
		}
		if (cache == null) {
			return recoverUncached(program, caller, call, blocks, monitor);
		}
		synchronized (cache) {
			CallWords cached = cache.words.get(call.getAddress());
			if (cached != null) {
				cache.hits++;
				return cached;
			}
		}
		CallWords recovered = recoverUncached(program, caller, call, blocks, monitor);
		synchronized (cache) {
			CallWords existing = cache.words.putIfAbsent(call.getAddress(), recovered);
			cache.misses++;
			return existing == null ? recovered : existing;
		}
	}

	private static CallWords recoverUncached(Program program, Function caller,
			Instruction call, BasicBlockModel blocks, TaskMonitor monitor)
			throws CancelledException {
		Map<Integer, WordValue> words = new HashMap<>();
		AddressSetView setupRegion = setupRegion(program, caller, call, blocks, monitor);
		boolean registerBankOccupied = true;
		for (int slot = 0; slot < 4; slot++) {
			Register register = program.getRegister("r" + (FIRST_ARGUMENT_REGISTER + slot));
			WordValue value = traceRegister(program, caller, setupRegion, call, register, 0,
				new HashSet<>());
			words.put(slot, value);
			registerBankOccupied &= value.defined();
		}
		if (registerBankOccupied) {
			Integer stackWords = stackArgumentWords(program, call);
			recoverPushedWords(program, caller, setupRegion, call, words, stackWords);
			return new CallWords(Map.copyOf(words), true, stackWords);
		}
		return new CallWords(Map.copyOf(words), false, stackArgumentWords(program, call));
	}

	static RecoverySession beginSharedRecovery(Program program) {
		RecoveryCache cache = new RecoveryCache();
		synchronized (ACTIVE_RECOVERY_CACHES) {
			ACTIVE_RECOVERY_CACHES.put(program, cache);
		}
		return new RecoverySession(program, cache);
	}

	static final class RecoverySession implements AutoCloseable {
		private final Program program;
		private final RecoveryCache cache;
		private boolean closed;

		private RecoverySession(Program program, RecoveryCache cache) {
			this.program = program;
			this.cache = cache;
		}

		int hits() {
			synchronized (cache) {
				return cache.hits;
			}
		}

		int misses() {
			synchronized (cache) {
				return cache.misses;
			}
		}

		@Override
		public void close() {
			if (closed) {
				return;
			}
			closed = true;
			synchronized (ACTIVE_RECOVERY_CACHES) {
				if (ACTIVE_RECOVERY_CACHES.get(program) == cache) {
					ACTIVE_RECOVERY_CACHES.remove(program);
				}
			}
		}
	}

	private static final class RecoveryCache {
		private final Map<Address, CallWords> words = new HashMap<>();
		private int hits;
		private int misses;
	}

	/**
	 * Ghidra may put a call instruction in its own basic block. TASKING may also
	 * leave an outer argument live on R0 while an inner call computes a later
	 * register argument. Extend the setup region through the unique linear
	 * fall-through chain, including call-return edges, but never through a jump
	 * or a predecessor merge.
	 */
	private static AddressSetView setupRegion(Program program, Function caller,
			Instruction call, BasicBlockModel blocks, TaskMonitor monitor)
			throws CancelledException {
		CodeBlock block = blocks.getFirstCodeBlockContaining(call.getAddress(), monitor);
		if (block == null) {
			return caller.getBody();
		}
		AddressSet result = new AddressSet(block);
		CodeBlock current = block;
		for (int crossed = 0; crossed < 16; crossed++) {
			Address first = current.getMinAddress();
			Instruction predecessor = program.getListing().getInstructionBefore(first);
			if (predecessor == null || !caller.getBody().contains(predecessor.getAddress()) ||
				predecessor.getFlowType().isJump() ||
				predecessor.getFlowType().isTerminal() ||
				!first.equals(predecessor.getFallThrough())) {
				break;
			}
			CodeBlock predecessorBlock =
				blocks.getFirstCodeBlockContaining(predecessor.getAddress(), monitor);
			if (predecessorBlock == null ||
				predecessorBlock.equals(current) ||
				!caller.getBody().contains(predecessorBlock.getMinAddress()) ||
				current.getNumSources(monitor) != 1) {
				break;
			}
			var sources = current.getSources(monitor);
			if (!sources.hasNext() ||
				!predecessorBlock.equals(sources.next().getSourceBlock())) {
				break;
			}
			result.add(predecessorBlock);
			current = predecessorBlock;
		}
		return result;
	}

	private static WordValue traceRegister(Program program, Function function,
			AddressSetView setupRegion, Instruction before, Register register, int depth,
			Set<String> visited) {
		if (register == null || depth > 16) {
			return WordValue.UNKNOWN;
		}
		String visit = before.getAddress() + ":" + register.getName();
		if (!visited.add(visit)) {
			return WordValue.UNKNOWN;
		}
		Instruction instruction = program.getListing().getInstructionBefore(before.getAddress());
		for (int scanned = 0; instruction != null && scanned < MAX_SETUP_SCAN_INSTRUCTIONS;
				scanned++, instruction =
					program.getListing().getInstructionBefore(instruction.getAddress())) {
			if (!function.getBody().contains(instruction.getAddress()) ||
				!setupRegion.contains(instruction.getAddress())) {
				break;
			}
			if (instruction.getFlowType().isJump()) {
				return uniqueSavedRegisterDefinition(program, function, before, register,
					depth, visited);
			}
			if (instruction.getFlowType().isCall()) {
				if (isTaskingCalleeSavedGeneralRegister(program, register)) {
					continue;
				}
				return WordValue.UNKNOWN;
			}
			if (!writesRegister(instruction, register)) {
				continue;
			}
			if (!instruction.getMnemonicString().equalsIgnoreCase("mov") ||
				instruction.getNumOperands() < 2 ||
				OperandType.isIndirect(instruction.getOperandType(0))) {
				return WordValue.definedUnknown(instruction.getAddress());
			}
			Register destination = operandRegister(instruction, 0);
			if (destination == null || !overlaps(register, destination)) {
				return WordValue.definedUnknown(instruction.getAddress());
			}
			int sourceType = instruction.getOperandType(1);
			Scalar scalar = instruction.getScalar(1);
			if (scalar != null && OperandType.isScalar(sourceType) &&
				!OperandType.isAddress(sourceType) && !OperandType.isIndirect(sourceType)) {
				return new WordValue(true, scalar.getUnsignedValue() & 0xffff,
					instruction.getAddress(), null, null, -1, null);
			}
			if (scalar != null && OperandType.isAddress(sourceType)) {
				Address loadAddress = resolveDirectDataAddress(program, function, setupRegion,
					instruction, scalar.getUnsignedValue(), depth + 1, visited);
				return new WordValue(true, scalar.getUnsignedValue() & 0xffff,
					instruction.getAddress(), loadAddress,
					null, -1, null);
			}
			Address directAddress = operandAddress(instruction, 1);
			if (directAddress != null) {
				Address loadAddress = resolveDirectDataAddress(program, function, setupRegion,
					instruction, directAddress.getOffset(), depth + 1, visited);
				return new WordValue(true, null, instruction.getAddress(), loadAddress,
					null, -1, null);
			}
			Scalar directScalar = operandScalar(instruction, 1);
			if (directScalar != null) {
				Address loadAddress = resolveDirectDataAddress(program, function, setupRegion,
					instruction, directScalar.getUnsignedValue(), depth + 1, visited);
				return new WordValue(true, null, instruction.getAddress(), loadAddress,
					null, -1, null);
			}
			Register source = operandRegister(instruction, 1);
			if (source != null && !OperandType.isIndirect(sourceType)) {
				WordValue traced = traceRegister(program, function, setupRegion, instruction,
					source, depth + 1, visited);
				return traced.defined() ? traced :
					WordValue.definedUnknown(instruction.getAddress());
			}
			return WordValue.definedUnknown(instruction.getAddress());
		}
		WordValue incoming = incomingParameterWord(program, function, register);
		return incoming.defined() ? incoming :
			uniqueSavedRegisterDefinition(program, function, before, register, depth, visited);
	}

	/**
	 * R6-R9 survive calls and are commonly assigned once in the prologue, then
	 * used after a conditional region.  A basic-block-local scan cannot see that
	 * origin.  Cross control flow only when the register has exactly one earlier
	 * definition in the entire function; multiple reaching definitions remain
	 * deliberately ambiguous.
	 */
	private static WordValue uniqueSavedRegisterDefinition(Program program,
			Function function, Instruction before, Register register, int depth,
			Set<String> visited) {
		if (depth > 16 || !isTaskingCalleeSavedGeneralRegister(program, register)) {
			return WordValue.UNKNOWN;
		}
		Instruction definition = null;
		for (Instruction instruction :
			program.getListing().getInstructions(function.getBody(), true)) {
			if (instruction.getAddress().compareTo(before.getAddress()) >= 0) {
				break;
			}
			if (!writesRegister(instruction, register)) {
				continue;
			}
			if (definition != null) {
				return WordValue.UNKNOWN;
			}
			definition = instruction;
		}
		if (definition == null ||
			!isStraightLineEntryPrefix(program, function, definition) ||
			!definition.getMnemonicString().equalsIgnoreCase("mov") ||
			definition.getNumOperands() < 2 ||
			OperandType.isIndirect(definition.getOperandType(0)) ||
			OperandType.isIndirect(definition.getOperandType(1))) {
			return WordValue.UNKNOWN;
		}
		Register source = operandRegister(definition, 1);
		if (source == null) {
			return WordValue.UNKNOWN;
		}
		WordValue value = traceRegister(program, function, function.getBody(),
			definition, source, depth + 1, new HashSet<>(visited));
		return value.defined() ? value : WordValue.UNKNOWN;
	}

	/**
	 * A unique textual definition is still unsafe when it lives on only one arm
	 * of a branch.  Trust the saved-register origin only when the definition is
	 * reached from the function entry through fall-through and call-return edges
	 * before the first jump.  TASKING parameter saves are emitted in precisely
	 * this prologue region.
	 */
	private static boolean isStraightLineEntryPrefix(Program program, Function function,
			Instruction definition) {
		Instruction instruction =
			program.getListing().getInstructionAt(function.getEntryPoint());
		for (int scanned = 0; instruction != null && scanned < MAX_SETUP_SCAN_INSTRUCTIONS;
				scanned++) {
			if (!function.getBody().contains(instruction.getAddress())) {
				return false;
			}
			if (instruction.getAddress().equals(definition.getAddress())) {
				return true;
			}
			if (instruction.getFlowType().isJump() ||
				instruction.getFlowType().isTerminal()) {
				return false;
			}
			Address fallThrough = instruction.getFallThrough();
			if (fallThrough == null) {
				return false;
			}
			instruction = program.getListing().getInstructionAt(fallThrough);
		}
		return false;
	}

	private static WordValue incomingParameterWord(Program program, Function function,
			Register register) {
		if (register == null) {
			return WordValue.UNKNOWN;
		}
		for (Parameter parameter : function.getParameters()) {
			DataType type = parameter.getFormalDataType();
			if (type == null || type.getLength() != 4 || !isPointer(type)) {
				continue;
			}
			var storageRegisters = parameter.getVariableStorage().getRegisters();
			if (storageRegisters == null || storageRegisters.size() != 2) {
				continue;
			}
			Integer firstRegister = null;
			for (Register storageRegister : storageRegisters) {
				Integer number = generalRegisterNumber(program, storageRegister);
				if (number == null) {
					firstRegister = null;
					break;
				}
				firstRegister = firstRegister == null ? number :
					Math.min(firstRegister, number);
			}
			if (firstRegister == null) {
				continue;
			}
			for (Register storageRegister : storageRegisters) {
				if (overlaps(register, storageRegister)) {
					Integer number = generalRegisterNumber(program, storageRegister);
					return new WordValue(true, null, function.getEntryPoint(), null,
						parameter.getOrdinal(), (number - firstRegister) * 2, type);
				}
			}
		}
		return WordValue.UNKNOWN;
	}

	private static boolean isPointer(DataType type) {
		DataType current = type;
		while (current instanceof TypeDef typeDef) {
			current = typeDef.getBaseDataType();
		}
		return current instanceof Pointer;
	}

	private static boolean isTaskingCalleeSavedGeneralRegister(Program program,
			Register register) {
		for (int number = 6; number <= 9; number++) {
			Register saved = program.getRegister("r" + number);
			if (overlaps(saved, register)) {
				return true;
			}
		}
		return false;
	}

	private static Integer generalRegisterNumber(Program program, Register register) {
		if (register == null) {
			return null;
		}
		for (int number = 0; number <= 15; number++) {
			Register general = program.getRegister("r" + number);
			if (overlaps(general, register)) {
				return number;
			}
		}
		return null;
	}

	private static Address resolveDirectDataAddress(Program program, Function function,
			AddressSetView setupRegion, Instruction instruction, long raw, int depth,
			Set<String> visited) {
		ProgramContext context = program.getProgramContext();
		Long extsEnabled = contextValue(context, "ExtsEn", instruction.getAddress());
		if (extsEnabled != null && extsEnabled != 0) {
			Long segment = effectiveOverride(program, function, setupRegion, instruction,
				"Exts", "ExtsReg", "ExtsRegMode", depth, visited);
			return segment == null ? null : toAddress(program,
				((segment & 0xffL) << 16) | (raw & 0xffffL));
		}
		Long extpEnabled = contextValue(context, "ExtpEn", instruction.getAddress());
		if (extpEnabled != null && extpEnabled != 0) {
			Long page = effectiveOverride(program, function, setupRegion, instruction,
				"Extp", "ExtpReg", "ExtpRegMode", depth, visited);
			return page == null ? null : toAddress(program,
				((page & 0x3ffL) << 14) | (raw & 0x3fffL));
		}

		int dppIndex = (int) ((raw >>> 14) & 3);
		Register dpp = program.getRegister("DPP" + dppIndex);
		WordValue traced = traceRegister(program, function, setupRegion, instruction,
			dpp, depth, new HashSet<>(visited));
		Long page = traced.constant();
		if (page == null) {
			if (C166PagedAddressEmitter.containingFunctionWrites(program,
				instruction.getAddress(), dpp)) {
				return null;
			}
			// Architectural reset state maps all four 16 KiB windows 1:1. DPP is
			// an ordinary register, so persisted ProgramContext is not evidence.
			page = (long)dppIndex;
		}
		return toAddress(program, ((page & 0x3ffL) << 14) | (raw & 0x3fffL));
	}

	private static Long effectiveOverride(Program program, Function function,
			AddressSetView setupRegion, Instruction instruction, String immediateName,
			String indexName, String modeName, int depth, Set<String> visited) {
		ProgramContext context = program.getProgramContext();
		Long registerMode = contextValue(context, modeName, instruction.getAddress());
		if (registerMode != null && registerMode != 0) {
			Long index = contextValue(context, indexName, instruction.getAddress());
			Register register = index == null ? null : program.getRegister("r" + (index & 0xf));
			return traceRegister(program, function, setupRegion, instruction, register,
				depth, new HashSet<>(visited)).constant();
		}
		return contextValue(context, immediateName, instruction.getAddress());
	}

	private static Long contextValue(ProgramContext context, String name, Address address) {
		Register register = context.getRegister(name);
		BigInteger value = register == null ? null : context.getValue(register, address, false);
		return value == null ? null : value.longValue();
	}

	private static Address toAddress(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private static void recoverPushedWords(Program program, Function function,
			AddressSetView setupRegion, Instruction call, Map<Integer, WordValue> words,
			Integer maximumWords) {
		Instruction instruction = program.getListing().getInstructionBefore(call.getAddress());
		int word = 0;
		int nestedWords = 0;
		for (int scanned = 0; instruction != null && scanned < MAX_SETUP_SCAN_INSTRUCTIONS;
				scanned++, instruction =
					program.getListing().getInstructionBefore(instruction.getAddress())) {
			if (maximumWords != null && word >= maximumWords) {
				break;
			}
			if (!function.getBody().contains(instruction.getAddress()) ||
				!setupRegion.contains(instruction.getAddress()) ||
				instruction.getFlowType().isJump()) {
				break;
			}
			Register stackPointer = program.getRegister("r0");
			Integer cleanupWords = stackCleanupWords(instruction);
			if (cleanupWords != null) {
				nestedWords += cleanupWords;
				continue;
			}
			if (!isStackPush(instruction) && writesRegister(instruction, stackPointer)) {
				break;
			}
			if (!isStackPush(instruction)) {
				continue;
			}
			if (nestedWords != 0) {
				nestedWords--;
				continue;
			}
			Register source = operandRegister(instruction, 1);
			WordValue value = source == null ? WordValue.definedUnknown(instruction.getAddress()) :
				traceRegister(program, function, setupRegion, instruction, source, 0,
					new HashSet<>());
			words.put(4 + word, value);
			word++;
		}
	}

	private static Integer stackCleanupWords(Instruction instruction) {
		if (!instruction.getMnemonicString().equalsIgnoreCase("add") ||
			instruction.getNumOperands() < 2) {
			return null;
		}
		Register destination = operandRegister(instruction, 0);
		Scalar bytes = instruction.getScalar(1);
		if (destination == null || !destination.getName().equalsIgnoreCase("r0") ||
			bytes == null || bytes.getUnsignedValue() == 0 ||
			(bytes.getUnsignedValue() & 1) != 0 || bytes.getUnsignedValue() > 0x100) {
			return null;
		}
		return (int)bytes.getUnsignedValue() / 2;
	}

	/**
	 * TASKING uses caller cleanup for user-stack arguments.  The immediate
	 * post-call ADD R0,#bytes is therefore an exact bound on argument pushes;
	 * older recovery could walk into saved registers below those arguments and
	 * mistake them for additional parameter words.
	 */
	private static Integer stackArgumentWords(Program program, Instruction call) {
		Instruction cleanup = program.getListing().getInstructionAfter(call.getAddress());
		if (cleanup == null || !cleanup.getMnemonicString().equalsIgnoreCase("add") ||
			cleanup.getNumOperands() < 2) {
			return 0;
		}
		Register destination = operandRegister(cleanup, 0);
		Scalar bytes = cleanup.getScalar(1);
		if (destination == null || !destination.getName().equalsIgnoreCase("r0") ||
			bytes == null || (bytes.getUnsignedValue() & 1) != 0) {
			return 0;
		}
		return (int) (bytes.getUnsignedValue() / 2);
	}

	private static boolean isStackPush(Instruction instruction) {
		if (!instruction.getMnemonicString().equalsIgnoreCase("mov") ||
			instruction.getNumOperands() < 2) {
			return false;
		}
		return instruction.getDefaultOperandRepresentation(0)
			.replace(" ", "").equalsIgnoreCase("[-r0]");
	}

	private static boolean writesRegister(Instruction instruction, Register expected) {
		for (Object result : instruction.getResultObjects()) {
			if (result instanceof Register actual && overlaps(expected, actual)) {
				return true;
			}
		}
		return false;
	}

	private static boolean overlaps(Register expected, Register actual) {
		return expected != null && actual != null &&
			(expected.contains(actual) || actual.contains(expected));
	}

	private static Register operandRegister(Instruction instruction, int operand) {
		for (Object object : instruction.getOpObjects(operand)) {
			if (object instanceof Register register) {
				return register;
			}
		}
		return null;
	}

	private static Address operandAddress(Instruction instruction, int operand) {
		for (Object object : instruction.getOpObjects(operand)) {
			if (object instanceof Address address) {
				return address;
			}
		}
		return null;
	}

	private static Scalar operandScalar(Instruction instruction, int operand) {
		for (Object object : instruction.getOpObjects(operand)) {
			if (object instanceof Scalar scalar) {
				return scalar;
			}
		}
		return null;
	}

	record WordValue(boolean defined, Long constant, Address source, Address loadAddress,
			Integer parameterOrdinal, int byteOffset, DataType originType) {
		private static final WordValue UNKNOWN =
			new WordValue(false, null, null, null, null, -1, null);

		private static WordValue definedUnknown(Address source) {
			return new WordValue(true, null, source, null, null, -1, null);
		}
	}

	record CallWords(Map<Integer, WordValue> words, boolean registerBankOccupied,
			int stackArgumentWords) {
	}
}
