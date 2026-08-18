package ghidrainfineon;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
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

	private C166TaskingCallArguments() {
	}

	static CallWords recover(Program program, Function caller, Instruction call,
			BasicBlockModel blocks, TaskMonitor monitor) throws CancelledException {
		Map<Integer, WordValue> words = new HashMap<>();
		CodeBlock setupBlock = blocks.getFirstCodeBlockContaining(call.getAddress(), monitor);
		AddressSetView setupRegion = setupBlock == null ? caller.getBody() : setupBlock;
		boolean registerBankOccupied = true;
		for (int slot = 0; slot < 4; slot++) {
			Register register = program.getRegister("r" + (FIRST_ARGUMENT_REGISTER + slot));
			WordValue value = traceRegister(program, caller, setupRegion, call, register, 0,
				new HashSet<>());
			words.put(slot, value);
			registerBankOccupied &= value.defined();
		}
		if (registerBankOccupied) {
			recoverPushedWords(program, caller, setupRegion, call, words,
				stackArgumentWords(program, call));
		}
		return new CallWords(Map.copyOf(words), registerBankOccupied);
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
			if (instruction.getFlowType().isCall() || instruction.getFlowType().isJump()) {
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
					instruction.getAddress(), null);
			}
			if (scalar != null && OperandType.isAddress(sourceType)) {
				Address loadAddress = resolveDirectDataAddress(program, function, setupRegion,
					instruction, scalar.getUnsignedValue(), depth + 1, visited);
				return new WordValue(true, null, instruction.getAddress(), loadAddress);
			}
			Address directAddress = operandAddress(instruction, 1);
			if (directAddress != null) {
				Address loadAddress = resolveDirectDataAddress(program, function, setupRegion,
					instruction, directAddress.getOffset(), depth + 1, visited);
				return new WordValue(true, null, instruction.getAddress(), loadAddress);
			}
			Scalar directScalar = operandScalar(instruction, 1);
			if (directScalar != null) {
				Address loadAddress = resolveDirectDataAddress(program, function, setupRegion,
					instruction, directScalar.getUnsignedValue(), depth + 1, visited);
				return new WordValue(true, null, instruction.getAddress(), loadAddress);
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
		return WordValue.UNKNOWN;
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
		for (int scanned = 0; instruction != null && scanned < MAX_SETUP_SCAN_INSTRUCTIONS;
				scanned++, instruction =
					program.getListing().getInstructionBefore(instruction.getAddress())) {
			if (maximumWords != null && word >= maximumWords) {
				break;
			}
			if (!function.getBody().contains(instruction.getAddress()) ||
				!setupRegion.contains(instruction.getAddress()) ||
				instruction.getFlowType().isCall() || instruction.getFlowType().isJump()) {
				break;
			}
			Register stackPointer = program.getRegister("r0");
			if (!isStackPush(instruction) && writesRegister(instruction, stackPointer)) {
				break;
			}
			if (!isStackPush(instruction)) {
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

	record WordValue(boolean defined, Long constant, Address source, Address loadAddress) {
		private static final WordValue UNKNOWN = new WordValue(false, null, null, null);

		private static WordValue definedUnknown(Address source) {
			return new WordValue(true, null, source, null);
		}
	}

	record CallWords(Map<Integer, WordValue> words, boolean registerBankOccupied) {
	}
}
