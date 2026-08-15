package ghidrainfineon;

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
			recoverPushedWords(program, caller, setupRegion, call, words);
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
				return WordValue.DEFINED_UNKNOWN;
			}
			Register destination = operandRegister(instruction, 0);
			if (destination == null || !overlaps(register, destination)) {
				return WordValue.DEFINED_UNKNOWN;
			}
			int sourceType = instruction.getOperandType(1);
			Scalar scalar = instruction.getScalar(1);
			if (scalar != null && OperandType.isScalar(sourceType) &&
				!OperandType.isAddress(sourceType) && !OperandType.isIndirect(sourceType)) {
				return new WordValue(true, scalar.getUnsignedValue() & 0xffff,
					instruction.getAddress());
			}
			Register source = operandRegister(instruction, 1);
			if (source != null && !OperandType.isIndirect(sourceType)) {
				WordValue traced = traceRegister(program, function, setupRegion, instruction,
					source, depth + 1, visited);
				return traced.constant() == null ? WordValue.DEFINED_UNKNOWN : traced;
			}
			return WordValue.DEFINED_UNKNOWN;
		}
		return WordValue.UNKNOWN;
	}

	private static void recoverPushedWords(Program program, Function function,
			AddressSetView setupRegion, Instruction call, Map<Integer, WordValue> words) {
		Instruction instruction = program.getListing().getInstructionBefore(call.getAddress());
		int word = 0;
		for (int scanned = 0; instruction != null && scanned < MAX_SETUP_SCAN_INSTRUCTIONS;
				scanned++, instruction =
					program.getListing().getInstructionBefore(instruction.getAddress())) {
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
			WordValue value = source == null ? WordValue.DEFINED_UNKNOWN :
				traceRegister(program, function, setupRegion, instruction, source, 0,
					new HashSet<>());
			words.put(4 + word, value);
			word++;
		}
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

	record WordValue(boolean defined, Long constant, Address source) {
		private static final WordValue UNKNOWN = new WordValue(false, null, null);
		private static final WordValue DEFINED_UNKNOWN = new WordValue(true, null, null);
	}

	record CallWords(Map<Integer, WordValue> words, boolean registerBankOccupied) {
	}
}
