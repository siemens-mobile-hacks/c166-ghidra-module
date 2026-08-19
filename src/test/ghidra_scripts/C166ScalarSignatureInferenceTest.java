// Headless regression test; run via tools/test-tasking-abi.sh.
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidrainfineon.C166ScalarSignaturePhase;

public class C166ScalarSignatureInferenceTest extends GhidraScript {

	private long nextFixture = 0x1e0000;

	@Override
	protected void run() throws Exception {
		check("tasking-classic-large".equals(
			currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()),
			"wrong compiler spec");

		Function wordReturn = fixture("word_return_from_r4", bytes(
			0xe6, 0xf4, 0x01, 0x00, // mov R4,#1
			0xdb, 0x00));
		wordReturn.setReturnType(Undefined.getUndefinedDataType(1), SourceType.ANALYSIS);
		Function byteReturn = fixture("byte_return_from_rl4", bytes(
			0xe1, 0x18,             // movb RL4,#1
			0xdb, 0x00));
		byteReturn.setReturnType(Undefined.getUndefinedDataType(2), SourceType.ANALYSIS);
		Function concreteReturn = fixture("concrete_return_is_preserved", bytes(
			0xe6, 0xf4, 0x01, 0x00,
			0xdb, 0x00));
		concreteReturn.setReturnType(
			new UnsignedCharDataType(currentProgram.getDataTypeManager()), SourceType.ANALYSIS);

		Function liveR12 = fixture("incoming_r12_is_parameter", bytes(
			0xf0, 0x8c,             // mov R8,R12
			0xe6, 0xf4, 0x00, 0x00,
			0xdb, 0x00));
		Function liveR12R13 = fixture("incoming_r12_r13_are_parameters", bytes(
			0xf0, 0x8c,             // mov R8,R12
			0xf0, 0x9d,             // mov R9,R13
			0xe6, 0xf4, 0x00, 0x00,
			0xdb, 0x00));
		setWords(liveR12R13, SourceType.ANALYSIS, "old0", "old1", "stale2", "stale3");

		Function overwrittenR12 = fixture("overwritten_r12_is_not_parameter", bytes(
			0xe6, 0xfc, 0x34, 0x12, // mov R12,#0x1234
			0xf0, 0x8c,             // mov R8,R12
			0xe6, 0xf4, 0x00, 0x00,
			0xdb, 0x00));
		Function helper = fixture("parameter_barrier_helper", bytes(0xdb, 0x00));
		Function readAfterCall = fixture("r12_read_after_call_is_not_incoming", concat(
			calls(helper), bytes(
				0xf0, 0x8c,
				0xe6, 0xf4, 0x00, 0x00,
				0xdb, 0x00)));
		Function setupOnlyTarget = fixture("caller_setup_alone_is_not_parameter_evidence",
			bytes(0xdb, 0x00));
		Function setupOnlyCaller = fixture("caller_setup_control", concat(bytes(
			0xe6, 0xfc, 0x34, 0x12,
			0xe6, 0xfd, 0x78, 0x56), calls(setupOnlyTarget), bytes(0xdb, 0x00)));

		Function existingPointer = fixture("analysis_pointer_layout_is_preserved", bytes(
			0xf0, 0x8c,
			0xe6, 0xf4, 0x00, 0x00,
			0xdb, 0x00));
		setAnalysisPointer(existingPointer, "value");
		Function userDefined = fixture("user_signature_is_preserved", bytes(
			0xf0, 0x8c,
			0xe6, 0xf4, 0x00, 0x00,
			0xdb, 0x00));
		setWords(userDefined, SourceType.USER_DEFINED, "value");
		Function stackSignature = fixture("stack_signature_is_preserved", bytes(
			0xf0, 0x8c,
			0xe6, 0xf4, 0x00, 0x00,
			0xdb, 0x00));
		setWords(stackSignature, SourceType.ANALYSIS,
			"r12", "r13", "r14", "r15", "stack");
		stackSignature.setReturnType(
			new UnsignedShortDataType(currentProgram.getDataTypeManager()), SourceType.ANALYSIS);

		String protectedSnapshot = snapshot(concreteReturn, userDefined, stackSignature);
		C166ScalarSignaturePhase phase = new C166ScalarSignaturePhase();
		MessageLog log = new MessageLog();
		check(phase.added(currentProgram, currentProgram.getMemory(), monitor, log),
			"scalar-signature analysis failed");
		check(!log.hasMessages(), "scalar-signature diagnostics leaked into Analysis Log: " + log);

		checkReturn(wordReturn, 2);
		checkReturn(byteReturn, 1);
		checkParameters(liveR12, "r12");
		checkParameters(liveR12R13, "r12", "r13");
		check("old0".equals(liveR12R13.getParameter(0).getName()) &&
			"old1".equals(liveR12R13.getParameter(1).getName()),
			"surviving ANALYSIS parameter names were not preserved");
		checkParameters(overwrittenR12);
		checkParameters(readAfterCall);
		checkParameters(setupOnlyTarget);
		check(existingPointer.getParameterCount() == 1 &&
			existingPointer.getParameter(0).getFormalDataType() instanceof Pointer &&
			"r13+r12".equals(describe(existingPointer.getParameter(0).getVariableStorage())),
			"existing four-byte pointer layout was split or truncated");
		check(protectedSnapshot.equals(snapshot(concreteReturn, userDefined, stackSignature)),
			"concrete return, USER_DEFINED signature, or stack signature changed");

		String firstSnapshot = snapshot(wordReturn, byteReturn, liveR12, liveR12R13,
			overwrittenR12, readAfterCall, setupOnlyTarget, existingPointer,
			concreteReturn, userDefined, stackSignature);
		MessageLog repeatedLog = new MessageLog();
		check(phase.added(currentProgram, currentProgram.getMemory(), monitor, repeatedLog),
			"repeated scalar-signature analysis failed");
		check(!repeatedLog.hasMessages(),
			"repeated scalar-signature diagnostics leaked into Analysis Log: " + repeatedLog);
		check(firstSnapshot.equals(snapshot(wordReturn, byteReturn, liveR12, liveR12R13,
			overwrittenR12, readAfterCall, setupOnlyTarget, existingPointer,
			concreteReturn, userDefined, stackSignature)),
			"scalar-signature inference is not idempotent");
		check(setupOnlyCaller != null, "missing caller-only evidence fixture");
		println("TASKING scalar-signature inference matrix passed.");
	}

	private Function fixture(String name, byte[] code) throws Exception {
		Address entry = toAddr(nextFixture);
		nextFixture += 0x100;
		MemoryBlock block = createMemoryBlock(name + "_bytes", entry, code, false);
		block.setExecute(true);
		check(disassemble(entry), "failed to disassemble " + name);
		Function function = createFunction(entry, name);
		check(function != null, "failed to create " + name);
		return function;
	}

	private void setWords(Function function, SourceType source, String... names)
			throws Exception {
		List<Variable> parameters = new ArrayList<>();
		for (String name : names) {
			parameters.add(new ParameterImpl(name,
				new UnsignedShortDataType(currentProgram.getDataTypeManager()), currentProgram));
		}
		function.updateFunction("__tasking_c166_classic", null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, source);
	}

	private void setAnalysisPointer(Function function, String name) throws Exception {
		Variable parameter = new ParameterImpl(name,
			new PointerDataType(VoidDataType.dataType,
				currentProgram.getDataTypeManager()), currentProgram);
		function.updateFunction("__tasking_c166_classic", null, List.of(parameter),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
	}

	private void checkReturn(Function function, int expectedLength) {
		check(function.getReturnType().getLength() == expectedLength &&
			Undefined.isUndefined(function.getReturnType()),
			function.getName() + ": unexpected return type " +
				function.getReturnType().getDisplayName());
		check((expectedLength == 1 ? "rl4" : "r4").equals(
			describe(function.getReturn().getVariableStorage())),
			function.getName() + ": unexpected return storage " +
				describe(function.getReturn().getVariableStorage()));
	}

	private void checkParameters(Function function, String... expectedStorage) {
		Parameter[] parameters = function.getParameters();
		check(parameters.length == expectedStorage.length,
			function.getName() + ": expected " + expectedStorage.length +
				" parameter(s), got " + parameters.length);
		for (int i = 0; i < parameters.length; i++) {
			check(expectedStorage[i].equals(describe(parameters[i].getVariableStorage())),
				function.getName() + "[" + i + "]: unexpected storage " +
					describe(parameters[i].getVariableStorage()));
			check(parameters[i].getFormalDataType().getLength() == 2,
				function.getName() + "[" + i + "]: unexpected type " +
					parameters[i].getFormalDataType().getDisplayName());
		}
	}

	private String snapshot(Function... functions) {
		StringBuilder result = new StringBuilder();
		for (Function function : functions) {
			result.append(function.getEntryPoint()).append(':')
				.append(function.getSignatureSource()).append(':')
				.append(function.getPrototypeString(true, true)).append(':')
				.append(describe(function.getReturn().getVariableStorage())).append('\n');
			for (Parameter parameter : function.getParameters()) {
				result.append("  ").append(parameter.getName()).append(':')
					.append(parameter.getSource()).append(':')
					.append(parameter.getFormalDataType().getPathName()).append(':')
					.append(describe(parameter.getVariableStorage())).append('\n');
			}
		}
		return result.toString();
	}

	private String describe(VariableStorage storage) {
		if (storage.isUnassignedStorage()) {
			return "unassigned";
		}
		if (storage.isStackStorage()) {
			return "Stack[0x" + Long.toHexString(storage.getStackOffset()) + "]:" +
				storage.size();
		}
		StringBuilder result = new StringBuilder();
		for (var register : storage.getRegisters()) {
			if (result.length() != 0) {
				result.append('+');
			}
			result.append(register.getName().toLowerCase());
		}
		return result.length() == 0 ? storage.toString() : result.toString();
	}

	private byte[] calls(Function target) {
		long address = target.getEntryPoint().getUnsignedOffset();
		return bytes(0xda, (int) (address >> 16), (int) address, (int) (address >> 8));
	}

	private byte[] concat(byte[]... parts) {
		int length = 0;
		for (byte[] part : parts) {
			length += part.length;
		}
		byte[] result = new byte[length];
		int offset = 0;
		for (byte[] part : parts) {
			System.arraycopy(part, 0, result, offset, part.length);
			offset += part.length;
		}
		return result;
	}

	private byte[] bytes(int... values) {
		byte[] result = new byte[values.length];
		for (int i = 0; i < values.length; i++) {
			result[i] = (byte) values[i];
		}
		return result;
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
