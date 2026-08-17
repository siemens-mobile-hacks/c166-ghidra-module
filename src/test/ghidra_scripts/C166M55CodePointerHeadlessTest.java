// Headless diagnostic for the real M55_v91.bin Ghidra database.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidrainfineon.C166CodePointerAnalyzer;
import ghidrainfineon.C166FarPointerAnalyzer;
import ghidrainfineon.C166TaskingRuntimeAnalyzer;

public class C166M55CodePointerHeadlessTest extends GhidraScript {

	private static final long[] TARGETS = {
		0x9b0678, 0x9bb936, 0x9bc42a, 0x29ffde, 0x25901a, 0x2590ce, 0x99b53a,
		0xc3ca42, 0xc3ca4a
	};

	@Override
	protected void run() throws Exception {
		println("M55 HEADLESS language=" + currentProgram.getLanguageID() +
			" compiler=" + currentProgram.getCompilerSpec().getCompilerSpecID());
		ensureFunction(0x2590ce);
		dump("BEFORE");

		AddressSet wholeProgram = new AddressSet(currentProgram.getMemory());
		MessageLog runtimeLog = new MessageLog();
		new C166TaskingRuntimeAnalyzer().added(currentProgram, wholeProgram, monitor, runtimeLog);
		println("M55 HEADLESS runtime-log=" + runtimeLog);
		MessageLog codeLog = new MessageLog();
		new C166CodePointerAnalyzer().added(currentProgram, wholeProgram, monitor, codeLog);
		println("M55 HEADLESS code-log=" + codeLog);
		dump("AFTER_CODE");

		MessageLog farLog = new MessageLog();
		new C166FarPointerAnalyzer().added(currentProgram, wholeProgram, monitor, farLog);
		println("M55 HEADLESS far-log=" + farLog);
		dump("AFTER_CODE_THEN_FAR");
		verifyFinalState();
		println("M55 real-program code-pointer regression passed.");
	}

	private void verifyFinalState() throws Exception {
		Function dispatcher = getFunctionAt(toAddr(0xa26154));
		check(dispatcher != null, "missing M55 far-indirect dispatcher");
		check("call_far_indirect".equals(dispatcher.getCallFixup()),
			"M55 far-indirect dispatcher did not receive its call-fixup");
		check(dispatcher.getParameterCount() == 0,
			"M55 far-indirect dispatcher retained an inferred C signature");
		checkFunctionPointers(0x9b0678, 0, 1);
		checkFunctionPointers(0x9bb936, 0, 1);
		checkFunctionPointers(0x9bc42a, 2, 3);
		checkFunctionPointers(0x29ffde, 2);
		checkFunctionPointers(0x25901a, 1, 2);
		checkFunctionPointers(0x2590ce, 0, 1);
		checkScalarWord(0x99b53a, 0, "r12");
		checkScalarWord(0x99b53a, 1, "r13");
		checkScalarWord(0xc3ca42, 0, "r12");
		checkScalarWord(0xc3ca42, 1, "r13");
		checkScalarWord(0xc3ca4a, 0, "r12");
		checkScalarWord(0xc3ca4a, 1, "r13");
		Function impossibleCodePointer = getFunctionAt(toAddr(0xc393da));
		check(impossibleCodePointer != null, "missing FUN_c393da");
		for (Parameter parameter : impossibleCodePointer.getParameters()) {
			check(!isFunctionPointer(parameter.getFormalDataType()),
				"FUN_c393da retained an impossible generic code pointer");
		}

		Function caller = getFunctionAt(toAddr(0x242066));
		check(caller != null, "missing FUN_242066");
		String code = decompile(caller, "VERIFY");
		check(code.contains("FUN_253d0e"),
			"FUN_242066 lost the malloc code-pointer target");
		check(code.contains("FUN_253d7c"),
			"FUN_242066 lost the free code-pointer target");
		check(!code.contains("0x97d0e") && !code.contains("0x97d7c"),
			"FUN_242066 still contains PAGE:OFFSET callback addresses");

		Function singleCaller = getFunctionAt(toAddr(0x259214));
		check(singleCaller != null, "missing FUN_259214");
		String singleCallerCode = decompile(singleCaller, "VERIFY");
		check(singleCallerCode.contains("FUN_253d0e"),
			"FUN_259214 lost the malloc code-pointer target");
		check(singleCallerCode.contains("FUN_253d7c"),
			"FUN_259214 lost the free code-pointer target");
		check(!singleCallerCode.contains("0x97d0e") &&
			!singleCallerCode.contains("0x97d7c"),
			"FUN_259214 still contains PAGE:OFFSET callback addresses");

		Function scalarCaller = getFunctionAt(toAddr(0x6f2ea6));
		check(scalarCaller != null, "missing caller containing 6f30aa");
		String scalarCallerCode = decompile(scalarCaller, "VERIFY");
		String compactScalarCode = scalarCallerCode.replaceAll("\\s+", "");
		check(compactScalarCode.contains("FUN_99b53a(1,0x2c3)"),
			"6f30aa did not retain separate flag and LGP-id arguments");
		check(!compactScalarCode.contains("0xb0c001") &&
			!compactScalarCode.contains("DAT_b0c001"),
			"6f30aa still contains the false PAGE:OFFSET pointer");

		Function resultCaller = ensureFunction(0xc394dc);
		String compactResultCode = decompile(resultCaller, "VERIFY").replaceAll("\\s+", "");
		check(compactResultCode.contains("FUN_c3ca42(1,0xff)") ||
			compactResultCode.contains("FUN_c3ca4a(1,0xff)"),
			"c394dc did not retain separate result and message-id arguments");
		check(!compactResultCode.contains("0x3fc001") &&
			!compactResultCode.contains("DAT_3fc001"),
			"c394dc still contains the false PAGE:OFFSET pointer");

		Function dispatcherCaller = getFunctionAt(toAddr(0x2eb0e8));
		check(dispatcherCaller != null, "missing FUN_2eb0e8");
		String dispatcherCode = decompile(dispatcherCaller, "VERIFY");
		check(!dispatcherCode.contains("FUN_a26154(") &&
			dispatcherCode.contains("(*(code *)"),
			"FUN_2eb0e8 still exposes the far-indirect dispatcher as split arguments:\n" +
				dispatcherCode);

		Function extpCaller = getFunctionAt(toAddr(0xc35672));
		check(extpCaller != null, "missing FUN_c35672");
		String extpCode = decompile(extpCaller, "VERIFY");
		check(extpCode.contains("* 0x4000"),
			"FUN_c35672 lost PAGE while lowering register EXTP");
	}

	private void checkScalarWord(long address, int index, String registerName) {
		Function function = getFunctionAt(toAddr(address));
		check(function != null, "missing function at " + Long.toHexString(address));
		if (function.getParameterCount() == 0 &&
			function.getSignatureSource() == ghidra.program.model.symbol.SourceType.DEFAULT) {
			return;
		}
		check(index < function.getParameterCount(),
			function.getName() + ": missing parameter " + index);
		Parameter parameter = function.getParameter(index);
		check(!isPointer(parameter.getFormalDataType()), function.getName() + "[" + index +
			"] is still a pointer: " + parameter.getFormalDataType().getDisplayName());
		check(parameter.getVariableStorage().size() == 2, function.getName() + "[" + index +
			"] is not one word: " + parameter.getVariableStorage());
		var registers = parameter.getVariableStorage().getRegisters();
		check(registers != null && registers.size() == 1,
			function.getName() + "[" + index + "] has unexpected storage: " +
				parameter.getVariableStorage());
		Register register = registers.get(0);
		check(registerName.equalsIgnoreCase(register.getName()), function.getName() + "[" +
			index + "] expected " + registerName + ", got " + register.getName());
	}

	private boolean isPointer(DataType type) {
		DataType current = type;
		while (current instanceof TypeDef typeDef) {
			current = typeDef.getBaseDataType();
		}
		return current instanceof Pointer;
	}

	private void checkFunctionPointers(long address, int... indexes) {
		Function function = getFunctionAt(toAddr(address));
		check(function != null, "missing function at " + Long.toHexString(address));
		for (int index : indexes) {
			check(index < function.getParameterCount(),
				function.getName() + ": missing parameter " + index);
			DataType type = function.getParameter(index).getFormalDataType();
			check(isFunctionPointer(type), function.getName() + "[" + index +
				"] is not a function pointer: " + type.getDisplayName());
			check(type instanceof TypeDef typeDef && "fpointer".equals(typeDef.getName()),
				function.getName() + "[" + index + "] is not fpointer: " +
					type.getDisplayName());
		}
	}

	private boolean isFunctionPointer(DataType type) {
		DataType current = type;
		while (current instanceof TypeDef typeDef) {
			current = typeDef.getBaseDataType();
		}
		if (!(current instanceof Pointer pointer)) {
			return false;
		}
		current = pointer.getDataType();
		while (current instanceof TypeDef typeDef) {
			current = typeDef.getBaseDataType();
		}
		return current instanceof FunctionDefinition;
	}

	private void dump(String phase) throws Exception {
		for (long offset : TARGETS) {
			Function function = getFunctionAt(toAddr(offset));
			if (function == null) {
				println("M55 HEADLESS " + phase + " missing function at " +
					Long.toHexString(offset));
				continue;
			}
			println("M55 HEADLESS " + phase + " function=" + function.getName() +
				" signatureSource=" + function.getSignatureSource() +
				" callingConvention=" + function.getCallingConventionName() +
				" signature=" + function.getSignature());
			for (int i = 0; i < function.getParameterCount(); i++) {
				Parameter parameter = function.getParameter(i);
				DataType type = parameter.getFormalDataType();
				println("M55 HEADLESS " + phase + " parameter=" + i +
					" source=" + parameter.getSource() + " storage=" +
					parameter.getVariableStorage() + " type=" + type.getDisplayName() +
					" class=" + type.getClass().getName());
			}
		}

		Function caller = getFunctionAt(toAddr(0x242066));
		if (caller == null) {
			println("M55 HEADLESS " + phase + " missing FUN_242066");
			return;
		}
		String c = decompile(caller, phase);
		println("M55 HEADLESS " + phase + " FUN_242066_BEGIN");
		println(c);
		println("M55 HEADLESS " + phase + " FUN_242066_END");

		Function scalarCaller = getFunctionAt(toAddr(0x6f2ea6));
		if (scalarCaller != null) {
			println("M55 HEADLESS " + phase + " FUN_6f2ea6_BEGIN");
			println(decompile(scalarCaller, phase));
			println("M55 HEADLESS " + phase + " FUN_6f2ea6_END");
		}

		Function resultCaller = ensureFunction(0xc394dc);
		if (resultCaller != null) {
			println("M55 HEADLESS " + phase + " AT_SayResult_BEGIN");
			println(decompile(resultCaller, phase));
			println("M55 HEADLESS " + phase + " AT_SayResult_END");
		}
	}

	private String decompile(Function function, String phase) throws Exception {
		DecompInterface decompiler = new DecompInterface();
		try {
			decompiler.toggleCCode(true);
			decompiler.toggleSyntaxTree(true);
			if (!decompiler.openProgram(currentProgram)) {
				throw new AssertionError("M55 HEADLESS " + phase +
					" decompiler-open-failed=" + decompiler.getLastMessage());
			}
			DecompileResults results = decompiler.decompileFunction(function, 120, monitor);
			if (!results.decompileCompleted()) {
				throw new AssertionError("M55 HEADLESS " + phase + " decompile-failed=" +
					results.getErrorMessage());
			}
			return results.getDecompiledFunction().getC();
		}
		finally {
			decompiler.dispose();
		}
	}

	private Function ensureFunction(long address) throws Exception {
		Function function = getFunctionAt(toAddr(address));
		if (function != null) {
			return function;
		}
		check(getFunctionContaining(toAddr(address)) == null,
			"M55 fixture entry is inside another function at " + Long.toHexString(address));
		if (getInstructionAt(toAddr(address)) == null) {
			check(disassemble(toAddr(address)),
				"failed to disassemble M55 fixture at " + Long.toHexString(address));
		}
		function = createFunction(toAddr(address), "FUN_" + Long.toHexString(address));
		check(function != null,
			"failed to create M55 fixture at " + Long.toHexString(address));
		return function;
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
