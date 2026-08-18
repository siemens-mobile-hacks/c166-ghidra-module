// Headless diagnostic for the real real firmware program Ghidra database.
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
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
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidrainfineon.C166CodePointerPhase;
import ghidrainfineon.C166FarPointerPhase;
import ghidrainfineon.C166TaskingRuntimeAnalyzer;

public class C166CodePointerHeadlessTest extends GhidraScript {

	private static final long[] TARGETS = {
		0x9b0678, 0x9bb936, 0x9bc42a, 0x29ffde, 0x25901a, 0x2590ce, 0x99b53a,
		0xc3ca42, 0xc3ca4a, 0x26cee4, 0x26cd1c, 0xc58cb6, 0x740b28, 0x9057dc
	};

	@Override
	protected void run() throws Exception {
		println("firmware HEADLESS language=" + currentProgram.getLanguageID() +
			" compiler=" + currentProgram.getCompilerSpec().getCompilerSpecID());
		ensureFunction(0x2590ce);
		seedScalarRegressionState();
		PointerCounts beforeCounts = pointerCounts();
		Set<String> beforeCodePointers = codePointerSlots();
		dump("BEFORE");

		AddressSet wholeProgram = new AddressSet(currentProgram.getMemory());
		MessageLog runtimeLog = new MessageLog();
		new C166TaskingRuntimeAnalyzer().added(currentProgram, wholeProgram, monitor, runtimeLog);
		println("firmware HEADLESS runtime-log=" + runtimeLog);
		MessageLog codeLog = new MessageLog();
		new C166CodePointerPhase().added(currentProgram, wholeProgram, monitor, codeLog);
		println("firmware HEADLESS code-log=" + codeLog);
		dump("AFTER_CODE");
		verifyScalarState("AFTER_CODE");
		checkFunctionPointers(0x740b28, 0, 1);
		checkFunctionPointers(0x9057dc, 1);
		PointerCounts afterCodeCounts = pointerCounts();
		Set<String> afterCodePointers = codePointerSlots();

		MessageLog farLog = new MessageLog();
		new C166FarPointerPhase().added(currentProgram, wholeProgram, monitor, farLog);
		println("firmware HEADLESS far-log=" + farLog);
		dump("AFTER_CODE_THEN_FAR");
		verifyFinalState();
		PointerCounts afterFarCounts = pointerCounts();
		Set<String> afterFarPointers = codePointerSlots();
		println("firmware HEADLESS pointer-counts before=" + beforeCounts +
			" after-code=" + afterCodeCounts + " after-far=" + afterFarCounts);
		println("firmware HEADLESS code-pointers removed-by-code=" +
			difference(beforeCodePointers, afterCodePointers));
		println("firmware HEADLESS code-pointers added-by-code=" +
			difference(afterCodePointers, beforeCodePointers));
		println("firmware HEADLESS code-pointers removed-by-far=" +
			difference(afterCodePointers, afterFarPointers));
		println("firmware HEADLESS code-pointers added-by-far=" +
			difference(afterFarPointers, afterCodePointers));
		println("firmware real-program code-pointer regression passed.");
	}

	private Set<String> codePointerSlots() {
		Set<String> result = new TreeSet<>();
		var functions = currentProgram.getFunctionManager().getFunctions(true);
		while (functions.hasNext()) {
			Function function = functions.next();
			for (Parameter parameter : function.getParameters()) {
				if (isFunctionPointer(parameter.getFormalDataType())) {
					result.add(function.getEntryPoint() + ":" +
						describe(parameter.getVariableStorage()));
				}
			}
		}
		return Set.copyOf(result);
	}

	private Set<String> difference(Set<String> first, Set<String> second) {
		Set<String> result = new TreeSet<>(first);
		result.removeAll(second);
		return result;
	}

	private PointerCounts pointerCounts() {
		int code = 0;
		int data = 0;
		int packedScalars = 0;
		var functions = currentProgram.getFunctionManager().getFunctions(true);
		while (functions.hasNext()) {
			for (Parameter parameter : functions.next().getParameters()) {
				DataType type = parameter.getFormalDataType();
				if (isFunctionPointer(type)) {
					code++;
				}
				else if (isPointer(type)) {
					data++;
				}
				else if (type.getLength() == 4 && Undefined.isUndefined(type)) {
					packedScalars++;
				}
			}
		}
		return new PointerCounts(code, data, packedScalars);
	}

	private record PointerCounts(int codePointers, int dataPointers, int packedScalars) {
	}

	private void seedScalarRegressionState() throws Exception {
		DataType fpointer = ensureCanonicalFunctionPointer();
		check(fpointer != null && isFunctionPointer(fpointer),
			"missing canonical fpointer type");
		DataType word = Undefined.getUndefinedDataType(2);
		DataType dataPointer = new PointerDataType(VoidDataType.dataType,
			currentProgram.getDataTypeManager());

		setAnalysisParameters(requiredFunction(0xc58cb6), fpointer);
		setAnalysisParameters(requiredFunction(0x26cd1c),
			word, word, fpointer, dataPointer, fpointer);
		setAnalysisParameters(requiredFunction(0x26cee4),
			word, word, word, word, fpointer, fpointer);

		// The current GUI database receives these prototypes from the runtime
		// archive.  The saved headless fixture predates that archive import, so
		// reproduce the same typed scalar sinks before testing stale-signature
		// migration.
		DataType uint16 = UnsignedShortDataType.dataType;
		DataType uint32 = UnsignedIntegerDataType.dataType;
		setParameters(requiredFunction(0xa417e8), SourceType.USER_DEFINED,
			uint16, uint32, uint16, dataPointer, dataPointer);
		setParameters(requiredFunction(0xa4172e), SourceType.USER_DEFINED,
			uint16, dataPointer, uint16, dataPointer);
	}

	private DataType ensureCanonicalFunctionPointer() {
		DataType existing = currentProgram.getDataTypeManager().getDataType("/fpointer");
		if (existing instanceof TypeDef && isFunctionPointer(existing)) {
			return existing;
		}
		DataType function = currentProgram.getDataTypeManager().getDataType("/c166/function");
		if (!(function instanceof FunctionDefinition)) {
			FunctionDefinitionDataType definition = new FunctionDefinitionDataType(
				new CategoryPath("/c166"), "function",
				currentProgram.getDataTypeManager());
			definition.setVarArgs(true);
			function = currentProgram.getDataTypeManager().resolve(definition,
				DataTypeConflictHandler.DEFAULT_HANDLER);
		}
		DataType pointer = new PointerDataType(function,
			currentProgram.getDataTypeManager());
		return currentProgram.getDataTypeManager().resolve(new TypedefDataType(
			CategoryPath.ROOT, "fpointer", pointer,
			currentProgram.getDataTypeManager()),
			DataTypeConflictHandler.DEFAULT_HANDLER);
	}

	private Function requiredFunction(long address) {
		Function function = getFunctionAt(toAddr(address));
		check(function != null, "missing function at " + Long.toHexString(address));
		return function;
	}

	private void setAnalysisParameters(Function function, DataType... types) throws Exception {
		setParameters(function, SourceType.ANALYSIS, types);
	}

	private void setParameters(Function function, SourceType source, DataType... types)
			throws Exception {
		List<Variable> parameters = new ArrayList<>();
		for (DataType type : types) {
			parameters.add(new ParameterImpl(null, type, currentProgram));
		}
		function.updateFunction("__tasking_c166_classic", null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, source);
	}

	private void verifyFinalState() throws Exception {
		Function dispatcher = getFunctionAt(toAddr(0xa26154));
		check(dispatcher != null, "missing firmware far-indirect dispatcher");
		check("call_far_indirect".equals(dispatcher.getCallFixup()),
			"firmware far-indirect dispatcher did not receive its call-fixup");
		check(dispatcher.getParameterCount() == 0,
			"firmware far-indirect dispatcher retained an inferred C signature");
		checkFunctionPointers(0x9b0678, 0, 1);
		checkFunctionPointers(0x9bb936, 0, 1);
		checkFunctionPointers(0x9bc42a, 2, 3);
		checkFunctionPointers(0x29ffde, 2);
		checkFunctionPointers(0x25901a, 1, 2);
		checkFunctionPointers(0x2590ce, 0, 1);
		checkFunctionPointers(0x740b28, 0, 1);
		checkFunctionPointers(0x9057dc, 1);
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
		verifyScalarState("FINAL");

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
		check(compactScalarCode.contains("FUN_99b53a(1,0x2c3,") ||
			compactScalarCode.contains("FUN_99b53a(1,0x2c3)"),
			"6f30aa did not retain separate flag and LGP-id arguments");
		check(!compactScalarCode.contains("0xb0c001") &&
			!compactScalarCode.contains("DAT_b0c001"),
			"6f30aa still contains the false PAGE:OFFSET pointer");

		Function resultCaller = getFunctionContaining(toAddr(0xc394dc));
		check(resultCaller != null, "missing caller containing c394dc");
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

	private void verifyScalarState(String stage) throws Exception {
		checkPackedScalar(0xc58cb6, 0, "r13+r12");
		checkPackedScalar(0x26cd1c, 2, "r15+r14");
		checkDataPointer(0x26cd1c, 3, "Stack[0x0]:4");
		checkPackedScalar(0x26cd1c, 4, "Stack[0x4]:4");
		Function recursiveScalar = getFunctionAt(toAddr(0x26cee4));
		check(recursiveScalar != null, stage + ": missing FUN_26cee4");
		check(recursiveScalar.getParameterCount() == 5,
			stage + ": FUN_26cee4 expected five ABI parameters, got " +
				recursiveScalar.getPrototypeString(true, true));
		checkScalarWord(0x26cee4, 0, "r12");
		checkScalarWord(0x26cee4, 1, "r13");
		checkScalarWord(0x26cee4, 2, "r14");
		checkPackedScalar(0x26cee4, 3, "Stack[0x0]:4");
		checkPackedScalar(0x26cee4, 4, "Stack[0x4]:4");
		String recursiveCode = decompile(recursiveScalar, stage);
		check(!recursiveCode.contains("fpointer") &&
			!recursiveCode.contains("(function *)"),
			stage + ": FUN_26cee4 retained false function-pointer arguments:\n" +
				recursiveCode);
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

	private void checkPackedScalar(long address, int index, String storage) {
		Function function = getFunctionAt(toAddr(address));
		check(function != null, "missing function at " + Long.toHexString(address));
		check(index < function.getParameterCount(),
			function.getName() + ": missing packed scalar parameter " + index);
		Parameter parameter = function.getParameter(index);
		check(storage.equals(describe(parameter.getVariableStorage())),
			function.getName() + "[" + index + "] expected " + storage + ", got " +
				describe(parameter.getVariableStorage()));
		check(parameter.getFormalDataType().getLength() == 4 &&
			Undefined.isUndefined(parameter.getFormalDataType()) &&
			!isPointer(parameter.getFormalDataType()),
			function.getName() + "[" + index + "] is not a packed scalar: " +
				parameter.getFormalDataType().getDisplayName());
	}

	private void checkDataPointer(long address, int index, String storage) {
		Function function = getFunctionAt(toAddr(address));
		check(function != null && index < function.getParameterCount(),
			"missing data-pointer parameter at " + Long.toHexString(address));
		Parameter parameter = function.getParameter(index);
		check(storage.equals(describe(parameter.getVariableStorage())) &&
			isPointer(parameter.getFormalDataType()) &&
			!isFunctionPointer(parameter.getFormalDataType()),
			function.getName() + "[" + index + "] is not the expected data pointer: " +
				parameter.getFormalDataType().getDisplayName() + " " +
				parameter.getVariableStorage());
	}

	private String describe(ghidra.program.model.listing.VariableStorage storage) {
		List<Register> registers = storage.getRegisters();
		if (registers != null && !registers.isEmpty()) {
			StringBuilder result = new StringBuilder();
			for (Register register : registers) {
				if (result.length() != 0) {
					result.append('+');
				}
				result.append(register.getName().toLowerCase());
			}
			return result.toString();
		}
		if (storage.isStackStorage()) {
			return "Stack[0x" + Long.toHexString(storage.getStackOffset()) + "]:" +
				storage.size();
		}
		return storage.toString();
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
				println("firmware HEADLESS " + phase + " missing function at " +
					Long.toHexString(offset));
				continue;
			}
			println("firmware HEADLESS " + phase + " function=" + function.getName() +
				" signatureSource=" + function.getSignatureSource() +
				" callingConvention=" + function.getCallingConventionName() +
				" signature=" + function.getSignature());
			for (int i = 0; i < function.getParameterCount(); i++) {
				Parameter parameter = function.getParameter(i);
				DataType type = parameter.getFormalDataType();
				println("firmware HEADLESS " + phase + " parameter=" + i +
					" source=" + parameter.getSource() + " storage=" +
					parameter.getVariableStorage() + " type=" + type.getDisplayName() +
					" class=" + type.getClass().getName());
			}
		}

		Function caller = getFunctionAt(toAddr(0x242066));
		if (caller == null) {
			println("firmware HEADLESS " + phase + " missing FUN_242066");
			return;
		}
		String c = decompile(caller, phase);
		println("firmware HEADLESS " + phase + " FUN_242066_BEGIN");
		println(c);
		println("firmware HEADLESS " + phase + " FUN_242066_END");

		Function scalarCaller = getFunctionAt(toAddr(0x6f2ea6));
		if (scalarCaller != null) {
			println("firmware HEADLESS " + phase + " FUN_6f2ea6_BEGIN");
			println(decompile(scalarCaller, phase));
			println("firmware HEADLESS " + phase + " FUN_6f2ea6_END");
		}

		Function resultCaller = getFunctionContaining(toAddr(0xc394dc));
		if (resultCaller != null) {
			println("firmware HEADLESS " + phase + " AT_SayResult_BEGIN");
			println(decompile(resultCaller, phase));
			println("firmware HEADLESS " + phase + " AT_SayResult_END");
		}
	}

	private String decompile(Function function, String phase) throws Exception {
		DecompInterface decompiler = new DecompInterface();
		try {
			decompiler.toggleCCode(true);
			decompiler.toggleSyntaxTree(true);
			if (!decompiler.openProgram(currentProgram)) {
				throw new AssertionError("firmware HEADLESS " + phase +
					" decompiler-open-failed=" + decompiler.getLastMessage());
			}
			DecompileResults results = decompiler.decompileFunction(function, 120, monitor);
			if (!results.decompileCompleted()) {
				throw new AssertionError("firmware HEADLESS " + phase + " decompile-failed=" +
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
			"firmware fixture entry is inside another function at " + Long.toHexString(address));
		if (getInstructionAt(toAddr(address)) == null) {
			check(disassemble(toAddr(address)),
				"failed to disassemble firmware fixture at " + Long.toHexString(address));
		}
		function = createFunction(toAddr(address), "FUN_" + Long.toHexString(address));
		check(function != null,
			"failed to create firmware fixture at " + Long.toHexString(address));
		return function;
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
