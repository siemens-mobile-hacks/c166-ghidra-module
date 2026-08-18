// Real M55 regression for TASKING Large far-data-pointer returns in R5:R4.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Function;
import ghidrainfineon.C166CodePointerPhase;
import ghidrainfineon.C166FarPointerPhase;
import ghidrainfineon.C166PointerReturnPhase;
import ghidrainfineon.C166TaskingRuntimeAnalyzer;

public class C166M55ReturnPointerHeadlessTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		check("tasking-classic-large".equals(
			currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()),
			"M55 test is not using TASKING Classic large");
		boolean hiddenFunctionsMissing = getFunctionAt(toAddr(0x2590ce)) == null ||
			getFunctionAt(toAddr(0x259214)) == null ||
			getFunctionAt(toAddr(0x25911a)) == null ||
			getFunctionAt(toAddr(0x2592e6)) == null ||
			getFunctionAt(toAddr(0x259372)) == null;
		ensureFunction(0x2590ce);
		Function swTeamCaller = ensureFunction(0x259214);
		Function swTeamSetup = ensureFunction(0x25911a);
		Function swTeamPopulate = ensureFunction(0x2592e6);
		Function swTeamFinish = ensureFunction(0x259372);

		boolean checkOnly = getScriptArgs().length == 1 &&
			"check-only".equals(getScriptArgs()[0]);
		if (!checkOnly) {
			AddressSet wholeProgram = new AddressSet(currentProgram.getMemory());
			MessageLog runtimeLog = new MessageLog();
			check(new C166TaskingRuntimeAnalyzer().added(currentProgram, wholeProgram, monitor,
				runtimeLog), "runtime analysis failed: " + runtimeLog);
			MessageLog codeLog = new MessageLog();
			check(new C166CodePointerPhase().added(currentProgram, wholeProgram, monitor,
				codeLog), "code-pointer analysis failed: " + codeLog);
			MessageLog farLog = new MessageLog();
			check(new C166FarPointerPhase().added(currentProgram, wholeProgram, monitor,
				farLog), "far-data-pointer analysis failed: " + farLog);
			MessageLog repeatedCodeLog = new MessageLog();
			check(new C166CodePointerPhase().added(currentProgram, wholeProgram, monitor,
				repeatedCodeLog),
				"repeated code-pointer analysis failed: " + repeatedCodeLog);
			MessageLog returnLog = new MessageLog();
			check(new C166PointerReturnPhase().added(currentProgram, wholeProgram, monitor,
				returnLog), "return-pointer analysis failed: " + returnLog);
		}
		else if (hiddenFunctionsMissing) {
			AddressSet hiddenScope = new AddressSet(swTeamCaller.getBody());
			hiddenScope.add(swTeamSetup.getBody());
			hiddenScope.add(swTeamPopulate.getBody());
			hiddenScope.add(swTeamFinish.getBody());
			MessageLog farLog = new MessageLog();
			check(new C166FarPointerPhase().added(currentProgram, hiddenScope, monitor,
				farLog), "focused hidden-function far analysis failed: " + farLog);
			MessageLog codeLog = new MessageLog();
			check(new C166CodePointerPhase().added(currentProgram, hiddenScope, monitor,
				codeLog), "focused hidden-function code analysis failed: " + codeLog);
			MessageLog returnLog = new MessageLog();
			check(new C166PointerReturnPhase().added(currentProgram,
				swTeamCaller.getBody(), monitor, returnLog),
				"focused hidden-function return analysis failed: " + returnLog);
		}

		checkDataPointerReturn(0x9bb936);
		checkDataPointerReturn(0x9b0678);
		checkDataPointerReturn(0x2590ce);
		checkAllocatorWrapperSignature();

		String mainCode = decompile(requiredFunction(0x242066));
		check(!mainCode.contains("(fpointer)FUN_9bb936") &&
			!mainCode.contains("(void *)FUN_9bb936") &&
			!mainCode.contains("(void *)FUN_9b0678"),
			"FUN_242066 still casts split returns instead of using R5:R4 pointers:\n" +
				mainCode);
		String swTeamCode = decompile(swTeamCaller);
		check(!swTeamCode.contains("(void *)FUN_2590ce") &&
			!swTeamCode.contains("(void *)func_0x2590ce"),
			"FUN_259214 still casts the split FUN_2590ce return:\n" + swTeamCode);
		println("M55 TASKING far-pointer return regression passed.");
	}

	private void checkAllocatorWrapperSignature() {
		Function function = requiredFunction(0x9bc42a);
		check(function.getParameterCount() == 4,
			function.getName() + " parameter count is " + function.getParameterCount());
		check(isDataPointer(function.getParameter(0).getFormalDataType()) &&
			isDataPointer(function.getParameter(1).getFormalDataType()),
			function.getName() + " object parameters are not data pointers: " +
			function.getPrototypeString(true, true));
		check(isFunctionPointer(function.getParameter(2).getFormalDataType()) &&
			isFunctionPointer(function.getParameter(3).getFormalDataType()),
			function.getName() + " callbacks are not function pointers: " +
			function.getPrototypeString(true, true));
	}

	private void checkDataPointerReturn(long address) {
		Function function = requiredFunction(address);
		DataType type = function.getReturnType();
		check(isDataPointer(type), function.getName() + " return is not a data pointer: " +
			type.getDisplayName());
		String storage = function.getReturn().getVariableStorage().toString().toLowerCase();
		check(storage.contains("r5") && storage.contains("r4") &&
			function.getReturn().getVariableStorage().size() == 4,
			function.getName() + " return storage is not R5:R4: " + storage);
	}

	private boolean isDataPointer(DataType type) {
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
		return !(current instanceof FunctionDefinition);
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

	private String decompile(Function function) {
		DecompInterface decompiler = new DecompInterface();
		try {
			decompiler.toggleCCode(true);
			decompiler.toggleSyntaxTree(true);
			check(decompiler.openProgram(currentProgram), decompiler.getLastMessage());
			DecompileResults result = decompiler.decompileFunction(function, 120, monitor);
			check(result.decompileCompleted(), "failed to decompile " + function.getName());
			return result.getDecompiledFunction().getC();
		}
		finally {
			decompiler.dispose();
		}
	}

	private Function requiredFunction(long address) {
		Function function = getFunctionAt(toAddr(address));
		check(function != null, "missing function at " + Long.toHexString(address));
		return function;
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
