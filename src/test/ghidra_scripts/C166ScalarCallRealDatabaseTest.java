// Focused saved-program regression for the five-argument TASKING declaration whose
// R12:R13 pointer and second stack pointer were previously lost while R13:R14
// was incorrectly collapsed into a pointer.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidrainfineon.C166FarPointerPhase;
import ghidrainfineon.C166PointerReturnPhase;

public class C166ScalarCallRealDatabaseTest extends GhidraScript {

	private static final long TARGET = 0xa060d6L;
	private static final long CALLER = 0x9e79acL;

	@Override
	protected void run() throws Exception {
		check("tasking-classic-large".equals(
			currentProgram.getLanguage().getProperty("c166.abi")),
			"real-program regression is not using TASKING Classic Large");
		Function target = requiredFunction(TARGET);
		Function caller = requiredFunction(CALLER);

		AddressSet scope = new AddressSet(target.getBody());
		scope.add(caller.getBody());
		MessageLog log = new MessageLog();
		check(new C166FarPointerPhase().added(currentProgram, scope, monitor, log),
			"focused far-pointer repair failed: " + log);
		MessageLog returnLog = new MessageLog();
		check(new C166PointerReturnPhase().added(currentProgram, scope, monitor,
			returnLog), "focused pointer-return repair failed: " + returnLog);

		Parameter[] parameters = target.getParameters();
		check(parameters.length == 5,
			"FUN_a060d6 expected five arguments, got " + parameters.length);
		check(isPointer(parameters[0]), "target is not a far data pointer");
		check(!isPointer(parameters[1]) && !isPointer(parameters[2]),
			"msg/submsg were incorrectly joined into a pointer");
		check(isPointer(parameters[3]) && isPointer(parameters[4]),
			"one or both stack payload pointers were not recovered");
		checkStorage(parameters[0], "r13+r12");
		checkStorage(parameters[1], "r14");
		checkStorage(parameters[2], "r15");
		checkStorage(parameters[3], "Stack[0x0]:4");
		checkStorage(parameters[4], "Stack[0x4]:4");
		check(isPointer(target.getReturnType()),
			"FUN_a060d6 return is not a far data pointer: " +
				target.getReturnType().getDisplayName());
		checkStorage(target.getReturn().getVariableStorage().toString(), "r5+r4",
			"FUN_a060d6 return");

		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		check(decompiler.openProgram(currentProgram), decompiler.getLastMessage());
		try {
			DecompileResults results = decompiler.decompileFunction(caller, 120, monitor);
			check(results.decompileCompleted(), results.getErrorMessage());
			String code = results.getDecompiledFunction().getC();
			println(code);
			String compact = code.replaceAll("\\s+", "");
			check(!compact.contains("&DAT_014011"),
				"R13:R14 is still incorrectly collapsed into a pointer:\n" + code);
			check(compact.matches("(?s).*FUN_a060d6\\([^,]+,5,2,pvVar7,[^)]+\\);.*"),
				"FUN_a060d6 arguments are still missing or shifted:\n" + code);
		}
		finally {
			decompiler.dispose();
		}

		println("Saved-program five-argument call regression passed for FUN_a060d6.");
	}

	private Function requiredFunction(long address) {
		Function function = getFunctionAt(toAddr(address));
		check(function != null, "missing function at " + Long.toHexString(address));
		return function;
	}

	private boolean isPointer(Parameter parameter) {
		return isPointer(parameter.getFormalDataType());
	}

	private boolean isPointer(DataType dataType) {
		var type = dataType;
		while (type instanceof TypeDef typeDef) {
			type = typeDef.getBaseDataType();
		}
		return type instanceof Pointer;
	}

	private void checkStorage(Parameter parameter, String expected) {
		checkStorage(parameter.getVariableStorage().toString(), expected,
			parameter.getName());
	}

	private void checkStorage(String actual, String expected, String name) {
		String normalized = actual.replace(":2", "").replace(',', '+');
		check(expected.equals(normalized),
			name + ": expected " + expected + ", got " + actual);
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
