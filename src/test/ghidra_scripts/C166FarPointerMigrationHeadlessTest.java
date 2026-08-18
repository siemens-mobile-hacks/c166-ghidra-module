// Focused real-program regression for stale far-pointer inference in real firmware program.
import java.util.Set;

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
import ghidra.program.model.listing.Parameter;
import ghidrainfineon.C166FarPointerPhase;

public class C166FarPointerMigrationHeadlessTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		check("tasking-classic-large".equals(
			currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()),
			"firmware test is not using TASKING Classic large");

		Function staleTarget = requiredFunction(0xc393da);
		Function scalarWrapper = requiredFunction(0xc3ca42);
		Function scalarBody = requiredFunction(0xc3ca4a);
		Function extpCaller = requiredFunction(0xc35672);

		AddressSet scope = new AddressSet();
		for (Function seed : Set.of(staleTarget, scalarWrapper, scalarBody, extpCaller)) {
			scope.add(seed.getBody());
			for (Function caller : seed.getCallingFunctions(monitor)) {
				scope.add(caller.getBody());
			}
		}

		MessageLog log = new MessageLog();
		check(new C166FarPointerPhase().added(currentProgram, scope, monitor, log),
			"focused far-pointer analysis failed: " + log);

		for (Parameter parameter : staleTarget.getParameters()) {
			println("FUN_c393da parameter storage=" + parameter.getVariableStorage() +
				" type=" + parameter.getFormalDataType().getPathName() +
				" target=" + pointerTargetPath(parameter.getFormalDataType()));
			check(!isFunctionPointer(parameter.getFormalDataType()),
				"FUN_c393da retained an impossible generic code pointer");
		}
		for (Function scalar : Set.of(scalarWrapper, scalarBody)) {
			for (Parameter parameter : scalar.getParameters()) {
				check(!isPointer(parameter.getFormalDataType()),
					scalar.getName() + " retained a false pointer parameter");
			}
		}

		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		check(decompiler.openProgram(currentProgram), decompiler.getLastMessage());
		try {
			String extpCode = decompile(decompiler, extpCaller);
			// The local 32-bit scalar may retain packed PAGE:OFFSET spelling, but
			// every dereference must use the Large Model physical page shift.
			check(extpCode.contains("* 0x4000"),
				"FUN_c35672 lost PAGE while lowering register EXTP");
			Function scalarCaller = getFunctionContaining(toAddr(0xc394dc));
			check(scalarCaller != null, "missing caller containing c394dc");
			String scalarCode = decompile(decompiler, scalarCaller)
				.replaceAll("\\s+", "");
			check(scalarCode.contains("FUN_c3ca42(1,0xff)") ||
				scalarCode.contains("FUN_c3ca4a(1,0xff)"),
				"AT_SayResult no longer passes two scalar arguments");
		}
		finally {
			decompiler.dispose();
		}
		println("firmware stale far-pointer migration regression passed.");
	}

	private String decompile(DecompInterface decompiler, Function function) {
		DecompileResults result = decompiler.decompileFunction(function, 120, monitor);
		check(result.decompileCompleted(), "failed to decompile " + function.getName());
		String code = result.getDecompiledFunction().getC();
		println("=== " + function.getName() + " ===");
		println(code);
		return code;
	}

	private Function requiredFunction(long address) {
		Function function = getFunctionAt(toAddr(address));
		check(function != null, "missing function at " + Long.toHexString(address));
		return function;
	}

	private boolean isPointer(DataType type) {
		DataType current = type;
		while (current instanceof TypeDef typeDef) {
			current = typeDef.getBaseDataType();
		}
		return current instanceof Pointer;
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

	private String pointerTargetPath(DataType type) {
		DataType current = type;
		while (current instanceof TypeDef typeDef) {
			current = typeDef.getBaseDataType();
		}
		if (!(current instanceof Pointer pointer)) {
			return "<not-pointer>";
		}
		current = pointer.getDataType();
		while (current instanceof TypeDef typeDef) {
			current = typeDef.getBaseDataType();
		}
		return current.getPathName();
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
