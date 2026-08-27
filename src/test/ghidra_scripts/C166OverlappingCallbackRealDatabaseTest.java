// Focused saved-program regression for FUN_2e5364.  R14 belongs to the real
// R15:R14 SEGMENT:OFFSET callback while the stale signature joined it with
// R13 as a PAGE:OFFSET data pointer to 0xcf867c.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidrainfineon.C166CodePointerPhase;
import ghidrainfineon.C166FarPointerPhase;
import ghidrainfineon.C166TaskingRuntimeAnalyzer;

public class C166OverlappingCallbackRealDatabaseTest extends GhidraScript {

	private static final long TARGET = 0x99b6c8L;
	private static final long WRAPPER = 0x2e5364L;
	private static final long CALLBACK = 0x2e533eL;
	private static final long FALSE_DATA_TARGET = 0xcf867cL;

	@Override
	protected void run() throws Exception {
		check("tasking-classic-large".equals(
			currentProgram.getLanguage().getProperty("c166.abi")),
			"real-program regression is not using TASKING Classic Large");
		Function target = requiredFunction(TARGET);
		Function wrapper = requiredFunction(WRAPPER);
		boolean callbackWasMissing = getFunctionAt(toAddr(CALLBACK)) == null;

		AddressSet scope = new AddressSet(target.getBody());
		scope.add(wrapper.getBody());
		ReferenceIterator references =
			currentProgram.getReferenceManager().getReferencesTo(toAddr(TARGET));
		while (references.hasNext()) {
			Function caller = getFunctionContaining(references.next().getFromAddress());
			if (caller != null) {
				scope.add(caller.getBody());
			}
		}

		MessageLog runtimeLog = new MessageLog();
		check(new C166TaskingRuntimeAnalyzer().added(currentProgram, scope, monitor,
			runtimeLog), "focused runtime-helper repair failed: " + runtimeLog);
		check(!"call_far_indirect".equals(target.getCallFixup()),
			"FUN_99b6c8 retained a stale far-dispatcher call-fixup");
		MessageLog codeLog = new MessageLog();
		check(new C166CodePointerPhase().added(currentProgram, scope, monitor, codeLog),
			"focused code-pointer repair failed: " + codeLog);
		check(getFunctionAt(toAddr(CALLBACK)) != null,
			"code-pointer phase did not retain callback at " + toAddr(CALLBACK));
		check(hasReference(toAddr(WRAPPER + 10), toAddr(CALLBACK)),
			"code-pointer phase did not add callback PARAM reference");
		MessageLog farLog = new MessageLog();
		check(new C166FarPointerPhase().added(currentProgram, scope, monitor, farLog),
			"focused far-pointer reconciliation failed: " + farLog);

		Function callback = getFunctionAt(toAddr(CALLBACK));
		check(callback != null, "missing callback function at " + toAddr(CALLBACK));
		Parameter[] parameters = target.getParameters();
		check(parameters.length == 3,
			"FUN_99b6c8 expected three arguments, got " + parameters.length);
		check(!isPointer(parameters[0].getFormalDataType()) &&
			!isPointer(parameters[1].getFormalDataType()),
			"R12 or R13 was incorrectly retained as a pointer");
		check(isFunctionPointer(parameters[2].getFormalDataType()),
			"R15:R14 is not a function pointer: " +
				parameters[2].getFormalDataType().getDisplayName());
		checkStorage(parameters[0], "r12");
		checkStorage(parameters[1], "r13");
		checkStorage(parameters[2], "r15+r14");

		check(hasReference(toAddr(WRAPPER + 10), toAddr(CALLBACK)),
			"R15 setup has no callback PARAM reference");
		check(!hasReference(toAddr(WRAPPER + 2), toAddr(FALSE_DATA_TARGET)),
			"stale R14:R13 PAGE:OFFSET reference to 0xcf867c remains");

		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		check(decompiler.openProgram(currentProgram), decompiler.getLastMessage());
		try {
			DecompileResults results = decompiler.decompileFunction(wrapper, 120, monitor);
			check(results.decompileCompleted(), results.getErrorMessage());
			String code = results.getDecompiledFunction().getC();
			println(code);
			String compact = code.replaceAll("\\s+", "");
			check(compact.contains("FUN_99b6c8(1,0x67c,") &&
				compact.contains("FUN_2e533e"),
				"callback arguments are still grouped incorrectly:\n" + code);
			check(!compact.contains("0xcf867c"),
				"false PAGE:OFFSET target remains in decompilation:\n" + code);
		}
		finally {
			decompiler.dispose();
		}

		println("Saved-program overlapping callback regression passed for FUN_2e5364; callback " +
			(callbackWasMissing ? "recovered" : "already present") + ".");
	}

	private Function requiredFunction(long address) {
		Function function = getFunctionAt(toAddr(address));
		check(function != null, "missing function at " + Long.toHexString(address));
		return function;
	}

	private boolean hasReference(Address from, Address to) {
		for (Reference reference : getReferencesFrom(from)) {
			if (to.equals(reference.getToAddress())) {
				return true;
			}
		}
		return false;
	}

	private boolean isPointer(DataType dataType) {
		return unwrap(dataType) instanceof Pointer;
	}

	private boolean isFunctionPointer(DataType dataType) {
		DataType unwrapped = unwrap(dataType);
		return unwrapped instanceof Pointer pointer &&
			unwrap(pointer.getDataType()) instanceof FunctionDefinition;
	}

	private DataType unwrap(DataType dataType) {
		DataType result = dataType;
		while (result instanceof TypeDef typeDef) {
			result = typeDef.getBaseDataType();
		}
		return result;
	}

	private void checkStorage(Parameter parameter, String expected) {
		String actual = parameter.getVariableStorage().toString();
		String normalized = actual.replace(":2", "").replace(',', '+');
		check(expected.equals(normalized),
			parameter.getName() + ": expected " + expected + ", got " + actual);
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
