// Run headlessly against the saved real-program fixture after full analysis.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.Function;

public class C166PagedPointerArithmeticHeadlessTest extends GhidraScript {

	private static final long TARGET = 0x35b82aL;

	@Override
	protected void run() throws Exception {
		check("tasking-classic-large".equals(
			currentProgram.getLanguage().getProperty("c166.abi")),
			"real-program regression is not using TASKING Classic Large");

		Function function = currentProgram.getFunctionManager().getFunctionAt(toAddr(TARGET));
		check(function != null, "missing real-program function at 0x35b82a");

		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		check(decompiler.openProgram(currentProgram), decompiler.getLastMessage());
		try {
			String first = decompile(decompiler, function);
			String second = decompile(decompiler, function);
			check(first.equals(second), "0x35b82a decompilation is not idempotent");
			check(first.contains("IsFeatureEnabled(0x514)"),
				"0x35b82a lost the feature-test call or its scalar argument:\n" + first);
			String featureBranch = statementRange(first, "IsFeatureEnabled(0x514)",
				"return 0x14;");
			check(featureBranch.contains("+ 0x2cc") || featureBranch.contains("+0x2cc"),
				"0x35b82a lost the context-field access at +0x2cc:\n" + first);
			check(!featureBranch.contains("0x4000") && !featureBranch.contains("0x3fff") &&
				!featureBranch.contains("uint3") && !featureBranch.contains(">> 0x10"),
				"0x35b82a feature branch still exposes paged-address representation " +
					"arithmetic:\n" + featureBranch);

			Function feature = findUniqueGlobalFunction("IsFeatureEnabled");
			check(feature.getParameterCount() == 1,
				"IsFeatureEnabled must have exactly one scalar parameter: " +
					feature.getSignature());
			check(!(feature.getParameter(0).getFormalDataType() instanceof Pointer),
				"IsFeatureEnabled parameter was misclassified as a pointer: " +
					feature.getSignature());

			println("real-program paged far-pointer arithmetic regression passed.");
		}
		finally {
			decompiler.dispose();
		}
	}

	private String statementRange(String code, String startMarker, String endMarker) {
		int start = code.indexOf(startMarker);
		check(start >= 0, "missing range start " + startMarker);
		int end = code.indexOf(endMarker, start);
		check(end >= 0, "missing range end " + endMarker);
		return code.substring(start, end + endMarker.length());
	}

	private String decompile(DecompInterface decompiler, Function function) {
		DecompileResults results = decompiler.decompileFunction(function, 120, monitor);
		check(results.decompileCompleted(),
			"failed to decompile " + function.getName() + ": " + results.getErrorMessage());
		String code = results.getDecompiledFunction().getC();
		println("=== " + function.getName() + " ===");
		println(code);
		return code;
	}

	private Function findUniqueGlobalFunction(String name) {
		Function match = null;
		for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
			if (!name.equals(function.getName())) {
				continue;
			}
			check(match == null, "multiple global functions named " + name);
			match = function;
		}
		check(match != null, "missing global function " + name);
		return match;
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
