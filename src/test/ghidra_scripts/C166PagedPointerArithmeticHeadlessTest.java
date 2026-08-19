// Run headlessly against the saved real-program fixture after full analysis.
import java.lang.reflect.Field;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompileProcessFactory;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.listing.Function;
import ghidrainfineon.C166TaskingTypeInferenceAnalyzer;

public class C166PagedPointerArithmeticHeadlessTest extends GhidraScript {

	private static final long TARGET = 0x35b82aL;

	@Override
	protected void run() throws Exception {
		useDevelopmentDecompilerIfRequested();
		check("tasking-classic-large".equals(
			currentProgram.getLanguage().getProperty("c166.abi")),
			"real-program regression is not using TASKING Classic Large");

		Function function = requiredFunction(TARGET);
		Function index = requiredFunction(0x9b58aeL);
		Function predicate = requiredFunction(0x35b478L);
		Function mapKey = requiredFunction(0x35cd78L);
		Function selectMessage = requiredFunction(0x254096L);
		Function notify = requiredFunction(0x99b4aaL);

		AddressSet scope = new AddressSet(function.getBody());
		for (Function dependency : new Function[] {
			index, predicate, mapKey, selectMessage, notify
		}) {
			scope.add(dependency.getBody());
		}
		C166TaskingTypeInferenceAnalyzer analyzer =
			new C166TaskingTypeInferenceAnalyzer();
		MessageLog firstLog = new MessageLog();
		check(analyzer.added(currentProgram, scope, monitor, firstLog),
			"unified TASKING analysis failed: " + firstLog);
		check(!firstLog.hasMessages(),
			"unified TASKING analysis leaked diagnostics: " + firstLog);
		assertSignatures(index, predicate, mapKey, selectMessage, notify);
		String signatures = signatureSnapshot(index, predicate, mapKey,
			selectMessage, notify);
		MessageLog secondLog = new MessageLog();
		check(analyzer.added(currentProgram, scope, monitor, secondLog),
			"unified TASKING idempotence pass failed: " + secondLog);
		check(!secondLog.hasMessages(),
			"idempotence pass leaked diagnostics: " + secondLog);
		check(signatures.equals(signatureSnapshot(index, predicate, mapKey,
			selectMessage, notify)), "real signatures changed on analyzer rerun");

		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		check(decompiler.openProgram(currentProgram), decompiler.getLastMessage());
		try {
			String first = decompile(decompiler, function);
			String second = decompile(decompiler, function);
			check(first.equals(second), "0x35b82a decompilation is not idempotent");
			check(!first.contains("Type propagation algorithm not settling"),
				"0x35b82a type propagation still does not settle:\n" + first);
			check(first.contains("IsFeatureEnabled(0x514)"),
				"0x35b82a lost the feature-test call or its scalar argument:\n" + first);
			String nestedPrefix = first.substring(0, first.indexOf("IsFeatureEnabled(0x514)"));
			check(!nestedPrefix.contains("0x3fff") &&
				!nestedPrefix.contains("0x4000") &&
				!nestedPrefix.contains("segment(") &&
				!nestedPrefix.contains("CONCAT"),
				"0x35b82a retained split nested far-pointer loads:\n" + nestedPrefix);
			String featureBranch = statementRange(first, "IsFeatureEnabled(0x514)",
				"return 0x14;");
			check(featureBranch.contains("+ 0x2cc") || featureBranch.contains("+0x2cc"),
				"0x35b82a lost the context-field access at +0x2cc:\n" + first);
			check(!featureBranch.contains("0x4000") && !featureBranch.contains("0x3fff") &&
				!featureBranch.contains("uint3") && !featureBranch.contains(">> 0x10"),
				"0x35b82a feature branch still exposes paged-address representation " +
					"arithmetic:\n" + featureBranch);
			String dispatchRead = statementRange(first, "LAB_35b92c:", "== 0x39");
			check(!dispatchRead.contains("0x3fff") && !dispatchRead.contains("CONCAT") &&
				!dispatchRead.contains(">> 0x10"),
				"0x35b82a direct far-pointer field read was not reconstructed:\n" +
					dispatchRead);
			String indexedBranch = statementRange(first, "== 0x2a", "LAB_35be2c:");
			check(!indexedBranch.contains("0x3fff") &&
				!indexedBranch.contains("CONCAT"),
				"0x35b82a indexed far-pointer arithmetic was not reconstructed:\n" +
					indexedBranch);
			String nestedEvent = statementRange(first, "== 0x15", "FUN_35cd78(3)");
			check(!nestedEvent.contains("0x3fff") && !nestedEvent.contains("CONCAT"),
				"0x35b82a late nested far-pointer load was not reconstructed:\n" +
					nestedEvent);
			String restoredPointer = statementRange(first, "FUN_254096(0x32a)",
				"FUN_9b3a74");
			check(!restoredPointer.contains("0x3fff") &&
				!restoredPointer.contains("CONCAT") &&
				!restoredPointer.contains("<< 0x10") &&
				!restoredPointer.contains("<<0x10"),
				"0x35b82a stack-restored far pointer was not reconstructed:\n" +
					restoredPointer);
			String lookupBranch = statementRange(first, "FUN_35cd78(3)",
				"FUN_9b4ee6");
			check(!lookupBranch.replaceAll("\\s+", "")
				.contains("&0x3fff)&0x7f") && !lookupBranch.contains("CONCAT"),
				"0x35b82a post-increment far-pointer load was not reconstructed:\n" +
					lookupBranch);

			Function feature = findUniqueGlobalFunction("IsFeatureEnabled");
			check(feature.getParameterCount() == 1,
				"IsFeatureEnabled must have exactly one scalar parameter: " +
					feature.getSignature());
			check(!(feature.getParameter(0).getFormalDataType() instanceof Pointer),
				"IsFeatureEnabled parameter was misclassified as a pointer: " +
					feature.getSignature());

			String compact = first.replaceAll("\\s+", "");
			check(!first.contains("(int)(float)") && !first.contains("(float)") &&
				!first.contains("extraout_RH4"),
				"0x35b82a retained poisoned scalar return data flow:\n" + first);
			check(compact.contains("FUN_35cd78(3)") &&
				compact.contains("FUN_254096(0x32a)") &&
				compact.contains("FUN_99b4aa(1,0xb86)"),
				"0x35b82a retained fictitious register arguments:\n" + first);

			println("real-program paged far-pointer arithmetic regression passed.");
		}
		finally {
			decompiler.dispose();
		}
	}

	private void assertSignatures(Function index, Function predicate, Function mapKey,
			Function selectMessage, Function notify) {
		DataType unsignedLong = new UnsignedLongDataType(
			currentProgram.getDataTypeManager());
		check(unsignedLong.isEquivalent(unwrap(index.getReturnType())),
			"FUN_9b58ae return is not unsigned long: " + index.getSignature());
		check(!isPointer(predicate.getReturnType()) &&
			predicate.getReturnType().getLength() == 2,
			"FUN_35b478 return is not one R4 word: " + predicate.getSignature());
		check(mapKey.getParameterCount() == 1,
			"FUN_35cd78 retained fictitious arguments: " + mapKey.getSignature());
		check(selectMessage.getParameterCount() == 1,
			"FUN_254096 retained fictitious arguments: " + selectMessage.getSignature());
		check(notify.getParameterCount() == 2,
			"FUN_99b4aa retained fictitious arguments: " + notify.getSignature());
	}

	private String signatureSnapshot(Function... functions) {
		StringBuilder result = new StringBuilder();
		for (Function function : functions) {
			result.append(function.getEntryPoint()).append(':')
				.append(function.getPrototypeString(true, true)).append(';');
		}
		return result.toString();
	}

	private DataType unwrap(DataType type) {
		while (type instanceof TypeDef typeDef) {
			type = typeDef.getBaseDataType();
		}
		return type;
	}

	private boolean isPointer(DataType type) {
		return unwrap(type) instanceof Pointer;
	}

	private Function requiredFunction(long address) {
		Function function = currentProgram.getFunctionManager().getFunctionAt(toAddr(address));
		check(function != null,
			"missing real-program function at 0x" + Long.toHexString(address));
		return function;
	}

	private void useDevelopmentDecompilerIfRequested() throws Exception {
		String path = System.getenv("C166_TEST_DECOMPILER");
		if (path == null || path.isBlank()) {
			return;
		}
		Field executablePath = DecompileProcessFactory.class.getDeclaredField("exepath");
		executablePath.setAccessible(true);
		executablePath.set(null, path);
		println("Using development decompiler: " + path);
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
