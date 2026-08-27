// Focused saved-program regression for the nested TASKING jump table and the
// pointer/scalar return values that meet in FUN_2e6276.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidrainfineon.C166CallTargetAnalyzer;
import ghidrainfineon.C166TaskingTypeInferenceAnalyzer;

public class C166Function2e6276RealDatabaseTest extends GhidraScript {

	private static final long SUBJECT = 0x2e6276L;
	private static final long JUMP = 0x2e63b4L;
	private static final long TABLE = 0x584fc0L;
	private static final long[] TARGETS = {
		0x2e63b6L, 0x2e6412L, 0x2e6412L, 0x2e63e0L, 0x2e6412L
	};
	private static final long[] TYPE_SCOPE = {
		SUBJECT, 0x224108L, 0x9fd688L, 0x2e72ceL, 0x2e72f6L,
		0x2e7338L, 0x2c68ccL, 0x2c699cL, 0x2c8636L, 0xa04a5eL,
		0x2e740cL, 0x86fd12L, 0x2e6434L
	};
	private static final long[] SIGNATURE_SCOPE = {
		SUBJECT, 0x224108L, 0x9fd688L, 0x2e72ceL, 0x2e72f6L,
		0x2e7338L, 0x2c68ccL, 0x2c699cL, 0x2c8636L, 0xa04a5eL,
		0x2e740cL, 0x86fd12L, 0x2e6434L, 0x9056d8L, 0x2e871eL,
		0x2e8564L, 0x2e85e6L, 0x2cc274L, 0x905a92L
	};

	@Override
	protected void run() throws Exception {
		check("tasking-classic-large".equals(
			currentProgram.getLanguage().getProperty("c166.abi")),
			"real-program regression is not using TASKING Classic Large");

		Function subject = requiredFunction(SUBJECT);
		MessageLog callLog = new MessageLog();
		check(new C166CallTargetAnalyzer().added(currentProgram,
			new AddressSet(subject.getBody()), monitor, callLog),
			"bounded switch recovery failed: " + callLog);

		AddressSet typeScope = new AddressSet();
		for (long entry : TYPE_SCOPE) {
			typeScope.add(requiredFunction(entry).getBody());
		}
		C166TaskingTypeInferenceAnalyzer typeAnalyzer =
			new C166TaskingTypeInferenceAnalyzer();
		MessageLog typeLog = new MessageLog();
		check(typeAnalyzer.added(currentProgram,
			typeScope, monitor, typeLog), "focused type inference failed: " + typeLog);

		for (int index = 0; index < TARGETS.length; index++) {
			Address target = toAddr(TARGETS[index]);
			check(getInstructionAt(target) != null,
				"local switch target was not disassembled: " + target);
			check(hasReference(toAddr(JUMP), target, RefType.COMPUTED_JUMP),
				"missing computed-jump reference to " + target);
			check(getFunctionAt(target) == null,
				"local switch target became a function: " + target);
			check(getDataAt(toAddr(TABLE + index * 2L)) != null &&
				getDataAt(toAddr(TABLE + index * 2L)).getDataType()
					.isEquivalent(UnsignedShortDataType.dataType),
				"jump-table word was not defined at index " + index);
		}

		checkReturnLength(0x2e72ceL, 2);
		checkReturnLength(0x2e72f6L, 2);
		checkReturnLength(0x2e7338L, 2);
		check(requiredFunction(SUBJECT).getReturnType() instanceof VoidDataType,
			"FUN_2e6276 retained an incidental call result");
		check(requiredFunction(0x2c68ccL).getReturnType() instanceof VoidDataType &&
			requiredFunction(0x2c699cL).getReturnType() instanceof VoidDataType &&
			requiredFunction(0x2c8636L).getReturnType() instanceof VoidDataType,
			"cleanup/tail-call chain retained incidental R4 return values");
		check(requiredFunction(0x224108L).getReturnType() instanceof VoidDataType,
			"FUN_224108 did not inherit the void tail target");
		Function noArgumentHelper = requiredFunction(0x9fd688L);
		check(noArgumentHelper.getParameterCount() == 0 &&
			"__tasking_c166_classic".equals(
				noArgumentHelper.getCallingConventionName()),
			"FUN_9fd688 retained an unlocked default signature");
		Function stateGetter = requiredFunction(0x86fd12L);
		check(stateGetter.getParameterCount() == 0 &&
			"__tasking_c166_classic".equals(stateGetter.getCallingConventionName()) &&
			stateGetter.getSignatureSource() == SourceType.ANALYSIS,
			"FUN_86fd12 retained an unlocked zero-argument signature");
		Function fixedArgumentWrapper = requiredFunction(0x2e7338L);
		check(fixedArgumentWrapper.getParameterCount() == 0 &&
			fixedArgumentWrapper.getSignatureSource() == SourceType.ANALYSIS,
			"FUN_2e7338 retained an unlocked old-style empty prototype");
		Function nestedTarget = requiredFunction(0x2e6434L);
		check(nestedTarget.getReturnType() instanceof VoidDataType &&
			nestedTarget.getParameterCount() == 1 &&
			nestedTarget.getParameter(0).getFormalDataType() instanceof Pointer,
			"FUN_2e6434 split its single far-data pointer into scalar words");
		check(requiredFunction(SUBJECT).getParameter(0).getFormalDataType() instanceof Pointer,
			"FUN_2e6276 param_1 is not a far-data pointer");
		check(requiredFunction(0x9056d8L).getReturnType() instanceof Pointer,
			"FUN_9056d8 no longer returns the local descriptor pointer");
		checkPointerParameter(0x2e871eL, 0);
		checkPointerParameter(0x2e8564L, 0);
		checkPointerParameter(0x2e85e6L, 0);
		checkPointerParameter(0x2e85e6L, 1);
		checkPointerParameter(0x2cc274L, 1);
		checkPointerParameter(0x905a92L, 0);
		checkPointerParameter(0x224108L, 0);
		checkPointerParameter(0x224108L, 1);

		String firstSignatures = signatureSnapshot();
		MessageLog repeatedTypeLog = new MessageLog();
		check(typeAnalyzer.added(currentProgram, typeScope, monitor, repeatedTypeLog),
			"repeated focused type inference failed: " + repeatedTypeLog);
		check(firstSignatures.equals(signatureSnapshot()),
			"focused real-program type inference is not idempotent");

		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		check(decompiler.openProgram(currentProgram), decompiler.getLastMessage());
		try {
			DecompileResults results = decompiler.decompileFunction(subject, 120, monitor);
			check(results.decompileCompleted(), results.getErrorMessage());
			String code = results.getDecompiledFunction().getC();
			println(code);
			String compact = code.replaceAll("\\s+", "");
			check(code.contains("switch") &&
				!code.contains("Could not recover jumptable") &&
				!code.contains("Treating indirect jump as call") &&
				!compact.contains("(*(code*)"),
				"nested bounded switch is still an indirect call:\n" + code);
			check(compact.contains("switch(local_5e)") &&
				compact.contains("case0:") &&
				compact.contains("case3:") &&
				(compact.contains("default:") || compact.contains("case1:") &&
					compact.contains("case2:") && compact.contains("case4:")) &&
				!compact.contains("case0x2e63b6:") &&
				!compact.contains("case0x2e63e0:") &&
				!compact.contains("case0x2e6412:") &&
				!compact.contains("switch((uint3)"),
				"nested switch uses branch addresses instead of local_5e labels 0..4:\n" +
					code);
			check(!compact.matches("(?s).*FUN_9fd688\\([^)]*,[^)]*\\).*"),
				"zero-argument helper still received fabricated arguments:\n" + code);
			check(!compact.matches("(?s).*thunk_FUN_86fd12\\([^)]{1,}\\).*"),
				"zero-argument state getter still received fabricated arguments:\n" + code);
			check(!compact.matches("(?s).*FUN_2e7338\\([^)]{1,}\\).*"),
				"fixed-argument tail wrapper still inherited target arguments:\n" + code);
			check(!code.contains("extraout_r4") && !code.contains("PTR_000001") &&
				!compact.contains("(int*)FUN_") &&
				!compact.contains("(int*)thunk_FUN_") &&
				compact.contains("FUN_2e6434(param_1)") &&
				compact.matches("(?s).*int\\*piVar\\d+;.*piVar\\d+=FUN_9056d8.*"),
				"pointer/scalar return merge is still contaminated:\n" + code);
		}
		finally {
			decompiler.dispose();
		}

		println("Saved-program FUN_2e6276 pointer and switch regression passed.");
	}

	private Function requiredFunction(long address) {
		Function function = getFunctionAt(toAddr(address));
		check(function != null, "missing function at " + Long.toHexString(address));
		return function;
	}

	private void checkReturnLength(long address, int expected) {
		Function function = requiredFunction(address);
		check(function.getReturnType().getLength() == expected,
			function.getName() + ": expected " + expected + "-byte return, got " +
				function.getReturnType().getDisplayName());
	}

	private void checkPointerParameter(long address, int ordinal) {
		Function function = requiredFunction(address);
		check(function.getParameterCount() > ordinal &&
			function.getParameter(ordinal).getFormalDataType() instanceof Pointer,
			function.getName() + " parameter " + ordinal + " is not a far-data pointer");
	}

	private String signatureSnapshot() {
		StringBuilder snapshot = new StringBuilder();
		for (long address : SIGNATURE_SCOPE) {
			Function function = requiredFunction(address);
			snapshot.append(function.getEntryPoint()).append(':')
				.append(function.getSignatureSource()).append(':')
				.append(function.getPrototypeString(true, true)).append('\n');
			for (Parameter parameter : function.getParameters()) {
				snapshot.append("  ").append(parameter.getVariableStorage()).append(':')
					.append(parameter.getFormalDataType().getPathName()).append('\n');
			}
		}
		return snapshot.toString();
	}

	private boolean hasReference(Address from, Address to, RefType type) {
		for (Reference reference : getReferencesFrom(from)) {
			if (reference.getToAddress().equals(to) &&
				reference.getReferenceType().equals(type)) {
				return true;
			}
		}
		return false;
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
