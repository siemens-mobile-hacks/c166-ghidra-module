// Representative real-program headless regression test for M55_v91.bin.
import java.util.List;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidrainfineon.C166TaskingRuntimeAnalyzer;

public class C166M55TaskingRuntimeHeadlessTest extends GhidraScript {
	@Override
	protected void run() throws Exception {
		check("tasking-classic-large".equals(
			currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()),
			"M55 test is not using TASKING Classic large");

		for (long address : new long[] {
			0xc483caL, 0xc483e8L, 0xc483feL, 0xc48416L, 0xc47df0L,
			0xc47becL, 0xc479e4L, 0xc479ecL, 0xc48584L, 0xc48128L,
			0xc484f2L, 0xc48106L
		}) {
			Function function = requiredFunction(address);
			function.setInline(false);
			function.setCallFixup(null);
		}
		C166TaskingRuntimeAnalyzer analyzer = new C166TaskingRuntimeAnalyzer();
		check(analyzer.added(currentProgram, currentProgram.getMemory(), monitor,
			new MessageLog()), "TASKING runtime analysis failed on M55");
		checkFixup(0xc483caL, "c166_tasking_load8f");
		checkFixup(0xc483e8L, "c166_tasking_store8f");
		checkFixup(0xc483feL, "c166_tasking_load8n");
		checkFixup(0xc48416L, "c166_tasking_store8n");
		checkFixup(0xc47df0L, "c166_tasking_cif28r");
		checkFixup(0xc47becL, "c166_tasking_cfi82r");
		checkFixup(0xc479e4L, "c166_tasking_sbf8r");
		checkFixup(0xc479ecL, "c166_tasking_adf8r");
		checkFixup(0xc48584L, "c166_tasking_mlf8r");
		checkFixup(0xc48128L, "c166_tasking_dvf8r");
		checkFixup(0xc484f2L, "c166_tasking_ngf8r");
		checkFixup(0xc48106L, "c166_tasking_swap8r");

		DoubleDataType doubleType = new DoubleDataType(currentProgram.getDataTypeManager());
		Function floor = requiredFunction(0xbf78c8L);
		floor.setReturnType(doubleType, SourceType.USER_DEFINED);
		floor.updateFunction("__tasking_c166_classic", null,
			List.of(new ParameterImpl("__x", doubleType, currentProgram)),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
		Function exp = requiredFunction(0xbff2aaL);
		exp.setReturnType(doubleType, SourceType.USER_DEFINED);
		exp.updateFunction("__tasking_c166_classic", null,
			List.of(new ParameterImpl("__x", doubleType, currentProgram)),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
		Function ldexp = requiredFunction(0xbfeed8L);
		ldexp.setReturnType(doubleType, SourceType.USER_DEFINED);
		ldexp.updateFunction("__tasking_c166_classic", null,
			List.of(new ParameterImpl("__x", doubleType, currentProgram),
				new ParameterImpl("__exponent",
					new IntegerDataType(currentProgram.getDataTypeManager()), currentProgram)),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);

		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		check(decompiler.openProgram(currentProgram), decompiler.getLastMessage());
		try {
			String floorCode = decompile(decompiler, floor);
			String expCode = decompile(decompiler, exp);
			String ldexpCode = decompile(decompiler, ldexp);
			check(!floorCode.contains("Variable defined which should be unmapped: __x"),
				"floor still has an unmapped double parameter");
			check(!expCode.contains("double __x_") &&
				!expCode.contains("int __exponent;") &&
				!expCode.contains("extraout_") && !expCode.contains("unaff_"),
				"exp still contains an uninitialized call argument");
			String calculatedFloorArgument =
				"\\b(\\w+)\\s*=\\s*[^;]*\\b__x\\b[^;]*;.*?" +
				Pattern.quote(floor.getName()) + "\\(\\1\\)";
			check(Pattern.compile(calculatedFloorArgument, Pattern.DOTALL)
				.matcher(expCode).find(),
				"exp does not pass its computed double expression to floor");
			check(expCode.contains(ldexp.getName() + "("),
				"exp no longer contains its ldexp call");
			println("M55 TASKING double runtime data-flow test passed.");
		}
		finally {
			decompiler.dispose();
		}
	}

	private String decompile(DecompInterface decompiler, Function function) {
		DecompileResults result = decompiler.decompileFunction(function, 120, monitor);
		check(result.decompileCompleted(), "failed to decompile " + function.getName());
		String code = result.getDecompiledFunction().getC();
		println("=== " + function.getName() + " ===");
		println(code);
		return code;
	}

	private Function requiredFunction(long address) throws Exception {
		Function function = getFunctionAt(toAddr(address));
		if (function == null) {
			check(disassemble(toAddr(address)),
				"failed to disassemble M55 function at " + Long.toHexString(address));
			function = createFunction(toAddr(address), "FUN_" + Long.toHexString(address));
		}
		check(function != null, "missing M55 function at " + Long.toHexString(address));
		return function;
	}

	private void checkFixup(long address, String expected) throws Exception {
		String actual = requiredFunction(address).getCallFixup();
		check(expected.equals(actual), "wrong call-fixup at " + Long.toHexString(address) +
			": " + actual);
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
