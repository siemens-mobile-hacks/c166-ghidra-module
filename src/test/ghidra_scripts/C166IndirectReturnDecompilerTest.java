// Run against the patched Ghidra via tools/test-patched-decompiler.sh.
import java.lang.reflect.Field;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileProcessFactory;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidrainfineon.C166TaskingRuntimeAnalyzer;

public class C166IndirectReturnDecompilerTest extends GhidraScript {

	@Override
	protected void run() throws Exception {
		useDevelopmentDecompilerIfRequested();
		check(currentProgram.getLanguageID().getIdAsString().startsWith("C166:"),
			"wrong processor language");
		check("tasking-classic-large".equals(
			currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()),
			"wrong compiler spec");

		Address entry = toAddr(0x1000);
		MemoryBlock block = createMemoryBlock("indirect_double_return_code", entry,
			new byte[] { (byte) 0xdb, 0 }, false);
		block.setExecute(true);
		check(disassemble(entry), "failed to disassemble indirect-return fixture");
		Function function = createFunction(entry, "indirect_double_return");
		check(function != null, "failed to create indirect-return fixture");
		DoubleDataType doubleType = new DoubleDataType(currentProgram.getDataTypeManager());
		function.setReturnType(doubleType, SourceType.USER_DEFINED);
		function.updateFunction("__tasking_c166_classic", null, List.of(),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);

		check(function.getSignature().getReturnType().isEquivalent(doubleType),
			"database signature return type is not double");
		check(function.getReturn().getVariableStorage().isForcedIndirect(),
			"double result is not physically returned through an indirect R4 pointer");
		check("r4".equals(function.getReturn().getVariableStorage()
			.getRegisters().get(0).getName().toLowerCase()),
			"double result is not returned through R4");
		check(function.getParameterCount() == 0,
			"double result unexpectedly gained a hidden return parameter");

		Function floor = function(toAddr(0x1100), "floor", new byte[] { (byte) 0xdb, 0 });
		floor.setReturnType(doubleType, SourceType.USER_DEFINED);
		floor.updateFunction("__tasking_c166_classic", null,
			List.of(new ParameterImpl("x", doubleType, currentProgram)),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
		Function ldexp = function(toAddr(0x1c00), "ldexp", new byte[] { (byte) 0xdb, 0 });
		ldexp.setReturnType(doubleType, SourceType.USER_DEFINED);
		ldexp.updateFunction("__tasking_c166_classic", null,
			List.of(new ParameterImpl("x", doubleType, currentProgram),
				new ParameterImpl("exponent",
					new ghidra.program.model.data.IntegerDataType(
						currentProgram.getDataTypeManager()), currentProgram)),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
		Function directCaller = function(toAddr(0x1200), "direct_double_argument", new byte[] {
			(byte) 0xe6, (byte) 0xf8, 0, 0,
			(byte) 0xe6, (byte) 0xf9, 0, 0,
			(byte) 0xe6, (byte) 0xfa, 0, 0,
			(byte) 0xe6, (byte) 0xfb, (byte) 0xf0, 0x3f,
			(byte) 0x88, (byte) 0x80,
			(byte) 0x88, (byte) 0x90,
			(byte) 0x88, (byte) 0xa0,
			(byte) 0x88, (byte) 0xb0,
			(byte) 0xda, 0, 0, 0x11,
			0x06, (byte) 0xf0, 0x08, 0,
			(byte) 0xdb, 0
		});
		Function directDoubleIntCaller = function(toAddr(0x1b00), "direct_double_int_arguments",
			new byte[] {
				(byte) 0xe6, (byte) 0xfc, 5, 0,
				(byte) 0x88, (byte) 0xc0,
				(byte) 0xe6, (byte) 0xf8, 0, 0,
				(byte) 0xe6, (byte) 0xf9, 0, 0,
				(byte) 0xe6, (byte) 0xfa, 0, 0,
				(byte) 0xe6, (byte) 0xfb, (byte) 0xf0, 0x3f,
				(byte) 0x88, (byte) 0x80,
				(byte) 0x88, (byte) 0x90,
				(byte) 0x88, (byte) 0xa0,
				(byte) 0x88, (byte) 0xb0,
				(byte) 0xda, 0, 0, 0x1c,
				0x06, (byte) 0xf0, 10, 0,
				(byte) 0xdb, 0
			});
		Function load8n = function(toAddr(0x1300), "tasking_load8n", new byte[] {
			0x26, (byte) 0xf0, 0x08, 0,
			(byte) 0xf0, (byte) 0xa0,
			(byte) 0xd8, (byte) 0xa4, 0x08, 0x42,
			(byte) 0xd8, (byte) 0xa4, 0x08, 0x42,
			(byte) 0xd8, (byte) 0xa4, 0x08, 0x42,
			(byte) 0xc8, (byte) 0xa4, 0x28, (byte) 0xa6,
			(byte) 0xdb, 0
		});
		Function nearMiss = function(toAddr(0x1500), "not_tasking_load8n", new byte[] {
			0x26, (byte) 0xf0, 0x08, 0,
			(byte) 0xf0, (byte) 0xa0,
			(byte) 0xd8, (byte) 0xa4, 0x08, 0x42,
			(byte) 0xd8, (byte) 0xa4, 0x08, 0x42,
			(byte) 0xd8, (byte) 0xa4, 0x08, 0x42,
			(byte) 0xc8, (byte) 0xa4, 0x28, (byte) 0xa7,
			(byte) 0xdb, 0
		});
		Function store8f = function(toAddr(0x1800), "tasking_store8f", new byte[] {
			(byte) 0xf6, (byte) 0xf5, 0, (byte) 0xfe, (byte) 0xcc, 0,
			(byte) 0xd8, 0x4a, 0x08, (byte) 0xa2,
			(byte) 0xd8, 0x4a, 0x08, (byte) 0xa2,
			(byte) 0xd8, 0x4a, 0x08, (byte) 0xa2,
			(byte) 0xc8, 0x4a, (byte) 0xdb, 0
		});
		Function cif28r = function(toAddr(0x1600), "tasking_cif28r", new byte[] {
			0x26, (byte) 0xf0, 0x08, 0,
			(byte) 0xf0, (byte) 0xa0,
			(byte) 0x88, 0x70, (byte) 0x88, (byte) 0x80, (byte) 0x88, (byte) 0x90,
			(byte) 0xf0, 0x74, 0x7c, (byte) 0xf7,
			(byte) 0xc4, 0x7a, 0x06, 0,
			(byte) 0xdb, 0
		});
		Function ngf8r = function(toAddr(0x1d00), "tasking_ngf8r", new byte[] {
			(byte) 0xa8, 0x2a, 0x3a, (byte) 0xf2, (byte) 0xf2, (byte) 0xff,
			(byte) 0xb8, 0x2a, (byte) 0xdb, 0
		});
		Function mlf8r = function(toAddr(0x1f00), "tasking_mlf8r", new byte[] {
			(byte) 0xda, (byte) 0xc4, 0x48, (byte) 0x83,
			0x7a, (byte) 0xf4, (byte) 0xf4, 0x10,
			0x48, 0x20, 0x2d, (byte) 0xdf,
			0x46, (byte) 0xf2, (byte) 0xff, 0x07,
			0x2d, (byte) 0xcc, 0x48, 0x10,
			0x2d, (byte) 0xdd, 0x46, (byte) 0xf1,
			(byte) 0xdb, 0
		});
		C166TaskingRuntimeAnalyzer runtimeAnalyzer = new C166TaskingRuntimeAnalyzer();
		check(runtimeAnalyzer.canAnalyze(currentProgram),
			"TASKING runtime analyzer rejected the large-model language");
		check(runtimeAnalyzer.added(currentProgram, currentProgram.getMemory(), monitor,
			new MessageLog()), "TASKING runtime analysis failed");
		check("c166_tasking_load8n".equals(load8n.getCallFixup()),
			"TASKING __load8n was not recognized by its implementation");
		check("c166_tasking_store8f".equals(store8f.getCallFixup()),
			"TASKING __store8f was not recognized by its implementation");
		check("c166_tasking_cif28r".equals(cif28r.getCallFixup()),
			"TASKING __cif28r was not recognized by its implementation");
		check("__tasking_c166_double_runtime".equals(ngf8r.getCallingConventionName()),
			"TASKING __ngf8r did not receive its ABI register-preservation model");
		check("c166_tasking_mlf8r".equals(mlf8r.getCallFixup()),
			"TASKING __mlf8r did not receive its arithmetic model");
		check(nearMiss.getCallFixup() == null,
			"near-match runtime code was incorrectly assigned a call-fixup");
		Function runtimeCaller = function(toAddr(0x1400), "runtime_double_argument",
			new byte[] {
				0x26, (byte) 0xf0, 0x18, 0,
				(byte) 0xe6, (byte) 0xf4, 0x18, 0,
				0, 0x40,
				(byte) 0xda, 0, 0, 0x13,
				(byte) 0xda, 0, 0, 0x11,
				0x06, (byte) 0xf0, 0x20, 0,
				(byte) 0xdb, 0
			});
		runtimeCaller.updateFunction("__tasking_c166_classic", null,
			List.of(new ParameterImpl("x", doubleType, currentProgram)),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
		Function conversionCaller = function(toAddr(0x1700), "runtime_int_to_double",
			new byte[] {
				(byte) 0xf0, 0x4c,
				(byte) 0xda, 0, 0, 0x16,
				(byte) 0xda, 0, 0, 0x11,
				0x06, (byte) 0xf0, 0x08, 0,
				(byte) 0xdb, 0
			});
		conversionCaller.updateFunction("__tasking_c166_classic", null,
			List.of(new ParameterImpl("x",
				new ghidra.program.model.data.IntegerDataType(currentProgram.getDataTypeManager()),
				currentProgram)),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
		Function preservedRegisterCaller = function(toAddr(0x1e00),
			"runtime_preserved_register", new byte[] {
				(byte) 0xda, 0, 0, 0x1d,
				(byte) 0xf0, 0x4c,
				(byte) 0xda, 0, 0, 0x16,
				(byte) 0xda, 0, 0, 0x11,
				0x06, (byte) 0xf0, 0x08, 0,
				(byte) 0xdb, 0
			});
		preservedRegisterCaller.updateFunction("__tasking_c166_classic", null,
			List.of(new ParameterImpl("x",
				new ghidra.program.model.data.IntegerDataType(currentProgram.getDataTypeManager()),
				currentProgram)),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
		Function multiplyCaller = function(toAddr(0x2000), "runtime_double_multiply",
			new byte[] {
				(byte) 0xf0, 0x40,
				(byte) 0xda, 0, 0, 0x13,
				(byte) 0xf0, (byte) 0xba,
				(byte) 0xe6, (byte) 0xf4, 0x10, 0,
				0, 0x40,
				(byte) 0xda, 0, 0, 0x13,
				(byte) 0xda, 0, 0, 0x1f,
				(byte) 0xda, 0, 0, 0x11,
				0x06, (byte) 0xf0, 0x10, 0,
				(byte) 0xdb, 0
			});
		multiplyCaller.updateFunction("__tasking_c166_classic", null,
			List.of(new ParameterImpl("x", doubleType, currentProgram),
				new ParameterImpl("y", doubleType, currentProgram)),
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);

		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		check(decompiler.openProgram(currentProgram),
			"failed to initialize decompiler: " + decompiler.getLastMessage());
		try {
			String directCode = decompile(decompiler, directCaller);
			println(directCode);
			check(directCode.contains("floor("),
				"direct stack-double call is missing:\n" + directCode);
			check(!directCode.contains("unaff_") && !directCode.contains(" in_"),
				"direct stack-double argument is not mapped:\n" + directCode);
			String directDoubleIntCode = decompile(decompiler, directDoubleIntCaller);
			println(directDoubleIntCode);
			check(directDoubleIntCode.contains("ldexp(") &&
				directDoubleIntCode.replaceAll("\\s+", "").contains(",5)"),
				"double followed by an integer is not mapped on the user stack:\n" +
					directDoubleIntCode);
			String runtimeCode = decompile(decompiler, runtimeCaller);
			println(runtimeCode);
			check(runtimeCode.replaceAll("\\s+", "").contains("floor(x)"),
				"TASKING __load8n stack-double argument is not mapped:\n" + runtimeCode);
			String conversionCode = decompile(decompiler, conversionCaller);
			println(conversionCode);
			check(conversionCode.contains("floor(") && conversionCode.contains("x") &&
				!conversionCode.contains("in_r4"),
				"TASKING __cif28r result is not mapped to the user stack:\n" + conversionCode);
			String preservedCode = decompile(decompiler, preservedRegisterCaller);
			println(preservedCode);
			check(preservedCode.contains("floor(") && preservedCode.contains("x") &&
				!preservedCode.contains("unaff_r12"),
				"TASKING double runtime did not preserve R12:\n" + preservedCode);
			String multiplyCode = decompile(decompiler, multiplyCaller);
			println(multiplyCode);
			check(multiplyCode.contains("floor(") && multiplyCode.contains(" * ") &&
				multiplyCode.contains("x") && multiplyCode.contains("y"),
				"TASKING __mlf8r arithmetic data flow is missing:\n" + multiplyCode);

			DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
			check(result.decompileCompleted(),
				"indirect-return fixture did not decompile: " + result.getErrorMessage());
			check(result.getHighFunction().getFunctionPrototype().getReturnType()
				.isEquivalent(doubleType), "high return type is not the logical double type");
			String code = result.getDecompiledFunction().getC();
			println(code);
			check(code.contains("double indirect_double_return("),
				"indirect R4 result was not rendered as a logical double return:\n" + code);
			check(!code.contains("double * indirect_double_return(") &&
				!code.contains("__return_storage_ptr__"),
				"physical indirect-return pointer leaked into the C signature:\n" + code);
			check(code.replaceAll("\\s+", "").contains("return*(double*)"),
				"double result was not read through a typed indirect R4 pointer:\n" + code);
		}
		finally {
			decompiler.dispose();
		}

		println("TASKING indirect R4 return decompiler test passed.");
	}

	private Function function(Address entry, String name, byte[] code) throws Exception {
		MemoryBlock block = createMemoryBlock(name + "_code", entry, code, false);
		block.setExecute(true);
		check(disassemble(entry), "failed to disassemble " + name);
		Function function = createFunction(entry, name);
		check(function != null, "failed to create " + name);
		return function;
	}

	private String decompile(DecompInterface decompiler, Function function) {
		DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
		check(result.decompileCompleted(),
			function.getName() + " did not decompile: " + result.getErrorMessage());
		return result.getDecompiledFunction().getC();
	}

	private void useDevelopmentDecompilerIfRequested() throws Exception {
		String path = System.getenv("C166_TEST_DECOMPILER");
		if (path == null || path.isBlank()) {
			return;
		}
		Field executablePath = DecompileProcessFactory.class.getDeclaredField("exepath");
		executablePath.setAccessible(true);
		executablePath.set(null, path);
		println("Using development decompiler: " + executablePath.get(null));
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
