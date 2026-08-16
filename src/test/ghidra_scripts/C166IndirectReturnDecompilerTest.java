// Run against the patched Ghidra via tools/test-patched-decompiler.sh.
import java.lang.reflect.Field;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileProcessFactory;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

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

		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		check(decompiler.openProgram(currentProgram),
			"failed to initialize decompiler: " + decompiler.getLastMessage());
		try {
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
