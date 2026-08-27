// Run headlessly against the saved database that exposed physical EXTP pages
// being reinterpreted as four-byte TASKING PAGE:OFFSET pointer encodings.
import java.math.BigInteger;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class C166ImmediateExtpRealDatabaseTest extends GhidraScript {

	private static final long TARGET = 0x2d3f1cL;

	@Override
	protected void run() throws Exception {
		check("tasking-classic-large".equals(
			currentProgram.getLanguage().getProperty("c166.abi")),
			"real-program regression is not using TASKING Classic Large");

		Function function = currentProgram.getFunctionManager().getFunctionAt(toAddr(TARGET));
		check(function != null, "missing saved-program function at " + toAddr(TARGET));
		assertExtpFixture(0x2d3fc0L, 0x2d3fc4L, 0x00a);
		assertExtpFixture(0x2d3fd2L, 0x2d3fd6L, 0x160);

		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		check(decompiler.openProgram(currentProgram), decompiler.getLastMessage());
		try {
			DecompileResults results = decompiler.decompileFunction(function, 120, monitor);
			check(results.decompileCompleted(), results.getErrorMessage());
			String code = results.getDecompiledFunction().getC();
			println(code);
			check(code.contains("FUN_c3f80c"),
				"FUN_2d3f1c lost the affected call:\n" + code);
			check(!code.contains("FUN_008000") && !code.contains("DAT_00a2f0") &&
				!code.contains("MIDI_160000") && !code.contains("DAT_160000"),
				"FUN_2d3f1c reinterpreted a physical address as PAGE:OFFSET:\n" + code);
			check(containsAny(code, "DAT_028000", "DAT_02a2f0", "0x2a2f0") &&
				containsAny(code, "DAT_580000", "UNK_580000", "DAT_581c58", "0x581c58"),
				"FUN_2d3f1c did not preserve both physical EXTP pages:\n" + code);
		}
		finally {
			decompiler.dispose();
		}

		println("Saved-program physical EXTP regression passed for FUN_2d3f1c.");
	}

	private void assertExtpFixture(long producerAddress, long loadAddress,
			long expectedPage) {
		Instruction producer = currentProgram.getListing().getInstructionAt(
			toAddr(producerAddress));
		check(producer != null && "extp".equalsIgnoreCase(producer.getMnemonicString()),
			"missing EXTP at " + toAddr(producerAddress));
		Register extp = currentProgram.getRegister("Extp");
		BigInteger page = currentProgram.getProgramContext().getValue(
			extp, toAddr(loadAddress), false);
		check(page != null && page.longValue() == expectedPage,
			"wrong EXTP context at " + toAddr(loadAddress));
	}

	private boolean containsAny(String value, String... candidates) {
		for (String candidate : candidates) {
			if (value.contains(candidate)) {
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
