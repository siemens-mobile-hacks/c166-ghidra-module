// Full saved-program performance and convergence regression.
// @category C166.Tests

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidrainfineon.C166TaskingTypeInferenceAnalyzer;

public class C166TypeInferenceRealPerformanceTest extends GhidraScript {

	@Override
	protected void run() throws Exception {
		check("tasking-classic-large".equals(
			currentProgram.getLanguage().getProperty("c166.abi")),
			"real performance test requires c166.abi=tasking-classic-large");

		C166TaskingTypeInferenceAnalyzer analyzer =
			new C166TaskingTypeInferenceAnalyzer();
		long firstStart = System.nanoTime();
		MessageLog firstLog = new MessageLog();
		check(analyzer.added(currentProgram, currentProgram.getMemory(), monitor, firstLog),
			"first full type-inference pass failed: " + firstLog);
		long firstMillis = (System.nanoTime() - firstStart) / 1_000_000;
		C166TaskingTypeInferenceAnalyzer.RunStatistics first =
			analyzer.getLastRunStatistics();
		check(first.fullScan() && first.converged(),
			"first full pass did not converge: " + first);

		println("Real full type-inference performance passed: first=" + firstMillis +
			" ms " + first + ".");
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
