// Saved-program regression for the scope used by interactive disassembly.
// @category C166.Tests

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidrainfineon.C166TaskingTypeInferenceAnalyzer;

public class C166TypeInferenceRealIncrementalPerformanceTest extends GhidraScript {

	@Override
	protected void run() throws Exception {
		check("tasking-classic-large".equals(
			currentProgram.getLanguage().getProperty("c166.abi")),
			"real incremental test requires c166.abi=tasking-classic-large");
		Address entry = toAddr(0x2e6276);
		Function function = currentProgram.getFunctionManager().getFunctionAt(entry);
		check(function != null, "missing real fixture function at " + entry);

		C166TaskingTypeInferenceAnalyzer analyzer =
			new C166TaskingTypeInferenceAnalyzer();
		long start = System.nanoTime();
		MessageLog log = new MessageLog();
		check(analyzer.added(currentProgram, function.getBody(), monitor, log),
			"incremental type-inference pass failed: " + log);
		long millis = (System.nanoTime() - start) / 1_000_000;
		C166TaskingTypeInferenceAnalyzer.RunStatistics statistics =
			analyzer.getLastRunStatistics();
		check(!statistics.fullScan() && statistics.initialFunctions() == 1,
			"interactive scope widened before analysis: " + statistics);
		check(statistics.processedFunctions() <= 8,
			"interactive worklist expanded unexpectedly: " + statistics);
		check(statistics.heavyDecompilations() <= 12,
			"interactive analysis requested excessive decompilation: " + statistics);
		check(statistics.converged(),
			"interactive analysis did not converge: " + statistics);

		println("Real incremental type-inference performance passed: " + millis +
			" ms " + statistics + ".");
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
