// Saved-program profile for R5:R4 return classification.
// @category C166.Tests

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidrainfineon.C166PointerReturnPhase;

public class C166PointerReturnRealPerformanceTest extends GhidraScript {

	@Override
	protected void run() throws Exception {
		check("tasking-classic-large".equals(
			currentProgram.getLanguage().getProperty("c166.abi")),
			"real return profile requires c166.abi=tasking-classic-large");
		C166PointerReturnPhase phase = new C166PointerReturnPhase();
		long start = System.nanoTime();
		check(phase.added(currentProgram, currentProgram.getMemory(), monitor,
			new MessageLog()), "pointer-return classification failed");
		long millis = (System.nanoTime() - start) / 1_000_000L;
		C166PointerReturnPhase.RunStatistics statistics =
			phase.getLastRunStatistics();
		check(statistics.callers() == 30954 && statistics.inferredReturns() == 1 &&
			statistics.fixedPointRounds() == 2 && statistics.conflicts() == 10,
			"real pointer-return result changed: " + statistics);
		println("Real pointer-return performance passed: " + millis + " ms " +
			statistics + ".");
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
