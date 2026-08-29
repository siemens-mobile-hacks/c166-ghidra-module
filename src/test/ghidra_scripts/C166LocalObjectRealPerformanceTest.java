// Saved-program profile for exact local stack-object inference.
// @category C166.Tests

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidrainfineon.C166LocalObjectTypePhase;

public class C166LocalObjectRealPerformanceTest extends GhidraScript {

	@Override
	protected void run() throws Exception {
		check("tasking-classic-large".equals(
			currentProgram.getLanguage().getProperty("c166.abi")),
			"real local-object profile requires c166.abi=tasking-classic-large");
		C166LocalObjectTypePhase phase = new C166LocalObjectTypePhase();
		long start = System.nanoTime();
		check(phase.added(currentProgram, currentProgram.getMemory(), monitor,
			new MessageLog()), "local-object inference failed");
		long millis = (System.nanoTime() - start) / 1_000_000L;
		println("Real local-object performance passed: " + millis + " ms " +
			phase.getLastRunStatistics() + ".");
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
