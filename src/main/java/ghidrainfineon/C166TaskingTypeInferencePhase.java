package ghidrainfineon;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Internal, non-discoverable phase of unified TASKING type inference. */
abstract class C166TaskingTypeInferencePhase {
	private final String name;

	protected C166TaskingTypeInferencePhase(String name) {
		this.name = name;
	}

	public final String getName() {
		return name;
	}

	public boolean canAnalyze(Program program) {
		return C166ArchitectureProfile.isTaskingClassicLarge(program);
	}

	public abstract boolean added(Program program, AddressSetView set,
			TaskMonitor monitor, MessageLog log) throws CancelledException;
}
