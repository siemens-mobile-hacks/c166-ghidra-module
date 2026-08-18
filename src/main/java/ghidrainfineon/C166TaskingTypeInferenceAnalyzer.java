package ghidrainfineon;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Owns TASKING Classic Large type inference as one ordered analysis pass.
 *
 * <p>The individual implementations are ordinary internal phases rather than
 * Ghidra analyzers. This coordinator is therefore the sole scheduler-visible
 * owner of analyzer-generated C166 parameter, return, and variadic call-site
 * types.</p>
 */
public class C166TaskingTypeInferenceAnalyzer extends AbstractAnalyzer {

	public C166TaskingTypeInferenceAnalyzer() {
		super("C166 TASKING Type Inference",
			"Classifies TASKING parameters as scalars, data pointers, or function " +
				"pointers in one ordered pass.",
			AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C166ArchitectureProfile.isTaskingClassicLarge(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		/*
		 * Variadic overrides affect the CALL inputs seen by the pointer phases, so
		 * bootstrap them before collecting evidence and rebuild them after the
		 * final parameter and return types are known.  Code/scalar evidence runs
		 * before far-data evidence: an actual far-indirect use is authoritative,
		 * while an analyzer-owned generic fpointer based only on an address-shaped
		 * constant may still be repaired by a real paged data access.
		 */
		boolean success = runPhase("ABI data types", new C166TaskingDataTypePhase(),
			program, set, monitor, log);
		success &= runPhase("variadic bootstrap", new C166VariadicCallPhase(),
			program, set, monitor, log);
		success &= runPhase("code/scalar classification", new C166CodePointerPhase(),
			program, set, monitor, log);
		success &= runPhase("far-data classification", new C166FarPointerPhase(),
			program, set, monitor, log);
		success &= runPhase("pointer returns", new C166PointerReturnPhase(),
			program, set, monitor, log);
		success &= runPhase("variadic finalization", new C166VariadicCallPhase(),
			program, set, monitor, log);
		return success;
	}

	private boolean runPhase(String name, C166TaskingTypeInferencePhase phase,
			Program program,
			AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		monitor.checkCancelled();
		monitor.setMessage("C166 TASKING type inference: " + name);
		boolean success = phase.added(program, set, monitor, log);
		if (!success) {
			Msg.error(this, "C166 TASKING type inference phase failed: " + name);
		}
		return success;
	}
}
