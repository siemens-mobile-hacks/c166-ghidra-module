package ghidrainfineon;

import java.util.ArrayDeque;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Queue;
import java.util.Set;
import java.util.WeakHashMap;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Builds the static C166 call graph from every existing function.
 *
 * Ghidra normally follows direct calls while initially disassembling a flow, but
 * an imported/raw program can already contain isolated instructions without the
 * corresponding call targets having been disassembled.  This analyzer closes
 * that gap without performing an unsafe linear sweep over code and data.
 */
public class C166CallTargetAnalyzer extends AbstractAnalyzer {

	private static final int MAX_DIAGNOSTIC_EXAMPLES = 8;
	private static final Set<String> SUPPORTED_PROCESSORS =
		Set.of("Infineon C167CR", "Infineon C167CS");
	private final Set<Program> analyzedPrograms =
		Collections.newSetFromMap(new WeakHashMap<>());

	public C166CallTargetAnalyzer() {
		super("C166 Call Graph Analyzer",
			"Builds the static call graph from all existing functions, disassembles " +
				"known call targets, and creates missing functions.",
			AnalyzerType.INSTRUCTION_ANALYZER);
		// Run after function-start and ordinary function analyzers so the seed
		// queue really contains every function discovered by earlier passes.
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return SUPPORTED_PROCESSORS.contains(
			program.getLanguage().getProcessor().toString());
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		synchronized (analyzedPrograms) {
			if (!analyzedPrograms.add(program)) {
				return true;
			}
		}

		Listing listing = program.getListing();
		Memory memory = program.getMemory();
		FunctionManager functions = program.getFunctionManager();
		ReferenceManager references = program.getReferenceManager();
		Queue<Address> pendingFunctions = new ArrayDeque<>();
		Set<Address> queuedFunctions = new HashSet<>();
		Set<Address> processedFunctions = new HashSet<>();

		FunctionIterator existingFunctions = functions.getFunctions(true);
		while (existingFunctions.hasNext()) {
			Address entry = existingFunctions.next().getEntryPoint();
			if (queuedFunctions.add(entry)) {
				pendingFunctions.add(entry);
			}
		}

		monitor.initialize(pendingFunctions.size());
		int disassembledCount = 0;
		int functionCount = 0;
		int referenceCount = 0;
		int scannedFunctionCount = 0;
		int callInstructionCount = 0;
		int targetOccurrenceCount = 0;
		Set<Address> uniqueTargets = new HashSet<>();
		Set<Address> acceptedTargets = new HashSet<>();
		TargetDiagnostics unmapped = new TargetDiagnostics();
		TargetDiagnostics nonExecutable = new TargetDiagnostics();
		TargetDiagnostics unaligned = new TargetDiagnostics();
		TargetDiagnostics definedData = new TargetDiagnostics();
		TargetDiagnostics invalidCode = new TargetDiagnostics();
		TargetDiagnostics failedDisassembly = new TargetDiagnostics();

		while (!pendingFunctions.isEmpty()) {
			monitor.checkCancelled();
			Address functionEntry = pendingFunctions.remove();
			if (!processedFunctions.add(functionEntry)) {
				continue;
			}
			Function function = functions.getFunctionAt(functionEntry);
			if (function == null || function.isExternal()) {
				continue;
			}

			scannedFunctionCount++;
			monitor.setMessage("C166 call graph: " + function.getName());
			monitor.incrementProgress(1);
			InstructionIterator instructions = listing.getInstructions(function.getBody(), true);

			while (instructions.hasNext()) {
				monitor.checkCancelled();
				Instruction instruction = instructions.next();
				if (!instruction.getFlowType().isCall()) {
					continue;
				}
				callInstructionCount++;

				for (Address target : getCallTargets(program, instruction)) {
					monitor.checkCancelled();
					targetOccurrenceCount++;
					uniqueTargets.add(target);
					Address source = instruction.getAddress();
					MemoryBlock block = memory.getBlock(target);
					if (block == null) {
						unmapped.record(source, target, null);
						continue;
					}
					if (!block.isExecute()) {
						nonExecutable.record(source, target,
							"block=" + block.getName() + " " + permissions(block));
						continue;
					}

					int alignment = program.getLanguage().getInstructionAlignment();
					if (alignment > 1 && Long.remainderUnsigned(target.getOffset(), alignment) != 0) {
						unaligned.record(source, target, "alignment=" + alignment);
						continue;
					}

					Instruction targetInstruction = listing.getInstructionAt(target);
					if (targetInstruction == null) {
						// Never replace user-defined data merely because a call points at it.
						if (listing.getDefinedDataContaining(target) != null) {
							definedData.record(source, target,
								"type=" + listing.getDefinedDataContaining(target)
									.getDataType().getDisplayName());
							continue;
						}

						// A direct-flow edge is useful evidence, but malformed instructions and
						// stale references must not turn arbitrary executable bytes into functions.
						PseudoDisassembler pseudoDisassembler = new PseudoDisassembler(program);
						pseudoDisassembler.setMaxInstructions(20);
						if (!pseudoDisassembler.checkValidSubroutine(target, true, false, true) ||
							pseudoDisassembler.getLastCheckValidInstructionCount() < 2) {
							invalidCode.record(source, target,
								"valid-instructions=" +
									pseudoDisassembler.getLastCheckValidInstructionCount());
							continue;
						}

						DisassembleCommand disassemble =
							new DisassembleCommand(target, memory.getExecuteSet(), true);
						disassemble.enableCodeAnalysis(false);
						if (!disassemble.applyTo(program, monitor)) {
							failedDisassembly.record(source, target,
								normalizeStatus(disassemble.getStatusMsg()));
							continue;
						}
						targetInstruction = listing.getInstructionAt(target);
						if (targetInstruction == null) {
							failedDisassembly.record(source, target,
								"command succeeded but created no instruction");
							continue;
						}
						disassembledCount++;
					}
					acceptedTargets.add(target);

					if (!hasCallReference(references, instruction.getAddress(), target)) {
						references.addMemoryReference(instruction.getAddress(), target,
							instruction.getFlowType(), SourceType.ANALYSIS, Reference.MNEMONIC);
						referenceCount++;
					}

					Function targetFunction = functions.getFunctionContaining(target);
					if (targetFunction == null) {
						CreateFunctionCmd createFunction = new CreateFunctionCmd(target);
						if (createFunction.applyTo(program, monitor)) {
							functionCount++;
							targetFunction = createFunction.getFunction();
					}
					}

					if (targetFunction != null) {
						Address targetEntry = targetFunction.getEntryPoint();
						if (queuedFunctions.add(targetEntry)) {
							pendingFunctions.add(targetEntry);
							monitor.setMaximum(monitor.getMaximum() + 1);
						}
					}
				}
			}
		}

		report(program, "Scanned " + scannedFunctionCount + " function(s) and " +
			callInstructionCount + " call instruction(s): " + targetOccurrenceCount +
			" target occurrence(s), " + uniqueTargets.size() + " unique, " +
			acceptedTargets.size() + " accepted.");
		report(program, "Changes: added " + referenceCount +
			" call reference(s), disassembled " + disassembledCount +
			" target(s), created " + functionCount + " function(s)." +
			(referenceCount == 0 && disassembledCount == 0 && functionCount == 0
					? " Static call graph was already complete." : ""));
		appendDiagnostics(program, "Unmapped", unmapped);
		appendDiagnostics(program, "Non-executable", nonExecutable);
		appendDiagnostics(program, "Unaligned", unaligned);
		appendDiagnostics(program, "Defined data", definedData);
		appendDiagnostics(program, "Invalid code", invalidCode);
		appendDiagnostics(program, "Disassembly failed", failedDisassembly);
		return true;
	}

	@Override
	public void analysisEnded(Program program) {
		synchronized (analyzedPrograms) {
			analyzedPrograms.remove(program);
		}
	}

	private boolean hasCallReference(ReferenceManager references, Address from, Address to) {
		for (Reference reference : references.getReferencesFrom(from)) {
			if (reference.getReferenceType().isCall() && reference.isMemoryReference() &&
				reference.getToAddress().equals(to)) {
				return true;
			}
		}
		return false;
	}

	private Set<Address> getCallTargets(Program program, Instruction instruction) {
		Set<Address> targets = new LinkedHashSet<>();
		for (Address target : instruction.getFlows()) {
			targets.add(target);
		}

		Reference[] references =
			program.getReferenceManager().getReferencesFrom(instruction.getAddress());
		for (Reference reference : references) {
			if (reference.getReferenceType().isCall() && reference.isMemoryReference()) {
				targets.add(reference.getToAddress());
			}
		}
		return targets;
	}

	private void appendDiagnostics(Program program, String label,
			TargetDiagnostics diagnostics) {
		if (diagnostics.occurrences == 0) {
			return;
		}
		report(program, label + ": " + diagnostics.occurrences +
			" occurrence(s), " + diagnostics.uniqueTargets.size() + " unique target(s)." +
			" Examples: " + String.join(", ", diagnostics.examples));
	}

	private void report(Program program, String message) {
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
		PluginTool tool = manager.getAnalysisTool();
		if (tool != null) {
			ConsoleService console = tool.getService(ConsoleService.class);
			if (console != null) {
				console.addMessage(getName(), message);
				return;
			}
		}
		Msg.info(this, getName() + "> " + message);
	}

	private String permissions(MemoryBlock block) {
		return (block.isRead() ? "r" : "-") + (block.isWrite() ? "w" : "-") +
			(block.isExecute() ? "x" : "-");
	}

	private String normalizeStatus(String status) {
		return status == null || status.isBlank() ? "no status message" : status;
	}

	private static class TargetDiagnostics {
		private int occurrences;
		private final Set<Address> uniqueTargets = new HashSet<>();
		private final Set<String> examples = new LinkedHashSet<>();

		void record(Address source, Address target, String detail) {
			occurrences++;
			uniqueTargets.add(target);
			if (examples.size() >= MAX_DIAGNOSTIC_EXAMPLES) {
				return;
			}
			String example = source + " -> " + target;
			if (detail != null && !detail.isBlank()) {
				example += " (" + detail + ")";
			}
			examples.add(example);
		}
	}
}
