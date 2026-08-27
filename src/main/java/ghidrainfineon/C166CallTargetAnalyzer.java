package ghidrainfineon;

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
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
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Extends the static C166 call graph from newly analyzed functions.  A full
 * memory scope, as supplied by One Shot without a selection, scans every
 * existing function.
 *
 * Ghidra normally follows direct calls while initially disassembling a flow, but
 * an imported/raw program can already contain isolated instructions without the
 * corresponding call targets having been disassembled.  This analyzer closes
 * that gap without performing an unsafe linear sweep over code and data.
 */
public class C166CallTargetAnalyzer extends AbstractAnalyzer {

	private static final int MAX_DIAGNOSTIC_EXAMPLES = 8;
	private static final int MAX_SWITCH_CASES = 256;
	private static final int MAX_SWITCH_RECOVERY_PASSES = 16;
	private final Set<Program> analyzedPrograms =
		Collections.newSetFromMap(new WeakHashMap<>());

	public C166CallTargetAnalyzer() {
		super("C166 Call Graph Analyzer",
			"Extends the static call graph from changed functions, disassembles known " +
				"call targets, and scans the whole program when run as a full One Shot.",
			AnalyzerType.INSTRUCTION_ANALYZER);
		// Run after function-start and ordinary function analyzers so the seed
		// queue really contains every function discovered by earlier passes.
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C166ArchitectureProfile.isTaskingClassicLarge(program);
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
		boolean fullScan = set == null || set.isEmpty() || set.contains(memory);
		Queue<Address> pendingFunctions = new ArrayDeque<>();
		Set<Address> queuedFunctions = new HashSet<>();
		Set<Address> processedFunctions = new HashSet<>();

		Iterator<Function> existingFunctions = fullScan
				? functions.getFunctions(true)
				: functions.getFunctionsOverlapping(set);
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
		int recoveredSwitchCount = 0;
		int recoveredSwitchTargetCount = 0;
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
			SwitchRecoveryStats switchStats = recoverSwitchTables(program, function,
				monitor, log);
			recoveredSwitchCount += switchStats.tables();
			recoveredSwitchTargetCount += switchStats.targets();
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
					boolean discoveredCode = false;
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
						discoveredCode = true;
					}
					acceptedTargets.add(target);

					if (!hasCallReference(references, instruction.getAddress(), target)) {
						references.addMemoryReference(instruction.getAddress(), target,
							instruction.getFlowType(), SourceType.ANALYSIS, Reference.MNEMONIC);
						referenceCount++;
					}

					Function targetFunction = functions.getFunctionContaining(target);
					boolean createdFunction = false;
					if (targetFunction == null) {
						CreateFunctionCmd createFunction = new CreateFunctionCmd(target);
						if (createFunction.applyTo(program, monitor)) {
							functionCount++;
							createdFunction = true;
							targetFunction = createFunction.getFunction();
						}
					}

					// A full One Shot walks every existing function.  Incremental analysis
					// follows only code/functions discovered from the changed seed set;
					// entering an already-known callee would reopen the whole old graph.
					if (targetFunction != null &&
						(fullScan || discoveredCode || createdFunction)) {
						Address targetEntry = targetFunction.getEntryPoint();
						if (queuedFunctions.add(targetEntry)) {
							pendingFunctions.add(targetEntry);
							monitor.setMaximum(monitor.getMaximum() + 1);
						}
					}
				}
			}
		}

		report(program, (fullScan ? "Full" : "Incremental") + " scan: " +
			scannedFunctionCount + " function(s) and " +
			callInstructionCount + " call instruction(s): " + targetOccurrenceCount +
			" target occurrence(s), " + uniqueTargets.size() + " unique, " +
			acceptedTargets.size() + " accepted.");
		report(program, "Changes: added " + referenceCount +
			" call reference(s), disassembled " + disassembledCount +
			" target(s), created " + functionCount + " function(s), recovered " +
			recoveredSwitchCount + " bounded switch table(s) with " +
			recoveredSwitchTargetCount + " case target(s)." +
			(referenceCount == 0 && disassembledCount == 0 && functionCount == 0 &&
				recoveredSwitchCount == 0
					? " Static call graph was already complete." : ""));
		appendDiagnostics(program, "Unmapped", unmapped);
		appendDiagnostics(program, "Non-executable", nonExecutable);
		appendDiagnostics(program, "Unaligned", unaligned);
		appendDiagnostics(program, "Defined data", definedData);
		appendDiagnostics(program, "Invalid code", invalidCode);
		appendDiagnostics(program, "Disassembly failed", failedDisassembly);
		return true;
	}

	/**
	 * Recover the exact bounded jump-table sequence emitted by TASKING Classic.
	 *
	 * <p>The compiler manual documents jump tables for dense switch statements.
	 * The generated sequence bounds an index, doubles it for a 16-bit table,
	 * loads a near code offset through EXTP/DPP, and performs an unconditional
	 * JMPI.  Every target is therefore a local basic block, never a function
	 * pointer.  Recovering these edges before call/type analysis prevents the
	 * decompiler from turning the branch into a spurious indirect call.</p>
	 */
	private SwitchRecoveryStats recoverSwitchTables(Program program, Function function,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		int tables = 0;
		int targets = 0;
		Set<Address> recovered = new HashSet<>();
		for (int pass = 0; pass < MAX_SWITCH_RECOVERY_PASSES; pass++) {
			monitor.checkCancelled();
			List<Instruction> candidates = new ArrayList<>();
			InstructionIterator instructions =
				program.getListing().getInstructions(function.getBody(), true);
			while (instructions.hasNext()) {
				Instruction instruction = instructions.next();
				if ("jmpi".equalsIgnoreCase(instruction.getMnemonicString()) &&
					!recovered.contains(instruction.getAddress())) {
					candidates.add(instruction);
				}
			}
			boolean changed = false;
			for (Instruction candidate : candidates) {
				monitor.checkCancelled();
				SwitchPattern pattern = matchSwitchPattern(program, function, candidate);
				if (pattern == null) {
					continue;
				}
				try {
					int recoveredTargets = applySwitchPattern(program, function, pattern,
						monitor);
					if (recoveredTargets != 0) {
						recovered.add(candidate.getAddress());
						tables++;
						targets += recoveredTargets;
						changed = true;
					}
				}
				catch (InvalidInputException e) {
					log.appendException(e);
				}
			}
			if (!changed) {
				break;
			}
		}
		return new SwitchRecoveryStats(tables, targets);
	}

	private SwitchPattern matchSwitchPattern(Program program, Function function,
			Instruction jump) {
		if (!isUnconditional(jump)) {
			return null;
		}
		Register jumpRegister = lastOperandRegister(jump);
		Instruction load = jump.getPrevious();
		if (jumpRegister == null || load == null ||
			!"mov".equalsIgnoreCase(load.getMnemonicString()) ||
			load.getNumOperands() < 2 ||
			!isIndirectOperand(load, 1) ||
			!sameRegister(jumpRegister, operandRegister(load, 0)) ||
			!sameRegister(jumpRegister, operandRegister(load, 1))) {
			return null;
		}

		Instruction cursor = load.getPrevious();
		Long page = null;
		if (cursor != null && "extp".equalsIgnoreCase(cursor.getMnemonicString())) {
			Scalar pageScalar = firstScalar(cursor);
			if (pageScalar == null) {
				return null;
			}
			page = pageScalar.getUnsignedValue() & 0x3ff;
			cursor = cursor.getPrevious();
		}
		if (cursor == null || !"add".equalsIgnoreCase(cursor.getMnemonicString()) ||
			!sameRegister(jumpRegister, operandRegister(cursor, 0))) {
			return null;
		}
		Scalar tableScalar = lastScalar(cursor);
		if (tableScalar == null) {
			return null;
		}
		long tableOffset = tableScalar.getUnsignedValue() & 0xffff;

		Instruction shift = cursor.getPrevious();
		if (shift == null || !"shl".equalsIgnoreCase(shift.getMnemonicString()) ||
			!sameRegister(jumpRegister, operandRegister(shift, 0)) ||
			lastScalarValue(shift) != 1) {
			return null;
		}
		Instruction guard = shift.getPrevious();
		Instruction compare = guard == null ? null : guard.getPrevious();
		if (guard == null || compare == null || !isUnsignedGreaterGuard(guard) ||
			!compare.getMnemonicString().toLowerCase().startsWith("cmp") ||
			!sameRegister(jumpRegister, operandRegister(compare, 0))) {
			return null;
		}
		Scalar maximum = lastScalar(compare);
		if (maximum == null || maximum.getUnsignedValue() >= MAX_SWITCH_CASES) {
			return null;
		}

		if (page == null) {
			int dppIndex = (int) ((tableOffset >>> 14) & 3);
			Register dpp = program.getRegister("DPP" + dppIndex);
			BigInteger value = dpp == null ? null : program.getProgramContext()
				.getValue(dpp, load.getAddress(), false);
			if (value == null) {
				return null;
			}
			page = value.longValue() & 0x3ff;
		}

		try {
			Address table = program.getAddressFactory().getDefaultAddressSpace().getAddress(
				(page << 14) | (tableOffset & 0x3fff));
			return validatedSwitchPattern(program, function, jump, table,
				(int) maximum.getUnsignedValue() + 1);
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

	private SwitchPattern validatedSwitchPattern(Program program, Function function,
			Instruction jump, Address table, int count) {
		Memory memory = program.getMemory();
		MemoryBlock tableBlock = memory.getBlock(table);
		if (count < 2 || count > MAX_SWITCH_CASES || tableBlock == null ||
			!tableBlock.isRead()) {
			return null;
		}
		long codeSegment = jump.getAddress().getUnsignedOffset() & 0xff0000L;
		ArrayList<Address> targets = new ArrayList<>(count);
		PseudoDisassembler pseudo = new PseudoDisassembler(program);
		for (int index = 0; index < count; index++) {
			try {
				Address entry = table.add(index * 2L);
				int offset = memory.getShort(entry) & 0xffff;
				Address target = jump.getAddress().getAddressSpace()
					.getAddress(codeSegment | offset);
				MemoryBlock targetBlock = memory.getBlock(target);
				Function containing =
					program.getFunctionManager().getFunctionContaining(target);
				if (targetBlock == null || !targetBlock.isExecute() ||
					(target.getUnsignedOffset() & 1) != 0 ||
					containing != null && !containing.equals(function)) {
					return null;
				}
				if (program.getListing().getInstructionAt(target) == null) {
					pseudo.disassemble(target);
				}
				targets.add(target);
			}
			catch (Exception e) {
				return null;
			}
		}
		return new SwitchPattern(jump, table, targets);
	}

	private int applySwitchPattern(Program program, Function function,
			SwitchPattern pattern, TaskMonitor monitor)
			throws InvalidInputException, CancelledException {
		Set<Address> uniqueTargets = new LinkedHashSet<>(pattern.targets());
		for (Address target : uniqueTargets) {
			if (program.getListing().getInstructionAt(target) == null) {
				DisassembleCommand command = new DisassembleCommand(target,
					program.getMemory().getExecuteSet(), true);
				command.enableCodeAnalysis(false);
				if (!command.applyTo(program, monitor) ||
					program.getListing().getInstructionAt(target) == null) {
					return 0;
				}
			}
			if (!hasReference(program.getReferenceManager(), pattern.jump().getAddress(),
				target, RefType.COMPUTED_JUMP)) {
				program.getReferenceManager().addMemoryReference(
					pattern.jump().getAddress(), target, RefType.COMPUTED_JUMP,
					SourceType.ANALYSIS, Reference.MNEMONIC);
			}
		}
		for (int index = 0; index < pattern.targets().size(); index++) {
			Address entry = pattern.table().add(index * 2L);
			if (program.getListing().getDefinedDataContaining(entry) == null) {
				try {
					DataUtilities.createData(program, entry,
						new UnsignedShortDataType(program.getDataTypeManager()), 2,
						false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
				}
				catch (Exception e) {
					// References and the override remain sufficient when an existing
					// non-default data definition intentionally owns the table bytes.
				}
			}
		}
		CreateFunctionCmd.fixupFunctionBody(program, function, monitor);
		new JumpTable(pattern.jump().getAddress(), pattern.targets(), true, 0)
			.writeOverride(function);
		return pattern.targets().size();
	}

	private boolean hasReference(ReferenceManager references, Address from,
			Address to, RefType type) {
		for (Reference reference : references.getReferencesFrom(from)) {
			if (reference.getToAddress().equals(to) && reference.getReferenceType().equals(type)) {
				return true;
			}
		}
		return false;
	}

	private boolean isUnconditional(Instruction instruction) {
		if (!instruction.getFlowType().isJump() || instruction.getFlowType().isConditional()) {
			return false;
		}
		for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
			String representation = instruction.getDefaultOperandRepresentation(operand);
			if (representation != null && representation.toLowerCase().contains("cc_uc")) {
				return true;
			}
		}
		return false;
	}

	private boolean isUnsignedGreaterGuard(Instruction instruction) {
		if (!instruction.getFlowType().isJump() || !instruction.getFlowType().isConditional()) {
			return false;
		}
		for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
			String representation = instruction.getDefaultOperandRepresentation(operand);
			if (representation != null && representation.toLowerCase().contains("cc_ugt")) {
				return true;
			}
		}
		return false;
	}

	private Register lastOperandRegister(Instruction instruction) {
		for (int operand = instruction.getNumOperands() - 1; operand >= 0; operand--) {
			Register register = operandRegister(instruction, operand);
			if (register != null) {
				return register;
			}
		}
		return null;
	}

	private Register operandRegister(Instruction instruction, int operand) {
		if (operand < 0 || operand >= instruction.getNumOperands()) {
			return null;
		}
		for (Object object : instruction.getOpObjects(operand)) {
			if (object instanceof Register register) {
				return register;
			}
		}
		return null;
	}

	private boolean isIndirectOperand(Instruction instruction, int operand) {
		Register register = operandRegister(instruction, operand);
		if (register == null) {
			return false;
		}
		String rendered = instruction.toString().replace(" ", "").toLowerCase();
		return rendered.contains("[" + register.getName().toLowerCase() + "]");
	}

	private boolean sameRegister(Register first, Register second) {
		return first != null && second != null &&
			first.getAddress().equals(second.getAddress()) &&
			first.getMinimumByteSize() == second.getMinimumByteSize();
	}

	private Scalar firstScalar(Instruction instruction) {
		for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
			for (Object object : instruction.getOpObjects(operand)) {
				if (object instanceof Scalar scalar) {
					return scalar;
				}
			}
		}
		return null;
	}

	private Scalar lastScalar(Instruction instruction) {
		for (int operand = instruction.getNumOperands() - 1; operand >= 0; operand--) {
			Object[] objects = instruction.getOpObjects(operand);
			for (int index = objects.length - 1; index >= 0; index--) {
				if (objects[index] instanceof Scalar scalar) {
					return scalar;
				}
			}
		}
		return null;
	}

	private long lastScalarValue(Instruction instruction) {
		Scalar scalar = lastScalar(instruction);
		return scalar == null ? -1 : scalar.getUnsignedValue();
	}

	private record SwitchPattern(Instruction jump, Address table,
		ArrayList<Address> targets) {
	}

	private record SwitchRecoveryStats(int tables, int targets) {
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
		// On C166, deleting the only stored call reference can also make
		// Instruction.getFlows() empty.  The direct CALL target is still present
		// in the instruction p-code, so use it to make analysis xrefs rebuildable.
		for (PcodeOp operation : instruction.getPcode()) {
			if (operation.getOpcode() == PcodeOp.CALL && operation.getNumInputs() != 0) {
				Address target = operation.getInput(0).getAddress();
				if (target != null && target.isMemoryAddress()) {
					targets.add(target);
				}
			}
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
