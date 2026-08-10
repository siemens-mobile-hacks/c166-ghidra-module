package ghidrainfineon;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.OperandReferenceAnalyzer;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Infers TASKING Classic far-pointer parameters from their documented memory
 * access semantics.
 * <p>
 * The C166/ST10 Classic 7.5 C compiler manual specifies four consecutive
 * parameter slots (R12-R15), a four-byte PAGE:OFFSET far pointer, stack spill
 * after the register bank is exhausted, and DPP0 as the scratch page register
 * used for far-pointer dereferences.  On targets using the extended instruction
 * set, EXTP provides the same paged access.  The decompiler normalizes both
 * forms to SEGMENTOP(page, offset).  A register or stack pair is therefore
 * joined only when its high word reaches PAGE and its adjacent low word reaches
 * OFFSET.
 * <p>
 * No function names, firmware addresses, constant values, strings, or mapped
 * data are used as evidence.
 */
public class C166FarPointerAnalyzer extends AbstractAnalyzer {

	private static final String COMPILER_ID = "tasking-classic-large";
	private static final String CALLING_CONVENTION = "__tasking_c166_classic";
	private static final int FIRST_ARGUMENT_REGISTER = 12;
	private static final int LAST_ARGUMENT_REGISTER = 15;
	private static final int DECOMPILE_TIMEOUT_SECONDS = 30;
	private static final int MAX_TRACE_DEPTH = 32;
	private static final int MAX_SETUP_SCAN_INSTRUCTIONS = 256;

	public C166FarPointerAnalyzer() {
		super("C166 TASKING Far Pointer Inference",
			"Joins PAGE:OFFSET parameter words proven by paged-memory data flow.",
			AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after().after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguageID().getIdAsString().startsWith("C166:") &&
			COMPILER_ID.equals(
				program.getCompilerSpec().getCompilerSpecID().getIdAsString());
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		boolean fullScan = set == null || set.isEmpty() || set.contains(program.getMemory());
		int legacyReferencesRemoved =
			removeLegacyCallReferences(program, set, fullScan, monitor);
		CandidateGraph graph = buildCandidateGraph(program, set, fullScan, monitor);
		SccSchedule schedule = buildSccSchedule(graph, monitor);
		monitor.initialize(Math.max(1, graph.functions().size()),
			"C166 far-pointer inference: decompiling candidates");
		if (graph.functions().isEmpty()) {
			monitor.setProgress(1);
		}
		AnalysisStats stats = new AnalysisStats();

		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(false);
		decompiler.toggleSyntaxTree(true);
		if (!decompiler.openProgram(program)) {
			report(program, "Decompiler initialization failed: " + decompiler.getLastMessage());
			return false;
		}

		try {
			for (int layerIndex = 0; layerIndex < schedule.layers().size(); layerIndex++) {
				boolean layerChanged = false;
				for (int componentIndex : schedule.layers().get(layerIndex)) {
					layerChanged |= analyzeComponent(program, decompiler,
						schedule.components().get(componentIndex), graph.callees(), stats,
						monitor, log);
				}
				if (layerChanged && layerIndex + 1 < schedule.layers().size()) {
					decompiler.flushCache();
				}
			}
		}
		finally {
			decompiler.dispose();
		}
		scheduleReferenceAnalysis(program, stats.referenceSources);

		report(program, (fullScan ? "Full" : "Incremental") + " scan: inspected " +
			stats.inspected.size() +
			" direct or forwarding function(s) in " + stats.decompilations +
			" decompilation(s) across " + schedule.components().size() +
			" call-graph component(s); inferred " + stats.inferredPointers +
			" far-pointer parameter(s) in " + stats.inferredFunctions +
			" function(s), added or updated " + stats.referenceCount +
			" physical far-pointer reference(s), queued Reference analysis for " +
			stats.referenceSources.getNumAddresses() +
			" parameter setup instruction(s), created " + stats.globalPointersCreated +
			" global far-pointer object(s), " +
			"removed " + legacyReferencesRemoved + " legacy call-site reference(s), " +
			stats.ambiguousFunctions.size() + " ambiguous, " + stats.failedFunctions.size() +
			" decompilation failure(s), " + stats.recursivePasses +
			" recursive fixed-point pass(es), " + stats.nonConvergentComponents +
			" non-convergent component(s).");
		return true;
	}

	private boolean analyzeComponent(Program program, DecompInterface decompiler,
			List<Function> component, Map<Function, Set<Function>> callees,
			AnalysisStats stats, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		boolean recursive = component.size() > 1 ||
			callees.getOrDefault(component.get(0), Set.of()).contains(component.get(0));
		Set<String> seenSignatures = new HashSet<>();
		boolean anyChange = false;
		boolean firstPass = true;
		while (true) {
			monitor.checkCancelled();
			String signatureState = componentSignatureState(component);
			if (!seenSignatures.add(signatureState)) {
				stats.nonConvergentComponents++;
				break;
			}

			List<Function> passFunctions = new ArrayList<>();
			for (Function function : component) {
				if (!stats.failedFunctions.contains(function)) {
					passFunctions.add(function);
				}
			}
			if (passFunctions.isEmpty()) {
				break;
			}
			if (!firstPass) {
				stats.recursivePasses++;
				monitor.setMaximum(monitor.getMaximum() + passFunctions.size());
				decompiler.flushCache();
			}

			boolean passChanged = false;
			for (Function function : passFunctions) {
				passChanged |= analyzeFunction(program, decompiler, function, stats,
					monitor, log);
			}
			anyChange |= passChanged;
			if (!recursive || !passChanged) {
				break;
			}
			firstPass = false;
		}
		return anyChange;
	}

	private boolean analyzeFunction(Program program, DecompInterface decompiler,
			Function function, AnalysisStats stats, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		monitor.checkCancelled();
		stats.inspected.add(function);
		stats.decompilations++;
		try {
			monitor.setMessage("C166 far-pointer inference (" +
				(stats.processedCandidates + 1) + "/" + monitor.getMaximum() + "): " +
				function.getName());
			DecompileResults result = decompiler.decompileFunction(function,
				DECOMPILE_TIMEOUT_SECONDS, monitor);
			if (!result.decompileCompleted() || result.getHighFunction() == null) {
				stats.failedFunctions.add(function);
				return false;
			}

			// DecompileCallback warnings do not make a partial HighFunction
			// unusable.  Keep all recovered p-code; scheduling, not warning text,
			// determines whether a recursive component needs another pass.
			stats.referenceCount += addFarPointerReferences(program,
				result.getHighFunction().getPcodeOps(), stats.referenceSources);
			Inference inference = inferPairs(program, function, result.getHighFunction());
			stats.globalPointersCreated += defineGlobalFarPointers(program,
				inference.globalPointerStarts());
			if (inference.ambiguous()) {
				stats.ambiguousFunctions.add(function);
				return false;
			}
			Set<Integer> pairStarts = retainSupportedPairs(function, inference.pairStarts(),
				inference.liveSlots());
			if (pairStarts.isEmpty() || signatureMatches(function, pairStarts,
				inference.liveSlots(), inference.pointerTypes())) {
				return false;
			}

			updateSignature(program, function, pairStarts, inference.liveSlots(),
				inference.pointerTypes());
			stats.inferredFunctions++;
			stats.inferredPointers += pairStarts.size();
			return true;
		}
		catch (DuplicateNameException | InvalidInputException e) {
			log.appendException(e);
			stats.failedFunctions.add(function);
			return false;
		}
		finally {
			stats.processedCandidates++;
			monitor.setProgress(stats.processedCandidates);
		}
	}

	private String componentSignatureState(List<Function> component) {
		StringBuilder state = new StringBuilder();
		for (Function function : component) {
			state.append(function.getEntryPoint()).append(':')
				.append(function.getPrototypeString(true, true));
			for (Parameter parameter : function.getParameters()) {
				state.append('|').append(parameter.getFormalDataType().getPathName())
					.append('@').append(parameter.getVariableStorage());
			}
			state.append(';');
		}
		return state.toString();
	}

	private static final class AnalysisStats {
		private final Set<Function> inspected = new HashSet<>();
		private final Set<Function> ambiguousFunctions = new HashSet<>();
		private final Set<Function> failedFunctions = new HashSet<>();
		private final AddressSet referenceSources = new AddressSet();
		private int processedCandidates;
		private int decompilations;
		private int inferredFunctions;
		private int inferredPointers;
		private int referenceCount;
		private int globalPointersCreated;
		private int recursivePasses;
		private int nonConvergentComponents;
	}

	private record CandidateGraph(Set<Function> functions,
			Map<Function, Set<Function>> callees) {
	}

	private record SccSchedule(List<List<Function>> components,
			List<List<Integer>> layers) {
	}

	private record DfsFrame(Function function, Iterator<Function> targets) {
	}

	private int removeLegacyCallReferences(Program program, AddressSetView set,
			boolean fullScan, TaskMonitor monitor)
			throws CancelledException {
		ReferenceManager references = program.getReferenceManager();
		InstructionIterator instructions = fullScan
				? program.getListing().getInstructions(true)
				: program.getListing().getInstructions(set, true);
		int removed = 0;
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			Instruction instruction = instructions.next();
			if (!instruction.getFlowType().isCall()) {
				continue;
			}
			for (Reference reference : instruction.getReferencesFrom()) {
				RefType type = reference.getReferenceType();
				if (reference.getOperandIndex() == Reference.MNEMONIC &&
					reference.getSource() == SourceType.ANALYSIS &&
					(type == RefType.DATA || type == RefType.READ)) {
					references.delete(reference);
					removed++;
				}
			}
		}
		return removed;
	}

	private int addFarPointerReferences(Program program, Iterator<PcodeOpAST> operations,
			AddressSet referenceSources) {
		ReferenceManager references = program.getReferenceManager();
		int added = 0;
		while (operations.hasNext()) {
			PcodeOpAST operation = operations.next();
			if (operation.getOpcode() != PcodeOp.CALL || operation.getNumInputs() < 2) {
				continue;
			}
			Function target = program.getFunctionManager()
				.getFunctionAt(operation.getInput(0).getAddress());
			if (target == null || !usesTaskingConvention(target)) {
				continue;
			}
			Parameter[] parameters = target.getParameters();
			int count = Math.min(parameters.length, operation.getNumInputs() - 1);
			for (int i = 0; i < count; i++) {
				DataType type = parameters[i].getFormalDataType();
				if (!(type instanceof Pointer) || type.getLength() != 4) {
					continue;
				}
				Address targetAddress = resolvePhysicalPointer(program, operation.getInput(i + 1),
					new HashSet<>(), 0);
				if (targetAddress == null || !program.getMemory().contains(targetAddress)) {
					continue;
				}
				Address callSource = operation.getSeqnum().getTarget();
				Address source = findPointerSetupSource(program, callSource, targetAddress,
					parameters[i].getVariableStorage());
				if (source == null) {
					source = callSource;
				}
				referenceSources.add(source);
				removeLegacyCallReference(references, callSource, targetAddress, source);
				Reference existing =
					references.getReference(source, targetAddress, Reference.MNEMONIC);
				if (existing == null) {
					references.addMemoryReference(source, targetAddress, RefType.PARAM,
						SourceType.ANALYSIS, Reference.MNEMONIC);
					added++;
				}
				else if (!existing.getReferenceType().isFlow() &&
					existing.getReferenceType() != RefType.PARAM) {
					references.updateRefType(existing, RefType.PARAM);
					added++;
				}
			}
		}
		return added;
	}

	private void removeLegacyCallReference(ReferenceManager references, Address callSource,
			Address targetAddress, Address replacementSource) {
		if (callSource.equals(replacementSource)) {
			return;
		}
		Reference legacy =
			references.getReference(callSource, targetAddress, Reference.MNEMONIC);
		if (legacy != null && legacy.getSource() == SourceType.ANALYSIS &&
			!legacy.getReferenceType().isFlow()) {
			references.delete(legacy);
		}
	}

	/**
	 * Match Ghidra's constant-propagation convention: a PARAM reference belongs
	 * to the instruction which materializes the argument, not to the call itself.
	 * A TASKING far pointer is materialized as its documented PAGE and OFFSET
	 * words, normally in the two registers assigned to the formal parameter.
	 */
	private Address findPointerSetupSource(Program program, Address callSource,
			Address targetAddress, VariableStorage storage) {
		long physical = targetAddress.getUnsignedOffset();
		long offset = physical & 0x3fff;
		long page = physical >>> 14;
		Register lowRegister = null;
		Register highRegister = null;
		List<Register> registers = storage.getRegisters();
		if (registers != null && registers.size() == 2) {
			Register first = registers.get(0);
			Register second = registers.get(1);
			Integer firstNumber = generalRegisterNumber(first);
			Integer secondNumber = generalRegisterNumber(second);
			if (firstNumber != null && secondNumber != null) {
				if (firstNumber < secondNumber) {
					lowRegister = first;
					highRegister = second;
				}
				else {
					lowRegister = second;
					highRegister = first;
				}
			}
		}

		Address source = scanPointerSetupSource(program, callSource, offset, page, lowRegister,
			highRegister);
		if (source != null || lowRegister == null || highRegister == null) {
			return source;
		}
		return scanPointerSetupSource(program, callSource, offset, page, null, null);
	}

	private Address scanPointerSetupSource(Program program, Address callSource, long offset,
			long page, Register lowRegister, Register highRegister) {
		Address lowSource = null;
		Address highSource = null;
		Function caller = program.getFunctionManager().getFunctionContaining(callSource);
		Instruction instruction = program.getListing().getInstructionBefore(callSource);
		for (int scanned = 0; instruction != null && scanned < MAX_SETUP_SCAN_INSTRUCTIONS;
				scanned++, instruction = program.getListing().getInstructionBefore(
					instruction.getAddress())) {
			if (caller != null && !caller.getBody().contains(instruction.getAddress())) {
				break;
			}
			Register destination = instruction.getRegister(0);
			Scalar immediate = instruction.getScalar(1);
			if (destination == null || immediate == null) {
				continue;
			}
			long value = immediate.getUnsignedValue();
			if (lowSource == null && value == offset &&
				(lowRegister == null || destination.equals(lowRegister))) {
				lowSource = instruction.getAddress();
			}
			if (highSource == null && value == page &&
				(highRegister == null || destination.equals(highRegister))) {
				highSource = instruction.getAddress();
			}
			if (lowSource != null && highSource != null) {
				if (lowRegister == null || highRegister == null) {
					// A stack argument has no identifying register pair and adjacent
					// far pointers commonly share the same PAGE.  OFFSET is unique;
					// anchoring there avoids borrowing a neighbour's PAGE setup.
					return lowSource;
				}
				// Anchor the reference where the second word completes the far
				// pointer, matching Ghidra's constant-propagation convention.
				return lowSource.compareTo(highSource) > 0 ? lowSource : highSource;
			}
		}
		if (lowSource != null) {
			return lowSource;
		}
		return highSource;
	}

	private Integer generalRegisterNumber(Register register) {
		if (register == null) {
			return null;
		}
		String name = register.getName().toLowerCase();
		if (!name.matches("r(?:[0-9]|1[0-5])")) {
			return null;
		}
		return Integer.parseInt(name.substring(1));
	}

	private void scheduleReferenceAnalysis(Program program, AddressSet referenceSources) {
		if (referenceSources.isEmpty()) {
			return;
		}
		AutoAnalysisManager.getAnalysisManager(program).scheduleOneTimeAnalysis(
			new OperandReferenceAnalyzer(), referenceSources);
	}

	private Address resolvePhysicalPointer(Program program, Varnode value,
			Set<Varnode> visited, int depth) {
		if (value == null || depth > MAX_TRACE_DEPTH || !visited.add(value)) {
			return null;
		}
		if (value.isConstant()) {
			return normalizePointerAddress(program, value.getOffset());
		}
		if (value.getDef() == null) {
			return null;
		}
		PcodeOp definition = value.getDef();
		switch (definition.getOpcode()) {
			case PcodeOp.COPY:
			case PcodeOp.CAST:
			case PcodeOp.INT_ZEXT:
				return resolvePhysicalPointer(program, definition.getInput(0), visited, depth + 1);
			case PcodeOp.SEGMENTOP:
				if (definition.getNumInputs() == 3) {
					Long page = constantValue(definition.getInput(1), new HashSet<>(), 0);
					Long offset = constantValue(definition.getInput(2), new HashSet<>(), 0);
					if (page != null && offset != null) {
						return physicalPointerAddress(program, page, offset);
					}
				}
				return null;
			case PcodeOp.PIECE:
				if (definition.getNumInputs() == 2) {
					Long page = constantValue(definition.getInput(0), new HashSet<>(), 0);
					Long offset = constantValue(definition.getInput(1), new HashSet<>(), 0);
					if (page != null && offset != null) {
						return physicalPointerAddress(program, page, offset);
					}
				}
				return null;
			case PcodeOp.PTRSUB:
			case PcodeOp.PTRADD:
				Address address = HighFunctionDBUtil.getSpacebaseReferenceAddress(
					program.getAddressFactory(), definition);
				if (address == null && definition.getNumInputs() > 1 &&
					definition.getInput(1).isConstant()) {
					return normalizePointerAddress(program,
						definition.getInput(1).getOffset());
				}
				return address == null ? null :
					normalizePointerAddress(program, address.getUnsignedOffset());
			default:
				return null;
		}
	}

	private Address physicalPointerAddress(Program program, long page, long offset) {
		long physical = ((page & 0x3ff) << 14) | (offset & 0x3fff);
		Address address = address(program.getLanguage().getDefaultDataSpace(), physical);
		return address != null && program.getMemory().contains(address) ? address : null;
	}

	private Long constantValue(Varnode value, Set<Varnode> visited, int depth) {
		if (value == null || depth > MAX_TRACE_DEPTH || !visited.add(value)) {
			return null;
		}
		if (value.isConstant()) {
			return value.getOffset();
		}
		PcodeOp definition = value.getDef();
		if (definition == null) {
			return null;
		}
		switch (definition.getOpcode()) {
			case PcodeOp.COPY:
			case PcodeOp.CAST:
			case PcodeOp.INT_ZEXT:
			case PcodeOp.INT_SEXT:
				return constantValue(definition.getInput(0), visited, depth + 1);
			case PcodeOp.INT_AND:
			case PcodeOp.INT_OR:
			case PcodeOp.INT_ADD:
			case PcodeOp.INT_SUB:
				Long left = constantValue(definition.getInput(0), visited, depth + 1);
				Long right = constantValue(definition.getInput(1), visited, depth + 1);
				if (left == null || right == null) {
					return null;
				}
				return switch (definition.getOpcode()) {
					case PcodeOp.INT_AND -> left & right;
					case PcodeOp.INT_OR -> left | right;
					case PcodeOp.INT_ADD -> left + right;
					default -> left - right;
				};
			default:
				return null;
		}
	}

	private Address normalizePointerAddress(Program program, long value) {
		AddressSpace space = program.getLanguage().getDefaultDataSpace();
		Address direct = address(space, value);
		if (direct != null && program.getMemory().contains(direct)) {
			return direct;
		}

		// TASKING Classic stores a far pointer as PAGE:OFFSET, while the
		// program database uses the physical 24-bit address.  Defined string
		// constants can retain the raw encoding in high p-code, so decode it
		// only when the direct value is not a mapped program address.
		long page = (value >>> 16) & 0xffff;
		long offset = value & 0xffff;
		long physical = ((page & 0x3ff) << 14) | (offset & 0x3fff);
		Address decoded = address(space, physical);
		if (decoded != null && program.getMemory().contains(decoded)) {
			return decoded;
		}
		return direct;
	}

	private Address address(AddressSpace space, long offset) {
		try {
			return space.getAddress(offset, true);
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

	private CandidateGraph buildCandidateGraph(Program program, AddressSetView set,
			boolean fullScan, TaskMonitor monitor)
			throws CancelledException {
		Set<Function> candidates = new HashSet<>();
		List<Function> typedTargets = new ArrayList<>();
		ArrayDeque<Function> frontier = new ArrayDeque<>();
		Set<Function> expanded = new HashSet<>();
		Iterator<Function> functions = fullScan
				? program.getFunctionManager().getFunctions(true)
				: program.getFunctionManager().getFunctionsOverlapping(set);
		List<Function> scopedFunctions = new ArrayList<>();
		functions.forEachRemaining(scopedFunctions::add);
		monitor.initialize(Math.max(1, scopedFunctions.size()),
			"C166 far-pointer inference: scanning functions");
		for (Function function : scopedFunctions) {
			monitor.checkCancelled();
			if (hasFarPointerParameter(function) && usesTaskingConvention(function)) {
				typedTargets.add(function);
			}
			if (mayAnalyze(function) &&
				(!fullScan || containsDynamicPagedAccessSetup(program, function))) {
				if (candidates.add(function)) {
					frontier.addLast(function);
				}
			}
			monitor.incrementProgress(1);
		}
		frontier.addAll(typedTargets);
		monitor.setMessage("C166 far-pointer inference: expanding forwarding callers");
		while (!frontier.isEmpty()) {
			monitor.checkCancelled();
			Function target = frontier.removeFirst();
			if (!expanded.add(target)) {
				continue;
			}
			for (Function caller : directCallers(program, target)) {
				if (caller != target && mayAnalyze(caller) &&
					(fullScan || caller.getBody().intersects(set)) && candidates.add(caller)) {
					frontier.addLast(caller);
				}
			}
		}

		monitor.initialize(Math.max(1, candidates.size()),
			"C166 far-pointer inference: building candidate call graph");
		Map<Function, Set<Function>> callees = new HashMap<>();
		for (Function function : orderedFunctions(candidates)) {
			monitor.checkCancelled();
			Set<Function> relevant = new HashSet<>();
			for (Function target : directTargets(program, function)) {
				if (candidates.contains(target)) {
					relevant.add(target);
				}
			}
			callees.put(function, Set.copyOf(relevant));
			monitor.incrementProgress(1);
		}
		return new CandidateGraph(Set.copyOf(candidates), Map.copyOf(callees));
	}

	private Set<Function> directCallers(Program program, Function target) {
		Set<Function> callers = new HashSet<>();
		ReferenceIterator references =
			program.getReferenceManager().getReferencesTo(target.getEntryPoint());
		while (references.hasNext()) {
			Reference reference = references.next();
			RefType type = reference.getReferenceType();
			if (!type.isCall() && !type.isJump()) {
				continue;
			}
			Function caller = program.getFunctionManager()
				.getFunctionContaining(reference.getFromAddress());
			if (caller != null) {
				callers.add(caller);
			}
		}
		return callers;
	}

	private Set<Function> directTargets(Program program, Function caller) {
		Set<Function> targets = new HashSet<>();
		InstructionIterator instructions =
			program.getListing().getInstructions(caller.getBody(), true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			if (!instruction.getFlowType().isCall() &&
				!instruction.getFlowType().isJump()) {
				continue;
			}
			for (Reference reference : instruction.getReferencesFrom()) {
				RefType type = reference.getReferenceType();
				if (!type.isCall() && !type.isJump()) {
					continue;
				}
				Function target = program.getFunctionManager()
					.getFunctionAt(reference.getToAddress());
				if (target != null) {
					targets.add(target);
				}
			}
			for (Address flow : instruction.getFlows()) {
				Function target = program.getFunctionManager().getFunctionAt(flow);
				if (target != null) {
					targets.add(target);
				}
			}
		}
		return targets;
	}

	private SccSchedule buildSccSchedule(CandidateGraph graph, TaskMonitor monitor)
			throws CancelledException {
		Map<Function, Set<Function>> reverse = new HashMap<>();
		for (Function function : graph.functions()) {
			reverse.put(function, new HashSet<>());
		}
		for (Map.Entry<Function, Set<Function>> entry : graph.callees().entrySet()) {
			for (Function target : entry.getValue()) {
				reverse.get(target).add(entry.getKey());
			}
		}

		monitor.initialize(Math.max(1, graph.functions().size()),
			"C166 far-pointer inference: ordering call graph");
		List<Function> finishOrder = new ArrayList<>();
		Set<Function> visited = new HashSet<>();
		for (Function root : orderedFunctions(graph.functions())) {
			monitor.checkCancelled();
			if (!visited.add(root)) {
				continue;
			}
			ArrayDeque<DfsFrame> stack = new ArrayDeque<>();
			stack.push(new DfsFrame(root,
				orderedFunctions(graph.callees().getOrDefault(root, Set.of())).iterator()));
			while (!stack.isEmpty()) {
				monitor.checkCancelled();
				DfsFrame frame = stack.peek();
				if (frame.targets().hasNext()) {
					Function target = frame.targets().next();
					if (visited.add(target)) {
						stack.push(new DfsFrame(target, orderedFunctions(
							graph.callees().getOrDefault(target, Set.of())).iterator()));
					}
				}
				else {
					stack.pop();
					finishOrder.add(frame.function());
					monitor.incrementProgress(1);
				}
			}
		}

		List<List<Function>> components = new ArrayList<>();
		Set<Function> assigned = new HashSet<>();
		for (int i = finishOrder.size() - 1; i >= 0; i--) {
			monitor.checkCancelled();
			Function root = finishOrder.get(i);
			if (!assigned.add(root)) {
				continue;
			}
			List<Function> component = new ArrayList<>();
			ArrayDeque<Function> stack = new ArrayDeque<>();
			stack.push(root);
			while (!stack.isEmpty()) {
				Function function = stack.pop();
				component.add(function);
				for (Function caller : reverse.getOrDefault(function, Set.of())) {
					if (assigned.add(caller)) {
						stack.push(caller);
					}
				}
			}
			component.sort(Comparator.comparing(Function::getEntryPoint));
			components.add(List.copyOf(component));
		}

		Map<Function, Integer> componentOf = new HashMap<>();
		for (int i = 0; i < components.size(); i++) {
			for (Function function : components.get(i)) {
				componentOf.put(function, i);
			}
		}
		List<Set<Integer>> dependencies = new ArrayList<>();
		List<Set<Integer>> callers = new ArrayList<>();
		for (int i = 0; i < components.size(); i++) {
			dependencies.add(new HashSet<>());
			callers.add(new HashSet<>());
		}
		for (Map.Entry<Function, Set<Function>> entry : graph.callees().entrySet()) {
			int callerComponent = componentOf.get(entry.getKey());
			for (Function target : entry.getValue()) {
				int targetComponent = componentOf.get(target);
				if (callerComponent != targetComponent &&
					dependencies.get(callerComponent).add(targetComponent)) {
					callers.get(targetComponent).add(callerComponent);
				}
			}
		}

		int[] remainingDependencies = new int[components.size()];
		List<Integer> ready = new ArrayList<>();
		for (int i = 0; i < components.size(); i++) {
			remainingDependencies[i] = dependencies.get(i).size();
			if (remainingDependencies[i] == 0) {
				ready.add(i);
			}
		}
		Comparator<Integer> componentOrder = Comparator.comparing(
			i -> components.get(i).get(0).getEntryPoint());
		List<List<Integer>> layers = new ArrayList<>();
		int scheduled = 0;
		while (!ready.isEmpty()) {
			ready.sort(componentOrder);
			List<Integer> layer = List.copyOf(ready);
			layers.add(layer);
			scheduled += layer.size();
			Set<Integer> next = new HashSet<>();
			for (int completed : layer) {
				for (int caller : callers.get(completed)) {
					remainingDependencies[caller]--;
					if (remainingDependencies[caller] == 0) {
						next.add(caller);
					}
				}
			}
			ready = new ArrayList<>(next);
		}
		if (scheduled != components.size()) {
			throw new IllegalStateException("SCC condensation graph contains a cycle");
		}
		return new SccSchedule(List.copyOf(components), List.copyOf(layers));
	}

	private List<Function> orderedFunctions(Set<Function> functions) {
		List<Function> ordered = new ArrayList<>(functions);
		ordered.sort(Comparator.comparing(Function::getEntryPoint));
		return ordered;
	}

	private boolean mayAnalyze(Function function) {
		return !function.isExternal() && !function.isThunk() && mayUpdate(function) &&
			usesTaskingConvention(function);
	}

	private boolean hasFarPointerParameter(Function function) {
		for (Parameter parameter : function.getParameters()) {
			if (parameter.getFormalDataType() instanceof Pointer &&
				parameter.getFormalDataType().getLength() == 4) {
				return true;
			}
		}
		return false;
	}

	private boolean usesTaskingConvention(Function function) {
		String name = function.getCallingConventionName();
		return CALLING_CONVENTION.equals(name) ||
			Function.DEFAULT_CALLING_CONVENTION_STRING.equals(name) ||
			Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(name);
	}

	private boolean mayUpdate(Function function) {
		SourceType source = function.getSignatureSource();
		return source == SourceType.DEFAULT || source == SourceType.ANALYSIS;
	}

	private boolean containsDynamicPagedAccessSetup(Program program, Function function) {
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			Register pageSource = dynamicPageSource(instruction);
			if (pageSource != null && pageMayCarryPointerInput(program, function,
				instruction, pageSource)) {
				return true;
			}
		}
		return false;
	}

	private Register dynamicPageSource(Instruction instruction) {
		String mnemonic = instruction.getMnemonicString().toLowerCase();
		if ((mnemonic.equals("extp") || mnemonic.equals("extpr")) &&
			instruction.getNumOperands() != 0) {
			return operandRegister(instruction, 0);
		}
		if (!mnemonic.equals("mov") || instruction.getNumOperands() < 2) {
			return null;
		}
		for (Object result : instruction.getResultObjects()) {
			if (result instanceof Register register &&
				"dpp0".equalsIgnoreCase(register.getName())) {
				Register source = operandRegister(instruction, 1);
				// R0 is the stack pointer; MOV DPP0,[R0+] is a restore, not
				// dynamic PAGE evidence.
				return source != null && !"r0".equalsIgnoreCase(source.getName()) ?
					source : null;
			}
		}
		return null;
	}

	private Register operandRegister(Instruction instruction, int operand) {
		for (Object object : instruction.getOpObjects(operand)) {
			if (object instanceof Register register) {
				return register;
			}
		}
		return null;
	}

	/**
	 * Cheaply reject the overwhelmingly common constant/local page setups before
	 * invoking the decompiler.  Walk backwards through straight-line register
	 * copies.  Any control-flow or unrecognized definition remains a candidate;
	 * this is a conservative prefilter, not pointer evidence.
	 */
	private boolean pageMayCarryPointerInput(Program program, Function function,
			Instruction setup, Register source) {
		Register traced = source;
		Instruction instruction = program.getListing().getInstructionBefore(setup.getAddress());
		int scanned = 0;
		for (; instruction != null && scanned < MAX_SETUP_SCAN_INSTRUCTIONS;
				scanned++, instruction =
					program.getListing().getInstructionBefore(instruction.getAddress())) {
			if (!function.getBody().contains(instruction.getAddress())) {
				break;
			}
			if (instruction.getFlowType().isJump() || instruction.getFlowType().isCall()) {
				return true;
			}
			if (!writesRegister(instruction, traced)) {
				continue;
			}
			if (!instruction.getMnemonicString().equalsIgnoreCase("mov") ||
				instruction.getNumOperands() < 2) {
				// Arithmetic such as OFFSET adjustment preserves possible input
				// provenance; anything else is deliberately kept conservative.
				return true;
			}
			int sourceType = instruction.getOperandType(1);
			Register previous = operandRegister(instruction, 1);
			if (previous != null && !OperandType.isIndirect(sourceType)) {
				if ("r0".equalsIgnoreCase(previous.getName())) {
					return true;
				}
				if (previous.getName().toLowerCase().startsWith("dpp")) {
					return false;
				}
				traced = previous;
				continue;
			}
			if (OperandType.isScalar(sourceType) && !OperandType.isAddress(sourceType) &&
				!OperandType.isIndirect(sourceType)) {
				return false;
			}
			// Stack and absolute-memory loads can carry spilled parameters or
			// adjacent global PAGE:OFFSET words and require full p-code analysis.
			return true;
		}
		if (instruction != null && function.getBody().contains(instruction.getAddress())) {
			// The bounded prefilter ran out of history.  Keep the candidate so a
			// long function cannot turn this performance optimization into a
			// false negative.
			return true;
		}
		return argumentSlot(traced) != null;
	}

	private boolean writesRegister(Instruction instruction, Register expected) {
		for (Object result : instruction.getResultObjects()) {
			if (result instanceof Register actual && overlaps(expected, actual)) {
				return true;
			}
		}
		return false;
	}

	private Inference inferPairs(Program program, Function function,
			HighFunction highFunction) {
		Map<Integer, Integer> scores = new HashMap<>();
		Set<Integer> liveSlots = new HashSet<>();
		Map<Integer, DataType> pointerTypes = new HashMap<>();
		Set<Address> globalPointerStarts = new HashSet<>();
		Iterator<PcodeOpAST> operations = highFunction.getPcodeOps();
		while (operations.hasNext()) {
			PcodeOpAST operation = operations.next();
			for (int i = 0; i < operation.getNumInputs(); i++) {
				liveSlots.addAll(traceParameterWords(program, operation.getInput(i), 0,
					new HashSet<>()));
			}
			if (operation.getOpcode() == PcodeOp.CALL) {
				scoreForwardedPointers(program, operation, scores, pointerTypes,
					globalPointerStarts);
			}
			Varnode page;
			Varnode offset;
			if (operation.getOpcode() == PcodeOp.SEGMENTOP && operation.getNumInputs() == 3) {
				page = operation.getInput(1);
				offset = operation.getInput(2);
			}
			else if (isTypedFarPointerPiece(operation)) {
				page = operation.getInput(0);
				offset = operation.getInput(1);
			}
			else {
				continue;
			}
			Integer start = scorePairSources(program, page, offset, scores);
			Address globalStart = globalPairStart(program, page, offset);
			if (globalStart != null) {
				globalPointerStarts.add(globalStart);
			}
			DataType pointerType = typedPointerType(operation);
			if (start != null && pointerType != null) {
				mergePointerType(program, pointerTypes, start, pointerType);
			}
		}
		scoreRecoveredPointerParameters(program, highFunction, scores, liveSlots,
			pointerTypes);
		scoreIdentityTailCall(program, function, scores, liveSlots, pointerTypes);

		List<Integer> candidates = new ArrayList<>(scores.keySet());
		Collections.sort(candidates);
		Selection selection = selectPairs(candidates, scores, 0, new HashMap<>());
		pointerTypes.keySet().retainAll(selection.starts());
		return new Inference(selection.starts(), liveSlots, pointerTypes,
			globalPointerStarts,
			selection.ambiguous() && selection.score() != 0);
	}

	/**
	 * Preserve a pointer parameter which the decompiler recovered from typed data
	 * flow even when the Program DB still describes the same ABI storage as two
	 * words.  A split candidate is accepted only if both documented adjacent
	 * PAGE:OFFSET slots are existing HighFunction parameters; this never invents
	 * a missing stack word or joins an arbitrary scalar pair.
	 */
	private void scoreRecoveredPointerParameters(Program program,
			HighFunction highFunction, Map<Integer, Integer> scores,
			Set<Integer> liveSlots, Map<Integer, DataType> pointerTypes) {
		Map<Integer, HighSymbol> symbolsBySlot = new HashMap<>();
		int count = highFunction.getLocalSymbolMap().getNumParams();
		for (int i = 0; i < count; i++) {
			HighSymbol symbol = highFunction.getLocalSymbolMap().getParamSymbol(i);
			Integer start = parameterStart(symbol.getStorage());
			if (start != null) {
				symbolsBySlot.put(start, symbol);
			}
		}

		for (Map.Entry<Integer, HighSymbol> entry : symbolsBySlot.entrySet()) {
			int start = entry.getKey();
			HighSymbol symbol = entry.getValue();
			DataType type = symbol.getDataType();
			if (!isPointerType(type) || type.getLength() != 4 ||
				!isLegalPairStart(start)) {
				continue;
			}
			int storageSize = symbol.getStorage().size();
			if (storageSize == 2) {
				HighSymbol page = symbolsBySlot.get(start + 1);
				if (page == null || page.getStorage().size() != 2) {
					continue;
				}
			}
			else if (storageSize != 4) {
				continue;
			}
			scores.merge(start, 1, Integer::sum);
			liveSlots.add(start);
			liveSlots.add(start + 1);
			mergePointerType(program, pointerTypes, start, type);
		}
	}

	/**
	 * A TASKING tail-call keeps the callee's argument registers live across a
	 * terminal JMPS/JMPA.  High p-code represents this as BRANCH and consequently
	 * carries no call inputs.  Propagate only identity register pairs which the
	 * wrapper never writes; copied or transformed pairs remain intentionally
	 * unsupported rather than guessed.
	 */
	private void scoreIdentityTailCall(Program program, Function function,
			Map<Integer, Integer> scores, Set<Integer> liveSlots,
			Map<Integer, DataType> pointerTypes) {
		Instruction tail = program.getListing().getInstructionContaining(
			function.getBody().getMaxAddress());
		if (tail == null || !tail.getFlowType().isJump()) {
			return;
		}
		Address[] flows = tail.getFlows();
		if (flows.length != 1) {
			return;
		}
		Function target = program.getFunctionManager().getFunctionAt(flows[0]);
		if (target == null || !usesTaskingConvention(target)) {
			return;
		}
		for (Parameter parameter : target.getParameters()) {
			DataType type = parameter.getFormalDataType();
			Integer start = parameterStart(parameter.getVariableStorage());
			if (!isPointerType(type) || type.getLength() != 4 || start == null ||
				start >= 4 || writesArgumentPair(program, function, tail, start)) {
				continue;
			}
			scores.merge(start, 1, Integer::sum);
			liveSlots.add(start);
			liveSlots.add(start + 1);
			mergePointerType(program, pointerTypes, start, type);
		}
	}

	private boolean writesArgumentPair(Program program, Function function, Instruction tail,
			int start) {
		Register low = program.getRegister("r" + (FIRST_ARGUMENT_REGISTER + start));
		Register high = program.getRegister("r" + (FIRST_ARGUMENT_REGISTER + start + 1));
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			if (instruction.equals(tail)) {
				break;
			}
			for (Object result : instruction.getResultObjects()) {
				if (result instanceof Register register &&
					(overlaps(low, register) || overlaps(high, register))) {
					return true;
				}
			}
		}
		return false;
	}

	private boolean overlaps(Register expected, Register actual) {
		return expected != null && actual != null &&
			(expected.contains(actual) || actual.contains(expected));
	}

	private void scoreForwardedPointers(Program program, PcodeOp operation,
			Map<Integer, Integer> scores, Map<Integer, DataType> pointerTypes,
			Set<Address> globalPointerStarts) {
		Function target = program.getFunctionManager()
			.getFunctionAt(operation.getInput(0).getAddress());
		if (target == null || !usesTaskingConvention(target)) {
			return;
		}
		int inputIndex = 1;
		for (Parameter parameter : target.getParameters()) {
			int storageSize = parameter.getVariableStorage().size();
			if (storageSize <= 0 || inputIndex >= operation.getNumInputs()) {
				return;
			}
			List<Varnode> pieces = new ArrayList<>();
			int consumed = 0;
			while (inputIndex < operation.getNumInputs() && consumed < storageSize) {
				Varnode input = operation.getInput(inputIndex++);
				if (input.getSize() > storageSize - consumed) {
					return;
				}
				pieces.add(input);
				consumed += input.getSize();
			}
			if (consumed != storageSize) {
				return;
			}

			DataType type = parameter.getFormalDataType();
			if (!isPointerType(type) || type.getLength() != 4) {
				continue;
			}
			if (pieces.size() == 1) {
				scorePointerValue(program, pieces.get(0), scores, pointerTypes, type,
					globalPointerStarts, 0, new HashSet<>());
			}
			else if (pieces.size() == 2 && pieces.get(0).getSize() == 2 &&
				pieces.get(1).getSize() == 2) {
				// CALL inputs are ordered OFFSET then PAGE for a split TASKING
				// far pointer.  The callee's four-byte pointer storage is the
				// authoritative reason to join them; inferred caller types are not.
				Integer start = scorePairSources(program, pieces.get(1), pieces.get(0),
					scores);
				if (start != null) {
					mergePointerType(program, pointerTypes, start, type);
				}
			}
		}
	}

	private void scorePointerValue(Program program, Varnode value,
			Map<Integer, Integer> scores, Map<Integer, DataType> pointerTypes,
			DataType pointerType,
			Set<Address> globalPointerStarts, int depth, Set<Varnode> visited) {
		if (value == null || depth > MAX_TRACE_DEPTH || !visited.add(value)) {
			return;
		}
		PcodeOp definition = value.getDef();
		if (definition == null) {
			HighVariable high = value.getHigh();
			HighSymbol symbol = high == null ? null : high.getSymbol();
			if (symbol != null && symbol.isParameter() && symbol.getStorage().size() == 4) {
				Integer start = parameterStart(symbol.getStorage());
				if (start != null && isLegalPairStart(start)) {
					scores.merge(start, 1, Integer::sum);
					mergePointerType(program, pointerTypes, start, pointerType);
				}
			}
			return;
		}
		switch (definition.getOpcode()) {
			case PcodeOp.SEGMENTOP:
				if (definition.getNumInputs() == 3) {
					Address globalStart = globalPairStart(program, definition.getInput(1),
						definition.getInput(2));
					if (globalStart != null) {
						globalPointerStarts.add(globalStart);
					}
					Integer start = scorePairSources(program, definition.getInput(1),
						definition.getInput(2), scores);
					if (start != null) {
						mergePointerType(program, pointerTypes, start, pointerType);
					}
				}
				break;
			case PcodeOp.PIECE:
				if (definition.getNumInputs() == 2 && definition.getInput(0).getSize() == 2 &&
					definition.getInput(1).getSize() == 2) {
					Address globalStart = globalPairStart(program, definition.getInput(0),
						definition.getInput(1));
					if (globalStart != null) {
						globalPointerStarts.add(globalStart);
					}
					Integer start = scorePairSources(program, definition.getInput(0),
						definition.getInput(1), scores);
					if (start != null) {
						mergePointerType(program, pointerTypes, start, pointerType);
					}
				}
				break;
			case PcodeOp.COPY:
			case PcodeOp.CAST:
			case PcodeOp.INT_ZEXT:
				scorePointerValue(program, definition.getInput(0), scores, pointerTypes,
					pointerType, globalPointerStarts, depth + 1, visited);
				break;
			default:
				break;
		}
	}

	private Address globalPairStart(Program program, Varnode page, Varnode offset) {
		Address highAddress = traceGlobalWordAddress(program, page, 0, new HashSet<>());
		Address lowAddress = traceGlobalWordAddress(program, offset, 0, new HashSet<>());
		if (highAddress == null || lowAddress == null ||
			!highAddress.getAddressSpace().equals(lowAddress.getAddressSpace())) {
			return null;
		}
		try {
			return highAddress.equals(lowAddress.add(2)) ? lowAddress : null;
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}
	}

	private Address traceGlobalWordAddress(Program program, Varnode value, int depth,
			Set<Varnode> visited) {
		if (value == null || depth > MAX_TRACE_DEPTH || !visited.add(value)) {
			return null;
		}
		Address varnodeAddress = value.getAddress();
		if (value.getSize() == 2 && varnodeAddress != null &&
			varnodeAddress.isMemoryAddress()) {
			return varnodeAddress;
		}
		PcodeOp definition = value.getDef();
		if (definition == null) {
			return null;
		}
		switch (definition.getOpcode()) {
			case PcodeOp.LOAD:
				if (definition.getNumInputs() > 1) {
					return resolveGlobalLoadAddress(program, definition.getInput(1));
				}
				return null;
			case PcodeOp.COPY:
			case PcodeOp.CAST:
			case PcodeOp.INT_ZEXT:
			case PcodeOp.INT_SEXT:
			case PcodeOp.SUBPIECE:
				return traceGlobalWordAddress(program, definition.getInput(0), depth + 1,
					visited);
			default:
				return null;
		}
	}

	private Address resolveGlobalLoadAddress(Program program, Varnode pointer) {
		if (pointer == null || !pointer.isConstant()) {
			return null;
		}
		AddressSpace space = program.getLanguage().getDefaultDataSpace();
		return address(space, pointer.getOffset());
	}

	private int defineGlobalFarPointers(Program program, Set<Address> starts) {
		int created = 0;
		for (Address start : starts) {
			if (!mayReplaceGlobalWords(program, start)) {
				continue;
			}
			DataType pointer = new PointerDataType(VoidDataType.dataType,
				program.getDataTypeManager());
			try {
				DataUtilities.createData(program, start, pointer, pointer.getLength(), false,
					ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
				created++;
			}
			catch (CodeUnitInsertionException | RuntimeException e) {
				// A conflicting instruction or user-defined object is not analysis-owned.
			}
		}
		return created;
	}

	private boolean mayReplaceGlobalWords(Program program, Address start) {
		Address end;
		try {
			end = start.add(3);
		}
		catch (AddressOutOfBoundsException e) {
			return false;
		}
		if (!program.getMemory().contains(start) || !program.getMemory().contains(end) ||
			program.getListing().getInstructions(new AddressSet(start, end), true).hasNext()) {
			return false;
		}
		Data existing = program.getListing().getDefinedDataAt(start);
		if (existing != null && existing.getDataType() instanceof Pointer &&
			existing.getLength() == 4) {
			return false;
		}
		for (Address address : List.of(start, start.add(2))) {
			Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
			if (symbol != null && symbol.getSource() != SourceType.DEFAULT &&
				symbol.getSource() != SourceType.ANALYSIS) {
				return false;
			}
			CodeUnit unit = program.getListing().getCodeUnitContaining(address);
			if (unit instanceof Data data && data.isDefined() &&
				!(data.getDataType() instanceof AbstractIntegerDataType) &&
				!Undefined.isUndefined(data.getDataType())) {
				return false;
			}
		}
		return true;
	}

	private Integer scorePairSources(Program program, Varnode page, Varnode offset,
			Map<Integer, Integer> scores) {
		Set<Integer> pageSlots = traceParameterWords(program, page, 0, new HashSet<>());
		if (pageSlots.size() != 1) {
			return null;
		}
		int highSlot = pageSlots.iterator().next();
		int lowSlot = highSlot - 1;
		if (!isLegalPairStart(lowSlot)) {
			return null;
		}
		Set<Integer> offsetSlots = traceParameterWords(program, offset, 0, new HashSet<>());
		if (offsetSlots.contains(lowSlot) && !offsetSlots.contains(highSlot)) {
			scores.merge(lowSlot, 1, Integer::sum);
			return lowSlot;
		}
		return null;
	}

	private boolean isTypedFarPointerPiece(PcodeOp operation) {
		if (operation.getOpcode() != PcodeOp.PIECE || operation.getNumInputs() != 2 ||
			operation.getOutput() == null || operation.getOutput().getSize() != 4 ||
			operation.getInput(0).getSize() != 2 || operation.getInput(1).getSize() != 2) {
			return false;
		}
		return typedPointerType(operation) != null;
	}

	private DataType typedPointerType(PcodeOp operation) {
		if (operation.getOutput() == null || operation.getOutput().getHigh() == null) {
			return null;
		}
		DataType type = operation.getOutput().getHigh().getDataType();
		return isPointerType(type) && type.getLength() == 4 ? type : null;
	}

	private boolean isPointerType(DataType type) {
		return pointerDataType(type) != null;
	}

	private Pointer pointerDataType(DataType type) {
		DataType current = type;
		while (current instanceof TypeDef typeDef) {
			current = typeDef.getBaseDataType();
		}
		return current instanceof Pointer pointer ? pointer : null;
	}

	private void mergePointerType(Program program, Map<Integer, DataType> pointerTypes,
			int start, DataType candidate) {
		Pointer candidatePointer = pointerDataType(candidate);
		if (candidatePointer == null || candidate.getLength() != 4) {
			return;
		}
		DataType existing = pointerTypes.get(start);
		if (existing == null) {
			pointerTypes.put(start, candidate);
			return;
		}
		Pointer existingPointer = pointerDataType(existing);
		DataType existingTarget = existingPointer.getDataType();
		DataType candidateTarget = candidatePointer.getDataType();
		if (existingTarget.isEquivalent(candidateTarget) || isVoidType(candidateTarget)) {
			return;
		}
		if (isVoidType(existingTarget)) {
			pointerTypes.put(start, candidate);
			return;
		}
		pointerTypes.put(start, new PointerDataType(VoidDataType.dataType,
			program.getDataTypeManager()));
	}

	private boolean isVoidType(DataType type) {
		return type instanceof VoidDataType || "void".equals(type.getName());
	}

	private Selection selectPairs(List<Integer> candidates, Map<Integer, Integer> scores,
			int index, Map<Integer, Selection> memo) {
		if (index >= candidates.size()) {
			return new Selection(0, Set.of(), false);
		}
		Selection cached = memo.get(index);
		if (cached != null) {
			return cached;
		}

		int start = candidates.get(index);
		Selection skipped = selectPairs(candidates, scores, index + 1, memo);
		int next = index + 1;
		while (next < candidates.size() && candidates.get(next) <= start + 1) {
			next++;
		}
		Selection tail = selectPairs(candidates, scores, next, memo);
		Set<Integer> takenStarts = new HashSet<>(tail.starts());
		takenStarts.add(start);
		Selection taken = new Selection(scores.get(start) + tail.score(), takenStarts,
			tail.ambiguous());

		Selection result;
		if (taken.score() > skipped.score()) {
			result = taken;
		}
		else if (skipped.score() > taken.score()) {
			result = skipped;
		}
		else if (taken.score() == 0 || taken.starts().equals(skipped.starts())) {
			result = skipped;
		}
		else {
			result = new Selection(taken.score(), taken.starts(), true);
		}
		memo.put(index, result);
		return result;
	}

	private boolean isLegalPairStart(int start) {
		return (start >= 0 && start <= 2) || start >= 4;
	}

	private Set<Integer> traceParameterWords(Program program, Varnode varnode, int depth,
			Set<Varnode> visited) {
		Set<Integer> result = new HashSet<>();
		if (varnode == null || depth > MAX_TRACE_DEPTH || !visited.add(varnode) ||
			varnode.isConstant()) {
			return result;
		}
		Integer parameterWord = parameterWord(varnode);
		if (parameterWord != null) {
			result.add(parameterWord);
			return result;
		}

		PcodeOp definition = varnode.getDef();
		if (definition == null) {
			Register register = program.getRegister(varnode);
			Integer slot = argumentSlot(register);
			if (slot != null) {
				result.add(slot);
			}
			return result;
		}

			switch (definition.getOpcode()) {
			case PcodeOp.COPY:
			case PcodeOp.CAST:
			case PcodeOp.INT_ZEXT:
			case PcodeOp.INT_SEXT:
			case PcodeOp.SUBPIECE:
				result.addAll(traceParameterWords(program, definition.getInput(0), depth + 1,
					visited));
				break;
			case PcodeOp.INDIRECT:
				result.addAll(traceParameterWords(program, definition.getInput(0), depth + 1,
					visited));
				break;
			case PcodeOp.INT_ADD:
			case PcodeOp.INT_SUB:
			case PcodeOp.INT_AND:
			case PcodeOp.INT_OR:
			case PcodeOp.PTRADD:
			case PcodeOp.PTRSUB:
			case PcodeOp.PIECE:
			case PcodeOp.MULTIEQUAL:
				for (int i = 0; i < definition.getNumInputs(); i++) {
					result.addAll(traceParameterWords(program, definition.getInput(i), depth + 1,
						visited));
				}
				break;
			default:
				break;
		}
		return result;
	}

	private Integer parameterWord(Varnode varnode) {
		HighVariable high = varnode.getHigh();
		HighSymbol symbol = high == null ? null : high.getSymbol();
		if (symbol == null) {
			return null;
		}
		VariableStorage storage = symbol.getStorage();
		// Register inputs retain their architectural varnodes and are traced below.
		// Positive stack offsets are incoming TASKING argument words.  Until the DB
		// signature has been widened, the decompiler names these no-def inputs
		// unaff_000000XX instead of marking them as formal parameters; they are still
		// ABI parameter slots.  Refuse defined stack values (locals), negative stack
		// offsets, and compound symbols whose high/low subpiece cannot be identified
		// from the symbol's start offset alone.
		if (!symbol.isParameter() && varnode.getDef() != null) {
			return null;
		}
		if (!storage.isStackStorage() || storage.size() != 2 ||
			storage.getStackOffset() < 0 ||
			(storage.getStackOffset() & 1) != 0) {
			return null;
		}
		return 4 + storage.getStackOffset() / 2;
	}

	private Integer argumentSlot(Register register) {
		if (register == null || register.getMinimumByteSize() != 2) {
			return null;
		}
		String name = register.getName().toLowerCase();
		if (!name.matches("r1[2-5]")) {
			return null;
		}
		int number = Integer.parseInt(name.substring(1));
		if (number < FIRST_ARGUMENT_REGISTER || number > LAST_ARGUMENT_REGISTER) {
			return null;
		}
		return number - FIRST_ARGUMENT_REGISTER;
	}

	private boolean signatureMatches(Function function, Set<Integer> pairStarts,
			Set<Integer> liveSlots, Map<Integer, DataType> pointerTypes) {
		Map<Integer, Parameter> parameters = new HashMap<>();
		int lastSlot = -1;
		for (Parameter parameter : function.getParameters()) {
			Integer start = parameterStart(parameter.getVariableStorage());
			if (start != null) {
				parameters.put(start, parameter);
				lastSlot = Math.max(lastSlot,
					start + Math.max(1, parameter.getVariableStorage().size() / 2) - 1);
			}
		}
		for (int start : pairStarts) {
			lastSlot = Math.max(lastSlot, start + 1);
		}
		for (int slot : liveSlots) {
			lastSlot = Math.max(lastSlot, slot);
		}

		int expectedCount = 0;
		for (int slot = 0; slot <= lastSlot;) {
			Parameter parameter = parameters.get(slot);
			if (pairStarts.contains(slot)) {
				if (parameter == null || !isPointerType(parameter.getFormalDataType()) ||
					parameter.getVariableStorage().size() != 4 ||
					!existingPointerSatisfies(parameter.getFormalDataType(),
						pointerTypes.get(slot))) {
					return false;
				}
				slot += 2;
			}
			else {
				if (parameter == null || parameter.getVariableStorage().size() != 2) {
					return false;
				}
				slot++;
			}
			expectedCount++;
		}
		return function.getParameterCount() == expectedCount;
	}

	private Set<Integer> retainSupportedPairs(Function function, Set<Integer> pairStarts,
			Set<Integer> liveSlots) {
		if (pairStarts.stream().noneMatch(start -> start >= 4)) {
			return pairStarts;
		}

		boolean[] occupiedRegisters = new boolean[4];
		for (int start : pairStarts) {
			if (start < 4) {
				occupiedRegisters[start] = true;
				occupiedRegisters[start + 1] = true;
			}
		}
		for (int slot : liveSlots) {
			if (slot >= 0 && slot < occupiedRegisters.length) {
				occupiedRegisters[slot] = true;
			}
		}
		for (Parameter parameter : function.getParameters()) {
			Integer start = registerStart(parameter.getVariableStorage());
			if (start == null) {
				continue;
			}
			int span = Math.max(1, parameter.getVariableStorage().size() / 2);
			for (int slot = start; slot < Math.min(4, start + span); slot++) {
				occupiedRegisters[slot] = true;
			}
		}
		for (boolean occupied : occupiedRegisters) {
			if (!occupied) {
				Set<Integer> registerPairs = new HashSet<>();
				for (int start : pairStarts) {
					if (start < 4) {
						registerPairs.add(start);
					}
				}
				return Set.copyOf(registerPairs);
			}
		}
		return pairStarts;
	}

	private void updateSignature(Program program, Function function, Set<Integer> pairStarts,
			Set<Integer> liveSlots, Map<Integer, DataType> pointerTypes)
			throws DuplicateNameException, InvalidInputException {
		Map<Integer, Parameter> registerParameters = new HashMap<>();
		Map<Integer, Parameter> stackParameters = new HashMap<>();
		int lastRegisterSlot = -1;
		int lastStackWord = -1;
		for (Parameter parameter : function.getParameters()) {
			VariableStorage storage = parameter.getVariableStorage();
			Integer start = registerStart(storage);
			if (start != null) {
				registerParameters.put(start, parameter);
				lastRegisterSlot = Math.max(lastRegisterSlot,
					start + Math.max(1, storage.size() / 2) - 1);
			}
			else if (storage.hasStackStorage()) {
				int word = storage.getStackOffset() / 2;
				stackParameters.put(word, parameter);
				lastStackWord = Math.max(lastStackWord,
					word + Math.max(1, storage.size() / 2) - 1);
			}
		}
		for (int start : pairStarts) {
			if (start < 4) {
				lastRegisterSlot = Math.max(lastRegisterSlot, start + 1);
			}
			else {
				lastRegisterSlot = Math.max(lastRegisterSlot, 3);
				lastStackWord = Math.max(lastStackWord, start - 4 + 1);
			}
		}
		for (int slot : liveSlots) {
			if (slot < 4) {
				lastRegisterSlot = Math.max(lastRegisterSlot, slot);
			}
			else {
				lastRegisterSlot = Math.max(lastRegisterSlot, 3);
				lastStackWord = Math.max(lastStackWord, slot - 4);
			}
		}

		List<Variable> parameters = new ArrayList<>();
		for (int slot = 0; slot <= lastRegisterSlot;) {
			Parameter existing = registerParameters.get(slot);
			if (pairStarts.contains(slot)) {
				parameters.add(new ParameterImpl(existingName(existing),
					inferredPointerType(program, existing, pointerTypes.get(slot)),
					program));
				slot += 2;
				continue;
			}
			if (existing != null) {
				int span = Math.max(1, existing.getVariableStorage().size() / 2);
				if (!overlapsInferredPair(slot, span, pairStarts)) {
					parameters.add(new ParameterImpl(existingName(existing),
						existing.getFormalDataType(), program));
					slot += span;
					continue;
				}
				parameters.add(new ParameterImpl(null, Undefined.getUndefinedDataType(2), program));
				slot++;
				continue;
			}
			parameters.add(new ParameterImpl(null, Undefined.getUndefinedDataType(2), program));
			slot++;
		}
		for (int word = 0; word <= lastStackWord;) {
			int encodedStart = 4 + word;
			Parameter existing = stackParameters.get(word);
			if (pairStarts.contains(encodedStart)) {
				parameters.add(new ParameterImpl(existingName(existing),
					inferredPointerType(program, existing,
						pointerTypes.get(encodedStart)), program));
				word += 2;
				continue;
			}
			if (existing != null) {
				int span = Math.max(1, existing.getVariableStorage().size() / 2);
				if (!overlapsInferredPair(encodedStart, span, pairStarts)) {
					parameters.add(new ParameterImpl(existingName(existing),
						existing.getFormalDataType(), program));
					word += span;
					continue;
				}
			}
			parameters.add(new ParameterImpl(null, Undefined.getUndefinedDataType(2), program));
			word++;
		}

		function.updateFunction(CALLING_CONVENTION, null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.ANALYSIS);
	}

	private boolean existingPointerSatisfies(DataType existing, DataType inferred) {
		Pointer existingPointer = pointerDataType(existing);
		Pointer inferredPointer = pointerDataType(inferred);
		if (existingPointer == null || inferredPointer == null) {
			return inferredPointer == null;
		}
		DataType existingTarget = existingPointer.getDataType();
		DataType inferredTarget = inferredPointer.getDataType();
		return !isVoidType(existingTarget) || isVoidType(inferredTarget) ||
			existingTarget.isEquivalent(inferredTarget);
	}

	private DataType inferredPointerType(Program program, Parameter existing,
			DataType inferred) {
		if (existing != null && isPointerType(existing.getFormalDataType())) {
			Pointer existingPointer = pointerDataType(existing.getFormalDataType());
			if (!isVoidType(existingPointer.getDataType()) || inferred == null ||
				isVoidType(pointerDataType(inferred).getDataType())) {
				return existing.getFormalDataType();
			}
		}
		Pointer inferredPointer = pointerDataType(inferred);
		DataType pointedTo = inferredPointer == null ? VoidDataType.dataType :
			inferredPointer.getDataType();
		return new PointerDataType(pointedTo, program.getDataTypeManager());
	}

	private boolean overlapsInferredPair(int start, int span, Set<Integer> pairStarts) {
		int end = start + span;
		for (int pairStart : pairStarts) {
			if (start < pairStart + 2 && pairStart < end) {
				return true;
			}
		}
		return false;
	}

	private String existingName(Parameter parameter) {
		if (parameter == null || parameter.getSource() == SourceType.DEFAULT) {
			return null;
		}
		return parameter.getName();
	}

	private Integer registerStart(VariableStorage storage) {
		List<Register> registers = storage.getRegisters();
		if (registers == null) {
			return null;
		}
		int minimum = Integer.MAX_VALUE;
		boolean found = false;
		for (Register register : registers) {
			Integer slot = argumentSlot(register);
			if (slot == null) {
				return null;
			}
			minimum = Math.min(minimum, slot);
			found = true;
		}
		return found ? minimum : null;
	}

	private Integer parameterStart(VariableStorage storage) {
		Integer register = registerStart(storage);
		if (register != null) {
			return register;
		}
		if (storage.isStackStorage() && storage.getStackOffset() >= 0 &&
			(storage.getStackOffset() & 1) == 0) {
			return 4 + storage.getStackOffset() / 2;
		}
		return null;
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

	private record Inference(Set<Integer> pairStarts, Set<Integer> liveSlots,
			Map<Integer, DataType> pointerTypes, Set<Address> globalPointerStarts,
			boolean ambiguous) {
	}

	private record Selection(int score, Set<Integer> starts, boolean ambiguous) {
	}
}
