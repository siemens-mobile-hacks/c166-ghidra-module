package ghidrainfineon;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.util.FillOutStructureHelper;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Recovers compact aggregate layouts behind analyzer-owned TASKING far data
 * pointers.  A new structure is accepted only when recursive decompiler
 * evidence proves both a complete far-pointer field at offset zero and a
 * distinct 16-bit field at a later offset.  This deliberately excludes plain
 * buffers and isolated pointer arithmetic.
 */
public class C166AggregateLayoutPhase extends C166TaskingTypeInferencePhase {

	private static final int MAX_RETURN_ALIAS_DEPTH = 2;
	private static final int MAX_LAYOUT_SIZE = 0x1000;
	private static final int DECOMPILE_TIMEOUT_SECONDS = 10;
	private int lastDecompilations;
	private int lastDecompilerCacheHits;

	public C166AggregateLayoutPhase() {
		super("C166 TASKING Aggregate Layouts");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		lastDecompilations = 0;
		lastDecompilerCacheHits = 0;
		if (!canAnalyze(program)) {
			return true;
		}

		List<Function> functions = candidateFunctions(program, set, monitor);
		if (functions.isEmpty()) {
			report(program, "Inspected 0 function(s); created 0 compact descriptor " +
				"layout(s), extended 0, propagated 0 exact returned-layout alias(es), " +
				"rejected 0 weak candidate(s), 0 decompilation failure(s), reused 0 " +
				"cached HighFunction result(s).");
			return true;
		}
		DecompInterface decompiler = new FillOutStructureHelper(program, monitor)
			.setUpDecompiler(new DecompileOptions());
		if (decompiler == null) {
			return false;
		}

		int created = 0;
		int extended = 0;
		int rejected = 0;
		int aliases = 0;
		int decompileFailures = 0;
		Map<Function, DecompileResults> decompiled = new HashMap<>();
		try {
			for (Function function : functions) {
				monitor.checkCancelled();
				if (!C166AnalysisFunctions.hasUsableBody(function) ||
					function.getSignatureSource() == SourceType.USER_DEFINED) {
					continue;
				}
				DecompileResults results = decompile(function, decompiler, decompiled,
					monitor);
				if (!results.decompileCompleted() || results.getHighFunction() == null) {
					decompileFailures++;
					continue;
				}
				for (int ordinal = 0; ordinal < function.getParameterCount(); ordinal++) {
					Parameter parameter = function.getParameter(ordinal);
					if (parameter.getSource() == SourceType.USER_DEFINED ||
						!(parameter.getFormalDataType() instanceof Pointer pointer) ||
						pointer.getLength() != 4) {
						continue;
					}
					DataType target = pointer.getDataType();
					if (target instanceof FunctionDefinition) {
						continue;
					}
					boolean create = !(target instanceof Structure);
					if (!create && !(target instanceof Structure structure &&
						isOwnedAutoStructure(structure))) {
						continue;
					}
					HighSymbol symbol = results.getHighFunction()
						.getLocalSymbolMap().getParamSymbol(ordinal);
					if (symbol == null || symbol.getHighVariable() == null) {
						continue;
					}
					if (!hasDirectMemoryUse(symbol.getHighVariable())) {
						continue;
					}

					String before = create ? null : layoutSnapshot((Structure) target);
					List<ProtectedPointerField> protectedFields = create ? List.of() :
						protectedPointerFields((Structure) target);
					Structure layout;
					try {
						/*
						 * Keep structure discovery inside the already selected root function.
						 * FillOutStructureHelper's optional decompiler recursively follows every
						 * pointer-bearing call, bypassing this phase's bounded worklist and
						 * repeatedly retrying malformed callees.  Exact returned-layout aliases
						 * are propagated below by our own bounded queue.
						 */
						layout = new FillOutStructureHelper(program, monitor)
							.processStructure(symbol.getHighVariable(), function, create, false,
								null);
					}
					catch (IllegalArgumentException e) {
						// FillOutStructureHelper assumes every recovered field interval is
						// ordered.  Malformed or partial p-code can violate that assumption;
						// reject this candidate instead of aborting the entire analysis run.
						log.appendMsg(getName(), function.getEntryPoint() +
							": rejected invalid aggregate candidate: " + e.getMessage());
						rejected++;
						continue;
					}
					if (layout == null) {
						continue;
					}
					if (create && !isStrongDescriptorLayout(layout)) {
						program.getDataTypeManager().remove(layout);
						rejected++;
						continue;
					}
					if (create) {
						try {
							parameter.setDataType(new PointerDataType(layout,
								program.getDataTypeManager()), SourceType.ANALYSIS);
							created++;
						}
						catch (InvalidInputException e) {
							program.getDataTypeManager().remove(layout);
							log.appendException(e);
							return false;
						}
					}
					else {
						restoreProtectedPointerFields(layout, protectedFields);
						if (!before.equals(layoutSnapshot(layout))) {
							extended++;
						}
					}
				}
			}
			aliases = propagateReturnedLayouts(program, functions, decompiler, decompiled,
				monitor, log);
		}
		finally {
			decompiler.dispose();
		}

		report(program, "Inspected " + functions.size() + " function(s); created " +
			created + " compact descriptor layout(s), extended " + extended +
			", propagated " + aliases + " exact returned-layout alias(es), rejected " +
			rejected + " weak candidate(s), " + decompileFailures +
			" decompilation failure(s), reused " + lastDecompilerCacheHits +
			" cached HighFunction result(s).");
		return true;
	}

	private boolean hasDirectMemoryUse(HighVariable variable) {
		ArrayDeque<Varnode> pending = new ArrayDeque<>();
		Set<Varnode> visited = new HashSet<>();
		for (Varnode instance : variable.getInstances()) {
			pending.addLast(instance);
		}
		int traversed = 0;
		while (!pending.isEmpty() && traversed++ < 512) {
			Varnode value = pending.removeFirst();
			if (!visited.add(value)) {
				continue;
			}
			var uses = value.getDescendants();
			while (uses.hasNext()) {
				PcodeOp use = uses.next();
				if ((use.getOpcode() == PcodeOp.LOAD || use.getOpcode() == PcodeOp.STORE) &&
					use.getNumInputs() > 1 && use.getInput(1).equals(value)) {
					return true;
				}
				if (use.getOutput() != null && propagatesPointerValue(use.getOpcode())) {
					pending.addLast(use.getOutput());
				}
			}
		}
		return false;
	}

	private boolean propagatesPointerValue(int opcode) {
		return switch (opcode) {
			case PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INDIRECT, PcodeOp.MULTIEQUAL,
				PcodeOp.PIECE, PcodeOp.SUBPIECE, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT,
				PcodeOp.INT_AND, PcodeOp.INT_ADD, PcodeOp.PTRADD, PcodeOp.PTRSUB,
				PcodeOp.SEGMENTOP -> true;
			default -> false;
		};
	}

	public int getLastDecompilations() {
		return lastDecompilations;
	}

	public int getLastDecompilerCacheHits() {
		return lastDecompilerCacheHits;
	}

	private DecompileResults decompile(Function function, DecompInterface decompiler,
			Map<Function, DecompileResults> cache, TaskMonitor monitor)
			throws CancelledException {
		DecompileResults result = cache.get(function);
		if (result != null) {
			lastDecompilerCacheHits++;
			return result;
		}
		lastDecompilations++;
		result = decompiler.decompileFunction(function, DECOMPILE_TIMEOUT_SECONDS, monitor);
		cache.put(function, result);
		return result;
	}

	private int propagateReturnedLayouts(Program program, List<Function> functions,
			DecompInterface decompiler, Map<Function, DecompileResults> decompiled,
			TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		int changed = 0;
		ArrayDeque<Function> pending = new ArrayDeque<>();
		Set<Function> queued = new HashSet<>();
		for (Function function : functions) {
			if (concreteOwnedLayoutPointer(function.getReturnType()) != null &&
				function.getSignatureSource() == SourceType.ANALYSIS && queued.add(function)) {
				pending.addLast(function);
			}
		}
		while (!pending.isEmpty()) {
			monitor.checkCancelled();
			Function function = pending.removeFirst();
			queued.remove(function);
			DataType returnedType = concreteOwnedLayoutPointer(function.getReturnType());
			if (returnedType == null ||
				function.getSignatureSource() != SourceType.ANALYSIS) {
				continue;
			}
			DecompileResults results = decompile(function, decompiler, decompiled, monitor);
			if (!results.decompileCompleted() || results.getHighFunction() == null) {
				continue;
			}
			ReturnedAlias alias = returnedAlias(program, results, function);
			try {
				Integer returnedParameter = returnedParameterAlias(program, function,
					results, decompiler, decompiled, monitor, new HashSet<>(), 0);
				if (returnedParameter != null) {
					Parameter parameter = function.getParameter(returnedParameter);
					if (parameter != null && parameter.getSource() != SourceType.USER_DEFINED &&
						isGenericDataPointer(parameter.getFormalDataType())) {
						parameter.setDataType(returnedType, SourceType.ANALYSIS);
						changed++;
					}
				}
				if (alias instanceof ParameterAlias parameterAlias) {
					Parameter parameter = function.getParameter(parameterAlias.ordinal());
					if (parameter != null && parameter.getSource() != SourceType.USER_DEFINED &&
						isGenericDataPointer(parameter.getFormalDataType())) {
						parameter.setDataType(returnedType, SourceType.ANALYSIS);
						changed++;
					}
				}
				else if (alias instanceof CallAlias callAlias) {
					Function callee = callAlias.function();
					if (callee.getSignatureSource() == SourceType.ANALYSIS &&
						isGenericDataPointer(callee.getReturnType())) {
						callee.setReturnType(returnedType, SourceType.ANALYSIS);
						changed++;
						// The callee's HighFunction was recovered under its old generic
						// return type.  Invalidate both caches before following the newly
						// concrete alias.  A function already processed may be queued again;
						// the type transition is monotonic, so this still terminates.
						decompiled.remove(callee);
						decompiler.flushCache();
						if (queued.add(callee)) {
							pending.addLast(callee);
						}
					}
				}
			}
			catch (InvalidInputException e) {
				log.appendException(e);
			}
		}
		return changed;
	}

	private Integer returnedParameterAlias(Program program, Function function,
			DecompileResults results, DecompInterface decompiler,
			Map<Function, DecompileResults> decompiled, TaskMonitor monitor,
			Set<Function> visited, int depth) throws CancelledException {
		if (depth > MAX_RETURN_ALIAS_DEPTH || !visited.add(function)) {
			return null;
		}
		ReturnedAlias alias = returnedAlias(program, results, function);
		if (alias instanceof ParameterAlias parameterAlias) {
			return parameterAlias.ordinal();
		}
		if (!(alias instanceof CallAlias callAlias)) {
			return null;
		}
		Function callee = callAlias.function();
		DecompileResults calleeResults = decompile(callee, decompiler, decompiled, monitor);
		if (!calleeResults.decompileCompleted() || calleeResults.getHighFunction() == null) {
			return null;
		}
		Integer calleeParameter = returnedParameterAlias(program, callee, calleeResults,
			decompiler, decompiled, monitor, visited, depth + 1);
		if (calleeParameter == null) {
			return null;
		}
		ReturnedAlias argument = returnedCallArgumentAlias(program, results, callee,
			calleeParameter);
		return argument instanceof ParameterAlias parameterAlias ?
			parameterAlias.ordinal() : null;
	}

	private ReturnedAlias returnedCallArgumentAlias(Program program,
			DecompileResults results, Function callee, int parameterOrdinal) {
		ParameterMaps maps = parameterMaps(results);
		ReturnedAlias common = null;
		boolean sawReturn = false;
		var operations = results.getHighFunction().getPcodeOps();
		while (operations.hasNext()) {
			PcodeOpAST operation = operations.next();
			if (operation.getOpcode() != PcodeOp.RETURN || operation.getNumInputs() < 2) {
				continue;
			}
			sawReturn = true;
			ReturnedAlias alias = traceReturnedCallArgument(program,
				operation.getInput(1), callee, parameterOrdinal, maps.parameters(),
				maps.inputParts(), new HashSet<>(), 0);
			if (alias == null || common != null && !common.equals(alias)) {
				return null;
			}
			common = alias;
		}
		return sawReturn ? common : null;
	}

	private ReturnedAlias traceReturnedCallArgument(Program program, Varnode value,
			Function callee, int parameterOrdinal, Map<HighVariable, Integer> parameters,
			Map<StorageKey, ParameterPart> inputParts, Set<Varnode> visited, int depth) {
		if (value == null || depth > 64 || !visited.add(value)) {
			return null;
		}
		PcodeOp definition = value.getDef();
		if (definition == null) {
			return null;
		}
		switch (definition.getOpcode()) {
			case PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INDIRECT:
				return traceReturnedCallArgument(program, definition.getInput(0), callee,
					parameterOrdinal, parameters, inputParts, visited, depth + 1);
			case PcodeOp.MULTIEQUAL: {
				ReturnedAlias common = null;
				for (int index = 0; index < definition.getNumInputs(); index++) {
					ReturnedAlias input = traceReturnedCallArgument(program,
						definition.getInput(index), callee, parameterOrdinal, parameters,
						inputParts, new HashSet<>(visited), depth + 1);
					if (input == null || common != null && !common.equals(input)) {
						return null;
					}
					common = input;
				}
				return common;
			}
			case PcodeOp.CALL:
				if (definition.getNumInputs() <= parameterOrdinal + 1 ||
					definition.getInput(0).getAddress() == null ||
					!callee.getEntryPoint().equals(definition.getInput(0).getAddress())) {
					return null;
				}
				return traceReturnedAlias(program, definition.getInput(parameterOrdinal + 1),
					parameters, inputParts, new HashSet<>(), depth + 1);
			default:
				return null;
		}
	}

	private ReturnedAlias returnedAlias(Program program, DecompileResults results,
			Function function) {
		ParameterMaps maps = parameterMaps(results);
		Map<HighVariable, Integer> parameters = maps.parameters();
		Map<StorageKey, ParameterPart> inputParts = maps.inputParts();
		ReturnedAlias common = null;
		boolean sawReturn = false;
		var operations = results.getHighFunction().getPcodeOps();
		while (operations.hasNext()) {
			PcodeOpAST operation = operations.next();
			if (operation.getOpcode() != PcodeOp.RETURN || operation.getNumInputs() < 2) {
				continue;
			}
			sawReturn = true;
			ReturnedAlias alias = traceReturnedAlias(program, operation.getInput(1),
				parameters, inputParts, new HashSet<>(), 0);
			if (alias == null || common != null && !common.equals(alias)) {
				return null;
			}
			common = alias;
		}
		return sawReturn ? common : null;
	}

	private ParameterMaps parameterMaps(DecompileResults results) {
		Map<HighVariable, Integer> parameters = new HashMap<>();
		Map<StorageKey, ParameterPart> inputParts = new HashMap<>();
		for (int ordinal = 0;
				ordinal < results.getHighFunction().getLocalSymbolMap().getNumParams(); ordinal++) {
			HighSymbol symbol = results.getHighFunction().getLocalSymbolMap()
				.getParamSymbol(ordinal);
			if (symbol != null) {
				if (symbol.getHighVariable() != null) {
					parameters.put(symbol.getHighVariable(), ordinal);
				}
				Varnode[] storage = symbol.getStorage().getVarnodes();
				List<Register> registers = symbol.getStorage().getRegisters();
				if (registers != null && registers.size() == 2) {
					inputParts.put(new StorageKey(registers.get(0).getAddress(), 2),
						new ParameterPart(ordinal, 1));
					inputParts.put(new StorageKey(registers.get(1).getAddress(), 2),
						new ParameterPart(ordinal, 2));
				}
				else if (storage.length == 1 && storage[0].getSize() == 4) {
					inputParts.put(StorageKey.of(storage[0]), new ParameterPart(ordinal, 3));
				}
				else if (storage.length == 2 && storage[0].getSize() == 2 &&
					storage[1].getSize() == 2) {
					inputParts.put(StorageKey.of(storage[0]), new ParameterPart(ordinal, 1));
					inputParts.put(StorageKey.of(storage[1]), new ParameterPart(ordinal, 2));
				}
			}
		}
		return new ParameterMaps(parameters, inputParts);
	}

	private ReturnedAlias traceReturnedAlias(Program program, Varnode value,
			Map<HighVariable, Integer> parameters,
			Map<StorageKey, ParameterPart> inputParts, Set<Varnode> visited, int depth) {
		if (value == null || depth > 64 || !visited.add(value)) {
			return null;
		}
		Map<Integer, Integer> coverage = parameterCoverage(value, parameters,
			inputParts, new HashSet<>(), 0);
		if (coverage.size() == 1) {
			Map.Entry<Integer, Integer> only = coverage.entrySet().iterator().next();
			if (only.getValue() == 3) {
				return new ParameterAlias(only.getKey());
			}
		}
		Integer ordinal = parameterOrdinal(value, parameters);
		if (ordinal != null && value.getSize() == 4) {
			return new ParameterAlias(ordinal);
		}
		PcodeOp definition = value.getDef();
		if (definition == null) {
			return null;
		}
		switch (definition.getOpcode()) {
			case PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INDIRECT:
				return traceReturnedAlias(program, definition.getInput(0), parameters,
					inputParts, visited, depth + 1);
			case PcodeOp.MULTIEQUAL: {
				ReturnedAlias common = null;
				for (int index = 0; index < definition.getNumInputs(); index++) {
					ReturnedAlias input = traceReturnedAlias(program,
						definition.getInput(index), parameters, inputParts,
						new HashSet<>(visited), depth + 1);
					if (input == null || common != null && !common.equals(input)) {
						return null;
					}
					common = input;
				}
				return common;
			}
			case PcodeOp.CALL: {
				if (definition.getNumInputs() == 0 ||
					definition.getInput(0).getAddress() == null) {
					return null;
				}
				Function callee = program.getFunctionManager().getFunctionAt(
					definition.getInput(0).getAddress());
				return callee == null ? null : new CallAlias(callee);
			}
			default:
				return null;
		}
	}

	private Map<Integer, Integer> parameterCoverage(Varnode value,
			Map<HighVariable, Integer> parameters,
			Map<StorageKey, ParameterPart> inputParts, Set<Varnode> visited, int depth) {
		if (value == null || depth > 64 || !visited.add(value) || value.isConstant()) {
			return Map.of();
		}
		Integer ordinal = parameterOrdinal(value, parameters);
		if (ordinal != null && value.getSize() == 4) {
			return Map.of(ordinal, 3);
		}
		ParameterPart direct = inputParts.get(StorageKey.of(value));
		if (direct != null && (value.isInput() || value.getDef() == null)) {
			return Map.of(direct.ordinal(), direct.mask());
		}
		PcodeOp definition = value.getDef();
		if (definition == null) {
			return Map.of();
		}
		if (definition.getOpcode() == PcodeOp.SUBPIECE &&
			definition.getNumInputs() == 2 && definition.getInput(1).isConstant()) {
			Varnode whole = definition.getInput(0);
			Integer wholeOrdinal = parameterOrdinal(whole, parameters);
			long offset = definition.getInput(1).getOffset();
			if (wholeOrdinal != null && whole.getSize() == 4 && value.getSize() == 2 &&
				(offset == 0 || offset == 2)) {
				return Map.of(wholeOrdinal, offset == 0 ? 1 : 2);
			}
		}
		switch (definition.getOpcode()) {
			case PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INDIRECT, PcodeOp.SUBPIECE:
				return parameterCoverage(definition.getInput(0), parameters, inputParts,
					visited, depth + 1);
			case PcodeOp.PIECE: {
				Map<Integer, Integer> combined = new HashMap<>();
				for (int index = 0; index < definition.getNumInputs(); index++) {
					Map<Integer, Integer> input = parameterCoverage(definition.getInput(index),
						parameters, inputParts, new HashSet<>(visited), depth + 1);
					for (Map.Entry<Integer, Integer> entry : input.entrySet()) {
						combined.merge(entry.getKey(), entry.getValue(), (left, right) ->
							left | right);
					}
				}
				return combined;
			}
			case PcodeOp.MULTIEQUAL: {
				Map<Integer, Integer> common = null;
				for (int index = 0; index < definition.getNumInputs(); index++) {
					Map<Integer, Integer> input = parameterCoverage(definition.getInput(index),
						parameters, inputParts, new HashSet<>(visited), depth + 1);
					if (common != null && !common.equals(input)) {
						return Map.of();
					}
					common = input;
				}
				return common == null ? Map.of() : common;
			}
			default:
				return Map.of();
		}
	}

	private Integer parameterOrdinal(Varnode value,
			Map<HighVariable, Integer> parameters) {
		HighVariable high = value == null ? null : value.getHigh();
		HighSymbol symbol = high == null ? null : high.getSymbol();
		if (symbol != null && symbol.isParameter()) {
			return symbol.getCategoryIndex();
		}
		return parameters.get(high);
	}

	private DataType concreteOwnedLayoutPointer(DataType type) {
		if (!(type instanceof Pointer pointer) || pointer.getLength() != 4 ||
			!(pointer.getDataType() instanceof Structure structure) ||
			!isOwnedAutoStructure(structure)) {
			return null;
		}
		return type;
	}

	private boolean isGenericDataPointer(DataType type) {
		return type instanceof Pointer pointer && pointer.getLength() == 4 &&
			(pointer.getDataType() instanceof VoidDataType ||
				ghidra.program.model.data.Undefined.isUndefined(pointer.getDataType()));
	}

	private List<Function> candidateFunctions(Program program, AddressSetView set,
			TaskMonitor monitor) throws CancelledException {
		FunctionIterator roots = set == null || set.isEmpty() ?
			program.getFunctionManager().getFunctions(true) :
			program.getFunctionManager().getFunctions(set, true);
		List<Function> functions = new ArrayList<>();
		while (roots.hasNext()) {
			monitor.checkCancelled();
			Function function = roots.next();
			if (isAggregateCandidate(program, function)) {
				functions.add(function);
			}
		}
		return functions;
	}

	private boolean isAggregateCandidate(Program program, Function function) {
		if (function.isExternal() || function.isThunk() ||
			function.getSignatureSource() == SourceType.USER_DEFINED) {
			return false;
		}
		if (concreteOwnedLayoutPointer(function.getReturnType()) != null) {
			return true;
		}
		boolean genericPointerParameter = false;
		boolean ownedPointerParameter = false;
		for (Parameter parameter : function.getParameters()) {
			if (parameter.getSource() == SourceType.USER_DEFINED ||
				!(parameter.getFormalDataType() instanceof Pointer pointer) ||
				pointer.getLength() != 4 || pointer.getDataType() instanceof FunctionDefinition) {
				continue;
			}
			DataType target = pointer.getDataType();
			if (target instanceof VoidDataType ||
				ghidra.program.model.data.Undefined.isUndefined(target)) {
				genericPointerParameter = true;
			}
			else if (target instanceof Structure structure &&
				isOwnedAutoStructure(structure)) {
				ownedPointerParameter = true;
			}
		}
		if (!genericPointerParameter && !ownedPointerParameter) {
			return false;
		}
		Map<Integer, Set<Integer>> offsets =
			new C166FarPointerPhase().directPagedDataUseOffsets(program, function);
		if (ownedPointerParameter && !offsets.isEmpty()) {
			return true;
		}
		for (Set<Integer> pairOffsets : offsets.values()) {
			if (pairOffsets.contains(0) && pairOffsets.contains(2) &&
				pairOffsets.stream().anyMatch(offset -> offset >= 4 && offset < MAX_LAYOUT_SIZE)) {
				return true;
			}
		}
		return false;
	}

	private boolean isStrongDescriptorLayout(Structure structure) {
		if (structure.getLength() < 6 || structure.getLength() > MAX_LAYOUT_SIZE) {
			return false;
		}
		boolean farPointerAtZero = false;
		boolean laterWord = false;
		for (DataTypeComponent component : structure.getDefinedComponents()) {
			if (component.getOffset() == 0 && component.getLength() == 4 &&
				component.getDataType() instanceof Pointer pointer &&
				pointer.getLength() == 4) {
				farPointerAtZero = true;
			}
			if (component.getOffset() >= 4 && component.getLength() == 2) {
				laterWord = true;
			}
		}
		return farPointerAtZero && laterWord;
	}

	private boolean isOwnedAutoStructure(Structure structure) {
		return "/auto_structs".equals(structure.getCategoryPath().getPath()) &&
			structure.getName().startsWith("astruct");
	}

	private List<ProtectedPointerField> protectedPointerFields(Structure structure) {
		List<ProtectedPointerField> protectedFields = new ArrayList<>();
		for (DataTypeComponent component : structure.getDefinedComponents()) {
			if (!(component.getDataType() instanceof Pointer pointer) ||
				pointer.getLength() != 4 || pointer.getDataType() instanceof VoidDataType ||
				ghidra.program.model.data.Undefined.isUndefined(pointer.getDataType()) ||
				pointer.getDataType() instanceof FunctionDefinition) {
				continue;
			}
			protectedFields.add(new ProtectedPointerField(component.getOffset(),
				component.getDataType(), component.getLength(), component.getFieldName(),
				component.getComment()));
		}
		return protectedFields;
	}

	private void restoreProtectedPointerFields(Structure structure,
			List<ProtectedPointerField> protectedFields) {
		for (ProtectedPointerField field : protectedFields) {
			DataTypeComponent current = structure.getComponentAt(field.offset());
			if (current != null && current.getOffset() == field.offset() &&
				current.getLength() == field.length() &&
				current.getDataType().isEquivalent(field.type())) {
				continue;
			}
			int end = field.offset() + field.length();
			for (int offset = field.offset(); offset < end;) {
				DataTypeComponent overlapping = structure.getComponentAt(offset);
				if (overlapping == null) {
					offset++;
					continue;
				}
				int next = Math.max(offset + 1,
					overlapping.getOffset() + overlapping.getLength());
				structure.clearAtOffset(overlapping.getOffset());
				offset = next;
			}
			structure.replaceAtOffset(field.offset(), field.type(), field.length(),
				field.name(), field.comment());
		}
	}

	private String layoutSnapshot(Structure structure) {
		StringBuilder result = new StringBuilder();
		result.append(structure.getLength());
		for (DataTypeComponent component : structure.getDefinedComponents()) {
			result.append('|').append(component.getOffset()).append(':')
				.append(component.getLength()).append(':')
				.append(component.getDataType().getPathName());
		}
		return result.toString();
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

	private interface ReturnedAlias {
	}

	private record ParameterAlias(int ordinal) implements ReturnedAlias {
	}

	private record CallAlias(Function function) implements ReturnedAlias {
	}

	private record ParameterPart(int ordinal, int mask) {
	}

	private record ParameterMaps(Map<HighVariable, Integer> parameters,
			Map<StorageKey, ParameterPart> inputParts) {
	}

	private record ProtectedPointerField(int offset, DataType type, int length,
			String name, String comment) {
	}

	private record StorageKey(ghidra.program.model.address.Address address, int size) {
		private static StorageKey of(Varnode value) {
			return new StorageKey(value.getAddress(), value.getSize());
		}
	}
}
