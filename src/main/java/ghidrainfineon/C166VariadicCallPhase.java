package ghidrainfineon;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Repairs TASKING Classic variadic call sites whose fixed compound parameters
 * are split into individual 16-bit register trials by Ghidra's vararg recovery.
 *
 * The analyzer uses only the callee's declared signature, calling convention,
 * and decompiler-recovered call inputs.  It has no knowledge of library names,
 * firmware addresses, format strings, or string contents.
 */
public class C166VariadicCallPhase extends C166TaskingTypeInferencePhase {

	private static final String CALLING_CONVENTION = "__tasking_c166_classic";
	private static final String VARARG_CONVENTION_PREFIX =
		"__tasking_c166_classic_vararg_";
	private static final String GENERATED_SIGNATURE_NAME = "c166_variadic_call";
	private static final int DECOMPILE_TIMEOUT_SECONDS = 30;

	public C166VariadicCallPhase() {
		super("C166 TASKING Variadic Calls");
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C166ArchitectureProfile.isTaskingClassicLarge(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		boolean fullScan = set == null || set.isEmpty() || set.contains(program.getMemory());
		Map<Address, Function> variadicTargets = findTypedVariadicTargets(program);
		if (variadicTargets.isEmpty()) {
			return true;
		}

		Set<Function> callers =
			findCallers(program, variadicTargets.keySet(), set, fullScan);
		monitor.initialize(callers.size());
		int callsSeen = 0;
		int overridesAdded = 0;
		int existingOverrides = 0;
		int replacedOverrides = 0;
		int ambiguousCalls = 0;
		int failedFunctions = 0;
		int fallbackOverrides = 0;
		Set<Function> refinementCallers = new LinkedHashSet<>();
		BasicBlockModel basicBlocks = new BasicBlockModel(program);

		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(false);
		decompiler.toggleSyntaxTree(true);
		if (!decompiler.openProgram(program)) {
			report(program, "Decompiler initialization failed: " + decompiler.getLastMessage());
			return false;
		}

		try {
			for (Function caller : callers) {
				monitor.checkCancelled();
				monitor.setMessage("C166 variadic calls: " + caller.getName());
				monitor.incrementProgress(1);

				DecompileResults result = decompiler.decompileFunction(caller,
					DECOMPILE_TIMEOUT_SECONDS, monitor);
				if (!result.decompileCompleted() || result.getHighFunction() == null) {
					failedFunctions++;
					fallbackOverrides += addCleanupFallbackOverrides(program, caller,
						variadicTargets, basicBlocks, monitor, log);
					continue;
				}
				Set<Address> removedOverrideSites = repairInvalidPrototypeOverrides(program,
					caller, result.getHighFunction(), variadicTargets, monitor, log);
				if (!removedOverrideSites.isEmpty()) {
					decompiler.flushCache();
					result = decompiler.decompileFunction(caller, DECOMPILE_TIMEOUT_SECONDS, monitor);
					if (!result.decompileCompleted() || result.getHighFunction() == null) {
						failedFunctions++;
						int recovered = addCleanupFallbackOverrides(program, caller,
							variadicTargets, basicBlocks, monitor, log);
						fallbackOverrides += recovered;
						replacedOverrides += Math.min(recovered, removedOverrideSites.size());
						continue;
					}
				}

				Iterator<PcodeOpAST> operations = result.getHighFunction().getPcodeOps();
				while (operations.hasNext()) {
					monitor.checkCancelled();
					PcodeOpAST operation = operations.next();
					if (operation.getOpcode() != PcodeOp.CALL || operation.getNumInputs() < 2) {
						continue;
					}
					Function target = variadicTargets.get(operation.getInput(0).getAddress());
					if (target == null) {
						continue;
					}
					callsSeen++;
					Address callSite = operation.getSeqnum().getTarget();
					Instruction callInstruction = program.getListing().getInstructionAt(callSite);
					DataTypeSymbol existingOverride = prototypeOverride(caller, callSite);
					if (existingOverride != null && validPrototypeOverride(program, target,
						callInstruction, existingOverride)) {
						if (removedOverrideSites.contains(callSite)) {
							replacedOverrides++;
						}
						else {
							existingOverrides++;
						}
						continue;
					}

					FunctionDefinitionDataType override = buildOverride(program, target, operation);
					if (override != null && !validPrototypeDefinition(program, target,
						callInstruction, override)) {
						override = null;
					}
					if (override == null) {
						Integer optionalWords = optionalWordsAfterFixedStack(program.getListing(),
							callInstruction, target);
						if (optionalWords != null) {
							// Raw variadic recovery may shuffle fixed compound trials ahead of
							// real optional inputs. First align the CALL with a word override;
							// typed optional recovery is safe on the refinement pass below.
							override = buildFallbackOverride(program, target,
								recoveredSetupOptionalTypes(program, caller, callInstruction,
									target, optionalWords, basicBlocks, monitor));
							fallbackOverrides++;
							refinementCallers.add(caller);
						}
					}
					if (override == null) {
						ambiguousCalls++;
						continue;
					}
					try {
						HighFunctionDBUtil.writeOverride(caller, callSite, override);
						if (removedOverrideSites.contains(callSite)) {
							replacedOverrides++;
						}
						else if (existingOverride == null) {
							overridesAdded++;
						}
						else {
							replacedOverrides++;
						}
					}
					catch (InvalidInputException e) {
						log.appendException(e);
						ambiguousCalls++;
					}
				}
			}

			// A raw variadic CALL can omit all stack inputs.  The cleanup-derived
			// word override makes those inputs visible to the decompiler.  Refine
			// that temporary representation immediately, in the same analyzer run,
			// once data flow proves that two words came from one pointer.
			if (!refinementCallers.isEmpty()) {
				for (Function caller : refinementCallers) {
					monitor.checkCancelled();
					decompiler.flushCache();
					DecompileResults result = decompiler.decompileFunction(caller,
						DECOMPILE_TIMEOUT_SECONDS, monitor);
					if (!result.decompileCompleted() || result.getHighFunction() == null) {
						continue;
					}
					replacedOverrides += repairInvalidPrototypeOverrides(program, caller,
						result.getHighFunction(), variadicTargets, monitor, log).size();
				}
			}
		}
		finally {
			decompiler.dispose();
		}

		report(program, (fullScan ? "Full" : "Incremental") + " scan: inspected " +
			callers.size() + " caller function(s) and " + callsSeen +
			" typed variadic call(s); added " + overridesAdded + " prototype override(s), " +
			existingOverrides + " already present, " + replacedOverrides +
			" incompatible override(s) replaced, " + ambiguousCalls + " left unchanged" +
			(fallbackOverrides == 0 ? "" : ", " + fallbackOverrides +
				" fallback override(s) recovered from stack cleanup") +
			(failedFunctions == 0 ? "." : ", " + failedFunctions + " decompilation failure(s)."));
		return true;
	}

	private Map<Address, Function> findTypedVariadicTargets(Program program) {
		Map<Address, Function> result = new HashMap<>();
		FunctionIterator functions = program.getFunctionManager().getFunctions(true);
		while (functions.hasNext()) {
			Function function = functions.next();
			if (!function.hasVarArgs() || function.getParameterCount() == 0 ||
				function.getSignatureSource() == SourceType.DEFAULT ||
				!usesTaskingConvention(function) ||
				!fixedPartExhaustsArgumentRegisters(function)) {
				continue;
			}
			boolean hasCompoundParameter = false;
			for (Parameter parameter : function.getParameters()) {
				if (parameter.getVariableStorage().getVarnodeCount() > 1) {
					hasCompoundParameter = true;
					break;
				}
			}
			if (hasCompoundParameter) {
				result.put(function.getEntryPoint(), function);
			}
		}
		return result;
	}

	private boolean usesTaskingConvention(Function function) {
		String name = function.getCallingConventionName();
		return CALLING_CONVENTION.equals(name) ||
			Function.DEFAULT_CALLING_CONVENTION_STRING.equals(name) ||
			Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(name);
	}

	private boolean fixedPartExhaustsArgumentRegisters(Function function) {
		// Once the fixed part has consumed R12-R15, every recovered trailing
		// trial is necessarily a real stack argument. A fixed parameter which
		// has already spilled to the stack is equally conclusive: TASKING's
		// failed register join exhausts the remaining register area. If neither
		// happened, speculative register trials cannot be distinguished from
		// real varargs without format-dependent guesses.
		Set<String> used = new HashSet<>();
		for (Parameter parameter : function.getParameters()) {
			VariableStorage storage = parameter.getVariableStorage();
			if (storage.hasStackStorage()) {
				return true;
			}
			List<Register> registers = storage.getRegisters();
			if (registers != null) {
				registers.forEach(register -> used.add(register.getName().toLowerCase()));
			}
		}
		return used.containsAll(Set.of("r12", "r13", "r14", "r15"));
	}

	private Set<Function> findCallers(Program program, Set<Address> targets,
			AddressSetView set, boolean fullScan) {
		Set<Function> callers = new LinkedHashSet<>();
		FunctionManager functions = program.getFunctionManager();
		for (Address target : targets) {
			Function targetFunction = functions.getFunctionAt(target);
			boolean targetAffected = !fullScan && targetFunction != null &&
				targetFunction.getBody().intersects(set);
			ReferenceIterator references = program.getReferenceManager().getReferencesTo(target);
			while (references.hasNext()) {
				Reference reference = references.next();
				if (!reference.getReferenceType().isCall()) {
					continue;
				}
				Function caller = functions.getFunctionContaining(reference.getFromAddress());
				if (caller != null && !caller.isExternal() &&
					(fullScan || targetAffected || caller.getBody().intersects(set))) {
					callers.add(caller);
				}
			}
		}
		return callers;
	}

	private FunctionDefinitionDataType buildOverride(Program program, Function target,
			PcodeOp call) {
		List<Integer> rawFixedSizes = new ArrayList<>();
		for (Parameter parameter : target.getParameters()) {
			VariableStorage storage = parameter.getVariableStorage();
			for (Varnode varnode : storage.getVarnodes()) {
				rawFixedSizes.add(varnode.getSize());
			}
		}

		int recoveredCount = call.getNumInputs() - 1;
		if (recoveredCount < rawFixedSizes.size()) {
			return null;
		}
		for (int i = 0; i < rawFixedSizes.size(); i++) {
			if (call.getInput(i + 1).getSize() != rawFixedSizes.get(i)) {
				// The decompiler already kept at least one compound fixed parameter intact,
				// so this is not the split-trial failure this analyzer repairs.
				return null;
			}
		}

		Instruction callInstruction = program.getListing().getInstructionAt(
			call.getSeqnum().getTarget());
		Integer optionalWords = optionalWordsAfterFixedStack(program.getListing(),
			callInstruction, target);
		if (optionalWords == null) {
			return null;
		}

		List<ParameterDefinition> parameters = new ArrayList<>();
		for (Parameter parameter : target.getParameters()) {
			parameters.add(new ParameterDefinitionImpl(parameter.getName(),
				currentFormalType(program, parameter.getFormalDataType()), null));
		}
		List<DataType> optionalTypes = recoveredOptionalTypes(program, call, optionalWords,
			rawFixedSizes.size() + 1);
		for (int i = 0; i < optionalTypes.size(); i++) {
			parameters.add(new ParameterDefinitionImpl("vararg_" + (i + 1),
				optionalTypes.get(i), null));
		}

		return createOverride(program, target, parameters);
	}

	private FunctionDefinitionDataType createOverride(Program program, Function target,
			List<ParameterDefinition> parameters) {
		FunctionDefinitionDataType signature = new FunctionDefinitionDataType(
			GENERATED_SIGNATURE_NAME, program.getDataTypeManager());
		try {
			signature.setCallingConvention(conventionFor(target));
		}
		catch (InvalidInputException e) {
			return null;
		}
		signature.setReturnType(target.getReturnType());
		signature.setArguments(parameters.toArray(ParameterDefinition[]::new));
		signature.setVarArgs(false);
		signature.setNoReturn(target.hasNoReturn());
		return signature;
	}

	private FunctionDefinitionDataType buildFallbackOverride(Program program, Function target,
			int optionalWordCount) {
		List<DataType> optionalTypes = new ArrayList<>();
		for (int i = 0; i < optionalWordCount; i++) {
			optionalTypes.add(Undefined.getUndefinedDataType(2));
		}
		return buildFallbackOverride(program, target, optionalTypes);
	}

	private FunctionDefinitionDataType buildFallbackOverride(Program program, Function target,
			List<DataType> optionalTypes) {
		List<ParameterDefinition> parameters = new ArrayList<>();
		for (Parameter parameter : target.getParameters()) {
			parameters.add(new ParameterDefinitionImpl(parameter.getName(),
				currentFormalType(program, parameter.getFormalDataType()), null));
		}
		for (int i = 0; i < optionalTypes.size(); i++) {
			parameters.add(new ParameterDefinitionImpl("vararg_" + (i + 1),
				optionalTypes.get(i), null));
		}
		return createOverride(program, target, parameters);
	}

	private List<DataType> recoveredSetupOptionalTypes(Program program, Function caller,
			Instruction call, Function target, int optionalWordCount, BasicBlockModel blocks,
			TaskMonitor monitor) throws CancelledException {
		C166TaskingCallArguments.CallWords words =
			C166TaskingCallArguments.recover(program, caller, call, blocks, monitor);
		int slot = 4 + fixedStackWords(target);
		List<DataType> result = new ArrayList<>();
		for (int consumed = 0; consumed < optionalWordCount;) {
			C166TaskingCallArguments.WordValue low = words.words().get(slot + consumed);
			C166TaskingCallArguments.WordValue high =
				words.words().get(slot + consumed + 1);
			DataType pointer = loadedPointerType(program, low, high);
			if (pointer != null && consumed + 1 < optionalWordCount) {
				result.add(pointer);
				consumed += 2;
			}
			else {
				result.add(Undefined.getUndefinedDataType(2));
				consumed++;
			}
		}
		return result;
	}

	private int fixedStackWords(Function target) {
		int words = 0;
		for (Parameter parameter : target.getParameters()) {
			VariableStorage storage = parameter.getVariableStorage();
			if (!storage.hasStackStorage() || storage.getStackOffset() < 0) {
				continue;
			}
			int end = storage.getStackOffset() + storage.size();
			words = Math.max(words, (end + 1) / 2);
		}
		return words;
	}

	private DataType loadedPointerType(Program program,
			C166TaskingCallArguments.WordValue low,
			C166TaskingCallArguments.WordValue high) {
		if (low == null || high == null) {
			return null;
		}
		if (low.parameterOrdinal() != null &&
			low.parameterOrdinal().equals(high.parameterOrdinal()) &&
			low.byteOffset() == 0 && high.byteOffset() == 2 &&
			low.originType() != null && isPointer(low.originType()) &&
			low.originType().getLength() == 4) {
			return currentFormalType(program, low.originType());
		}
		if (low.loadAddress() == null ||
			high.loadAddress() == null ||
			!high.loadAddress().equals(low.loadAddress().add(2))) {
			return null;
		}
		Data data = program.getListing().getDefinedDataAt(low.loadAddress());
		return data != null && data.getLength() == 4 && isPointer(data.getDataType())
			? currentFormalType(program, data.getDataType()) : null;
	}

	private List<DataType> recoveredOptionalTypes(Program program, PcodeOp call,
			int optionalWordCount, int firstOptionalInput) {
		int remainingBytes = optionalWordCount * 2;
		Map<Integer, DataType> recovered = new HashMap<>();
		Set<Integer> consumedInputs = new HashSet<>();
		// A previously generated word-wise override can force a pointer into two
		// 16-bit CALL inputs. Rejoin only when p-code proves that adjacent words
		// are byte offsets 0 and 2 of the same typed four-byte value.
		for (int i = call.getNumInputs() - 2;
				i >= firstOptionalInput && remainingBytes >= 4; i--) {
			DataType pointer = splitPointerType(program, call.getInput(i), call.getInput(i + 1));
			if (pointer == null) {
				continue;
			}
			recovered.put(i, pointer);
			consumedInputs.add(i);
			consumedInputs.add(i + 1);
			remainingBytes -= 4;
			i--;
		}
		// Prefer complete typed pointer values over their representation-only
		// word trials.  Old unsafe overrides can leave both forms on the CALL.
		for (int i = call.getNumInputs() - 1;
				i >= firstOptionalInput && remainingBytes != 0; i--) {
			if (consumedInputs.contains(i)) {
				continue;
			}
			Varnode input = call.getInput(i);
			DataType type = recoveredOptionalType(program, input);
			if (!isPointer(type) || input.getSize() > remainingBytes) {
				continue;
			}
			recovered.put(i, type);
			consumedInputs.add(i);
			remainingBytes -= input.getSize();
		}
		for (int i = call.getNumInputs() - 1;
				i >= firstOptionalInput && remainingBytes != 0; i--) {
			if (consumedInputs.contains(i)) {
				continue;
			}
			Varnode input = call.getInput(i);
			if (input.getSize() > remainingBytes) {
				continue;
			}
			DataType type = recoveredOptionalType(program, input);
			recovered.put(i, type);
			remainingBytes -= input.getSize();
		}
		if (remainingBytes != 0) {
			return java.util.Collections.nCopies(optionalWordCount,
				Undefined.getUndefinedDataType(2));
		}
		// Detection runs from the end to prefer the actual stack tail when old
		// overrides expose duplicate trials, but the signature must retain the
		// original left-to-right CALL input order.
		List<Integer> inputOrder = new ArrayList<>(recovered.keySet());
		inputOrder.sort(Integer::compareTo);
		List<DataType> result = new ArrayList<>();
		for (int inputIndex : inputOrder) {
			result.add(recovered.get(inputIndex));
		}
		return result;
	}

	private DataType recoveredOptionalType(Program program, Varnode input) {
		if (input.getHigh() != null) {
			DataType type = input.getHigh().getDataType();
			if (type != null && type.getLength() == input.getSize()) {
				DataType current = currentFormalType(program, type);
				if (current.getLength() == input.getSize()) {
					return current;
				}
			}
		}
		return Undefined.getUndefinedDataType(input.getSize());
	}

	private DataType splitPointerType(Program program, Varnode low, Varnode high) {
		if (low.getSize() != 2 || high.getSize() != 2) {
			return null;
		}
		DataType loadedPointer = adjacentLoadedPointerType(program, low, high);
		if (loadedPointer != null) {
			return loadedPointer;
		}
		PieceOrigin lowOrigin = pieceOrigin(low, 0, 0, new HashSet<>());
		PieceOrigin highOrigin = pieceOrigin(high, 0, 0, new HashSet<>());
		if (lowOrigin != null && highOrigin != null &&
			sameHighValue(lowOrigin.base(), highOrigin.base()) &&
			lowOrigin.byteOffset() == 0 && highOrigin.byteOffset() == 2) {
			DataType pointer = lowOrigin.pointerType() != null ? lowOrigin.pointerType()
					: highOrigin.pointerType();
			return pointer == null ? null : currentFormalType(program, pointer);
		}

		// The patched decompiler can retain pointer semantics on the 16-bit OFFSET
		// trial (rendered internally as char *16) while exposing PAGE separately.
		// Normalize that narrowed intermediate through the documented large-model
		// pointer type. Require evidence specifically on OFFSET so a scalar cannot
		// be joined to the PAGE half of a preceding pointer argument.
		DataType lowPointer = pointerEvidence(low, 0, new HashSet<>());
		DataType normalizedLowPointer = lowPointer == null ? null :
			currentFormalType(program, lowPointer);
		if (normalizedLowPointer != null && normalizedLowPointer.getLength() == 4) {
			return normalizedLowPointer;
		}

		// An old word-wise override can split an incoming far-pointer parameter
		// before HighVariable unification.  In that state the low word still has
		// pointer type evidence, while the page word is exposed as the next ABI
		// parameter.  Rejoin only an adjacent documented TASKING slot pair and
		// only when its data flow still contains an actual pointer type.  Two
		// unrelated scalar parameters therefore remain two scalar varargs.
		Integer lowSlot = parameterSlot(program, low, 0, new HashSet<>());
		Integer highSlot = parameterSlot(program, high, 0, new HashSet<>());
		if (lowSlot == null || highSlot == null || highSlot != lowSlot + 1 ||
			!isLegalPairStart(lowSlot)) {
			return null;
		}
		DataType pointer = pointerEvidence(low, 0, new HashSet<>());
		if (pointer == null) {
			pointer = pointerEvidence(high, 0, new HashSet<>());
		}
		return pointer == null ? null : currentFormalType(program, pointer);
	}

	/**
	 * Recover a typed far pointer loaded as two direct 16-bit words.
	 *
	 * <p>The C166 p-code keeps DPP as a live architectural register.  That is
	 * required for code which changes DPP inside a function, but it also means
	 * an operand-reference side effect is no longer guaranteed to carry the
	 * type of a static four-byte object into both word trials of an old variadic
	 * override.  The semantic evidence is the object itself: adjacent LOADs at
	 * offsets 0 and 2 of one defined four-byte pointer.</p>
	 */
	private DataType adjacentLoadedPointerType(Program program, Varnode low, Varnode high) {
		Long lowAddress = loadedAddress(low, 0, new HashSet<>());
		Long highAddress = loadedAddress(high, 0, new HashSet<>());
		if (lowAddress == null || highAddress == null || highAddress != lowAddress + 2) {
			return null;
		}
		Data data = program.getListing().getDefinedDataAt(toAddress(program, lowAddress));
		if (data == null || data.getLength() != 4 || !isPointer(data.getDataType())) {
			return null;
		}
		return currentFormalType(program, data.getDataType());
	}

	private Address toAddress(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private Long loadedAddress(Varnode node, int depth, Set<Varnode> visited) {
		if (node == null || depth > 24 || !visited.add(node)) {
			return null;
		}
		PcodeOp definition = node.getDef();
		if (definition == null) {
			return null;
		}
		switch (definition.getOpcode()) {
			case PcodeOp.LOAD:
				return definition.getNumInputs() < 2 ? null :
					constantValue(definition.getInput(1), depth + 1, new HashSet<>());
			case PcodeOp.COPY:
			case PcodeOp.CAST:
			case PcodeOp.INT_ZEXT:
			case PcodeOp.INT_SEXT:
			case PcodeOp.SUBPIECE:
			case PcodeOp.INDIRECT:
				return loadedAddress(definition.getInput(0), depth + 1, visited);
			default:
				return null;
		}
	}

	private Long constantValue(Varnode node, int depth, Set<Varnode> visited) {
		if (node == null || depth > 24 || !visited.add(node)) {
			return null;
		}
		if (node.isConstant() || node.isAddress()) {
			return node.getOffset();
		}
		PcodeOp definition = node.getDef();
		if (definition == null) {
			return null;
		}
		Long left;
		Long right;
		switch (definition.getOpcode()) {
			case PcodeOp.COPY:
			case PcodeOp.CAST:
			case PcodeOp.INT_ZEXT:
			case PcodeOp.INT_SEXT:
				return constantValue(definition.getInput(0), depth + 1, visited);
			case PcodeOp.SEGMENTOP:
				if (definition.getNumInputs() < 3) {
					return null;
				}
				left = constantValue(definition.getInput(1), depth + 1, new HashSet<>());
				right = constantValue(definition.getInput(2), depth + 1, new HashSet<>());
				return left == null || right == null ? null :
					((left & 0x3ffL) << 14) | (right & 0x3fffL);
			case PcodeOp.INT_ADD:
			case PcodeOp.INT_OR:
			case PcodeOp.INT_AND:
			case PcodeOp.INT_LEFT:
				left = constantValue(definition.getInput(0), depth + 1, new HashSet<>());
				right = constantValue(definition.getInput(1), depth + 1, new HashSet<>());
				if (left == null || right == null) {
					return null;
				}
				return switch (definition.getOpcode()) {
					case PcodeOp.INT_ADD -> left + right;
					case PcodeOp.INT_OR -> left | right;
					case PcodeOp.INT_AND -> left & right;
					default -> left << right;
				};
			default:
				return null;
		}
	}

	private boolean sameHighValue(Varnode left, Varnode right) {
		if (left.equals(right)) {
			return true;
		}
		HighVariable leftHigh = left.getHigh();
		HighVariable rightHigh = right.getHigh();
		return leftHigh != null && leftHigh == rightHigh;
	}

	private Integer parameterSlot(Program program, Varnode node, int depth,
			Set<Varnode> visited) {
		if (node == null || depth > 16 || !visited.add(node)) {
			return null;
		}
		HighVariable high = node.getHigh();
		HighSymbol symbol = high == null ? null : high.getSymbol();
		if (symbol != null && symbol.isParameter()) {
			Integer slot = storageSlot(symbol.getStorage());
			if (slot != null) {
				return slot;
			}
		}
		if (node.getDef() == null) {
			return registerSlot(program.getRegister(node));
		}
		PcodeOp definition = node.getDef();
		switch (definition.getOpcode()) {
			case PcodeOp.COPY:
			case PcodeOp.CAST:
			case PcodeOp.INT_ZEXT:
			case PcodeOp.INT_SEXT:
			case PcodeOp.SUBPIECE:
			case PcodeOp.INDIRECT:
				return parameterSlot(program, definition.getInput(0), depth + 1, visited);
			default:
				return null;
		}
	}

	private Integer storageSlot(VariableStorage storage) {
		if (storage == null || storage.size() != 2) {
			return null;
		}
		if (storage.isStackStorage() && storage.getStackOffset() >= 0 &&
			(storage.getStackOffset() & 1) == 0) {
			return 4 + storage.getStackOffset() / 2;
		}
		List<Register> registers = storage.getRegisters();
		return registers == null || registers.size() != 1 ? null :
			registerSlot(registers.get(0));
	}

	private Integer registerSlot(Register register) {
		if (register == null || register.getMinimumByteSize() != 2) {
			return null;
		}
		String name = register.getName().toLowerCase();
		if (!name.matches("r1[2-5]")) {
			return null;
		}
		return Integer.parseInt(name.substring(1)) - 12;
	}

	private boolean isLegalPairStart(int slot) {
		return slot >= 0 && slot <= 2 || slot >= 4;
	}

	private DataType pointerEvidence(Varnode node, int depth, Set<Varnode> visited) {
		if (node == null || depth > 16 || !visited.add(node)) {
			return null;
		}
		if (node.getHigh() != null && isPointer(node.getHigh().getDataType())) {
			return node.getHigh().getDataType();
		}
		PcodeOp definition = node.getDef();
		if (definition == null) {
			return null;
		}
		switch (definition.getOpcode()) {
			case PcodeOp.COPY:
			case PcodeOp.CAST:
			case PcodeOp.INT_ZEXT:
			case PcodeOp.INT_SEXT:
			case PcodeOp.SUBPIECE:
			case PcodeOp.INDIRECT:
				return pointerEvidence(definition.getInput(0), depth + 1, visited);
			default:
				return null;
		}
	}

	private PieceOrigin pieceOrigin(Varnode node, int byteOffset, int depth,
			Set<Varnode> visited) {
		if (node == null || depth > 16 || !visited.add(node)) {
			return null;
		}
		DataType pointerType = null;
		if (node.getHigh() != null && isPointer(node.getHigh().getDataType())) {
			pointerType = node.getHigh().getDataType();
		}
		PcodeOp definition = node.getDef();
		if (definition == null) {
			return node.getSize() >= 4 ? new PieceOrigin(node, byteOffset, pointerType) : null;
		}

		PieceOrigin origin = null;
		switch (definition.getOpcode()) {
			case PcodeOp.COPY:
			case PcodeOp.CAST:
				origin = pieceOrigin(definition.getInput(0), byteOffset, depth + 1, visited);
				break;
			case PcodeOp.SUBPIECE:
				if (definition.getInput(1).isConstant()) {
					origin = pieceOrigin(definition.getInput(0), byteOffset +
						(int) definition.getInput(1).getOffset(), depth + 1, visited);
				}
				break;
			case PcodeOp.INT_RIGHT:
			case PcodeOp.INT_SRIGHT:
				if (definition.getInput(1).isConstant() &&
					(definition.getInput(1).getOffset() & 7) == 0) {
					origin = pieceOrigin(definition.getInput(0), byteOffset +
						(int) (definition.getInput(1).getOffset() / 8), depth + 1, visited);
				}
				break;
			default:
				return null;
		}
		if (origin == null || origin.pointerType() != null || pointerType == null) {
			return origin;
		}
		return new PieceOrigin(origin.base(), origin.byteOffset(), pointerType);
	}

	private record PieceOrigin(Varnode base, int byteOffset, DataType pointerType) {
	}

	private Set<Address> repairInvalidPrototypeOverrides(Program program, Function caller,
			HighFunction highFunction, Map<Address, Function> variadicTargets,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		Set<Address> removed = new HashSet<>();
		BasicBlockModel blocks = new BasicBlockModel(program);
		Iterator<PcodeOpAST> operations = highFunction.getPcodeOps();
		while (operations.hasNext()) {
			monitor.checkCancelled();
			PcodeOpAST operation = operations.next();
			if (operation.getOpcode() != PcodeOp.CALL || operation.getNumInputs() < 2) {
				continue;
			}
			Function target = variadicTargets.get(operation.getInput(0).getAddress());
			if (target == null) {
				continue;
			}
			Address callSite = operation.getSeqnum().getTarget();
			DataTypeSymbol existing = prototypeOverride(caller, callSite);
			Instruction call = program.getListing().getInstructionAt(callSite);
			boolean valid = existing != null &&
				validPrototypeOverride(program, target, call, existing);
			boolean refinePointer = valid &&
				needsPointerRefinement(program, target, operation, existing);
			boolean normalizeScalars = valid &&
				needsScalarNormalization(target, operation, existing);
			List<DataType> setupTypes = null;
			boolean refineSetup = false;
			Integer optionalWords = optionalWordsAfterFixedStack(
				program.getListing(), call, target);
			if (valid && optionalWords != null &&
				existing.getDataType() instanceof FunctionDefinition definition) {
				setupTypes = recoveredSetupOptionalTypes(program, caller, call, target,
					optionalWords, blocks, monitor);
				refineSetup = needsSetupRefinement(target, definition, setupTypes);
			}
			if (existing == null ||
				valid && !refineSetup && !refinePointer && !normalizeScalars) {
				continue;
			}

			FunctionDefinitionDataType replacement = null;
			if (refineSetup) {
				replacement = buildFallbackOverride(program, target, setupTypes);
			}
			else if (normalizeScalars &&
				existing.getDataType() instanceof FunctionDefinition definition) {
				replacement = buildFallbackOverride(program, target,
					normalizedOptionalTypes(program, target, operation, definition));
			}
			else if (refinePointer) {
				if (optionalWords != null) {
					replacement = buildFallbackOverride(program, target,
						recoveredOptionalTypes(program, operation, optionalWords,
							target.getParameterCount() + 1));
					if (replacement != null && !validPrototypeDefinition(program, target,
						call, replacement)) {
						replacement = null;
					}
				}
			}
			Symbol symbol = existing.getSymbol();
			if (symbol != null && symbol.delete()) {
				removed.add(callSite);
				if (replacement != null) {
					try {
						HighFunctionDBUtil.writeOverride(caller, callSite, replacement);
					}
					catch (InvalidInputException e) {
						log.appendException(e);
					}
				}
			}
		}
		return removed;
	}

	/**
	 * A raw decompiler CALL may coalesce several optional stack words into one
	 * undefined compound input.  Cleanup makes the byte count valid, so the old
	 * override would otherwise survive forever.  Replace it only when listing
	 * data flow proves at least one typed pointer origin and its pointer/scalar
	 * grouping differs from the saved override.
	 */
	private boolean needsSetupRefinement(Function target,
			FunctionDefinition definition, List<DataType> setupTypes) {
		if (setupTypes == null || setupTypes.stream().noneMatch(this::isPointer)) {
			return false;
		}
		ParameterDefinition[] arguments = definition.getArguments();
		int fixed = target.getParameterCount();
		if (arguments.length - fixed != setupTypes.size()) {
			return true;
		}
		for (int i = 0; i < setupTypes.size(); i++) {
			DataType saved = arguments[fixed + i].getDataType();
			DataType recovered = setupTypes.get(i);
			if (saved.getLength() != recovered.getLength() ||
				isPointer(saved) != isPointer(recovered)) {
				return true;
			}
		}
		return false;
	}

	private boolean needsScalarNormalization(Function target, PcodeOp call,
			DataTypeSymbol symbol) {
		if (!(symbol.getDataType() instanceof FunctionDefinition definition)) {
			return false;
		}
		ParameterDefinition[] arguments = definition.getArguments();
		int fixedCount = target.getParameterCount();
		// A stale override can leave extra representation-only trials at the end
		// of the CALL.  Its declared arguments still map one-for-one to the
		// leading inputs, which are the only inputs inspected here.
		if (call.getNumInputs() < arguments.length + 1) {
			return false;
		}
		for (int i = fixedCount; i < arguments.length; i++) {
			DataType type = arguments[i].getDataType();
			if (isPointer(type) && type.getLength() == 4 &&
				isPromotedScalarPair(call.getInput(i + 1), 0, new HashSet<>())) {
				return true;
			}
		}
		return false;
	}

	private List<DataType> normalizedOptionalTypes(Program program, Function target,
			PcodeOp call, FunctionDefinition definition) {
		List<DataType> result = new ArrayList<>();
		ParameterDefinition[] arguments = definition.getArguments();
		for (int i = target.getParameterCount(); i < arguments.length; i++) {
			DataType type = currentFormalType(program, arguments[i].getDataType());
			if (isPointer(type) && type.getLength() == 4 &&
				isPromotedScalarPair(call.getInput(i + 1), 0, new HashSet<>())) {
				result.add(Undefined.getUndefinedDataType(2));
				result.add(Undefined.getUndefinedDataType(2));
			}
			else {
				result.add(type);
			}
		}
		return result;
	}

	private boolean isPromotedScalarPair(Varnode node, int depth, Set<Varnode> visited) {
		if (node == null || depth > 16 || !visited.add(node)) {
			return false;
		}
		PcodeOp definition = node.getDef();
		if (definition == null) {
			return false;
		}
		switch (definition.getOpcode()) {
			case PcodeOp.COPY:
			case PcodeOp.CAST:
			case PcodeOp.INT_ZEXT:
			case PcodeOp.INT_SEXT:
			case PcodeOp.INDIRECT:
				return isPromotedScalarPair(definition.getInput(0), depth + 1, visited);
			case PcodeOp.INT_AND:
				return definition.getInput(1).isConstant() &&
					definition.getInput(1).getOffset() == 0xff00ff &&
					isPackedPromotedBytePair(definition.getInput(0));
			case PcodeOp.PIECE:
				return (isScalarByte(definition.getInput(0)) &&
					isPromotedScalarWord(definition.getInput(1), 0, new HashSet<>())) ||
					(isPromotedScalarWord(definition.getInput(0), 0, new HashSet<>()) &&
					isPromotedScalarWord(definition.getInput(1), 0, new HashSet<>()));
			case PcodeOp.SEGMENTOP:
				return definition.getNumInputs() >= 3 &&
					isPromotedScalarWord(definition.getInput(1), 0, new HashSet<>()) &&
					isPromotedScalarWord(definition.getInput(2), 0, new HashSet<>());
			default:
				return false;
		}
	}

	private boolean isPackedPromotedBytePair(Varnode node) {
		PcodeOp piece = node == null ? null : node.getDef();
		if (piece == null || piece.getOpcode() != PcodeOp.PIECE ||
			piece.getNumInputs() != 2) {
			return false;
		}
		Varnode highByte = piece.getInput(0);
		Varnode word = piece.getInput(1);
		PcodeOp subpiece = highByte.getDef();
		return highByte.getSize() == 1 && word.getSize() == 2 &&
			subpiece != null && subpiece.getOpcode() == PcodeOp.SUBPIECE &&
			subpiece.getNumInputs() == 2 && subpiece.getInput(0).equals(word) &&
			subpiece.getInput(1).isConstant() &&
			subpiece.getInput(1).getOffset() == 1;
	}

	private boolean isScalarByte(Varnode node) {
		return node != null && node.getSize() == 1 &&
			(node.getHigh() == null || !isPointer(node.getHigh().getDataType()));
	}

	private boolean isPromotedScalarWord(Varnode node, int depth, Set<Varnode> visited) {
		if (node == null || depth > 16 || !visited.add(node)) {
			return false;
		}
		PcodeOp definition = node.getDef();
		if (definition == null) {
			return false;
		}
		switch (definition.getOpcode()) {
			case PcodeOp.INT_ZEXT:
			case PcodeOp.INT_SEXT:
				return definition.getInput(0).getSize() < node.getSize();
			case PcodeOp.COPY:
			case PcodeOp.CAST:
			case PcodeOp.SUBPIECE:
			case PcodeOp.INDIRECT:
				return isPromotedScalarWord(definition.getInput(0), depth + 1, visited);
			case PcodeOp.INT_AND:
				Varnode mask = definition.getInput(1);
				return mask.isConstant() && mask.getOffset() <= 0xff;
			case PcodeOp.INT_RIGHT:
			case PcodeOp.INT_SRIGHT:
				Varnode shift = definition.getInput(1);
				return shift.isConstant() && shift.getOffset() > 0 &&
					(shift.getOffset() & 7) == 0;
			default:
				return false;
		}
	}

	private boolean needsPointerRefinement(Program program, Function target, PcodeOp call,
			DataTypeSymbol symbol) {
		if (!(symbol.getDataType() instanceof FunctionDefinition definition)) {
			return false;
		}
		int fixedCount = target.getParameterCount();
		ParameterDefinition[] arguments = definition.getArguments();
		if (arguments.length - fixedCount < 2 ||
			call.getNumInputs() < arguments.length + 1) {
			return false;
		}
		// With a saved override, CALL input zero is the target and every later
		// input corresponds one-for-one to an override parameter.  Inspect only
		// adjacent optional 16-bit parameters: scanning fixed inputs could make a
		// correct override look stale merely because it also has far pointers.
		for (int i = fixedCount; i + 1 < arguments.length; i++) {
			DataType lowType = arguments[i].getDataType();
			DataType highType = arguments[i + 1].getDataType();
			if (lowType.getLength() != 2 || highType.getLength() != 2 ||
				isPointer(lowType) || isPointer(highType)) {
				continue;
			}
			if (splitPointerType(program, call.getInput(i + 1), call.getInput(i + 2)) != null) {
				return true;
			}
		}
		return false;
	}

	private boolean validPrototypeOverride(Program program, Function target, Instruction call,
			DataTypeSymbol symbol) {
		if (!(symbol.getDataType() instanceof FunctionDefinition definition)) {
			return false;
		}
		return validPrototypeDefinition(program, target, call, definition);
	}

	private boolean validPrototypeDefinition(Program program, Function target, Instruction call,
			FunctionDefinition definition) {
		if (definition.hasVarArgs() ||
			!conventionFor(target).equals(definition.getCallingConventionName())) {
			return false;
		}
		ParameterDefinition[] arguments = definition.getArguments();
		Parameter[] fixed = target.getParameters();
		if (arguments.length < fixed.length) {
			return false;
		}
		for (int i = 0; i < fixed.length; i++) {
			DataType expected = currentFormalType(program, fixed[i].getFormalDataType());
			DataType actual = arguments[i].getDataType();
			if (expected.getLength() != actual.getLength() ||
				isPointer(expected) != isPointer(actual)) {
				return false;
			}
		}
		Integer optionalWords = optionalWordsAfterFixedStack(program.getListing(), call, target);
		if (optionalWords == null) {
			return false;
		}
		int optionalBytes = 0;
		for (int i = fixed.length; i < arguments.length; i++) {
			int length = arguments[i].getDataType().getLength();
			if (length <= 0) {
				return false;
			}
			optionalBytes += length;
		}
		return optionalBytes == optionalWords * 2;
	}

	private int addCleanupFallbackOverrides(Program program, Function caller,
			Map<Address, Function> variadicTargets, BasicBlockModel blocks,
			TaskMonitor monitor, MessageLog log) throws CancelledException {
		Listing listing = program.getListing();
		int added = 0;
		for (Instruction instruction : listing.getInstructions(caller.getBody(), true)) {
			if (!instruction.getFlowType().isCall()) {
				continue;
			}
			Function target = null;
			for (Address flow : instruction.getFlows()) {
				target = variadicTargets.get(flow);
				if (target != null) {
					break;
				}
			}
			Address callSite = instruction.getAddress();
			if (target == null || hasPrototypeOverride(caller, callSite)) {
				continue;
			}

			Integer optionalWords = optionalWordsAfterFixedStack(listing, instruction, target);
			if (optionalWords == null) {
				continue;
			}
			FunctionDefinitionDataType override = buildFallbackOverride(program, target,
				recoveredSetupOptionalTypes(program, caller, instruction, target,
					optionalWords, blocks, monitor));
			if (override == null) {
				continue;
			}
			try {
				HighFunctionDBUtil.writeOverride(caller, callSite, override);
				added++;
			}
			catch (InvalidInputException e) {
				log.appendException(e);
			}
		}
		return added;
	}

	private Integer optionalWordsAfterFixedStack(Listing listing, Instruction call,
			Function target) {
		if (call == null) {
			return null;
		}
		Integer cleanupWords = optionalWordsFromCleanup(listing, call);
		if (cleanupWords == null) {
			return null;
		}
		int fixedStackWords = 0;
		for (Parameter parameter : target.getParameters()) {
			VariableStorage storage = parameter.getVariableStorage();
			if (storage.hasStackStorage()) {
				fixedStackWords += (storage.size() + 1) / 2;
			}
		}
		return cleanupWords < fixedStackWords ? null : cleanupWords - fixedStackWords;
	}

	private Integer optionalWordsFromCleanup(Listing listing, Instruction call) {
		Address fallThrough = call.getFallThrough();
		if (fallThrough == null) {
			return null;
		}
		Instruction cleanup = listing.getInstructionAt(fallThrough);
		if (cleanup == null || !"add".equalsIgnoreCase(cleanup.getMnemonicString())) {
			return 0;
		}
		Register destination = cleanup.getRegister(0);
		if (destination == null || !"r0".equalsIgnoreCase(destination.getName())) {
			return 0;
		}
		for (Object object : cleanup.getOpObjects(1)) {
			if (!(object instanceof Scalar scalar)) {
				continue;
			}
			long bytes = scalar.getUnsignedValue();
			if (bytes <= 0x100 && (bytes & 1) == 0) {
				return (int) bytes / 2;
			}
		}
		return null;
	}

	private String conventionFor(Function target) {
		int fixedParameterCount = target.getParameterCount();
		if (fixedParameterCount >= 1 && fixedParameterCount <= 3) {
			return VARARG_CONVENTION_PREFIX + fixedParameterCount;
		}
		return CALLING_CONVENTION;
	}

	private boolean isPointer(DataType type) {
		return type instanceof Pointer || type instanceof TypeDef typeDef && typeDef.isPointer();
	}

	private DataType currentFormalType(Program program, DataType type) {
		DataType pointerType = type;
		while (pointerType instanceof TypeDef typeDef) {
			pointerType = typeDef.getBaseDataType();
		}
		if (pointerType instanceof Pointer pointer) {
			return new PointerDataType(pointer.getDataType(), program.getDataTypeManager());
		}
		return type;
	}

	private DataTypeSymbol prototypeOverride(Function caller, Address callSite) {
		if (HighFunction.findOverrideSpace(caller) == null) {
			return null;
		}
		for (Symbol symbol : caller.getProgram().getSymbolTable().getSymbols(callSite)) {
			if (symbol.getSymbolType() == SymbolType.LABEL &&
				HighFunction.isOverrideNamespace(symbol.getParentNamespace())) {
				DataTypeSymbol override = HighFunctionDBUtil.readOverride(symbol);
				if (override != null) {
					return override;
				}
			}
		}
		return null;
	}

	private boolean hasPrototypeOverride(Function caller, Address callSite) {
		return prototypeOverride(caller, callSite) != null;
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
}
