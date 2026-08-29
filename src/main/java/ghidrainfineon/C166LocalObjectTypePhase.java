package ghidrainfineon;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Retypes analyzer-owned stack objects from concrete direct-callee pointer
 * parameters.  Only an exact local base address and an exact size-preserving
 * object/array type are accepted.
 */
public class C166LocalObjectTypePhase extends C166TaskingTypeInferencePhase {

	private static final int MAX_TRACE_DEPTH = 32;
	private static final int DECOMPILE_TIMEOUT_SECONDS = 10;
	private int lastDecompilations;
	private RunStatistics lastRunStatistics = RunStatistics.empty();

	public C166LocalObjectTypePhase() {
		super("C166 TASKING Local Object Types");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		lastDecompilations = 0;
		if (!canAnalyze(program)) {
			return true;
		}
		List<Function> candidateFunctions = new ArrayList<>();
		int candidatesWithWeakDatabaseLocal = 0;
		Iterator<Function> scoped = set == null || set.isEmpty() ?
			program.getFunctionManager().getFunctions(true) :
			program.getFunctionManager().getFunctionsOverlapping(set);
		while (scoped.hasNext()) {
			monitor.checkCancelled();
			Function function = scoped.next();
			if (!C166AnalysisFunctions.hasUsableBody(function) || function.isThunk() ||
				!hasConcreteLocalPointerCall(program, function)) {
				continue;
			}
			candidateFunctions.add(function);
			if (hasWeakDatabaseLocal(function)) {
				candidatesWithWeakDatabaseLocal++;
			}
		}
		int candidates = candidateFunctions.size();
		if (candidateFunctions.isEmpty()) {
			lastRunStatistics = RunStatistics.empty();
			report(program, "Inspected 0 exact local-pointer candidate function(s); " +
				"retyped 0 exact-size local stack object(s), rejected 0 conflicting " +
				"local type candidate(s), 0 decompilation failure(s); 0 candidate(s) " +
				"had a weak persisted stack local and 0 retype(s) required a " +
				"dynamic-only HighSymbol.");
			return true;
		}
		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(false);
		decompiler.toggleSyntaxTree(true);
		if (!decompiler.openProgram(program)) {
			return false;
		}
		int changed = 0;
		int conflicts = 0;
		int decompileFailures = 0;
		int retypedWithoutWeakDatabaseLocal = 0;
		try {
			for (Function function : candidateFunctions) {
				monitor.checkCancelled();
				boolean weakDatabaseLocal = hasWeakDatabaseLocal(function);
				int changedBeforeFunction = changed;
				lastDecompilations++;
				DecompileResults results = decompiler.decompileFunction(function,
					DECOMPILE_TIMEOUT_SECONDS, monitor);
				if (!results.decompileCompleted() || results.getHighFunction() == null) {
					decompileFailures++;
					continue;
				}
				Map<LocalKey, LocalInference> inferred = new HashMap<>();
				Set<LocalKey> rejected = new HashSet<>();
				var operations = results.getHighFunction().getPcodeOps();
				while (operations.hasNext()) {
					PcodeOpAST operation = operations.next();
					if (operation.getOpcode() != PcodeOp.CALL ||
						operation.getNumInputs() == 0) {
						continue;
					}
					Function callee = program.getFunctionManager().getFunctionAt(
						operation.getInput(0).getAddress());
					if (callee == null) {
						continue;
					}
					collectCallInferences(program, function, results.getHighFunction(), callee,
						operation, inferred, rejected);
				}
				for (Map.Entry<LocalKey, LocalInference> entry : inferred.entrySet()) {
					if (rejected.contains(entry.getKey())) {
						conflicts++;
						continue;
					}
					LocalInference inference = entry.getValue();
					LocalObject local = inference.local();
					if (local.symbol().isTypeLocked() ||
						local.variable() != null &&
							local.variable().getSource() == SourceType.USER_DEFINED ||
						!isWeakLocalType(local.currentType()) ||
						local.length() != inference.type().getLength()) {
						continue;
					}
					try {
						// Commit the exact HighSymbol selected by the decompiler.  Updating the
						// backing Variable directly can leave a dynamic stack HighSymbol mapped
						// to its old undefined-byte array on the next decompilation.
						HighFunctionDBUtil.updateDBVariable(local.symbol(),
							local.symbol().getName(), inference.type(), SourceType.ANALYSIS);
						changed++;
					}
					catch (InvalidInputException | ghidra.util.exception.DuplicateNameException e) {
						log.appendException(e);
					}
					catch (IllegalArgumentException e) {
						// A stale HighSymbol can have stack storage but no mappable PC address.
						// Reject that optional local retype without aborting the analyzer.
						conflicts++;
					}
				}
				if (!weakDatabaseLocal && changed != changedBeforeFunction) {
					retypedWithoutWeakDatabaseLocal++;
				}
			}
		}
		finally {
			decompiler.dispose();
		}
		lastRunStatistics = new RunStatistics(candidates,
			candidatesWithWeakDatabaseLocal, retypedWithoutWeakDatabaseLocal,
			changed, conflicts, decompileFailures, lastDecompilations);
		report(program, "Inspected " + candidates + " exact local-pointer candidate " +
			"function(s); retyped " + changed + " exact-size local stack object(s), " +
			"rejected " + conflicts + " conflicting local type candidate(s), " +
			decompileFailures + " decompilation failure(s); " +
			candidatesWithWeakDatabaseLocal + " candidate(s) had a weak persisted stack " +
			"local and " + retypedWithoutWeakDatabaseLocal +
			" retype(s) required a dynamic-only HighSymbol.");
		return true;
	}

	public int getLastDecompilations() {
		return lastDecompilations;
	}

	public RunStatistics getLastRunStatistics() {
		return lastRunStatistics;
	}

	private boolean hasWeakDatabaseLocal(Function function) {
		for (Variable variable : function.getLocalVariables()) {
			if (variable.getVariableStorage().isStackStorage() &&
				variable.getSource() != SourceType.USER_DEFINED &&
				isWeakLocalType(variable.getDataType())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Cheap TASKING preflight for a concrete pointer argument whose low word is
	 * derived from R0 at that exact call.  Keeping the call, parameter storage,
	 * and local-address evidence tied together avoids decompiling a whole function
	 * merely because it contains an unrelated stack calculation and an unrelated
	 * pointer-taking call.
	 */
	private boolean hasConcreteLocalPointerCall(Program program, Function function) {
		Register stackPointer = program.getRegister("r0");
		if (stackPointer == null) {
			return false;
		}
		for (Instruction instruction :
				C166AnalysisEvidenceIndex.flowInstructions(program, function)) {
			if (!instruction.getFlowType().isCall()) {
				continue;
			}
			Function callee = directCallee(program, instruction);
			if (callee == null) {
				continue;
			}
			for (Parameter parameter : callee.getParameters()) {
				if (concretePointee(parameter.getFormalDataType()) == null) {
					continue;
				}
				var registers = parameter.getVariableStorage().getRegisters();
				if (registers == null) {
					continue;
				}
				for (Register argument : registers) {
					if (!overlaps(argument, stackPointer) && tracesLocalAddress(program,
							function, instruction, argument, stackPointer)) {
						return true;
					}
				}
			}
		}
		return false;
	}

	private Function directCallee(Program program, Instruction call) {
		for (ghidra.program.model.address.Address flow : call.getFlows()) {
			Function callee = program.getFunctionManager().getFunctionAt(flow);
			if (callee != null) {
				return callee;
			}
		}
		for (Reference reference : call.getReferencesFrom()) {
			if (reference.getReferenceType().isCall()) {
				Function callee = program.getFunctionManager()
					.getFunctionAt(reference.getToAddress());
				if (callee != null) {
					return callee;
				}
			}
		}
		return null;
	}

	private boolean tracesLocalAddress(Program program, Function function,
			Instruction call, Register argument, Register stackPointer) {
		Register tracked = argument;
		Instruction instruction = program.getListing().getInstructionBefore(call.getAddress());
		int remaining = 256;
		while (instruction != null && function.getBody().contains(instruction.getAddress()) &&
			remaining-- > 0) {
			if (instruction.getFlowType().isCall() || instruction.getFlowType().isJump()) {
				return false;
			}
			Register destination = operandRegister(instruction, 0);
			if (destination == null || !overlaps(destination, tracked)) {
				instruction = program.getListing().getInstructionBefore(instruction.getAddress());
				continue;
			}
			if (instruction.getNumOperands() < 2 ||
				OperandType.isIndirect(instruction.getOperandType(0))) {
				return false;
			}
			String mnemonic = instruction.getMnemonicString().toLowerCase();
			Register source = operandRegister(instruction, 1);
			if ((mnemonic.equals("add") || mnemonic.equals("mov")) && source != null) {
				if (overlaps(source, stackPointer)) {
					return true;
				}
				if (mnemonic.equals("mov") && !OperandType.isIndirect(
						instruction.getOperandType(1))) {
					tracked = source;
					instruction = program.getListing()
						.getInstructionBefore(instruction.getAddress());
					continue;
				}
			}
			if ((mnemonic.equals("and") || mnemonic.equals("add") ||
				mnemonic.equals("sub")) && source == null &&
				!OperandType.isIndirect(instruction.getOperandType(1))) {
				instruction = program.getListing().getInstructionBefore(instruction.getAddress());
				continue;
			}
			return false;
		}
		return false;
	}

	private boolean overlaps(Register left, Register right) {
		if (left == null || right == null ||
			!left.getAddress().getAddressSpace().equals(
				right.getAddress().getAddressSpace())) {
			return false;
		}
		long leftStart = left.getAddress().getOffset();
		long rightStart = right.getAddress().getOffset();
		long leftEnd = leftStart + left.getMinimumByteSize();
		long rightEnd = rightStart + right.getMinimumByteSize();
		return leftStart < rightEnd && rightStart < leftEnd;
	}

	private Register operandRegister(Instruction instruction, int operand) {
		for (Object object : instruction.getOpObjects(operand)) {
			if (object instanceof Register register) {
				return register;
			}
		}
		return null;
	}

	private void collectCallInferences(Program program, Function caller,
			HighFunction highFunction, Function callee, PcodeOp operation,
			Map<LocalKey, LocalInference> inferred,
			Set<LocalKey> rejected) {
		int inputIndex = 1;
		for (Parameter parameter : callee.getParameters()) {
			int storageSize = parameter.getVariableStorage().size();
			if (storageSize <= 0 || inputIndex >= operation.getNumInputs()) {
				return;
			}
			Varnode whole = null;
			int consumed = 0;
			while (inputIndex < operation.getNumInputs() && consumed < storageSize) {
				Varnode input = operation.getInput(inputIndex++);
				if (input.getSize() > storageSize - consumed) {
					return;
				}
				if (consumed == 0 && input.getSize() == storageSize) {
					whole = input;
				}
				consumed += input.getSize();
			}
			if (consumed != storageSize) {
				return;
			}
			DataType target = concretePointee(parameter.getFormalDataType());
			if (whole == null || target == null) {
				continue;
			}
			LocalObject local = localObject(caller, highFunction, whole,
				new HashSet<>(), 0);
			if (local == null) {
				continue;
			}
			DataType desired = localObjectType(program, target, local.length());
			if (desired == null) {
				continue;
			}
			LocalKey key = new LocalKey(local.stackOffset(), local.length());
			LocalInference previous = inferred.putIfAbsent(key,
				new LocalInference(local, desired));
			if (previous != null && !previous.type().isEquivalent(desired)) {
				rejected.add(key);
			}
		}
	}

	private LocalObject localObject(Function function, HighFunction highFunction,
			Varnode value, Set<Varnode> visited, int depth) {
		if (value == null || depth > MAX_TRACE_DEPTH || !visited.add(value)) {
			return null;
		}
		HighVariable high = value.getHigh();
		HighSymbol symbol = high == null ? null : high.getSymbol();
		if (symbol != null && !symbol.isParameter() && !symbol.isGlobal() &&
			symbol.getStorage().isStackStorage()) {
			Variable variable = HighFunctionDBUtil.getFunctionVariable(symbol);
			return new LocalObject(symbol, variable,
				symbol.getStorage().getStackOffset(), symbol.getSize(), symbol.getDataType());
		}
		PcodeOp definition = value.getDef();
		if (definition == null) {
			return null;
		}
		switch (definition.getOpcode()) {
			case PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INDIRECT:
			case PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT:
				return localObject(function, highFunction, definition.getInput(0), visited,
					depth + 1);
			case PcodeOp.SEGMENTOP:
				if (definition.getNumInputs() != 3) {
					return null;
				}
				return localObject(function, highFunction, definition.getInput(2), visited,
					depth + 1);
			case PcodeOp.INT_AND:
				if (definition.getNumInputs() == 2) {
					for (int index = 0; index < 2; index++) {
						Varnode mask = definition.getInput(index);
						if (mask.isConstant() &&
							(mask.getOffset() == 0x3fffL ||
								mask.getOffset() == 0xffff3fffL)) {
							return localObject(function, highFunction,
								definition.getInput(1 - index), visited, depth + 1);
						}
					}
				}
				return null;
			case PcodeOp.PTRSUB, PcodeOp.PTRADD: {
				ghidra.program.model.address.Address stack =
					HighFunctionDBUtil.getSpacebaseReferenceAddress(
						function.getProgram().getAddressFactory(), definition);
				if (stack == null || !stack.isStackAddress()) {
					return null;
				}
				Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
				while (symbols.hasNext()) {
					HighSymbol local = symbols.next();
					if (local.isParameter() || local.isGlobal() ||
						!local.getStorage().isStackStorage() ||
						local.getStorage().getStackOffset() != stack.getOffset()) {
						continue;
					}
					Variable variable = HighFunctionDBUtil.getFunctionVariable(local);
					return new LocalObject(local, variable,
						local.getStorage().getStackOffset(), local.getSize(),
						local.getDataType());
				}
				return null;
			}
			default:
				return null;
		}
	}

	private DataType concretePointee(DataType type) {
		while (type instanceof TypeDef typeDef) {
			type = typeDef.getBaseDataType();
		}
		if (!(type instanceof Pointer pointer) || pointer.getLength() != 4 ||
			pointer.getDataType() instanceof VoidDataType ||
			pointer.getDataType() instanceof FunctionDefinition) {
			return null;
		}
		// A width-specific undefined2/undefined4 pointee still carries exact object
		// size evidence. This is enough to collapse an analyzer-owned byte array
		// into one ABI-sized output object.
		if (Undefined.isUndefined(pointer.getDataType()) &&
			pointer.getDataType().getLength() <= 1) {
			return null;
		}
		return pointer.getDataType();
	}

	private DataType localObjectType(Program program, DataType element, int size) {
		int elementSize = element.getLength();
		if (elementSize <= 0 || size <= 0 || size % elementSize != 0) {
			return null;
		}
		if (Undefined.isUndefined(element)) {
			// Ghidra does not persist undefined2/undefined4 as an explicit local
			// datatype: the next decompilation expands it back into undefined1[].
			// Use the same-width unsigned bit-vector as the stable ABI-neutral form.
			element = AbstractIntegerDataType.getUnsignedDataType(elementSize,
				program.getDataTypeManager());
		}
		if (size == elementSize) {
			return element;
		}
		return new ArrayDataType(element, size / elementSize, elementSize,
			program.getDataTypeManager());
	}

	private boolean isWeakLocalType(DataType type) {
		return Undefined.isUndefined(type) ||
			type instanceof Array array && Undefined.isUndefined(array.getDataType());
	}

	private void report(Program program, String message) {
		ghidra.app.plugin.core.analysis.AutoAnalysisManager manager =
			ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(program);
		ghidra.framework.plugintool.PluginTool tool = manager.getAnalysisTool();
		if (tool != null) {
			ghidra.app.services.ConsoleService console =
				tool.getService(ghidra.app.services.ConsoleService.class);
			if (console != null) {
				console.addMessage(getName(), message);
				return;
			}
		}
		ghidra.util.Msg.info(this, getName() + "> " + message);
	}

	private record LocalKey(int stackOffset, int length) {
	}

	private record LocalObject(HighSymbol symbol, Variable variable, int stackOffset,
			int length, DataType currentType) {
	}

	private record LocalInference(LocalObject local, DataType type) {
	}

	public record RunStatistics(int candidates, int candidatesWithWeakDatabaseLocal,
			int retypedWithoutWeakDatabaseLocal, int retypedObjects, int conflicts,
			int decompileFailures, int decompilations) {
		private static RunStatistics empty() {
			return new RunStatistics(0, 0, 0, 0, 0, 0, 0);
		}
	}
}
