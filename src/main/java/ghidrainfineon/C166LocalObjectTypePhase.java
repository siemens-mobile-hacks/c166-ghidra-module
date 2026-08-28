package ghidrainfineon;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
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
import ghidra.program.model.listing.Function;
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

	public C166LocalObjectTypePhase() {
		super("C166 TASKING Local Object Types");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		if (!canAnalyze(program)) {
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
		try {
			Iterator<Function> functions = set == null || set.isEmpty() ?
				program.getFunctionManager().getFunctions(true) :
				program.getFunctionManager().getFunctionsOverlapping(set);
			while (functions.hasNext()) {
				monitor.checkCancelled();
				Function function = functions.next();
				if (function.isExternal() || function.isThunk()) {
					continue;
				}
				DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
				if (!results.decompileCompleted() || results.getHighFunction() == null) {
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
				}
			}
		}
		finally {
			decompiler.dispose();
		}
		report(program, "Retyped " + changed + " exact-size local stack object(s), " +
			"rejected " + conflicts + " conflicting local type candidate(s).");
		return true;
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
}
