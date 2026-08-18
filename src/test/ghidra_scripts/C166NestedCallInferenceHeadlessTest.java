// Real-program regression for nested stack arguments, R5:R4 return
// classification, and mixed pointer/scalar variadic arguments.
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidrainfineon.C166TaskingTypeInferenceAnalyzer;

public class C166NestedCallInferenceHeadlessTest extends GhidraScript {

	private static final long LENGTH_WRAPPER = 0x39b5a4;
	private static final long ALLOCATOR = 0x39bcf8;
	private static final long FORMATTER_WRAPPER = 0x3c32dc;
	private static final long REPRESENTATIVE_CALLER = 0x37c104;
	private static final long SPRINTF_CALL = 0x3c332c;

	@Override
	protected void run() throws Exception {
		check("tasking-classic-large".equals(
			currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()),
			"test program is not using TASKING Classic Large");

		Function length = requiredFunction(LENGTH_WRAPPER);
		Function allocator = requiredFunction(ALLOCATOR);
		Function formatter = requiredFunction(FORMATTER_WRAPPER);
		Function caller = requiredFunction(REPRESENTATIVE_CALLER);

		seedBrokenAnalysisSignatures(length, allocator, formatter);
		deletePrototypeOverride(formatter, toAddr(SPRINTF_CALL));
		seedCoalescedSprintfOverride(formatter);

		AddressSet scope = new AddressSet(length.getBody());
		scope.add(allocator.getBody());
		scope.add(formatter.getBody());
		scope.add(caller.getBody());

		C166TaskingTypeInferenceAnalyzer analyzer =
			new C166TaskingTypeInferenceAnalyzer();
		MessageLog firstLog = new MessageLog();
		check(analyzer.added(currentProgram, scope, monitor, firstLog),
			"unified TASKING analysis failed: " + firstLog);
		check(!firstLog.hasMessages(),
			"TASKING diagnostics leaked into the Analysis Log: " + firstLog);
		assertSignatures(length, allocator, formatter);
		assertSprintfOverride(formatter);
		assertDecompilation(length, formatter, caller);

		String before = snapshot(length, allocator, formatter, caller) +
			overrideSnapshot(formatter, toAddr(SPRINTF_CALL));
		MessageLog secondLog = new MessageLog();
		check(analyzer.added(currentProgram, scope, monitor, secondLog),
			"idempotence analysis failed: " + secondLog);
		check(!secondLog.hasMessages(),
			"idempotence diagnostics leaked into the Analysis Log: " + secondLog);
		String after = snapshot(length, allocator, formatter, caller) +
			overrideSnapshot(formatter, toAddr(SPRINTF_CALL));
		check(before.equals(after), "real-program signatures or override changed on rerun\n" +
			"BEFORE: " + before + "\nAFTER: " + after);
		assertSignatures(length, allocator, formatter);
		assertSprintfOverride(formatter);
		assertDecompilation(length, formatter, caller);

		println("Nested-call return and variadic inference regression passed.");
	}

	private void seedBrokenAnalysisSignatures(Function length, Function allocator,
			Function formatter) throws Exception {
		DataType charPointer = new PointerDataType(
			new CharDataType(currentProgram.getDataTypeManager()),
			currentProgram.getDataTypeManager());

		updateAnalysisParameters(length, List.of(
			new ParameterImpl("string", charPointer, currentProgram)));
		length.setReturnType(Undefined.getUndefinedDataType(1), SourceType.ANALYSIS);

		updateAnalysisParameters(allocator, List.of(
			new ParameterImpl("size", Undefined.getUndefinedDataType(4), currentProgram),
			new ParameterImpl("file", charPointer, currentProgram)));
		allocator.setReturnType(new PointerDataType(VoidDataType.dataType,
			currentProgram.getDataTypeManager()), SourceType.ANALYSIS);

		updateAnalysisParameters(formatter, List.of(
			new ParameterImpl("name", charPointer, currentProgram),
			new ParameterImpl("id", Undefined.getUndefinedDataType(2), currentProgram)));
		formatter.setReturnType(Undefined.getUndefinedDataType(1), SourceType.ANALYSIS);
	}

	private void updateAnalysisParameters(Function function, List<? extends Variable> parameters)
			throws Exception {
		function.updateFunction("__tasking_c166_classic", null,
			new ArrayList<>(parameters), FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
			true, SourceType.ANALYSIS);
	}

	private void seedCoalescedSprintfOverride(Function formatter) throws Exception {
		DataType charPointer = new PointerDataType(
			new CharDataType(currentProgram.getDataTypeManager()),
			currentProgram.getDataTypeManager());
		FunctionDefinitionDataType stale = new FunctionDefinitionDataType(
			"stale_coalesced_sprintf_override", currentProgram.getDataTypeManager());
		stale.setCallingConvention("__tasking_c166_classic_vararg_2");
		stale.setReturnType(Undefined.getUndefinedDataType(2));
		stale.setArguments(
			new ParameterDefinitionImpl("s", charPointer, null),
			new ParameterDefinitionImpl("format", charPointer, null),
			new ParameterDefinitionImpl("coalesced_optional_words",
				Undefined.getUndefinedDataType(6), null));
		HighFunctionDBUtil.writeOverride(formatter, toAddr(SPRINTF_CALL), stale);
		DataTypeSymbol symbol = prototypeOverride(formatter, toAddr(SPRINTF_CALL));
		check(symbol != null && symbol.getDataType() instanceof FunctionDefinition definition &&
			definition.getArguments().length == 3 &&
			definition.getArguments()[2].getDataType().getLength() == 6,
			"failed to seed stale coalesced sprintf override");
	}

	private void assertSignatures(Function length, Function allocator, Function formatter) {
		check(length.getReturnType().getLength() == 4 &&
			Undefined.isUndefined(length.getReturnType()) &&
			!isPointer(length.getReturnType()),
			"FUN_39b5a4 return is not a four-byte scalar: " +
				length.getPrototypeString(true, true));
		check(length.getReturn().getVariableStorage().size() == 4,
			"FUN_39b5a4 return is not stored in R5:R4");

		check(allocator.getParameterCount() == 3,
			"FUN_39bcf8 did not recover the nested stack line argument: " +
				allocator.getPrototypeString(true, true));
		check(allocator.getParameter(0).getFormalDataType().getLength() == 4 &&
			!isPointer(allocator.getParameter(0).getFormalDataType()),
			"FUN_39bcf8 size is not one four-byte scalar");
		check(isDataPointer(allocator.getParameter(1).getFormalDataType()),
			"FUN_39bcf8 file is not a far data pointer");
		check(allocator.getParameter(2).getFormalDataType().getLength() == 2 &&
			allocator.getParameter(2).getVariableStorage().hasStackStorage(),
			"FUN_39bcf8 line is not one user-stack word");

		check(formatter.getParameterCount() == 2 &&
			isDataPointer(formatter.getParameter(0).getFormalDataType()) &&
			formatter.getParameter(1).getFormalDataType().getLength() == 2,
			"FUN_3c32dc input layout changed: " +
				formatter.getPrototypeString(true, true));
		check(isDataPointer(formatter.getReturnType()) &&
			formatter.getReturn().getVariableStorage().size() == 4,
			"FUN_3c32dc return is not a far data pointer: " +
				formatter.getPrototypeString(true, true));
	}

	private void assertSprintfOverride(Function formatter) {
		DataTypeSymbol symbol = prototypeOverride(formatter, toAddr(SPRINTF_CALL));
		check(symbol != null && symbol.getDataType() instanceof FunctionDefinition,
			"sprintf prototype override is missing");
		FunctionDefinition definition = (FunctionDefinition)symbol.getDataType();
		ParameterDefinition[] arguments = definition.getArguments();
		StringBuilder types = new StringBuilder();
		for (ParameterDefinition argument : arguments) {
			if (!types.isEmpty()) {
				types.append(", ");
			}
			types.append(argument.getDataType().getDisplayName())
				.append('[').append(argument.getDataType().getLength()).append(']');
		}
		check(arguments.length == 4,
			"sprintf override expected two fixed plus two optional arguments, got " +
				arguments.length + ": " + types);
		check(isDataPointer(arguments[2].getDataType()) &&
			arguments[2].getDataType().getLength() == 4,
			"sprintf first optional argument is not one far data pointer");
		check(arguments[3].getDataType().getLength() == 2 &&
			!isPointer(arguments[3].getDataType()),
			"sprintf second optional argument is not one scalar word");
	}

	private void assertDecompilation(Function length, Function formatter, Function caller) {
		DecompInterface decompiler = new DecompInterface();
		try {
			decompiler.toggleCCode(true);
			decompiler.toggleSyntaxTree(true);
			check(decompiler.openProgram(currentProgram), decompiler.getLastMessage());
			String lengthCode = decompile(decompiler, length);
			String formatterCode = decompile(decompiler, formatter);
			String callerCode = decompile(decompiler, caller);
			check(!lengthCode.contains("extraout_RH4") &&
				!lengthCode.contains("extraout_r5") &&
				!formatterCode.contains("extraout_RH4") &&
				!formatterCode.contains("extraout_r5") &&
				!formatterCode.contains("CONCAT22") &&
				!formatterCode.contains(">> 0x10") &&
				!formatterCode.contains("return (char)"),
				"real program retained split return or pointer artifacts:\n" + formatterCode);
			check(!callerCode.contains("(char)FUN_3c32dc") &&
				!callerCode.contains("(undefined1)FUN_3c32dc"),
				"caller retained a narrowed FUN_3c32dc return:\n" + callerCode);
			check(formatterCode.contains("FUN_39bcf8") &&
				(formatterCode.contains("0x52c") || formatterCode.contains("1324")),
				"allocator call lost its nested line argument:\n" + formatterCode);
		}
		finally {
			decompiler.dispose();
		}
	}

	private String decompile(DecompInterface decompiler, Function function) {
		DecompileResults result = decompiler.decompileFunction(function, 120, monitor);
		check(result.decompileCompleted() && result.getDecompiledFunction() != null,
			"failed to decompile " + function.getName() + ": " +
				result.getErrorMessage());
		return result.getDecompiledFunction().getC();
	}

	private String snapshot(Function... functions) {
		StringBuilder result = new StringBuilder();
		for (Function function : functions) {
			result.append(function.getEntryPoint()).append(':')
				.append(function.getPrototypeString(true, true)).append(';');
		}
		return result.toString();
	}

	private String overrideSnapshot(Function caller, Address callSite) {
		DataTypeSymbol symbol = prototypeOverride(caller, callSite);
		if (symbol == null || !(symbol.getDataType() instanceof FunctionDefinition definition)) {
			return "no-override";
		}
		StringBuilder result = new StringBuilder(symbol.getDataType().getPathName());
		for (ParameterDefinition argument : definition.getArguments()) {
			result.append('|').append(argument.getDataType().getPathName())
				.append('[').append(argument.getDataType().getLength()).append(']');
		}
		return result.toString();
	}

	private DataTypeSymbol prototypeOverride(Function caller, Address callSite) {
		if (HighFunction.findOverrideSpace(caller) == null) {
			return null;
		}
		for (Symbol symbol : currentProgram.getSymbolTable().getSymbols(callSite)) {
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

	private void deletePrototypeOverride(Function caller, Address callSite) {
		DataTypeSymbol symbol = prototypeOverride(caller, callSite);
		if (symbol != null && symbol.getSymbol() != null) {
			check(symbol.getSymbol().delete(),
				"failed to delete stale sprintf prototype override");
		}
	}

	private boolean isDataPointer(DataType type) {
		DataType current = unwrap(type);
		return current instanceof Pointer pointer &&
			!(unwrap(pointer.getDataType()) instanceof FunctionDefinition);
	}

	private boolean isPointer(DataType type) {
		return unwrap(type) instanceof Pointer;
	}

	private DataType unwrap(DataType type) {
		DataType current = type;
		while (current instanceof TypeDef typeDef) {
			current = typeDef.getBaseDataType();
		}
		return current;
	}

	private Function requiredFunction(long address) {
		Function function = getFunctionAt(toAddr(address));
		check(function != null, "missing function at 0x" + Long.toHexString(address));
		return function;
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
