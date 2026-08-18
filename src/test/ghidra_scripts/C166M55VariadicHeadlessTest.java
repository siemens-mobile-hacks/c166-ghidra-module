// Representative real-program regression for M55_v91 FUN_747f44.
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidrainfineon.C166FarPointerPhase;
import ghidrainfineon.C166VariadicCallPhase;

public class C166M55VariadicHeadlessTest extends GhidraScript {

	private static final long CALLER = 0x747f44;
	private static final long CALL = 0x748042;
	private static final long PREPARE = 0x743766;
	private static final long STRLEN = 0xbfa81a;
	private static final long SNPRINTF = 0xbfb34a;
	private static final long SYS_OPEN = 0xa41692;

	@Override
	protected void run() throws Exception {
		check("tasking-classic-large".equals(
			currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()),
			"M55 test is not using TASKING Classic large");
		Function caller = ensureFunction(CALLER, "FUN_747f44");
		Function snprintf = ensureFunction(SNPRINTF, "snprintf");
		DataType charPointer = new PointerDataType(CharDataType.dataType,
			currentProgram.getDataTypeManager());
		DataType voidPointer = new PointerDataType(VoidDataType.dataType,
			currentProgram.getDataTypeManager());
		DataType word = new UnsignedShortDataType(currentProgram.getDataTypeManager());
		DataType dwordPointer = new PointerDataType(
			new UnsignedLongDataType(currentProgram.getDataTypeManager()),
			currentProgram.getDataTypeManager());
		defineFunction(ensureFunction(STRLEN, "strlen"), word, charPointer);
		defineFunction(ensureFunction(PREPARE, "FUN_743766"),
			new IntegerDataType(currentProgram.getDataTypeManager()),
			charPointer, dwordPointer, voidPointer);
		defineFunction(ensureFunction(SYS_OPEN, "sys_open"),
			new IntegerDataType(currentProgram.getDataTypeManager()),
			charPointer, word, word, new PointerDataType(word,
				currentProgram.getDataTypeManager()));
		defineSnprintf(snprintf, charPointer);
		definePointerData(charPointer);
		if (getDataAt(toAddr(0x5c5972)) == null) {
			createAsciiString(toAddr(0x5c5972));
		}

		C166FarPointerPhase farPointerAnalyzer = new C166FarPointerPhase();
		check(farPointerAnalyzer.added(currentProgram, new AddressSet(caller.getBody()), monitor,
			new MessageLog()), "M55 caller parameter analysis failed");
		check(snprintf.hasVarArgs() && snprintf.getParameterCount() == 3,
			"M55 far-pointer analysis changed snprintf's fixed variadic prefix");
		Variable[] callerParameters = caller.getParameters();
		check(callerParameters.length == 3 &&
			isFarPointer(callerParameters[0].getDataType()) &&
			callerParameters[1].getDataType().getLength() == 2 &&
			callerParameters[2].getDataType().getLength() == 2 &&
			!(callerParameters[1].getDataType() instanceof Pointer) &&
			!(callerParameters[2].getDataType() instanceof Pointer),
			"M55 FUN_747f44 scalar flags/mode were joined as a pointer");

		C166VariadicCallPhase analyzer = new C166VariadicCallPhase();
		check(analyzer.added(currentProgram, new AddressSet(snprintf.getBody()), monitor,
			new MessageLog()), "M55 variadic analysis failed");

		FunctionDefinition override = prototypeOverride(caller, toAddr(CALL));
		check(override != null, "M55 snprintf call-site override is missing");
		ParameterDefinition[] arguments = override.getArguments();
		check(arguments.length == 20,
			"M55 snprintf expected 20 arguments, got " + arguments.length);
		check(isFarPointer(arguments[0].getDataType()) &&
			arguments[1].getDataType().getLength() == 2 &&
			isFarPointer(arguments[2].getDataType()) &&
			isFarPointer(arguments[3].getDataType()),
			"M55 snprintf fixed arguments or pointer vararg are split");
		for (int i = 4; i < arguments.length; i++) {
			check(arguments[i].getDataType().getLength() == 2,
				"M55 snprintf scalar vararg " + (i - 4) + " is not one word");
		}

		String code = decompile(caller);
		String compact = code.replaceAll("\\s+", "");
		check(compact.contains("snprintf(") && compact.contains(",0x2d,") &&
			(compact.contains("\"%s\\\\%0.2x") || compact.contains("(char*)0x5c5972") ||
				compact.contains("5c5972")),
			"M55 snprintf fixed arguments are wrong:\n" + code);
		check(code.contains("PTR_00196e") &&
			!code.contains("PTR_00196e._2_2_") && !code.contains("0x1711972"),
			"M55 snprintf retained split far pointers:\n" + code);
		check(code.contains(" = strlen(") &&
			!code.matches("(?s).*\\n\\s*strlen\\([^;]+;.*"),
			"M55 strlen result is not assigned to the length object:\n" + code);
		check(!code.contains("extraout_RH4") && !code.contains(">> 0x10") &&
			code.contains("sys_open("),
			"M55 FUN_747f44 retained a split status or scalar parameter:\n" + code);
		println("M55 FUN_747f44 variadic snprintf regression passed.");
	}

	private void defineFunction(Function function, DataType returnType,
			DataType... parameterTypes) throws Exception {
		List<Variable> parameters = new ArrayList<>();
		for (int i = 0; i < parameterTypes.length; i++) {
			parameters.add(new ParameterImpl("param_" + (i + 1), parameterTypes[i],
				currentProgram));
		}
		function.setReturnType(returnType, SourceType.USER_DEFINED);
		function.updateFunction("__tasking_c166_classic", null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
	}

	private void defineSnprintf(Function snprintf, DataType charPointer) throws Exception {
		List<Variable> parameters = new ArrayList<>();
		parameters.add(new ParameterImpl("s", charPointer, currentProgram));
		parameters.add(new ParameterImpl("maxlen",
			new UnsignedShortDataType(currentProgram.getDataTypeManager()), currentProgram));
		parameters.add(new ParameterImpl("format", charPointer, currentProgram));
		snprintf.setReturnType(new ShortDataType(currentProgram.getDataTypeManager()),
			SourceType.USER_DEFINED);
		snprintf.updateFunction("__tasking_c166_classic", null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
		snprintf.setVarArgs(true);
		snprintf.setSignatureSource(SourceType.USER_DEFINED);
	}

	private void definePointerData(DataType pointerType) throws Exception {
		Address address = toAddr(0x196e);
		if (!currentProgram.getMemory().contains(address)) {
			MemoryBlock block = createMemoryBlock("m55_pointer_196e", address,
				new byte[4], false);
			block.setWrite(true);
		}
		clearListing(address, address.add(3));
		createData(address, pointerType);
		createLabel(address, "PTR_00196e", true);
	}

	private Function ensureFunction(long offset, String name) throws Exception {
		Address entry = toAddr(offset);
		Function function = getFunctionAt(entry);
		if (function != null) {
			if (!name.equals(function.getName())) {
				function.setName(name, SourceType.USER_DEFINED);
			}
			return function;
		}
		check(disassemble(entry), "failed to disassemble " + name);
		function = createFunction(entry, name);
		check(function != null, "failed to create " + name);
		return function;
	}

	private FunctionDefinition prototypeOverride(Function caller, Address callSite) {
		if (HighFunction.findOverrideSpace(caller) == null) {
			return null;
		}
		for (Symbol symbol : currentProgram.getSymbolTable().getSymbols(callSite)) {
			if (symbol.getSymbolType() != SymbolType.LABEL ||
				!HighFunction.isOverrideNamespace(symbol.getParentNamespace())) {
				continue;
			}
			DataTypeSymbol dataTypeSymbol = HighFunctionDBUtil.readOverride(symbol);
			if (dataTypeSymbol != null &&
				dataTypeSymbol.getDataType() instanceof FunctionDefinition definition) {
				return definition;
			}
		}
		return null;
	}

	private boolean isFarPointer(DataType type) {
		return type instanceof Pointer && type.getLength() == 4;
	}

	private String decompile(Function function) {
		DecompInterface decompiler = new DecompInterface();
		try {
			decompiler.toggleCCode(true);
			decompiler.toggleSyntaxTree(true);
			check(decompiler.openProgram(currentProgram), decompiler.getLastMessage());
			DecompileResults result = decompiler.decompileFunction(function, 120, monitor);
			check(result.decompileCompleted(), result.getErrorMessage());
			String code = result.getDecompiledFunction().getC();
			println(code);
			return code;
		}
		finally {
			decompiler.dispose();
		}
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
