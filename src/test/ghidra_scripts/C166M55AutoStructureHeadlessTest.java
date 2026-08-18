// Run headlessly against the real M55_v91 program after full analysis.
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompilerLocationInfo;
import ghidra.app.decompiler.location.DefaultDecompilerLocation;
import ghidra.app.decompiler.util.FillOutStructureCmd;
import ghidra.app.decompiler.util.FillOutStructureHelper;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.FunctionParameterFieldLocation;
import ghidrainfineon.C166TaskingTypeInferenceAnalyzer;

public class C166M55AutoStructureHeadlessTest extends GhidraScript {

	private static final long PARAMETER_TARGET = 0x9b4e9cL;
	private static final long INITIALIZER_TARGET = 0x34b230L;
	private static final long INDEXED_GLOBAL_TARGET = 0x34b662L;
	private static final long INDEXED_GLOBAL = 0x2c2c8L;
	private static final long PATH_GLOBAL = 0x2c2ccL;
	private static final long SYS_OPEN = 0xa41692L;

	@Override
	protected void run() throws Exception {
		check("tasking-classic-large".equals(
			currentProgram.getLanguage().getProperty("c166.abi")),
			"M55 regression is not running with TASKING Classic Large");
		checkGlobalInitializerRecovery();
		checkIndexedGlobalRecovery();

		Function function =
			currentProgram.getFunctionManager().getFunctionAt(toAddr(PARAMETER_TARGET));
		check(function != null, "missing M55 FUN_9b4e9c");
		check(function.getParameterCount() > 0 &&
			function.getParameter(0).getFormalDataType() instanceof Pointer &&
			function.getParameter(0).getFormalDataType().getLength() == 4,
			"FUN_9b4e9c parameter 0 is not a four-byte far data pointer");

		FillOutStructureHelper setup = new FillOutStructureHelper(currentProgram, monitor);
		DecompInterface decompiler = setup.setUpDecompiler(new DecompileOptions());
		check(decompiler != null, "failed to initialize M55 decompiler");
		try {
			DecompileResults results = decompiler.decompileFunction(function, 120, monitor);
			check(results.decompileCompleted() && results.getHighFunction() != null,
				"failed to decompile FUN_9b4e9c: " + results.getErrorMessage());
			HighSymbol symbol = results.getHighFunction().getLocalSymbolMap().getParamSymbol(0);
			HighVariable variable = symbol == null ? null : symbol.getHighVariable();
			Structure structure = new FillOutStructureHelper(currentProgram, monitor)
				.processStructure(variable, function, true, false, null);
			check(structure != null && structure.getLength() == 0x44,
				"FUN_9b4e9c auto-structure length is not 0x44");
			check(structure.getComponentAt(0x40) != null &&
				structure.getComponentAt(0x40).getLength() == 2,
				"FUN_9b4e9c auto-structure lacks the word at 0x40");
			check(structure.getComponentAt(0x42) != null &&
				structure.getComponentAt(0x42).getLength() == 2,
				"FUN_9b4e9c auto-structure lacks the word at 0x42");
		}
		finally {
			decompiler.dispose();
		}

		Parameter parameter = function.getParameter(0);
		FunctionParameterFieldLocation location = new FunctionParameterFieldLocation(
			currentProgram, function.getEntryPoint(), function.getEntryPoint(), 0,
			function.getSignature().toString(), parameter);
		FillOutStructureCmd command = new FillOutStructureCmd(location,
			new DecompileOptions());
		check(runCommand(command),
			"FUN_9b4e9c GUI command path failed: " + command.getStatusMsg());
		Parameter updatedParameter = function.getParameter(0);
		check(updatedParameter.getFormalDataType() instanceof Pointer,
			"FUN_9b4e9c GUI command did not assign a structure pointer");
		Pointer updatedPointer = (Pointer) updatedParameter.getFormalDataType();
		check(updatedPointer.getDataType() instanceof Structure,
			"FUN_9b4e9c GUI command pointer does not target a structure");
		Structure commandStructure = (Structure) updatedPointer.getDataType();
		check(commandStructure.getLength() >= 0x44 &&
			commandStructure.getComponentAt(0x40) != null &&
			commandStructure.getComponentAt(0x42) != null,
			"FUN_9b4e9c GUI command structure lacks the expected fields");

		println("M55 FUN_9b4e9c helper and GUI-command far-pointer auto-structure " +
			"regressions passed.");
	}

	private void checkGlobalInitializerRecovery() throws Exception {
		Function function = currentProgram.getFunctionManager()
			.getFunctionAt(toAddr(INITIALIZER_TARGET));
		check(function != null, "missing M55 FUN_34b230");
		DecompInterface decompiler = new DecompInterface();
		decompiler.toggleCCode(true);
		decompiler.toggleSyntaxTree(true);
		check(decompiler.openProgram(currentProgram), decompiler.getLastMessage());
		try {
			DecompileResults results = decompiler.decompileFunction(function, 120, monitor);
			check(results.decompileCompleted(),
				"failed to decompile FUN_34b230: " + results.getErrorMessage());
			String code = results.getDecompiledFunction().getC();
			check(!code.contains("ram,0x0002c") &&
				!code.contains("DAT_0002c") && !code.contains("uRam0002c") &&
				!code.contains("Removing unreachable block"),
				"FUN_34b230 still uses the unpaged low globals or loses its body:\n" + code);
			check(code.contains("02c2c") || code.contains("02C2C") ||
				code.contains("2c2c") || code.contains("2C2C"),
				"FUN_34b230 does not reference the physical DPP-backed globals:\n" + code);
		}
		finally {
			decompiler.dispose();
		}
		println("M55 FUN_34b230 live-DPP global initialization regression passed.");
	}

	private void checkIndexedGlobalRecovery() throws Exception {
		Address globalAddress = toAddr(INDEXED_GLOBAL);
		Function function = currentProgram.getFunctionManager()
			.getFunctionAt(toAddr(INDEXED_GLOBAL_TARGET));
		check(function != null, "missing M55 FUN_34b662");
		Data initialData = currentProgram.getListing().getDefinedDataAt(globalAddress);
		Structure initialStructure = pointedStructure(initialData);
		boolean hadFalseCode =
			currentProgram.getListing().getInstructionContaining(globalAddress) != null;

		C166TaskingTypeInferenceAnalyzer analyzer =
			new C166TaskingTypeInferenceAnalyzer();
		AddressSet analysisSet = new AddressSet(function.getBody());
		check(analyzer.added(currentProgram, analysisSet, monitor,
			new MessageLog()), "unified TASKING type inference failed on FUN_34b662");

		Data pointerData = currentProgram.getListing().getDefinedDataAt(globalAddress);
		check(pointerData != null && pointerData.getDataType() instanceof Pointer &&
			pointerData.getLength() == 4,
			"FUN_34b662 did not recover 0x2c2c8/0x2c2ca as one four-byte pointer: address=" +
				globalAddress + ", unit=" +
				currentProgram.getListing().getCodeUnitContaining(globalAddress) +
				", data=" + pointerData);
		check(currentProgram.getListing().getInstructionContaining(globalAddress) == null &&
			currentProgram.getListing().getInstructionContaining(globalAddress.add(2)) == null,
			"analysis-owned false code survived at 0x2c2c8/0x2c2ca");
		check(currentProgram.getFunctionManager().getFunctionContaining(globalAddress) == null,
			"analysis-owned false function body still contains 0x2c2c8");
		if (hadFalseCode) {
			println("M55 fixture contained false code at 0x2c2c8; analyzer repaired it.");
		}
		Address pathAddress = toAddr(PATH_GLOBAL);
		DataType genericFarPointer = new PointerDataType(VoidDataType.dataType,
			currentProgram.getDataTypeManager());
		DataUtilities.createData(currentProgram, pathAddress, genericFarPointer,
			genericFarPointer.getLength(), false,
			DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		if (initialStructure != null) {
			checkExpectedIndexedStructure(initialStructure,
				"previously recovered FUN_34b662 structure");
			DataType voidPointer = new PointerDataType(VoidDataType.dataType,
				currentProgram.getDataTypeManager());
			DataUtilities.createData(currentProgram, globalAddress, voidPointer,
				voidPointer.getLength(), false,
				DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		defineSysOpen();
		}

		FillOutStructureHelper helper = new FillOutStructureHelper(currentProgram, monitor);
		DecompInterface decompiler = helper.setUpDecompiler(new DecompileOptions());
		check(decompiler != null, "failed to initialize FUN_34b662 decompiler");
		DecompileResults results;
		List<ClangVariableToken> indexTokens;
		try {
			results = decompiler.decompileFunction(function, 120, monitor);
			check(results.decompileCompleted() && results.getHighFunction() != null,
				"failed to decompile FUN_34b662: " + results.getErrorMessage());
			String code = results.getDecompiledFunction().getC();
			check(!code.contains("0xb1420"),
				"writable far-pointer global 0x2c2cc was folded from flash bytes:\n" + code);
			String sysOpenCall = callStatement(code, "sys_open(");
			check(sysOpenCall != null && sysOpenCall.contains(",1,0x180,") &&
				!sysOpenCall.contains("0xffff3fff") && !sysOpenCall.contains("& 0x3fff") &&
				sysOpenCall.matches(
					".*sys_open\\(.+,1,0x180,[A-Za-z_][A-Za-z0-9_]*\\);"),
				"sys_open did not recover its stack far-pointer argument:\n" + code);
			Method findBase = FillOutStructureHelper.class.getDeclaredMethod(
				"findC166IndexedFarPointerBase", HighVariable.class, Varnode.class);
			findBase.setAccessible(true);
			indexTokens = findIndexedTokens(results, helper, findBase);
			check(!indexTokens.isEmpty(),
				"decompiler markup lacks the indexed far-pointer variable token");
			ClangVariableToken indexToken = indexTokens.get(0);
			HighVariable base = (HighVariable) findBase.invoke(helper,
				indexToken.getHighVariable(), indexToken.getVarnode());
			check(base != null,
				"Auto Structure did not redirect the index to the recovered far pointer");
			Structure structure = helper.processStructure(base, function, false, true, decompiler);
			check(structure != null && structure.getLength() >= 10,
				"FUN_34b662 auto-structure did not recover the ten-byte element stride");
			check(structure.getComponentAt(2) != null &&
				structure.getComponentAt(2).getLength() == 2,
				"FUN_34b662 auto-structure lacks the word field at offset 2");
		}
		finally {
			decompiler.dispose();
		}

		check(indexTokens.size() > 1,
			"FUN_34b662 test found only the convenient scaled index token");
		for (ClangVariableToken token : indexTokens) {
			Address tokenAddress = token.getMinAddress();
			if (tokenAddress == null) {
				tokenAddress = function.getEntryPoint();
			}
			DecompilerLocationInfo locationInfo = new DecompilerLocationInfo(
				function.getEntryPoint(), results, token, 0, 0);
			DefaultDecompilerLocation location = new DefaultDecompilerLocation(
				currentProgram, tokenAddress, locationInfo);
			FillOutStructureCmd command = new FillOutStructureCmd(location,
				new DecompileOptions());
			check(runCommand(command),
				"FUN_34b662 GUI command failed for token " + token.getText() + " at " +
					token.getVarnode() + ": " + command.getStatusMsg());
		}
		Data updatedData = currentProgram.getListing().getDefinedDataAt(globalAddress);
		check(updatedData != null && updatedData.getDataType() instanceof Pointer,
			"FUN_34b662 GUI command removed the recovered global pointer");
		Pointer updatedPointer = (Pointer) updatedData.getDataType();
		check(updatedPointer.getLength() == 4 &&
			updatedPointer.getDataType() instanceof Structure,
			"FUN_34b662 GUI command did not assign a far structure pointer");
		Structure commandStructure = (Structure) updatedPointer.getDataType();
		checkExpectedIndexedStructure(commandStructure,
			"FUN_34b662 GUI command structure");

		println("M55 FUN_34b662 analyzer-owned false-code repair and indexed global " +
			"Auto Structure GUI-command regressions passed.");
	}

	private void defineSysOpen() throws Exception {
		Function sysOpen = currentProgram.getFunctionManager().getFunctionAt(toAddr(SYS_OPEN));
		check(sysOpen != null, "missing M55 sys_open");
		DataType word = new UnsignedShortDataType(currentProgram.getDataTypeManager());
		DataType charPointer = new PointerDataType(CharDataType.dataType,
			currentProgram.getDataTypeManager());
		DataType errorPointer = new PointerDataType(word, currentProgram.getDataTypeManager());
		List<Variable> parameters = List.of(
			new ParameterImpl("path", charPointer, currentProgram),
			new ParameterImpl("flags", word, currentProgram),
			new ParameterImpl("mode", word, currentProgram),
			new ParameterImpl("err", errorPointer, currentProgram));
		sysOpen.setName("sys_open", SourceType.USER_DEFINED);
		sysOpen.setReturnType(new IntegerDataType(currentProgram.getDataTypeManager()),
			SourceType.USER_DEFINED);
		sysOpen.updateFunction("__tasking_c166_classic", null, parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);
	}

	private String callStatement(String code, String callName) {
		int start = code.indexOf(callName);
		if (start < 0) {
			return null;
		}
		int statementStart = code.lastIndexOf('\n', start);
		int statementEnd = code.indexOf(';', start);
		if (statementEnd < 0) {
			return null;
		}
		return code.substring(statementStart + 1, statementEnd + 1)
			.replaceAll("\\s+", "");
	}

	private Structure pointedStructure(Data data) {
		if (data == null || !(data.getDataType() instanceof Pointer pointer) ||
			pointer.getLength() != 4 || !(pointer.getDataType() instanceof Structure structure)) {
			return null;
		}
		return structure;
	}

	private void checkExpectedIndexedStructure(Structure structure, String description) {
		check(structure.getLength() >= 10 && structure.getComponentAt(2) != null &&
			structure.getComponentAt(2).getLength() == 2,
			description + " lacks the word at offset 2");
	}

	private List<ClangVariableToken> findIndexedTokens(DecompileResults results,
			FillOutStructureHelper helper, Method findBase) throws Exception {
		List<ClangNode> nodes = new ArrayList<>();
		results.getCCodeMarkup().flatten(nodes);
		HighVariable indexedVariable = null;
		for (ClangNode node : nodes) {
			if (!(node instanceof ClangVariableToken token)) {
				continue;
			}
			Varnode exactSpot = token.getVarnode();
			HighVariable variable = token.getHighVariable();
			if (exactSpot == null || variable == null) {
				continue;
			}
			HighVariable base =
				(HighVariable) findBase.invoke(helper, variable, exactSpot);
			if (base != null) {
				indexedVariable = variable;
				break;
			}
		}
		List<ClangVariableToken> result = new ArrayList<>();
		if (indexedVariable == null) {
			return result;
		}
		for (ClangNode node : nodes) {
			if (node instanceof ClangVariableToken token && token.getVarnode() != null &&
				token.getHighVariable() == indexedVariable) {
				HighVariable base = (HighVariable) findBase.invoke(helper,
					token.getHighVariable(), token.getVarnode());
				check(base != null,
					"indexed-variable token does not resolve to the far global: " +
						token.getText() + " at " + token.getVarnode());
				result.add(token);
			}
		}
		return result;
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
