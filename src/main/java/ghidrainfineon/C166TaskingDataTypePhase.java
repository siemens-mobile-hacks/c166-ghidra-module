package ghidrainfineon;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeDependencyException;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Normalizes implementation-defined C library types for the documented
 * TASKING C166 Classic data model.
 */
public class C166TaskingDataTypePhase extends C166TaskingTypeInferencePhase {

	private static final String SIZE_T_PATH = "/stddef.h/size_t";
	private static final String STDDEF_CATEGORY = "/stddef.h";
	private static final String SIZE_T_CONFLICT_PREFIX = "size_t.conflict";

	public C166TaskingDataTypePhase() {
		super("C166 TASKING Data Types");
	}

	@Override
	public boolean canAnalyze(Program program) {
		return C166ArchitectureProfile.isTaskingClassicLarge(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		DataTypeManager manager = program.getDataTypeManager();
		try {
			DataType canonical = normalizeCanonicalSizeType(manager);
			if (canonical == null) {
				return true;
			}

			int conflictsReplaced = replaceSizeTypeConflicts(manager, canonical);
			if (conflictsReplaced != 0) {
				report(program, "Replaced " + conflictsReplaced +
					" incompatible generic-clib size_t conflict(s) with the documented " +
					"2-byte TASKING unsigned int.");
			}
			return true;
		}
		catch (DataTypeDependencyException | IllegalArgumentException e) {
			log.appendException(e);
			return false;
		}
	}

	private DataType normalizeCanonicalSizeType(DataTypeManager manager)
			throws DataTypeDependencyException {
		DataType sizeType = manager.getDataType(SIZE_T_PATH);
		if (sizeType == null) {
			TypedefDataType replacement = new TypedefDataType(
				new CategoryPath(STDDEF_CATEGORY), "size_t",
				new UnsignedIntegerDataType(manager), manager);
			return manager.addDataType(replacement, DataTypeConflictHandler.REPLACE_HANDLER);
		}
		if (sizeType.getLength() == 2) {
			return sizeType;
		}

		TypedefDataType replacement = new TypedefDataType(sizeType.getCategoryPath(),
			sizeType.getName(), new UnsignedIntegerDataType(manager), manager);
		manager.replaceDataType(sizeType, replacement, true);
		return manager.getDataType(SIZE_T_PATH);
	}

	private int replaceSizeTypeConflicts(DataTypeManager manager, DataType canonical)
			throws DataTypeDependencyException {
		List<DataType> conflicts = new ArrayList<>();
		Iterator<DataType> types = manager.getAllDataTypes();
		while (types.hasNext()) {
			DataType type = types.next();
			String name = type.getName();
			if (STDDEF_CATEGORY.equals(type.getCategoryPath().getPath()) &&
				name.startsWith(SIZE_T_CONFLICT_PREFIX)) {
				conflicts.add(type);
			}
		}

		for (DataType conflict : conflicts) {
			manager.replaceDataType(conflict, canonical, true);
		}
		return conflicts.size();
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
