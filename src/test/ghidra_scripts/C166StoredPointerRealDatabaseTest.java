// Verify stored TASKING data pointers in the real regression database.
// @category C166.Tests

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Data;

public class C166StoredPointerRealDatabaseTest extends GhidraScript {

	@Override
	public void run() throws Exception {
		check("tasking-classic-large".equals(
			currentProgram.getLanguage().getProperty("c166.abi")),
			"test requires c166.abi=tasking-classic-large");

		Address descriptorAddress = toAddr(0x564bd4);
		checkBytes(descriptorAddress,
			0xa0, 0x3d, 0x7e, 0x01, 0x5d, 0x01, 0x5e, 0x01, 0x00,
			0x00, 0x78, 0x3d, 0x7e, 0x01, 0x03, 0x00, 0x6c, 0x00);
		Data descriptor = currentProgram.getListing().getDefinedDataAt(descriptorAddress);
		if (descriptor == null) {
			descriptor = createData(descriptorAddress, createDescriptorType());
		}
		check(descriptor != null && descriptor.getLength() == 18,
			"expected 18-byte descriptor at 0x564bd4, got " + describe(descriptor));
		checkPointer(descriptor.getComponent(0), 0x5fbda0,
			"icon-id PAGE:OFFSET pointer");
		checkPointer(descriptor.getComponent(4), 0x5fbd78,
			"softkeys PAGE:OFFSET pointer");

		println("Real stored pointer values at 0x564bd4 passed.");
	}

	private DataType createDescriptorType() {
		DataTypeManager manager = currentProgram.getDataTypeManager();
		DataType word = new UnsignedShortDataType(manager);
		DataType dataPointer = new PointerDataType(VoidDataType.dataType, 4, manager);
		StructureDataType descriptor = new StructureDataType(
			new CategoryPath("/C166/Tests"), "StoredPointerRealDescriptor", 0, manager);
		descriptor.add(dataPointer, "icon_id_ptr_paged", null);
		descriptor.add(word, "lgp_id_small", null);
		descriptor.add(word, "lgp_id_large", null);
		descriptor.add(word, "zero", null);
		descriptor.add(dataPointer, "softkeys_ptr_paged", null);
		descriptor.add(word, "flags", null);
		descriptor.add(word, "feature_id", null);
		return manager.addDataType(descriptor, DataTypeConflictHandler.REPLACE_HANDLER);
	}

	private void checkBytes(Address start, int... expected) throws Exception {
		byte[] actual = new byte[expected.length];
		currentProgram.getMemory().getBytes(start, actual);
		for (int index = 0; index < expected.length; index++) {
			check((actual[index] & 0xff) == expected[index],
				"unexpected real byte at " + start.add(index));
		}
	}

	private String describe(Data data) {
		if (data == null) {
			return "null";
		}
		return data.getDataType().getDisplayName() + " length=" + data.getLength() +
			" components=" + data.getNumComponents() + " value=" + data.getValue();
	}

	private void checkPointer(Data pointer, long expected, String description) {
		check(pointer != null, description + " component is missing");
		Object value = pointer.getValue();
		check(value instanceof Address && ((Address) value).getUnsignedOffset() == expected,
			description + " resolved incorrectly: " + value);
		String representation = pointer.getDefaultValueRepresentation();
		check(!representation.contains("AddressOutOfBoundsException"),
			description + " leaked AddressOutOfBoundsException: " + representation);
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
