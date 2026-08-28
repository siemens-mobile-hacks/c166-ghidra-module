// Verify stored TASKING Classic Large pointers through Ghidra's Data API.
// @category C166.Tests

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryBlock;

public class C166StoredPointerValueTest extends GhidraScript {

	@Override
	public void run() throws Exception {
		check("tasking-classic-large".equals(
			currentProgram.getLanguage().getProperty("c166.abi")),
			"test requires c166.abi=tasking-classic-large");

		MemoryBlock storage = createMemoryBlock("pointer_values", toAddr(0xf00000), 0x30);
		storage.setWrite(true);

		DataType ushort = UnsignedShortDataType.dataType;
		PointerDataType dataPointer = new PointerDataType(ushort, 4,
			currentProgram.getDataTypeManager());
		setBytes(toAddr(0xf00000), bytes(0xa0, 0x3d, 0x7e, 0x01));
		Data pagedData = createData(toAddr(0xf00000), dataPointer);
		checkAddress(pagedData, 0x5fbda0,
			"PAGE:OFFSET data pointer was not decoded as page << 14");

		setBytes(toAddr(0xf00008), bytes(0xa0, 0xbd, 0x5f, 0x00));
		Data physicalData = createData(toAddr(0xf00008), dataPointer);
		checkAddress(physicalData, 0x5fbda0,
			"already physical data pointer was decoded a second time");

		FunctionDefinitionDataType callback = new FunctionDefinitionDataType(
			"stored_pointer_callback", currentProgram.getDataTypeManager());
		PointerDataType functionPointer = new PointerDataType(callback, 4,
			currentProgram.getDataTypeManager());
		setBytes(toAddr(0xf00010), bytes(0x00, 0x3d, 0x56, 0x00));
		Data codeData = createData(toAddr(0xf00010), functionPointer);
		checkAddress(codeData, 0x563d00,
			"function pointer was incorrectly decoded as paged data");

		println("Stored TASKING PAGE:OFFSET data-pointer value test passed.");
	}

	private MemoryBlock createMemoryBlock(String name, Address start, long size)
			throws Exception {
		return currentProgram.getMemory().createInitializedBlock(name, start, size,
			(byte) 0, monitor, false);
	}

	private void checkAddress(Data data, long expected, String message) {
		Object value = data.getValue();
		check(value instanceof Address && ((Address) value).getUnsignedOffset() == expected,
			message + ": " + value);
		String representation = data.getDefaultValueRepresentation();
		check(!representation.contains("AddressOutOfBoundsException"),
			"pointer representation leaked AddressOutOfBoundsException: " + representation);
	}

	private byte[] bytes(int... values) {
		byte[] result = new byte[values.length];
		for (int index = 0; index < values.length; index++) {
			result[index] = (byte) values[index];
		}
		return result;
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
