// Verify that shared pointer-value decoding remains unchanged off C166 TASKING.
// @category C166.Tests

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryBlock;

public class NonC166PointerValueControlTest extends GhidraScript {

	@Override
	public void run() throws Exception {
		check(!"tasking-classic-large".equals(
			currentProgram.getLanguage().getProperty("c166.abi")),
			"control must not use the TASKING Classic Large profile");

		MemoryBlock storage = currentProgram.getMemory().createInitializedBlock(
			"pointer_value_control", toAddr(0xf00000), 4, (byte) 0, monitor, false);
		storage.setWrite(true);
		setBytes(toAddr(0xf00000), new byte[] {
			(byte) 0xa0, 0x3d, 0x7e, 0x01
		});
		PointerDataType pointer = new PointerDataType(UnsignedShortDataType.dataType, 4,
			currentProgram.getDataTypeManager());
		Data data = createData(toAddr(0xf00000), pointer);
		Object value = data.getValue();
		check(value instanceof Address &&
			((Address) value).getUnsignedOffset() == 0x17e3da0L,
			"non-C166 pointer value changed: " + value);
		println("Non-C166 stored pointer-value control passed for " +
			currentProgram.getLanguageID() + ".");
	}

	private void check(boolean condition, String message) {
		if (!condition) {
			throw new AssertionError(message);
		}
	}
}
