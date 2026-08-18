package ghidrainfineon;

import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;

/**
 * Single source of truth for opt-in C166 ABI behaviour.
 *
 * <p>The processor specification owns the profile selection.  An analyzer must
 * not reconstruct it from a language id, processor name, compiler-spec id, or
 * the incidental presence of a p-code userop.</p>
 */
public final class C166ArchitectureProfile {
	public static final String PROPERTY = "c166.abi";
	public static final String TASKING_CLASSIC_LARGE = "tasking-classic-large";

	private C166ArchitectureProfile() {
	}

	public static boolean isTaskingClassicLarge(Program program) {
		return program != null && isTaskingClassicLarge(program.getLanguage());
	}

	public static boolean isTaskingClassicLarge(Language language) {
		return language != null &&
			TASKING_CLASSIC_LARGE.equals(language.getProperty(PROPERTY));
	}
}
