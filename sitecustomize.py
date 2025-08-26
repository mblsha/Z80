# sitecustomize.py
# Runs automatically at Python startup (imported by 'site')
#
# TEMPORARY WORKAROUND: This file patches binja-test-mocks at runtime to fix
# architecture registration issues. Once PR #8 is merged and released
# (https://github.com/mblsha/binja-test-mocks/pull/8), this file can be deleted.
#
# The fixes implemented here have been properly contributed upstream.


def _patch_binja_mocks():
    try:
        # The mock exposes the API here; 'binaryninja' re-exports from this.
        import binja_test_mocks.binja_api as mock_api
    except Exception:
        return  # Mocks not installed; nothing to do.

    Arch = getattr(mock_api, "Architecture", None)
    if Arch is None or getattr(Arch, "_patched_registry", False):
        return  # Either no Architecture or already patched.

    # ---- Define specific errors (optional but helpful) ----
    class RegistrationError(RuntimeError):
        pass

    class NotRegisteredError(KeyError):
        pass

    # Export them on the mock module so tests can import if desired
    mock_api.RegistrationError = RegistrationError  # noqa: B010
    mock_api.NotRegisteredError = NotRegisteredError  # noqa: B010

    # ---- Real registry (mutate the existing class object) ----
    if not hasattr(Arch, "_registry"):
        Arch._registry = {}

    @classmethod
    def register(cls) -> None:
        name = getattr(cls, "name", None)
        if not name:
            raise RegistrationError("Architecture subclass must define a non-empty 'name'.")
        # One canonical instance per arch, mirroring BN behavior well enough for tests.
        Arch._registry[name] = cls()

    @classmethod
    def __class_getitem__(cls, name: str):
        inst = Arch._registry.get(name)
        if inst is None:
            raise NotRegisteredError(
                f"Architecture '{name}' is not registered in the mocks. "
                "Import your plugin and call Z80.register() before using Architecture['Z80']."
            )
        return inst

    @classmethod
    def clear_registry(cls) -> None:
        Arch._registry.clear()

    # Apply patches to the same class object that plugins subclassed
    Arch.register = register
    Arch.__class_getitem__ = __class_getitem__
    Arch.clear_registry = clear_registry
    Arch._patched_registry = True

    # ---- Compatibility shims for next blockers (safe no-ops if API differs) ----
    # 1) InstructionTextToken: accept 3 args (type, text, value) but only use first 2
    try:
        # The mock expects InstructionTextToken(type, text) but plugin calls (type, text, value)
        Tok = getattr(mock_api, "InstructionTextToken", None)
        if Tok is not None and hasattr(Tok, "__init__"):
            _orig_init = Tok.__init__

            def _init_compat(self, *args, **kwargs):
                # Plugin calls (type, text, value) but mock expects (type, text)
                if len(args) >= 3:
                    args = (args[0], args[1])  # Keep only type and text
                # Remove any extra kwargs that mock doesn't expect
                if "value" in kwargs:
                    kwargs.pop("value", None)
                if "address" in kwargs:
                    kwargs.pop("address", None)
                return _orig_init(self, *args, **kwargs)

            Tok.__init__ = _init_compat
    except Exception:
        pass

    # 2) MockLowLevelILFunction.flag_condition: add a stub if missing
    try:
        from binja_test_mocks.mock_llil import MockLowLevelILFunction

        if not hasattr(MockLowLevelILFunction, "flag_condition"):

            def flag_condition(self, *args, **kwargs):
                # Minimal stub so tests can proceed; tailor as needed
                return None

            MockLowLevelILFunction.flag_condition = flag_condition
    except Exception:
        pass


_patch_binja_mocks()
