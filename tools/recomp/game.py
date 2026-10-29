# Recompiler settings for Prototype (prototypeenginef.dll, Steam build 19788432); read by recomp.py and
# data_entries.py. Addresses are at the DLL's preferred base 0x10000000.
import os

IMAGE = os.environ.get("PROTORE_ENGINE", "~/Downloads/Prototype (2009)/Prototype/prototypeenginef.dll")
# MSVCR80 setjmp/longjmp: thunk and IAT slot addresses.
SETJMP_TARGETS = {0x10a88a30}
SETJMP_IAT = {0x11331fc4}
LONGJMP_IAT = {0x11331fbc}
INLINE_HELPERS = {0x10a88426: "ftol2", 0x10a883b0: "chkstk", 0x10a889e0: "chkstk16", 0x10a889f6: "chkstk8",
                  0x10a88370: "allmul", 0x10a884b0: "allshl", 0x10ba2b50: "aullshr"}
# src/native/hot_*.cpp
NATIVE_OVERRIDES = {0x105e8860, 0x105c62e0, 0x105eb280, 0x1071b610}
