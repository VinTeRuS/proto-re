# Native host (no Wine): the recompiled engine plus the Win32 emulation layer.
#   make                         Linux x86-64 executable (build/native/proto-native)
#   make PLATFORM=android [ABI=arm64-v8a|x86_64]
#                                libmain.so for the APK (android/build-apk.sh), against the libraries from
#                                android/build-deps.sh
PLATFORM ?= linux
# Generated for the rebased engine: recomp.py --functions all --base 0x7c000000 --split 400 --out build/recomp/native (see guest.h)
RECOMP_DIR ?= ../../build/recomp/native
DXVK ?= $(HOME)/proto-re-data/deps/dxvk
# Guest memory: a 4 GiB window at 64 GiB (guest.h kGuestBase), clear of the low 4 GiB that Android's Java heap and
# Qualcomm's GPU driver use.
COMMON_FLAGS := -DRECOMP_FLAT_MEMORY -DRECOMP_GUEST_BASE=0x1000000000ull -fsigned-char -I../recomp
# Generated code: flat memory turns G() into plain pointers. -O1 on the desktop keeps rebuilds quick; Android gets
# -O2 (clang: barely slower to build).
RECOMP_OPT ?= -O1
RECOMP_CFLAGS = -std=c11 $(RECOMP_OPT) $(RECOMP_EXTRA) -g0 -fno-strict-aliasing -fwrapv -fno-delete-null-pointer-checks -w $(COMMON_FLAGS) \
                $(TARGET_FLAGS)
CXXFLAGS = -std=c++17 -O2 -g -Wall -Wextra -Wno-unused-parameter $(COMMON_FLAGS) $(TARGET_FLAGS) \
           -I$(DXVK)/include/native/directx -I$(DXVK)/include/native/windows -I$(DXVK)/include/native/wsi \
           $(DEP_INCLUDES)

ifeq ($(PLATFORM),android)
ABI ?= arm64-v8a
NDK ?= $(HOME)/Android/Sdk/ndk/28.2.13676358
DEPS ?= $(HOME)/proto-re-data/android-deps/$(ABI)
TRIPLE := $(if $(filter x86_64,$(ABI)),x86_64,aarch64)-linux-android26
TOOLCHAIN := $(NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin
CXX := $(TOOLCHAIN)/$(TRIPLE)-clang++
CC := $(TOOLCHAIN)/$(TRIPLE)-clang
OUT ?= ../../build/android/$(ABI)
# arm64: ARMv8.2 + RCpc (Cortex-A55/A76/X1 and newer, i.e. phones from 2019 on): LDAPR for the TSO acquire loads,
# inline LSE atomics. ARM_ARCH=armv8-a builds for older cores (Cortex-A53/A73), with outline atomics.
ARM_ARCH ?= armv8.2-a+rcpc
TARGET_FLAGS := -fPIC $(if $(filter arm64-v8a,$(ABI)),-march=$(ARM_ARCH) -mtune=cortex-a76 \
                $(if $(filter armv8-a,$(ARM_ARCH)),-moutline-atomics))
RECOMP_OPT := -O2
# arm64 is weakly ordered: guest memory accesses get x86-like ordering (runtime.h RECOMP_TSO); tso=0 to measure.
TSO ?= 1
RECOMP_EXTRA := $(if $(filter 1,$(TSO)),-DRECOMP_TSO)
DEP_INCLUDES := -I$(DEPS)/include
LDFLAGS := -shared -Wl,-Bsymbolic -static-libstdc++ -Wl,--no-undefined -L$(DEPS)/lib -ldxvk_d3d9 -lFAudio -lSDL2 \
           -lavformat -lavcodec -lavutil -llog -landroid
# Adreno: Turnip and libadrenotools from android/build-turnip.sh (arm64 only; built without them otherwise).
TURNIP ?= $(HOME)/proto-re-data/android-turnip
ifneq ($(and $(filter arm64-v8a,$(ABI)),$(wildcard $(TURNIP)/lib/libadrenotools.a)),)
DEP_INCLUDES += -I$(TURNIP)/include -DPROTORE_ADRENOTOOLS
LDFLAGS += -L$(TURNIP)/lib -ladrenotools -llinkernsbypass -ldl \
           -Wl,--defsym=android_get_device_api_level=protore_device_api_level
# The driver probe program (turnip_probe.cpp): API 29 like libadrenotools, plain ARMv8.0 so one build runs on all.
EXTRA := $(OUT)/libturnipprobe.so
endif
BINARY := libmain.so
else
CXX ?= g++
CC ?= gcc
OUT ?= ../../build/native
# DXVK native (D3D9 on Vulkan) and FAudio (XAudio2 reimplementation, zlib license), built in deps.
DXVK_LIB ?= $(DXVK)/build-native/src/d3d9
FAUDIO ?= $(HOME)/proto-re-data/deps/FAudio
FAUDIO_LIB ?= $(FAUDIO)/build-native
TARGET_FLAGS :=
DEP_INCLUDES := -I$(FAUDIO)/include
LDFLAGS := -pthread -L$(DXVK_LIB) -Wl,-rpath,$(DXVK_LIB) -ldxvk_d3d9 -L$(FAUDIO_LIB) -Wl,-rpath,$(FAUDIO_LIB) -lFAudio \
           -lSDL2 $(shell pkg-config --libs libavformat libavcodec libavutil)
BINARY := proto-native
endif

SRCS := main.cpp memory.cpp loader.cpp imports.cpp runtime.cpp thread.cpp kernel32.cpp msvcr80.cpp user32.cpp \
        advapi32.cpp misc.cpp d3d9.cpp input.cpp xaudio2.cpp bink.cpp dinput.cpp gamepad.cpp config.cpp watchdog.cpp hot_audio.cpp hot_skin.cpp \
        vulkan_driver.cpp perf_hint.cpp
GEN := $(wildcard $(RECOMP_DIR)/*.c)
OBJS = $(SRCS:%.cpp=$(OUT)/%.o) $(GEN:$(RECOMP_DIR)/%.c=$(OUT)/gen/%.o)

all: $(OUT)/$(BINARY) $(EXTRA)

$(OUT)/libturnipprobe.so: turnip_probe.cpp turnip_load.h
	@mkdir -p $(dir $@)
	$(TOOLCHAIN)/aarch64-linux-android29-clang++ -std=c++17 -O2 -fPIE -pie -march=armv8-a -moutline-atomics -static-libstdc++ \
		-I$(TURNIP)/include -o $@ $< -L$(TURNIP)/lib -ladrenotools -llinkernsbypass -ldl -llog

$(OUT)/$(BINARY): $(OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS)

$(OUT)/%.o: %.cpp guest.h win.h turnip_load.h ../recomp/runtime.h d3d9_gen.inc
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(OUT)/gen/%.o: $(RECOMP_DIR)/%.c ../recomp/runtime.h ../recomp/runtime_fp.h
	@mkdir -p $(dir $@)
	$(CC) $(RECOMP_CFLAGS) -c -o $@ $<

clean:
	rm -rf $(OUT)

.PHONY: all clean
