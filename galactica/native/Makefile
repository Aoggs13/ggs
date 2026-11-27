# Galactica — native iOS tweak build
# produces libnativeunity.dylib (arm64, iOS 14+, plain .dylib)

SDK       := $(shell xcrun --sdk iphoneos --show-sdk-path)
CLANG     := $(shell xcrun -f clang)
LDID      := $(shell command -v ldid || echo ldid)
TARGET    := arm64-apple-ios14.0
INSTALL   := @executable_path/Frameworks/libnativeunity.dylib

CFLAGS    := -isysroot $(SDK) -target $(TARGET) -arch arm64 \
             -fvisibility=hidden \
             -O2 -Wall -Wno-unused-variable -Wno-unused-function \
             -mios-version-min=14.0

LDFLAGS   := -isysroot $(SDK) -target $(TARGET) -arch arm64 \
             -dynamiclib -install_name "$(INSTALL)" \
             -framework Foundation \
             -framework Security

# Menu-less build — Sam wants only the anti-ban layer. file_spoof's
# __attribute__((constructor(101))) installs the hooks on dylib load,
# no Objective-C code or UI needed.
C_SRCS    := file_spoof.c fishhook.c
OBJS      := $(C_SRCS:.c=.o)
OUTPUT    := libnativeunity.dylib

.PHONY: all clean sign

all: $(OUTPUT) sign

$(OUTPUT): $(OBJS)
	$(CLANG) $(LDFLAGS) -o $@ $^

%.o: %.m
	$(CLANG) $(CFLAGS) -c $< -o $@

%.o: %.c
	$(CLANG) $(CFLAGS) -fno-objc-arc -c $< -o $@

sign: $(OUTPUT)
	@# Ad-hoc codesign so dyld on iOS doesn't reject on load path. TrollStore/
	@# Sideloadly refakesign on install, this is belt-and-braces.
	codesign --force --sign - --timestamp=none $(OUTPUT) || \
	    $(LDID) -S $(OUTPUT) || true
	@echo "signed: $(OUTPUT)"
	@file $(OUTPUT)
	@ls -lh $(OUTPUT)

clean:
	rm -f $(OBJS) $(OUTPUT)
