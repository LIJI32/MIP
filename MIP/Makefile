.SECONDARY:
.PHONY: all install uninstall

LDFLAGS := -g -mmacosx-version-min=10.10 -lc -F/System/Library/PrivateFrameworks
CFLAGS := -g -mmacosx-version-min=10.10 -I. -Werror -O3 -Wno-deprecated-declarations
SYSROOT ?= $(shell xcodebuild -sdk macosx -version Path 2> /dev/null)
CFLAGS += -isysroot $(SYSROOT)
SUBSTITUTE ?= YES

ifneq ($(SUBSTITUTE),YES)
ifneq ($(SUBSTITUTE),NO)
$(error SUBSTITUTE must be either YES or NO)
endif
endif

LOADER_SOURCES := loader/loader.m
ifeq ($(SUBSTITUTE),YES)
SUBSTITUTE_CFLAGS := -Ithird-party/substitute/lib -Ithird-party/substitute/vendor
LOADER_SOURCES += $(shell find third-party/substitute -name "*.c" -o -name "*.S")
endif

ifeq ($(shell uname -m),arm64)
ARCH1 := arm64e
ARCH2 := x86_64
else
ARCH1 := x86_64
ARCH2 := i386
endif

SIGN_IDENTITY ?= CodeSign
CODESIGN_TARGET := codesign -s "$(SIGN_IDENTITY)"

all: build/lsdinjector.dylib build/loader.dylib build/inject local.lsdinjector.plist

build/lsdinjector.dylib: build/injector/lsd_injector.c.o \
								  build/injector/hook/hook.c.o \
								  build/injector/hook/symbols.c.o \
								  build/injector/hook/thread_locking.c.o \
								  build/injector/injector.o
	$(CC) $(LDFLAGS) -arch $(ARCH1) $^ -framework CoreSymbolication -lbsm -shared -o $@
	$(CODESIGN_TARGET) $@

build/loader.dylib: $(LOADER_SOURCES)
	$(CC) $(CFLAGS) $(SUBSTITUTE_CFLAGS) $(LDFLAGS) -install_name /Library/Apple/System/Library/Frameworks/mip/loader.dylib -framework Foundation -shared -arch $(ARCH1) -arch $(ARCH2) $^ -o $@
	$(CODESIGN_TARGET) $@

build/inject: build/injector/injector.o build/injector/main.c.o
	mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) $^ -o $@ -arch $(ARCH1)
	$(CODESIGN_TARGET) $@

build/injector/injector.o: build/injector/inject/inject.c.o build/injector/payloads/injected_$(ARCH1).c.bin build/injector/payloads/injected_$(ARCH2).c.bin 
	ld -r $(filter %.o,$^) -o $@ -sectcreate __INJ_$(ARCH1) __inj_$(ARCH1) build/injector/payloads/injected_$(ARCH1).c.bin -sectcreate __INJ_$(ARCH2) __inj_$(ARCH2) build/injector/payloads/injected_$(ARCH2).c.bin
	
build/%.o: %
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -arch $(ARCH1) -c $^ -o $@
	
build/injector/payloads/injected_i386.c.dylib: injector/payloads/injected_i386.c
	mkdir -p $(dir $@)
		
	@# Fix the unaligned movaps LLVM bug, and convert iret to ret.
	$(CC) $(CFLAGS) -arch i386 -Oz $^ -S -o - \
		| sed "s/^	iret/	ret/g" \
		| sed "s/^	movaps	%xmm7, -32(%ebp)/	movaps	%xmm7, -40(%ebp)/g" \
		| sed "s/^	movaps	-32(%ebp), %xmm7/	movaps	-40(%ebp), %xmm7/g" \
		| clang -Wl,-order_file,injector/payloads/order -shared -isysroot $(SYSROOT) -xassembler - -arch i386 -o $@
	
build/injector/payloads/injected_x86_64.c.dylib: injector/payloads/injected_x86_64.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -shared -arch x86_64 -Oz -Wl,-order_file,injector/payloads/order $^ -o $@

build/injector/payloads/injected_arm64e.c.dylib: injector/payloads/injected_arm64e.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -shared -arch arm64e -Oz -Wl,-order_file,injector/payloads/order $^ -o $@

build/injector/payloads/%.bin: build/injector/payloads/%.dylib
	gobjcopy -Obinary $^ $@

	

install: all
	if [ -d /usr/lib/mip ]; then \
		sudo rm /Users/*/Library/MIP ;\
		sudo mkdir -p /Library/Apple/System/Library/Frameworks/ ;\
		sudo mv /usr/lib/mip /Library/Apple/System/Library/Frameworks/ ;\
		sudo ln -s /Library/Apple/System/Library/Frameworks/mip /usr/lib/mip ;\
	fi
	sudo mkdir -p /Library/Apple/System/Library/Frameworks/mip/user_data
	sudo mkdir -p /Library/Apple/System/Library/Frameworks/mip/Bundles
	sudo mkdir -p /usr/local/include/mip
	@# We remove the old libraries before copying, overwriting causes codesigning issues.
	-@sudo rm -f /Library/Apple/System/Library/Frameworks/mip/lsdinjector.dylib /Library/Apple/System/Library/Frameworks/mip/loader.dylib
	sudo cp build/lsdinjector.dylib build/loader.dylib /Library/Apple/System/Library/Frameworks/mip/
	sudo cp build/inject /usr/local/bin/
	sudo cp loader/loader_public.h /usr/local/include/mip/loader.h
	sudo cp local.lsdinjector.plist /Library/LaunchDaemons/
	sudo defaults write /Library/Preferences/com.apple.security.libraryvalidation.plist DisableLibraryValidation -bool true
	(read -p "Inject MIP to launchservicesd without a restart? [y/N] " -n 1 -r; echo ; if [[ $$REPLY =~ ^[Yy]$$ ]]; then sudo inject launchservicesd /Library/Apple/System/Library/Frameworks/mip/lsdinjector.dylib; fi;)

uninstall:
	-sudo rm -rf /Library/Apple/System/Library/Frameworks/mip
	-sudo rm -rf /usr/include/mip
	-sudo rm /Library/LaunchDaemons/local.lsdinjector.plist
	-sudo defaults delete /Library/Preferences/com.apple.security.libraryvalidation.plist DisableLibraryValidation
	
clean:
	rm -rf build
