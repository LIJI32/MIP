.SECONDARY:
.PHONY: all install uninstall

LDFLAGS := -g -mmacosx-version-min=10.10 -lc -F/System/Library/PrivateFrameworks
CFLAGS := -g -mmacosx-version-min=10.10 -I. -Werror -O3 -Wno-unknown-warning-option -Wno-deprecated-declarations -Wno-interrupt-service-routine
SYSROOT ?= $(shell xcodebuild -sdk macosx -version Path 2> /dev/null)
ifeq ($(SYSROOT),)
SYSROOT := $(shell find /Library/Developer/CommandLineTools/SDKs -maxdepth 1 -name "MacOSX1*.sdk" | sort -V | tail -n 1)
endif
CFLAGS += -isysroot $(SYSROOT)
SUBSTITUTE ?= YES
MIP_ROOT ?= /Library/Apple/System/Library/Frameworks/mip

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
DUAL_ARCH ?= 1
CFLAGS += -DROSETTA
else
ARCH1 := x86_64
ARCH2 := i386
endif


SIGN_IDENTITY ?= CodeSign
CODESIGN_TARGET := codesign -s "$(SIGN_IDENTITY)"

all: build/lsdinjector.dylib build/loader.dylib build/inject build/injectd local.lsdinjector.plist

build/lsdinjector.dylib: build/injector/lsd_injector.c.o build/injector/injectd_client/injectd_client.m.o
	$(CC) $(LDFLAGS) -arch $(ARCH1) $^ -lbsm -framework Foundation -shared -o $@
	$(CODESIGN_TARGET) $@

build/loader.dylib: $(LOADER_SOURCES)
	$(CC) $(CFLAGS) $(SUBSTITUTE_CFLAGS) $(LDFLAGS) -install_name @loader_path/../../../../loader.dylib -framework Foundation -shared -arch $(ARCH1) $(if $(DUAL_ARCH), -arch $(ARCH2)) $^ -o $@
	$(CODESIGN_TARGET) $@

build/injectd: build/injector/injector.o build/injector/injectd.m.o | injector/injectd.entitlements
	mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -framework Foundation $^ -o $@ -arch $(ARCH1)
	$(CODESIGN_TARGET) --entitlements injector/injectd.entitlements $@
	
build/inject: build/injector/inject.c.o build/injector/injectd_client/injectd_client.m.o
	mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -framework Foundation $^ -o $@ -arch $(ARCH1)
	$(CODESIGN_TARGET) $@

build/injector/injector.o: build/injector/inject/inject.c.o build/injector/payloads/injected_$(ARCH1).c.bin build/injector/payloads/injected_$(ARCH2).c.bin
	ld -r $(filter %.o,$^) -o $@ -sectcreate __INJ_$(ARCH1) __inj_$(ARCH1) build/injector/payloads/injected_$(ARCH1).c.bin -sectcreate __INJ_$(ARCH2) __inj_$(ARCH2) build/injector/payloads/injected_$(ARCH2).c.bin
	
build/%.c.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -arch $(ARCH1) -c $^ -o $@
	
build/%.m.o: %.m
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -fobjc-arc -arch $(ARCH1) -c $^ -o $@

	
build/injector/payloads/injected_i386.c.dylib: injector/payloads/injected_i386.c
	mkdir -p $(dir $@)
		
	@# Fix the unaligned movaps LLVM bug, and convert iret to ret.
	$(CC) $(CFLAGS) -fno-exceptions -arch i386 -Oz $^ -S -o - \
		| sed "s/^	iret/	ret/g" \
		| sed "s/^	movaps	%xmm7, -32(%ebp)/	movaps	%xmm7, -40(%ebp)/g" \
		| sed "s/^	movaps	-32(%ebp), %xmm7/	movaps	-40(%ebp), %xmm7/g" \
		| clang -L. -Wl,-sectalign,__TEXT,__text,4000 -Wl,-order_file,injector/payloads/order -shared -isysroot $(SYSROOT) -xassembler - -arch i386 -o $@
	
build/injector/payloads/injected_x86_64.c.dylib: injector/payloads/injected_x86_64.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Wl,-sectalign,__TEXT,__text,4000 -fno-exceptions -shared -arch x86_64 -Oz -Wl,-order_file,injector/payloads/order $^ -o $@

build/injector/payloads/injected_arm64e.c.dylib: injector/payloads/injected_arm64e.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Wl,-sectalign,__TEXT,__text,4000 -fno-exceptions -shared -arch arm64e -Oz -Wl,-order_file,injector/payloads/order $^ -o $@

build/injector/payloads/%.bin: build/injector/payloads/%.dylib
	gobjcopy -Obinary $^ $@

	

install: all
	sudo mkdir -p $(MIP_ROOT)/user_data
	sudo mkdir -p $(MIP_ROOT)/Bundles
	sudo mkdir -p /usr/local/include/mip
	@# We remove the old libraries before copying, overwriting causes codesigning issues.
	-@sudo rm -f $(MIP_ROOT)/{lsdinjector.dylib,loader.dylib,injectd}
	sudo cp build/lsdinjector.dylib build/loader.dylib build/injectd $(MIP_ROOT)
	sudo cp build/inject /usr/local/bin/
	sudo cp loader/loader_public.h /usr/local/include/mip/loader.h	
	sed "s=@MIP_ROOT@=$(MIP_ROOT)=g" local.injectd.plist | sudo dd of=/Library/LaunchDaemons/local.injectd.plist
	sed "s=@MIP_ROOT@=$(MIP_ROOT)=g" local.lsdinjector.plist | sudo dd of=/Library/LaunchDaemons/local.lsdinjector.plist

	sudo defaults write /Library/Preferences/com.apple.security.libraryvalidation.plist DisableLibraryValidation -bool true
	-sudo launchctl bootstrap system /Library/LaunchDaemons/local.injectd.plist
	if nvram boot-args | grep -v tss_should_crash=0; then \
		sudo nvram boot-args="`nvram boot-args | cut -c 11-` tss_should_crash=0"; \
		if nvram boot-args | grep -v tss_should_crash=0; then\
			echo "Failed to add tss_should_crash=0. If you're running macOS Ventura or newer in a VM, you will need to update this bootarg manually."; \
		else \
			echo "Added tss_should_crash=0 boot argument. If you're running macOS Ventura or newer, a reboot is required"; \
		fi \
	fi
	if nvram boot-args | grep -v amfi_get_out_of_my_way=1; then \
		sudo nvram boot-args="`nvram boot-args | cut -c 11-` amfi_get_out_of_my_way=1"; \
		if nvram boot-args | grep -v amfi_get_out_of_my_way=1; then\
			echo "Failed to add amfi_get_out_of_my_way=1. If you're running macOS Sonoma or newer in a VM, you will need to update this bootarg manually."; \
		else \
			echo "Added amfi_get_out_of_my_way=1 boot argument. If you're running macOS Sonoma or newer, a reboot is required"; \
		fi \
	fi
	(read -p "Inject MIP to launchservicesd without a restart? [y/N] " -n 1 -r; echo ; if [[ $$REPLY =~ ^[Yy]$$ ]]; then sudo inject launchservicesd $(MIP_ROOT)/lsdinjector.dylib; fi;)

uninstall:
	-sudo rm -rf $(MIP_ROOT)
	-sudo rm -rf /usr/include/mip
	-sudo rm /Library/LaunchDaemons/local.lsdinjector.plist
	-sudo defaults delete /Library/Preferences/com.apple.security.libraryvalidation.plist DisableLibraryValidation
	
clean:
	rm -rf build
