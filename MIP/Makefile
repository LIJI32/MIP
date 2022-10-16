.SECONDARY:
.PHONY: all install uninstall

LDFLAGS := -g -mmacosx-version-min=10.10 -lc -F/System/Library/PrivateFrameworks
CFLAGS := -g -mmacosx-version-min=10.10 -I. -Werror -O3 -Wno-deprecated-declarations
SYSROOT ?= $(shell xcodebuild -sdk macosx -version Path 2> /dev/null)
CFLAGS += -isysroot $(SYSROOT)

SUBSTITUTE_CFLAGS := -Ithird-party/substitute/lib -Ithird-party/substitute/vendor
SUBSTITUTE_SOURCES := $(shell find third-party/substitute -name "*.c" -o -name "*.S")

ifeq ($(shell uname -m),arm64)
ARCH := arm64e
else
ARCH := x86_64
endif

SIGN_IDENTITY ?= -
CODESIGN_TARGET := codesign -s $(SIGN_IDENTITY)

all: build/loader.dylib build/inject local.lsdinjector.plist

build/loader.dylib: loader/loader.m $(SUBSTITUTE_SOURCES) build/injector/injector.o
	$(CC) $(CFLAGS) $(SUBSTITUTE_CFLAGS) $(LDFLAGS) -lbsm -install_name /Library/Apple/System/Library/Frameworks/mip/loader.dylib -framework Foundation -shared -arch $(ARCH) $^ -o $@
	$(CODESIGN_TARGET) $@

build/inject: build/injector/injector.o build/injector/main.c.o
	mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) $^ -o $@ -arch ${ARCH}
	$(CODESIGN_TARGET) $@

build/injector/injector.o: build/injector/inject/inject.c.o build/injector/payloads/injected_$(ARCH).c.bin
	ld -r $(filter %.o,$^) -o $@ -sectcreate __INJ_$(ARCH) __inj_$(ARCH) build/injector/payloads/injected_$(ARCH).c.bin
	
build/injector/payloads/injected_x86_64.c.dylib: injector/payloads/injected_x86_64.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -shared -arch x86_64 -Oz -Wl,-order_file,injector/payloads/order $^ -o $@

build/injector/payloads/injected_arm64e.c.dylib: injector/payloads/injected_arm64e.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -shared -arch arm64e -Oz -Wl,-order_file,injector/payloads/order $^ -o $@

build/injector/payloads/%.bin: build/injector/payloads/%.dylib
	gobjcopy -Obinary $^ $@

build/%.o: %
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -arch $(ARCH) -c $^ -o $@

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
	-@sudo rm -f /Library/Apple/System/Library/Frameworks/mip/loader.dylib
	sudo cp build/loader.dylib /Library/Apple/System/Library/Frameworks/mip/
	sudo cp build/inject /usr/local/bin/
	sudo cp loader/loader_public.h /usr/local/include/mip/loader.h
	sudo cp local.lsdinjector.plist /Library/LaunchDaemons/
	sudo defaults write /Library/Preferences/com.apple.security.libraryvalidation.plist DisableLibraryValidation -bool true
	(read -p "Inject MIP to launchservicesd without a restart? [y/N] " -n 1 -r; echo ; if [[ $$REPLY =~ ^[Yy]$$ ]]; then sudo inject launchservicesd /Library/Apple/System/Library/Frameworks/mip/loader.dylib; fi;)

uninstall:
	-sudo rm -rf /Library/Apple/System/Library/Frameworks/mip
	-sudo rm /usr/local/bin/inject
	-sudo rm -rf /usr/include/mip
	-sudo rm /Library/LaunchDaemons/local.lsdinjector.plist
	-sudo defaults delete /Library/Preferences/com.apple.security.libraryvalidation.plist DisableLibraryValidation

clean:
	rm -rf build
