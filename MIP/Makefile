.SECONDARY:
.PHONY: all install uninstall

LDFLAGS := -g -mmacosx-version-min=10.10 -lc -F/System/Library/PrivateFrameworks
CFLAGS := -g -mmacosx-version-min=10.10 -I. -Werror -O3 -Wno-deprecated-declarations
SIGN_IDENTITY ?= "CodeSign"

all: build/lsdinjector.dylib build/loader.dylib build/inject local.lsdinjector.plist

build/lsdinjector.dylib: build/injector/lsd_injector.c.o \
                                  build/injector/hook/hook.c.o \
                                  build/injector/hook/symbols.c.o \
                                  build/injector/hook/thread_locking.c.o \
                                  build/injector/injector.o
	clang $(LDFLAGS) $^ -framework CoreSymbolication -lbsm -shared -o $@
	codesign -s $(SIGN_IDENTITY) $@

build/loader.dylib: loader/loader.m build/markgc
	clang $(CFLAGS) $(LDFLAGS) -install_name /usr/lib/mip/loader.dylib -framework Foundation -shared -arch x86_64 -arch i386 $< -o $@
	build/markgc $@ >> /dev/null
	codesign -s $(SIGN_IDENTITY) $@

# This file is taken from Apple's Obj-C runtime. It marks a file GC-compatible without having to compile it with the no
# longer supported -fobjc-gc. This makes sure that we don't crash GC-enabled apps on El-Capitan and older. 
build/markgc: third-party/markgc.cpp
	clang $^ -std=c++11 -o $@

build/inject: build/injector/injector.o build/injector/main.c.o
	mkdir -p $(dir $@)
	clang $(LDFLAGS) $^ -o $@
	codesign -s $(SIGN_IDENTITY) $@

build/injector/injector.o: build/injector/inject/inject.c.o build/injector/payloads/injected64.c.bin build/injector/payloads/injected32.c.bin
	ld -r $(filter %.o,$^) -o $@ -sectcreate __INJECTED64 __injected64 build/injector/payloads/injected64.c.bin -sectcreate __INJECTED32 __injected32 build/injector/payloads/injected32.c.bin
	
build/%.o: %
	mkdir -p $(dir $@)
	clang $(CFLAGS) -c $^ -o $@
	
build/injector/payloads/injected64.c.dylib: injector/payloads/injected64.c
	mkdir -p $(dir $@)
	clang $(CFLAGS) -Oz -Wl,-order_file,injector/payloads/order -shared -nostdlib $^ -o $@
	
build/injector/payloads/injected32.c.dylib: injector/payloads/injected32.c
	mkdir -p $(dir $@)
	@# Fix the unaligned movaps LLVM bug, and convert iret to ret.
	clang $(CFLAGS) -Oz -arch i386 $^ -S -o - \
		| sed "s/^	iret/	ret/g" \
		| sed "s/^	movaps	%xmm7, -32(%ebp)/	movaps	%xmm7, -40(%ebp)/g" \
		| sed "s/^	movaps	-32(%ebp), %xmm7/	movaps	-40(%ebp), %xmm7/g" \
		| clang -Wl,-order_file,injector/payloads/order -shared -nostdlib -xassembler - -arch i386 -o $@
	
build/injector/payloads/%.bin: build/injector/payloads/%.dylib
	gobjcopy -Obinary $^ $@

install: all
	sudo mkdir -p /usr/lib/mip/user_data
	sudo mkdir -p /usr/lib/mip/Bundles
	sudo mkdir -p /usr/local/include/mip
	@# We remove the old libraries before copying, overwriting causes codesigning issues.
	-@sudo rm -f /usr/lib/mip/lsdinjector.dylib /usr/lib/mip/loader.dylib
	sudo cp build/lsdinjector.dylib build/loader.dylib /usr/lib/mip/
	sudo cp build/inject /usr/bin/
	sudo cp loader/loader_public.h /usr/local/include/mip/loader.h
	sudo cp local.lsdinjector.plist /Library/LaunchDaemons/
	(read -p "Inject MIP to launchservicesd without restart? [y/N] " -n 1 -r; echo ; if [[ $$REPLY =~ ^[Yy]$$ ]]; then sudo inject launchservicesd /usr/lib/mip/lsdinjector.dylib; fi;)

uninstall:
	-sudo rm -rf /usr/lib/mip
	-sudo rm -rf /usr/include/mip
	-sudo rm /Library/LaunchDaemons/local.lsdinjector.plist
	
clean:
	rm -rf build
