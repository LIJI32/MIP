# Make hacks
.INTERMEDIATE:
.PHONY: all install

all: build/Alt-Zoom.bundle build/Alt-Zoom.app

CC := clang
CFLAGS += -mmacosx-version-min=10.10 -Werror -Wall -I. -I/usr/local/include -g -O3
LDFLAGS += -mmacosx-version-min=10.10 -framework AppKit

SYSROOT ?= $(shell xcodebuild -sdk macosx -version Path 2> /dev/null)
CFLAGS += -isysroot $(SYSROOT)
LDFLAGS += -isysroot $(SYSROOT)

BUNDLE_CFLAGS := $(CFLAGS)
BUNDLE_LDFLAGS := $(LDFLAGS)

BUNDLE_CFLAGS += -arch x86_64
BUNDLE_LDFLAGS +=  -arch x86_64

ifeq ($(shell uname -m),arm64)
BUNDLE_CFLAGS += -arch arm64e
BUNDLE_LDFLAGS += -arch arm64e
else
ifeq ($(shell arch -i386 2>&1 | grep Unknown),)
BUNDLE_CFLAGS += -arch i386
BUNDLE_LDFLAGS += -arch i386
endif
endif

SIGN_IDENTITY ?= CodeSign
CODESIGN_TARGET := codesign -fs "$(SIGN_IDENTITY)"

BUNDLE_SOURCES := $(shell ls bundle/*.m)
SETTINGS_SOURCES := $(shell ls settings/*.m)

BUNDLE_OBJECTS := $(patsubst %,build/%.o,$(BUNDLE_SOURCES))
SETTINGS_OBJECTS := $(patsubst %,build/%.o,$(SETTINGS_SOURCES))
ALL_OBJECTS := $(BUNDLE_OBJECTS) $(SETTINGS_OBJECTS)

# Automatic dependency generation

ifneq ($(MAKECMDGOALS),clean)
-include $(ALL_OBJECTS:.o=.dep)
endif

build/%.dep: %
	-@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -MT build/$^.o -M $^ -c -o $@
	
build/settings/%.o: settings/%
	-@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -fobjc-arc -c $< -o $@
	
build/bundle/%.o: bundle/%
	-@mkdir -p $(dir $@)
	$(CC) $(BUNDLE_CFLAGS) -fobjc-arc -c $< -o $@

build/Alt-Zoom.bundle: build/Alt-Zoom.bundle/Contents/MacOS/Alt-Zoom build/Alt-Zoom.bundle/Contents/Info.plist
	$(CODESIGN_TARGET) $@
build/Alt-Zoom.app: build/Alt-Zoom.app/Contents/MacOS/Alt-Zoom\
                    build/Alt-Zoom.app/Contents/Info.plist\
                    build/Alt-Zoom.app/Contents/Resources/Base.lproj/MainMenu.nib\
                    build/Alt-Zoom.app/Contents/Resources/AppIcon.icns
	$(CODESIGN_TARGET) $@

build/Alt-Zoom.bundle/Contents/MacOS/Alt-Zoom: $(BUNDLE_OBJECTS)
	-@mkdir -p $(dir $@)
	$(CC) $(BUNDLE_LDFLAGS) -bundle /Library/Apple/System/Library/Frameworks/mip/loader.dylib $^ -o $@
	
build/Alt-Zoom.bundle/Contents/%: bundle/%
	-@mkdir -p $(dir $@)
	cp -f $^ $@
	
build/Alt-Zoom.app/Contents/Resources/Base.lproj/%.nib: settings/%.xib
	-@mkdir -p $(dir $@)
	ibtool --compile $@ $^

build/Alt-Zoom.app/Contents/%: settings/%
	-@mkdir -p $(dir $@)
	cp -f $^ $@
	
build/Alt-Zoom.app/Contents/Resources/%: settings/%
	-@mkdir -p $(dir $@)
	cp -f $^ $@

build/Alt-Zoom.app/Contents/MacOS/Alt-Zoom: $(SETTINGS_OBJECTS)
	-@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) $^ -o $@


clean:
	rm -rf build

install: all
	sudo cp -rf build/Alt-Zoom.app /Applications/
	sudo rm -rf /Library/Apple/System/Library/Frameworks/mip/Bundles/Alt-Zoom.bundle
	sudo cp -rf build/Alt-Zoom.bundle /Library/Apple/System/Library/Frameworks/mip/Bundles/

uninstall:
	sudo rm -rf /Library/Apple/System/Library/Frameworks/mip/Bundles/Alt-Zoom.bundle
	sudo rm -rf /Applications/Alt-Zoom.app
	