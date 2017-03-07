# Make hacks
.INTERMEDIATE:
.PHONY: all install

all: build/Alt-Zoom.bundle build/Alt-Zoom.app

CC := clang
CFLAGS += -mmacosx-version-min=10.10 -Werror -Wall -I. -I/usr/local/include -g -O3
LDFLAGS += -mmacosx-version-min=10.10 -framework AppKit
SIGN_IDENTITY ?= "CodeSign"

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
	$(CC) $(CFLAGS) -arch x86_64 -arch i386 -fobjc-arc -c $< -o $@

build/Alt-Zoom.bundle: build/Alt-Zoom.bundle/Contents/MacOS/Alt-Zoom build/Alt-Zoom.bundle/Contents/Info.plist
	codesign -fs $(SIGN_IDENTITY) $@
build/Alt-Zoom.app: build/Alt-Zoom.app/Contents/MacOS/Alt-Zoom\
                    build/Alt-Zoom.app/Contents/Info.plist\
                    build/Alt-Zoom.app/Contents/Resources/Base.lproj/MainMenu.nib\
                    build/Alt-Zoom.app/Contents/Resources/AppIcon.icns
	codesign -fs $(SIGN_IDENTITY) $@

build/Alt-Zoom.bundle/Contents/MacOS/Alt-Zoom: $(BUNDLE_OBJECTS)
	-@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -arch x86_64 -arch i386 -bundle /usr/lib/mip/loader.dylib $^ -o $@
	
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
	sudo rm -rf /usr/lib/mip/Bundles/Alt-Zoom.bundle
	sudo cp -rf build/Alt-Zoom.bundle /usr/lib/mip/Bundles/