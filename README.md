# MIP
MIP, macOS Injection Platform, is a platform that lets macOS developers create operating system tweaks by allowing them to create code that can be injected automatically to any GUI process. MIP was originally written as part of my unreleased macOS theming mechanism, because other techniques could not inject code in an early enough and reliable timing which allows all theming features. MIP was later rewritten to be more stable, generic and versatile, as well as easier to maintain, and became open source (MIT).

## Disclaimer
Code injection is dangerous, and might make your computer unstable or unsable if you don't know what you're doing. Use MIP with care. In case of emergency, delete `/Library/LaunchDaemons/local.lsdinjector.plist` using the recovery boot.

MIP should work on all 64-bit versions of macOS, but it's deliberately limited to Yosemite and newer; released versions were not tested on versions older than Sierra.

## MIP's Advantages
MIP has the following advantages when comparing to other injection techniques:

 * Injects to every single GUI process, including non-apps processes such as system processes with GUI, the dock, tab processes of browsers, etc.
 * Injects to restricted binaries (binaries using a `__RESTRICT,__restrict` section or special entitlements, where dyld enviroment variables are ignored)
 * The injected code runs on the main thread, and blocks it until it finishes initializing; preventing race bugs.
 * The injected code is always injected at a deterministic time, in the same code flow for every app, making code easier to debug
 * The injected code runs at a very early stage in the process's lifetime, before the UI frameworks start running, making advanced UI customizations possible
 * Can be installed without reboot
 * Does not modify any system file on disk and can be easily uninstalled without rebooting
 * Does not use `DYLD_INSERT_LIBRARIES`, which may break the system if a file is deleted.
 * Works with both 32- and 64-bit applications, and allows injection to Garbage Collected processes (On El Capitan and older, GC was removed in Sierra)
 * Supports every macOS major up to and including Monterey
 * Supports ARM64-based Macs

## How To Compile
You will need Xcode's command-line tools, as well as binutils for `gobjcopy` (`brew install binutils`), which should be linked as `gobjcopy`. You will also need a signing identity, which may be self-signed. Not signing MIP binaries properly will make your system unstable! On Intel Macs, you will need the [10.13 SDK](https://github.com/phracker/MacOSX-SDKs/releases/download/11.3/MacOSX10.13.sdk.tar.xz), to compile the 32-bit portions of MIP.

To compile, simply run `make SIGNING_IDENTITY=<codesign identity>` inside the MIP folder, or `make SYSROOT=path/to/MacOSX10.13.sdk SIGNING_IDENTITY=<codesign identity>` on Intel Macs.

## How To Install/Uninstall
MIP requires disabling SIP (System Integrity Protection) both during installation and during use. On ARM64 Macs, you will also need to enable the arm64e preview ABI (`sudo nvram boot-args=-arm64e_preview_abi`)

To install, simply run `make install` inside the MIP folder. You can uninstall by running `make uninstall"`. If you can't get a terminal to open due a misconfiguration of MIP, you can disable it by deleting `/Library/LaunchDaemons/local.lsdinjector.plist` using the recovery boot, which will disable MIP.

Bundles are installed to `/Library/Apple/System/Library/Frameworks/mip/Bundles`.

### Why Must I Disable SIP?
SIP not only prevents system files and folders from being modified, but also prevents debugging of any SIP-protected binary. Code injection, by definition, requires static (on filesystem) or dynamic (via debugging) modification of binary files, and MIP obviously cannot operate with such limitations. Even if you do not intend to inject code to Apple provided binaries, MIP operates by injecting code to a system process (launchservicesd), which later injects code to all other processes.

In El Capitan, MIP can be modified to run with SIP enabled as long as it was disabled during installation, due to task ports being leaked to launchservicesd via XPC messages, but this is neither recommended nor supported, and requires modifying launchservicesd's launchd plist file. This potential vulnerability was fixed in Sierra.

## Sample Bundles
MIP includes Alt-Zoom as both a useful tweak and a bundle development reference. Alt-Zoom is a bundle that lets you modify the default behavior of the zoom button and the way modifier keys affect its behavior. You can install it by running `make SIGNING_IDENTITY=<codesign identity>` and `make install` in Alt-Zoom's folder in the repository. It has a setting app to control its configuration.

## Injection Filters
The processes a bundle is loaded into are determined by that bundle's `Info.plist` file. By default MIP filters in a white-list manner. The following keys are used to control filtering:

 * `MIPBundleNames` - Array, controls the bundle names to inject to (or to ignore in black-list mode).
 * `MIPExecutableNames` - Array, controls the executable basenames to inject to (or to ignore in black-list mode).
 * `MIPUseBlacklistMode` - Boolean, sets the filtering mode to black-list mode if true.
 * `MIPSupportsGC` - Boolean, tells MIP the injected bundle supports Garbage Collection and may be injected to GC-enabled processes. If incorrectly set to true while the injected bundle does not actually support GC, the injected bundle will crash the process. Garbage Collection is not available in macOS Sierra's Objective-C runtime, no need to support it if you're targeting Sierra and newer.

Additionally, because bundles are installed on a system-wide basis (For security reasons, some Apple-signed binarys will intentionally crash when loading libraries not owned by root), a user may disable a specific bundle by creating a plist file at `~/Library/MIP/settings.plist` with an array `MIPDisabledBundles` set to a list of the disabled bundle identifiers.

## How It Works
During installation, MIP installs 4 files; lsdinjector.dylib and loader.dylib, a command line utility called `inject`, and a launch daemon.

`inject` is a command line utility that allows injecting a dylib file to a running process by PID. The launch daemon MIP installs runs `inject` as root when the system boots, and injects lsdinjector.dylib to launchservicesd.

When a Cocoa process launches, one of the early things it does is calling `_LSApplicationCheckIn`. This function sends an XPC message to launchserivcesd, and blocks until it receives a reply. lsdinjector.dylib hooks the function in launchservicesd that handles that XPC message. The hook will inject loader.dylib to the process before it sends a reply, so the process is still blocked during the injection. This uses the same code as the `inject` utility.

When the reply is sent, the process resumes running at the injected code, running loader.dylib's initializer which loads all tweak bundles. When loader.dylib finishes, the process' normal operation resumes.

This method of injection ensures the injected code *always* runs in the same flow and in the same thread.

To make sure all libraries, bundles and user settings and data are accessible from every process the user runs, even under very strict sandboxing, all MIP data is located in /Library/Apple/System/Library/Frameworks/mip. User data is located in /Library/Apple/System/Library/Frameworks/mip/user_data/UID, with the correct owner. A symlink to this folder is created in ~/Library/MIP for each user for convenience, but bundles should use the real path directly.

### How The Inject Function Works
The inject function both lsdinjector.dylib and `inject` use works by modifying the main thread's state to simulate a `call` instruction.

First, it copies a payload bootstrap code to the process (On Intel Macs, x86 or x86-64 code, depending on the processes), as well as a pointer to dyld's load address and the path of the dylib to inject. Then, it pauses the thread (to ensure atomicity) and modifies its PC/IP, SP and stack contents to simulate a call instruction to the entry function of the payload, and resumes the thread.

The payload function is a compiled but unlinked C code, so it can't used any external symbols such as dlopen directly. It is declared in a way that saves and restores all registers, and does additional calls to save and restore the flags register as well. The function uses the dyld pointer provided by the injector to find a pointer to dyld's dlopen function, and then calls it with the provided dylib path.

## Upgrading Notes

If you were using an old version on MIP that used `/usr/lib/mip` as its data directory on macOS Mojave or older, upon upgrading to macOS Catalina or newer MIP bundles that linked against `/usr/lib/mip/loader.dylib` will cease functioning. They must be recompiled and linked against `/Library/Apple/System/Library/Frameworks/mip/loader.dylib` instead.

## Rosetta Support

MIP is currently unable to inject to Intel processes running through Rosetta. This will be addressed in a future version.
