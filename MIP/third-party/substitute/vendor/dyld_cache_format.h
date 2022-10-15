/* -*- mode: C++; c-basic-offset: 4; tab-width: 4 -*- 
 *
 * Copyright (c) 2006-2009 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
#ifndef __DYLD_CACHE_FORMAT__
#define __DYLD_CACHE_FORMAT__

#include <stdint.h>


struct dyld_cache_header
{
	char		magic[16];			// e.g. "dyld_v0    i386"
	uint32_t	mappingOffset;			// file offset to first dyld_cache_mapping_info
	uint32_t	mappingCount;			// number of dyld_cache_mapping_info entries
	uint32_t	imagesOffset;			// file offset to first dyld_cache_image_info
	uint32_t	imagesCount;			// number of dyld_cache_image_info entries
	uint64_t	dyldBaseAddress;		// base address of dyld when cache was built
	uint64_t	codeSignatureOffset;		// file offset of code signature blob
	uint64_t	codeSignatureSize;		// size of code signature blob (zero means to end of file)
	uint64_t	slideInfoOffset;		// file offset of kernel slid info
	uint64_t	slideInfoSize;			// size of kernel slid info
	uint64_t	localSymbolsOffset;		// file offset of where local symbols are stored
	uint64_t	localSymbolsSize;		// size of local symbols information
	uint8_t		uuid[16];			// unique value for each shared cache file
	uint64_t	cacheType;			// 0 for development, 1 for production
	uint32_t	branchPoolsOffset;		// file offset to table of uint64_t pool addresses
	uint32_t	branchPoolsCount;		// number of uint64_t entries
	uint64_t	accelerateInfoAddr;		// (unslid) address of optimization info
	uint64_t	accelerateInfoSize;		// size of optimization info
	uint64_t	imagesTextOffset;		// file offset to first dyld_cache_image_text_info
	uint64_t	imagesTextCount;		// number of dyld_cache_image_text_info entries
	uint64_t	patchInfoAddr;			// (unslid) address of dyld_cache_patch_info
	uint64_t	patchInfoSize;			// Size of all of the patch information pointed to via the dyld_cache_patch_info
	uint64_t	otherImageGroupAddrUnused;	// unused
	uint64_t	otherImageGroupSizeUnused;	// unused
	uint64_t	progClosuresAddr;		// (unslid) address of list of program launch closures
	uint64_t	progClosuresSize;		// size of list of program launch closures
	uint64_t	progClosuresTrieAddr;		// (unslid) address of trie of indexes into program launch closures
	uint64_t	progClosuresTrieSize;		// size of trie of indexes into program launch closures
	uint32_t	platform;			// platform number (macOS=1, etc)
	uint32_t	formatVersion         	: 8,	// dyld3::closure::kFormatVersion
	        	dylibsExpectedOnDisk 	: 1,	// dyld should expect the dylib exists on disk and to compare inode/mtime to see if cache is valid
	        	simulator             	: 1,	// for simulator of specified platform
	        	locallyBuiltCache     	: 1,	// 0 for B&I built cache, 1 for locally built cache
	        	builtFromChainedFixups	: 1,	// some dylib in cache was built using chained fixups, so patch tables must be used for overrides
	        	padding               	: 20;	// TBD
	uint64_t	sharedRegionStart;		// base load address of cache if not slid
	uint64_t	sharedRegionSize;		// overall size of region cache can be mapped into
	uint64_t	maxSlide;			// runtime slide of cache can be between zero and this value
	uint64_t	dylibsImageArrayAddr;		// (unslid) address of ImageArray for dylibs in this cache
	uint64_t	dylibsImageArraySize;		// size of ImageArray for dylibs in this cache
	uint64_t	dylibsTrieAddr;			// (unslid) address of trie of indexes of all cached dylibs
	uint64_t	dylibsTrieSize;			// size of trie of cached dylib paths
	uint64_t	otherImageArrayAddr;		// (unslid) address of ImageArray for dylibs and bundles with dlopen closures
        uint64_t	otherImageArraySize;		// size of ImageArray for dylibs and bundles with dlopen closures
	uint64_t	otherTrieAddr;			// (unslid) address of trie of indexes of all dylibs and bundles with dlopen closures
	uint64_t	otherTrieSize;			// size of trie of dylibs and bundles with dlopen closures
	uint32_t	mappingWithSlideOffset;		// file offset to first dyld_cache_mapping_and_slide_info
	uint32_t	mappingWithSlideCount;		// number of dyld_cache_mapping_and_slide_info entries
	uint64_t	field_140;
	uint64_t	field_148;
	uint64_t	field_150;
	uint64_t	field_158;
	uint64_t	field_160;
	uint32_t	field_168;
	uint32_t	field_16C;
	uint32_t	field_170;
	uint32_t	field_174;
	uint32_t	field_178;
	uint32_t	field_17C;
	uint32_t	field_180;
	uint32_t	field_184;
	uint32_t	field_188;
	uint32_t	field_18C;
	uint8_t 	symbolSubCacheUUID[16];
	uint64_t	field_1A0;
	uint64_t	field_1A8;
	uint64_t	field_1B0;
	uint32_t	field_1B8;
	uint32_t	field_1BC;
	uint32_t	field_1C0;
	uint32_t	images_count;
};

struct dyld_cache_mapping_info {
	uint64_t	address;
	uint64_t	size;
	uint64_t	fileOffset;
	uint32_t	maxProt;
	uint32_t	initProt;
};

struct dyld_cache_image_info
{
	uint64_t	address;
	uint64_t	modTime;
	uint64_t	inode;
	uint32_t	pathFileOffset;
	uint32_t	pad;
};

struct dyld_cache_slide_info
{
	uint32_t	version;		// currently 1
	uint32_t	toc_offset;
	uint32_t	toc_count;
	uint32_t	entries_offset;
	uint32_t	entries_count;
	uint32_t	entries_size;  // currently 128 
	// uint16_t toc[toc_count];
	// entrybitmap entries[entries_count];
};


struct dyld_cache_local_symbols_info
{
	uint32_t	nlistOffset;		// offset into this chunk of nlist entries
	uint32_t	nlistCount;			// count of nlist entries
	uint32_t	stringsOffset;		// offset into this chunk of string pool
	uint32_t	stringsSize;		// byte count of string pool
	uint32_t	entriesOffset;		// offset into this chunk of array of dyld_cache_local_symbols_entry 
	uint32_t	entriesCount;		// number of elements in dyld_cache_local_symbols_entry array
};

struct dyld_cache_local_symbols_entry_32
{
	uint32_t	dylibOffset;		// offset in cache file of start of dylib
	uint32_t	nlistStartIndex;	// start index of locals for this dylib
	uint32_t	nlistCount;		// number of local symbols for this dylib
};

struct dyld_cache_local_symbols_entry_64
{
	uint64_t	dylibOffset;		// offset in cache file of start of dylib
	uint32_t	nlistStartIndex;	// start index of locals for this dylib
	uint32_t	nlistCount;		// number of local symbols for this dylib
};


#define MACOSX_DYLD_SHARED_CACHE_DIR	"/var/db/dyld/"
#define IPHONE_DYLD_SHARED_CACHE_DIR	"/System/Library/Caches/com.apple.dyld/"
#define DYLD_SHARED_CACHE_BASE_NAME		"dyld_shared_cache_"



#endif // __DYLD_CACHE_FORMAT__


