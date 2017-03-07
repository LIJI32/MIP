#ifndef symbols_h
#define symbols_h

/* dlsym-like function that uses (private API) CoreSymbolication to get unexported symbols.
   C functions use their C name, without the underscore prefix. C++ functions use their
   demangled names, e.g. "MYClass::function(int, void *)" */
void *get_symbol(const char *name);

#endif
