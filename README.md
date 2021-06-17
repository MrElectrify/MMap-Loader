# MMap-Loader
MMap-Loader is a Windows Portable Executable (PE) loader. It maps a view of an executable PE file, performs all necessary actions to make the view executable, and executes the file.

## Features
- Supports both DLL and EXE types
- Supports C++ exceptions, vectored exception handling, and structured exception handling
- Adds the entry to the loader structures, allowing support for functions such as `GetModuleHandle`
- MSVC recognizes mapped executables and debugging of children is fully supported with symbols
- Supports lazy execution, where multiple PE files can be loaded before any are executed
- Returns control flow to the calling function after execution is complete
- Small codebase, using C++20

## Known Limitations
- 32-bit is not fully supported (but is an easy fix)
- `GetModuleInformation` and related functions will not find the loaded module. This is because the linked lists that are used to find the module for these functions are sanity checked and protected by the kernel, and the first access after modifying these structures would result in a fatal OS exception. A suggested alternative is to use `VirtualQuery` to get the size of allocation
- Relies on function signatures for all `Ldrp` functions. This can be remedied by downloading the `ntdll.dll` PDB and walking through the symbols, but was excessive for my use case. This does mean that Windows updates may break some signatures causing failure, and platforms like Wine do not work because they don't have an implementation of these functions. Last tested on Windows 10 Pro 20H2 build 19042.1052
- PEs are not un-loaded from OS structures to reduce the number of required signatures to upkeep. If necessary, functions exist to reverse all OS calls.

## Example
```cpp
#include <MMapLoader/PortableExecutable.h>

using MMapLoader::PortableExecutable;

int main()
{
  PortableExecutable exe;
  if (auto res = exe.Load("foo.exe"); res.has_value() == true)
  {
    // handle load failure. most of the time a sensical NTSTATUS or windows error (DWORD) is returned.
    // in some cases such as signature failure, STATUS_ACPI_FAILURE is returned. another custom NTSTATUS
    // return code is STATUS_OBJECTID_NOT_FOUND, in the event that an imported module was not found
  }
  PortableExecutable dll;
  if (auto res = dll.Load("bar.dll"); res.has_value() == true)
  {
    // handle this too
  }
  // let's say we want to run bar::DllMain before foo::WinMain
  if (dll.Run() == FALSE)
  {
    // the DLL returned false. handle this accordingly, as per MSDN this indicates failure
  }
  exe.Run();
  return 0;
}
```
