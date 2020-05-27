# PE-file-checker
PE file checker (C# with Visual Studio)

The program checks PE files (Windows exe and dll) for correctness

Please note that the program sometimes mistakes correct files as incorrect ones , because it does not take into account certain features of PE files ( for example, the fact that a section may be loaded at the another relative address as it is located in the file)

The program can be useful if you are trying to generate a PE file yourself (PE32 or PE32+ [aka PE64])

If you check the checkboxes, you can usually view the import and export tables. Does not apply to .NET.
