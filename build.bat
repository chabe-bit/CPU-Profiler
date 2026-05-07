@echo off

set CommonCompilerFlags=/nologo
set CommonLinkerFlags=user32.lib gdi32.lib winmm.lib advapi32.lib idh.lib 
set SourceFiles=main.cpp

cl %CommonCompilerFlags% %SourceFiles% /Femain.exe /link /PDB:main.pdb /incremental:no /subsystem:windows %CommonLinkerFlags%

