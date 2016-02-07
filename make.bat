@echo off

C:\masm32\bin\ml.exe /c /coff /I C:\masm32 cave.asm stub.asm main.asm 
C:\masm32\bin\link.exe /SUBSYSTEM:CONSOLE /LIBPATH:C:\masm32\lib /OUT:test.exe main.obj cave.obj stub.obj

del cave.obj
del main.obj
del stub.obj

pause