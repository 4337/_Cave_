IFNDEF CAVE_INC
CAVE_INC EQU <1>

__NO_ERROR           equ 000000000h
__FILE_OPEN_ERROR    equ 000000001h
__INVALID_SIZE_ERROR equ 000000010h
__GET_HEAP_ERROR     equ 000000100h
__HEAP_ALLOC_ERROR   equ 000001000h
__INVALID_PE_ERROR   equ 000010000h
__IS_X64_PE_ERROR    equ 000100000h
__READ_FILE_ERROR    equ 001000000h    
__NO_CAVE_ERROR      equ 010000000h
__WRITE_FILE_ERROR   equ 0f0000000h

CAVE_HNDS struct 
           
          h_file     dd     0
          oep        dd     0     
          ep         dd     0     
          nt         dd     0     
          dos        dd     0     
          ib         dd     0
          f_align    dd     0         ;0x18
          s_align    dd     0         ;0x1c
          f_size     dd     0
          v_sizes    dd 9 dup(0)
          r_sizes    dd 9 dup(0)
          v_addr     dd 9 dup(0)
          p_raw      dd 9 dup(0)
          entries    dd 9 dup(0)   ;caves addresses
          sizes      dd 9 dup(0)   ;cave sizes
          
CAVE_HNDS ends

cave_init       proto stdcall :ptr CAVE_HNDS,:ptr BYTE

cave_search     proto stdcall :ptr CAVE_HNDS,:ptr IMAGE_SECTION_HEADER,:ptr BYTE,:DWORD

cave_get_bigest proto stdcall :ptr CAVE_HNDS

cave_add_code   proto stdcall :ptr CAVE_HNDS,:ptr BYTE,:UINT

cave_release    proto stdcall :ptr CAVE_HNDS

ENDIF