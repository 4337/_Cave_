.386
.model         flat,stdcall
option         casemap:none

include       include\windows.inc
include       include\kernel32.inc
include       include\masm32.inc
include       .\cave.inc

includelib    C:\masm32\lib\kernel32.lib            ; fix

cave_open MACRO f_name
    push    0 
    push    FILE_ATTRIBUTE_NORMAL or \
            FILE_ATTRIBUTE_HIDDEN or \
            FILE_ATTRIBUTE_SYSTEM
    push    OPEN_EXISTING
    push    0
    push    FILE_SHARE_READ
    push    GENERIC_READ or GENERIC_WRITE
    push    f_name
    call    CreateFile 
endm

cave_close MACRO f_hnd
    push   f_hnd
    call   CloseHandle 
endm

is_pe MACRO nt, dos
  push      edi
  push      esi
  xor       eax,eax
  mov       edi,dos
  mov       esi,nt
  assume    edi:ptr IMAGE_DOS_HEADER
  .if       word ptr[edi].e_magic != 'ZM' || \   
            dword ptr[esi] != 'EP'
  mov       eax,__INVALID_PE_ERROR               
  .else                                     
  assume    esi:ptr IMAGE_NT_HEADERS            
  lea       esi,dword ptr[esi].OptionalHeader
  assume    esi:ptr IMAGE_OPTIONAL_HEADER
  .if       word ptr[esi].Magic != 010Bh    
  mov       eax,__IS_X64_PE_ERROR           
  .endif                  
  .endif      
  pop       esi
  pop       edi                                
endm

.data 

.code

cave_search proc stdcall uses edi ebx esi ecx\
                 c_hnds:ptr CAVE_HNDS,\
                 f_sec:ptr IMAGE_SECTION_HEADER,\
                 f_buf:ptr BYTE, \
                 s_cnt:DWORD
 LOCAL       array_index:DWORD
 
 mov         DWORD ptr[array_index],0
 
 std
 xor         eax,eax        
 mov         ebx,f_sec     
 
 assume      ebx:ptr IMAGE_SECTION_HEADER

 xor         si,si
 
 .while      si < word ptr[s_cnt]
 
 test        dword ptr[ebx].Characteristics,080000000h 
 jne         @f

 
 mov         edi,f_buf
 add         edi,dword ptr[ebx].PointerToRawData
 add         edi,dword ptr[ebx].SizeOfRawData
 dec         edi
 mov         ecx,dword ptr[ebx].SizeOfRawData
 repe        scasb
 jne         __set

@@:add       ebx,sizeof IMAGE_SECTION_HEADER
 inc         esi
 
 .endw
 jmp         @f
 __set:      push        ebx
 push        edi
 
 mov         edi,ebx
 assume      edi:ptr IMAGE_SECTION_HEADER
 
 or          dword ptr[ebx].Characteristics, 020000000h                       
 
 inc         ecx
 inc         ecx ;one byte for breath

 mov         edi, dword ptr[edi].SizeOfRawData
 sub         edi, ecx
 
 push        dword ptr[ebx].VirtualAddress 
 
 push        dword ptr[ebx].SizeOfRawData
 
 push        dword ptr[ebx].Misc.VirtualSize
 
 push        dword ptr[ebx].PointerToRawData
 
 push        dword ptr[ebx].PointerToRawData
  
 mov         ebx,c_hnds
 assume      ebx:ptr CAVE_HNDS
   
 mov         eax,array_index
 
 pop         dword ptr[ebx].p_raw[eax * 4]
 
 pop         dword ptr[ebx].entries[eax * 4]
 
 pop         dword ptr[ebx].v_sizes[eax * 4]
 
 pop         dword ptr[ebx].r_sizes[eax * 4]
    
 pop         dword ptr[ebx].v_addr[eax * 4] 
 
 add         dword ptr[ebx].entries[eax * 4],ecx   
 
 mov         dword ptr[ebx].sizes[eax * 4],edi
 
 inc         dword ptr[array_index]
 xor         eax,eax
 pop         edi
 pop         ebx
 jmp         @b
 
@@:          cld 
 ret         010h
cave_search endp

cave_release proc stdcall \
             c_hnds:ptr CAVE_HNDS
 mov        eax,c_hnds
 cave_close dword ptr[eax]                      
 ret         04h            
cave_release endp

cave_add_code proc stdcall uses ebx ecx\
                c_hnds:ptr CAVE_HNDS,\
                c_code:ptr BYTE,\
                c_size:UINT
 
  LOCAL     index:DWORD
  
  mov       dword ptr[index],0
               
  mov       ebx,c_hnds
  assume    ebx:ptr CAVE_HNDS             
           
  push      ebx
  call      cave_get_bigest

  mov       index,eax

  mov       ecx,c_size
  
  .if       dword ptr[ebx].sizes[eax * 4] < ecx 
  mov       eax,__NO_CAVE_ERROR
  .else 

	push      FILE_BEGIN
  push      0
  push      dword ptr[ebx].entries[eax * 4]
  push      dword ptr[ebx].h_file
  call      SetFilePointer
  
  push      0
  push      0
  push      c_size
  push      c_code
  push      dword ptr[ebx].h_file
  call      WriteFile 
  .if       eax == 0
  mov       eax,__WRITE_FILE_ERROR
  jmp       @f
  .endif

  push      FILE_BEGIN   
  push      0
  push      0118h                    ;entry_point
  push      dword ptr[ebx].h_file
  call      SetFilePointer
  
  mov       eax,index
  
  mov       ecx,dword ptr[ebx].v_addr[eax * 4]     
  dec       ecx
  add       ecx,dword ptr[ebx].v_sizes[eax * 4]
  ;
  push      ecx
  lea       ecx,dword ptr[esp]
  ;  
  push      0
  push      0
  push      4
  push      ecx
  push      dword ptr[ebx].h_file
  call      WriteFile 
  .if       eax == 0
  mov       eax,__WRITE_FILE_ERROR
  jmp       @f
  .endif
  
  ;now set FilePointer here: dword ptr[ebx].entries[eax * 4] + dword ptr[ebx].sizes[eax * 4]
  ;and place jmp to oep

  .endif 
  
  xor       eax,eax

@@:
  
  ret       0ch
                
cave_add_code endp      

cave_init proc stdcall uses ebx\
               c_hnds:ptr CAVE_HNDS, \
               f_name:ptr BYTE, 
                          
  LOCAL       hproc:HANDLE
  LOCAL       fbuff:ptr BYTE
  LOCAL       scnt:DWORD
         
  mov         dword ptr[scnt],0          
            
  mov         ebx,c_hnds
  mov         eax,f_name
  assume      ebx:ptr CAVE_HNDS
  
  cave_open   eax
  .if         eax == INVALID_HANDLE_VALUE || \
              eax == 0
  mov         eax,__FILE_OPEN_ERROR
  .else  
  mov         dword ptr[ebx].h_file,eax
  
  push        0
  push        eax
  call        GetFileSize
  .if         eax == INVALID_FILE_SIZE || \
              eax <= 0 
  mov         eax,__INVALID_SIZE_ERROR
  .else 
  
  mov         dword ptr[ebx].f_size,eax
    
  call        GetProcessHeap
  .if         eax == 0
  mov         eax,__GET_HEAP_ERROR
  .else
  mov         hproc,eax
  
  push        dword ptr[ebx].f_size
  push        HEAP_ZERO_MEMORY
  push        eax
  call        HeapAlloc
  .if eax == 0 
  mov         eax,__HEAP_ALLOC_ERROR
  .else
  mov         fbuff,eax
  
  push        0
  push        0
  push        dword ptr[ebx].f_size
  push        eax
  push        dword ptr[ebx].h_file
  call        ReadFile
  
  .if         eax == 0 
  mov         eax,__READ_FILE_ERROR 
  .else 
  
  mov         eax,fbuff
  assume      eax:ptr IMAGE_DOS_HEADER
  
  mov         dword ptr[ebx].dos,eax
  add         eax,dword ptr[eax].e_lfanew
  
  mov         dword ptr[ebx].nt,eax
  
  is_pe       dword ptr[ebx].nt,dword ptr[ebx].dos
  
  .if         eax == __NO_ERROR

  mov         eax,dword ptr[ebx].nt
  
  assume      eax:ptr IMAGE_NT_HEADERS
  
  lea         ebx,dword ptr[eax].FileHeader
  
  assume      ebx:ptr IMAGE_FILE_HEADER
  
  push        word ptr[ebx].NumberOfSections
  pop         scnt
  
  lea         eax,dword ptr[eax].OptionalHeader
  
  assume      eax:ptr IMAGE_OPTIONAL_HEADER
  
  mov         ebx,c_hnds
  
  assume      ebx:ptr CAVE_HNDS
  
  push        dword ptr[eax].FileAlignment
  pop         dword ptr[ebx].f_align
                                        
  push        dword ptr[eax].SectionAlignment
  pop         dword ptr[ebx].s_align                                      
                                        
  push        dword ptr[eax].AddressOfEntryPoint
  pop         dword ptr[ebx + 4]                  ;oep
  
  push        dword ptr[eax].ImageBase
  pop         dword ptr[ebx + 014h]               ;ib
  
  add         eax,sizeof IMAGE_OPTIONAL_HEADER

  
  assume      eax:ptr IMAGE_SECTION_HEADER
  
  push        scnt
  push        fbuff
  push        eax
  push        ebx
  call        cave_search
  
  push        FILE_BEGIN   
  push        0
  push        0
  push        dword ptr[ebx]
  call        SetFilePointer
  
  push        0
  push        0
  push        dword ptr[ebx].f_size
  push        fbuff
  push        dword ptr[ebx]
  call        WriteFile
  
  .if         eax == 0 
  mov         eax,__WRITE_FILE_ERROR
  .else 
  mov         eax, __NO_ERROR
  .endif

  .endif

  .endif
  
  push        eax
  
  push        fbuff
  push        HEAP_ZERO_MEMORY
  push        hproc
  call        HeapFree
  
  pop         eax
  
 .endif
  
 .endif
   
 .endif
  
 .endif
   
 ret             08h
             
cave_init endp

cave_get_bigest proc stdcall uses ebx edi \
                c_hnds:ptr CAVE_HNDS       
           
 LOCAL          index:DWORD
 
 mov            dword ptr[index],0
 
 mov            ebx,c_hnds
 assume         ebx:ptr CAVE_HNDS

 xor            eax,eax
 
 mov            edi,dword ptr[ebx].sizes[eax * 4]
 
 .while         eax < 8 
 
 inc            eax
 .if            edi < dword ptr[ebx].sizes[eax * 4]          ; N+1 (128,0,15,190,5) 
 mov            edi,dword ptr[ebx].sizes[eax  * 4]                                            
 mov            index,eax        
 .endif
 
 .endw
 
 mov            eax,index
 
 ret            04h
 
cave_get_bigest endp

end                                                                               

