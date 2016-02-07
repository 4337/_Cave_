.386
.model         flat,stdcall
option         casemap:none

include        include\windows.inc

public         __vx
public         vx_size
public         __vx_end 

assume         fs:nothing

.data 

vx_size        dd (__vx_end - __vx) + 5

.code

__vx:

db 'BADZJAKALA'
db 10 dup(0cch)
db 'ALAMAKOTA' 

__vx_end        db 5 dup(0e9h)                        

end
                      

