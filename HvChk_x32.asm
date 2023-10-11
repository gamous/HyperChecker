.686p
.model flat
.CODE

__asm_fyl2xp1 PROC
FYL2XP1
ret
__asm_fyl2xp1 ENDP

__asm_set_tf PROC
pushfd
or dword ptr[esp],10100h
popfd
db 0fh
db 0a2h
nop
nop
nop
ret
__asm_set_tf ENDP

__asm_check_ind PROC
pushfd
cli
push 1                 ; Set cache data
wbinvd                 ; Flush writeback data set from previous instruction to system memory.
mov byte ptr [esp], 0  ; Set memory to 0. This is in WB memory so it will not be in system memory.
invd                   ; Flush the caches but do not write back to system memory. Real hardware will result in loss of previous operation.
pop eax                ; Proper system behaviour will have AL = 1; Hypervisor/emulator that uses WBINVD or does nothing will have AL = 0.
popfd
ret
__asm_check_ind ENDP

__asm_check_lbr PROC
    mov ecx, 01D9h
    xor edx, edx
    wrmsr
    rdmsr
    shl edx, 20h	; EDX:EAX for wrmsr
    or eax, edx
    jmp check_msr

check_msr:
    test al, 1
    jnz no_detect
    mov al, 1
    ret
    
no_detect:
    xor eax, eax
    xor edx, edx
    mov edx, 01D9h
    wrmsr
    ret
__asm_check_lbr ENDP


END