.CODE

_asm_fyl2xp1 PROC
FYL2XP1
ret
_asm_fyl2xp1 ENDP

_asm_set_tf PROC
pushfq
or dword ptr[rsp],10100h
popfq
db 0fh
db 0a2h
nop
nop
nop
ret
_asm_set_tf ENDP

_asm_check_ind PROC
pushfq
cli
push 1                 ; Set cache data
wbinvd                 ; Flush writeback data set from previous instruction to system memory.
mov byte ptr [rsp], 0  ; Set memory to 0. This is in WB memory so it will not be in system memory.
invd                   ; Flush the caches but do not write back to system memory. Real hardware will result in loss of previous operation.
pop rax                ; Proper system behaviour will have AL = 1; Hypervisor/emulator that uses WBINVD or does nothing will have AL = 0.
popfq
ret
_asm_check_ind ENDP

_asm_check_lbr PROC
    mov rcx, 01D9h
    xor rdx, rdx
    wrmsr
    rdmsr
    shl rdx, 20h	; EDX:EAX for wrmsr
    or rax, rdx
    jmp check_msr

check_msr:
    test al, 1
    jnz no_detect
    mov al, 1
    ret
    
no_detect:
    xor rax, rax
    xor rdx, rdx
    mov rdx, 01D9h
    wrmsr
    ret
_asm_check_lbr ENDP


END