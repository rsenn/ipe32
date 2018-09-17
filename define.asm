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
%define MATH_ADD         OPTYPE_ADD shl 0x03
%define MATH_OR          OPTYPE_OR  shl 0x03
%define MATH_ADC         OPTYPE_ADC shl 0x03
%define MATH_SBB         OPTYPE_SBB shl 0x03
%define MATH_AND         OPTYPE_AND shl 0x03
%define MATH_SUB         OPTYPE_SUB shl 0x03
%define MATH_XOR         OPTYPE_XOR shl 0x03
%define MATH_CMP         OPTYPE_CMP shl 0x03

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

%define MOD_SIB          0b00010000                 ; use sib byte

; REG bits
%define _REG             0b000111000            ; mask for REG-field

; RM bits
%define RM_DIRECT        REG_EBP xor MOD_NODISP
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
