NASM = nasm

#OBJ_FORMATS =  ith srec aout aoutb coff elf32 elf64 elfx32 as86 obj win32 win64 rdf ieee macho32 macho64 dbg elf macho win
OBJ_FORMATS =  coff elf elf32 elf64 elfx32 obj win win32 win64 macho macho32 macho64
OBJ_FORMATS =  coff elf elf32 obj win win32 macho macho32

OBJECTS = $(patsubst %,ipe32.nasm.%.o,$(OBJ_FORMATS))

all: $(OBJECTS)

ipe32.nasm.obj.o: NASMFLAGS += -DNO_SHORT_JMP=1
ipe32.nasm.%.o: ipe32-nasm.asm
	$(NASM) $(NASMFLAGS) -f $(@:ipe32.%.o=%) -o $@ $<
