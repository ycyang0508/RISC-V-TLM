TARGET   = freertos_test

TARGET_ARCH = riscv32

CC       = riscv-none-elf-gcc

# compiling flags here
CFLAGS = -Wall -I. -O0 -static -march=rv32imac_zicsr -mabi=ilp32 --specs=nosys.specs

LINKER   = riscv-none-elf-gcc
# linking flags here
LDFLAGS   = -I. -static 
LIBS   = $(EXTRA_LIBS)


# change these to proper directories where each file should be
SRCDIR   = ./
OBJDIR   = .
BINDIR   = ./
INCDIR = -I.
LIBDIR = -L.


SOURCES  := $(wildcard $(SRCDIR)/*.c)
INCLUDES := $(wildcard $(INCDIR)/*.h)
OBJECTS  := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

SOURCES_ASM := $(wildcard $(SRCDIR)/*.S)
OBJECTS_ASM := $(SOURCES_ASM:$(SRCDIR)/%.S=$(OBJDIR)/%.o)

rm       = rm -f


$(BINDIR)/$(TARGET): $(OBJECTS) $(OBJECTS_ASM)
	$(LINKER) $(CFLAGS) $(LDFLAGS) $(LIBS) $(LIBDIR) $(OBJECTS) $(OBJECTS_ASM) -o $@
	riscv-none-elf-objdump -d $@ > dump
	riscv-none-elf-objcopy -Oihex $@ $(TARGET).hex
	@echo "Linking complete!"

$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	@echo "Compiling "$<" ..."
	$(CC) $(CFLAGS) $(INCDIR) -c $< -o $@
	@echo "Done!"

$(OBJECTS_ASM): $(OBJDIR)/%.o: $(SRCDIR)/%.S
	@echo "Assembling "$<" ..."
	$(CC) $(CFLAGS) $(INCDIR) -c $< -o $@
	@echo "Done!"

.PHONY: clean
clean:
	@$(rm) $(TARGET) $(OBJECTS) $(OBJECTS_ASM) *.hex dump
	@echo "Cleanup complete!"

.PHONY: remove
remove: clean
	@$(rm) $(BINDIR)/$(TARGET)
	@echo "Executable removed!"
