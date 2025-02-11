TARGET   = dhrystone

TARGET_ARCH = riscv32

CC       = riscv-none-elf-gcc

# compiling flags here
CFLAGS = -Wall -I. -O0 -static -march=rv32imac_zicsr -mabi=ilp32 --specs=nosys.specs -ggdb


LINKER   = riscv-none-elf-gcc
# linking flags here
LDFLAGS   = -I. -static -g
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

rm       = rm -f


$(BINDIR)/$(TARGET): $(OBJECTS)
	$(LINKER) $(CFLAGS) $(LDFLAGS) $(LIBS) $(LIBDIR) $(OBJECTS) -o $@
	riscv-none-elf-objdump -d $@ > dump
	riscv-none-elf-objcopy -Oihex $@ $(TARGET).hex
	@echo "Linking complete!"

$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	@echo "Compiling "$<" ..."
	$(CC) $(CFLAGS) $(INCDIR) -c $< -o $@
	@echo "Done!"

.PHONY: clean
clean:
	@$(rm) $(OBJECTS) *.hex dump
	@echo "Cleanup complete!"

.PHONY: remove
remove: clean
	@$(rm) $(BINDIR)/$(TARGET) $(OBJECTS)
	@echo "Executable removed!"

all: $(BINDIR)/$(TARGET)
