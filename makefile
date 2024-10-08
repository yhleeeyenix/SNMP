CC      := $(CROSS_COMPILE)gcc $(CPU_CFLAGS) -g -Wall
TARGET  := a2a_dev

.PHONY: all clean

all: $(TARGET)

$(TARGET): snmp.c
        @echo " $(CC) -o $@ $< "
        $(CC) -o $@ $^
        
clean:
        rm -rf *.o
        rm -rf $(TARGET)