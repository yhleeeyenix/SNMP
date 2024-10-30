# 컴파일러 설정 (CROSS_COMPILE과 CPU_CFLAGS 포함)
CC      := $(CROSS_COMPILE)gcc $(CPU_CFLAGS) -g -Wall
TARGET  := snmp

# 소스 파일 목록 (src 폴더 내)
SRCS    := src/main.c src/snmp.c src/snmp_mib.c src/snmp_parse.c src/utility.c

# 오브젝트 파일 목록
OBJS    := $(SRCS:.c=.o)

# 헤더 파일 목록 (include 폴더 내)
HEADERS := include/snmp.h include/snmp_mib.h include/snmp_parse.h include/utility.h

.PHONY: all clean

# 기본 빌드 대상은 $(TARGET)
all: $(TARGET)

# 링크 과정에서 모든 오브젝트 파일을 함께 사용하여 타겟을 생성
$(TARGET): $(OBJS)
	@echo "Linking $(TARGET)"
	$(CC) -o $@ $^

# 개별 .c 파일을 .o 파일로 컴파일
src/%.o: src/%.c $(HEADERS)
	@echo "Compiling $<"
	$(CC) -Iinclude -c $< -o $@

# clean 대상 - 빌드 결과물을 삭제
clean:
	@echo "Cleaning up..."
	rm -rf src/*.o
	rm -rf $(TARGET)
