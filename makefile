# 기존 설정에 맞추어 CROSS_COMPILE과 CPU_CFLAGS를 포함한 컴파일러 설정
CC      := $(CROSS_COMPILE)gcc $(CPU_CFLAGS) -g -Wall
TARGET  := snmp

# 소스 파일 목록
SRCS    := snmp.c agent_handler.c

# 오브젝트 파일 목록
OBJS    := $(SRCS:.c=.o)

.PHONY: all clean

# 기본 빌드 대상은 $(TARGET)
all: $(TARGET)

# 링크 과정에서 모든 오브젝트 파일을 함께 사용하여 타겟을 생성
$(TARGET): $(OBJS)
	@echo " $(CC) -o $@ $^ "
	$(CC) -o $@ $^

# 개별 .c 파일을 .o 파일로 컴파일
%.o: %.c
	@echo " $(CC) -c $< -o $@ "
	$(CC) -c $< -o $@

# clean 대상 - 빌드 결과물을 삭제
clean:
	rm -rf *.o
	rm -rf $(TARGET)
