all: libdnp3sec.a dnp3test.out

clean:
	rm -f *~ *.o *.d libdnp3sec.a *.out

install:
	@echo Nothing to be made.

include ./lib.rules


CFLAGS += -DCONFIG_TLS_INTERNAL_CLIENT
CFLAGS += -DCONFIG_TLS_INTERNAL_SERVER
#CFLAGS += -DALL_DH_GROUPS
CFLAGS += -DCONFIG_SHA256
#CFLAGS += -I ../crypto
#LDFLAGS += -L ../crypto
#LIBS += -lcrypto


libdnp3sec.a: dnp3_sec.o
	$(AR) crT $@ $?
dnp3test.out: dnp3_test.o dnp3_sec.o
	$(CC) -o $@ $? $(CFLAGS)
	
-include $(OBJS:%.o=%.d)
