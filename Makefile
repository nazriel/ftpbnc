# f-ftpbnc v1.6 Makefile
# $Rev: 421 $ $Date: 2008-01-30 22:56:40 +0100 (Wed, 30 Jan 2008) $

INCCONF=
MODEL_FLAG=
ifneq (,$(MODEL))
    ifeq (32,$(MODEL))
        INCCONF=s
    endif
    MODEL_FLAG=-m$(MODEL)
endif

DFLAGS=-W -Wall -g $(MODEL_FLAG)
CFLAGS=$(DFLAGS)
LDFLAGS=
LIBS=

all: f-ftpbnc

new: clean f-ftpbnc

config:
	./mkconfig

clean:
	rm -f *.o f-ftpbnc mkconfig

sha256.o: sha256.c
	$(CC) $(CFLAGS) -c -o $@ $<

f-ftpbnc: f-ftpbnc.o sha256.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ f-ftpbnc.o sha256.o $(LIBS)

ifneq (,$(INCCONF))
f-ftpbnc.o: f-ftpbnc.c xtea-cipher.h inc-config.h
	$(CC) $(CFLAGS) -c -o $@ f-ftpbnc.c

mkconfig.o: mkconfig.c xtea-cipher.h
	$(CC) $(CFLAGS) -c -o $@ $<

mkconfig: mkconfig.o sha256.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ mkconfig.o sha256.o $(LIBS)

inc-config.h: mkconfig
	./mkconfig
endif
