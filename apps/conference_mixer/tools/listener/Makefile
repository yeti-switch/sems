CC=gcc
CFLAGS=-std=gnu11 -O2 -g -I. -Wall -lasound -lpulse-simple -lpulse
DEPS=
TARGET=
TARGET=listener

all: $(TARGET)

$(TARGET): $(TARGET).o
	$(CC) -o $(TARGET) $(TARGET).o $(CFLAGS)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)
