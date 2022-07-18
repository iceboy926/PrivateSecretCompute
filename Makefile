CC = /usr/bin/g++
CFLAGS = -O3 -Wall -Wextra -std=c++11 -fpic -pthread
CFLAGS += -fpermissive
CINCLUDE = -I./ \
			-I./network/ \
			-I./gm/bn/include/ \
			-I./de25519/ \
			-I./algrithm/include/ \
			-I./algrithm/aes/ \
			-I./algrithm/rand/include/ \
			-I./algrithm/sm2/ \
			-I./algrithm/sm3/ \
			-I./algrithm/sm4/ \
			-I./algrithm/src/ \


######################################################


USB_SUPPORT= -L ./lib -lusb-1.0 -ludev

# the obj dir
OBJDIR := obj
SRCDIR := .
SRCS := $(shell find $(SRCDIR) -name "*.c")
SRCPS := $(shell find $(SRCDIR) -name "*.cpp")
OBJS := $(SRCS:$(SRCDIR)/%.c=$(SRCDIR)/%.o)
OBJPS := $(SRCPS:$(SRCDIR)/%.cpp=$(SRCDIR)/%.o)


.PHONY: clean

main: $(OBJS) $(OBJPS)
	$(CC) -o main $(CFLAGS) $(CINCLUDE) ${OBJS} $(OBJPS)

.SECONDEXPANSION:
$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) $(CINCLUDE) -o $@ -c $<
$(SRCDIR)/%.o: $(SRCDIR)/%.cpp
	$(CC) $(CFLAGS) $(CINCLUDE) -o $@ -c $<

clean:
	rm ${OBJS} $(OBJPS)
	

