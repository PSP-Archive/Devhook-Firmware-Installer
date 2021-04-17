TARGET = dhfwinstaller
OBJS = main.o common.o

INCDIR = 
CFLAGS = -O2 -G0 -Wall
CXXFLAGS = $(CFLAGS) -fno-exceptions -fno-rtti
ASFLAGS = $(CFLAGS) -c

LIBDIR =
LDFLAGS = 
# -lpspglue -lpsplibc

EXTRA_TARGETS = EBOOT.PBP
PSP_EBOOT_TITLE = Devhook Firmware Installer
PSP_EBOOT_ICON = ICON0.PNG

PSPSDK=$(shell psp-config --pspsdk-path)
include $(PSPSDK)/lib/build.mak

