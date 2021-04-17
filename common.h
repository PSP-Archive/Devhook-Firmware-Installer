#ifndef COMMON_H
#define COMMON_H

#include <pspdebug.h>
#include <pspsdk.h>
#include <pspkernel.h>
#include <pspctrl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define BGR(r,g,b) ((r) | ((g) << 8) | ((b) << 16))
#define BG      BGR(36,136,193)
#define TXT     BGR(255,255,255)
#define ERROR   BGR(255,0,0)
#define OK      BGR(73,255,103)

//PBP Header
typedef struct
{
    char header[4];
    char id[4];
    u32 off_sfo;
    u32 off_icon0;
    u32 off_icon1;
    u32 off_unknown;
    u32 off_pic1;
    u32 off_snd0;
    u32 psp;
    u32 psar;
}PBP_HEADER;

//PSF Header
typedef struct
{
    char magic[4];
    char id[4];
    u32 keytable;
    u32 valuetable;
    u32 pairs;
}PSF_HEADER;

//PSF Index Table
typedef struct
{
    u16 keytable;
    u8 unknown;
    u8 datatype;
    u32 size;
    u32 sizepadded;
    u32 valuetable;
}INDEX_TABLE;

//Get the PBP header
int getpbphdr(PBP_HEADER *);
//Validate update
int validatepbp(PBP_HEADER *);
//Get the update version and make sure it's supported
int getupdateversion(u32 );
//Get filesize
u32 filesize(char *);
//check if fw update is supported and guaranteed to work
int supportedfw();
//make devhook firmware path
void makedevpath();

void printright(int , char *src);
void setupdebugscreen();
void printerror(char *);
void printerrorxy(int ,int ,char *);
void printinstallheader();
void printok(char *);
#endif

