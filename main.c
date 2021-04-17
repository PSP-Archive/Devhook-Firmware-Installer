// PSAR dumper for Updater data - Version 3
// (c) 2005-2007 PspPet
// Devhook Firmware Installer v0.6 - 0.6h by Sleepy


// WORKING WITH:
//  1.00 - 3.30

#define DELETE_AT_START

#include <pspsdk.h>
#include <pspkernel.h>
#include <pspdebug.h>
#include <pspctrl.h>
#include <pspsuspend.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "common.h"     
#include "ireg.h"
#include "dreg.h"
#include "ireg2.h"
#include "dreg2.h"

extern char version[];
extern char fw[];
extern char devpath[];
extern char fwpath[];
extern char updpath[];
extern char path[];
extern char installpath[];

PSP_MODULE_INFO("dhfwinstaller", 0x1000, 1, 1);
PSP_MAIN_THREAD_ATTR(0);
//
#define printf    pspDebugScreenPrintf
typedef enum { false, true } bool;
////////////////////////////////////////////////////////////////////
// big buffers for data. Some system calls require 64 byte alignment

u8 g_dataPSAR[19000000] __attribute__((aligned(64)));
    // big enough for the full PSAR file

u8 g_dataOut[3000000] __attribute__((aligned(0x40)));
    // big enough for the largest (multiple uses)
//u8 g_dataOut2[3000000] __attribute__((aligned(0x40)));
u8 *g_dataOut2;
    // for deflate output

////////////////////////////////////////////////////////////////////
// File helpers

bool g_bWriteError = false;
bool SaveFile(const char* szFile, const void *addr, int len)
{
    int fd = sceIoOpen(szFile, PSP_O_CREAT | PSP_O_TRUNC | PSP_O_WRONLY, 0777);
    if (fd < 0)
        return false;
    bool ok = true;
    if (sceIoWrite(fd, addr, len) != len)
        ok = false;
    if (sceIoClose(fd) != 0)
        ok = false;
    if (!ok)
    {
        printf("Write error, stick may be full\n");
        g_bWriteError = true;
    }
    return ok;
}

int LoadPsarFile(const char* szFile)
{
    int fd = sceIoOpen(szFile, PSP_O_RDONLY, 0777);
    if (fd < 0)
        return -1;
    int cb = sceIoRead(fd, g_dataPSAR, sizeof(g_dataPSAR));
    sceIoClose(fd);
    return cb;
}

// simple logging (don't rely on FILE*)
static int my_openlogfile(const char* szFile)
{
    return sceIoOpen(szFile, PSP_O_CREAT | PSP_O_TRUNC | PSP_O_WRONLY, 0777);
}
static void my_print(int fd, const char* sz)
{
    sceIoWrite(fd, sz, strlen(sz));
}
static void my_close(int fd)
{
    sceIoClose(fd);
}


////////////////////////////////////////////////////////////////////
// Direct system calls used for PSAR decoding and PRX decryption

typedef int (*PROC_DECODE)(void* r4in, u32 r5in, int* r6Ret); // decodes in place
PROC_DECODE g_decodeProc6;
PROC_DECODE g_decodeProcE;

typedef int (*PROC_MANGLE)(void* r4, u32 r5, void* r6, u32 r7, u32 r8);
PROC_MANGLE g_mangleProc;
    // secret access to hardware decryption AKA "semaphore_2"
    // r8=opcode: 7=>block cypher/scramble (many uses),
        // 11=>SHA1, 1=>magic decode of real PRX code

typedef u32 (*PROC_DEFLATE)(void* destP, u32 cb, const void* scrP, u32* retP);
PROC_DEFLATE g_sceDeflateDecompress;
PROC_DEFLATE g_sceGzipDecompress;

/***static u32 FindProc(const char* szMod, const char* szLib, u32 nid)
{
    SceModule* modP = sceKernelFindModuleByName(szMod);
    if (modP == NULL)
    {
        printf("Failed to find mod '%s'\n", szMod);
        return 0;
    }
    SceLibraryEntryTable* entP = (SceLibraryEntryTable*)modP->ent_top;
    while ((u32)entP < ((u32)modP->ent_top + modP->ent_size))
    {
        if (entP->libname != NULL && strcmp(entP->libname, szLib) == 0)
        {
            // found lib
            int i;
            int count = entP->stubcount + entP->vstubcount;
            u32* nidtable = (u32*)entP->entrytable;
            for (i = 0; i < count; i++)
            {
                if (nidtable[i] == nid)
                {
                    u32 procAddr = nidtable[count+i];
                    // printf("entry found: '%s' '%s' = $%x\n", szMod, szLib, (int)procAddr);
                    return procAddr;
                }
            }
            printf("Found mod '%s' and lib '%s' but not nid=$%x\n", szMod, szLib, nid);
            return 0;
        }
        entP++;
    }
    printf("Found mod '%s' but not lib '%s'\n", szMod, szLib);
    return 0;
}***/

/* New FindProc based on tyranid's psplink code. PspPet one doesn't work
   well with 2.7X+ sysmem.prx */
u32 FindProc(const char* szMod, const char* szLib, u32 nid)
{
	struct SceLibraryEntryTable *entry;
	SceModule *pMod;
	void *entTab;
	int entLen;

	pMod = sceKernelFindModuleByName(szMod);

	if (!pMod)
	{
		printf("Cannot find module %s\n", szMod);
		return 0;
	}
	
	int i = 0;

	entTab = pMod->ent_top;
	entLen = pMod->ent_size;
	//***printf("entTab %p - entLen %d\n", entTab, entLen);
	while(i < entLen)
    {
		int count;
		int total;
		unsigned int *vars;

		entry = (struct SceLibraryEntryTable *) (entTab + i);

        if(entry->libname && !strcmp(entry->libname, szLib))
		{
			total = entry->stubcount + entry->vstubcount;
			vars = entry->entrytable;

			if(entry->stubcount > 0)
			{
				for(count = 0; count < entry->stubcount; count++)
				{
					if (vars[count] == nid)
						return vars[count+total];					
				}
			}
		}

		i += (entry->len * 4);
	}

	printf("Funtion not found.\n");
	return 0;
}

bool InitSysEntries()
{
    // dynamic/explicit lookup
    g_decodeProc6 = (PROC_DECODE)FindProc("sceMesgLed", "sceNwman_driver", 0x9555d68d);
    g_decodeProcE = (PROC_DECODE)FindProc("sceMesgLed", "sceMesgd_driver", 0x102dc8af);
    g_mangleProc = (PROC_MANGLE)FindProc("sceMemlmd", "semaphore", 0x4c537c72);
    g_sceDeflateDecompress = (PROC_DEFLATE)FindProc("sceKernelUtils", "UtilsForKernel", 0xe8db3ce6);
    g_sceGzipDecompress = (PROC_DEFLATE)FindProc("sceKernelUtils", "UtilsForKernel", 0x78934841);

    return (g_decodeProc6 != NULL &&
      g_decodeProcE != NULL &&
      g_mangleProc != NULL &&
      g_sceDeflateDecompress != NULL &&
      g_sceGzipDecompress != NULL);
}

////////////////////////////////////////////////////////////////////
// Hardware direct Decoding of ~PSP/PRX files (side-step the PSP firmware)

#ifdef SPECIAL_KEYS
#include "keys.c_"
#else
// use pre-calculated keys (step1 results)

static unsigned long const g_key0[] =
{
  0x7b21f3be, 0x299c5e1d, 0x1c9c5e71, 0x96cb4645, 0x3c9b1be0, 0xeb85de3d,
  0x4a7f2022, 0xc2206eaa, 0xd50b3265, 0x55770567, 0x3c080840, 0x981d55f2,
  0x5fd8f6f3, 0xee8eb0c5, 0x944d8152, 0xf8278651, 0x2705bafa, 0x8420e533,
  0x27154ae9, 0x4819aa32, 0x59a3aa40, 0x2cb3cf65, 0xf274466d, 0x3a655605,
  0x21b0f88f, 0xc5b18d26, 0x64c19051, 0xd669c94e, 0xe87035f2, 0x9d3a5909,
  0x6f4e7102, 0xdca946ce, 0x8416881b, 0xbab097a5, 0x249125c6, 0xb34c0872,
};
static unsigned long const g_key2[] =
{
  0xccfda932, 0x51c06f76, 0x046dcccf, 0x49e1821e, 0x7d3b024c, 0x9dda5865,
  0xcc8c9825, 0xd1e97db5, 0x6874d8cb, 0x3471c987, 0x72edb3fc, 0x81c8365d,
  0xe161e33a, 0xfc92db59, 0x2009b1ec, 0xb1a94ce4, 0x2f03696b, 0x87e236d8,
  0x3b2b8ce9, 0x0305e784, 0xf9710883, 0xb039db39, 0x893bea37, 0xe74d6805,
  0x2a5c38bd, 0xb08dc813, 0x15b32375, 0x46be4525, 0x0103fd90, 0xa90e87a2,
  0x52aba66a, 0x85bf7b80, 0x45e8ce63, 0x4dd716d3, 0xf5e30d2d, 0xaf3ae456,
};
static unsigned long const g_key3[] =
{
  0xa6c8f5ca, 0x6d67c080, 0x924f4d3a, 0x047ca06a, 0x08640297, 0x4fd4a758,
  0xbd685a87, 0x9b2701c2, 0x83b62a35, 0x726b533c, 0xe522fa0c, 0xc24b06b4,
  0x459d1cac, 0xa8c5417b, 0x4fea62a2, 0x0615d742, 0x30628d09, 0xc44fab14,
  0x69ff715e, 0xd2d8837d, 0xbeed0b8b, 0x1e6e57ae, 0x61e8c402, 0xbe367a06,
  0x543f2b5e, 0xdb3ec058, 0xbe852075, 0x1e7e4dcc, 0x1564ea55, 0xec7825b4,
  0xc0538cad, 0x70f72c7f, 0x49e8c3d0, 0xeda97ec5, 0xf492b0a4, 0xe05eb02a,
};
static unsigned long const g_key44[] =
{
  0xef80e005, 0x3a54689f, 0x43c99ccd, 0x1b7727be, 0x5cb80038, 0xdd2efe62,
  0xf369f92c, 0x160f94c5, 0x29560019, 0xbf3c10c5, 0xf2ce5566, 0xcea2c626,
  0xb601816f, 0x64e7481e, 0x0c34debd, 0x98f29cb0, 0x3fc504d7, 0xc8fb39f0,
  0x0221b3d8, 0x63f936a2, 0x9a3a4800, 0x6ecc32e3, 0x8e120cfd, 0xb0361623,
  0xaee1e689, 0x745502eb, 0xe4a6c61c, 0x74f23eb4, 0xd7fa5813, 0xb01916eb,
  0x12328457, 0xd2bc97d2, 0x646425d8, 0x328380a5, 0x43da8ab1, 0x4b122ac9,
};
static unsigned long const g_key20[] =
{
  0x33b50800, 0xf32f5fcd, 0x3c14881f, 0x6e8a2a95, 0x29feefd5, 0x1394eae3,
  0xbd6bd443, 0x0821c083, 0xfab379d3, 0xe613e165, 0xf5a754d3, 0x108b2952,
  0x0a4b1e15, 0x61eadeba, 0x557565df, 0x3b465301, 0xae54ecc3, 0x61423309,
  0x70c9ff19, 0x5b0ae5ec, 0x989df126, 0x9d987a5f, 0x55bc750e, 0xc66eba27,
  0x2de988e8, 0xf76600da, 0x0382dccb, 0x5569f5f2, 0x8e431262, 0x288fe3d3,
  0x656f2187, 0x37d12e9c, 0x2f539eb4, 0xa492998e, 0xed3958f7, 0x39e96523,
};
static unsigned long const g_key3A[] =
{
  0x67877069, 0x3abd5617, 0xc23ab1dc, 0xab57507d, 0x066a7f40, 0x24def9b9,
  0x06f759e4, 0xdcf524b1, 0x13793e5e, 0x0359022d, 0xaae7e1a2, 0x76b9b2fa,
  0x9a160340, 0x87822fba, 0x19e28fbb, 0x9e338a02, 0xd8007e9a, 0xea317af1,
  0x630671de, 0x0b67ca7c, 0x865192af, 0xea3c3526, 0x2b448c8e, 0x8b599254,
  0x4602e9cb, 0x4de16cda, 0xe164d5bb, 0x07ecd88e, 0x99ffe5f8, 0x768800c1,
  0x53b091ed, 0x84047434, 0xb426dbbc, 0x36f948bb, 0x46142158, 0x749bb492,
};
#endif

typedef struct
{
    u32 tag; // 4 byte value at offset 0xD0 in the PRX file
    u8* key; // "step1_result" use for XOR step
    u8 code;
    u8 codeExtra;
} TAG_INFO;

static const TAG_INFO g_tagInfo[] =
{
    // 1.x PRXs
    { 0x00000000, (u8*)g_key0, 0x42 },
    { 0x02000000, (u8*)g_key2, 0x45 },
    { 0x03000000, (u8*)g_key3, 0x46 },
#ifdef LATER
    // add keys 6 and 14 - for PSAR data
        // then we can replace "g_decodeProc6/ProcE" with our own version
#endif
    // 2.0 PRXs
    { 0x4467415d, (u8*)g_key44, 0x59, 0x59 },
    { 0x207bbf2f, (u8*)g_key20, 0x5A, 0x5A },
    { 0x3ace4dce, (u8*)g_key3A, 0x5B, 0x5B },
};

#ifdef SPECIAL_KEYS
#include "initkeys.c_"
#endif


static TAG_INFO const* GetTagInfo(u32 tagFind)
{
    int iTag;
    for (iTag = 0; iTag < sizeof(g_tagInfo)/sizeof(TAG_INFO); iTag++)
        if (g_tagInfo[iTag].tag == tagFind)
            return &g_tagInfo[iTag];
    return NULL; // not found
}


static void ExtraV2Mangle(u8* buffer1, u8 codeExtra)
{
    static u8 g_dataTmp[20+0xA0] __attribute__((aligned(0x40)));
    u8* buffer2 = g_dataTmp; // aligned

    memcpy(buffer2+20, buffer1, 0xA0);
    u32* pl2 = (u32*)buffer2;
    pl2[0] = 5;
    pl2[1] = pl2[2] = 0;
    pl2[3] = codeExtra;
    pl2[4] = 0xA0;

    int ret = (*g_mangleProc)(buffer2, 20+0xA0, buffer2, 20+0xA0, 7);
    if (ret != 0)
        printf("extra de-mangle returns %d\n", ret);
    // copy result back
    memcpy(buffer1, buffer2, 0xA0);
}

static int MyDecryptPRX(const u8* pbIn, u8* pbOut, int cbTotal, u32 tag)
{
    TAG_INFO const* pti = GetTagInfo(tag);
    if (pti == NULL)
        return -1;

    // build conversion into pbOut
    memcpy(pbOut, pbIn, cbTotal);
    memset(pbOut, 0, 0x150);
    memset(pbOut, 0x55, 0x40); // first $40 bytes ignored

    // step3 demangle in place
    u32* pl = (u32*)(pbOut+0x2C);
    pl[0] = 5; // number of ulongs in the header
    pl[1] = pl[2] = 0;
    pl[3] = pti->code; // initial seed for PRX
    pl[4] = 0x70;   // size

    // redo part of the SIG check (step2)
    u8 buffer1[0x150];
    memcpy(buffer1+0x00, pbIn+0xD0, 0x80);
    memcpy(buffer1+0x80, pbIn+0x80, 0x50);
    memcpy(buffer1+0xD0, pbIn+0x00, 0x80);
    if (pti->codeExtra != 0)
        ExtraV2Mangle(buffer1+0x10, pti->codeExtra);
    memcpy(pbOut+0x40 /* 0x2C+20 */, buffer1+0x40, 0x40);

    int ret;
    int iXOR;
    for (iXOR = 0; iXOR < 0x70; iXOR++)
        pbOut[0x40+iXOR] = pbOut[0x40+iXOR] ^ pti->key[0x14+iXOR];

    ret = (*g_mangleProc)(pbOut+0x2C, 20+0x70, pbOut+0x2C, 20+0x70, 7);
    if (ret != 0)
    {
        printf("mangle#7 returned $%x\n", ret);
        return -1;
    }

    for (iXOR = 0x6F; iXOR >= 0; iXOR--)
        pbOut[0x40+iXOR] = pbOut[0x2C+iXOR] ^ pti->key[0x20+iXOR];

    memset(pbOut+0x80, 0, 0x30); // $40 bytes kept, clean up
    pbOut[0xA0] = 1;
    // copy unscrambled parts from header
    memcpy(pbOut+0xB0, pbIn+0xB0, 0x20); // file size + lots of zeros
    memcpy(pbOut+0xD0, pbIn+0x00, 0x80); // ~PSP header

    // step4: do the actual decryption of code block
    //  point 0x40 bytes into the buffer to key info
    ret = (*g_mangleProc)(pbOut, cbTotal, pbOut+0x40, cbTotal-0x40, 0x1);
    if (ret != 0)
    {
        printf("mangle#1 returned $%x\n", ret);
        return -1;
    }

    // return cbTotal - 0x150; // rounded up size
	return *(u32*)&pbIn[0xB0]; // size of actual data (fix thanks to Vampire)
}

/***2.60-2.80 PRX Decryption routines and sigcheck generation (Dark_AleX) ***/

/* kernel modules 2.80 */
u8 keys280_0[0x10] =
{
	0xCA, 0xFB, 0xBF, 0xC7, 0x50, 0xEA, 0xB4, 0x40,
	0x8E, 0x44, 0x5C, 0x63, 0x53, 0xCE, 0x80, 0xB1
};

/* user modules 2.80 */
u8 keys280_1[0x10] =
{
	0x40, 0x9B, 0xC6, 0x9B, 0xA9, 0xFB, 0x84, 0x7F,
	0x72, 0x21, 0xD2, 0x36, 0x96, 0x55, 0x09, 0x74
};

/* vshmain executable 2.80 */
u8 keys280_2[0x10] =
{
	0x03, 0xA7, 0xCC, 0x4A, 0x5B, 0x91, 0xC2, 0x07,
	0xFF, 0xFC, 0x26, 0x25, 0x1E, 0x42, 0x4B, 0xB5
};

/* kernel modules 2.60-2.71 */
u8 keys260_0[0x10] =
{
	0xC3, 0x24, 0x89, 0xD3, 0x80, 0x87, 0xB2, 0x4E,
	0x4C, 0xD7, 0x49, 0xE4, 0x9D, 0x1D, 0x34, 0xD1

};

/* user modules 2.60-2.71 */
u8 keys260_1[0x10] =
{
	0xF3, 0xAC, 0x6E, 0x7C, 0x04, 0x0A, 0x23, 0xE7,
	0x0D, 0x33, 0xD8, 0x24, 0x73, 0x39, 0x2B, 0x4A
};

/* vshmain 2.60-2.71 */
u8 keys260_2[0x10] =
{
	0x72, 0xB4, 0x39, 0xFF, 0x34, 0x9B, 0xAE, 0x82,
	0x30, 0x34, 0x4A, 0x1D, 0xA2, 0xD8, 0xB4, 0x3C
};

/* kernel modules 3.00 */
u8 keys300_0[0x10] =
{
	0x9F, 0x67, 0x1A, 0x7A, 0x22, 0xF3, 0x59, 0x0B,
    0xAA, 0x6D, 0xA4, 0xC6, 0x8B, 0xD0, 0x03, 0x77

};

/* user modules 3.00 */
u8 keys300_1[0x10] =
{
	0x15, 0x07, 0x63, 0x26, 0xDB, 0xE2, 0x69, 0x34,
    0x56, 0x08, 0x2A, 0x93, 0x4E, 0x4B, 0x8A, 0xB2

};

/* vshmain 3.00 */
u8 keys300_2[0x10] =
{
	0x56, 0x3B, 0x69, 0xF7, 0x29, 0x88, 0x2F, 0x4C,
    0xDB, 0xD5, 0xDE, 0x80, 0xC6, 0x5C, 0xC8, 0x73

};

/* kernel modules 3.00 */
u8 keys303_0[0x10] =
{
	0x7b, 0xa1, 0xe2, 0x5a, 0x91, 0xb9, 0xd3, 0x13,
	0x77, 0x65, 0x4a, 0xb7, 0xc2, 0x8a, 0x10, 0xaf
};

/* kernel modules 3.10 */
u8 keys310_0[0x10] =
{
	0xa2, 0x41, 0xe8, 0x39, 0x66, 0x5b, 0xfa, 0xbb,
	0x1b, 0x2d, 0x6e, 0x0e, 0x33, 0xe5, 0xd7, 0x3f
};

/* user modules 3.10 */
u8 keys310_1[0x10] =
{
	0xA4, 0x60, 0x8F, 0xAB, 0xAB, 0xDE, 0xA5, 0x65,
	0x5D, 0x43, 0x3A, 0xD1, 0x5E, 0xC3, 0xFF, 0xEA
};

/* vshmain 3.10 */
u8 keys310_2[0x10] =
{
	0xE7, 0x5C, 0x85, 0x7A, 0x59, 0xB4, 0xE3, 0x1D,
	0xD0, 0x9E, 0xCE, 0xC2, 0xD6, 0xD4, 0xBD, 0x2B
};

/* reboot.bin 3.10 */
u8 keys310_3[0x10] =
{
    0x2E, 0x00, 0xF6, 0xF7, 0x52, 0xCF, 0x95, 0x5A,
    0xA1, 0x26, 0xB4, 0x84, 0x9B, 0x58, 0x76, 0x2F
};

/* kernel modules 3.30 */ 
u8 keys330_0[0x10] = 
{ 
	0x3B, 0x9B, 0x1A, 0x56, 0x21, 0x80, 0x14, 0xED,
	0x8E, 0x8B, 0x08, 0x42, 0xFA, 0x2C, 0xDC, 0x3A
};

/* user modules 3.30 */ 
u8 keys330_1[0x10] = 
{ 
    0xE8, 0xBE, 0x2F, 0x06, 0xB1, 0x05, 0x2A, 0xB9, 
    0x18, 0x18, 0x03, 0xE3, 0xEB, 0x64, 0x7D, 0x26 
}; 

/* vshmain 3.30 */ 
u8 keys330_2[0x10] = 
{ 
    0xAB, 0x82, 0x25, 0xD7, 0x43, 0x6F, 0x6C, 0xC1, 
    0x95, 0xC5, 0xF7, 0xF0, 0x63, 0x73, 0x3F, 0xE7 
}; 

/* reboot.bin 3.30 */ 
u8 keys330_3[0x10] = 
{ 
    0xA8, 0xB1, 0x47, 0x77, 0xDC, 0x49, 0x6A, 0x6F, 
    0x38, 0x4C, 0x4D, 0x96, 0xBD, 0x49, 0xEC, 0x9B 
}; 

/* stdio.prx 3.30 */
u8 keys330_4[0x10] =
{
	0xEC, 0x3B, 0xD2, 0xC0, 0xFA, 0xC1, 0xEE, 0xB9,
	0x9A, 0xBC, 0xFF, 0xA3, 0x89, 0xF2, 0x60, 0x1F
};

typedef struct
{
    u32 tag; // 4 byte value at offset 0xD0 in the PRX file
    u8  *key; // 16 bytes keys
    u8 code; // code for scramble
} TAG_INFO2;

static TAG_INFO2 g_tagInfo2[] =
{
	{ 0x4C940BF0, keys330_0, 0x43 }, 
	{ 0x457B0AF0, keys330_1, 0x5B }, 
	{ 0x38020AF0, keys330_2, 0x5A }, 
	{ 0x4C940AF0, keys330_3, 0x62 }, 
	{ 0x4C940CF0, keys330_4, 0x43 }, 

	{ 0xcfef09f0, keys310_0, 0x62 },
	{ 0x457b08f0, keys310_1, 0x5B },
	{ 0x380208F0, keys310_2, 0x5A },
	{ 0xcfef08f0, keys310_3, 0x62 },

	{ 0xCFEF07F0, keys303_0, 0x62 },
	{ 0xCFEF06F0, keys300_0, 0x62 },
	{ 0x457B06F0, keys300_1, 0x5B },
	{ 0x380206F0, keys300_2, 0x5A },
	{ 0xCFEF05F0, keys280_0, 0x62 },
	{ 0x457B05F0, keys280_1, 0x5B },
	{ 0x380205F0, keys280_2, 0x5A },
	{ 0x16D59E03, keys260_0, 0x62 },
	{ 0x76202403, keys260_1, 0x5B },
	{ 0x0F037303, keys260_2, 0x5A }
};


static TAG_INFO2 *GetTagInfo2(u32 tagFind)
{
    int iTag;

    for (iTag = 0; iTag < sizeof(g_tagInfo2) / sizeof(TAG_INFO2); iTag++)
	{
        if (g_tagInfo2[iTag].tag == tagFind)
		{
            return &g_tagInfo2[iTag];
		}
	}

	return NULL; // not found
}

int Scramble(u32 *buf, u32 size, u32 code)
{
	buf[0] = 5;
	buf[1] = buf[2] = 0;
	buf[3] = code;
	buf[4] = size;

	if (g_mangleProc(buf, size+0x14, buf, size+0x14, 7) < 0)
	{
		return -1;
	}

	return 0;
}

int DecryptPRX2(u8 *inbuf, u8 *outbuf, u32 size, u32 tag)
{
	TAG_INFO2 const* pti = GetTagInfo2(tag);

	if (!pti)
	{
		printf("--Unknown-2.80-tag %08X.\n",tag);
		for(;;)
			sceDisplayWaitVblankStart();
		return -1;
	}

	int retsize = *(int *)&inbuf[0xB0];
	u8	tmp1[0x150], tmp2[0x90+0x14], tmp3[0x60+0x14];

	memset(tmp1, 0, 0x150);
	memset(tmp2, 0, 0x90+0x14);
	memset(tmp3, 0, 0x60+0x14);

	memcpy(outbuf, inbuf, size);

	if (*((u32 *)outbuf) != 0x5053507E) // "~PSP"
	{
		printf("Error: unknown signature.\n");
		return -1;
	}

	if (size < 0x160)
	{
		printf("Buffer not big enough.\n");
		return -1;
	}

	if (((u32)outbuf & 0x3F))
	{
		printf("Buffer not aligned to 64 bytes.\n");
		return -1;
	}

	if ((size - 0x150) < retsize)
	{
		printf("No enough data.\n");
		return -1;
	}

	memcpy(tmp1, outbuf, 0x150);

	int i, j;
	u8 *p = tmp2+0x14;

	for (i = 0; i < 9; i++)
	{
		for (j = 0; j < 0x10; j++)
		{
			p[(i << 4) + j] = pti->key[j]; 			
		}

		p[(i << 4)] = i;
	}	

	if (Scramble((u32 *)tmp2, 0x90, pti->code) < 0)
	{
		printf("Error in Scramble #1.\n");
		return -1;
	}

	memcpy(outbuf, tmp1+0xD0, 0x5C);
	memcpy(outbuf+0x5C, tmp1+0x140, 0x10);
	memcpy(outbuf+0x6C, tmp1+0x12C, 0x14);
	memcpy(outbuf+0x80, tmp1+0x080, 0x30);
	memcpy(outbuf+0xB0, tmp1+0x0C0, 0x10);
	memcpy(outbuf+0xC0, tmp1+0x0B0, 0x10);
	memcpy(outbuf+0xD0, tmp1+0x000, 0x80);

	memcpy(tmp3+0x14, outbuf+0x5C, 0x60);	

	if (Scramble((u32 *)tmp3, 0x60, pti->code) < 0)
	{
		printf("Error in Scramble #2.\n");
		return -1;
	}

	memcpy(outbuf+0x5C, tmp3, 0x60);
	memcpy(tmp3, outbuf+0x6C, 0x14);
	memcpy(outbuf+0x70, outbuf+0x5C, 0x10);
	memset(outbuf+0x18, 0, 0x58);
	memcpy(outbuf+0x04, outbuf, 0x04);

	*((u32 *)outbuf) = 0x014C;
	memcpy(outbuf+0x08, tmp2, 0x10);	

	/* sha-1 */
	if (g_mangleProc(outbuf, 3000000, outbuf, 3000000, 0x0B) < 0)
	{
		printf("Error in semaphore2  #1.\n");
		return -1;
	}	

	if (memcmp(outbuf, tmp3, 0x14) != 0)
	{
		printf("SHA-1 is incorrect.\n");
        sceKernelExitGame();
//		return -1;
	}

	int iXOR;

	for (iXOR = 0; iXOR < 0x40; iXOR++)
	{
		tmp3[iXOR+0x14] = outbuf[iXOR+0x80] ^ tmp2[iXOR+0x10];
	}

	if (Scramble((u32 *)tmp3, 0x40, pti->code) != 0)
	{
		printf("Error in Scramble #2.\n");
		return -1;
	}
	
	for (iXOR = 0x3F; iXOR >= 0; iXOR--)
	{
		outbuf[iXOR+0x40] = tmp3[iXOR] ^ tmp2[iXOR+0x50]; // uns 8
	}

	memset(outbuf+0x80, 0, 0x30);
	*(u32 *)&outbuf[0xA0] = 1;

	memcpy(outbuf+0xB0, outbuf+0xC0, 0x10);
	memset(outbuf+0xC0, 0, 0x10);

	// The real decryption
	if (g_mangleProc(outbuf, size, outbuf+0x40, size-0x40, 0x1) < 0)
	{
		printf("Error in semaphore2  #2.\n");
		return -1;
	}

	if (retsize < 0x150)
	{
		// Fill with 0
		memset(outbuf+retsize, 0, 0x150-retsize);		
	}

	return retsize;

}

/* Generation of sig check area: it has only be tested with 2.71-2.80 files */
/* Maybe previous firmwares updates use different keys */

u8 check_keys0[0x10] =
{
	0x71, 0xF6, 0xA8, 0x31, 0x1E, 0xE0, 0xFF, 0x1E,
	0x50, 0xBA, 0x6C, 0xD2, 0x98, 0x2D, 0xD6, 0x2D
};

u8 check_keys1[0x10] =
{
	0xAA, 0x85, 0x4D, 0xB0, 0xFF, 0xCA, 0x47, 0xEB,
	0x38, 0x7F, 0xD7, 0xE4, 0x3D, 0x62, 0xB0, 0x10
};

int Encrypt(u32 *buf, int size)
{
	buf[0] = 4;
	buf[1] = buf[2] = 0;
	buf[3] = 0x100;
	buf[4] = size;

	/* Note: this encryption returns different data in each psp,
	   But it always returns the same in a specific psp (even if it has two nands) */
	if (g_mangleProc(buf, size+0x14, buf, size+0x14, 5) < 0)
		return -1;

	return 0;
}

int GenerateSigCheck(u8 *buf)
{
	u8 enc[0xD0+0x14];
	int iXOR, res;

	memcpy(enc+0x14, buf+0x110, 0x40);
	memcpy(enc+0x14+0x40, buf+0x80, 0x90);
	
	for (iXOR = 0; iXOR < 0xD0; iXOR++)
	{
		enc[0x14+iXOR] ^= check_keys0[iXOR&0xF];
	}

	if ((res = Encrypt((u32 *)enc, 0xD0)) < 0)
	{
		printf("Encrypt failed.\n");
		return res;
	}

	for (iXOR = 0; iXOR < 0xD0; iXOR++)
	{
		enc[0x14+iXOR] ^= check_keys1[iXOR&0xF];
	}

	memcpy(buf+0x80, enc+0x14, 0xD0);
	return 0;
}

/*** End of 2.60-2.80 PRX Decryption and sigcheck ***/

////////////////////////////////////////////////////////////////////
// IPL decode logic - thanks to 'nem'
//  for more details see "http://forums.ps2dev.org/viewtopic.php?t=3573"
// part1_/part2_ and part3_ prefix different steps of decryption process

static int DecryptIPL1(const u8* pbIn, u8* pbOut, int cbIn)
{
    // 0x1000 pages
    static u8 g_dataTmp[0x1040] __attribute__((aligned(0x40)));
    int cbOut = 0;
    while (cbIn >= 0x1000)
    {
	    memcpy(g_dataTmp+0x40, pbIn, 0x1000);
        pbIn += 0x1000;
        cbIn -= 0x1000;

        int ret = (*g_mangleProc)(g_dataTmp, 0x1040, g_dataTmp+0x40, 0x500, 1);
	    if (ret != 0)
        {
	        printf("mangle#1 returned $%x\n", ret);
            break; // stop, save what we can
        }
        memcpy(pbOut, g_dataTmp, 0x1000);
        pbOut += 0x1000;
        cbOut += 0x1000;
    }
    return cbOut;
}

static int LinearizeIPL2(const u8* pbIn, u8* pbOut, int cbIn)
{
    u32 nextAddr = 0;
    int cbOut = 0;
    while (cbIn > 0)
    {
        u32* pl = (u32*)pbIn;
        u32 addr = pl[0];
        if (addr != nextAddr && nextAddr != 0)
            return 0;   // error
        u32 count = pl[1];
        nextAddr = addr + count;
        memcpy(pbOut, pbIn+0x10, count);
        pbOut += count;
        cbOut += count;
        pbIn += 0x1000;
        cbIn -= 0x1000;
    }
    return cbOut;
}

static int DecryptIPL3(const u8* pbIn, u8* pbOut, int cbIn)
{
    // all together now (pbIn/pbOut must be aligned)
    pbIn += 0x10000;
    cbIn -= 0x10000;
	memcpy(pbOut+0x40, pbIn, cbIn);
	int ret = (*g_mangleProc)(pbOut, cbIn+0x40, pbOut+0x40, cbIn, 1);
	if (ret != 0)
    {
		printf("mangle#1 returned $%x\n", ret);
        return 0;
    }
    return *(u32*)&pbIn[0x70]; // true size
}

////////////////////////////////////////////////////////////////////
// Decode encrypted data blocks, minimal support for PSAR files
// keys #6 (old) or #14 (new)

#define OVERHEAD    0x150 /* size of encryption block overhead */
#define SIZE_A      0x110 /* size of uncompressed file entry = 272 bytes */

static int g_bOldSchool = 0; // true=> 1.00 "Bogus" update

// for 1.50 and later, they mangled the plaintext parts of the header
static void Demangle(const u8* pIn, u8* pOut)
{
    u8 buffer[20+0x130];
    memcpy(buffer+20, pIn, 0x130);
    u32* pl = (u32*)buffer; // first 20 bytes
    pl[0] = 5;
    pl[1] = pl[2] = 0;
    pl[3] = 0x55;
    pl[4] = 0x130;

    (*g_mangleProc)(buffer, 20+0x130, buffer, 20+0x130, 7);
    memcpy(pOut, buffer, 0x130);
}

int DecodeBlock(const u8* pIn, int cbIn, u8* pOut)
{
    // pOut also used as temporary buffer for mangled input
    // assert((((u32)pOut) & 0x3F) == 0); // must be aligned

    memcpy(pOut, pIn, cbIn + 0x10); // copy a little more for $10 page alignment

    int ret;
    int cbOut;
    if (g_bOldSchool)
    {
        // old style - unscrambled PSAR (1.00 "BOGUS" update)
        if (*(u32*)&pOut[0xd0] != 0x06000000)
        {
            printf("Oldschool 6 failed\n");
            return -1;
        }
        ret = (*g_decodeProc6)(pOut, cbIn, &cbOut);
        if (ret != 0)
            printf("Sys_Decode6 returned $%x %d\n", ret, cbOut);
    }
    else
    {
        // new style - scrambled PSAR (works with 1.5x and 2.00)
        Demangle(pIn+0x20, pOut+0x20); // demangle the inside $130 bytes
        if (*(u32*)&pOut[0xd0] != 0x0E000000)
        {
            printf("Demangle failed\n");
            printf(" PSAR format not supported\n");
            // SaveFile("ms0:/err1.bin", pIn, cbIn);
            // SaveFile("ms0:/err2.bin", pOut, cbIn);
            return -1;
        }
        ret = (*g_decodeProcE)(pOut, cbIn, &cbOut);
        if (ret != 0)
            printf("Sys_DecodeE returned $%x %d\n", ret, cbOut);
    }
    if (ret != 0)
        return -1; // error
    return cbOut;
}

////////////////////////////////////////////////////////////////////
// reporting

static void PrintHeader(int pf)
{
    my_print(pf, "Extraction report\n");
    my_print(pf, "From PSAR Dump .03\n");
    my_print(pf, " a PspPet utility\n");
    my_print(pf, " [Devhook Firmware Installer v0.6h by Sleepy]\n");
    my_print(pf, "-------------\n");
    my_print(pf, "LEGAL NOTICE:\n");
    my_print(pf, " the files extracted are Sony copyrighted material\n");
    my_print(pf, " do not post them on the web or share them\n");
    my_print(pf, " for legal DMCA compatible \"fair use\" uses only\n");
    my_print(pf, "-------------\n");
    my_print(pf, "\n");
}

/*** reboot.bin extract (Dark_AleX) ***/

int ReadFile(const char* file, u32 offset, void *buf, u32 size)
{
	SceUID fd = sceIoOpen(file, PSP_O_RDONLY, 0777);
	int read;

	if (fd < 0)
		return fd;

	if (offset != 0)
	{
		sceIoLseek32(fd, 0, PSP_SEEK_SET);
	}

	read = sceIoRead(fd, buf, size);
	sceIoClose(fd);

	return read;
}



/* "RLZ" decompress */
u32 (* UtilsForKernel_7DD07271) (void* destP, u32 cb, const void* scrP, u32* retP);
void ExtractReboot(char *loadexec, char *sysmem)
{
	int size = ReadFile(loadexec, 0, g_dataOut, 3000000);

	if (size > 0)
	{
		int i;

		for (i = 0; i < size-0xD0; i++)
		{
			if (memcmp(g_dataOut+i, "~PSP", 4) == 0)
			{
				int pspsize, decsize, savesize;
				u32 tag;
				u8  *psave;
				
				pspsize = *(u32 *)&g_dataOut[i+0x2C];
				tag = *(u32 *)&g_dataOut[i+0xD0];
				decsize = MyDecryptPRX(g_dataOut+i, g_dataOut2, pspsize, tag);
				
				if (decsize <= 0)
				{
					decsize = DecryptPRX2(g_dataOut+i, g_dataOut2, pspsize, tag);
				}				

				if (decsize > 0)
				{
					psave = g_dataOut2;
					savesize = decsize;

					if (g_dataOut2[0] == 0x1F && g_dataOut2[1] == 0x8B)
					{
						// Gzip
						decsize = g_sceGzipDecompress(g_dataOut, sizeof(g_dataOut2), g_dataOut2, NULL);

						if (decsize > 0)
						{
							psave = g_dataOut;
							savesize = decsize;
						}
					}

					else if (memcmp(g_dataOut2, "2RLZ", 4) == 0)
					{
						// Temporal solution before i reverse that decompress function
						SceUID mod;

						size = ReadFile(sysmem, 0, g_dataOut, 3000000);

						if (size > 0)
						{
							for (i = 0; i < size-0x100; i++)
							{
								if (memcmp(g_dataOut+i, "sceSystemMemoryManager", 22) == 0)
								{
									memcpy(g_dataOut+i, "dax", 3);

									pspSdkInstallNoPlainModuleCheckPatch();
									mod = sceKernelLoadModuleBuffer((u32)g_dataOut, (void *)size, 0, NULL);

									if (mod < 0)
									{
										printf("Cannot load sysmem.prx.\n");
										return;
									}

									UtilsForKernel_7DD07271 = (void *)FindProc("daxSystemMemoryManager", "UtilsForKernel", 0x7DD07271);

									if (!UtilsForKernel_7DD07271)
										return;

									printf("RLZ decompressing...\n");

									decsize = UtilsForKernel_7DD07271(g_dataOut, sizeof(g_dataOut), g_dataOut2+4, NULL);
									if (decsize > 0)
									{
										psave = g_dataOut;
										savesize = decsize;
									}
									else
									{
										printf("RLZ decompression failed.\n");
									}
                                    sceKernelUnloadModule(mod);
									break;
								}
							}
						}
					}					

					SaveFile("ms0:/F0/reboot.bin", psave, savesize);
					
				}

				else
				{
					printf("Cannot decrypt reboot.bin.\n");
				}

				break;
			}
		}
	}

	else
	{
		printf("Error reading loadexec.\n");
	}
}

/*** end of reboot.bin extract ***/

////////////////////////////////////////////////////////////////////

enum
{
	MODE_ENCRYPT_SIGCHECK,
	MODE_ENCRYPT,
	MODE_DECRYPT,
};

//Extracts data.psar from update eboot
int getpsar(PBP_HEADER *tmp)
{

  u32 filesize=0;
  SceUID in;
  in = sceIoOpen(updpath, PSP_O_RDONLY, 0777);
  printf("Extracting PSAR....!\n");
  filesize = sceIoLseek(in, 0, SEEK_END);
  sceIoLseek(in, tmp->psar, SEEK_SET);
  sceIoRead(in, g_dataPSAR, filesize-tmp->psar);
  printf("Done!\n");
  sceIoClose(in);
  return (filesize-tmp->psar);
}

int main(void)
{
    int mode=0;
	PBP_HEADER foo;
	char path[128];  //path to devhook+fw dir
	char buffer[128];  //path to the various files

    if (!InitSysEntries())
    {
        printf("ERROR: system doesn't jive\n");
        return -1;
    }


  setupdebugscreen();
  printinstallheader();
  if(!getpbpheader(&foo))
  {
    //Error
    printerror("Can't find update eboot !");
    printerror("auto-exiting in 10 seconds");
    sceKernelDelayThread(10*1000*1000);
	sceKernelExitGame();
  }
  if(!getupdateversion(foo.off_sfo))
  {
    printerror("Can't determine firmware update version!");
    printerror("auto-exiting in 10 seconds");
    sceKernelDelayThread(10*1000*1000);
	sceKernelExitGame();
  }

  pspDebugScreenPrintf("Found Update eboot\n");
  pspDebugScreenPrintf("Update version is: %s\n\n",fw);
  if(supportedfw())
  {
    printok("Press [X] to install firmware");
  }
  else
  {
    printerror("This fw version is not guaranteed to work!");
    printerror("There's a 50/50 chance it will work");
    printerror("Press [X] to install firmware anyways");
  }
  makedevpath();
  sprintf(path, "%s%s/", devpath,fwpath);

	while (1)
	{
		SceCtrlData pad;

		sceCtrlReadBufferPositive(&pad, 1);

		if (pad.Buttons & PSP_CTRL_CROSS)
		{
			mode = MODE_ENCRYPT_SIGCHECK;
			break;
		}
		/*else if (pad.Buttons & PSP_CTRL_CIRCLE)
		{
			mode = MODE_ENCRYPT;
			break;
		}
		else if (pad.Buttons & PSP_CTRL_SQUARE)
		{
			mode = MODE_DECRYPT;
			break;
		}*/

		sceKernelDelayThread(10000);
	}

#ifdef SPECIAL_KEYS
	InitKeys();
#endif
    pspDebugScreenClear();

    int cbFile =0;
    cbFile = getpsar(&foo);


    if (memcmp(g_dataPSAR, "PSAR", 4) != 0)
    {
        printf("Not a PSAR file\n");
        return -1;
    }
    g_bOldSchool = g_dataPSAR[4] == 1;  // old "bogus" update

    //set up F0 folder
    sprintf(buffer, "%sF0", installpath);
    sceIoMkdir(buffer, 0777);
    sprintf(buffer, "%sF0/PSARDUMPER", installpath);
    sceIoMkdir(buffer, 0777); 
    sprintf(buffer, "%sF0/data", installpath);
    sceIoMkdir(buffer, 0777);
    sprintf(buffer, "%sF0/dic", installpath);
    sceIoMkdir(buffer, 0777);
    sprintf(buffer, "%sF0/font", installpath);
    sceIoMkdir(buffer, 0777);
    sprintf(buffer, "%sF0/kd", installpath);
    sceIoMkdir(buffer, 0777);
    sprintf(buffer, "%sF0/vsh", installpath);
    sceIoMkdir(buffer, 0777);
    sprintf(buffer, "%sF0/data/cert", installpath);
    sceIoMkdir(buffer, 0777);
    sprintf(buffer, "%sF0/kd/resource", installpath);
    sceIoMkdir(buffer, 0777);
    sprintf(buffer, "%sF0/vsh/etc", installpath);
    sceIoMkdir(buffer, 0777);
    sprintf(buffer, "%sF0/vsh/module", installpath);
    sceIoMkdir(buffer, 0777);
    sprintf(buffer, "%sF0/vsh/resource", installpath);
    sceIoMkdir(buffer, 0777);

    sprintf(buffer, "%sF0/PSARDUMPER/README.txt", installpath);
    int pfLog = my_openlogfile(buffer);
    if (pfLog < 0)
    {
        printf("Failed to create report file\n");
        printf("Stick may be full or can't create OUT folder\n");
        return -1;
    }

    sprintf(buffer, "%sF0/PSARDUMPER/READMEX.txt", installpath);
    int pfLogX = my_openlogfile(buffer);
    if (pfLogX < 0)
    {
        printf("Failed to create report file\n");
        printf("Stick may be full or can't create OUTX folder\n");
        return -1;
    }

    // ready to go

#ifdef DELETE_AT_START
    printf("deleting original Update Eboot to free up space on memory stick\n");
    if (sceIoRemove(updpath) != 0)
    {
        printf("WARNING: failed to delete Update Eboot \n");
        printf(" may run out of space on 32MB stick\n");
    }
#endif

    PrintHeader(pfLog);
    my_print(pfLog, "Special Files:\n");
    PrintHeader(pfLogX);
    my_print(pfLogX, "Decrypted ~PSP Files:\n");

    int cbOut;

    // at the start of the PSAR file,
    //   there are one or two special version data chunks
    printf("Special PSAR records:\n");
    cbOut = DecodeBlock(&g_dataPSAR[0x10], OVERHEAD+SIZE_A, g_dataOut);
    if (cbOut <= 0)
    {
        printf("Failed to decode\n");
        return -1;
    }
    if (cbOut != SIZE_A)
    {
        printf("Start PSAR chunk has invalid size (%d)\n", cbOut);
        return -1;
    }
    printf("version info - %d bytes\n", cbOut);
    sprintf(buffer, " version info - saved as %sF0/PSARDUMPER/data0.bin", installpath);
    my_print(pfLog, buffer);
    sprintf(buffer, "%sF0/PSARDUMPER/data0.bin", installpath);

    if (!SaveFile(buffer, g_dataOut, cbOut))
        return -1;

    int iBase = 0x10+OVERHEAD+SIZE_A; // after first entry
            // iBase points to the next block to decode (0x10 aligned)

    if (!g_bOldSchool)
    {
        // second block
        cbOut = DecodeBlock(&g_dataPSAR[0x10+OVERHEAD+SIZE_A], OVERHEAD+100, g_dataOut);
        if (cbOut <= 0)
        {
            printf("Performing V2.70 test\n"); // version 2.7 is bigger
	        cbOut = DecodeBlock(&g_dataPSAR[0x10+OVERHEAD+SIZE_A], OVERHEAD+144, g_dataOut);
            if (cbOut <= 0)
	        {
	            printf("Failed to decode(2)\n");
	            return -1;
	        }
        }
        printf("other info - %d bytes\n", cbOut);
        sprintf(buffer, "%sF0/PSARDUMPER/data1.bin", installpath);
        if (!SaveFile(buffer, g_dataOut, cbOut))
            return -1;
        sprintf(buffer, " other info - saved as %sF0/PSARDUMPER/data1.bin\n", installpath);
        my_print(pfLog, buffer);
        int cbChunk = (cbOut + 15) & 0xFFFFFFF0;
        iBase += OVERHEAD+cbChunk;
    }
    else
    {
        printf("Skipping 2nd call\n");
    }

    my_print(pfLog, "\n");
    my_print(pfLog, "Regular Files:\n");

    // smart enumerate
    printf("Enumerating PSAR file records:\n");
    int nSaved = 0; // data saved
    int nSavedX = 0; // PRX decoded
    int nErr = 0;

    char szT[256]; // temporary use

    while (iBase < cbFile-OVERHEAD)
    {
        cbOut = DecodeBlock(&g_dataPSAR[iBase], OVERHEAD+SIZE_A, g_dataOut);
        if (cbOut <= 0)
        {
            printf("Abort return cb=%d [@$%x]\n", cbOut, iBase);
            break;
        }
        if (cbOut != SIZE_A)
        {
            printf("Bad size for filename %d\n", cbOut);
            break;
        }
        char name[64];
        strcpy(name, (const char*)&g_dataOut[4]);
        printf("'%s' ", name);
        char* szFileBase = strrchr(name, '/');
        if (szFileBase != NULL)
            szFileBase++;  // after slash
        else
            szFileBase = "err.err";

        u32* pl = (u32*)&g_dataOut[0x100];
		int sigcheck = (g_dataOut[0x10F] == 2);
            // pl[0] is 0
            // pl[1] is the PSAR chunk size (including OVERHEAD)
            // pl[2] is true file size (TypeA=272=SIZE_A, TypeB=size when expanded)
            // pl[3] is flags or version?
        if (pl[0] != 0)
        {
            printf("Abort pl[0] = $%x\n", pl[0]);
            break;
        }

        iBase += OVERHEAD + SIZE_A;
        u32 cbDataChunk = pl[1]; // size of next data chunk (including OVERHEAD)
        u32 cbExpanded = pl[2]; // size of file when expanded

        sprintf(szT, " %s (%d bytes)", name, cbExpanded);
        my_print(pfLog, szT);

        if (cbExpanded > 0)
        {
            cbOut = DecodeBlock(&g_dataPSAR[iBase], cbDataChunk, g_dataOut);
            if (cbOut > 10 && g_dataOut[0] == 0x78 && g_dataOut[1] == 0x9C)
            {
                // standard Deflate header

                const u8* pbIn = &g_dataOut[2]; // after header
                u32 pbEnd;
                int ret = (*g_sceDeflateDecompress)(g_dataOut2, cbExpanded, pbIn, &pbEnd);
                if (ret == cbExpanded)
                {
                    char szDataPath[128];
                    //sprintf(szDataPath, "ms0:/OUT/%s", szFileBase);

                    if (!strncmp(name, "flash0:/", 8))
					{
						sprintf(szDataPath, "%sF0/%s", installpath,name+8);
					}

					else if (!strncmp(name, "flash1:/", 8))
					{
						sprintf(szDataPath, "%sF1/%s", installpath,name+8);
					}

					else
					{
						sprintf(szDataPath, "%sF0/PSARDUMPER/%s",installpath, strrchr(name, '/') + 1);
					}
					printf("expanded"); // cbUsed = pbEnd-(u32)pbIn

					if (sigcheck && mode == MODE_ENCRYPT_SIGCHECK && (strcmp(name, "flash0:/kd/loadexec.prx") != 0)
						&& (strcmp(name, "flash0:/kd/sysmem.prx") != 0))
					{
						GenerateSigCheck(g_dataOut2);
					}

					if ((mode != MODE_DECRYPT) || (memcmp(g_dataOut2, "~PSP", 4) != 0))
					{
						if (!SaveFile(szDataPath, g_dataOut2, cbExpanded))
	                    {
	                        my_print(pfLog, "\nWRITE ERROR - process aborted\n");
	                        break;
	                    }
	                    printf(",saved");
	                    sprintf(szT, " -- saved as '%s'", szDataPath);
	                    my_print(pfLog, szT);
	                    nSaved++;
					}
                    char loadexectmp[64];
                    char sysmemtmp[64];
					if (mode != MODE_DECRYPT)
					{
						if (!strcmp(name, "flash0:/kd/loadexec.prx"))
						{
							sprintf(buffer, "%sF0/loadexec.tmp",installpath);
							strcpy(szDataPath, buffer);
							strcpy(loadexectmp, buffer);
                        }
						if (!strcmp(name, "flash0:/kd/sysmem.prx"))
						{
							sprintf(buffer, "%sF0/sysmem.tmp",installpath);
							strcpy(szDataPath, buffer);
							strcpy(sysmemtmp, buffer);
                        }
					}

                    //if ((memcmp(g_dataOut2, "~PSP", 4) == 0) &&
						//(mode == MODE_DECRYPT || !strcmp(szDataPath, "ms0:/dh/301/F0/loadexec.tmp") ||
						//!strcmp(szDataPath, "ms0:/dh/301/F0/sysmem.tmp")))
                    if ((memcmp(g_dataOut2, "~PSP", 4) == 0) &&
						(mode == MODE_DECRYPT || !strcmp(szDataPath, loadexectmp) ||
						!strcmp(szDataPath, sysmemtmp)))
                    {
                        u32 tag = *(u32*)&g_dataOut2[0xD0];
                        int cbDecrypted = MyDecryptPRX(g_dataOut2, g_dataOut,
                            cbExpanded, tag);

						if (cbDecrypted <= 0)
						{
							cbDecrypted = DecryptPRX2(g_dataOut2, g_dataOut, cbExpanded, tag);
						}
                            // output goes back to main buffer
                            // trashed 'g_dataOut2'
                        if (cbDecrypted > 0)
                        {
                            u8* pbToSave = g_dataOut;
                            int cbToSave = cbDecrypted;

                            printf(",decrypted");
                            //***sprintf(szDataPath, "ms0:/OUTX/%s", szFileBase);
							/*if (!strncmp(name, "flash0:/", 8))
							{
								sprintf(szDataPath, "ms0:/dh/301/F0/%s", name+8);
							}

							else if (!strncmp(name, "flash1:/", 8))
							{
								sprintf(szDataPath, "ms0:/F1/%s", name+8);
							}

							else
							{
								sprintf(szDataPath, "ms0:/dh/301/F0/PSARDUMPER/%s", strrchr(name, '/') + 1);
							}*/

                            if (g_dataOut[0] == 0x1F && g_dataOut[1] == 0x8B)
                            {
                                int cbExp = (*g_sceGzipDecompress)(g_dataOut2,
                                    sizeof(g_dataOut), g_dataOut, NULL);
                                    // expanded result to g_dataOut
                                if (cbExp > 0)
                                {
                                    printf(",expanded");
                                    pbToSave = g_dataOut2;
                                    cbToSave = cbExp;
                                }
                                else
                                {
                                    sprintf(szT, "GZIP DECOMPRESS ERROR '%s' - saving what I can\n", name);
                                    my_print(pfLogX, szT);
                                    nErr++;
                                }
                            }
                            if (!SaveFile(szDataPath, pbToSave, cbToSave))
                            {
                                my_print(pfLogX, "\nWRITE ERROR - process aborted\n");
                                nErr++;
                                break;
                            }
                            else
                            {
                                sprintf(szT, " %s - decrypted and saved as '%s'\n",
                                    name, szDataPath);
                                my_print(pfLogX, szT);
                                nSavedX++;
                            }
                            printf(",saved!");
                        }
                        else
                        {
                            my_print(pfLogX, "\nDECRYPT ERROR\n");
                            nErr++;
                        }
                    }
                    else if (strncmp(name, "ipl:", 4) == 0)
                    {
						sprintf(szDataPath, "%sF0/PSARDUMPER/part1_%s",installpath, szFileBase);
                        int cb1 = DecryptIPL1(g_dataOut2, g_dataOut,
                            cbExpanded);
						if (cb1 > 0 && SaveFile(szDataPath, g_dataOut, cb1))
                        {
							sprintf(szT, " %s - special IPL part1 decrypt saved as '%s'\n",
                                    name, szDataPath);
							my_print(pfLogX, szT);

                            int cb2 = LinearizeIPL2(g_dataOut, g_dataOut2, cb1);
							sprintf(szDataPath, "%sF0/PSARDUMPER/part2_%s",installpath, szFileBase);
							if (SaveFile(szDataPath, g_dataOut2, cb2))
                            {
								sprintf(szT, " %s - special IPL part2 decrypt saved as '%s'\n",
	                                    name, szDataPath);
								my_print(pfLogX, szT);
                            }

							int cb3 = DecryptIPL3(g_dataOut2, g_dataOut, cb2);

							sprintf(szDataPath, "%sF0/PSARDUMPER/part3_%s",installpath, szFileBase);
							if (SaveFile(szDataPath, g_dataOut, cb3))
                            {
								sprintf(szT, " %s - special IPL part3 decrypt saved as '%s'\n",
	                                    name, szDataPath);
								my_print(pfLogX, szT);

                            }
                        }
                    }
                }
                else
                {
                    printf("deflate ERROR $%x\n", ret);
                    nErr++;
                }
            }
            else
            {
                printf("decode data ERROR cbOut=%d\n", cbOut);
                nErr++;
            }
        }
        else if (cbExpanded == 0)
        {
            printf("empty");
        }
        else
        {
            printf("cbExpanded bogus (%d) -- abort\n", cbExpanded);
            break;
        }
        printf("\n");
        my_print(pfLog, "\n");
    
        iBase += cbDataChunk;   // skip over data chunk
    }

    printf("\ndone - %d saved, %d decrypted, %d errors\n", nSaved, nSavedX, nErr);
    printf("  (0x%x bytes left over at end of file)\n", cbFile - iBase);

    my_print(pfLog, "-------------\n");
    my_print(pfLog, "\n");
    sprintf(szT, "%d data files saved\n", nSaved);
    my_print(pfLog, szT);
    sprintf(szT, "%d errors\n", nErr);
    my_print(pfLog, szT);
    my_print(pfLog, "\n");

    my_print(pfLogX, "-------------\n");
    my_print(pfLogX, "\n");
    sprintf(szT, "%d decrypted of %d data files saved\n", nSavedX, nSaved);
    my_print(pfLogX, szT);
    my_print(pfLogX, "\n");

    my_close(pfLog);
    my_close(pfLogX);

	printf("Extracting reboot.bin...\n");

	if (mode == MODE_DECRYPT)
	{
		char s1[64],s2[64];
		sprintf(s1, "%sF0/kd/loadexec.prx", installpath);
		sprintf(s1, "%sF0/kd/sysmem.prx", installpath);
		ExtractReboot(s1, s2);
    }
	else
	{
		char s1[64],s2[64];
		sprintf(s1, "%sF0/loadexec.tmp", installpath);
		sprintf(s2, "%sF0/sysmem.tmp", installpath);
		ExtractReboot(s1, s2);
        sceIoRemove(s1);
		sceIoRemove(s2);	
	}

	if (mode == MODE_ENCRYPT_SIGCHECK)
	{
		// Do the sigcheck no those two now
		int size;

		sprintf(buffer, "%sF0/kd/loadexec.prx", installpath);
		size = ReadFile(buffer, 0, g_dataOut, 3000000);

		if (size > 0)
		{
			GenerateSigCheck(g_dataOut);
			SaveFile(buffer, g_dataOut, size);
		}

		sprintf(buffer, "%sF0/kd/sysmem.prx", installpath);
		size = ReadFile(buffer, 0, g_dataOut, 3000000);
		
		if (size > 0)
		{
			GenerateSigCheck(g_dataOut);
			SaveFile(buffer, g_dataOut, size);
		}
	}

    printf("\n");
    if (g_bWriteError)
        printf("\nWARNING: dump incomplete, memory stick full\n\n");
        
    //Set up F1
    SceUID out;
    printf("Creating Flash1...\n");
    sprintf(buffer, "%sF1/registry", installpath);
    sceIoMkdir(buffer, 0777);
    sprintf(buffer, "%sF1/vsh", installpath);
    sceIoMkdir(buffer, 0777);
    sprintf(buffer, "%sF1/vsh/theme", installpath);
    sceIoMkdir(buffer, 0777);
    sprintf(buffer, "%sF1/dic", installpath);
    sceIoMkdir(buffer, 0777);
    sprintf(buffer, "%sF1/gps", installpath);
    sceIoMkdir(buffer, 0777);
    sprintf(buffer, "%sF1/net", installpath);
    sceIoMkdir(buffer, 0777);
    sprintf(buffer, "%sF1/net/http", installpath);
    sceIoMkdir(buffer, 0777);
    
    //Different firmwares need different registries
    if((!memcmp(fw, "2.71", 4))||(!memcmp(fw, "2.80", 4))||(!memcmp(fw, "2.81", 4))||(!memcmp(fw, "2.82", 4))||(!memcmp(fw, "3.00", 4))||(!memcmp(fw, "3.01", 4))||(!memcmp(fw, "3.02", 4))||(!memcmp(fw, "3.03", 4))||(!memcmp(fw, "3.10", 4))||(!memcmp(fw, "3.11", 4))||(!memcmp(fw, "3.30", 4)))
    {
      sprintf(buffer, "%sF1/registry/system.ireg", installpath);
      out = sceIoOpen(buffer, PSP_O_CREAT | PSP_O_TRUNC | PSP_O_WRONLY, 0777);
      sceIoWrite(out, ireg2, IREG2_LEN);
      sceIoClose(out);
      sprintf(buffer, "%sF1/registry/system.dreg", installpath);
      out = sceIoOpen(buffer, PSP_O_CREAT | PSP_O_TRUNC | PSP_O_WRONLY, 0777);
      sceIoWrite(out, dreg2, DREG2_LEN);
      sceIoClose(out);
    }
    else
    {
      sprintf(buffer, "%sF1/registry/system.ireg", installpath);
      out = sceIoOpen(buffer, PSP_O_CREAT | PSP_O_TRUNC | PSP_O_WRONLY, 0777);
      sceIoWrite(out, ireg, IREG_LEN);
      sceIoClose(out);
      sprintf(buffer, "%sF1/registry/system.dreg", installpath);
      out = sceIoOpen(buffer, PSP_O_CREAT | PSP_O_TRUNC | PSP_O_WRONLY, 0777);
      sceIoWrite(out, dreg, DREG_LEN);
      sceIoClose(out);
    }

    printf("Done (auto-exiting in 10 seconds)\n");
    printf("\n\n\n\n\n");

	sceKernelDelayThread(10*1000*1000);
	sceKernelExitGame();
    
    return 0;
}


