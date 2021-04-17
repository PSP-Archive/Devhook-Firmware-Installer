//=============================================
//Devhook Firmware Installer
//tommydanger
//v0.6h by Sleepy
//=============================================

#include "common.h"

//Firmware Installer Version
const char version[64] = "Devhook Firmware Installer v0.6h";
//Devhook Path
const char devpath[] = "ms0:/dh/";

//Update Eboot path
const char updpath[] = "ms0:/EBOOT.PBP";
//PBP Magic
char pbpmagic[4] =  {0x0,0x50,0x42,0x50};   //_PBP
char pbpid[4] =     {0,0,1,0};      //Filetype ID?!
//PSF Magic
char psfmagic[4] =  {0x0,0x50,0x53,0x46};
char psfid[4] =     {1,1,0,0};

//buffer to store the update version from the update eboot
char fw[8];
//converted update version number (3.30 ->330)
char fwpath[4];
//full installation path e.g. ms0:/dh/330/
//depends on selected update
char installpath[64];

//Get the PBP Header
int getpbpheader(PBP_HEADER *tmp)
{
  int bytes_read = 0;
  SceUID fd;
  if(!(fd = sceIoOpen(updpath, PSP_O_RDONLY, 0777)))
  {
        return 0;
  }
  bytes_read = sceIoRead(fd, tmp, sizeof(PBP_HEADER));
  if(bytes_read != sizeof(PBP_HEADER))
  {
    return 0;
  }
  sceIoClose(fd);
  return  validatepbp(tmp);
}
//check if eboot is valid
int validatepbp(PBP_HEADER *src)
{
  if(memcmp(src->header, pbpmagic, 4) != 0)
  {
    return 0;
  }
  else
  {
    //printerror("Eboot is not a valid Update");
    return 1;
  }
  
}
//gets the update version from the sfo
int getupdateversion(u32 psf)
{
  PSF_HEADER header;
  INDEX_TABLE index;
  SceUID fd;
  int i=0;
  int ok=-1;
  char buffer[32];
  
  if(!(fd = sceIoOpen(updpath, PSP_O_RDONLY, 0777)))
  {
    //error
    return ok;
  }
  sceIoLseek(fd, psf, SEEK_SET);
  sceIoRead(fd, &header, sizeof(PSF_HEADER));
  
  for(i=0;i<header.pairs;i++)
  {
    memset (buffer, 0, 32);
    sceIoLseek(fd, psf+sizeof(PSF_HEADER)+(sizeof(INDEX_TABLE)*i), SEEK_SET);
    sceIoRead(fd, &index, sizeof(INDEX_TABLE));
    sceIoLseek(fd, psf+header.keytable+index.keytable, SEEK_SET);
    sceIoRead(fd, buffer, 32);
    if(!(memcmp(buffer, "UPDATER_VER", 11)))
    {
      //pspDebugScreenPrintf("FOUND UPDATE VERSION\n");
      ok = 1;
      break;
    }
  }
  sceIoLseek(fd, psf+header.valuetable+index.valuetable, SEEK_SET);
  sceIoRead(fd, fw, index.sizepadded);
  sceIoClose(fd);
  return ok;
  
}

u32 filesize(char *src)
{
  SceUID fd;
  u32 filesize = 0;
  if((fd = sceIoOpen(updpath, PSP_O_RDONLY, 0777)))
  filesize = sceIoLseek(fd, 0, SEEK_END);
  sceIoClose(fd);
  
  return filesize;
}

void printright(int y, char *src)
{
  const int chars = 67;
  int len = 0;
  int tmp; 
  int i=0;
  for(i=0;i<chars;i++)
  {
    if(src[i]==0x00)
    break;
  }
       
  len=i;
  tmp = chars - len+1;
  
  pspDebugScreenSetXY(tmp, y);
  pspDebugScreenPrintf("%s\n",src);
}

void setupdebugscreen()
{
  pspDebugScreenInit();
  pspDebugScreenSetBackColor(BG);
  pspDebugScreenSetTextColor(TXT);
  pspDebugScreenClear();
}

void printerror(char *src)
{
  pspDebugScreenSetTextColor(ERROR);
  pspDebugScreenPrintf("%s\n",src);
  pspDebugScreenSetTextColor(TXT);
}

void printerrorxy(int x, int y, char *src)
{
  pspDebugScreenSetTextColor(ERROR);
  pspDebugScreenSetXY(x,y);
  pspDebugScreenPrintf("%s",src);
  pspDebugScreenSetTextColor(TXT);
}

void printinstallheader()
{
  pspDebugScreenSetXY(0,0);
  pspDebugScreenPrintf("--------------------------------------------------------------------");
  pspDebugScreenPrintf("%s                              Sleepy",version);
  pspDebugScreenPrintf("based on code from PspPet, Dark_AleX, Team Noobz, tommydanger\n");
  pspDebugScreenPrintf("--------------------------------------------------------------------");
}

void printok(char *src)
{
  pspDebugScreenSetTextColor(OK);
  pspDebugScreenPrintf("%s\n",src);
  pspDebugScreenSetTextColor(TXT);
}

//pretty lazy but yeah.....
//needs some better implementation
int supportedfw()
{
  if(!memcmp(fw, "1.50", 4))
  {
    return 1;
  }
  if(!memcmp(fw, "1.51", 4))
  {
    return 1;
  }
  if(!memcmp(fw, "1.52", 4))
  {
    return 1;
  }
  if(!memcmp(fw, "2.00", 4))
  {
    return 1;
  }
  if(!memcmp(fw, "2.01", 4))
  {
    return 1;
  }
  if(!memcmp(fw, "2.50", 4))
  {
    return 1;
  }
  if(!memcmp(fw, "2.60", 4))
  {
    return 1;
  }
  if(!memcmp(fw, "2.70", 4))
  {
    return 1;
  }
  if(!memcmp(fw, "2.71", 4))
  {
    return 1;
  }
  if(!memcmp(fw, "2.80", 4))
  {
    return 1;
  }
  if(!memcmp(fw, "2.81", 4))
  {
    return 1;
  }
  if(!memcmp(fw, "2.82", 4))
  {
    return 1;
  }
  if(!memcmp(fw, "3.00", 4))
  {
    return 1;
  }
  if(!memcmp(fw, "3.01", 4))
  {
    return 1;
  }
  if(!memcmp(fw, "3.02", 4))
  {
    return 1;
  }
  if(!memcmp(fw, "3.03", 4))
  {
    return 1;
  }
  if(!memcmp(fw, "3.10", 4))
  {
    return 1;
  }
  if(!memcmp(fw, "3.11", 4))
  {
    return 1;
  }
  if(!memcmp(fw, "3.30", 4))
  {
    return 1;
  }


  return 0;

}

void makedevpath()
{
  int i=0;
  int y=0;
  for(i=0;i<4;i++)
  {
    if(fw[i]!='.')
    {
      fwpath[y]=fw[i];
      y++;
    }
  }
  fwpath[y] = 0x00;
  sprintf(installpath, "%s%s/", devpath,fwpath);
}
