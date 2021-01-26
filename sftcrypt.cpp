// Copyright 2011-2021 by Bob Frazier and S.F.T. Inc
//
// This program is open source.  You may use it in any way you see fit
//
// The encryption method implemented here is mostly an experiment.  It has
// not been verified to be secure and the key size is limited to 128 bits
// by design.  You can use the algorithm in any way you see fit.
// The encryption algorithm (a stream cipher) used here was originally
// conceived in the late 1990's, and the original version of this program
// was created in 2011.  An earlier version was done ca 1998 in protest
// of the encryption export nonsense from the U.S. government, by being
// described "in prose" on mrp3.com/encrypt.html, which was first
// published online in 1998 and last updated in 2013 at the time of this
// writing (see copyright statement).  Needless to say this is basically
// a claim of "prior art" in case anyone has any claim to patent the
// algorithm or make any new claims regarding its availability to the
// world...
//
// NOTE:  nearly all open source operating systems will have encryption
//        included with it.  'gpg' and 'openssl' are two of the more
//        popular ones.  Use these if you want REAL data protection.
//
// The one advantage this algorithm has is PURE SPEED, once the encryption
// tables have been generated.  That process used to take a noticeable period
// of time (less than a second, but noticeable) on a very old platform (486).
// However, with CPUs running in Ghz now, it's barely any time at all.
// But the speed advantage is also less significant on modern CPUs, except
// maybe for VERY large data sizes.


// build command on POSIX systems;  c++ -o sftcrypt sftcrypt.cpp


#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <fcntl.h>
#include <string.h>

#ifdef WIN32

// Win32-isms to help with compatibility

#include <io.h>

#define __CDECL__ __cdecl

#else // WIN32

#include <unistd.h>
#include <ctype.h>
#include <memory.h>
#include <errno.h>
#include <termios.h>

#define _O_BINARY 0
#define _O_RDONLY O_RDONLY
#define _fileno fileno
#define _setmode(X,Y) fcntl(X,F_SETFD,Y)
#define __CDECL__

#endif // WIN32


typedef char *LPSTR;
typedef const char *LPCSTR;
typedef unsigned char BYTE;
typedef unsigned char * LPBYTE;
typedef const unsigned char * LPCBYTE;
typedef unsigned int UINT;
typedef unsigned int DWORD;
typedef unsigned short WORD;
typedef unsigned int BOOL;

#define LOWORD(X) ((WORD)((DWORD)(X) & 0xffff))
#define HIWORD(X) ((WORD)((((DWORD)(X)) >> 16) & 0xffff))

#define FALSE 0
#define TRUE !0


UINT _calc_crc16(LPCSTR source, UINT size);

void EncryptDataStream(const BYTE *lpDict, LPBYTE lpData, UINT cbData,
                       BYTE *pbSeed, UINT cbKeysize,
                       BOOL bDecryptFlag = FALSE,
                       BYTE bTableSize = 0);
void EncryptDataStream2(const BYTE *lpDict, LPBYTE lpData, UINT cbData,
                        BYTE *pbSeed, UINT cbKeysize,
                        BOOL bDecryptFlag = FALSE,
                        BYTE bTableSize = 0);
LPBYTE BuildEncryptionDictionary(DWORD dw1, DWORD dw2, DWORD dwMask,
                                 WORD w1, WORD w2,
                                 BYTE bTableSize = 0);



void do_help()
{
  fprintf(stderr, "SFTCRYPT - Encryption/Decryption technology "
                  "(c) 1998 by SFT Inc.\n\n"
                  "COMMAND LINE:  SFTCRYPT [-h] [-d] [[-p] key|-P[-]] [input file [output file]]\n"
                  "    where      'key' is a 128-bit key defined by a binary hex literal\n"
                  "               or a quoted 'key phrase' [if '-p' specified]\n"
                  "     and       -P prompts for a pass phrase (via console)\n"
                  "               specifying '-P-' will echo the passphrase; use with discretion\n"
                  "     and       'input file' is an optional input file (default is STDIN)\n"
                  "     and       'output file' is the default output file (default is STDOUT)\n"
                  "     and       '-d' indicates \"decrypt\"\n"
                  "     and       '-h' prints this message\n"
                  "\n\n");
}



BOOL bDebug = FALSE;

int main(int nArg, char *aszArgList[])
{
FILE *pIN = stdin, *pOUT = stdout;
int i1, iArg=1, iKeyArg = -1;
BOOL bDecrypt = FALSE, bPhrase = FALSE, bPhraseEcho = FALSE, bPrompt = FALSE;
BYTE pbSeed[16];  // 16 byte "seed"
DWORD dwKey[4]={0,0,0,0};


  if(nArg < 2)
  {
    fprintf(stderr, "invalid command line (too few arguments)\n");
    do_help();
    return 1;
  }

  // not using getopt because, Win32
  while(iArg < nArg &&
        (aszArgList[iArg][0] == '-'
#ifdef WIN32
        || aszArgList[iArg][0] == '/'  // windows only
#endif // WIN32
        ))
  {
    if(
#ifdef WIN32
       aszArgList[iArg][1] == '?' || // windows only
#endif // WIN32
       aszArgList[iArg][1] == 'h')
    {
      do_help();
      return 1;
    }

    if(aszArgList[iArg][1] == 'D')
    {
      bDebug = TRUE;
    }
    else if(aszArgList[iArg][1] == 'd')
    {
      bDecrypt = TRUE;
    }
    else if(toupper(aszArgList[iArg][1]) == 'P')
    {
      bPhrase = TRUE;
      if(aszArgList[iArg][2]=='-')
      {
        bPhraseEcho = TRUE;
      }
      else
      {
        bPhraseEcho = FALSE;
      }

      if(aszArgList[iArg][1] == 'P') // TODO:  check for presence of next arg
        bPrompt = TRUE;
      else
        iKeyArg = ++iArg;
    }
    else if(aszArgList[iArg][1] != aszArgList[iArg][0])
    {
      fprintf(stderr, "INVALID SWITCH in command line\n");
      return(2);
    }

    iArg++;
  }

  if(iKeyArg <= 0 && !bPrompt)
  {
    iKeyArg = iArg++;
  }

  if((iKeyArg <= 0 && !bPrompt) || iKeyArg >= nArg ||
     (!bPrompt && (!aszArgList[iKeyArg] || !aszArgList[iKeyArg][0])))
  {
    fprintf(stderr, "Illegal pass phrase / key - blank not allowed.\n");

    do_help();
    return 2;
  }

  if(bPhrase)
  {
    // generate a key from this by encrypting the data with the
    // following key:  533EA24D0B164864.  Note that this is a lot
    // like hashing but less effective unless the phrase is long.

    dwKey[0] = 0x533ea24d; // so what if it's well known, I'm just using it
    dwKey[1] = 0x0b164864; // to hash the pass phrase as a legit key
    dwKey[2] = 0xd6073e8a; // however unlike other hashes, it DOES open the
    dwKey[3] = 0x463d72b5; // passphrase up to brute-force cracking if it's short

    char *p1;

    if(bPrompt)
    {
      FILE *pTTY = NULL;
#ifdef WIN32
      // Win32 version - do something!

#else // WIN32
      struct termios sIOS0;

      // NOTE:  if win32 code is significantly different, use 'readpasswphrase()' instead
      pTTY = fopen("/dev/tty", "r"); // read from  console directly

      if(pTTY && !bPhraseEcho)
      {
        struct termios sIOS;
        int iFile = fileno(pTTY);

        if(tcgetattr(iFile, &sIOS))
        {
          fprintf(stderr, "error %d getting attributes\n", errno);

          fclose(pTTY);
          pTTY = NULL;
        }
        else
        {
          memcpy(&sIOS0, &sIOS, sizeof(sIOS0)); // cache it so I can restore it

          // make sure echoing is disabled and control chars aren't translated or omitted
#if defined(__FreeBSD__)
          sIOS.c_lflag &= ~(ECHO | ECHOKE | ECHOE | ECHONL | ECHOPRT | ECHOCTL | ICANON | IEXTEN | ISIG | ALTWERASE);
#else // Linux? YMMV
          sIOS.c_lflag &= ~(ECHO | ECHOKE | ECHOE | ECHONL
#ifdef ECHOPRT
                        | ECHOPRT
#else
#warning no 'ECHOPRT'
#endif // ECHOPRT
                        | ECHOCTL | ICANON | IEXTEN | ISIG);
#endif // FBSD vs Linux

          if(tcsetattr(iFile, TCSANOW, &sIOS))
          {
            fprintf(stderr, "error %d setting attributes\n", errno);
          }
        }
      }

#endif // WIN32

      if(!pTTY)
      {
        fprintf(stderr, "unable to read console for pass phrase\n");
        do_help();
        return 4;
      }

      p1 = new char[65536];
      if(!p1)
      {
        fclose(pTTY);
        goto null_p1;
      }

      memset(p1, 0, 65536);
      fputs("Enter pass-phrase:", stderr);
      fflush(stderr); // make sure
      fgets(p1 +  sizeof(pbSeed), 65534 - sizeof(pbSeed), pTTY);
      fflush(stderr);

#ifdef WIN32
      // Win32 version - do something!

#else // WIN32
      if(!bPhraseEcho)
      {
        if(tcsetattr(fileno(pTTY), TCSANOW, &sIOS0)) // restore terminal state
        {
          fprintf(stderr, "error %d setting attributes\n", errno);
        }
      }
#endif // WIN32
      fclose(pTTY);
      fputs("\n", stderr);

      char *p2;
      p2 = p1 + sizeof(pbSeed) + strlen(p1 + sizeof(pbSeed));

      while(p2 > (p1 + sizeof(pbSeed)) && *(p2 - 1) <= ' ') // trailing white space not allowed
        *(--p2) = 0;

      i1 = p2 - (p1 + sizeof(pbSeed)); // the length of the string

      if(!*(p1 + sizeof(pbSeed)))
      {
        fprintf(stderr, "Blank pass phrase not allowed\n");
        do_help();
        return 3;
      }
    }
    else
    {
      p1 = new char[strlen(aszArgList[iKeyArg]) + 1 + sizeof(pbSeed)];
      if(!p1)
      {
null_p1:
        fprintf(stderr, "Not enough memory to complete the desired operation.\n");
        return(-1);
      }

      char *p2 = p1 + sizeof(pbSeed);
      i1 = strlen(aszArgList[iKeyArg]);
      memcpy(p2, aszArgList[iKeyArg], i1);
    }


    // NOTE:  code forced to "low endian" initial key

    for(i1=0; i1 < 16; i1++)
    {
      DWORD dw1 = dwKey[i1 >> 2];

      if(i1 & 3)
        pbSeed[i1] = (BYTE)((dw1 >> (4 * (i1 & 3))) & 0xff);
      else
        pbSeed[i1] = (BYTE)(dw1 & 0xff);
    }

    memcpy(p1, pbSeed, sizeof(pbSeed));


    // build a special crypto key thingy for this

    WORD w1a = (WORD)(dwKey[3] & 0xffff);
    WORD w2a = (WORD)((dwKey[3] >> 16) & 0xffff);

    LPBYTE pDict0 = BuildEncryptionDictionary(dwKey[0], dwKey[1],
                                              dwKey[2], w1a, w2a);

    if(!pDict0)
    {
      fprintf(stderr, "  Internal error - unable to create dictionary\n");
      return(-1);
    }

    char *p2 = p1 + sizeof(pbSeed);

    EncryptDataStream2(pDict0, (LPBYTE)p2, i1, pbSeed, sizeof(pbSeed), FALSE);

    // next, grab the last 16 bytes of 'p1' and I'm done!
    p2 += i1 - 16;  // do all 16 bytes for this one (32 'digits')

    for(i1=0; i1 < 4; i1++)
    {
      dwKey[i1] = (BYTE)p2[i1 * 4 + 0] * 0x1000000L
                + (BYTE)p2[i1 * 4 + 1] * 0x10000L
                + (BYTE)p2[i1 * 4 + 2] * 0x100L
                + (BYTE)p2[i1 * 4 + 3];
    }

#ifdef DEBUG
    fprintf(stderr, " [KEY=%08x%08x%08x%08x] ",
            dwKey[0], dwKey[1], dwKey[2], dwKey[3]);
#endif // DEBUG

    delete [] p1;
    delete [] pDict0;
  }
  else
  {
    dwKey[0] = 0;
    dwKey[1] = 0;
    dwKey[2] = 0;
    dwKey[3] = 0;

    for(i1=0; i1 < strlen(aszArgList[iKeyArg]); i1++)
    {
      unsigned char c = toupper(aszArgList[iKeyArg][i1]);

      if(c >= '0' && c <= '9')
      {
        c -= '0';
      }
      else if(c >= 'A' && c <= 'F')
      {
        c -= 'A' - '\xa';
      }
      else
      {
        fprintf(stderr, "Illegal character in key\n");
        return(2);
      }

      dwKey[i1 >> 3] *= 16;
      dwKey[i1 >> 3] += c;
    }
  }

  if(bDebug)
  {
    fprintf(stderr, "dwKey[] = {%lx,%lx,%lx,%lx}\n",
            (unsigned long)dwKey[0],
            (unsigned long)dwKey[1],
            (unsigned long)dwKey[2],
            (unsigned long)dwKey[3]);
  }


  // now, get the bytes for the key
  // NOTE:  code forced to "low endian" initial key

  for(i1=0; i1 < 16; i1++)
  {
    DWORD dw1 = dwKey[i1 >> 2];

    if(i1 & 3)
      pbSeed[i1] = (BYTE)((dw1 >> (4 * (i1 & 3))) & 0xff);
    else
      pbSeed[i1] = (BYTE)(dw1 & 0xff);
  }

  // next, I need to build the crypto key

  WORD w1 = (WORD)(dwKey[3] & 0xffff);
  WORD w2 = (WORD)((dwKey[3] >> 16) & 0xffff);

  LPBYTE pDict = BuildEncryptionDictionary(dwKey[0], dwKey[1],
                                           dwKey[2], w1, w2);

  if(!pDict)
  {
    fprintf(stderr, "  Internal error - unable to create dictionary\n");
    return(-1);
  }

  fprintf(stderr, "\n");

  BOOL bInFile = FALSE, bOutFile = FALSE;

  if(nArg > iArg)
  {
    pIN = fopen(aszArgList[iArg++],"rb");

    if(!pIN)
    {
      fprintf(stderr, "Unable to open input file '%s'\n",
              aszArgList[iArg - 1]);

      return(-1);
    }

    bInFile = TRUE;
  }
  else
  {
    _setmode(_fileno(stdin), _O_BINARY);
  }

  if(nArg > iArg)
  {
    unlink(aszArgList[iArg]);  // just in case

    pOUT = fopen(aszArgList[iArg++],"wb");

    if(!pOUT)
    {
      fprintf(stderr, "Unable to open output file '%s'\n",
              aszArgList[iArg - 1]);

      fclose(pIN);
      return(-1);
    }

    bOutFile = TRUE;
  }
  else
  {
    _setmode(_fileno(stdout), _O_BINARY);
  }

  BYTE cBuf[32768];
  int iRval = 0;

  while(!feof(pIN))
  {
    DWORD cb1 = fread(cBuf, 1, sizeof(cBuf), pIN);

    if(!cb1)
      break;

    // encrypt the buffer, 'cb1' items

    EncryptDataStream2(pDict, cBuf, cb1, pbSeed, sizeof(pbSeed), bDecrypt);

    // now, write it

    if(fwrite(cBuf, 1, cb1, pOUT) != cb1)
    {
      fprintf(stderr, "Write error on output file\n");
      iRval = 3;
      break;
    }
  }

  if(bInFile)
    fclose(pIN);

  if(bOutFile)
    fclose(pOUT);

  delete [] pDict;

  return(iRval);
}


static int __CDECL__ EncryptionDictionarySortCompare(const void *p1, const void *p2)
{
  DWORD *pdw1 = *((DWORD **)p1);
  DWORD *pdw2 = *((DWORD **)p2);

  /*register*/ DWORD dw1 = *pdw1;
  /*register*/ DWORD dw2 = *pdw2;

  if(dw1 < dw2)
    return(-1);
  else if(dw1 > dw2)
    return(1);
  else
  {
    // values are equal - use their relative position to reverse
    // the original order.  This will ensure consistency even if
    // the 'random sequence' were to contain all identical values.

    // NOTE:  this part may behave differently with different compilers and OSs
    //        most likely due to differing qsort implementations...

    if(p1 < p2)
      return(1);        // reverse
    else if(p1 > p2)
      return(-1);       // reverse
    else
      return(0);        // unlikely

  }
}

// 128-bit key random encryption dictionary table generator
// table size must be consistent for encrypt/decrypt to work
// fastest table generation is a small 'bTableSize' (non-zero)
// fastest encryption is a zero 'bTableSize' (max table size)

LPBYTE BuildEncryptionDictionary(DWORD dw1, DWORD dw2, DWORD dwMask,
                                 WORD w1, WORD w2,
                                 BYTE bTableSize /* = 0 */)
{
  if(bDebug)
  {
    fprintf(stderr, "BuildEncryptionDictionary(%lx,%lx,%lx,%x,%x,%u)\n",
            (unsigned long)dw1,
            (unsigned long)dw2,
            (unsigned long)dwMask,
            w1, w2, bTableSize);
  }

  // build an encrypt and a decrypt dictionary.  Encrypt dictionary
  // is at offset 0 in resulting pointer.  Decrypt dictionary is at
  // offset 0x10000 (bytes) in resulting pointer.  Memory block
  // contains 512 256-byte lookup tables, one set of 256 for
  // encryption, and one set of 256 for decryption.

  // to encrypt a byte, use the 'seed' (previous byte) value as the
  // table index, and proceed as follows:

  // LPBYTE lpTable; BYTE bSeed; BYTE bDecrypt = value;
  // BYTE bEncrypt = lpTable[bDecrypt + (bSeed << 8)];
  // ASSERT([bDecrypt == lpTable[bEncrypt + (bSeed << 8) + 0x10000L]);

  int iTableSize = (bTableSize ? bTableSize : 256);  // max index
  DWORD dwTableSize = 256 * (DWORD)iTableSize;       // # of bytes
  LPBYTE pRval = new BYTE[(int)(dwTableSize * 2)];

  DWORD *pIndex0[256], *pIndex[256];  // index pointers
  BYTE bIndex0[256], bIndex[256];
  DWORD dwRand[256]; // random DWORDs

  // step 1:  final order of indices in result "table"

  int i1, i2;
  DWORD dw3, dw4;
  WORD w3, w4, wMask = (HIWORD(dwMask) ^ LOWORD(dwMask));


  // TODO:  see if there's a mathematical possibility of creating
  //        entries that produce duplicate entries within a sequence
  //        smaller than 256 using specific values of 'w1' and 'w2'

  for(i1=0; i1 < iTableSize; i1++)
  {
    if((w1 & 0x8000) == (w2 & 0x8000))
    {
      w2 ^= 0x8021;  // flip a few bits if they match
    }

    w3 = (1 + ((w1 ^ wMask) + (w2 ^ wMask)))
       ^ 0x1021;  // 16-bit CRC 'xor' bitmask

    w1 = w2;
    w2 = w3;

    if(!(wMask & 0x8000)) // rotate it
      wMask = (wMask << 1) | 1;
    else
      wMask = wMask << 1;

    wMask ^= 0x1021;              // XOR with mask
    if(wMask & 0x8000)        // and rotate it
      wMask = (wMask << 1) + 1;
    else
      wMask = (wMask << 1);

    // again for w4

    if((w1 & 0x8000) == (w2 & 0x8000))
    {
      w2 ^= 0x8021;  // flip a few bits if they match
    }

    w4 = (1 + ((w1 ^ wMask) + (w2 ^ wMask)))
       ^ 0x1021;  // 16-bit CRC 'xor' bitmask

    w1 = w2;
    w2 = w4;

    if(!(wMask & 0x8000)) // rotate it
      wMask = (wMask << 1) | 1;
    else
      wMask = wMask << 1;

    wMask ^= 0x1021;              // XOR with mask
    if(wMask & 0x8000)        // and rotate it
      wMask = (wMask << 1) + 1;
    else
      wMask = (wMask << 1);

    dwRand[i1] = ((DWORD)w4 << 16) | w3;

    pIndex0[i1] = (DWORD *)dwRand + i1;
  }

  // sort the DWORD * array using quicksort algorithm

  qsort(pIndex0, iTableSize, sizeof(*pIndex0),
        EncryptionDictionarySortCompare);

  // convert pointers to indices

  for(i1=0; i1 < iTableSize; i1++)
  {
    bIndex0[i1] = (pIndex0[i1] - (DWORD *)dwRand);
  }


  // step 2:  create the 'encrypt' table

  for(i2=0; i2 < iTableSize; i2++)
  {
    int iTableOffset = (int)bIndex0[i2] * 256;

    for(i1=0; i1 < 256; i1++)
    {
      dw3 = (1 + ((dw1 ^ dwMask) + (dw2 ^ dwMask)))
          ^ 0x10005021;  // 32-bit CRC 'xor' bitmask

      dw1 = dw2;
      dw2 = dw3;

      if(!(dwMask & 0x80000000)) // rotate it
        dwMask = (dwMask << 1) | 1;
      else
        dwMask = dwMask << 1;

      dwMask ^= 0x10005021;          // XOR with mask
      if(dwMask & 0x80000000)        // and rotate it
        dwMask = (dwMask << 1) + 1;
      else
        dwMask = (dwMask << 1);

      dw4 = (1 + ((dw1 ^ dwMask) + (dw2 ^ dwMask)))
          ^ 0x10005021;  // 32-bit CRC 'xor' bitmask

      dw1 = dw2;
      dw2 = dw4;

      if(!(dwMask & 0x80000000)) // rotate it
        dwMask = (dwMask << 1) | 1;
      else
        dwMask = dwMask << 1;

      dwMask ^= 0x10005021;          // XOR with mask
      if(dwMask & 0x80000000)        // and rotate it
        dwMask = (dwMask << 1) + 1;
      else
        dwMask = (dwMask << 1);

      dwRand[i1] = dw3 ^ dw4;
      pIndex[i1] = (DWORD *)dwRand + i1;
    }

    // sort the DWORD * array using quicksort algorithm

    qsort(pIndex, sizeof(pIndex) / sizeof(*pIndex),
          sizeof(*pIndex), EncryptionDictionarySortCompare);

    // convert pointers to indices

    for(i1=0; i1 < 256; i1++)
    {
      bIndex[i1] = (pIndex[i1] - (DWORD *)dwRand);
    }

    // copy data into correct section of result array, "randomly"
    // arranged with respect to one another.

    for(i1=0; i1 < 256; i1++)
    {
      pRval[iTableOffset + i1] = bIndex[i1];
    }
  }

  // step 3:  the decryption array
  //
  // for each member in the source (encryption) array, calculate the
  // decryption array from it.  Each array is 1:1 corresponding.  It's
  // up to the caller to use corresponding 256-byte arrays within the
  // encryption/decryption table to both encrypt AND decrypt the data.

  for(i2=0; i2 < iTableSize; i2++)
  {
    int iBase = i2 * 256;

    for(i1=0; i1 < 256; i1++)
    {
      pRval[dwTableSize + iBase   // decrypt array offset
            + pRval[iBase + i1]] = (BYTE)i1;
    }
  }


#ifdef DEBUG
  if(bDebug)
  {
    for(i2=0; i2 < iTableSize; i2++)
    {
      fprintf(stderr, "%3d :", i2);
      for(i1=0; i1 < 256; i1++)
      {
        if(i1 != 0 && (i1 & 31) == 0)
        {
          fprintf(stderr, "\n    :");
        }

        fprintf(stderr, " %02x", pRval[i2 * 256 + i1]);
      }

      fprintf(stderr, "\n");
    }
  }
#endif // DEBUG

  return(pRval);
}






void EncryptDataStream(const BYTE *lpDict, LPBYTE lpData, UINT cbData,
                       BYTE *pbSeed0, UINT cbKeySize,
                       BOOL bDecryptFlag /* = FALSE */,
                       BYTE bTableSize /* = 0 */)
{
  UINT cb1;
  int iTableSize = (bTableSize ? bTableSize : 256);  // max index
  DWORD dwTableSize = 256 * (DWORD)iTableSize;       // # of bytes

  BYTE *pbSeed = new BYTE[(int)(cbKeySize * 2)];



  if(!pbSeed)
    return;  // for now, just return


  int i1;

  for(i1=0; i1 < cbKeySize; i1++)
  {
    pbSeed[i1] = pbSeed0[i1];
    pbSeed[i1 + cbKeySize] = pbSeed0[i1];
  }

  if(bDecryptFlag)
  {
    for(cb1=0; cb1 < cbData; cb1++)
    {
      i1 = (int)(cb1 % cbKeySize);

      BYTE bSeed = (BYTE)_calc_crc16((LPCSTR)pbSeed + i1, cbKeySize);
      BYTE bVal = lpData[cb1];

      if(bTableSize)
        lpData[cb1] = lpDict[dwTableSize + ((int)bSeed % bTableSize) * 256 + bVal];
      else
        lpData[cb1] = lpDict[dwTableSize + (int)bSeed * 256 + bVal];

      pbSeed[i1] = bVal;  // NOTE:  encrypted value
      pbSeed[cbKeySize + i1] = bVal;
    }
  }
  else
  {
    for(cb1=0; cb1 < cbData; cb1++)
    {
      i1 = (int)(cb1 % cbKeySize);

      BYTE bSeed = (BYTE)_calc_crc16((LPCSTR)pbSeed + i1, cbKeySize);
      BYTE bVal;

      if(bTableSize)
        bVal = lpDict[((int)bSeed % bTableSize) * 256 + lpData[cb1]];
      else
        bVal = lpDict[(int)bSeed * 256 + lpData[cb1]];

      lpData[cb1] = bVal;  // encrypted

      pbSeed[i1] = bVal;  // NOTE:  encrypted value
      pbSeed[cbKeySize + i1] = bVal;
    }
  }


  // now, fix up "pbSeed"

  int i2 = (cbData % cbKeySize);  // offset to "next set of keys"

  for(i1=0; i1 < cbKeySize; i1++)
  {
    pbSeed0[i1] = pbSeed[i1 + i2];
  }

  delete[] pbSeed;
}




inline UINT _calc_crc16_byte(UINT crc, BYTE bVal)
{
int i2;

  for(i2=0; i2 < 8; i2++)
  {
    if(bVal & 0x80)  // would set carry
    {
      if(crc & 0x8000)  // would set carry
      {
        crc = (crc << 1) + 1;  // need to 'rcl' (so bit 0 is set)
      }
      else
      {
        crc = ((crc << 1) + 1) ^ 0x1021;
      }
    }
    else
    {
      if(crc & 0x8000)  // would set carry
      {
        crc = (crc << 1) ^ 0x1021;
      }
      else
      {
        crc = crc << 1;
      }
    }

    bVal = bVal << 1;
  }

  return(crc);
}


UINT _calc_crc16(LPCSTR source, UINT size)
{
WORD crc = 0 /* 0xffffL */;
DWORD count;

  // ths was turned into a checksum...

  for(count=0; count < size; count++)
  {
    crc += (unsigned char)source[count];
    if(crc >= 0x100)
    {
      crc = ((crc + 1) & 0xff);
    }

//    crc = _calc_crc16_byte(crc, source[count]);
  }

  return(crc);

}


void EncryptDataStream2(const BYTE *lpDict, LPBYTE lpData, UINT cbData,
                        BYTE *pbSeed0, UINT cbKeySize,
                        BOOL bDecryptFlag /* = FALSE */,
                        BYTE bTableSize /* = 0 */)
{
  UINT cb1;
  int i1, i2, i3,
      iTableSize = (bTableSize ? bTableSize : 256);  // max index
  DWORD dwTableSize = 256 * (DWORD)iTableSize;       // # of bytes


  BYTE *pbSeed = new BYTE[(int)(cbKeySize * 2)];

  if(!pbSeed)
  {
    return;  // for now, just return
  }

  // make local copy of byte array (input key)

  for(i1=0; i1 < cbKeySize; i1++)
  {
    pbSeed[i1] = pbSeed0[i1];
    pbSeed[i1 + cbKeySize] = pbSeed0[i1];
  }

  if(bDebug)
  {
    fprintf(stderr, "pbSeed[] = {");

    for(i1=0; i1 < cbKeySize * 2; i1++)
    {
      fprintf(stderr, "%02x", pbSeed[i1]);
    }

    fprintf(stderr, "}\n");
  }

  for(cb1=0; cb1 < cbData; cb1++)
  {
    BYTE bVal, bSeed;

    i1 = (int)(cb1 % cbKeySize);

    for(i2=0, i3=0; i2 < cbKeySize; i2++)
    {
      i3 += pbSeed[i1 + i2];
    }

    bSeed = (BYTE)((i3 & 0xff) + ((i3 >> 8) & 0xff));

    // NOW, do it again, this time encrypting the values using
    // 'bSeed' as the encryption key.
    // NOTE:  this may be a clue to a public key method.... encrypt
    //        one way, decrypt the other (?)

    for(i2=0, i3=0; i2 < cbKeySize; i2++)
    {
      int iIndex;
      if(bTableSize)
        iIndex = ((unsigned int)bSeed % bTableSize) * 256 + pbSeed[i1 + i2];
      else
        iIndex = (unsigned int)bSeed * 256 + pbSeed[i1 + i2];

      bSeed = lpDict[iIndex];

      i3 += bSeed;
    }

    bSeed = (BYTE)((i3 & 0xff) + ((i3 >> 8) & 0xff));

    if(bDecryptFlag)
    {
      BYTE bVal = lpData[cb1];

      if(bTableSize)
        lpData[cb1] = lpDict[dwTableSize + ((int)bSeed % bTableSize) * 256 + bVal];
      else
        lpData[cb1] = lpDict[dwTableSize + (int)bSeed * 256 + bVal];

      pbSeed[i1] = bVal;  // NOTE:  encrypted value
      pbSeed[cbKeySize + i1] = bVal;
    }
    else
    {
      if(bTableSize)
        bVal = lpDict[((int)bSeed % bTableSize) * 256 + lpData[cb1]];
      else
        bVal = lpDict[(int)bSeed * 256 + lpData[cb1]];

      lpData[cb1] = bVal;  // encrypted

      pbSeed[i1] = bVal;  // NOTE:  encrypted value
      pbSeed[cbKeySize + i1] = bVal;
    }
  }

  // now, fix up "pbSeed" so I can make consecutive calls...

  i2 = (cbData % cbKeySize);  // offset to "next set of keys"

  for(i1=0; i1 < cbKeySize; i1++)
  {
    pbSeed0[i1] = pbSeed[i1 + i2];
  }

  delete[] pbSeed;
}

