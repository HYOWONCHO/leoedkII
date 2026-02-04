/********************************************************************************
 * Copyright (C) 2024 by Security Platform Inc.                                 *
 * This file is part of the SBC Project.                                        *
 *                                                                              *
 * This software contains confidential and proprietary information of           *
 * Security Platform Inc. Unauthorized reproduction, distribution, or           *
 * disclosure of this software, in whole or in part, is strictly prohibited.    *
 ********************************************************************************/

/**
 * @file SBC_Log.c
 * @brief Logging utility implementation for SBC system modules 
 *
 * @author LEON
 * @version 1.0
 * @date 2025-10-31
 *
 * @copyright (c) 2025 Security Platform Inc. All rights
 *            reserved.
 *
 * @details
 */

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>       // For UnicodeSPrint (used internally by my _LogFmtVPrint)
#include <Library/BaseMemoryLib.h>  // For ZeroMem, SetMem
#include <Library/DebugLib.h>       // For DEBUG macros
#include <Library/UefiRuntimeServicesTableLib.h> // For gRT->GetTime
//#include <Library/SafeStringLib.h>  // For StrnCpyS, StrnLenS, UnicodeStrToAsciiStrS etc. (EDK II safe string functions)


#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Protocol/LoadedImage.h>
#include "SBC_Log.h"


SBC_LOG_CTX gLogCtx;

#ifndef FMT_INT64_DFORMAT
#define FMT_INT64_DFORMAT   L"ll"   // For signed decimal 64-bit
#endif

#ifndef FMT_UINT64_DFORMAT
#define FMT_UINT64_DFORMAT  L"ll"   // For unsigned decimal 64-bit
#endif

#ifndef FMT_UINT64_XFORMAT
#define FMT_UINT64_XFORMAT  L"ll"   // For hexadecimal 64-bit
#endif

// For 32-bit (if needed)
#ifndef FMT_INT32_DFORMAT
#define FMT_INT32_DFORMAT   L""     // int is default
#endif

#ifndef FMT_UINT32_DFORMAT
#define FMT_UINT32_DFORMAT  L""
#endif

#ifndef FMT_UINT32_XFORMAT
#define FMT_UINT32_XFORMAT  L""
#endif

// Define a suitable max print buffer size via PCD or a fixed constant
// This should match your EDK II PCD for PcdUefiLibMaxPrintBufferSize if you use it.
#ifndef PcdGet32
#define PcdGet32(TokenName)   8192 // Default if PCD is not defined
#endif

CHAR16 str_log_format[8192];

// Global string literals for safety (in case of NULL input pointers)
CONST CHAR16 * CONST gNullStringUefi  = L"(null)"; // For Unicode strings (%s)
CONST CHAR8  * CONST gNullStringAscii = "(null)"; // For ASCII strings (%a)
CONST CHAR16 * CONST gEmptyStringUefi = L"";       // For empty Unicode strings

// Dummy for external functions (replace with your actual implementations)
extern UINTN remove_all_space(CHAR8 *buffer, UINTN buffer_size_in_bytes);
extern EFI_STATUS _sbc_write_log_file(CHAR8 *log_data, UINTN length_in_bytes);

// ===========================================================================
// Helper Functions (UnicodeStrLen, UnicodeStrToAsciiStrS - adapted for safety)
// EDK II provides these in SafeStringLib, but if you need to roll your own:
// ===========================================================================

#define LINE_LEN 16
void SBC_mem_print_bin(
        CHAR8 *title /**< [in] display name strings */,
        UINT8* buffer /**< [in] print buffer  */,
        UINT32 length /**< [in] length of buffer */
        )
{
#ifdef _DEBUG_PRINT_ON_
    SBC_external_mem_print_bin(title,buffer,length);
#else
    (VOID)title;
    (VOID)buffer;
    (VOID)length;
#endif
    return;
}


void SBC_external_mem_print_bin(
        CHAR8 *title /**< [in] display name strings */,
        UINT8* buffer /**< [in] print buffer  */,
        UINT32 length /**< [in] length of buffer */
        )
{
#if defined(_DEBUG_PRINT_ON_) || defined(_SHELL_CMD_LINE_)
    UINT32 i, j; //, sz;
    //UINT32 offset = 0;

    if(title) {
        DEBUG((DEBUG_INFO,"%a (length of buffer: %d) \r\r\n", title, length)) ;
    }

    if (!buffer) {
        return;
    }

    for (i = 0 ; i < length; i+= 16) {
        Print(L"%08x ", i);

        // Print the hex bytes 
        for (j = 0; j < 16; j++) {
            if (i + j < length) {
                Print(L"%02x ", buffer[i + j]);
            }
            else {
                Print(L"   ");
            }

            if ( j == 7 ) {
                Print(L" ");
            }
        }

        // Ascii separator
        Print(L" |");

        // Ascii character 
        for (j = 0; j < 16 && (i+j) < length; j++) {
            CHAR16  c = (CHAR16)buffer[i + j];
            if ( c >= 0x20 && c <= 0x7E ) {
                Print(L"%c",c);
            }
            else {
                Print(L".");
            }
        }

        Print(L"|\n");


    }



#else
    (VOID)title;
    (VOID)buffer;
    (VOID)length;
#endif

    return;
}

#ifdef _USECASE_TEST_
void _uc_mem_print_bin(
        CHAR8 *title /**< [in] display name strings */,
        UINT8* buffer /**< [in] print buffer  */,
        UINT32 length /**< [in] length of buffer */
        )
{
    UINT32 i, sz;
    UINT32 offset = 0;

    if(title) {
        DEBUG((DEBUG_INFO,"%a (length of buffer: %d) \r\r\n", title, length)) ;
    }

    if (!buffer) {
        return;
    }

    while (length > 0) {
        sz = length;
        if (sz > LINE_LEN)
            sz = LINE_LEN;

        DEBUG((DEBUG_INFO," [0x%08X] :  ", offset));
        for (i = 0; i < LINE_LEN; i++) {
            if (i < length)
                DEBUG((DEBUG_INFO,"%02x ", buffer[i]));
            else
                DEBUG((DEBUG_INFO,"   "));
        }
        DEBUG((DEBUG_INFO," | "));
        for (i = 0; i < sz; i++) {
            if (buffer[i] > 31 && buffer[i] < 127)
                DEBUG((DEBUG_INFO,"%c", buffer[i]));
            else
                DEBUG((DEBUG_INFO,"."));
        }
        offset += LINE_LEN;
        DEBUG((DEBUG_INFO,"\r\n"));


        buffer += sz;
        length -= sz;
    }

    return;
}
#endif

VOID SBC_LogElapsedTime(const CHAR16 *Tag, UINTN Ns)
{
    CHAR16 Buf[128] = {0, };
    double Ms = (double)Ns / 1.0e6; // conver to ns to ms

    UINTN int_part = (UINTN)Ms;
    UINTN frac_part = (UINTN)((Ms - (double)int_part) * 1000); // three-digit decimal
    UnicodeSPrint(Buf, 
                  sizeof(Buf),
                  L"[TIME] %s: %lu ns (%u.%03u ms)\n",
                  Tag,
                  (UINTN)Ns,
                  int_part,
                  frac_part);

    DEBUG((DEBUG_INFO,"%s", Buf)); 

}

UINTN
_LogFmtVPrint(
  IN CONST CHAR16 *Format,
  IN VA_LIST      VaListMaker, // The original VA_LIST
  IN OUT CHAR16   *LogBuf,     // Buffer to write into (CHAR16 array)
  IN UINTN        BufLenBytes  // Remaining buffer size in BYTES
  )
{
  CONST CHAR16      *Fmt;
  CHAR16            *Dest;
  UINTN             PrintedChars = 0;
  UINTN             RemainingBufChars;
//VA_LIST           CurrentVaList; // Use a copy to iterate
//
//// Make a copy of the VA_LIST for safe iteration within this function.
//// VA_COPY is preferred for portability, but direct assignment often works.
//#ifdef VA_COPY
//////dprint();
//VA_COPY(CurrentVaList, VaListMaker);
//#else
//////dprint();
//CurrentVaList = VaListMaker;
//#endif

  Fmt = Format;
  Dest = LogBuf;
  RemainingBufChars = BufLenBytes / sizeof(CHAR16);

  ////dprint();
  // Leave at least one CHAR16 for the null terminator.
  if (RemainingBufChars == 0) {
      goto Exit;
  }

  ////dprint();
  // Loop through the format string
  while (*Fmt != L'\0' && RemainingBufChars > 1) {
    if (*Fmt != L'%') {
      *Dest++ = *Fmt++;
      PrintedChars++;
      RemainingBufChars--;
      continue;
    }

    ////dprint();

    // Found a '%', now parse the specifier and arguments
    Fmt++; // Skip '%'

    // Simple parsing for flags, width, precision, length modifiers
    // This is a minimalist set; PrintLib's internal v_snprintf_unicode is far more robust.
    BOOLEAN PadWithZero = FALSE;
    BOOLEAN LeftJustify = FALSE;
    UINTN   Width = 0;
    UINTN   Precision = MAX_UINTN; // Unlimited precision by default
    BOOLEAN Long = FALSE; // %l, %ll, %L (used for size modifiers)

    ////dprint();
    // Parse flags
    while (TRUE) {
      if (*Fmt == L'-') { LeftJustify = TRUE; }
      else if (*Fmt == L'0') { PadWithZero = TRUE; }
      else { break; }
      Fmt++;
    }

    ////dprint();
    // Parse width
    if (*Fmt == L'*') {
      Width = VA_ARG(VaListMaker, UINTN);
      Fmt++;
    } else {
      while ((*Fmt >= L'0') && (*Fmt <= L'9')) {
        Width = Width * 10 + (*Fmt - L'0');
        Fmt++;
      }
    }

    ////dprint();

    // Parse precision
    if (*Fmt == L'.') {
      Fmt++;
      if (*Fmt == L'*') {
        Precision = VA_ARG(VaListMaker, UINTN);
        Fmt++;
      } else {
        Precision = 0; // Default precision if no number follows '.'
        while ((*Fmt >= L'0') && (*Fmt <= L'9')) {
          Precision = Precision * 10 + (*Fmt - L'0');
          Fmt++;
        }
      }
    }

    ////dprint();
    // Parse length modifiers
    if ((*Fmt == L'l') || (*Fmt == L'L')) {
      Long = TRUE; // Indicate a 'long' argument size
      Fmt++;
      if (*Fmt == L'l') { // For %ll (long long)
          Fmt++;
      }
    } else if ((*Fmt == L'h')) { // For %h (short)
        Fmt++;
        if (*Fmt == L'h') { // For %hh (char)
            Fmt++;
        }
    }

    ////dprint();

    UINTN CharsWrittenForSpecifier = 0;
    UINTN RemainingBytesForSpecifier = RemainingBufChars * sizeof(CHAR16);

    switch (*Fmt) {
      case L's': // Unicode string (CHAR16*)
      {
        ////dprint();
        CONST CHAR16 *StringArg = VA_ARG(VaListMaker, CONST CHAR16*);
        ////dprint();
        // *** THE CRITICAL NULL CHECK ***
        if (StringArg == NULL) {
          StringArg = gNullStringUefi; // Substitute with safe "(null)" string
        }
        // Use UnicodeSPrint for the segment to handle padding, width, precision for strings
        CharsWrittenForSpecifier = UnicodeSPrint(Dest, RemainingBytesForSpecifier, L"%s", StringArg);
        break;
      }
      case L'a': // ASCII string (CHAR8*) - needs conversion
      {
        ////dprint();
        CONST CHAR8 *AsciiArg = VA_ARG(VaListMaker, CONST CHAR8*);
        CHAR8 TempAsciiBuf[PcdGet32(PcdUefiLibMaxPrintBufferSize) + 1]; // Temp buffer for ASCII string
        UINTN AsciiLen;
        ////dprint();

        if (AsciiArg == NULL) {
          AsciiArg = gNullStringAscii; // Substitute with safe "(null)"
        }
        // Safely copy ASCII to temp buffer, truncate if needed for ASCII buffer
        AsciiLen = AsciiStrCpyS(TempAsciiBuf, sizeof(TempAsciiBuf), AsciiArg);
        
        // Apply precision for ASCII strings before converting to Unicode
        if (Precision != MAX_UINTN && AsciiLen > Precision) {
            AsciiLen = Precision;
            TempAsciiBuf[AsciiLen] = '\0'; // Truncate
        }

        // Now convert temp ASCII to Unicode char by char into the destination
        UINTN Count = 0;
        CHAR16 PadChar = PadWithZero ? L'0' : L' ';

        // Handle right-justification (padding before string)
        if (Width > AsciiLen && !LeftJustify) {
            for (UINTN i = 0; i < Width - AsciiLen && RemainingBufChars > (PrintedChars + Count + 1); i++) {
                Dest[Count++] = PadChar;
            }
        }
        // Copy characters
        for (UINTN i = 0; i < AsciiLen && RemainingBufChars > (PrintedChars + Count + 1); i++) {
          Dest[Count++] = (CHAR16)TempAsciiBuf[i];
        }
        // Handle left-justification (padding after string)
        if (Width > AsciiLen && LeftJustify) {
            for (UINTN i = 0; i < Width - AsciiLen && RemainingBufChars > (PrintedChars + Count + 1); i++) {
                Dest[Count++] = PadChar;
            }
        }
        CharsWrittenForSpecifier = Count;
        break;
      }
      case L'd': // Signed decimal integer
      case L'i':
      {
        ////dprint();
        INTN Val = (Long ? VA_ARG(VaListMaker, INT64) : VA_ARG(VaListMaker, INTN));
        ////dprint();
        CharsWrittenForSpecifier = UnicodeSPrint(Dest, RemainingBytesForSpecifier, L"%" FMT_INT64_DFORMAT L"d", Val);
        break;
      }
      case L'u': // Unsigned decimal integer
      {
        ////dprint();
        UINTN Val = (Long ? VA_ARG(VaListMaker, UINT64) : VA_ARG(VaListMaker, UINTN));
        ////dprint();
        CharsWrittenForSpecifier = UnicodeSPrint(Dest, RemainingBytesForSpecifier, L"%" FMT_UINT64_DFORMAT L"u", Val);
        break;
      }
      case L'x': // Hexadecimal lowercase
      {
        ////dprint();
        UINTN Val = (Long ? VA_ARG(VaListMaker, UINT64) : VA_ARG(VaListMaker, UINTN));
        ////dprint();
        CharsWrittenForSpecifier = UnicodeSPrint(Dest, RemainingBytesForSpecifier, L"%" FMT_UINT64_XFORMAT L"x", Val);
        break;
      }
      case L'X': // Hexadecimal uppercase
      {
        ////dprint();
        UINTN Val = (Long ? VA_ARG(VaListMaker, UINT64) : VA_ARG(VaListMaker, UINTN));
        ////dprint();
        CharsWrittenForSpecifier = UnicodeSPrint(Dest, RemainingBytesForSpecifier, L"%" FMT_UINT64_XFORMAT L"X", Val);
        break;
      }
      case L'p': // Pointer address (hex)
      {
        ////dprint();
        VOID *Ptr = VA_ARG(VaListMaker, VOID*);
        ////dprint();
        CharsWrittenForSpecifier = UnicodeSPrint(Dest, RemainingBytesForSpecifier, L"%p", Ptr);
        break;
      }
      case L'c': // Unicode character
      {
        ////dprint();
        CHAR16 CharVal = (CHAR16)VA_ARG(VaListMaker, UINTN); // Char args are promoted to int
        ////dprint();
        *Dest = CharVal;
        CharsWrittenForSpecifier = 1;
        break;
      }
      case L'%': // Literal '%'
        ////dprint();
        *Dest = L'%';
        CharsWrittenForSpecifier = 1;
        break;
      default: // Unrecognized specifier, print literally
        ////dprint();
        *Dest++ = L'%';
        *Dest++ = *Fmt;
        PrintedChars += 2; // Adjust immediately as we wrote directly
        RemainingBufChars -= 2;
        goto NextFmtChar; // Skip common update at end of switch
    }
    
    ////dprint();
    // Update pointers and counts after processing a specifier
    Dest += CharsWrittenForSpecifier;
    PrintedChars += CharsWrittenForSpecifier;
    RemainingBufChars -= CharsWrittenForSpecifier;

NextFmtChar:
    ////dprint();
    Fmt++; // Move to next char in format string
  }

  *Dest = L'\0'; // Null-terminate the buffer
  
Exit:
  ////dprint();
  VA_END(VaListMaker); // Clean up the copied VA_LIST
  ////dprint();
  return PrintedChars;
}


UINTN SBC_LogHexToStrChar8( UINT8 *data, UINTN len, CHAR8 *out, UINTN out_cap, BOOLEAN loweracse, CHAR8 sep)
{
    CHAR8 HEXU16[] = "0123456789ABCDEF";
    CHAR8 HEXL16[] = "0123456789abcdef";
    CHAR8 *HEX = loweracse ? HEXL16 : HEXU16;
    UINTN need = (sep ? (len ? (len * 2 + (len - 1)) : 0) : (len * 2)) + 1; // +1 for L'\0'
    dprint("out cap : %d , need : %d", out_cap, need);
    if (out_cap < need) {
        return 0;
    }

    UINTN pos = 0;
    for (UINTN i = 0; i < len; i++) {
        UINT8 b = data[i];
        out[pos++] = HEX[(b >> 4) & 0xFF];
        out[pos++] = HEX[b & 0x0F];
        if (sep && i + 1 < len) {
            out[pos++] = sep;
        }
    }

    out[pos] = L'\0';
    return pos;
}

UINTN SBC_LogHexToStrChar16( UINT8 *data, UINTN len, CHAR16 *out, UINTN out_cap, BOOLEAN loweracse, CHAR16 sep)
{
    CHAR16 HEXU16[] = L"0123456789ABCDEF";
    CHAR16 HEXL16[] = L"0123456789abcdef";
    CHAR16 *HEX = loweracse ? HEXL16 : HEXU16;
    UINTN need = (sep ? (len ? (len * 2 + (len - 1)) : 0) : (len * 2)) + 1; // +1 for L'\0'
    //dprint("out cap : %d , need : %d", out_cap, need);
    if (out_cap < need) {
        return 0;
    }

    UINTN pos = 0;
    for (UINTN i = 0; i < len; i++) {
        UINT8 b = data[i];
        out[pos++] = HEX[(b >> 4) & 0xFF];
        out[pos++] = HEX[b & 0x0F];
        if (sep && i + 1 < len) {
            out[pos++] = sep;
        }
    }

    out[pos] = L'\0';
    return pos;
}

EFI_STATUS 
SBC_BuildHexFormattedMessage (
  IN  CONST VOID  *PubKey,
  IN  UINTN        PubKeySize,
  IN  CONST CHAR16 *FormatString,
  OUT CHAR16      *OutMsg,
  IN  UINTN        OutMsgBytes
  )
{
  if (PubKey == NULL || PubKeySize == 0 ||
      FormatString == NULL || OutMsg == NULL ||
      OutMsgBytes < sizeof(CHAR16)) {
    return EFI_INVALID_PARAMETER;
  }

//SBC_mem_print_bin("SBC_BuildHexFormattedMessage original",
//                  (UINT8 *)PubKey,
//                  (UINT32)PubKeySize);

  // %s 자리가 존재하는지 간단 검증 (선택사항)
  if (StrStr(FormatString, L"%s") == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  const UINTN HexChars = PubKeySize * 2;
  const UINTN HexBytes = (HexChars + 1) * sizeof(CHAR16);

  CHAR16 *HexStr = AllocateZeroPool(HexBytes);
  if (HexStr == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  // 바이너리 → HEX 문자열 변환
  SBC_LogHexToStrChar16(
      (VOID *)PubKey,
      PubKeySize,
      HexStr,
      HexChars + 1,
      FALSE,   // 대문자/소문자 구분 옵션
      0
  );

//SBC_mem_print_bin("SBC_BuildHexFormattedMessage Hex",
//                  (UINT8 *)HexStr,
//                  (UINT32)HexChars + 1);
  ZeroMem(OutMsg, OutMsgBytes);

  // 포맷 문자열과 HEX 문자열을 합침
  UnicodeSPrint(
      OutMsg,
      OutMsgBytes,
      FormatString,
      HexStr
  );

//Print(L"OutMsg (%ld) : %s\n",OutMsgBytes, OutMsg);

  FreePool(HexStr);
  return EFI_SUCCESS;
}


/**
  Converts a Null-terminated Unicode string to a Null-terminated ASCII string.
  (Similar to UnicodeStrToAsciiStrS in EDK II's SafeStringLib)

  @param  Destination   A pointer to the buffer to store the ASCII string.
  @param  DestinationSize The size in bytes of the Destination buffer.
  @param  Source        A pointer to the Null-terminated Unicode string.

  @retval The length of the converted ASCII string (not including null terminator).
          Returns 0 if Source is NULL, or DestinationSize is too small for null terminator.
          Truncates if Source is too long.
**/
UINTN
MyUnicodeStrToAsciiStrS (
  OUT CHAR8        *Destination,
  IN  UINTN        DestinationSize, // Size in bytes
  IN  CONST CHAR16 *Source
  )
{
  UINTN Index;

  if (Destination == NULL || Source == NULL || DestinationSize == 0) {
    DEBUG ((DEBUG_ERROR, "MyUnicodeStrToAsciiStrS: Invalid input parameters.\n"));
    return 0;
  }

  // Ensure there's space for the null terminator
  if (DestinationSize < 1) {
    return 0;
  }

  for (Index = 0; Index < (DestinationSize - 1) && Source[Index] != L'\0'; Index++) {
    // Only convert if the Unicode character is within ASCII range
    if (Source[Index] > 0xFF) {
      Destination[Index] = '?'; // Replace non-ASCII with '?'
      DEBUG ((DEBUG_WARN, "MyUnicodeStrToAsciiStrS: Non-ASCII char 0x%x replaced with '?'.\n", Source[Index]));
    } else {
      Destination[Index] = (CHAR8)Source[Index];
    }
  }
  Destination[Index] = '\0'; // Null-terminate the ASCII string

  return Index; // Return length without null terminator
}

//
// Added by Leon
//


static
VOID
SbcLogZeroCtx(IN OUT SBC_LOG_CTX *Ctx)
{
    if (!Ctx) return;
    SetMem(Ctx, sizeof(*Ctx), 0);
}

static
EFI_STATUS
SbcLogEnsureFileOpen(IN OUT SBC_LOG_CTX *Ctx)
{
    EFI_STATUS Status;

    if (!Ctx || !Ctx->Ready) {
        Print(L"SbcLogEnsureFileOpen NOT READY \n");
        return EFI_NOT_READY;
    }
    if (Ctx->File) {
        Print(L"SbcLogEnsureFileOpen Ctx->File already open \n");
        return EFI_SUCCESS;
    }

    // Try open existing for READ|WRITE (append)
    Status = Ctx->Root->Open(
                    Ctx->Root,
                    &Ctx->File,
                    Ctx->FilePath,
                    EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE,
                    0
                );
    if (!EFI_ERROR(Status)) {
        Print(L"Seek EOF for append \n");
        Status = Ctx->File->SetPosition(Ctx->File, (UINT64)-1);
        if (EFI_ERROR(Status)) {
            Print(L"SetPosition fail : %r \n", Status);
            Ctx->File->Close(Ctx->File);
            Ctx->File = NULL;
            return Status;
        }

        return EFI_SUCCESS;
    }

    Print(L"If not found, create it \n");
    if (Status == EFI_NOT_FOUND) {
        Print(L"%s file not found, so it's create \n",Ctx->FilePath);
        Status = Ctx->Root->Open(
                        Ctx->Root,
                        &Ctx->File,
                        Ctx->FilePath,
                        EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                        0
                    );
        if (EFI_ERROR(Status)) {
            Print(L"%a   file create fail (%r) \n", Ctx->FilePath, Status);
            return Status;
        }

        Status = Ctx->File->SetPosition(Ctx->File, (UINT64)-1);
        if (EFI_ERROR(Status)) {
            Print(L"2. SetPosition fail : %r \n", Status);
            Ctx->File->Close(Ctx->File);
            Ctx->File = NULL;
            return Status;
        }
        return EFI_SUCCESS;
    }

    return Status;
}

static
EFI_STATUS
SbcLogBufAppend(IN OUT SBC_LOG_CTX *Ctx, IN CONST CHAR8 *Data, IN UINTN Len)
{
    EFI_STATUS Status;

    if (!Ctx || !Ctx->Ready) {
        Print(L"SbcLogBufAppend NOT ready( ctx : %p, ready : %d) \n", Ctx, Ctx->Ready);
        return EFI_NOT_READY;
    }
    if (!Data || Len == 0) {
        Print(L"SbcLogBufAppend Data : %p, Message Len :%lu \n", Data, Len);
        return EFI_SUCCESS;
    }

    // If single message bigger than buffer: flush existing, then write directly.
    //Print(L"Len :%lu, BufCap : %lu \n", Len, Ctx->BufCap);
    if (Len > Ctx->BufCap) {
        
        Status = SBC_LogFlush(Ctx);
        if (EFI_ERROR(Status)) {
            Print(L"SBC_LogFlush call fail \n");
            return Status;
        }

        Status = SbcLogEnsureFileOpen(Ctx);
        if (EFI_ERROR(Status)) {
            Print(L"SbcLogEnsureFileOpen call fail \n");
            return Status;
        }

        UINTN W = Len;
        Print(L"SbcLogBufAppend Ctx->File->Write ... \n");
        Status = Ctx->File->Write(Ctx->File, &W, (VOID*)Data);
        if (EFI_ERROR(Status)) {
            Print(L"Ctx->File->Write fail (%r) \n", Status);
        }
        return Status;
    }

    // If not enough space: flush first

    //Print(L"Len :%lu, BufCap : %lu \n", Ctx->BufLen + Len , Ctx->BufCap);
    if (Ctx->BufLen + Len > Ctx->BufCap) {
        Print(L"SBC_LogFlush .... \n");
        Status = SBC_LogFlush(Ctx);
        if (EFI_ERROR(Status))  {
            Print(L"2.. SBC_LogFlush call fail \n");
            return Status;
        }
    }

    CopyMem(Ctx->Buf + Ctx->BufLen, Data, Len);
    Ctx->BufLen += Len;
    return EFI_SUCCESS;
}

EFI_STATUS
SBC_LogInit(
    OUT SBC_LOG_CTX   *Ctx,
    IN  EFI_HANDLE     FsHandle,
    IN  CONST CHAR16  *LogPath,
    IN  UINTN          BufferSize
)
{
    EFI_STATUS Status = EFI_SUCCESS;

    Print(L"SSBL Log Init sttart ( path : %s ) \n", LogPath);

    if (Ctx == NULL || FsHandle == NULL || LogPath == NULL) {
        Print(L"Log init invalid parameter \n");
        return EFI_INVALID_PARAMETER;
    }

    SbcLogZeroCtx(Ctx);

    Ctx->FsHandle = FsHandle;

    Status = gBS->HandleProtocol(
                    FsHandle,
                    &gEfiSimpleFileSystemProtocolGuid,
                    (VOID**)&Ctx->SimpleFs
                );
    if (EFI_ERROR(Status) || Ctx->SimpleFs == NULL) {
        Print(L"gBS->HandleProtocol failed \n");
        goto Exit;
    }

    Status = Ctx->SimpleFs->OpenVolume(Ctx->SimpleFs, &Ctx->Root);
    if (EFI_ERROR(Status) || Ctx->Root == NULL) {
        Print(L"Ctx->SimpleFs->OpenVolume failed \n");
        goto Exit;
    }

    Ctx->FilePath = AllocateCopyPool(StrSize(LogPath), LogPath);
    if (Ctx->FilePath == NULL) {
        Print(L"Ctx->FilePath = AllocateCopyPool out of resource \n");
        Status = EFI_OUT_OF_RESOURCES;
        goto Exit;
    }
    Print(L"Copy File Path : %s, %s \n", Ctx->FilePath, LogPath );

    if (BufferSize == 0)
        BufferSize = SBC_LOG_DEFAULT_BUF_SIZE;

    Ctx->Buf = AllocateZeroPool(BufferSize);
    if (Ctx->Buf == NULL) {
        Print(L"Ctx->Buf = AllocateZeroPool out of resource \n");
        Status = EFI_OUT_OF_RESOURCES;
        goto Exit;
    }

    Ctx->BufCap = BufferSize;
    Ctx->BufLen = 0;

    // If you want to fail-fast for write-protected / path errors, enable this.
    // Status = SbcLogEnsureFileOpen(Ctx);
    // if (EFI_ERROR(Status)) goto Exit;

    Ctx->Ready = TRUE;

    Print(L" SBC_LogInit success \n");
    return EFI_SUCCESS;

Exit:
    // Ensure Ready is false on failure
    Ctx->Ready = FALSE;

    if (Ctx->File) {
        Ctx->File->Close(Ctx->File);
        Ctx->File = NULL;
    }
    if (Ctx->Root) {
        Ctx->Root->Close(Ctx->Root);
        Ctx->Root = NULL;
    }
    if (Ctx->Buf) {
        FreePool(Ctx->Buf);
        Ctx->Buf = NULL;
        Ctx->BufCap = 0;
        Ctx->BufLen = 0;
    }
    if (Ctx->FilePath) {
        FreePool(Ctx->FilePath);
        Ctx->FilePath = NULL;
    }

    // Keep FsHandle/SimpleFs as-is or clear; usually clear to avoid stale pointers.
    Ctx->FsHandle = NULL;
    Ctx->SimpleFs = NULL;

    Print(L" SBC_LogInit Fail \n");
    return Status;
}

static
EFI_STATUS
SBC_FindAnyWritableSimpleFsHandle(
    OUT EFI_HANDLE *OutFsHandle
)
{
    if (OutFsHandle == NULL)
        return EFI_INVALID_PARAMETER;

    *OutFsHandle = NULL;

    EFI_STATUS Status;
    EFI_HANDLE *Handles = NULL;
    UINTN Count = 0;

    Status = gBS->LocateHandleBuffer(
                    ByProtocol,
                    &gEfiSimpleFileSystemProtocolGuid,
                    NULL,
                    &Count,
                    &Handles
             );
    if (EFI_ERROR(Status) || Handles == NULL || Count == 0) {
        Print(L"Log Handle not found : %r\n", Status);
        return EFI_NOT_FOUND;
    }

    // Pick the first FS that can open volume (you can add better selection logic)
    for (UINTN i = 0; i < Count; i++) {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs = NULL;
        EFI_FILE_PROTOCOL *Root = NULL;

        Status = gBS->HandleProtocol(
                        Handles[i],
                        &gEfiSimpleFileSystemProtocolGuid,
                        (VOID**)&Fs
                 );
        if (EFI_ERROR(Status) || Fs == NULL)
            continue;

        Status = Fs->OpenVolume(Fs, &Root);
        if (!EFI_ERROR(Status) && Root != NULL) {
            Root->Close(Root);
            *OutFsHandle = Handles[i];
            Print(L"Out FsHandle : %p \n", *OutFsHandle);
            break;
        }
    }

    FreePool(Handles);
    return (*OutFsHandle != NULL) ? EFI_SUCCESS : EFI_NOT_FOUND;
}

EFI_STATUS
SBC_LogInitAuto(
    OUT SBC_LOG_CTX   *Ctx,
    IN  EFI_HANDLE     ImageHandle,
    IN  CONST CHAR16  *LogPath,
    IN  UINTN          BufferSize,
    OUT EFI_HANDLE    *OutFsHandle OPTIONAL
)
{
    EFI_STATUS Status;
    EFI_LOADED_IMAGE_PROTOCOL *LoadedImage = NULL;
    EFI_HANDLE FsHandle = NULL;

    Print(L"SSBL SBC_LogInitAuto start\n");

    if (Ctx == NULL || ImageHandle == NULL || LogPath == NULL) {
        Print(L"EFI_INVALID_PARAMETER\n");
        return EFI_INVALID_PARAMETER;
    }

    Status = gBS->HandleProtocol(
                    ImageHandle,
                    &gEfiLoadedImageProtocolGuid,
                    (VOID**)&LoadedImage
             );
    if (EFI_ERROR(Status) || LoadedImage == NULL || LoadedImage->DeviceHandle == NULL) {
        Print(L"LoadedImage not available\n");
        return EFI_UNSUPPORTED;
    }

    //
    // 1) First try: use LoadedImage->DeviceHandle directly
    //
    {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs = NULL;
        Status = gBS->HandleProtocol(
                        LoadedImage->DeviceHandle,
                        &gEfiSimpleFileSystemProtocolGuid,
                        (VOID**)&Fs
                 );
        if (!EFI_ERROR(Status) && Fs != NULL) {
            FsHandle = LoadedImage->DeviceHandle;
        }
    }

    //
    // 2) Fallback: scan any SimpleFS handle
    //
    if (FsHandle == NULL) {
        Status = SBC_FindAnyWritableSimpleFsHandle(&FsHandle);
        if (EFI_ERROR(Status) || FsHandle == NULL) {
            Print(L"SBC_FindAnyWritableSimpleFsHandle No SimpleFS handle found\n");
            return EFI_NOT_FOUND;
        }

        Print(L"FsHandle : %p \n", FsHandle);
    }

    if (OutFsHandle)
        *OutFsHandle = FsHandle;

    return SBC_LogInit(Ctx, FsHandle, LogPath, BufferSize);
}

EFI_STATUS
SBC_LogWrite16(
    IN OUT SBC_LOG_CTX  *Ctx,
    IN     CONST CHAR16 *Msg
)
{
    EFI_STATUS Status;

    //Print(L"%a \n", __FUNCTION__);
    if (!Ctx || !Ctx->Ready || !Msg) {
        Print(L"LogWrite16 EFI_NOT_READY \n");
        return EFI_INVALID_PARAMETER;
    }

    // Convert CHAR16 -> ASCII into a temporary buffer
    // Worst-case allocate (Len*3 + 2) like you did, but WRITE only actual length.
    UINTN ULen = StrLen((CHAR16*)Msg);
    if (ULen == 0) {
        Print(L"Message Length is %lu \n", ULen);
        return EFI_SUCCESS;
    }

    UINTN AsciiCap = (ULen * 3) + 2; // + newline space
    //Print(L"AsciiCap : %lu \n", AsciiCap);
    CHAR8 *Tmp = AllocateZeroPool(AsciiCap);
    if (!Tmp) {
        Print(L"EFI_OUT_OF_RESOURCES \n");
        return EFI_OUT_OF_RESOURCES;
    }

    // Safe conversion. Non-ASCII will become '?'
    UnicodeStrToAsciiStrS((CHAR16*)Msg, Tmp, AsciiCap);

    UINTN Actual = AsciiStrLen(Tmp); // IMPORTANT: write actual bytes only
    //Print(L"write actual : %a (%lu) \n", Tmp, Actual);
    Status = SbcLogBufAppend(Ctx, Tmp, Actual);
    if (!EFI_ERROR(Status)) {

        // Append newline
        //Print(L"Append newline \n");
        CHAR8 NL = '\n';
        Status = SbcLogBufAppend(Ctx, &NL, 1);
    }
    else {
        Print(L"SbcLogBufAppend fail \n");
    }

    if (EFI_ERROR(Status)) {
        Print(L"Append New line fail \n");
    }

    FreePool(Tmp);
    return Status;
}

EFI_STATUS
SBC_LogFlush(
    IN OUT SBC_LOG_CTX *Ctx
)
{
    EFI_STATUS Status;

    if (!Ctx || !Ctx->Ready) {
        Print(L"LogFlush EFI_NOT_READY \n");
        return EFI_NOT_READY;
    }
    if (Ctx->BufLen == 0) {
        Print(L"LogFlush BufLen 0 \n");
        return EFI_SUCCESS;
    }

    Status = SbcLogEnsureFileOpen(Ctx);
    if (EFI_ERROR(Status)) {
        Print(L"SbcLogEnsureFileOpen fail \n");
        return Status;
    }

    UINTN W = Ctx->BufLen;
    Print(L"SBC_LogFlush Ctx->File->Write ... \n");
    Status = Ctx->File->Write(Ctx->File, &W, Ctx->Buf);
    if (EFI_ERROR(Status)) {
        Print(L"Log write fail (%r) \n", Status);
        return Status;
    }

    // Optional: flush to media (some FS honor it, some ignore)
    Ctx->File->Flush(Ctx->File);

    // Reset buffer
    Ctx->BufLen = 0;
    SetMem(Ctx->Buf, Ctx->BufCap, 0);

    return EFI_SUCCESS;
}

VOID
SBC_LogDeinit(
    IN OUT SBC_LOG_CTX *Ctx
)
{
    if (!Ctx) return;

    // Best-effort flush
    if (Ctx->Ready) {
        (VOID)SBC_LogFlush(Ctx);
    }

    if (Ctx->File) {
        Ctx->File->Close(Ctx->File);
        Ctx->File = NULL;
    }
    if (Ctx->Root) {
        Ctx->Root->Close(Ctx->Root);
        Ctx->Root = NULL;
    }
    if (Ctx->Buf) {
        FreePool(Ctx->Buf);
        Ctx->Buf = NULL;
    }
    if (Ctx->FilePath) {
        FreePool(Ctx->FilePath);
        Ctx->FilePath = NULL;
    }

    SbcLogZeroCtx(Ctx);
}

// ===========================================================================
// SBC_LogPrint (Main Logging Function)
// ===========================================================================
//SBC_LOG_CTX *gLogWriteCtx;
//
//VOID SBC_SetLogWriteCtxHndl(VOID *ctx)
//{
//    gLogWriteCtx = (SBC_LOG_CTX *)ctx;
//}


VOID SBC_LogPrint(
  CONST CHAR16* func,     // For [%s:%d] if uncommented (CHAR16*)
  UINT32 funcline,        // For [%s:%d] if uncommented
  UINT32 prio,            // Priority
  UINT32 ver,             // Version (e.g., event version)
  CHAR16 *host,           // Hostname or system identifier (potentially NULL)
  CHAR16 *appname,        // Application name (potentially NULL)
  CHAR16 *csc,            // Custom field (e.g., Component Specific Code, potentially NULL)
  UINT32 sfrid,           // Specific Function/Event ID
  CHAR16 *evtype,         // Event Type string (potentially NULL)
  CHAR16 *format,         // Format string for the message body (can contain %s, %d etc.)
  ...
  )
{
    EFI_STATUS retval;
    VA_LIST args;
    EFI_TIME logtime;
    
    // Buffer for the full Unicode log message. Size in CHAR16s.
    CHAR16 full_log_msg[PcdGet32 (PcdUefiLibMaxPrintBufferSize) + 1]; 
    UINTN nxtofs = 0; // Current offset in CHAR16s
    UINTN remaining_buffer_bytes;
    
    // Calculate total buffer size in bytes for safer print functions
    UINTN max_full_log_msg_bytes = sizeof(full_log_msg);

    //dprint("SBC_LogPrint: Log buf size in CHAR16s: %d (Bytes: %d)\n",
    //                     PcdGet32(PcdUefiLibMaxPrintBufferSize) + 1, max_full_log_msg_bytes);
    
    ZeroMem(full_log_msg, max_full_log_msg_bytes); // Clear the buffer
    ZeroMem(&logtime, sizeof(EFI_TIME)); // Clear time struct

    ////dprint();
    retval = gRT->GetTime(&logtime, NULL);
    if (EFI_ERROR(retval)) {
      // Fallback if time retrieval fails (e.g., set to a fixed epoch or default)
      logtime.Year = 2000;
      logtime.Month = 1;
      logtime.Day = 1;
      logtime.Hour = 0;
      logtime.Minute = 0;
      logtime.Second = 0;
      logtime.Nanosecond = 0;
      // Also set timezone and DaylightSaving if needed
    }

    ////dprint();

    // --- Safely handle potentially NULL CHAR16* arguments for the header ---
    // These pointers are passed directly to UnicodeSPrint, which itself is safe.
    // However, explicitly ensuring non-NULL pointers is good practice and clear.
    [[maybe_unused]] CONST CHAR16 *safe_func    = (func != NULL) ? func : gEmptyStringUefi; // If func is CHAR16*
    CONST CHAR16 *safe_host    = (host != NULL) ? host : gNullStringUefi;
    CONST CHAR16 *safe_appname = (appname != NULL) ? appname : gNullStringUefi;
    CONST CHAR16 *safe_csc     = (csc != NULL) ? csc : gNullStringUefi;
    CONST CHAR16 *safe_evtype  = (evtype != NULL) ? evtype : gNullStringUefi;

    remaining_buffer_bytes = max_full_log_msg_bytes;

    // Optional: Prepend function name and line number
    // Assuming 'func' is a CHAR16* as per your signature.
    // If 'func' was CHAR8*, you would use %a or convert it first.
    // nxtofs += UnicodeSPrint(
    //             full_log_msg + nxtofs,
    //             remaining_buffer_bytes,
    //             L"[%s:%d] ", // Added space after ]
    //             safe_func, funcline
    //             );
    // remaining_buffer_bytes -= (nxtofs * sizeof(CHAR16));


    ////dprint();
    // --- Construct the main header part of the log message ---
    // Format: PRIO VER YYYY-MM-DDTHH:MM:SS HOST APPNAME CSC R-SAT-PWT-SFR-XXX EVTYPE [Message Body]
    // Using %02d for consistent two-digit formatting for month, day, hour, etc.
    nxtofs += UnicodeSPrint(
                full_log_msg + nxtofs,
                remaining_buffer_bytes,
                L"<%d> %d %04d-%02d-%02dT%02d:%02d:%02d %s %s %s R-SAT-PWT-SFR-%03d %s ",
                prio, ver,
                logtime.Year, logtime.Month, logtime.Day,
                logtime.Hour, logtime.Minute, logtime.Second,
                safe_host, safe_appname, safe_csc, // Using the safely handled pointers
                sfrid, safe_evtype
                );

    // Update remaining buffer size in bytes for the next print.
    remaining_buffer_bytes -= (nxtofs * sizeof(CHAR16));
    
    ////dprint();
    // Ensure we have at least some space left for the message body and null terminator
    if (remaining_buffer_bytes <= sizeof(CHAR16) * 4) { // Small space for "..." + NULL
        //dprint("SBC_LogPrint: Buffer almost full before message body. Truncating.\n");
        UnicodeSPrint(full_log_msg + nxtofs, sizeof(CHAR16)*4, L"..."); // Indicate truncation
        return; // Skip to the end
    }

    // --- Message body (variable part) ---
    VA_START(args, format);
    ////dprint();
    // Call the enhanced _LogFmtVPrint, which now handles NULL CHAR16* arguments safely.
#if 0
    nxtofs += SBC_InternalPrint(format,
                                args);
#else
    nxtofs += _LogFmtVPrint(
                format, // The format string for the variable arguments
                args,
                full_log_msg + nxtofs, // Start writing from current offset
                remaining_buffer_bytes   // Remaining buffer size in bytes
                );
#endif
    VA_END(args);

    // --- Final null-termination and length check ---
    // _LogFmtVPrint should null-terminate, but being explicit for the overall buffer.
    // Ensure the final message length does not exceed the total buffer capacity.
    if (nxtofs >= PcdGet32(PcdUefiLibMaxPrintBufferSize)) {
        // Truncate if necessary and ensure final null-termination
        full_log_msg[PcdGet32(PcdUefiLibMaxPrintBufferSize)] = L'\0';
    } else {
        full_log_msg[nxtofs] = L'\0'; // Explicit null termination
    }

    // --- Post-processing and output ---
    // Convert the full Unicode log message to ASCII for file/network output
    // Assuming `remove_all_space` and `_sbc_write_log_file` expect ASCII CHAR8*.
    CHAR8  AsciiLogBuffer[PcdGet32 (PcdUefiLibMaxPrintBufferSize) + 1]; // One byte per CHAR16 (safe for ASCII range)
    UINTN  AsciiConvertedLen;

    AsciiConvertedLen = MyUnicodeStrToAsciiStrS(AsciiLogBuffer, sizeof(AsciiLogBuffer), full_log_msg);
    if (AsciiConvertedLen == 0 && full_log_msg[0] != L'\0') {
        DEBUG ((DEBUG_ERROR, "SBC_LogPrint: Failed to convert Unicode log to ASCII or buffer too small.\n"));
        // Handle conversion error, maybe log truncated msg or error to console
        Print(L"WARNING: ASCII conversion failed for log. Unicode content: %s\n", full_log_msg);
        goto ExitLog;
    }


    Print(L"%s\n", full_log_msg);

#if 1
#ifdef _LOG_RECODING_
        SBC_LogWrite16(&gLogCtx, full_log_msg);
#endif
#else
    {
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *SimpleFs;
        EFI_FILE_PROTOCOL *Root;
        EFI_FILE_PROTOCOL *File;
        EFI_STATUS Status;

        UINTN AsciiLen = StrLen(full_log_msg) * 3 + 1;
        
        CHAR8 *AsciiBuf = AllocateZeroPool(AsciiLen);
        UnicodeStrToAsciiStrS(full_log_msg, AsciiBuf, AsciiLen);
        //dprint();
//      Status = gBS->HandleProtocol(
//                      write_log_handle,
//                      &gEfiSimpleFileSystemProtocolGuid,
//                      (VOID**)&SimpleFs
//                  );

        Status = gBS->LocateProtocol(&gEfiSimpleFileSystemProtocolGuid, NULL, (VOID**)&SimpleFs);
        if (!EFI_ERROR(Status)) {

            Status = SimpleFs->OpenVolume(SimpleFs, &Root);
            if (!EFI_ERROR(Status)) {

                // Open file for append (READ | WRITE). Do NOT use CREATE.
                Status = Root->Open(
                            Root,
                            &File,
                            SSBL_LOG_PATH,
                            EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE,
                            0
                        );

                if (!EFI_ERROR(Status)) {
                    //dprint();
                    // Move cursor to end for append
                    File->SetPosition(File, (UINT64)-1);

                    // Write ASCII buffer
//                  UINTN WriteLen = final_ascii_len;
//                  File->Write(File, &WriteLen, wrlog_ptr);
                    UINTN WriteLen = AsciiLen;
                    File->Write(File, &WriteLen, AsciiBuf);
                    // Add newline
                    CHAR8 NewLine[2] = { '\n', 0 };
                    UINTN NL = 1;
                    File->Write(File, &NL, NewLine);

                    File->Close(File);
                }
                else {

                    dprint();
                    eprint("Log File Open fail (%r) ", Status);
                }

                Root->Close(Root);
            }
            else {

                dprint();
                eprint("Log File OpenVolume fail (%r) ", Status);
            }
        }

        FreePool(AsciiBuf);
    }
#endif


ExitLog:
    return;
}

