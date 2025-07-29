#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>       // For UnicodeSPrint (used internally by my _LogFmtVPrint)
#include <Library/BaseMemoryLib.h>  // For ZeroMem, SetMem
#include <Library/DebugLib.h>       // For DEBUG macros
#include <Library/UefiRuntimeServicesTableLib.h> // For gRT->GetTime
//#include <Library/SafeStringLib.h>  // For StrnCpyS, StrnLenS, UnicodeStrToAsciiStrS etc. (EDK II safe string functions)

#include "SBC_Log.h"





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
    UINT32 i, sz;

    if(title) {
        Print(L"%a (length of buffer: %d) \r\r\n", title, length) ;
    }

    if (!buffer) {
        Print(L"\tNULL\r\n");
        return;
    }

    while (length > 0) {
        sz = length;
        if (sz > LINE_LEN)
            sz = LINE_LEN;

        Print(L"\t");
        for (i = 0; i < LINE_LEN; i++) {
            if (i < length)
                Print(L"%02x ", buffer[i]);
            else
                Print(L"   ");
        }
        Print(L"| ");
        for (i = 0; i < sz; i++) {
            if (buffer[i] > 31 && buffer[i] < 127)
                Print(L"%c", buffer[i]);
            else
                Print(L".");
        }
        Print(L"\r\r\n");


        buffer += sz;
        length -= sz;
    }
}


void SBC_external_mem_print_bin(
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
}


CHAR16 *SBC_LogMrg(CONST CHAR16 *fmt, ...)
{

  VA_LIST maker;

  VA_START(maker, fmt);

  ZeroMem(str_log_format, sizeof str_log_format);
  UnicodeSPrint(str_log_format, sizeof str_log_format, fmt);

  VA_END(maker);



  return str_log_format;
}

/**
  Returns the length of a Null-terminated Unicode string, up to a specified maximum size.
  (Similar to StrnLenS in EDK II's SafeStringLib)

  @param  String  A pointer to a Null-terminated Unicode string.
  @param  MaxSize The maximum number of Unicode characters to examine.

  @retval 0       If String is NULL or empty.
  @retval Others  The length of String, or MaxSize if the string is longer
                  than MaxSize and no Null-terminator is found.
**/
UINTN
MyUnicodeStrnLenS (
  IN CONST CHAR16  *String,
  IN UINTN         MaxSize
  )
{
  UINTN Length;

  if (String == NULL) {
    DEBUG ((DEBUG_ERROR, "MyUnicodeStrnLenS: Input String is NULL.\n"));
    return 0;
  }

  for (Length = 0; Length < MaxSize && *String != L'\0'; String++, Length++);

  return Length;
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


// ===========================================================================
// _LogFmtVPrint (The heart of safe variable argument formatting)
// ===========================================================================

/**
  Formats a variable argument list into a Unicode string buffer,
  handling NULL CHAR16* arguments safely.

  This function parses the format string and uses arguments from VaListMaker
  to construct a formatted Unicode string in LogBuf. It performs NULL checks
  for %s specifiers to prevent hard faults.

  @param  Format        The format string.
  @param  VaListMaker   The VA_LIST containing the arguments.
  @param  LogBuf        The destination buffer for the formatted Unicode string.
  @param  BufLenBytes   The remaining size of LogBuf in BYTES.

  @retval The number of CHAR16s written to LogBuf (excluding null terminator).
**/
//UINTN
//_LogFmtVPrint(
//  IN CONST CHAR16 *Format,
//  IN VA_LIST      VaListMaker, // The original VA_LIST
//  IN OUT CHAR16   *LogBuf,     // Buffer to write into (CHAR16 array)
//  IN UINTN        BufLenBytes  // Remaining buffer size in BYTES
//  )
//{
//  CONST CHAR16      *Fmt;
//  CHAR16            *Dest;
//  UINTN             PrintedChars = 0;
//  UINTN             RemainingBufChars;
//  VA_LIST           CurrentVaList; // Use a copy to iterate
//
//  // Make a copy of the VA_LIST for safe iteration within this function.
//  // VA_COPY is preferred for portability, but direct assignment often works.
//  #ifdef VA_COPY
//  //dprint();
//  VA_COPY(CurrentVaList, VaListMaker);
//  #else
//  //dprint();
//  CurrentVaList = VaListMaker;
//  #endif
//
//  Fmt = Format;
//  Dest = LogBuf;
//  RemainingBufChars = BufLenBytes / sizeof(CHAR16);
//
//  //dprint();
//  // Leave at least one CHAR16 for the null terminator.
//  if (RemainingBufChars == 0) {
//      goto Exit;
//  }
//
//  //dprint();
//  // Loop through the format string
//  while (*Fmt != L'\0' && RemainingBufChars > 1) {
//    if (*Fmt != L'%') {
//      *Dest++ = *Fmt++;
//      PrintedChars++;
//      RemainingBufChars--;
//      continue;
//    }
//
//    //dprint();
//
//    // Found a '%', now parse the specifier and arguments
//    Fmt++; // Skip '%'
//
//    // Simple parsing for flags, width, precision, length modifiers
//    // This is a minimalist set; PrintLib's internal v_snprintf_unicode is far more robust.
//    BOOLEAN PadWithZero = FALSE;
//    BOOLEAN LeftJustify = FALSE;
//    UINTN   Width = 0;
//    UINTN   Precision = MAX_UINTN; // Unlimited precision by default
//    BOOLEAN Long = FALSE; // %l, %ll, %L (used for size modifiers)
//
//    //dprint();
//    // Parse flags
//    while (TRUE) {
//      if (*Fmt == L'-') { LeftJustify = TRUE; }
//      else if (*Fmt == L'0') { PadWithZero = TRUE; }
//      else { break; }
//      Fmt++;
//    }
//
//    //dprint();
//    // Parse width
//    if (*Fmt == L'*') {
//      Width = VA_ARG(CurrentVaList, UINTN);
//      Fmt++;
//    } else {
//      while ((*Fmt >= L'0') && (*Fmt <= L'9')) {
//        Width = Width * 10 + (*Fmt - L'0');
//        Fmt++;
//      }
//    }
//
//    //dprint();
//
//    // Parse precision
//    if (*Fmt == L'.') {
//      Fmt++;
//      if (*Fmt == L'*') {
//        Precision = VA_ARG(CurrentVaList, UINTN);
//        Fmt++;
//      } else {
//        Precision = 0; // Default precision if no number follows '.'
//        while ((*Fmt >= L'0') && (*Fmt <= L'9')) {
//          Precision = Precision * 10 + (*Fmt - L'0');
//          Fmt++;
//        }
//      }
//    }
//
//    //dprint();
//    // Parse length modifiers
//    if ((*Fmt == L'l') || (*Fmt == L'L')) {
//      Long = TRUE; // Indicate a 'long' argument size
//      Fmt++;
//      if (*Fmt == L'l') { // For %ll (long long)
//          Fmt++;
//      }
//    } else if ((*Fmt == L'h')) { // For %h (short)
//        Fmt++;
//        if (*Fmt == L'h') { // For %hh (char)
//            Fmt++;
//        }
//    }
//
//    //dprint();
//
//    UINTN CharsWrittenForSpecifier = 0;
//    UINTN RemainingBytesForSpecifier = RemainingBufChars * sizeof(CHAR16);
//
//    switch (*Fmt) {
//      case L's': // Unicode string (CHAR16*)
//      {
//        //dprint();
//        CONST CHAR16 *StringArg = VA_ARG(CurrentVaList, CONST CHAR16*);
//        //dprint();
//        // *** THE CRITICAL NULL CHECK ***
//        if (StringArg == NULL) {
//          StringArg = gNullStringUefi; // Substitute with safe "(null)" string
//        }
//        // Use UnicodeSPrint for the segment to handle padding, width, precision for strings
//        CharsWrittenForSpecifier = UnicodeSPrint(Dest, RemainingBytesForSpecifier, L"%s", StringArg);
//        break;
//      }
//      case L'a': // ASCII string (CHAR8*) - needs conversion
//      {
//        //dprint();
//        CONST CHAR8 *AsciiArg = VA_ARG(CurrentVaList, CONST CHAR8*);
//        CHAR8 TempAsciiBuf[PcdGet32(PcdUefiLibMaxPrintBufferSize) + 1]; // Temp buffer for ASCII string
//        UINTN AsciiLen;
//        //dprint();
//
//        if (AsciiArg == NULL) {
//          AsciiArg = gNullStringAscii; // Substitute with safe "(null)"
//        }
//        // Safely copy ASCII to temp buffer, truncate if needed for ASCII buffer
//        AsciiLen = AsciiStrCpyS(TempAsciiBuf, sizeof(TempAsciiBuf), AsciiArg);
//
//        // Apply precision for ASCII strings before converting to Unicode
//        if (Precision != MAX_UINTN && AsciiLen > Precision) {
//            AsciiLen = Precision;
//            TempAsciiBuf[AsciiLen] = '\0'; // Truncate
//        }
//
//        // Now convert temp ASCII to Unicode char by char into the destination
//        UINTN Count = 0;
//        CHAR16 PadChar = PadWithZero ? L'0' : L' ';
//
//        // Handle right-justification (padding before string)
//        if (Width > AsciiLen && !LeftJustify) {
//            for (UINTN i = 0; i < Width - AsciiLen && RemainingBufChars > (PrintedChars + Count + 1); i++) {
//                Dest[Count++] = PadChar;
//            }
//        }
//        // Copy characters
//        for (UINTN i = 0; i < AsciiLen && RemainingBufChars > (PrintedChars + Count + 1); i++) {
//          Dest[Count++] = (CHAR16)TempAsciiBuf[i];
//        }
//        // Handle left-justification (padding after string)
//        if (Width > AsciiLen && LeftJustify) {
//            for (UINTN i = 0; i < Width - AsciiLen && RemainingBufChars > (PrintedChars + Count + 1); i++) {
//                Dest[Count++] = PadChar;
//            }
//        }
//        CharsWrittenForSpecifier = Count;
//        break;
//      }
//      case L'd': // Signed decimal integer
//      case L'i':
//      {
//        //dprint();
//        INTN Val = (Long ? VA_ARG(CurrentVaList, INT64) : VA_ARG(CurrentVaList, INTN));
//        //dprint();
//        CharsWrittenForSpecifier = UnicodeSPrint(Dest, RemainingBytesForSpecifier, L"%" FMT_INT64_DFORMAT L"d", Val);
//        break;
//      }
//      case L'u': // Unsigned decimal integer
//      {
//        //dprint();
//        UINTN Val = (Long ? VA_ARG(CurrentVaList, UINT64) : VA_ARG(CurrentVaList, UINTN));
//        //dprint();
//        CharsWrittenForSpecifier = UnicodeSPrint(Dest, RemainingBytesForSpecifier, L"%" FMT_UINT64_DFORMAT L"u", Val);
//        break;
//      }
//      case L'x': // Hexadecimal lowercase
//      {
//        //dprint();
//        UINTN Val = (Long ? VA_ARG(CurrentVaList, UINT64) : VA_ARG(CurrentVaList, UINTN));
//        //dprint();
//        CharsWrittenForSpecifier = UnicodeSPrint(Dest, RemainingBytesForSpecifier, L"%" FMT_UINT64_XFORMAT L"x", Val);
//        break;
//      }
//      case L'X': // Hexadecimal uppercase
//      {
//        //dprint();
//        UINTN Val = (Long ? VA_ARG(CurrentVaList, UINT64) : VA_ARG(CurrentVaList, UINTN));
//        //dprint();
//        CharsWrittenForSpecifier = UnicodeSPrint(Dest, RemainingBytesForSpecifier, L"%" FMT_UINT64_XFORMAT L"X", Val);
//        break;
//      }
//      case L'p': // Pointer address (hex)
//      {
//        //dprint();
//        VOID *Ptr = VA_ARG(CurrentVaList, VOID*);
//        //dprint();
//        CharsWrittenForSpecifier = UnicodeSPrint(Dest, RemainingBytesForSpecifier, L"%p", Ptr);
//        break;
//      }
//      case L'c': // Unicode character
//      {
//        //dprint();
//        CHAR16 CharVal = (CHAR16)VA_ARG(CurrentVaList, UINTN); // Char args are promoted to int
//        //dprint();
//        *Dest = CharVal;
//        CharsWrittenForSpecifier = 1;
//        break;
//      }
//      case L'%': // Literal '%'
//        //dprint();
//        *Dest = L'%';
//        CharsWrittenForSpecifier = 1;
//        break;
//      default: // Unrecognized specifier, print literally
//        //dprint();
//        *Dest++ = L'%';
//        *Dest++ = *Fmt;
//        PrintedChars += 2; // Adjust immediately as we wrote directly
//        RemainingBufChars -= 2;
//        goto NextFmtChar; // Skip common update at end of switch
//    }
//
//    //dprint();
//    // Update pointers and counts after processing a specifier
//    Dest += CharsWrittenForSpecifier;
//    PrintedChars += CharsWrittenForSpecifier;
//    RemainingBufChars -= CharsWrittenForSpecifier;
//
//NextFmtChar:
//    //dprint();
//    Fmt++; // Move to next char in format string
//  }
//
//  *Dest = L'\0'; // Null-terminate the buffer
//
//Exit:
//  //dprint();
//  VA_END(CurrentVaList); // Clean up the copied VA_LIST
//  //dprint();
//  return PrintedChars;
//}


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
////dprint();
//VA_COPY(CurrentVaList, VaListMaker);
//#else
////dprint();
//CurrentVaList = VaListMaker;
//#endif

  Fmt = Format;
  Dest = LogBuf;
  RemainingBufChars = BufLenBytes / sizeof(CHAR16);

  //dprint();
  // Leave at least one CHAR16 for the null terminator.
  if (RemainingBufChars == 0) {
      goto Exit;
  }

  //dprint();
  // Loop through the format string
  while (*Fmt != L'\0' && RemainingBufChars > 1) {
    if (*Fmt != L'%') {
      *Dest++ = *Fmt++;
      PrintedChars++;
      RemainingBufChars--;
      continue;
    }

    //dprint();

    // Found a '%', now parse the specifier and arguments
    Fmt++; // Skip '%'

    // Simple parsing for flags, width, precision, length modifiers
    // This is a minimalist set; PrintLib's internal v_snprintf_unicode is far more robust.
    BOOLEAN PadWithZero = FALSE;
    BOOLEAN LeftJustify = FALSE;
    UINTN   Width = 0;
    UINTN   Precision = MAX_UINTN; // Unlimited precision by default
    BOOLEAN Long = FALSE; // %l, %ll, %L (used for size modifiers)

    //dprint();
    // Parse flags
    while (TRUE) {
      if (*Fmt == L'-') { LeftJustify = TRUE; }
      else if (*Fmt == L'0') { PadWithZero = TRUE; }
      else { break; }
      Fmt++;
    }

    //dprint();
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

    //dprint();

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

    //dprint();
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

    //dprint();

    UINTN CharsWrittenForSpecifier = 0;
    UINTN RemainingBytesForSpecifier = RemainingBufChars * sizeof(CHAR16);

    switch (*Fmt) {
      case L's': // Unicode string (CHAR16*)
      {
        //dprint();
        CONST CHAR16 *StringArg = VA_ARG(VaListMaker, CONST CHAR16*);
        //dprint();
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
        //dprint();
        CONST CHAR8 *AsciiArg = VA_ARG(VaListMaker, CONST CHAR8*);
        CHAR8 TempAsciiBuf[PcdGet32(PcdUefiLibMaxPrintBufferSize) + 1]; // Temp buffer for ASCII string
        UINTN AsciiLen;
        //dprint();

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
        //dprint();
        INTN Val = (Long ? VA_ARG(VaListMaker, INT64) : VA_ARG(VaListMaker, INTN));
        //dprint();
        CharsWrittenForSpecifier = UnicodeSPrint(Dest, RemainingBytesForSpecifier, L"%" FMT_INT64_DFORMAT L"d", Val);
        break;
      }
      case L'u': // Unsigned decimal integer
      {
        //dprint();
        UINTN Val = (Long ? VA_ARG(VaListMaker, UINT64) : VA_ARG(VaListMaker, UINTN));
        //dprint();
        CharsWrittenForSpecifier = UnicodeSPrint(Dest, RemainingBytesForSpecifier, L"%" FMT_UINT64_DFORMAT L"u", Val);
        break;
      }
      case L'x': // Hexadecimal lowercase
      {
        //dprint();
        UINTN Val = (Long ? VA_ARG(VaListMaker, UINT64) : VA_ARG(VaListMaker, UINTN));
        //dprint();
        CharsWrittenForSpecifier = UnicodeSPrint(Dest, RemainingBytesForSpecifier, L"%" FMT_UINT64_XFORMAT L"x", Val);
        break;
      }
      case L'X': // Hexadecimal uppercase
      {
        //dprint();
        UINTN Val = (Long ? VA_ARG(VaListMaker, UINT64) : VA_ARG(VaListMaker, UINTN));
        //dprint();
        CharsWrittenForSpecifier = UnicodeSPrint(Dest, RemainingBytesForSpecifier, L"%" FMT_UINT64_XFORMAT L"X", Val);
        break;
      }
      case L'p': // Pointer address (hex)
      {
        //dprint();
        VOID *Ptr = VA_ARG(VaListMaker, VOID*);
        //dprint();
        CharsWrittenForSpecifier = UnicodeSPrint(Dest, RemainingBytesForSpecifier, L"%p", Ptr);
        break;
      }
      case L'c': // Unicode character
      {
        //dprint();
        CHAR16 CharVal = (CHAR16)VA_ARG(VaListMaker, UINTN); // Char args are promoted to int
        //dprint();
        *Dest = CharVal;
        CharsWrittenForSpecifier = 1;
        break;
      }
      case L'%': // Literal '%'
        //dprint();
        *Dest = L'%';
        CharsWrittenForSpecifier = 1;
        break;
      default: // Unrecognized specifier, print literally
        //dprint();
        *Dest++ = L'%';
        *Dest++ = *Fmt;
        PrintedChars += 2; // Adjust immediately as we wrote directly
        RemainingBufChars -= 2;
        goto NextFmtChar; // Skip common update at end of switch
    }
    
    //dprint();
    // Update pointers and counts after processing a specifier
    Dest += CharsWrittenForSpecifier;
    PrintedChars += CharsWrittenForSpecifier;
    RemainingBufChars -= CharsWrittenForSpecifier;

NextFmtChar:
    //dprint();
    Fmt++; // Move to next char in format string
  }

  *Dest = L'\0'; // Null-terminate the buffer
  
Exit:
  //dprint();
  VA_END(VaListMaker); // Clean up the copied VA_LIST
  //dprint();
  return PrintedChars;
}


// ===========================================================================
// SBC_LogPrint (Main Logging Function)
// ===========================================================================

VOID
SBC_LogPrint(
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

    //dprint();
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

    //dprint();

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


    //dprint();
    // --- Construct the main header part of the log message ---
    // Format: PRIO VER YYYY-MM-DDTHH:MM:SS HOST APPNAME CSC R-SAT-PWT-SFR-XXX EVTYPE [Message Body]
    // Using %02d for consistent two-digit formatting for month, day, hour, etc.
    nxtofs += UnicodeSPrint(
                full_log_msg + nxtofs,
                remaining_buffer_bytes,
                L"%d %d %04d-%02d-%02dT%02d:%02d:%02d %s %s %s R-SAT-PWT-SFR-%03d %s ",
                prio, ver,
                logtime.Year, logtime.Month, logtime.Day,
                logtime.Hour, logtime.Minute, logtime.Second,
                safe_host, safe_appname, safe_csc, // Using the safely handled pointers
                sfrid, safe_evtype
                );

    // Update remaining buffer size in bytes for the next print.
    remaining_buffer_bytes -= (nxtofs * sizeof(CHAR16));
    
    //dprint();
    // Ensure we have at least some space left for the message body and null terminator
    if (remaining_buffer_bytes <= sizeof(CHAR16) * 4) { // Small space for "..." + NULL
        //dprint("SBC_LogPrint: Buffer almost full before message body. Truncating.\n");
        UnicodeSPrint(full_log_msg + nxtofs, sizeof(CHAR16)*4, L"..."); // Indicate truncation
        return; // Skip to the end
    }

    // --- Message body (variable part) ---
    VA_START(args, format);
    //dprint();
    // Call the enhanced _LogFmtVPrint, which now handles NULL CHAR16* arguments safely.
    nxtofs += _LogFmtVPrint(
                format, // The format string for the variable arguments
                args,
                full_log_msg + nxtofs, // Start writing from current offset
                remaining_buffer_bytes   // Remaining buffer size in bytes
                );
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

    // Now wrlog points to a proper ASCII string
    CHAR8 *wrlog_ptr = AsciiLogBuffer; 
    
    // Print for debug (both Unicode and ASCII for comparison)
    //dprint("SBC_LogPrint: Full Unicode Log msg : %s \n", full_log_msg);
    //dprint("SBC_LogPrint: Full ASCII Log msg   : %a (Length: %d) \n", wrlog_ptr, AsciiConvertedLen);

    // Call your remove_all_space function (expects ASCII CHAR8*)
    // It should modify wrlog_ptr in place and return the new length.
    // Make sure remove_all_space works on a null-terminated string and updates length correctly.
    UINTN final_ascii_len = remove_all_space(wrlog_ptr, AsciiConvertedLen); // Pass converted length, not full buffer size

    //dprint("SBC_LogPrint: ASCII Log msg after space removal: %a (Final Length: %d)\n", wrlog_ptr, final_ascii_len);

    // _sbc_write_log_file expects CHAR8* and its strlen.
    _sbc_write_log_file(wrlog_ptr, final_ascii_len);

ExitLog:
    return;
}

// ===========================================================================
// Dummy External Functions (Replace with your actual implementations)
// ===========================================================================

// Replace with your actual implementation that removes spaces from an ASCII buffer
UINTN remove_all_space(CHAR8 *buffer, UINTN buffer_size_in_bytes) {
    if (buffer == NULL || buffer_size_in_bytes == 0) {
        return 0;
    }
    UINTN  read_idx = 0;
    UINTN  write_idx = 0;
    while (read_idx < buffer_size_in_bytes && buffer[read_idx] != '\0') {
        if (buffer[read_idx] != ' ') {
            buffer[write_idx++] = buffer[read_idx];
        }
        read_idx++;
    }
    buffer[write_idx] = '\0'; // Null-terminate the new string
    return write_idx; // Return new length
}

// Replace with your actual implementation for writing to a log file or sending over network
EFI_STATUS _sbc_write_log_file(CHAR8 *log_data, UINTN length_in_bytes) {
    if (log_data == NULL || length_in_bytes == 0) {
        DEBUG ((DEBUG_ERROR, "SysLog: No data to write or invalid length.\n"));
        return EFI_INVALID_PARAMETER;
    }
    // For demonstration, just print to console as ASCII
    Print(L"SysLog_OUTPUT (ASCII): %a\n", log_data);

    // --- Placeholder for actual network (UDP) sending ---
    // EFI_STATUS Status;
    // EFI_UDP4_PROTOCOL *gUdp4 = NULL; // Get this protocol instance elsewhere
    // EFI_IP4_CONFIG_PROTOCOL *gIp4Config = NULL; // Get this protocol instance elsewhere
    // UINT32 SyslogServerIp = 0xC0A8010A; // Example: 192.168.1.10
    // UINT16 SyslogServerPort = 514;
    //
    // // Initialize UDP, configure IP, etc. (complex setup not shown)
    // // Status = gBS->LocateProtocol(&gEfiUdp4ProtocolGuid, NULL, (VOID **)&gUdp4);
    // // if (!EFI_ERROR(Status) && gUdp4 != NULL) {
    // //     EFI_UDP4_TRANSMIT_DATA TxData;
    // //     ZeroMem(&TxData, sizeof(TxData));
    // //     TxData.DestinationAddress.Addr[0] = (UINT8)(SyslogServerIp >> 24);
    // //     ...
    // //     TxData.FragmentCount = 1;
    // //     TxData.Fragment[0].FragmentLength = (UINT32)length_in_bytes;
    // //     TxData.Fragment[0].FragmentBuffer = log_data;
    // //     Status = gUdp4->Transmit(gUdp4, &TxData);
    // // }
    //
    // --- Placeholder for actual file writing ---
    // EFI_STATUS Status;
    // EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *gFs = NULL; // Get this protocol instance elsewhere
    // EFI_FILE_PROTOCOL *LogFile = NULL;
    //
    // // Locate file system protocol (e.g., on ESP or USB)
    // // Status = gBS->LocateProtocol(&gEfiSimpleFileSystemProtocolGuid, NULL, (VOID **)&gFs);
    // // if (!EFI_ERROR(Status) && gFs != NULL) {
    // //     // Open root directory
    // //     EFI_FILE_PROTOCOL *Root = NULL;
    // //     Status = gFs->OpenVolume(gFs, &Root);
    // //     if (!EFI_ERROR(Status) && Root != NULL) {
    // //         // Open or create log file
    // //         Status = Root->Open(Root, &LogFile, L"\\SysLog.log", EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
    // //         if (!EFI_ERROR(Status) && LogFile != NULL) {
    // //             // Seek to end and write
    // //             LogFile->SetPosition(LogFile, EFI_MAX_UINT64); // Seek to end
    // //             LogFile->Write(LogFile, &length_in_bytes, log_data);
    // //             LogFile->Close(LogFile);
    // //         }
    // //         Root->Close(Root);
    // //     }
    // // }

    return EFI_SUCCESS;
}
#if 0
#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UnitTestLib.h>
#include <Library/UefiLib.h>
//#include <Libray/RngLib.h>

#include <Library/BaseLib.h>
#include <Library/PrintLib.h>
#include <Library/HandleParsingLib.h>
#include <Library/ShellLib.h>

//#include <Library/UefiBootServicesTableLib.h>
//#include <Library/UefiRuntimeServceisTableLib.h>

#include <Library/UefiLib/UefiLibInternal.h>
#include <Library/PcdLib.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "SBC_Log.h"
#include "SBC_FileCtrl.h"

#define UNIT_TEST_MAX_LOG_BUFFER  SIZE_16KB

struct _UNIT_TEST_LOG_PREFIX_STRING {
  UNIT_TEST_STATUS    LogLevel;
  CHAR8               *String;
};

struct _UNIT_TEST_LOG_PREFIX_STRING  mLogPrefixStrings[] = {
  { UNIT_TEST_LOG_LEVEL_ERROR,   "[ERROR]       " },
  { UNIT_TEST_LOG_LEVEL_WARN,    "[WARNING]     " },
  { UNIT_TEST_LOG_LEVEL_INFO,    "[INFO]        " },
  { UNIT_TEST_LOG_LEVEL_VERBOSE, "[VERBOSE]     " }
};

#if 0


static void vcm_print_error(const char* const format, va_list args)
{
    char buffer[1024];
    size_t msg_len = 0;
    va_list ap;
    int len;
    va_copy(ap, args);

    len = vsnprintf(buffer, sizeof(buffer), format, args);
    if (len < 0) {
        /* TODO */
        goto end;
    }

    if (cm_error_message == NULL) {
        /* CREATE MESSAGE */

        cm_error_message = calloc(1, len + 1);
        if (cm_error_message == NULL) {
            /* TODO */
            goto end;
        }
    } else {
        /* APPEND MESSAGE */
        char *tmp;

        msg_len = strlen(cm_error_message);
        tmp = realloc(cm_error_message, msg_len + len + 1);
        if (tmp == NULL) {
            goto end;
        }
        cm_error_message = tmp;
    }

    if (((size_t)len) < sizeof(buffer)) {
        /* Use len + 1 to also copy '\0' */
        memcpy(cm_error_message + msg_len, buffer, len + 1);
    } else {
        vsnprintf(cm_error_message + msg_len, len, format, ap);
    }
end:
    va_end(ap);

}

void _fail(const char * const file, const int line) {
    enum cm_message_output output = cm_get_output();

    switch(output) {
        case CM_OUTPUT_STDOUT:
            cm_print_error("[   LINE   ] --- " SOURCE_LOCATION_FORMAT ": error: Failure!", file, line);
            break;
        default:
            cm_print_error(SOURCE_LOCATION_FORMAT ": error: Failure!", file, line);
            break;
    }
    //exit_test(1);

    /* Unreachable */
    exit(-1);
}

void cm_print_error(const char * const format, ...)
{
    va_list args;
    va_start(args, format);
    if (cm_error_message_enabled) {
        vcm_print_error(format, args);
    } else {
        vprint_error(format, args);
    }
    va_end(args);
}

void _assert_true(const LargestIntegralType result,
                  const char * const expression,
                  const char * const file, const int line) {
    if (!result) {
        cm_print_error("%s\n", expression);
        _fail(file, line);
    }
}


BOOLEAN SBC_Assert(BOOLEAN expression, CONST CHAR8 *funcname, UINTN linenumber, CONST CHAR8 *filename, CONST CHAR8 *description)
{
  CHAR8 tempstr[1025];
  snprintf (tempstr, sizeof (tempstr), "UT_ASSERT_TRUE(%s:%x)", description, expression);
  _assert_true (expression, , temstr, filename, (INT32)linenumber);

  return expression;

}
#endif


VOID SBC_LogBoolean(BOOLEAN expression, CONST CHAR8 *funcname, UINTN linenumber, CONST CHAR8 *filename, CONST CHAR8 *description)
{
  CHAR8 tempstr[1025];
  //snprintf (tempstr, sizeof (tempstr), "UT_ASSERT_TRUE(%s:%x)", description, expression);
  Print(L"%s \n", tempstr);


}



//VOID SBC_LogMsg(/*@unused@*/UINT8* logmsg ARG_UNUSED, CONST CHAR8 *funcname, UINTN linenumber, CONST CHAR8 *filename, CONST CHAR8 *description)
VOID SBC_LogMsg(CHAR8* logmsg , CONST CHAR8 *funcname, UINTN linenumber, CONST CHAR8 *filename)
{
  CHAR16 tempstr[1025] = {0, };
  UnicodeSPrint(tempstr, sizeof (tempstr), L"[%a:%a:%d] %a", filename, funcname, linenumber, logmsg);
  //CHAR8 tempstr[1025] = {0, };
  //snprintf(tempstr, sizeof (tempstr), "%s%s%lld%s", filename, funcname, linenumber, logmsg);
  //DEBUG((DEBUG_INFO, "%a", tempstr));
#if 1
  ShellPrintEx(
      -1,
      -1,
      tempstr,
      L""
      );
#endif




}

//extern EFI_STATUS SBC_LogWriteFile(EFI_HANDLE ImageHandle, CHAR16 *FileNames, LV_t *out);
//extern EFI_STATUS SBC_IsFlieAccess(EFI_HANDLE ImageHandle, CHAR16 *FileNames);
//extern EFI_STATUS SBC_IsDirExist(EFI_HANDLE ImageHandle, CHAR16 *DirName);
//
//
//void _sbc_write_log_file(CHAR8 *message, UINT32 msglen)
//{
//    EFI_STATUS Status;
//    SBCStatus ret = SBCOK;
//    EFI_HANDLE      *hndl = NULL;
//    EFI_HANDLE      loghnd = NULL;
//    UINTN           hndlcnt;
//    LV_t            wrlv;
//
//    CHAR16         *rocky_dir_name = L"\\EFI\\rocky";
//    CHAR16         *sbc_log_fname = L"\\EFI\\rocky\\sbc_fsbl_sys_log";
//
//    EFI_STATUS retval = EFI_SUCCESS;
//
//    hndlcnt = SBC_FindEfiFileSystemProtocol(&hndl);
//
//    ////dprint("Log gEfiSimpleFileSystemProtocolGuid Handle Count :%d ", hndlcnt);
//
//    for (int idx = 0; idx < hndlcnt; idx++) {
//        ////dprint("[idx:%d] handle addr : 0x%x", idx, hndl[idx]);
//        Status = SBC_IsDirExist(hndl[idx], rocky_dir_name);
//        switch (Status) {
//        case EFI_SUCCESS:
//          loghnd=  hndl[idx];
//          ////dprint("%s dir exists \n", rocky_dir_name);
//          break;
//        case EFI_NOT_FOUND:
//          ////dprint("%s dir not found \n", rocky_dir_name);
//          ////dprint();
//          //goto errdone;
//          break;
//        default:
//          //dprint("Unknown error (%s) \n", Status);
//          break;
//        }
//
//    }
//
//    if (loghnd == NULL) {
//        goto errdone;
//    }
//
//    Status = SBC_IsFlieAccess(loghnd, sbc_log_fname);
//    switch (Status) {
//    case EFI_SUCCESS:
//      break;
//    case EFI_NOT_FOUND:
//      // Create File
//      ret = SBC_CreateFile(loghnd, sbc_log_fname);
//      break;
//
//    default:
//      //dprint("Unknown error (%s) \n", Status);
//      goto errdone;
//
//    }
//
//    if (ret != SBCOK) {
//        eprint("log file create fail \n");
//        return;
//    }
//
//
//    wrlv.value = message;
//    wrlv.length = msglen;
//
//    retval = SBC_LogWriteFile(loghnd, sbc_log_fname, &wrlv);
//    if (EFI_ERROR(retval)) {
//        //dprint(" og  write fail (%r) \n",  retval);
//
//    }
//
//
//errdone:
//    return;
//
//}

UINTN
AsciiPrintToBuffer (
  IN  CONST CHAR8 *Format,
  ...
  )
{
 
  return 0;
}

UINTN
SBC_IntToUnicodeStringManual (
  IN INT64        Value,
  OUT CHAR16      *StringBuffer,
  IN UINTN        BufferSize
  )
{
  CHAR16  *Ptr = StringBuffer;
  CHAR16  TempChar;
  UINTN   Count = 0;
  BOOLEAN IsNegative = FALSE;
  UINT64  AbsValue; // 절대값을 저장할 부호 없는 타입

  // 입력 유효성 검사
  if (StringBuffer == NULL || BufferSize == 0) {
    DEBUG((DEBUG_ERROR, "IntToUnicodeStringManual: Invalid input parameters (buffer or size).\n"));
    return 0;
  }

  // 버퍼가 Null-terminator를 포함할 수 있도록 최소 1 CHAR16 공간이 필요합니다.
  if (BufferSize < sizeof(CHAR16)) {
      DEBUG((DEBUG_ERROR, "IntToUnicodeStringManual: Buffer too small for null terminator.\n"));
      return 0;
  }

  // 음수 처리
  if (Value < 0) {
    IsNegative = TRUE;
    AbsValue = (UINT64)(-Value); // 음수의 절대값
  } else {
    AbsValue = (UINT64)Value;
  }

  // 0인 경우 특별 처리
  if (AbsValue == 0) {
    if (BufferSize < 2 * sizeof(CHAR16)) { // '0' + null terminator
        DEBUG((DEBUG_ERROR, "IntToUnicodeStringManual: Buffer too small for '0'.\n"));
        return 0;
    }
    *Ptr++ = L'0';
    Count = 1;
  } else {
    // 숫자를 역순으로 버퍼에 채웁니다.
    while (AbsValue > 0 && Count < (BufferSize / sizeof(CHAR16)) - 1) { // -1 for null terminator
      *Ptr++ = (CHAR16)(L'0' + (AbsValue % 10));
      AbsValue /= 10;
      Count++;
    }
  }

  // 음수인 경우 '-' 부호를 추가합니다.
  if (IsNegative) {
    if (Count < (BufferSize / sizeof(CHAR16)) - 1) { // -1 for null terminator
      *Ptr++ = L'-';
      Count++;
    } else {
      // 버퍼가 너무 작아 음수 부호를 추가할 수 없는 경우
      DEBUG((DEBUG_ERROR, "IntToUnicodeStringManual: Buffer too small for negative sign.\n"));
      // 이 경우 부분적으로 변환된 문자열이 남을 수 있으므로 0을 반환하거나 오류 처리 필요
      // 여기서는 Null-terminator를 추가하고 현재까지의 Count를 반환합니다.
      *Ptr = L'\0';
      return 0; // 또는 Count를 반환하여 부분 변환을 알림
    }
  }

  // Null-terminator 추가
  *Ptr = L'\0';

  // 문자열 역순 정렬
  // 시작 포인터는 StringBuffer, 끝 포인터는 Null-terminator 바로 앞
  CHAR16 *Start = StringBuffer;
  CHAR16 *End = StringBuffer + Count - 1; // Count는 부호까지 포함된 길이

  if (IsNegative) { // 음수인 경우 부호는 그대로 두고 숫자 부분만 역순 정렬
    Start++; // 부호 다음부터 시작
  }

  while (Start < End) {
    TempChar = *Start;
    *Start = *End;
    *End = TempChar;
    Start++;
    End--;
  }

  return Count;
}



EFI_STATUS SBC_CustomPrint (
  IN CONST CHAR16 *Format,
  ...
  )
{
  VA_LIST     Args;
  CHAR16      Buffer[256]; // 출력 버퍼 (충분한 크기 할당)
  CHAR16      *BufferPtr = Buffer;
  CONST CHAR16 *FormatPtr = Format;
  EFI_STATUS  Status = EFI_SUCCESS;
  UINTN       RemainingBufferSize = sizeof(Buffer);

  // 입력 유효성 검사
  if (Format == NULL) {
    DEBUG((DEBUG_ERROR, "MyCustomPrint: Format string is NULL.\n"));
    return EFI_INVALID_PARAMETER;
  }

  // 가변 인자 목록 초기화
  VA_START(Args, Format);

  // 포맷 문자열을 파싱하며 버퍼에 문자열을 구성합니다.
  while (*FormatPtr != L'\0' && RemainingBufferSize > sizeof(CHAR16)) { // Null-terminator 공간 확보
    if (*FormatPtr == L'%') {
      FormatPtr++; // '%' 다음 문자로 이동

      switch (*FormatPtr) {
        case L'd': // 10진수 정수
          {
            INTN Value = VA_ARG(Args, INTN); // 다음 인자를 INTN으로 가져옴
            CHAR16 TempNumBuffer[30]; // 숫자를 문자열로 변환할 임시 버퍼
            UINTN NumChars;

            NumChars = SBC_IntToUnicodeStringManual(Value, TempNumBuffer, sizeof(TempNumBuffer));
            if (NumChars > 0) {
              // 임시 버퍼의 내용을 메인 버퍼로 복사
              UINTN CopySize = NumChars * sizeof(CHAR16);
              if (CopySize < RemainingBufferSize) {
                CopyMem(BufferPtr, TempNumBuffer, CopySize);
                BufferPtr += NumChars;
                RemainingBufferSize -= CopySize;
              } else {
                // 버퍼 오버플로우 처리
                DEBUG((DEBUG_ERROR, "MyCustomPrint: Buffer overflow for %%d.\n"));
                Status = EFI_BUFFER_TOO_SMALL;
                goto Exit; // 오류 발생 시 종료
              }
            }
          }
          break;
        case L's': // 유니코드 문자열
          {
            CHAR16 *Str = VA_ARG(Args, CHAR16*); // 다음 인자를 CHAR16*으로 가져옴
            UINTN StrLen = 0;
            CHAR16 *TempStrPtr = Str;

            if (Str == NULL) {
                Str = L"(null)"; // NULL 포인터 처리
            }

            while (*TempStrPtr != L'\0') {
              StrLen++;
              TempStrPtr++;
            }

            UINTN CopySize = StrLen * sizeof(CHAR16);
            if (CopySize < RemainingBufferSize) {
              CopyMem(BufferPtr, Str, CopySize);
              BufferPtr += StrLen;
              RemainingBufferSize -= CopySize;
            } else {
              // 버퍼 오버플로우 처리
              DEBUG((DEBUG_ERROR, "MyCustomPrint: Buffer overflow for %%s.\n"));
              Status = EFI_BUFFER_TOO_SMALL;
              goto Exit; // 오류 발생 시 종료
            }
          }
          break;
        case L'%': // '%%' 이스케이프 시퀀스
          if (RemainingBufferSize >= 2 * sizeof(CHAR16)) {
            *BufferPtr++ = L'%';
            RemainingBufferSize -= sizeof(CHAR16);
          } else {
            DEBUG((DEBUG_ERROR, "MyCustomPrint: Buffer too small for '%%'.\n"));
            Status = EFI_BUFFER_TOO_SMALL;
            goto Exit;
          }
          break;
        default: // 알 수 없는 포맷 지정자
          DEBUG((DEBUG_INFO,"MyCustomPrint: Unknown format specifier '%%%c'.\n", *FormatPtr));
          // 알 수 없는 지정자는 그대로 출력하거나 무시
          if (RemainingBufferSize >= 2 * sizeof(CHAR16)) {
            *BufferPtr++ = L'%';
            *BufferPtr++ = *FormatPtr;
            RemainingBufferSize -= 2 * sizeof(CHAR16);
          } else {
            DEBUG((DEBUG_ERROR, "MyCustomPrint: Buffer too small for unknown specifier.\n"));
            Status = EFI_BUFFER_TOO_SMALL;
            goto Exit;
          }
          break;
      }
    } else {
      // 일반 문자 복사
      if (RemainingBufferSize >= 2 * sizeof(CHAR16)) {
        *BufferPtr++ = *FormatPtr;
        RemainingBufferSize -= sizeof(CHAR16);
      } else {
        DEBUG((DEBUG_ERROR, "MyCustomPrint: Buffer too small for normal character.\n"));
        Status = EFI_BUFFER_TOO_SMALL;
        goto Exit;
      }
    }
    FormatPtr++;
  }

Exit:
  // Null-terminator 추가
  *BufferPtr = L'\0';

  // 가변 인자 목록 정리
  VA_END(Args);

  // 구성된 문자열을 콘솔에 출력
  if (!EFI_ERROR(Status)) {
    Status = gST->ConOut->OutputString(gST->ConOut, Buffer);
  } else {
    // 오류 발생 시 디버그 메시지만 출력
    DEBUG((DEBUG_ERROR, "MyCustomPrint: Failed to format string, attempting to print partial buffer.\n"));
    gST->ConOut->OutputString(gST->ConOut, Buffer); // 부분적으로라도 출력 시도
  }

  return Status;
}

VOID SBC_LogInternalX(IN CHAR8 *fmt,...)
{
    va_list args;
    UINTN fmtlen = 0;
    //VA_LIST marker;
    CHAR8 buf[512];

    //VA_START(marker, format);
    va_start(args, fmt);
    //dprint();
    fmtlen = AsciiVSPrint(buf, sizeof buf, fmt, args);
    //dprint("Fmt (%d) : %a", fmtlen, buf);
    va_end(args);

    //VA_END(marker);
}


VOID SBC_LogInternal(IN CHAR8 *fmt, IN va_list marker)
{
    UINTN fmtlen = 0;
    //VA_LIST marker;
    CHAR8 buf[512];

    //VA_START(marker, format);
    //dprint();
    fmtlen = AsciiVSPrint(buf, sizeof buf, fmt, marker);
    //dprint("Fmt (%d) : %s", fmtlen, buf);
    //VA_END(marker);
}

//static UINTN remove_all_space(CHAR8* str, UINTN cnt) {
//    UINTN write_index = 0;
//    UINTN read_index = 0;
//
//    while (read_index != cnt) {
//        if (str[read_index] != 0x00) {
//            str[write_index] = str[read_index];
//            write_index++;
//        }
//        read_index++;
//    }
//    str[write_index] = '\0';
//
//    return write_index;
//}

VOID SBC_LogVarIntMrg(CHAR16 *msg, UINT32 val, CHAR16 *msgout)
{
    UnicodeSPrint(msgout, StrLen(msg) + 4, L"%s:%d", (char *)msg, val);
}

UINTN SBC_LogFmtOutNoraml(IN CONST CHAR16 *fmt, ...)
{
    return 0;
}

UINTN SBC_LogFmtOut(OUT CHAR16 *outbuf, IN CONST CHAR16 *fmt, ...)
{
    VA_LIST marker;
    CHAR16 buf[8192];
    UINTN   retval;

    VA_START(marker, fmt);
    retval = UnicodeVSPrint(buf, sizeof(buf), fmt, marker);
    VA_END(marker);

    buf[retval] = '\0';

    CopyMem(outbuf, buf, retval);

    return retval;
}

//static CHAR8 full_log_msg[8192] = {0, };

//VOID  SBC_LogPrint(UINT32 prio, UINT32 ver, CHAR16 *host,
//                        CHAR16 *appname, CHAR16 *csc,
//                        UINT32 sfrid, CHAR16 *evtype,
//                        CHAR16 *message, CHAR16 *msgarg)
//{
//
//
//    [[gnu::unused]] VA_LIST args;
//    EFI_TIME logtime;
//    CHAR8 *wrlog = NULL;
//    CHAR16 full_log_msg[8192] = {0, };
//    UINTN nxtofs = 0;
//    UINTN endofs = sizeof full_log_msg;
//
//    ZeroMem(&logtime, sizeof(EFI_TIME));
//    gRT->GetTime(&logtime, NULL);
//
//    nxtofs +=  UnicodeSPrint(&full_log_msg[nxtofs], endofs , L"%d %d %d-%d-%dT%d:%d.%d %s %s %s",
//                             prio, ver,
//                             logtime.Year, logtime.Month, logtime.Day,
//                             logtime.Hour, logtime.Minute, logtime.Second,
//                             host, appname, csc);
//
//    endofs -= nxtofs;
//    nxtofs +=  UnicodeSPrint(&full_log_msg[nxtofs], endofs , L" R-SAT-PWT-SFR-%03d %s ",
//                             sfrid, evtype);
//
//
//    endofs -= nxtofs;
//    nxtofs += UnicodeSPrint(&full_log_msg[nxtofs], endofs, L"%s-%s", message, msgarg);
//
//
////  VA_START(args, format);
////
////  //dprint("End of FS :  %lu", endofs);
////  //nxtofs += UnicodeVSPrint(&full_log_msg[nxtofs] , endofs, format, args);
////  nxtofs += UnicodeVSPrint(full_log_msg , endofs, format, args);
////  VA_END(args);
//
//
//
//    //Print(L"Mesage buf length : %d  , size : %d\n", StrnLenS(full_log_msg,8192), StrnSizeS(full_log_msg,8192));
//
//    wrlog = (CHAR8 *)full_log_msg;
//    Print(L"%s \n", full_log_msg);
//    nxtofs = remove_all_space(wrlog,StrnSizeS(full_log_msg,8192));
//    //SBC_mem_print_bin("Log", (UINT8 *)wrlog, nxtofs);
//
//    _sbc_write_log_file(wrlog,strlen(wrlog));
//
//
//
//}


//VOID  SBC_LogPrint(CONST CHAR16* func, UINT32 funcline, UINT32 prio, UINT32 ver, CHAR16 *host,
//                        CHAR16 *appname, CHAR16 *csc,
//                        UINT32 sfrid, CHAR16 *evtype,
//                        CHAR16 *message, CHAR16 *msgarg,
//                        CHAR16 *format, ...)
//{
//
//
//    [[gnu::unused]] VA_LIST args;
//    EFI_TIME logtime;
//    CHAR8 *wrlog = NULL;
//    CHAR16 full_log_msg[8192] = {0, };
//    UINTN nxtofs = 0;
//    UINTN endofs = sizeof full_log_msg;
//
//    ZeroMem(&logtime, sizeof(EFI_TIME));
//    gRT->GetTime(&logtime, NULL);
//
//    nxtofs +=  UnicodeSPrint(&full_log_msg[nxtofs], endofs , L"%d %d %d-%d-%dT%d:%d.%d %s %s %s",
//                             prio, ver,
//                             logtime.Year, logtime.Month, logtime.Day,
//                             logtime.Hour, logtime.Minute, logtime.Second,
//                             host, appname, csc);
//
//    endofs -= nxtofs;
//    nxtofs +=  UnicodeSPrint(&full_log_msg[nxtofs], endofs , L" R-SAT-PWT-SFR-%03d %s ",
//                             sfrid, evtype);
//
//
//    endofs -= nxtofs;
//    nxtofs += UnicodeSPrint(&full_log_msg[nxtofs], endofs, L"%s-%s", message, msgarg);
//
//
////  VA_START(args, format);
////
////  //dprint("End of FS :  %lu", endofs);
////  //nxtofs += UnicodeVSPrint(&full_log_msg[nxtofs] , endofs, format, args);
////  nxtofs += UnicodeVSPrint(full_log_msg , endofs, format, args);
////  VA_END(args);
//
//
//
//    //Print(L"Mesage buf length : %d  , size : %d\n", StrnLenS(full_log_msg,8192), StrnSizeS(full_log_msg,8192));
//
//    wrlog = (CHAR8 *)full_log_msg;
//    nxtofs = remove_all_space(wrlog,StrnSizeS(full_log_msg,8192));
//    //SBC_mem_print_bin("Log", (UINT8 *)wrlog, nxtofs);
//    Print(L"[%a:%d] %a \n", func, funcline, wrlog);
//    _sbc_write_log_file(wrlog,strlen(wrlog));
//
//
//
//}


VOID  SBC_LogPrintX(UINT32 prio, UINT32 ver, CHAR16 *host, 
                        CHAR16 *appname, CHAR16 *csc,
                        UINT32 sfrid, CHAR16 *evtype,
                        CHAR16 *format, ...)
{

  return;
//  //CHAR16 buf[512];
//  //AR16 logtime[64];
//  [[gnu::unused]]VA_LIST args;
//  EFI_TIME logtime;
//  CHAR8 *wrlog = NULL;
//  CHAR16 full_log_msg[512] = {0, };
//  //CHAR16 sfr_id_buf[16] = {0, };
//  //CHAR16 time_buf[128] = {0, };
//
//  UINTN nxtofs = 0;
//
//  UINTN endofs = sizeof full_log_msg;
//
//
//
//  ZeroMem(&logtime, sizeof(EFI_TIME));
//  gRT->GetTime(&logtime, NULL);
//
//  //nxtofs=  UnicodeSPrint(full_log_msg, endofs, L"[%a:%d]", func, funcline);
//
//  //endofs -= nxtofs;
//  nxtofs +=  UnicodeSPrint(&full_log_msg[nxtofs], endofs , L"%d %d %d-%d-%dT%d:%d.%d %s %s %s",
//                           prio, ver,
//                           logtime.Year, logtime.Month, logtime.Day,
//                           logtime.Hour, logtime.Minute, logtime.Second,
//                           host, appname, csc);
//
//  endofs -= nxtofs;
//  nxtofs +=  UnicodeSPrint(&full_log_msg[nxtofs], endofs , L" R-SAT-PWT-SFR-%03d %s ",
//                           sfrid, evtype);
//
//
//  endofs -= nxtofs;
//
//
//  va_start(args, format);
//  nxtofs += UnicodeVSPrint(&full_log_msg[nxtofs] , endofs, format, args);
//  va_end(args);
//
//
//
//  //Print(L"Mesage buf length : %d  , size : %d\n", StrnLenS(full_log_msg,8192), StrnSizeS(full_log_msg,8192));
//
//  wrlog = (CHAR8 *)full_log_msg;
//  nxtofs = remove_all_space(wrlog,StrnSizeS(full_log_msg,8192));
//  //SBC_mem_print_bin("Log", (UINT8 *)wrlog, nxtofs);
//  Print(L"Full Log msg : %a \n", wrlog);
//  _sbc_write_log_file(wrlog,strlen(wrlog));
//
    

}

VOID  SBC_LogWrite(UINT32 prio, CHAR16 *ver, CHAR16 *host, 
                        CHAR16 *appname, CHAR16 *csc,
                        UINT32 sfrid, CHAR16 *evtype,
                        CONST CHAR16 *format, ...)
{

//  VA_LIST marker;
//  CHAR16 buf[512];
//  //AR16 logtime[64];
//  EFI_TIME logtime;
//  CHAR16 full_log_msg[1024] = {0, };
//  CHAR16 sfr_id_buf[16] = {0, };
//
//  VA_START(marker, format);
//
//  UnicodeVSPrint(buf, sizeof buf, format, marker);
//
//
//  ZeroMem(&logtime, sizeof(EFI_TIME));
//  gRT->GetTime(&logtime, NULL);
//
//  UnicodeVSPrint(sfr_id_buf, sizeof sfr_id_buf , L"SFR-%ld", sfrid);
//
//
//  UnicodeVSPrint(full_log_msg, sizeof full_log_msg,
//                 L"<%d> %s %d %d-%d-%dT%d:%d.$d %s %s %s %s %s %s",
//                 priortiy, ver,
//                 logtime.Year,logtime.Month,logtime.Day,
//                 logtime.Hour,logtime.Minute,logtime.Second,
//                 host, appname, cs, sfr_id_buf,evtype,
//                 buf
//  );
//
//
//  VA_END(marker);
//
    //Print(L"%s \n", CHAR16);

    return;
}

#define LINE_LEN 16
void SBC_mem_print_bin(
        CHAR8 *title /**< [in] display name strings */,
        UINT8* buffer /**< [in] print buffer  */,
        UINT32 length /**< [in] length of buffer */
        )
{
    UINT32 i, sz;

    if(title) {
        Print(L"%a (length of buffer: %d) \r\r\n", title, length) ;
    }

    if (!buffer) {
        Print(L"\tNULL\r\n");
        return;
    }

    while (length > 0) {
        sz = length;
        if (sz > LINE_LEN)
            sz = LINE_LEN;

        Print(L"\t");
        for (i = 0; i < LINE_LEN; i++) {
            if (i < length)
                Print(L"%02x ", buffer[i]);
            else
                Print(L"   ");
        }
        Print(L"| ");
        for (i = 0; i < sz; i++) {
            if (buffer[i] > 31 && buffer[i] < 127)
                Print(L"%c", buffer[i]);
            else
                Print(L".");
        }
        Print(L"\r\r\n");


        buffer += sz;
        length -= sz;
    }
}


void SBC_external_mem_print_bin(
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
}


static UINTN remove_all_space(CHAR8* str, UINTN cnt) {
    UINTN write_index = 0; 
    UINTN read_index = 0;  

    while (read_index != cnt) {
        if (str[read_index] != 0x00) {
            str[write_index] = str[read_index];
            write_index++;
        }
        read_index++;
    }
    str[write_index] = '\0';

    return write_index;
}
//
//void _sbc_write_log_file(CHAR8 *message, UINT32 msglen)
//{
//    EFI_STATUS Status;
//    SBCStatus ret = SBCOK;
//    EFI_HANDLE      *hndl = NULL;
//    EFI_HANDLE      loghnd = NULL;
//    UINTN           hndlcnt;
//    LV_t            wrlv;
//
//    CHAR16         *rocky_dir_name = L"\\EFI\\rocky\\sbc_fsbl_sys_log";
//    CHAR16         *sbc_log_fname = L"\\EFI\\rocky\\sbc_fsbl_sys_log";
//
//    EFI_STATUS retval = EFI_SUCCESS;
//
//    hndlcnt = SBC_FindEfiFileSystemProtocol(&hndl);
//
//    ////dprint("Log gEfiSimpleFileSystemProtocolGuid Handle Count :%d ", hndlcnt);
//
//    for (int idx = 0; idx < hndlcnt; idx++) {
//        ////dprint("[idx:%d] handle addr : 0x%x", idx, hndl[idx]);
//        Status = SBC_IsFlieAccess(hndl[idx], rocky_dir_name);
//        switch (Status) {
//        case EFI_SUCCESS:
//          loghnd=  hndl[idx];
//          ////dprint("%s dir exists \n", rocky_dir_name);
//          break;
//        case EFI_NOT_FOUND:
//          ////dprint("%s dir not found \n", rocky_dir_name);
//          ////dprint();
//          //goto errdone;
//          break;
//        default:
//          //dprint("Unknown error (%s) \n", Status);
//          break;
//        }
//
//    }
//
//    if (loghnd == NULL) {
//        goto errdone;
//    }
//
//    Status = SBC_IsFlieAccess(loghnd, sbc_log_fname);
//    switch (Status) {
//    case EFI_SUCCESS:
//      break;
//    case EFI_NOT_FOUND:
//      // Create File
//      ret = SBC_CreateFile(loghnd, sbc_log_fname);
//      break;
//
//    default:
//      //dprint("Unknown error (%s) \n", Status);
//      goto errdone;
//
//    }
//
//    if (ret != SBCOK) {
//        eprint("log file create fail \n");
//        return;
//    }
//
//
//    wrlv.value = message;
//    wrlv.length = msglen;
//
//    retval = SBC_LogWriteFile(loghnd, sbc_log_fname, &wrlv);
//    if (EFI_ERROR(retval)) {
//        //dprint(" og  write fail (%r) \n",  retval);
//
//    }
//
//
//errdone:
//    return;
//
//}
//
//// Global string literals for safety (in case of NULL input pointers)
//CONST CHAR16 * CONST gNullStringUefi = L"(null)"; // For Unicode strings
//CONST CHAR8  * CONST gNullStringAscii = "(null)"; // For ASCII strings (if you use %a)
//
//UINTN
//InternalUnicodePrintUint (
//  IN OUT CHAR16  *Buffer,
//  IN     UINTN   BufferSize,
//  IN     UINTN   Value,
//  IN     UINTN   Radix,
//  IN     BOOLEAN Uppercase,
//  IN     UINTN   MinWidth,
//  IN     BOOLEAN PadWithZero
//  )
//{
//  CHAR16 TempBuf[30]; // Sufficient for 64-bit numbers
//  CHAR16 *p = TempBuf + sizeof(TempBuf)/sizeof(CHAR16) - 1;
//  UINTN  Count = 0;
//  CHAR16 DigitChar;
//
//  *p = L'\0'; // Null terminate
//  if (Value == 0) {
//    *(--p) = L'0';
//    Count = 1;
//  } else {
//    while (Value > 0) {
//      DigitChar = (CHAR16)(Value % Radix);
//      if (DigitChar < 10) {
//        *(--p) = (CHAR16)(L'0' + DigitChar);
//      } else {
//        *(--p) = (CHAR16)((Uppercase ? L'A' : L'a') + DigitChar - 10);
//      }
//      Value /= Radix;
//      Count++;
//    }
//  }
//
//  // Handle padding
//  while (Count < MinWidth) {
//    *(--p) = PadWithZero ? L'0' : L' ';
//    Count++;
//  }
//
//  // Copy to destination buffer, respecting BufferSize
//  return UnicodeSPrint(Buffer, BufferSize, L"%s", p);
//}
//
//
//// --- MODIFIED _LogFmtVPrint ---
//// This function will now parse the format string and handle NULL %s arguments.
//UINTN
//_LogFmtVPrint(
//  IN CONST CHAR16 *Format,
//  IN VA_LIST      VaListMaker, // The original VA_LIST
//  IN OUT CHAR16   *LogBuf,     // Buffer to write into (CHAR16 array)
//  IN UINTN        BufLen       // Remaining buffer size in BYTES
//  )
//{
//  CONST CHAR16      *Fmt;
//  CHAR16            *Dest;
//  UINTN             PrintedLength = 0;
//  UINTN             RemainingBufChars;
//  VA_LIST           CurrentVaList; // Use a copy to iterate
//
//  // Make a copy of the VA_LIST for safe iteration within this function.
//  // VA_COPY is preferred, but VA_LIST can often be copied by assignment on many compilers.
//  // For robustness, if VA_COPY is available and supported, use it.
//  // Example: VA_COPY(CurrentVaList, VaListMaker);
//  CurrentVaList = VaListMaker; // Simple assignment, might not be portable to all compilers
//
//  //dprint();
//
//  Fmt = Format;
//  Dest = LogBuf;
//  RemainingBufChars = BufLen / sizeof(CHAR16); // Convert byte length to CHAR16s
//
//  //dprint();
//
//  // Loop through the format string
//  while (*Fmt != L'\0' && RemainingBufChars > 1) { // Leave space for null terminator
//    if (*Fmt != L'%') {
//      *Dest++ = *Fmt++;
//      PrintedLength++;
//      RemainingBufChars--;
//      continue;
//    }
//
//    //dprint();
//
//    // Found a '%', now parse the specifier
//    Fmt++; // Skip '%'
//
//    // Simple parsing for common specifiers and flags.
//    // This is a minimal implementation. A full one is complex.
//    [[maybe_unused]] BOOLEAN Long = FALSE; // For %l, %L (often ignored or used for size_t/long long)
//    [[maybe_unused]] BOOLEAN IsSigned = FALSE; // For %d, %i
//    BOOLEAN PadWithZero = FALSE;
//    UINTN   Width = 0;
//
//    // Flags (e.g., '0' for zero-padding)
//    while (*Fmt == L'0') {
//        PadWithZero = TRUE;
//        Fmt++;
//    }
//
//    // Width (e.g., %5d)
//    while ((*Fmt >= L'0') && (*Fmt <= L'9')) {
//      Width = Width * 10 + (*Fmt - L'0');
//      Fmt++;
//    }
//
//    // Length modifier (e.g., %lX for long)
//    if (*Fmt == L'l') {
//      Long = TRUE;
//      Fmt++;
//    }
//
//    //dprint();
//
//    switch (*Fmt) {
//      case L's': // Unicode string
//      {
//        CONST CHAR16 *StringArg = VA_ARG(CurrentVaList, CONST CHAR16*);
//        // *** THE CRITICAL NULL CHECK ***
//        if (StringArg == NULL) {
//          StringArg = gNullStringUefi; // Substitute with safe "(null)"
//        }
//        UINTN BytesWritten = UnicodeSPrint(Dest, RemainingBufChars * sizeof(CHAR16), L"%s", StringArg);
//        PrintedLength += BytesWritten / sizeof(CHAR16);
//        Dest += BytesWritten / sizeof(CHAR16);
//        RemainingBufChars -= BytesWritten / sizeof(CHAR16);
//        break;
//      }
//      case L'a': // ASCII string (must be converted to Unicode for LogBuf)
//      {
//        CONST CHAR8 *AsciiArg = VA_ARG(CurrentVaList, CONST CHAR8*);
//        CHAR8 TempAsciiBuf[256]; // Temp buffer for ASCII string
//        UINTN BytesConverted;
//
//        if (AsciiArg == NULL) {
//          AsciiArg = gNullStringAscii; // Substitute with safe "(null)"
//        }
//        // Safely copy ASCII to temp buffer, truncate if needed
//        AsciiStrCpyS(TempAsciiBuf, sizeof(TempAsciiBuf), AsciiArg);
//        BytesConverted = AsciiStrLen(TempAsciiBuf);
//
//        // Now convert temp ASCII to Unicode and print
//        // Use an internal helper or manually convert char by char
//        for (UINTN i = 0; i < BytesConverted && RemainingBufChars > 1; i++) {
//          *Dest++ = (CHAR16)TempAsciiBuf[i];
//          PrintedLength++;
//          RemainingBufChars--;
//        }
//        break;
//      }
//      case L'd': // Signed decimal integer
//      case L'i':
//      {
//        //dprint();
//        INTN Val = VA_ARG(CurrentVaList, INTN);
//        // Implement simple signed integer print or call PrintLib helper
//        UINTN BytesWritten = UnicodeSPrint(Dest, RemainingBufChars * sizeof(CHAR16), L"%d", Val);
//        PrintedLength += BytesWritten / sizeof(CHAR16);
//        Dest += BytesWritten / sizeof(CHAR16);
//        RemainingBufChars -= BytesWritten / sizeof(CHAR16);
//        break;
//      }
//      case L'u': // Unsigned decimal integer
//      {
//        //dprint();
//        UINTN Val = VA_ARG(CurrentVaList, UINTN);
//        UINTN BytesWritten = InternalUnicodePrintUint(Dest, RemainingBufChars * sizeof(CHAR16), Val, 10, FALSE, Width, PadWithZero);
//        PrintedLength += BytesWritten / sizeof(CHAR16);
//        Dest += BytesWritten / sizeof(CHAR16);
//        RemainingBufChars -= BytesWritten / sizeof(CHAR16);
//        break;
//      }
//      case L'x': // Hexadecimal lowercase
//      {
//        //dprint();
//        UINTN Val = VA_ARG(CurrentVaList, UINTN);
//        //dprint("x val :%lx", Val);
//        UINTN BytesWritten = InternalUnicodePrintUint(Dest, RemainingBufChars * sizeof(CHAR16), Val, 16, FALSE, Width, PadWithZero);
//        PrintedLength += BytesWritten / sizeof(CHAR16);
//        Dest += BytesWritten / sizeof(CHAR16);
//        RemainingBufChars -= BytesWritten / sizeof(CHAR16);
//        break;
//      }
//      case L'X': // Hexadecimal uppercase
//      {
//        UINTN Val = VA_ARG(CurrentVaList, UINTN);
//        UINTN BytesWritten = InternalUnicodePrintUint(Dest, RemainingBufChars * sizeof(CHAR16), Val, 16, TRUE, Width, PadWithZero);
//        PrintedLength += BytesWritten / sizeof(CHAR16);
//        Dest += BytesWritten / sizeof(CHAR16);
//        RemainingBufChars -= BytesWritten / sizeof(CHAR16);
//        break;
//      }
//      case L'p': // Pointer address (hex)
//      {
//        VOID *Ptr = VA_ARG(CurrentVaList, VOID*);
//        UINTN BytesWritten = UnicodeSPrint(Dest, RemainingBufChars * sizeof(CHAR16), L"%p", Ptr);
//        PrintedLength += BytesWritten / sizeof(CHAR16);
//        Dest += BytesWritten / sizeof(CHAR16);
//        RemainingBufChars -= BytesWritten / sizeof(CHAR16);
//        break;
//      }
//      case L'c': // Unicode character
//      {
//        CHAR16 CharVal = (CHAR16)VA_ARG(CurrentVaList, UINTN); // Char args are promoted to int
//        *Dest++ = CharVal;
//        PrintedLength++;
//        RemainingBufChars--;
//        break;
//      }
//      case L'%': // Literal '%'
//        *Dest++ = L'%';
//        PrintedLength++;
//        RemainingBufChars--;
//        break;
//      default: // Unrecognized specifier, print literally
//        *Dest++ = L'%';
//        *Dest++ = *Fmt;
//        PrintedLength += 2;
//        RemainingBufChars -= 2;
//        break;
//    }
//    Fmt++; // Move to next char in format string
//  }
//
//  *Dest = L'\0'; // Null-terminate the buffer
//  return PrintedLength;
//}
//
//
//VOID
//SBC_LogPrint(
//  CONST CHAR16* func,     // For [%a:%d] if uncommented
//  UINT32 funcline,        // For [%a:%d] if uncommented
//  UINT32 prio,
//  UINT32 ver,
//  CHAR16 *host,           // Potentially NULL
//  CHAR16 *appname,        // Potentially NULL
//  CHAR16 *csc,            // Potentially NULL
//  UINT32 sfrid,
//  CHAR16 *evtype,         // Potentially NULL
//  CHAR16 *format,         // Format string for the message body
//  ...
//  )
//{
//    EFI_STATUS retval;
//    VA_LIST args;
//    EFI_TIME logtime;
//    CHAR8 *wrlog = NULL;
//    // Buffer for the full Unicode log message
//    CHAR16 full_log_msg[(PcdGet32 (PcdUefiLibMaxPrintBufferSize) + 1)]; // Size is in CHAR16s now
//    UINTN nxtofs = 0;
//    UINTN remaining_buffer_bytes;
//
//    // Convert CHAR16 buffer size to bytes
//    UINTN max_full_log_msg_bytes = sizeof(full_log_msg);
//
//    DEBUG ((DEBUG_INFO, "Log buf size in CHAR16s: %d\n", PcdGet32(PcdUefiLibMaxPrintBufferSize) + 1));
//    ZeroMem(full_log_msg, max_full_log_msg_bytes); // Use byte size
//    ZeroMem(&logtime, sizeof(EFI_TIME));
//
//    retval = gRT->GetTime(&logtime, NULL);
//    if (EFI_ERROR(retval)) {
//      // If getting time fails, set to a known zero value or a default epoch
//      SetMem(&logtime, sizeof(EFI_TIME), 0);
//      // Or you might use specific fixed values for year, month, day, etc.
//      // logtime.Year = 2000; logtime.Month = 1; logtime.Day = 1; ...
//    }
//
//    // --- First part of the log header ---
//    // Safely handle potentially NULL CHAR16* arguments for %s
//    CONST CHAR16 *safe_host    = (host != NULL) ? host : gNullStringUefi;
//    CONST CHAR16 *safe_appname = (appname != NULL) ? appname : gNullStringUefi;
//    CONST CHAR16 *safe_csc     = (csc != NULL) ? csc : gNullStringUefi;
//    CONST CHAR16 *safe_evtype  = (evtype != NULL) ? evtype : gNullStringUefi;
//
//    remaining_buffer_bytes = max_full_log_msg_bytes;
//
//    // The commented out line below was using %a for func (CHAR16* func).
//    // If func is a CHAR16*, using %a is incorrect in UnicodeSPrint.
//    // If func is CHAR8*, then %a is correct. Assuming func is CHAR16* based on signature.
//    // If func is CHAR16* and you want it, use %s:
//    // nxtofs = UnicodeSPrint(full_log_msg, remaining_buffer_bytes, L"[%s:%d]", func, funcline);
//    // If func is CHAR8* and you want it converted:
//    // nxtofs = UnicodeSPrint(full_log_msg, remaining_buffer_bytes, L"[%a:%d]", (func != NULL ? (CHAR8*)func : gNullStringAscii), funcline);
//    // For now, it's commented out, so it won't be an issue.
//
//    // Calculate remaining buffer size in bytes for the next print.
//    remaining_buffer_bytes -= (nxtofs * sizeof(CHAR16));
//
//    //dprint();
//    // Construct the main header part of the log message
//    nxtofs += UnicodeSPrint(
//                full_log_msg + nxtofs,
//                remaining_buffer_bytes,
//                L"%d %d %d-%02d-%02dT%02d:%02d:%02d %s %s %s R-SAT-PWT-SFR-%03d %s ", // Added space after %s for clarity
//                prio, ver,
//                logtime.Year, logtime.Month, logtime.Day, // Use %02d for consistent formatting
//                logtime.Hour, logtime.Minute, logtime.Second,
//                safe_host, safe_appname, safe_csc, // Using the safely handled pointers
//                sfrid, safe_evtype
//                );
//
//    // Update remaining buffer size in bytes for _LogFmtVPrint
//    remaining_buffer_bytes -= (nxtofs * sizeof(CHAR16));
//
//    //dprint();
//    // Ensure we don't pass a negative or zero remaining_buffer_bytes to _LogFmtVPrint
//    if (remaining_buffer_bytes == 0 || nxtofs >= PcdGet32(PcdUefiLibMaxPrintBufferSize)) {
//        DEBUG ((DEBUG_ERROR, "SBC_LogPrint: Buffer full before message body. nxtofs=%d\n", nxtofs));
//        // Optionally, append an ellipsis to indicate truncation
//        UnicodeSPrint(full_log_msg + nxtofs, sizeof(CHAR16)*4, L"..."); // 4 bytes for "..." + NULL
//        goto Exit; // Skip to the end
//    }
//
//    //dprint();
//
//    // --- Message body (variable part) ---
//    VA_START(args, format);
//
//    //dprint();
//    // Call your internal _LogFmtVPrint. This function *must* also handle NULL CHAR16*
//    // for its %s specifiers from the 'format' string.
//    nxtofs += _LogFmtVPrint(
//                (CONST CHAR16 *)format,
//                args,
//                (CHAR16 *)full_log_msg + nxtofs, // Start writing from current offset
//                remaining_buffer_bytes           // Remaining buffer size in bytes
//                );
//    VA_END(args);
//
//    //dprint();
//
//    // Ensure the final message is null-terminated and doesn't exceed buffer
//    // UnicodeSPrint/VPrint usually null-terminate, but good to be explicit
//    // and check against the total allocated buffer size for robustness.
//    if (nxtofs >= PcdGet32(PcdUefiLibMaxPrintBufferSize)) {
//        // Truncate if necessary and null-terminate
//        full_log_msg[PcdGet32(PcdUefiLibMaxPrintBufferSize)] = L'\0';
//    } else {
//        full_log_msg[nxtofs] = L'\0';
//    }
//
//    //dprint();
//
//    // --- Post-processing and output ---
////  DEBUG ((DEBUG_INFO, L"Mesage buf length (CHAR16s): %d, size (bytes): %d\n",
////                       StrnLenS(full_log_msg), StrnLenS(full_log_msg)));
//
//    wrlog = (CHAR8 *)full_log_msg; // Cast for ASCII processing
//
//    // Print for debug
//    //dprint("Full Log msg : %s \n", full_log_msg);
//
//    // Call your remove_all_space function (assumed to work on ASCII CHAR8*)
//    // You need to be careful if remove_all_space expects an ASCII string,
//    // but wrlog is actually a Unicode string in memory.
//    // If remove_all_space expects ASCII, you need to convert full_log_msg to ASCII first.
//    // If it works on the raw byte representation of Unicode, that's unusual but possible.
//    // Assuming it's safe for now.
//    nxtofs = remove_all_space(wrlog, StrnSizeS((CHAR16*)wrlog, max_full_log_msg_bytes));
//
//    //DEBUG ((DEBUG_INFO, L"Full Log msg after space removal (ASCII interpretation): %a \n", wrlog));
//    //Print(L"Log : %a \n", wrlog);
//
//    // _sbc_write_log_file expects CHAR8* and its strlen.
//    // This again implies wrlog must be a valid ASCII string.
//    // If full_log_msg is truly Unicode, then wrlog needs to be a separate, converted ASCII buffer.
//    _sbc_write_log_file(wrlog, strlen(wrlog));
//
//Exit:
//    return;
//}
//


// Define a suitable max print buffer size via PCD or a fixed constant
// This should match your EDK II PCD for PcdUefiLibMaxPrintBufferSize if you use it.
#ifndef PcdGet32
#define PcdGet32(TokenName)   8192 // Default if PCD is not defined
#endif

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

/**
  Returns the length of a Null-terminated Unicode string, up to a specified maximum size.
  (Similar to StrnLenS in EDK II's SafeStringLib)

  @param  String  A pointer to a Null-terminated Unicode string.
  @param  MaxSize The maximum number of Unicode characters to examine.

  @retval 0       If String is NULL or empty.
  @retval Others  The length of String, or MaxSize if the string is longer
                  than MaxSize and no Null-terminator is found.
**/
UINTN
MyUnicodeStrnLenS (
  IN CONST CHAR16  *String,
  IN UINTN         MaxSize
  )
{
  UINTN Length;

  if (String == NULL) {
    DEBUG ((DEBUG_ERROR, "MyUnicodeStrnLenS: Input String is NULL.\n"));
    return 0;
  }

  for (Length = 0; Length < MaxSize && *String != L'\0'; String++, Length++);

  return Length;
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


// ===========================================================================
// _LogFmtVPrint (The heart of safe variable argument formatting)
// ===========================================================================

/**
  Formats a variable argument list into a Unicode string buffer,
  handling NULL CHAR16* arguments safely.

  This function parses the format string and uses arguments from VaListMaker
  to construct a formatted Unicode string in LogBuf. It performs NULL checks
  for %s specifiers to prevent hard faults.

  @param  Format        The format string.
  @param  VaListMaker   The VA_LIST containing the arguments.
  @param  LogBuf        The destination buffer for the formatted Unicode string.
  @param  BufLenBytes   The remaining size of LogBuf in BYTES.

  @retval The number of CHAR16s written to LogBuf (excluding null terminator).
**/

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
  VA_LIST           CurrentVaList; // Use a copy to iterate

  // Make a copy of the VA_LIST for safe iteration within this function.
  // VA_COPY is preferred for portability, but direct assignment often works.
  #ifdef VA_COPY
  VA_COPY(CurrentVaList, VaListMaker);
  #else
  CurrentVaList = VaListMaker;
  #endif

  Fmt = Format;
  Dest = LogBuf;
  RemainingBufChars = BufLenBytes / sizeof(CHAR16);

  // Leave at least one CHAR16 for the null terminator.
  if (RemainingBufChars == 0) {
      goto Exit;
  }

  // Loop through the format string
  while (*Fmt != L'\0' && RemainingBufChars > 1) {
    if (*Fmt != L'%') {
      *Dest++ = *Fmt++;
      PrintedChars++;
      RemainingBufChars--;
      continue;
    }

    // Found a '%', now parse the specifier and arguments
    Fmt++; // Skip '%'

    // Simple parsing for flags, width, precision, length modifiers
    // This is a minimalist set; PrintLib's internal v_snprintf_unicode is far more robust.
    BOOLEAN PadWithZero = FALSE;
    BOOLEAN LeftJustify = FALSE;
    UINTN   Width = 0;
    UINTN   Precision = MAX_UINTN; // Unlimited precision by default
    BOOLEAN Long = FALSE; // %l, %ll, %L (used for size modifiers)

    // Parse flags
    while (TRUE) {
      if (*Fmt == L'-') { LeftJustify = TRUE; }
      else if (*Fmt == L'0') { PadWithZero = TRUE; }
      else { break; }
      Fmt++;
    }

    // Parse width
    if (*Fmt == L'*') {
      Width = VA_ARG(CurrentVaList, UINTN);
      Fmt++;
    } else {
      while ((*Fmt >= L'0') && (*Fmt <= L'9')) {
        Width = Width * 10 + (*Fmt - L'0');
        Fmt++;
      }
    }

    // Parse precision
    if (*Fmt == L'.') {
      Fmt++;
      if (*Fmt == L'*') {
        Precision = VA_ARG(CurrentVaList, UINTN);
        Fmt++;
      } else {
        Precision = 0; // Default precision if no number follows '.'
        while ((*Fmt >= L'0') && (*Fmt <= L'9')) {
          Precision = Precision * 10 + (*Fmt - L'0');
          Fmt++;
        }
      }
    }

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


    UINTN CharsWrittenForSpecifier = 0;
    UINTN RemainingBytesForSpecifier = RemainingBufChars * sizeof(CHAR16);

    switch (*Fmt) {
      case L's': // Unicode string (CHAR16*)
      {
        CONST CHAR16 *StringArg = VA_ARG(CurrentVaList, CONST CHAR16*);
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
        CONST CHAR8 *AsciiArg = VA_ARG(CurrentVaList, CONST CHAR8*);
        CHAR8 TempAsciiBuf[PcdGet32(PcdUefiLibMaxPrintBufferSize) + 1]; // Temp buffer for ASCII string
        UINTN AsciiLen;

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
        INTN Val = (Long ? VA_ARG(CurrentVaList, INT64) : VA_ARG(CurrentVaList, INTN));
        CharsWrittenForSpecifier = UnicodeSPrint(Dest, RemainingBytesForSpecifier, L"%" FMT_INT64_DFORMAT L"d", Val);
        break;
      }
      case L'u': // Unsigned decimal integer
      {
        UINTN Val = (Long ? VA_ARG(CurrentVaList, UINT64) : VA_ARG(CurrentVaList, UINTN));
        CharsWrittenForSpecifier = UnicodeSPrint(Dest, RemainingBytesForSpecifier, L"%" FMT_UINT64_DFORMAT L"u", Val);
        break;
      }
      case L'x': // Hexadecimal lowercase
      {
        UINTN Val = (Long ? VA_ARG(CurrentVaList, UINT64) : VA_ARG(CurrentVaList, UINTN));
        CharsWrittenForSpecifier = UnicodeSPrint(Dest, RemainingBytesForSpecifier, L"%" FMT_UINT64_XFORMAT L"x", Val);
        break;
      }
      case L'X': // Hexadecimal uppercase
      {
        UINTN Val = (Long ? VA_ARG(CurrentVaList, UINT64) : VA_ARG(CurrentVaList, UINTN));
        CharsWrittenForSpecifier = UnicodeSPrint(Dest, RemainingBytesForSpecifier, L"%" FMT_UINT64_XFORMAT L"X", Val);
        break;
      }
      case L'p': // Pointer address (hex)
      {
        VOID *Ptr = VA_ARG(CurrentVaList, VOID*);
        CharsWrittenForSpecifier = UnicodeSPrint(Dest, RemainingBytesForSpecifier, L"%p", Ptr);
        break;
      }
      case L'c': // Unicode character
      {
        CHAR16 CharVal = (CHAR16)VA_ARG(CurrentVaList, UINTN); // Char args are promoted to int
        *Dest = CharVal;
        CharsWrittenForSpecifier = 1;
        break;
      }
      case L'%': // Literal '%'
        *Dest = L'%';
        CharsWrittenForSpecifier = 1;
        break;
      default: // Unrecognized specifier, print literally
        *Dest++ = L'%';
        *Dest++ = *Fmt;
        PrintedChars += 2; // Adjust immediately as we wrote directly
        RemainingBufChars -= 2;
        goto NextFmtChar; // Skip common update at end of switch
    }
    
    // Update pointers and counts after processing a specifier
    Dest += CharsWrittenForSpecifier;
    PrintedChars += CharsWrittenForSpecifier;
    RemainingBufChars -= CharsWrittenForSpecifier;

NextFmtChar:
    Fmt++; // Move to next char in format string
  }

  *Dest = L'\0'; // Null-terminate the buffer
  
Exit:
  VA_END(CurrentVaList); // Clean up the copied VA_LIST
  return PrintedChars;
}


// ===========================================================================
// SBC_LogPrint (Main Logging Function)
// ===========================================================================

VOID
SBC_LogPrint(
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

    DEBUG ((DEBUG_INFO, "SBC_LogPrint: Log buf size in CHAR16s: %d (Bytes: %d)\n",
                         PcdGet32(PcdUefiLibMaxPrintBufferSize) + 1, max_full_log_msg_bytes));
    
    ZeroMem(full_log_msg, max_full_log_msg_bytes); // Clear the buffer
    ZeroMem(&logtime, sizeof(EFI_TIME)); // Clear time struct

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

    // --- Safely handle potentially NULL CHAR16* arguments for the header ---
    // These pointers are passed directly to UnicodeSPrint, which itself is safe.
    // However, explicitly ensuring non-NULL pointers is good practice and clear.
    CONST CHAR16 *safe_func    = (func != NULL) ? func : gEmptyStringUefi; // If func is CHAR16*
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


    // --- Construct the main header part of the log message ---
    // Format: PRIO VER YYYY-MM-DDTHH:MM:SS HOST APPNAME CSC R-SAT-PWT-SFR-XXX EVTYPE [Message Body]
    // Using %02d for consistent two-digit formatting for month, day, hour, etc.
    nxtofs += UnicodeSPrint(
                full_log_msg + nxtofs,
                remaining_buffer_bytes,
                L"%d %d %04d-%02d-%02dT%02d:%02d:%02d %s %s %s R-SAT-PWT-SFR-%03d %s ",
                prio, ver,
                logtime.Year, logtime.Month, logtime.Day,
                logtime.Hour, logtime.Minute, logtime.Second,
                safe_host, safe_appname, safe_csc, // Using the safely handled pointers
                sfrid, safe_evtype
                );

    // Update remaining buffer size in bytes for the next print.
    remaining_buffer_bytes -= (nxtofs * sizeof(CHAR16));
    
    // Ensure we have at least some space left for the message body and null terminator
    if (remaining_buffer_bytes <= sizeof(CHAR16) * 4) { // Small space for "..." + NULL
        DEBUG ((DEBUG_ERROR, "SBC_LogPrint: Buffer almost full before message body. Truncating.\n"));
        UnicodeSPrint(full_log_msg + nxtofs, sizeof(CHAR16)*4, L"..."); // Indicate truncation
        return; // Skip to the end
    }

    // --- Message body (variable part) ---
    VA_START(args, format);
    // Call the enhanced _LogFmtVPrint, which now handles NULL CHAR16* arguments safely.
    nxtofs += _LogFmtVPrint(
                format, // The format string for the variable arguments
                args,
                full_log_msg + nxtofs, // Start writing from current offset
                remaining_buffer_bytes   // Remaining buffer size in bytes
                );
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

    // Now wrlog points to a proper ASCII string
    CHAR8 *wrlog_ptr = AsciiLogBuffer; 
    
    // Print for debug (both Unicode and ASCII for comparison)
    //dprint("SBC_LogPrint: Full Unicode Log msg : %s \n", full_log_msg);
    //dprint("SBC_LogPrint: Full ASCII Log msg   : %a (Length: %d) \n", wrlog_ptr, AsciiConvertedLen);

    // Call your remove_all_space function (expects ASCII CHAR8*)
    // It should modify wrlog_ptr in place and return the new length.
    // Make sure remove_all_space works on a null-terminated string and updates length correctly.
    UINTN final_ascii_len = remove_all_space(wrlog_ptr, AsciiConvertedLen); // Pass converted length, not full buffer size

    //dprint("SBC_LogPrint: ASCII Log msg after space removal: %a (Final Length: %d)\n", wrlog_ptr, final_ascii_len);

    // _sbc_write_log_file expects CHAR8* and its strlen.
    _sbc_write_log_file(wrlog_ptr, final_ascii_len);

ExitLog:
    return;
}

// ===========================================================================
// Dummy External Functions (Replace with your actual implementations)
// ===========================================================================

// Replace with your actual implementation that removes spaces from an ASCII buffer
UINTN remove_all_space(CHAR8 *buffer, UINTN buffer_size_in_bytes) {
    if (buffer == NULL || buffer_size_in_bytes == 0) {
        return 0;
    }
    UINTN  read_idx = 0;
    UINTN  write_idx = 0;
    while (read_idx < buffer_size_in_bytes && buffer[read_idx] != '\0') {
        if (buffer[read_idx] != ' ') {
            buffer[write_idx++] = buffer[read_idx];
        }
        read_idx++;
    }
    buffer[write_idx] = '\0'; // Null-terminate the new string
    return write_idx; // Return new length
}

// Replace with your actual implementation for writing to a log file or sending over network
EFI_STATUS _sbc_write_log_file(CHAR8 *log_data, UINTN length_in_bytes) {
    if (log_data == NULL || length_in_bytes == 0) {
        DEBUG ((DEBUG_ERROR, "SysLog: No data to write or invalid length.\n"));
        return EFI_INVALID_PARAMETER;
    }
    // For demonstration, just print to console as ASCII
    Print(L"SysLog_OUTPUT (ASCII): %a\n", log_data);

    // --- Placeholder for actual network (UDP) sending ---
    // EFI_STATUS Status;
    // EFI_UDP4_PROTOCOL *gUdp4 = NULL; // Get this protocol instance elsewhere
    // EFI_IP4_CONFIG_PROTOCOL *gIp4Config = NULL; // Get this protocol instance elsewhere
    // UINT32 SyslogServerIp = 0xC0A8010A; // Example: 192.168.1.10
    // UINT16 SyslogServerPort = 514;
    //
    // // Initialize UDP, configure IP, etc. (complex setup not shown)
    // // Status = gBS->LocateProtocol(&gEfiUdp4ProtocolGuid, NULL, (VOID **)&gUdp4);
    // // if (!EFI_ERROR(Status) && gUdp4 != NULL) {
    // //     EFI_UDP4_TRANSMIT_DATA TxData;
    // //     ZeroMem(&TxData, sizeof(TxData));
    // //     TxData.DestinationAddress.Addr[0] = (UINT8)(SyslogServerIp >> 24);
    // //     ...
    // //     TxData.FragmentCount = 1;
    // //     TxData.Fragment[0].FragmentLength = (UINT32)length_in_bytes;
    // //     TxData.Fragment[0].FragmentBuffer = log_data;
    // //     Status = gUdp4->Transmit(gUdp4, &TxData);
    // // }
    //
    // --- Placeholder for actual file writing ---
    // EFI_STATUS Status;
    // EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *gFs = NULL; // Get this protocol instance elsewhere
    // EFI_FILE_PROTOCOL *LogFile = NULL;
    //
    // // Locate file system protocol (e.g., on ESP or USB)
    // // Status = gBS->LocateProtocol(&gEfiSimpleFileSystemProtocolGuid, NULL, (VOID **)&gFs);
    // // if (!EFI_ERROR(Status) && gFs != NULL) {
    // //     // Open root directory
    // //     EFI_FILE_PROTOCOL *Root = NULL;
    // //     Status = gFs->OpenVolume(gFs, &Root);
    // //     if (!EFI_ERROR(Status) && Root != NULL) {
    // //         // Open or create log file
    // //         Status = Root->Open(Root, &LogFile, L"\\SysLog.log", EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
    // //         if (!EFI_ERROR(Status) && LogFile != NULL) {
    // //             // Seek to end and write
    // //             LogFile->SetPosition(LogFile, EFI_MAX_UINT64); // Seek to end
    // //             LogFile->Write(LogFile, &length_in_bytes, log_data);
    // //             LogFile->Close(LogFile);
    // //         }
    // //         Root->Close(Root);
    // //     }
    // // }

    return EFI_SUCCESS;
}





//
// 헬퍼 함수: 로그 레벨을 문자열로 변환
//
CONST CHAR16* GetLogLevelString(LOG_LEVEL Level) {
    switch (Level) {
        case LOG_LEVEL_DEBUG:       return L"DEBUG";
        case LOG_LEVEL_INFO:        return L"INFO";
        case LOG_LEVEL_NOTICE:      return L"NOTICE";
        case LOG_LEVEL_WARNING:     return L"WARNING";
        case LOG_LEVEL_ERROR:       return L"ERROR";
        case LOG_LEVEL_CRITICAL:    return L"CRITICAL";
        case LOG_LEVEL_ALERT:       return L"ALERT";
        case LOG_LEVEL_EMERGENCY:   return L"EMERGENCY";
        default:                    return L"UNKNOWN";
    }
}

//
// 헬퍼 함수: 이벤트를 문자열로 변환
//
CONST CHAR16* GetLogEventString(LOG_EVENT Event) {
    switch (Event) {
        case LOG_EVENT_GENERIC:       return L"GENERIC";
        case LOG_EVENT_BOOT_INIT:     return L"BOOT_INIT";
        case LOG_EVENT_DRIVER_LOAD:   return L"DRIVER_LOAD";
        case LOG_EVENT_FS_OPERATION:  return L"FS_OPER";
        case LOG_EVENT_NETWORK:       return L"NETWORK";
        case LOG_EVENT_SECURITY:      return L"SECURITY";
        case LOG_EVENT_CONFIG:        return L"CONFIG";
        case LOG_EVENT_NVRAM:         return L"NVRAM";
        case LOG_EVENT_REBOOT:        return L"REBOOT";
        default:                      return L"UNKNOWN_EVENT";
    }
}

#define MAX_LOG_MESSAGE_LENGTH 512

VOID UefiLog(LOG_LEVEL Level, LOG_EVENT Event, CONST CHAR16 *Format, ...) {
    EFI_STATUS  Status;
    EFI_TIME    Time;
    CHAR16      LogMessageBuffer[MAX_LOG_MESSAGE_LENGTH];
    VA_LIST     Args;
    UINTN       Offset = 0;

    // 현재 시간을 가져옴
    Status = gRT->GetTime(&Time, NULL);
    if (EFI_ERROR(Status)) {
        // 시간 가져오기 실패 시 기본값 사용
        SetMem(&Time, sizeof(EFI_TIME), 0);
    }

    // 타임스탬프, 레벨, 이벤트 카테고리 포맷
    Offset += UnicodeSPrint(LogMessageBuffer + Offset, sizeof(LogMessageBuffer) - (Offset * sizeof(CHAR16)),
                     L"[%04d-%02d-%02d %02d:%02d:%02d] [%s] [%s] ",
                     Time.Year, Time.Month, Time.Day, Time.Hour, Time.Minute, Time.Second,
                     GetLogLevelString(Level), GetLogEventString(Event));

    // 사용자 메시지 포맷
    VA_START(Args, Format);
    Offset += UnicodeSPrint(LogMessageBuffer + Offset, sizeof(LogMessageBuffer) - (Offset * sizeof(CHAR16)),
                     Format, Args);
    VA_END(Args);

    // 콘솔에 출력
    Print(L"%s\n", LogMessageBuffer);
}

#endif
