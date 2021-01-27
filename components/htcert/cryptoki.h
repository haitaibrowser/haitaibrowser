/* -*- c -*- */
/*
 * This file is part of GPKCS11.
 * (c) 1999,2000 TC TrustCenter GmbH
 *
 * GPKCS11 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * GPKCS11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GPKCS11; see the file COPYING.  If not, write to the Free
 * Software Foundation, 59 Temple Place - Suite 330, Boston, MA 02111, USA.
 */
/*
 * RCSID:       $Id: cryptoki.h,v 1.6 2000/09/19 09:14:54 lbe Exp $
 * Source:      $Source: /usr/cvsroot/pkcs11/libgpkcs11/cryptoki.h,v $
 * Last Delta:  $Date: 2000/09/19 09:14:54 $ $Revision: 1.6 $ $Author: lbe $
 * State:       $State: Exp $ $Locker:  $
 * NAME:        cryptoki.h
 * SYNOPSIS:    -
 * DESCRIPTION: -
 * FILES:       -
 * SEE/ALSO:    -
 * AUTHOR:      lbe
 * BUGS: *      -
 * HISTORY:     $Log: cryptoki.h,v $
 * HISTORY:     Revision 1.6  2000/09/19 09:14:54  lbe
 * HISTORY:     write flag for pin change onto SC, support Auth Pin path
 * HISTORY:
 * HISTORY:     Revision 1.5.2.1  2000/09/04 17:45:41  lbe
 * HISTORY:     mem leak fixes to tcsc-token, remove key_block/8 from cryptdb.c
 * HISTORY:
 * HISTORY:     Revision 1.5  2000/02/07 14:04:10  lbe
 * HISTORY:     release 0.6 and clean up of files
 * HISTORY:
 * HISTORY:     Revision 1.4  2000/01/31 18:09:02  lbe
 * HISTORY:     lockdown prior to win_gdbm change
 * HISTORY:
 * HISTORY:     Revision 1.3  1999/11/30 14:02:42  lbe
 * HISTORY:     write tons of small changes
 * HISTORY:
 * HISTORY:     Revision 1.2  1999/11/25 16:46:51  lbe
 * HISTORY:     moved all lib version defines into the conf.h
 * HISTORY:
 * HISTORY:     Revision 1.1  1999/06/16 09:46:06  lbe
 * HISTORY:     reorder files
 * HISTORY:
 * HISTORY:     Revision 1.6  1999/03/11 09:19:53  lbe
 * HISTORY:     added config file
 * HISTORY:
 * HISTORY:     Revision 1.5  1999/01/19 12:19:37  lbe
 * HISTORY:     first release lockdown
 * HISTORY:
 * HISTORY:     Revision 1.4  1998/10/12 10:07:56  lbe
 * HISTORY:     clampdown
 * HISTORY:
 * HISTORY:     Revision 1.3  1998/07/30 15:29:52  lbe
 * HISTORY:     Win32 Port
 * HISTORY:
 * HISTORY:     Revision 1.2  1998/07/16 08:28:03  lbe
 * HISTORY:     CRYPTOKI_H Macro als Include-Schutz hinzugefügt
 * HISTORY:
 * HISTORY:     Revision 1.1  1998/07/02 17:08:19  lbe
 * HISTORY:     Initial revision
 * HISTORY:
 */

#ifndef CRYPTOKI_H
#define CRYPTOKI_H 1

/*
 * Defines one of the following to indicate OS used:
 * CK_Win32   for WindowsNT or Windows95
 * CK_Win16   for Windows 3.x
 * CK_GENERIC for any Unix. Special compiler directives for certain Unix
 *            variants may be used and are defined by the specific OS and
 *            C compiler
 *
 * If you include this as part of the gpkcs11 source, you do not need to
 * set the defines, as this is handled by the conf.h file
 */
#ifdef HAVE_CONFIG_H
# include "conf.h"
#elif WIN32
# include "conf.h.win32"
#endif


#if defined(CK_Win32)
#pragma pack(push, cryptoki, 1)

#define CK_PTR *

#if defined(CK_I_library_build)
#define CK_DEFINE_FUNCTION(returnType, name) \
  __declspec(dllexport) returnType name

#define CK_DECLARE_FUNCTION(returnType, name) \
  __declspec(dllexport) returnType name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType (* name)

#else /* ! CK_I_library_build */
/* CK_DEFINE_FUNCTION gibts nicht weil das
 * eigentlich gar nicht vorkommen sollte! (darf es nur in den
 * *.c Dateien geben. Nicht in den Headern!!!)
 * Dafür gibt es CK_DECLARE_FUNCTION um eine Funktion einer
 * anderen Lib zu importieren.
 */

#define CK_DECLARE_FUNCTION(returnType, name) \
  __declspec(dllimport) returnType name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  __declspec(dllimport) returnType (* name)

#endif /* ! CK_I_library_build */

#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#elif defined(CK_Win16)
#pragma pack(1)

#define CK_PTR far *

#define CK_DEFINE_FUNCTION(returnType, name) \
  returnType __export _far _pascal name

#define CK_DECLARE_FUNCTION(returnType, name) \
  returnType __export _far _pascal name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType __export _far _pascal (* name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType _far _pascal (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#elif defined(CK_GENERIC)
#define CK_PTR *

#define CK_DEFINE_FUNCTION(returnType, name) \
  returnType name

#define CK_DECLARE_FUNCTION(returnType, name) \
  returnType name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType (* name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#else
#error no OS type define (needs to be one of CK_Win32, CK_Win16, CK_GENERIC)
#endif /* OS Type */

/* load the actual definitions of PKCS#11 */
#include "pkcs11.h"

/* Some TC specific definitions */
/* a constant string */
typedef const unsigned char *CK_C_CHAR_PTR;
typedef const unsigned char *CK_C_BYTE_PTR;

#if defined(CK_Win32)
#pragma pack(pop, cryptoki)
#endif

#endif /* CRYPTOKI_H */
/*
 * Local variables:
 * folded-file: t
 * end:
 */
