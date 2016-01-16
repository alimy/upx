/* except.cpp --

   This file is part of the UPX executable compressor.

   Copyright (C) 1996-2001 Markus Franz Xaver Johannes Oberhumer
   Copyright (C) 1996-2001 Laszlo Molnar

   UPX and the UCL library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.
   If not, write to the Free Software Foundation, Inc.,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

   Markus F.X.J. Oberhumer                   Laszlo Molnar
   markus.oberhumer@jk.uni-linz.ac.at        ml1050@cdata.tvnet.hu
 */


#include "conf.h"


/*************************************************************************
//
**************************************************************************/

long Throwable::counter = 0;

Throwable::Throwable(const char *m, int e, bool w)
    : super(), msg(NULL), err(e), is_warning(w)
{
    if (m)
        msg = strdup(m);
#if 0
    fprintf(stderr, "construct exception: %s %ld\n", msg, counter);
    counter++;
#endif
}


Throwable::Throwable(Throwable const &other)
    : super(other), msg(NULL), err(other.err), is_warning(other.is_warning)
{
    if (other.msg)
        msg = strdup(other.msg);
#if 0
    fprintf(stderr, "copy exception: %s %ld\n", msg, counter);
    counter++;
#endif
}


Throwable::~Throwable() NOTHROW
{
#if 0
    counter--;
    fprintf(stderr, "destruct exception: %s %ld\n", msg, counter);
#endif
    if (msg)
        free(msg);
}


/*************************************************************************
// compression
**************************************************************************/

void throwCantPack(const char *msg)
{
    // UGLY, but makes things easier
    if (opt->cmd == CMD_COMPRESS)
        throw CantPackException(msg);
    else if (opt->cmd == CMD_FILEINFO)
        throw CantPackException(msg);
    else
        throw CantUnpackException(msg);
}

void throwFilterException()
{
    throwCantPack("filter problem");
}

void throwUnknownExecutableFormat(const char *msg, bool warn)
{
    throw UnknownExecutableFormatException(msg, warn);
}

void throwNotCompressible(const char *msg)
{
    throw NotCompressibleException(msg);
}

void throwAlreadyPacked(const char *msg)
{
    throw AlreadyPackedException(msg);
}


/*************************************************************************
// decompression
**************************************************************************/

void throwCantUnpack(const char *msg)
{
    // UGLY, but makes things easier
    throwCantPack(msg);
}

void throwNotPacked(const char *msg)
{
    if (msg == NULL)
        msg = "not packed by UPX";
    throw NotPackedException(msg);
}

void throwChecksumError()
{
    throw Exception("checksum error");
}

void throwCompressedDataViolation()
{
    throw Exception("compressed data violation");
}


/*************************************************************************
// other
**************************************************************************/

void throwInternalError(const char *msg)
{
    throw InternalError(msg);
}

void throwBadLoader()
{
    throwInternalError("bad loader");
}


void throwIOException(const char *msg, int e)
{
    throw IOException(msg,e);
}


/*************************************************************************
//
**************************************************************************/

const char *prettyName(const char *n)
{
    if (!n)
        return "";
    while (*n >= '0' && *n <= '9')          // gcc / egcs
        n++;
    if (strncmp(n, "class ", 6) == 0)       // Visual C++
        n += 6;
    return n;
}

const char *prettyName(const type_info &ti)
{
    return prettyName(ti.name());
}


/*
vi:ts=4:et
*/

