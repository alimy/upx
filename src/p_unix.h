/* p_unix.h --

   This file is part of the UPX executable compressor.

   Copyright (C) 1996-2002 Markus Franz Xaver Johannes Oberhumer
   Copyright (C) 1996-2002 Laszlo Molnar
   All Rights Reserved.

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

   Markus F.X.J. Oberhumer              Laszlo Molnar
   <mfx@users.sourceforge.net>          <ml1050@users.sourceforge.net>
 */


#ifndef __UPX_P_UNIX_H
#define __UPX_P_UNIX_H


/*************************************************************************
// Abstract class for all Unix-type packers.
// Already provides most of the functionality.
**************************************************************************/

class PackUnix : public Packer
{
    typedef Packer super;
protected:
    PackUnix(InputFile *f);
public:
    virtual int getVersion() const { return 11; }
    virtual const int *getFilters() const { return NULL; }

    virtual void pack(OutputFile *fo);
    virtual void unpack(OutputFile *fo);

    virtual bool canPack();
    virtual bool canUnpack();

protected:
    // called by the generic pack()
    virtual void patchLoader() = 0;

    // in order too share as much code as possible we introduce
    // an endian abstraction here
    virtual unsigned get_native32(const void *) = 0;
    virtual void set_native32(void *, unsigned) = 0;

    virtual bool checkCompressionRatio(unsigned, unsigned) const;

    int exetype;
    unsigned blocksize;
    unsigned progid;              // program id
    unsigned overlay_offset;      // used when decompressing
};


/*************************************************************************
// abstract classes encapsulating endian issues
// note: UPX_MAGIC is always stored in le32 format
**************************************************************************/

class PackUnixBe32 : public PackUnix
{
    typedef PackUnix super;
protected:
    PackUnixBe32(InputFile *f) : super(f) { }
    virtual unsigned get_native32(const void *b)
    {
        return get_be32(b);
    }
    virtual void set_native32(void *b, unsigned v)
    {
        set_be32(b, v);
    }
};


class PackUnixLe32 : public PackUnix
{
    typedef PackUnix super;
protected:
    PackUnixLe32(InputFile *f) : super(f) { }
    virtual unsigned get_native32(const void *b)
    {
        return get_le32(b);
    }
    virtual void set_native32(void *b, unsigned v)
    {
        set_le32(b, v);
    }
};


/*************************************************************************
// linux/i386
**************************************************************************/

class PackLinuxI386 : public PackUnixLe32
{
    typedef PackUnixLe32 super;
public:
    PackLinuxI386(InputFile *f) : super(f) { }
    virtual int getFormat() const { return UPX_F_LINUX_i386; }
    virtual const char *getName() const { return "linux/386"; }
    virtual int getCompressionMethod() const;

    virtual bool canPack();

protected:
    virtual const upx_byte *getLoader() const;
    virtual int getLoaderSize() const;

    virtual void patchLoader();

    enum {
        UPX_ELF_MAGIC = 0x5850557f          // "\x7fUPX"
    };
};


/*************************************************************************
// solaris/sparc
**************************************************************************/

#if 0
class PackSolarisSparc : public PackUnixBe32
{
    typedef PackUnixBe32 super;
public:
    PackSolarisSparc(InputFile *f) : super(f) { }
    virtual int getFormat() const { return UPX_F_SOLARIS_SPARC; }
    virtual const char *getName() const { return "solaris/sparc"; }

    virtual bool canPack();

protected:
    virtual const upx_byte *getLoader() const;
    virtual int getLoaderSize() const;

    virtual void patchLoader();
};
#endif


#endif /* already included */


/*
vi:ts=4:et
*/

