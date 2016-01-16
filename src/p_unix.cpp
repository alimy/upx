/* p_unix.cpp --

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


#include "conf.h"

#include "file.h"
#include "packer.h"
#include "p_unix.h"

// do not change
#define BLOCKSIZE       (512*1024)
#define OVERHEAD        2048


/*************************************************************************
//
**************************************************************************/

PackUnix::PackUnix(InputFile *f) :
    super(f), exetype(0), blocksize(0), overlay_offset(0)
{
}


// common part of canPack(), enhanced by subclasses
bool PackUnix::canPack()
{
    if (exetype == 0)
        return false;

#if defined(__unix__)
    // must be executable by owner
    if ((fi->st.st_mode & S_IXUSR) == 0)
        throwCantPack("file not executable; try `chmod +x'");
#endif
    if (file_size < 4096)
        throwCantPack("file is too small");

    // info: currently the header is 36 (32+4) bytes before EOF
    unsigned char buf[256];
    fi->seek(-(long)sizeof(buf), SEEK_END);
    fi->readx(buf,sizeof(buf));
    if (pfind_le32(buf,sizeof(buf),UPX_MAGIC_LE32))  // note: always le32
        throwAlreadyPacked();

    return true;
}


/*************************************************************************
// Generic Unix pack(). Subclasses must provide writeLoader().
//
// A typical compressed Unix executable looks like this:
//   - loader stub
//   - 12 bytes header info
//   - the compressed blocks, each with a 8 byte header for block sizes
//   - 4 bytes block end marker (uncompressed size 0)
//   - 32 bytes UPX packheader
//   - 4 bytes overlay offset
**************************************************************************/

// see note below and Packer::compress()
bool PackUnix::checkCompressionRatio(unsigned, unsigned) const
{
    return true;
}

void PackUnix::pack(OutputFile *fo)
{
    // set options
    blocksize = opt->o_unix.blocksize;
    if (blocksize <= 0)
        blocksize = BLOCKSIZE;
    if ((off_t)blocksize > file_size)
        blocksize = file_size;
    // create a pseudo-unique program id for our paranoid stub
    progid = getRandomId();

    // prepare loader
    const int lsize = getLoaderSize();
    loader = new upx_byte[lsize + 12];
    memcpy(loader,getLoader(),lsize);

    // prepare header info
    unsigned char *hbuf = loader + lsize;
    set_native32(hbuf+0,progid);
    set_native32(hbuf+4,file_size);
    set_native32(hbuf+8,blocksize);

    // patch loader, write loader + header info
    patchLoader();
    fo->write(loader, lsize + 12);

    // init compression buffers
    ibuf = new upx_byte[blocksize];
    obuf = new upx_byte[blocksize+blocksize/8+256];

    // compress blocks
    unsigned total_in = 0;
    unsigned total_out = 0;
    ui_total_passes = (file_size + blocksize - 1) / blocksize;
    if (ui_total_passes == 1)
        ui_total_passes = 0;
    fi->seek(0, SEEK_SET);
    for (;;)
    {
        int l = fi->read(ibuf, blocksize);
        if (l == 0)
            break;

        // Note:
        //   Compression of a single block can fail for a number of
        //   reasons, e.g. if the  file is blocksize + 1 bytes long.
        //   We just continue and check the final compression ratio.
        const unsigned saved_c_adler = ph.c_adler;

        // compress
        ph.u_len = l;
        (void) compress(ibuf, obuf);   // ignore return value

        if (ph.c_len < ph.u_len)
        {
            if (!testOverlappingDecompression(obuf, ibuf, OVERHEAD))
            {
                // not in-place compressible
                ph.c_len = ph.u_len;
            }
        }
        if (ph.c_len >= ph.u_len)
        {
            // block is not compressible
            ph.c_len = ph.u_len;
            // manually update checksum of compressed data
            ph.c_adler = upx_adler32(ibuf, ph.u_len, saved_c_adler);
        }

        // write block sizes
        unsigned char size[8];
        set_native32(size+0, ph.u_len);
        set_native32(size+4, ph.c_len);
        fo->write(size, 8);

        // write compressed data
        if (ph.c_len < ph.u_len)
            fo->write(obuf, ph.c_len);
        else
            fo->write(ibuf, ph.u_len);

        total_in += ph.u_len;
        total_out += ph.c_len;
    }
    if ((off_t)total_in != file_size)
        throw EOFException();

    // write block end marker (uncompressed size 0)
    fo->write("\x00\x00\x00\x00", 4);

    // update header with totals
    ph.u_len = total_in;
    ph.c_len = total_out;

    // write header
    const int hsize = ph.getPackHeaderSize();
    set_le32(obuf, ph.magic);               // note: always le32
    putPackHeader(obuf, hsize);
    fo->write(obuf, hsize);

    // write overlay offset (needed for decompression)
    set_native32(obuf, lsize);
    fo->write(obuf, 4);

    // finally check compression ratio
    if (!Packer::checkCompressionRatio(fo->getBytesWritten(), ph.u_len))
        throwNotCompressible();
}


/*************************************************************************
// Generic Unix canUnpack().
**************************************************************************/

bool PackUnix::canUnpack()
{
    upx_byte buf[128];
    const int bufsize = sizeof(buf);

    fi->seek(-bufsize, SEEK_END);
    if (!readPackHeader(128, -1, buf))
        return false;

    int l = ph.buf_offset + ph.getPackHeaderSize();
    if (l < 0 || l + 4 > bufsize)
        throwCantUnpack("file corrupted");
    overlay_offset = get_native32(buf+l);
    if ((off_t)overlay_offset >= file_size)
        throwCantUnpack("file corrupted");

    return true;
}


/*************************************************************************
// Generic Unix unpack().
//
// This code looks much like the one in stub/l_linux.c
// See notes there.
**************************************************************************/

void PackUnix::unpack(OutputFile *fo)
{
    unsigned c_adler = 1;   // == upx_adler32(NULL, 0);
    unsigned u_adler = 1;   // == upx_adler32(NULL, 0);

    // defaults for ph.version == 8
    unsigned orig_file_size = 0;
    blocksize = 512 * 1024;

    fi->seek(overlay_offset, SEEK_SET);
    if (ph.version > 8)
    {
        unsigned char hbuf[12];
        fi->readx(hbuf, 12);
        orig_file_size = get_native32(hbuf+4);
        blocksize = get_native32(hbuf+8);

        if (file_size > (off_t)orig_file_size || blocksize > orig_file_size)
            throwCantUnpack("file header corrupted");
    }
    else
    {
        // skip 4 bytes (program id)
        fi->seek(4, SEEK_CUR);
    }

    ibuf = new upx_byte[blocksize + OVERHEAD];

    // decompress blocks
    unsigned total_in = 0;
    unsigned total_out = 0;
    for (;;)
    {
#define buf ibuf
        int i;
        int size[2];

        fi->readx(buf, 8);
        ph.u_len = size[0] = get_native32(buf+0);
        ph.c_len = size[1] = get_native32(buf+4);

        if (size[0] == 0)                   // uncompressed size 0 -> EOF
        {
            // note: must reload size[1] as magic is always stored le32
            size[1] = get_le32(buf+4);
            if (size[1] != UPX_MAGIC_LE32)  // size[1] must be h->magic
                throwCompressedDataViolation();
            break;
        }
        if (size[0] <= 0 || size[1] <= 0)
            throwCompressedDataViolation();
        if (size[1] > size[0] || size[0] > (int)blocksize)
            throwCompressedDataViolation();

        i = blocksize + OVERHEAD - size[1];
        fi->readx(buf+i, size[1]);
        // update checksum of compressed data
        c_adler = upx_adler32(buf + i, size[1], c_adler);
        // decompress
        if (size[1] < size[0])
        {
            decompress(buf+i, buf, false);
            i = 0;
        }
        // update checksum of uncompressed data
        u_adler = upx_adler32(buf + i, size[0], u_adler);
        total_in += size[1];
        total_out += size[0];
        // write block
        if (fo)
            fo->write(buf + i, size[0]);
#undef buf
    }

    // update header with totals
    ph.c_len = total_in;
    ph.u_len = total_out;

    // all bytes must be written
    if (ph.version > 8 && total_out != orig_file_size)
        throw EOFException();

    // finally test the checksums
    if (ph.c_adler != c_adler || ph.u_adler != u_adler)
        throwChecksumError();
}


/*************************************************************************
// Linux/i386 specific
**************************************************************************/

static const
#include "stub/l_lx_n2b.h"
static const
#include "stub/l_lx_n2d.h"
static const
#include "stub/l_lx_n2e.h"


int PackLinuxI386::getCompressionMethod() const
{
    if (M_IS_NRV2B(opt->method))
        return M_NRV2B_LE32;
    if (M_IS_NRV2D(opt->method))
        return M_NRV2D_LE32;
    if (M_IS_NRV2E(opt->method))
        return M_NRV2E_LE32;
    return opt->level > 1 && file_size >= 512*1024 ? M_NRV2D_LE32 : M_NRV2B_LE32;
}


const upx_byte *PackLinuxI386::getLoader() const
{
    if (M_IS_NRV2B(opt->method))
        return linux_i386_nrv2b_loader;
    if (M_IS_NRV2D(opt->method))
        return linux_i386_nrv2d_loader;
    if (M_IS_NRV2E(opt->method))
        return linux_i386_nrv2e_loader;
    return NULL;
}

int PackLinuxI386::getLoaderSize() const
{
    if (M_IS_NRV2B(opt->method))
        return sizeof(linux_i386_nrv2b_loader);
    if (M_IS_NRV2D(opt->method))
        return sizeof(linux_i386_nrv2d_loader);
    if (M_IS_NRV2E(opt->method))
        return sizeof(linux_i386_nrv2e_loader);
    return 0;
}


bool PackLinuxI386::canPack()
{
    unsigned char buf[52];      // sizeof(ELF_LE32_Ehdr)
    exetype = 0;

    fi->readx(buf,sizeof(buf));
    fi->seek(0, SEEK_SET);
    const unsigned l = get_le32(buf);
    if (!memcmp(buf, "\x7f\x45\x4c\x46\x01\x01\x01", 7)) // ELF 32-bit LSB
    {
        exetype = 1;
        // now check the ELF header
        if (memcmp(buf+8, "FreeBSD", 7) == 0)   // branded
            exetype = 0;
        if (get_le16(buf+16) != 2)              // e_type - executable
            exetype = 0;
        if (get_le16(buf+18) != 3)              // e_machine - Intel 80386
            exetype = 0;
        if (get_le32(buf+20) != 1)              // e_version
            exetype = 0;
        if (get_le16(buf+44) < 1)               // e_phnum
            exetype = 0;
        // check for Linux kernels
        const unsigned e_entry = get_le32(buf+24);
        if (e_entry == 0xC0100000)              // uncompressed vmlinux
            exetype = 0;
        if (e_entry == 0x00001000)              // compressed vmlinux
            exetype = 0;
        if (e_entry == 0x00100000)              // compressed bvmlinux
            exetype = 0;
    }
    else if (l == 0x00640107 || l == 0x00640108 || l == 0x0064010b || l == 0x006400cc)
    {
        // OMAGIC / NMAGIC / ZMAGIC / QMAGIC
        exetype = 2;
        // FIXME: N_TRSIZE, N_DRSIZE
        // FIXME: check for aout shared libraries
    }
#if defined(__linux__)
    // only compress scripts when running under Linux
    else if (!memcmp(buf, "#!/", 3))                    // #!/bin/sh
        exetype = -1;
    else if (!memcmp(buf, "#! /", 4))                   // #! /bin/sh
        exetype = -1;
    else if (!memcmp(buf, "\xca\xfe\xba\xbe", 4))       // Java bytecode
        exetype = -2;
#endif

    return super::canPack();
}


void PackLinuxI386::patchLoader()
{
    const int lsize = getLoaderSize();

    // mmapsize is (blocksize + OVERHEAD) rounded up to next PAGE_SIZE
    const unsigned pagesize = 4096;
    const unsigned mmapsize = ALIGN_UP(blocksize + OVERHEAD, pagesize);

    // patch loader
    // note: we only can use /proc/self/fd when exetype > 0.
    //   also, we sleep much longer when compressing a script.
    patch_le32(loader,lsize,"UPX5",mmapsize);
    patch_le32(loader,lsize,"UPX4",exetype > 0 ? 3 : 15);   // sleep time
    patch_le32(loader,lsize,"UPX3",exetype > 0 ? 0 : 0x7fffffff);
    patch_le32(loader,lsize,"UPX2",progid);
    patch_le32(loader,lsize,"UPX1",lsize);

    // The beginning of our loader consists of a elf_hdr (52 bytes) and
    // two sections elf_phdr (2 * 32 byte), so we have 12 free bytes
    // from offset 116 to the program start at offset 128.
    assert(get_le32(loader + 28) == 52);        // e_phoff
    assert(get_le32(loader + 32) == 0);         // e_shoff
    assert(get_le16(loader + 40) == 52);        // e_ehsize
    assert(get_le16(loader + 42) == 32);        // e_phentsize
    assert(get_le16(loader + 44) == 2);         // e_phnum
    assert(get_le16(loader + 48) == 0);         // e_shnum
    assert(lsize > 128 && lsize < 4096);
    // set additional info
    set_le32(loader + 120, UPX_ELF_MAGIC);
    set_le16(loader + 124, lsize);
    loader[126] = (unsigned char) ph.version;
    loader[127] = (unsigned char) ph.format;

    // checksum for loader + 12 header bytes
    set_le32(loader + 116, 0);
    unsigned adler = upx_adler32(loader, lsize + 12);
    set_le32(loader + 116, adler);
}


/*
vi:ts=4:et
*/

