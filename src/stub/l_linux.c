/* l_linux.c -- stub loader for Linux

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


#if !defined(__linux__) || !defined(__i386__)
#  error "this stub must be compiled under linux/i386"
#endif

struct timex;

#define __need_timeval
#include <sys/types.h>
#include <sys/resource.h>
#include <elf.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/time.h>
#include <time.h>
#include <linux/errno.h>
#include <linux/mman.h>
#include <linux/personality.h>
//#include <linux/timex.h>
#include <linux/unistd.h>


/*************************************************************************
// configuration section
**************************************************************************/

// use malloc instead of the bss segement
#define USE_MALLOC


/*************************************************************************
// syscalls
//
// Because of different <asm/unistd.h> versions and subtle bugs
// in both gcc and egcs we define all syscalls manually.
// Also, errno conversion is not necessary in our case.
**************************************************************************/

#undef _syscall0
#undef _syscall1
#undef _syscall2
#undef _syscall3
#ifndef __NR__exit
#  define __NR__exit __NR_exit
#endif

#if defined(__i386__)
#define _syscall0(type,name) \
type name(void) \
{ \
long __res; \
__asm__ __volatile__ ("int $0x80" \
        : "=a" (__res) \
        : "a" (__NR_##name)); \
return (type) __res; \
}

#define _syscall1(type,name,type1,arg1) \
type name(type1 arg1) \
{ \
long __res; \
__asm__ __volatile__ ("int $0x80" \
        : "=a" (__res) \
        : "a" (__NR_##name),"b" ((long)(arg1))); \
return (type) __res; \
}

#define _syscall2(type,name,type1,arg1,type2,arg2) \
type name(type1 arg1,type2 arg2) \
{ \
long __res; \
__asm__ __volatile__ ("int $0x80" \
        : "=a" (__res) \
        : "a" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2))); \
return (type) __res; \
}

#define _syscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
type name(type1 arg1,type2 arg2,type3 arg3) \
{ \
long __res; \
__asm__ __volatile__ ("int $0x80" \
        : "=a" (__res) \
        : "a" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2)), \
                  "d" ((long)(arg3))); \
return (type) __res; \
}
#endif /* __i386__ */

#define access          syscall_access
#define fcntl           syscall_fcntl
#define getcwd          syscall_getcwd
#define getrusage       syscall_getrusage
#define gettimeofday    syscall_gettimeofday
#define nanosleep       syscall_nanosleep
#define open            syscall_open
#define personality     syscall_personality

static inline _syscall2(int,access,const char *,file,int,mode)
static inline _syscall1(int,adjtimex,struct timex *,ntx)
static inline _syscall1(int,close,int,fd)
static inline _syscall3(int,execve,const char *,file,char **,argv,char **,envp)
static inline _syscall1(int,_exit,int,exitcode)
static inline _syscall3(int,fcntl,int,fd,int,cmd,long,arg)
static inline _syscall2(int,ftruncate,int,fd,size_t,len)
static inline _syscall0(pid_t,fork)
static inline _syscall2(int,getcwd,char *,buf,unsigned long,size);
static inline _syscall0(pid_t,getpid)
static inline _syscall2(int,getrusage,int,who,struct rusage *,usage);
static inline _syscall2(int,gettimeofday,struct timeval *,tv,void *,tz)
static inline _syscall3(off_t,lseek,int,fd,off_t,offset,int,whence)
static inline _syscall1(caddr_t,mmap,const int *,args)
static inline _syscall3(int,msync,const void *,start,size_t,length,int,flags)
static inline _syscall2(int,munmap,void *,start,size_t,length)
static inline _syscall2(int,nanosleep,const struct timespec *,rqtp,struct timespec *,rmtp)
static inline _syscall3(int,open,const char *,file,int,flag,int,mode)
static inline _syscall1(int,personality,unsigned long,persona)
static inline _syscall3(int,read,int,fd,char *,buf,off_t,count)
static inline _syscall3(pid_t,waitpid,pid_t,pid,int *,wait_stat,int,options)
static inline _syscall3(int,write,int,fd,const char *,buf,off_t,count)
static inline _syscall1(int,unlink,const char *,file)
#define exit _exit


#undef int32_t
#undef uint32_t
#define int32_t         int
#define uint32_t        unsigned int


/*************************************************************************
// file util
**************************************************************************/

#undef xread
#undef xwrite

#if 1
//static int xread(int fd, void *buf, int count) __attribute__((__stdcall__));
static int xread(int fd, void *buf, int count)
{
    // note: we can assert(count > 0);
    do {
        int n = read(fd, buf, count);
        if (n == -EINTR)
            continue;
        if (n <= 0)
            break;
        buf += n;               // gcc extension: add to void *
        count -= n;
    } while (count > 0);
    return count;
}
#else
#define xread(fd,buf,count)     ((count) - read(fd,buf,count))
#endif


#if 1
static __inline__ int xwrite(int fd, const void *buf, int count)
{
    // note: we can assert(count > 0);
    do {
        int n = write(fd, buf, count);
        if (n == -EINTR)
            continue;
        if (n <= 0)
            break;
        buf += n;               // gcc extension: add to void *
        count -= n;
    } while (count > 0);
    return count;
}
#else
#define xwrite(fd,buf,count)    ((count) - write(fd,buf,count))
#endif


/*************************************************************************
// util
**************************************************************************/

static char *upx_itoa(char *buf, unsigned long v)
{
    char *p = buf;
    {
        unsigned long k = v;
        do {
            p++;
            k /= 10;
        } while (k > 0);
    }
    buf = p;
    *p = 0;
    {
        unsigned long k = v;
        do {
            *--p = '0' + k % 10;
            k /= 10;
        } while (k > 0);
    }
    return buf;
}


#if defined(__i386__)
#  define SET2(p, c0, c1) \
        * (unsigned short *) (p) = ((c1)<<8 | c0)
#  define SET4(p, c0, c1, c2, c3) \
        * (uint32_t *) (p) = ((c3)<<24 | (c2)<<16 | (c1)<<8 | c0)
#  define SET3(p, c0, c1, c2) \
        SET4(p, c0, c1, c2, 0)
#else
#  define SET2(p, c0, c1) \
        (p)[0] = c0, (p)[1] = c1
#  define SET3(p, c0, c1, c2) \
        (p)[0] = c0, (p)[1] = c1, (p)[2] = c2
#  define SET4(p, c0, c1, c2, c3) \
        (p)[0] = c0, (p)[1] = c1, (p)[2] = c2, (p)[3] = c3
#endif


/*************************************************************************
// UPX & NRV stuff
**************************************************************************/

// must be the same as in p_unix.cpp !
#define OVERHEAD        2048
#if !defined(USE_MALLOC)
#  define BLOCKSIZE     (512*1024)
#endif


// patch & magic constants for our loader (le32 format)
#define UPX1            0x31585055          // "UPX1"
#define UPX2            0x32585055          // "UPX2"
#define UPX3            0x33585055          // "UPX4"
#define UPX4            0x34585055          // "UPX4"
#define UPX5            0x35585055          // "UPX5"
#define UPX_MAGIC_LE32  0x21585055          // "UPX!"


typedef int nrv_int;
typedef int nrv_int32;
typedef unsigned nrv_uint;
typedef unsigned nrv_uint32;
#define nrv_byte unsigned char
#define nrv_voidp void *

#if defined(__i386__)
extern int
nrv2b_decompress_asm_fast ( const nrv_byte *src, nrv_uint src_len,
                            nrv_byte *dst, nrv_uint *dst_len );
#define nrv2b_decompress        nrv2b_decompress_asm_fast
extern int
nrv2d_decompress_asm_fast ( const nrv_byte *src, nrv_uint src_len,
                            nrv_byte *dst, nrv_uint *dst_len );
#define nrv2d_decompress        nrv2d_decompress_asm_fast
#endif /* __i386__ */


/*************************************************************************
// upx_main - called by our entry code
//
// This function is optimized for size.
**************************************************************************/

void upx_main(char *argv[], char *envp[]) __asm__("upx_main");
void upx_main(char *argv[], char *envp[])
{
    // file descriptors
    int fdi, fdo;

    uint32_t header[3];
    // header[0]: a random program id generated at compression time
    // header[1]: original (uncompressed) file size
    // header[2]: blocksize used for compression

    // for getpid()
    pid_t pid;

    // temporary file name (max 14 chars)
    static char tmpname_buf[] = "/tmp/upxAAAAAAAAAAA";
    char *tmpname = tmpname_buf;
    char procself_buf[64];
    char *procself;

    // decompression buffer
#if defined(USE_MALLOC)
    unsigned char *buf;
    static int malloc_args[6] = {
        0, UPX5, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
    };
#else
    static unsigned char buf[BLOCKSIZE + OVERHEAD];
#endif

    //
    // ----- Step 0: set /proc/self using /proc/<pid> -----
    //

    //personality(PER_LINUX);
    pid = getpid();
    SET4(procself_buf + 0, '/', 'p', 'r', 'o');
    SET2(procself_buf + 4, 'c', '/');
    procself = upx_itoa(procself_buf + 6, pid);
    *procself++ = '/';


    //
    // ----- Step 1: prepare input file -----
    //

    // Open the exe.
    SET3(procself, 'e', 'x', 'e');
    fdi = open(procself_buf, O_RDONLY, 0);
#if 1
    // try /proc/<pid>/file for the sake of FreeBSD
    if (fdi < 0)
    {
        SET4(procself, 'f', 'i', 'l', 'e');
        fdi = open(procself_buf, O_RDONLY, 0);
    }
#endif
#if 0
    // Save some bytes of code - the lseek() below will fail anyway.
    if (fdi < 0)
        goto error1;
#endif

    // Seek to start of compressed data. The offset is patched
    // by the compressor.
    if (lseek(fdi, UPX1, 0) < 0)
        goto error1;
    // Read header.
    if (xread(fdi, (void *)header, 12) != 0)
        goto error1;
    // Paranoia. Make sure this is actually our expected executable
    // by checking the random program id. (The id is both stored
    // in the header and patched into this stub.)
    if (header[0] != UPX2)
        goto error1;


    //
    // ----- Step 2: prepare temporary output file -----
    //

    // Compute name of temporary output file in tmpname[].
    // Protect against Denial-of-Service attacks.
    {
        char *p = tmpname_buf + sizeof(tmpname_buf) - 1;
        uint32_t r;

        // Compute the last 4 characters (20 bits) from getpid().
        {
            unsigned k = 4;
            r = (uint32_t) pid;
            do {
                unsigned char d = r % 32;
                if (d >= 26) d += '0' - 'Z' - 1;
                *--p += d;
                r /= 32;
            } while (--k > 0);
        }

        // Provide 4 random bytes from our program id.
        r ^= header[0];
        // Mix in 4 runtime random bytes.
        // Don't consume precious bytes from /dev/urandom.
        {
#if 1
            struct timeval tv;
            gettimeofday(&tv, 0);
            r ^= (uint32_t) tv.tv_sec;
            r ^= ((uint32_t) tv.tv_usec) << 12;      // shift into high-bits
#else
            // using adjtimex() may cause portability problems
            static struct timex tx;
            adjtimex(&tx);
            r ^= (uint32_t) tx.time.tv_sec;
            r ^= ((uint32_t) tx.time.tv_usec) << 12; // shift into high-bits
            r ^= (uint32_t) tx.errcnt;
#endif
        }
        // Compute 7 more characters from the 32 random bits.
        {
            unsigned k = 7;
            do {
                unsigned char d = r % 32;
                if (d >= 26) d += '0' - 'Z' - 1;
                *--p += d;
                r /= 32;
            } while (--k > 0);
        }
    }

    // Just in case, remove the file.
    {
        int err = unlink(tmpname);
        if (err != -ENOENT && err != 0)
            goto error1;
    }

    // Create the temporary output file.
    fdo = open(tmpname, O_WRONLY | O_CREAT | O_EXCL, 0700);
#if 0
    // Save some bytes of code - the ftruncate() below will fail anyway.
    if (fdo < 0)
        goto error;
#endif

    // Set expected file size.
    if (ftruncate(fdo, header[1]) != 0)
        goto error;


    //
    // ----- Step 3: setup memory -----
    //

#if defined(USE_MALLOC)
    buf = mmap(malloc_args);
    if ((unsigned long) buf >= (unsigned long) -4095)
        goto error;
#else
    if (header[2] > BLOCKSIZE)
        goto error;
#endif


    //
    // ----- Step 4: decompress blocks -----
    //

    for (;;)
    {
        int32_t size[2];
        // size[0]: uncompressed block size
        // size[1]: compressed block size
        //   Note: if size[0] == size[1] then the block was not
        //   compressible and is stored in its uncompressed form.
        int i;

        // Read and check block sizes.
        if (xread(fdi, (void *)size, 8) != 0)
            goto error;
        if (size[0] == 0)                       // uncompressed size 0 -> EOF
        {
            if (size[1] != UPX_MAGIC_LE32)      // size[1] must be h->magic
                goto error;
            if (header[1] != 0)                 // all bytes must be written
                goto error;
            break;
        }
        if (size[1] <= 0)
            goto error;
        if (size[1] > size[0] || size[0] > (int32_t)header[2])
            goto error;
        // Now we have:
        //   assert(size[1] <= size[0]);
        //   assert(size[0] > 0 && size[0] <= blocksize);
        //   assert(size[1] > 0 && size[1] <= blocksize);

        // Read compressed block.
        i = header[2] + OVERHEAD - size[1];
        if (xread(fdi, buf+i, size[1]) != 0)
            goto error;

        // Decompress block.
        if (size[1] < size[0])
        {
            // in-place decompression
            nrv_uint out_len;
#if defined(NRV2B)
            i = nrv2b_decompress(buf+i, size[1], buf, &out_len);
#elif defined(NRV2D)
            i = nrv2d_decompress(buf+i, size[1], buf, &out_len);
#else
#  error
#endif
            if (i != 0 || out_len != (nrv_uint)size[0])
                goto error;
            // i == 0 now
        }

        // Write uncompressed block.
        if (xwrite(fdo, buf+i, size[0]) != 0)
        {
// error exit is here in the middle to keep the jumps short.
        error:
            (void) unlink(tmpname);
        error1:
            // Note: the kernel will close all open files and
            //       unmap any allocated memory.
            for (;;)
                (void) exit(127);
        }
        header[1] -= size[0];
    }


    //
    // ----- Step 5: release resources -----
    //

#if defined(USE_MALLOC)
    munmap(buf, malloc_args[1]);
#endif

    if (close(fdo) != 0)
        goto error;
    if (close(fdi) != 0)
        goto error;


    //
    // ----- Step 6: try to start program via /proc/self/fd/X -----
    //

    // Many thanks to Andi Kleen <ak@muc.de> and
    // Jamie Lokier <nospam@cern.ch> for this nice idea.

    // Open the temp file.
    fdi = open(tmpname, O_RDONLY, 0);
    if (fdi < 0)
        goto error;

    // Compute name of temp fdi.
    SET3(procself, 'f', 'd', '/');
    upx_itoa(procself + 3, fdi);

    // Check for working /proc/self/fd/X by accessing the
    // temp file again, now via temp fdi.
#define err fdo
    err = access(procself_buf, R_OK | X_OK);
    if (err == UPX3)
    {
        // Now it's safe to unlink the temp file (as it is still open).
        unlink(tmpname);
        // Set the file close-on-exec.
        fcntl(fdi, F_SETFD, FD_CLOEXEC);
        // Execute the original program via /proc/self/fd/X.
        execve(procself_buf, argv, envp);
        // If we get here we've lost.
    }
#undef err

    // The proc filesystem isn't working. No problem.
    close(fdi);


    //
    // ----- Step 7: start program in /tmp  -----
    //

    // Fork off a subprocess to clean up.
    // We have to do this double-fork trick to keep a zombie from
    // hanging around if the spawned original program doesn't check for
    // subprocesses (as well as to prevent the real program from getting
    // confused about this subprocess it shouldn't have).
    // Thanks to Adam Ierymenko <api@one.net> for this solution.

    if (fork() == 0)
    {
        if (fork() == 0)
        {
            // Sleep 3 seconds, then remove the temp file.
            static const struct timespec ts = { UPX4, 0 };
            nanosleep(&ts, 0);
            unlink(tmpname);
        }
        exit(0);
    }

    // Wait for the first fork()'d process to die.
    waitpid(-1, (int *)0, 0);

    // Execute the original program.
    execve(tmpname, argv, envp);


    //
    // ----- Step 8: error exit -----
    //

    // If we return from execve() there was an error. Give up.
    goto error;
}


/*
vi:ts=4:et:nowrap
*/

