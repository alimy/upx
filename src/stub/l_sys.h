/* l_sys.h -- created from l_sys.bin, 926 (0x39e) bytes

   This file is part of the UPX executable compressor.

   Copyright (C) 1996-2004 Markus Franz Xaver Johannes Oberhumer
   Copyright (C) 1996-2004 Laszlo Molnar
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


#define NRV2B_LOADER_ADLER32 0x1ea7e80e
#define NRV2B_LOADER_CRC32   0xc6ee1163

unsigned char nrv2b_loader[926] = {
255,255,255,255,  0,  0, 10,  0,  0,  0, 96, 80, 83, 81, 82, 86,   /* 0x   0 */
 87, 85,190, 83, 73,191, 68, 73,137,241,  6, 30,  7,253,243,164,   /* 0x  10 */
252,187,  0,128,135,247,131,238,187, 25,237, 87,233, 74, 77, 85,   /* 0x  20 */
 80, 88, 33,161,216,208,213,  0,  0,  0,  0,  0,  0,  0,  0,  0,   /* 0x  30 */
  0,  0,  0,  0, 45,164,232,  0,  0,114,250, 65,232,  0,  0,227,   /* 0x  40 */
  0,227,  0,115,  0,131,233,  3,114,  6,136,204,172,247,208,149,   /* 0x  50 */
 49,201,232,  0,  0, 17,201,117,  8, 65,232,  0,  0,115,251, 65,   /* 0x  60 */
 65, 65,129,253,  0,243,131,209,  1,141,  3,150,243,164,150,235,   /* 0x  70 */
  0,232,  2,  0, 17,201,  1,219,117,  4,173, 17,192,147,195, 94,   /* 0x  80 */
185, 67, 84,172, 44,232, 60,  1,119,249,193,  4,  8, 41, 52,139,   /* 0x  90 */
 28,134,223, 41,243,137, 28,173,226,  0,176,232,176,233, 95,185,   /* 0x  a0 */
 67, 84,242,174,117,  0,117,  0,193,  5,  8, 41, 61,139, 29,134,   /* 0x  b0 */
223, 41,251,137, 29,175,235,  0,  7, 97, 93, 95, 94, 90, 89, 91,   /* 0x  c0 */
 88,233, 74, 79, 83, 89, 83, 77, 65, 73, 78, 49,  0,  0,  0,  0,   /* 0x  d0 */
 83, 89, 83, 73, 50, 56, 54, 49, 10,  0,  0,  0, 83, 89, 83, 73,   /* 0x  e0 */
 48, 56, 54, 49, 11,  0,  0,  0, 83, 89, 83, 77, 65, 73, 78, 50,   /* 0x  f0 */
 18,  0,  0,  0, 83, 89, 83, 83, 85, 66, 83, 73, 41,  0,  0,  0,   /* 0x 100 */
 83, 89, 83, 83, 66, 66, 66, 80, 41,  0,  0,  0, 83, 89, 83, 67,   /* 0x 110 */
 65, 76, 76, 84, 43,  0,  0,  0, 83, 89, 83, 77, 65, 73, 78, 51,   /* 0x 120 */
 44,  0,  0,  0, 85, 80, 88, 49, 72, 69, 65, 68, 47,  0,  0,  0,   /* 0x 130 */
 83, 89, 83, 67, 85, 84, 80, 79, 69,  0,  0,  0, 78, 82, 86, 50,   /* 0x 140 */
 66, 49, 54, 48, 69,  0,  0,  0,  0,  0,  0,  0, 73,  0,  0,  0,   /* 0x 150 */
 78, 82, 86, 68, 69, 67, 79, 50, 13,  0,  0,  0,  0,  0,  0,  0,   /* 0x 160 */
 79,  0,  0,  0, 78, 82, 86, 68, 69, 67, 79, 50,  8,  0,  0,  0,   /* 0x 170 */
 78, 82, 86, 68, 68, 79, 78, 69, 79,  0,  0,  0,  0,  0,  0,  0,   /* 0x 180 */
 81,  0,  0,  0, 78, 82, 86, 68, 69, 67, 79, 50, 22,  0,  0,  0,   /* 0x 190 */
 78, 82, 86, 68, 82, 69, 84, 85, 81,  0,  0,  0,  0,  0,  0,  0,   /* 0x 1a0 */
 83,  0,  0,  0, 78, 82, 86, 68, 69, 67, 79, 50, 21,  0,  0,  0,   /* 0x 1b0 */
 78, 82, 86, 68, 69, 67, 79, 49, 83,  0,  0,  0,  0,  0,  0,  0,   /* 0x 1c0 */
 85,  0,  0,  0, 78, 82, 86, 50, 66, 49, 54, 48,  7,  0,  0,  0,   /* 0x 1d0 */
  0,  0,  0,  0,101,  0,  0,  0, 78, 82, 86, 68, 69, 67, 79, 50,   /* 0x 1e0 */
  8,  0,  0,  0,  0,  0,  0,  0,109,  0,  0,  0, 78, 82, 86, 68,   /* 0x 1f0 */
 69, 67, 79, 50,  8,  0,  0,  0, 78, 82, 86, 76, 69, 68, 48, 48,   /* 0x 200 */
113,  0,  0,  0, 78, 82, 86, 71, 84, 68, 48, 48,114,  0,  0,  0,   /* 0x 210 */
 78, 82, 86, 68, 69, 67, 79, 50,121,  0,  0,  0,  0,  0,  0,  0,   /* 0x 220 */
129,  0,  0,  0, 78, 82, 86, 50, 66, 49, 54, 48,  1,  0,  0,  0,   /* 0x 230 */
 78, 82, 86, 50, 66, 49, 54, 57,143,  0,  0,  0, 67, 65, 76, 76,   /* 0x 240 */
 84, 82, 49, 54,143,  0,  0,  0, 67, 84, 49, 54, 73, 50, 56, 54,   /* 0x 250 */
154,  0,  0,  0, 67, 84, 49, 54, 83, 85, 66, 48,157,  0,  0,  0,   /* 0x 260 */
 67, 84, 49, 54, 73, 48, 56, 54,159,  0,  0,  0, 67, 65, 76, 76,   /* 0x 270 */
 84, 82, 73, 50,167,  0,  0,  0,  0,  0,  0,  0,170,  0,  0,  0,   /* 0x 280 */
 67, 65, 76, 76, 84, 82, 49, 54,  4,  0,  0,  0, 67, 84, 49, 54,   /* 0x 290 */
 68, 85, 77, 49,170,  0,  0,  0, 67, 84, 49, 54, 69, 56, 48, 48,   /* 0x 2a0 */
170,  0,  0,  0, 67, 84, 49, 54, 69, 57, 48, 48,172,  0,  0,  0,   /* 0x 2b0 */
 67, 65, 76, 76, 84, 82, 73, 53,174,  0,  0,  0, 67, 84, 49, 54,   /* 0x 2c0 */
 74, 69, 78, 68,180,  0,  0,  0,  0,  0,  0,  0,182,  0,  0,  0,   /* 0x 2d0 */
 78, 82, 86, 68, 69, 67, 79, 50, 21,  0,  0,  0, 67, 84, 49, 54,   /* 0x 2e0 */
 74, 85, 76, 50,182,  0,  0,  0,  0,  0,  0,  0,184,  0,  0,  0,   /* 0x 2f0 */
 67, 65, 76, 76, 84, 82, 73, 54,  3,  0,  0,  0, 67, 84, 49, 54,   /* 0x 300 */
 68, 85, 77, 50,184,  0,  0,  0, 67, 84, 49, 54, 73, 50, 56, 55,   /* 0x 310 */
184,  0,  0,  0, 67, 84, 49, 54, 83, 85, 66, 49,187,  0,  0,  0,   /* 0x 320 */
 67, 84, 49, 54, 73, 48, 56, 55,189,  0,  0,  0, 67, 65, 76, 76,   /* 0x 330 */
 84, 82, 73, 54,197,  0,  0,  0,  0,  0,  0,  0,200,  0,  0,  0,   /* 0x 340 */
 67, 65, 76, 76, 84, 82, 73, 53,  4,  0,  0,  0, 83, 89, 83, 77,   /* 0x 350 */
 65, 73, 78, 53,200,  0,  0,  0, 83, 89, 83, 73, 50, 56, 54, 50,   /* 0x 360 */
201,  0,  0,  0, 83, 89, 83, 73, 48, 56, 54, 50,202,  0,  0,  0,   /* 0x 370 */
 83, 89, 83, 74, 85, 77, 80, 49,209,  0,  0,  0, 83, 89, 83, 84,   /* 0x 380 */
 72, 69, 78, 68,212,  0,  0,  0,255,255,255,255,212,  0            /* 0x 390 */
};
