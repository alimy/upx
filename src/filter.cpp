/* filter.cpp --

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
#include "filter.h"


/*************************************************************************
// util
**************************************************************************/

static //inline
void initFilter(Filter *f, upx_byte *buf, unsigned buf_len)
{
    f->buf = buf;
    f->buf_len = buf_len;
    // clear output parameters
    f->calls = f->wrongcalls = f->noncalls = f->lastcall = 0;
}


/*************************************************************************
// implementation
**************************************************************************/

const FilterImp::f_t *FilterImp::getFilter(int id)
{
    static bool done = false;
    static unsigned filter_id[256];

    if (id < 0 || id > 255)
        return NULL;
    if (!done)
    {
        memset(filter_id, 0xff, sizeof(filter_id));
        for (int i = 0; i < n_filters; i++)
            filter_id[filters[i].id] = i;
        done = true;
    }

    unsigned index = filter_id[id];
    if (index > 255)
        return NULL;
    assert(filters[index].id == id);
    return &filters[index];
}


/*************************************************************************
// high level API
**************************************************************************/

void Filter::init(int id_, unsigned addvalue_)
{
    this->id = id_;
    initFilter(this, NULL, 0);
    // clear input parameters
    this->addvalue = addvalue_;
    this->forced_cto = -1;
    this->preferred_ctos = NULL;
    // clear input/output parameters
    this->cto = 0;
}


bool Filter::filter(upx_byte *buf_, unsigned buf_len_)
{
    initFilter(this, buf_, buf_len_);
    const FilterImp::f_t *ft = FilterImp::getFilter(id);
    if (ft == NULL)
        throwInternalError("filter-1");
    if (ft->id == 0)
        return true;
    if (buf_len < ft->min_buf_len)
        return false;
    if (ft->max_buf_len && buf_len > ft->max_buf_len)
        return false;
    if (!ft->f)
        throwInternalError("filter-2");

    // setChecksum
    this->adler = 0;
    if (clevel != 1)
        this->adler = upx_adler32(this->buf, this->buf_len);
    //printf("filter: %02x %p %d\n", this->id, this->buf, this->buf_len);
    int r = (*ft->f)(this);
    //printf("filter: %02x %d\n", ft->id, r);
    if (r > 0)
        throwFilterException();
    if (r == 0)
        return true;
    return false;
}


bool Filter::unfilter(upx_byte *buf_, unsigned buf_len_, bool vc)
{
    initFilter(this, buf_, buf_len_);
    const FilterImp::f_t *ft = FilterImp::getFilter(id);
    if (ft == NULL)
        throwInternalError("unfilter-1");
    if (ft->id == 0)
        return true;
    if (buf_len < ft->min_buf_len)
        return false;
    if (ft->max_buf_len && buf_len > ft->max_buf_len)
        return false;
    if (!ft->u)
        throwInternalError("unfilter-2");

    //printf("unfilter: %02x %p %d\n", this->id, this->buf, this->buf_len);
    int r = (*ft->u)(this);
    //printf("unfilter: %02x %d\n", ft->id, r);
    if (r != 0)
        throwInternalError("unfilter-3");

    // verifyChecksum
    if (vc && clevel != 1)
    {
        if (this->adler != upx_adler32(this->buf, this->buf_len))
            throwInternalError("unfilter-4");
    }

    return true;
}


bool Filter::verifyUnfilter()
{
    // TODO: at some future point this verify should
    //       be not necessary any longer
    //printf("verifyUnfilter: %02x %p %d\n", this->id, this->buf, this->buf_len);
    if (clevel == 1)
        return true;
    return unfilter(this->buf, this->buf_len, true);
}


bool Filter::scan(const upx_byte *buf_, unsigned buf_len_)
{
    // Note: must use const_cast here. This is fine as the scan
    //   implementations (f->s) actually don't change the buffer.
    upx_byte *b = const_cast<upx_byte *>(buf_);
    initFilter(this, b, buf_len_);

    const FilterImp::f_t *ft = FilterImp::getFilter(id);
    if (ft == NULL)
        throwInternalError("filter-1");
    if (ft->id == 0)
        return true;
    if (buf_len < ft->min_buf_len)
        return false;
    if (ft->max_buf_len && buf_len > ft->max_buf_len)
        return false;
    if (!ft->s)
        throwInternalError("filter-2");

    //printf("filter: %02x %p %d\n", this->id, this->buf, this->buf_len);
    int r = (*ft->s)(this);
    //printf("filter: %02x %d\n", ft->id, r);
    if (r > 0)
        throwFilterException();
    if (r == 0)
        return true;
    return false;
}


/*
vi:ts=4:et
*/

