/*
   $Id$

   * Copyright (C) 2009 Inter7 Internet Technologies, Inc.
   *
   * This program is free software; you can redistribute it and/or modify
   * it under the terms of the GNU General Public License as published by
   * the Free Software Foundation; either version 2 of the License, or
   * (at your option) any later version.
   *
   * This program is distributed in the hope that it will be useful,
   * but WITHOUT ANY WARRANTY; without even the implied warranty of
   * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   * GNU General Public License for more details.
   *
   * You should have received a copy of the GNU General Public License
   * along with this program; if not, write to the Free Software
   * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
*/

#ifndef __STORAGE_H_
   #define __STORAGE_H_

#include <stdint.h>

/*
   htonll() and ntohll()
*/

#include <endian.h>
#include <byteswap.h>

#if defined(__LITTLE_ENDIAN) || defined(_LITTLE_ENDIAN) || defined(__LITTLE_ENDIAN__)
# ifndef ntohll
# if defined(__DARWIN__)
# define ntohll(_x_) NXSwapBigLongLongToHost(_x_)
# else
# define ntohll(_x_) __bswap_64(_x_)
# endif
# endif
# ifndef htonll
# if defined(__DARWIN__)
# define htonll(_x_) NXSwapHostLongLongToBig(_x_)
# else
# define htonll(_x_) __bswap_64(_x_)
# endif
# endif
#elif defined(__BIG_ENDIAN) || defined(_BIG_ENDIAN) || defined(__BIG_ENDIAN__)
# ifndef ntohll
# define ntohll(_x_) _x_
# endif
# ifndef htonll
# define htonll(_x_) _x_
# endif
#else /* No Endian selected */
# error A byte order must be selected
#endif

/*
   Define htonll() and ntohll() if not already defined
*/

#ifndef ntohll
   #define ntohll(x) __bswap_64(x)
#endif

#ifndef htonll
   #define htonll(x) __bswap_64(x)
#endif

/*
   Arbitrary storage counts
*/

typedef uint64_t storage_t;

#endif
