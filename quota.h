/*
 * $Id$
 * Copyright (C) 1999-2009 Inter7 Internet Technologies, Inc.
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
 *
 */

#ifndef __QUOTA_H_
   #define __QUOTA_H_

#include "storage.h"

int quota_check(const char *);
int quota_compare(const char *, const char *);
int quota_usage(const char *, const char *);
int quota_get_usage(const char *, storage_t *, storage_t *);
int quota_mtos(const char *, storage_t *, storage_t *);

#endif
