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

#ifndef __GROUP_H_
   #define __GROUP_H_

/*
   Box group structure
*/

typedef struct __group_ {
   char *owner,					// Owner of group
		**member,				// Members of group
		datafile[255];			// Data file location

   int n_members,				// Number of members
	   max_members,				// Maximum members allowed
	   quota;					// Quota of members
} group_t;

int group_init(group_t *);
void group_reset(group_t *);
int group_load(char *, char *, group_t *);
int group_add(group_t *, char *, char *);
int group_remove(group_t *, char *, char *);
int group_write(group_t *);
int group_new(group_t *, char *, char *);

#endif
