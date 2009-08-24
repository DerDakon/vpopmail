/*
 * $Id$
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

#ifndef __VPALIAS_H_
   #define __VPALIAS_H_

char *vpalias_next_return_line(char *alias);
char *vpalias_select_names_next();
void vpalias_select_names_end();
char *vpalias_select( char *alias, char *domain );
char *vpalias_select_next();
int vpalias_insert( char *alias, char *domain, char *alias_line);
int vpalias_remove( char *alias, char *domain, char *alias_line);
int vpalias_delete( char *alias, char *domain);
char *vpalias_select_names( char *domain );
char *vpalias_select_names_next();
void vpalias_select_names_end();
char *vpalias_select_all( char *alias, char *domain );
char *vpalias_select_all_next(char *alias);
int vpalias_delete_domain(char *domain);

#endif
