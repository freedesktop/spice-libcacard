/*
 * common.h: Utility functions for libcacard
 *
 * Copyright (C) 2016 - 2018 Red Hat, Inc.
 *
 * Authors: Robert Relyea <rrelyea@redhat.com>
 *          Jakub Jelen <jjelen@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _COMMON_H
#define _COMMON_H

#include <stddef.h>

unsigned char *ushort2lebytes(unsigned char *buf, unsigned short x);
unsigned short lebytes2ushort(const unsigned char *buf);

char *hex_dump(const unsigned char *buf, size_t buflen);

#endif
