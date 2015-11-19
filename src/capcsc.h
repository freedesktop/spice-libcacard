/*
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 */
#ifndef CAPCSC_H
#define CAPCSC_H 1

#if !defined(__LIBCACARD_H_INSIDE__) && !defined(LIBCACARD_COMPILATION)
#warning "Only <libcacard.h> can be included directly"
#endif

#define CAPCSC_POLL_TIME            50      /* ms  - Time we will poll for */
                                            /*       card change when a    */
                                            /*       reader is connected */
#define CAPCSC_MAX_READERS          16

#define CAPCSC_APPLET               "CAPCSC APPLET"

int capcsc_init(void);


#endif
