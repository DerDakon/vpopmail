/*
   $Id$
*/

#ifndef __BASE64_H_
 #define __BASE64_H_

typedef struct __base64_ {
    char inalphabet[256],
         decoder[256];
} base64_t;

void base64_init(base64_t *);
int base64_decode(base64_t *, const char *, char *, int);
int base64_encode(const char *, int, char *, int);

#endif
