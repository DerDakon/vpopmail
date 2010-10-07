/*
   $Id$
*/

#include <stdio.h>
#include <string.h>
#include "base64.h"
#include "vpopmail.h"

static unsigned char alphabet[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_init(base64_t *b)
{
  int i = 0;

  memset(b->inalphabet, 0, sizeof(b->inalphabet));
  memset(b->decoder, 0, sizeof(b->decoder));

  for (i = (sizeof alphabet) - 1; i >= 0 ; i--) {
      b->inalphabet[alphabet[i]] = 1;
      b->decoder[alphabet[i]] = i;
  }
}

int base64_decode(base64_t *b, const char *data, char *outbuf, int bufsz)
{
  unsigned char buf[3] = { 0 };
  const unsigned char *p = NULL;
  int bits = 0, char_count = 0, c = 0, out = 0;

  memset(outbuf, 0, bufsz);
  p = (const unsigned char *)data;
  char_count = bits = out = 0;

  while (*p) {
    if (*p == '=')
       break;

    if (!b->inalphabet[*p]) {
       p++;
       continue;
    }

    bits += b->decoder[*p];
    char_count++;

    if (char_count == 4) {
       buf[0] = (bits >> 16);
       buf[1] = ((bits >> 8) & 0xff);
       buf[2] = (bits & 0xff);

	   if ((out + 3) >= bufsz)
		  return VA_INTERNAL_BUFFER_EXCEEDED;

	   memcpy(outbuf, buf, 3);
	   out += 3;
	   outbuf += 3;

       bits = 0;
       char_count = 0;
    }
    
    else
       bits <<= 6;

    p++;
  }

  if (!(*p)) {
     if (char_count)
		return VA_BAD_CHAR;
  }

  else {
     switch (char_count) {
       case 1:
		  return VA_BAD_CHAR;

       case 2:
            c = (bits >> 10);
			if ((out + 1) >= bufsz)
			   return VA_INTERNAL_BUFFER_EXCEEDED;

			*outbuf++ = c;
			out++;

			break;

       case 3:
            buf[0] = (bits >> 16);
            buf[1] = ((bits >> 8) & 0xff);

			if ((out + 2) >= bufsz)
			   return VA_INTERNAL_BUFFER_EXCEEDED;

			memcpy(outbuf, buf, 2);
			outbuf += 2;
			out += 2;
	    break;
     }
  }

  return VA_SUCCESS;
}

int base64_encode(const char *inbuf, int insz, char *outbuf, int outsz)
{
  unsigned long bytes = 0;
  const unsigned char *p = NULL;
  unsigned char buf[4] = { 0 };
  int cols = 0, bits = 0, c = 0, char_count = 0, ret = 0, out = 0;

  bytes = 0;
  p = (const unsigned char *)inbuf;
  bits = cols = char_count = c = 0;

  memset(outbuf, 0, outsz);
  
  while(bytes < insz) {
    bits += *p;
    char_count++;

    if (char_count == 3) {
       buf[0] = alphabet[bits >> 18];
       buf[1] = alphabet[(bits >> 12) & 0x3f];
       buf[2] = alphabet[(bits >> 6) & 0x3f];
       buf[3] = alphabet[bits & 0x3f];

	   if ((out + 4) >= outsz)
		  return VA_INTERNAL_BUFFER_EXCEEDED;

	   memcpy(outbuf, buf, 4);
	   outbuf += 4;
	   out += 4;

       cols += 4;
       
       if (cols == 72) {
		  if ((out + 2) >= outsz)
			 return VA_INTERNAL_BUFFER_EXCEEDED;

		  memcpy(outbuf, "\r\n", 2);
		  outbuf += 2;
		  out += 2;

          cols = 0;
       }

       bits = 0;
       char_count = 0;
    }

    else
       bits <<= 8;    

    p++;
    bytes++;
  }

  if (char_count != 0) {
     bits <<= (16 - (8 * char_count));

     buf[0] = alphabet[bits >> 18];
     buf[1] = alphabet[(bits >> 12) & 0x3f];

	 if ((out + 2) >= outsz)
		return VA_INTERNAL_BUFFER_EXCEEDED;

	 memcpy(outbuf, buf, 2);
	 outbuf += 2;
	 out += 2;

     if (char_count == 1) {
        buf[0] = '=';
        buf[1] = '=';

		if ((out + 2) >= outsz)
		   return VA_INTERNAL_BUFFER_EXCEEDED;

		memcpy(outbuf, buf, 2);
		outbuf += 2;
		out += 2;
     }

     else {
        buf[0] = alphabet[(bits >> 6) & 0x3f];
        buf[1] = '=';

		if ((out + 2) >= outsz)
		   return VA_INTERNAL_BUFFER_EXCEEDED;

		memcpy(outbuf, buf, 2);
		outbuf += 2;
		out += 2;
     }

     if (cols > 0) {
		if ((out + 2) >= outsz)
		   return VA_INTERNAL_BUFFER_EXCEEDED;

		memcpy(outbuf, "\r\n", 2);
		outbuf += 2;
		out += 2;
     }
  }

  return VA_SUCCESS;
}
