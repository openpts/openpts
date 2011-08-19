/*
 * This file is part of the OpenPTS project.
 *
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2010 International Business
 * Machines Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
 */

/**
 * \file src/base64.c
 * \brief Base64 Encode/Decode
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-04-01
 * cleanup 2011-08-17 SM
 *
 * http://en.wikipedia.org/wiki/Base64
 *
 * 2011-08-17 SM - encodebase64 & decodeBase64  - alloc output buffer
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openpts.h>

/**
 * calc base64 size
 *
 * string(or binary data) => base64 string + 1
 * Output is actual string size + 1 (for \0)
 */
int _sizeofBase64Encode(int len) {
    /* check */
    if (len <  0) return 0;
    if (len == 0) return 1;

    return (len + 2 - ((len + 2) % 3)) * 4 / 3 + 1;
}

/**
 * calc original data size from base64 string size
 *
 * This is rough estimation.
 * Output is actual string size (+1 or +2) + 1 (for \0)
 *
 */
int _sizeofBase64Decode(int len) {
    /* check */
    if (len <  0) return 0;
    if (len == 0) return 1;

    return (len / 4 * 3) + 1;
}



/**
 * Encode BYTE[] to Base64 string
 */
int _encodeBase64(char *out, unsigned char * in, int len) {
    int ptr1 = 0;
    int ptr2 = 0;

    /* */
    static unsigned char transTable[64] = {
         /* 41h - */
         'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
         /* - 5Ah */
         'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
         /* 61h - */
         'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
         /* - 7Ah */
         'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
         /* 30h - 39h, 2Bh, 2Fh */
         '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
         };

    if (out ==NULL) {
        ERROR("out is NULL\n");
        return -1;
    }

    if (len == 0) {
        out[0] = 0;
        return 0;
    }

    /* Trans */

    while (1) {
        if ( len >= 3 ) {
            out[ptr2  ] = transTable[   in[ptr1  ] >>2];
            out[ptr2+1] = transTable[ ((in[ptr1  ]&0x03) <<4 |
                                       (in[ptr1+1]&0xF0) >> 4) ];
            out[ptr2+2] = transTable[ ((in[ptr1+1]&0x0F) <<2 |
                                       (in[ptr1+2]&0xC0) >> 6) ];
            out[ptr2+3] = transTable[  (in[ptr1+2]&0x3F) ];
            len -= 3;
            ptr1 += 3;
            ptr2 += 4;
        } else if ( len == 2 ) {
            out[ptr2  ] = transTable[   in[ptr1  ] >>2];
            out[ptr2+1] = transTable[ ((in[ptr1  ]&0x03) <<4 |
                                       (in[ptr1+1]&0xF0) >> 4) ];
            out[ptr2+2] = transTable[  (in[ptr1+1]&0x0F) <<2 ];
            out[ptr2+3] = '=';
            ptr2 += 4;
            break;
        } else if ( len == 1 ) {
            out[ptr2  ] = transTable[  in[ptr1  ] >>2];
            out[ptr2+1] = transTable[ (in[ptr1  ]&0x03) <<4 ];
            out[ptr2+2] = '=';
            out[ptr2+3] = '=';
            ptr2 += 4;
            break;
        } else {
            break;
        }
    }

    /* add \0 at the end of buffer */
    out[ptr2] = 0;

    return ptr2;
}
/**
 * Encode BYTE[] to Base64 string
 *
 * @param  *in     buffer of input data
 * @param  inlen   length
 * @raram  *outlen size of output
 * @return *out    Base64 string, malloc new buffer
 */
char *encodeBase64(unsigned char * in, int inlen, int *outlen) {
    char *out;
    int len2;

    *outlen = _sizeofBase64Encode(inlen);
    out = (char *) malloc(*outlen);
    if (out == NULL) {
        ERROR("no memory");
        *outlen = 0;
        return NULL;
    }
    memset(out,0,*outlen);

    len2 = _encodeBase64(out, in, inlen);
    if (len2 > *outlen) {
        ERROR("fatal error");
        free(out);
        *outlen = 0;
        return NULL;
    }

    return out;
}

/**
  * return length - TBD
  */
int plain64size(int len) {
    // TODO(munetoh) calc
    return len;
}

/**
  * trans
  */
unsigned char trans(unsigned char in) {
    if (in == '+') return 62;
    if (in == '/') return 63;
    if (in >= 'a') return (in-'a' + 26);
    if (in >= 'A') return (in-'A');
    if (in >= '0') return (in-'0' + 52);
    return 0xFF;
}


/**
  * Decode Base64 string to BYTE[]
  *
  * caller must provide the buffer
  *
  * return size of BYTE[] array
  */
int _decodeBase64core(unsigned char *out, char * in, int len) {
    int ptr1 = 0; // in
    int ptr2 = 0; // out
    int len2;
    char * in2;

    /* check */
    if (out ==NULL) {
        ERROR("decodeBase64core - out is NULL\n");
        return -1;
    }

    if (len == 0) {
        out[0] = 0;
        return 0;
    }

    len2 = len;
    in2 = in;

    // printf("[%3d]=[%s]\n", len2, in2);

    /* Trans */

    while (1) {
        if (len2 > 4) {
            out[ptr2  ] =  (trans(in2[ptr1  ])       << 2) |
                           (trans(in2[ptr1+1]) >> 4);
            out[ptr2+1] = ((trans(in2[ptr1+1])&0x0F) << 4) |
                           (trans(in2[ptr1+2]) >> 2);
            out[ptr2+2] = ((trans(in2[ptr1+2])&0x03) << 6) |
                            trans(in2[ptr1+3]);
            len2  -= 4;
            ptr1 += 4;
            ptr2 += 3;
        } else if ( in2[ptr1+1] == '=' ) {
            out[ptr2  ] = trans(in2[ptr1  ])      <<2;
            ptr2 += 1;
            break;
        } else if ( in2[ptr1+2] == '=' ) {
            out[ptr2  ] = (trans(in2[ptr1  ]) <<2) |
                          (trans(in2[ptr1+1]) >> 4);
            ptr2 += 1;
            break;
        } else if ( in2[ptr1+3] == '=' ) {
            out[ptr2  ] =  (trans(in2[ptr1  ])       << 2) |
                           (trans(in2[ptr1+1]) >> 4);
            out[ptr2+1] = ((trans(in2[ptr1+1])&0x0F) << 4) |
                           (trans(in2[ptr1+2]) >> 2);
            ptr2 += 2;
            break;
        } else {
            out[ptr2  ] =  (trans(in2[ptr1  ])       << 2) |
                           (trans(in2[ptr1+1]) >> 4);
            out[ptr2+1] = ((trans(in2[ptr1+1])&0x0F) << 4) |
                           (trans(in2[ptr1+2]) >> 2);
            out[ptr2+2] = ((trans(in2[ptr1+2])&0x03) << 6) |
                            trans(in2[ptr1+3]);
            ptr2 += 3;
            break;
        }
    }


    /* Anyway, add \0 at the end of buffer */
    // TODO("out[%d] = 0\n", ptr2);
    out[ptr2] = 0;

    return ptr2;
}


/**
 * remove space & CR in Base64 string
 *
 * @param  *in   Base64 string buffer
 * @param  *len  size of buffer, before and after
 * @return       new Base64 string buffer (malloced)
 */
char * _removeCR(char *in, int *len) {
    char *out;
    int i;
    int j = 0;

    out = malloc(*len);
    memset(out, 0, *len);

    for (i = 0; i < *len; i++) {
        if (in[i] == '\n') {
            /* skip */
            // DEBUG("CR\n");
        } else if (in[i] == ' ') {
            /* skip */
            // DEBUG("SP\n");
        } else {
            /* valid data */
            out[j]=in[i];
            j++;
        }
    }

    *len = j;
    // note)
    // if there are no skip, it return same buffer
    // if there are skip, out[j] is 0, since memset(0) before

    return out;
}

/**
  * Decode Base64(with CRLF) string to BYTE[]
  *
  * @param *out
  * @param *in
  * @param *len
  * @return size of BYTE[] array
  */
int _decodeBase64(unsigned char *out, char * in, int len) {
    int rc;
    char * in2;
    int len2 = len;

    in2 = _removeCR(in, &len2);

    rc = _decodeBase64core(out, in2, len2);

    free(in2);

    return rc;
}

/**
 * Decode Base64(with CRLF) string to BYTE[]
 *
 * @param  *in     buffer of base64 string
 * @param  inlen   length
 * @raram  *outlen size of BYTE[] array from base64 string, malloced size is bigger then this
 * @return *out    malloc new buffer
 */
unsigned char *decodeBase64(char * in, int inlen, int *outlen) {
    unsigned char *out;
    int len1;
    int len2;

    len1 = _sizeofBase64Decode(inlen);
    out = (unsigned char *) malloc(len1);
    if (out == NULL) {
        ERROR("no memory");
        *outlen = 0;
        return NULL;
    }
    memset(out,0,len1);

    len2 = _decodeBase64(out, in, inlen);
    if (len2 > len1) {
        ERROR("fatal error");
        free(out);
        *outlen = 0;
        return NULL;
    }

    /* return actial data size created from base64 */
    *outlen = len2;

    return out;
}
