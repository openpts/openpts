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
 * cleanup 2012-01-05 SM
 *
 * http://en.wikipedia.org/wiki/Base64
 *
 * 2011-08-17 SM - encodebase64 & decodeBase64  - alloc output buffer
 * 2011-08-21 SM - remove _removeCR() and malloc
 * 2011-08-21 SM - check bad string in BASE64 msg.
 *
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

int getDecodedBase64Size(unsigned char *in, int inLen) {
    int inCount;
    int outCount;

    /* check */
    if (in == NULL) {
        LOG(LOG_ERR, "null input");
        return 0;
    }

    inCount = inLen / 4;
    if (inCount > 0) {
        --inCount;
    }
    outCount = inCount * 3;
    inCount *= 4;

    if ( in[inCount+1] == '=' ) {
        outCount += 1;
    } else if ( in[inCount+2] == '=' ) {
        outCount += 1;
    } else if ( in[inCount+3] == '=' ) {
        outCount += 2;
    } else {
        outCount += 3;
    }

    return outCount;
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
 * Return
 *   count
 *   -1    ERROR
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

    /* check */
    if (out == NULL) {
        LOG(LOG_ERR, "null input\n");
        return -1;
    }
    if (len == 0) {
        out[0] = 0;
        return 0;
    }
    if (in == NULL) {
        LOG(LOG_ERR, "null input");
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

    /* check */
    if (in == NULL) {
        LOG(LOG_ERR, "null input\n");
        return NULL;
    }

    *outlen = _sizeofBase64Encode(inlen);
    out = (char *) xmalloc_assert(*outlen);
    if (out == NULL) {
        LOG(LOG_ERR, "no memory");
        *outlen = 0;
        return NULL;
    }
    memset(out, 0, *outlen);

    len2 = _encodeBase64(out, in, inlen);
    if (len2 > *outlen) {
        LOG(LOG_ERR, "fatal error");
        xfree(out);
        *outlen = 0;
        return NULL;
    }

    return out;
}

/**
  * trans (do not check the bad input)
  */
unsigned char _b64trans(unsigned char in) {
    if (in == '+') return 62;
    if (in == '/') return 63;
    if (in >= 'a') return (in-'a' + 26);
    if (in >= 'A') return (in-'A');
    if (in >= '0') return (in-'0' + 52);
    return 0xFF;
}

/**
 * string length without space at the end
 *
 * 2011-11-30 Munetoh - fixed to skip the char in the middle of string
 */
int _strippedlength(char * in, int len) {
    int skip = 0;
    int i;

    /* check */
    if (in == NULL) {
        LOG(LOG_ERR, "null input\n");
        return -1;
    }

    /* last char */
    i = len - 1;

    while (i > 0) {
        if (in[i] == '\n') {
            /* skip */
            skip++;
        } else if (in[i] == ' ') {
            /* skip */
            skip++;
        }
        i = i - 1;
    }

    return len - skip;
}



/**
  * Decode Base64 string to BYTE[]
  *
  * caller must provide the buffer
  *
  * return size of BYTE[] array
  */
int _decodeBase64(unsigned char *out, char * in, int len) {
    int ptr1 = 0;  // in
    int ptr2 = 0;  // out
    int len2;
    char * in2;
    char inbuf[4];
    int i, j;
    int skip;

    /* check */
    if (out == NULL) {
        LOG(LOG_ERR, "decodeBase64core - out is NULL\n");
        return -1;
    }
    /* null input? */
    if (in == NULL) {
        LOG(LOG_ERR, "decodeBase64core - in is NULL\n");
        return -1;
    }
    /* in[0] => out[0]=\0 */
    if (len == 0) {
        out[0] = 0;
        return 0;
    }

    len2 = _strippedlength(in, len);
    in2 = in;

    /* Trans */
    while (1) {
        /* check remain buffer size >= 4 */
        if (len2 < 4) {
            LOG(LOG_ERR, "bad base64 data size");
            goto error;
        }
        /* remove CR and Space and check bad string */
        j = 0;
        skip = 0;
        for (i = ptr1; j < 4 ; i++) {
            if (in2[i] == '\n') {
                /* skip */
                skip++;
            } else if (in2[i] == ' ') {
                /* skip */
                skip++;
            } else {
                if ((in2[i] == 0x2B) ||
                   (in2[i] == 0x2F) ||
                   (in2[i] == 0x3D) ||
                   ((0x30 <= in2[i]) && (in2[i] <= 0x39)) ||
                   ((0x41 <= in2[i]) && (in2[i] <= 0x5A)) ||
                   ((0x61 <= in2[i]) && (in2[i] <= 0x7A))) {
                    /* valid data */
                    inbuf[j]=in2[i];
                    j++;
                } else {
                    /* BAD BASE64 String */
                    LOG(LOG_ERR, "bad base64 data string, 0x%0x", in2[i]);
                    goto error;
                }
            }
        }
        /* BASE64 -> Plain */
        if (len2 > 4) {
            out[ptr2  ] =  (_b64trans(inbuf[0])       << 2) |
                           (_b64trans(inbuf[1]) >> 4);
            out[ptr2+1] = ((_b64trans(inbuf[1])&0x0F) << 4) |
                           (_b64trans(inbuf[2]) >> 2);
            out[ptr2+2] = ((_b64trans(inbuf[2])&0x03) << 6) |
                            _b64trans(inbuf[3]);
            len2 -= 4;  // skip chars has been removed in len2
            ptr1 += 4 + skip;
            ptr2 += 3;
        } else if ( inbuf[1] == '=' ) {
            out[ptr2  ] = _b64trans(inbuf[0])      << 2;
            ptr2 += 1;
            break;
        } else if ( inbuf[2] == '=' ) {
            out[ptr2  ] = (_b64trans(inbuf[0]) << 2) |
                          (_b64trans(inbuf[1]) >> 4);
            ptr2 += 1;
            break;
        } else if ( inbuf[3] == '=' ) {
            out[ptr2  ] =  (_b64trans(inbuf[0])       << 2) |
                           (_b64trans(inbuf[1]) >> 4);
            out[ptr2+1] = ((_b64trans(inbuf[1])&0x0F) << 4) |
                           (_b64trans(inbuf[2]) >> 2);
            ptr2 += 2;
            break;
        } else {
            out[ptr2  ] =  (_b64trans(inbuf[0])       << 2) |
                           (_b64trans(inbuf[1]) >> 4);
            out[ptr2+1] = ((_b64trans(inbuf[1])&0x0F) << 4) |
                           (_b64trans(inbuf[2]) >> 2);
            out[ptr2+2] = ((_b64trans(inbuf[2])&0x03) << 6) |
                            _b64trans(inbuf[3]);
            ptr2 += 3;
            break;
        }
    }

    /* Anyway, add \0 at the end of buffer */
    out[ptr2] = 0;

    return ptr2;

  error:
    return -1;
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

    /* check */
    if (in == NULL) {
        LOG(LOG_ERR, "null input\n");
        return NULL;
    }

    len1 = _sizeofBase64Decode(inlen);
    out = (unsigned char *) xmalloc_assert(len1);
    if (out == NULL) {
        LOG(LOG_ERR, "no memory");
        *outlen = 0;
        return NULL;
    }
    memset(out, 0, len1);

    len2 = _decodeBase64(out, in, inlen);
    if (len2 < 0) {
        LOG(LOG_ERR, "fatal error");
        xfree(out);
        *outlen = 0;
        return NULL;
    }

    /* return actial data size created from base64 */
    *outlen = len2;

    return out;
}
