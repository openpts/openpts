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
 * cleanup 2011-01-22 SM
 *
 * http://en.wikipedia.org/wiki/Base64
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openpts.h>

/**
  * calc base64 size 
  */
int base64size(int len) {
    /* check */
    if (len <  0) return 0;
    if (len == 0) return 1;

    return (len + 2 - ((len + 2) % 3)) * 4 / 3 + 1;
}

/**
  * Encode BYTE[] to Base64 string
  */
int encodeBase64(unsigned char *out, unsigned char * in, int len) {
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

    out[ptr2] = 0;
    return ptr2;
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
  * return size of BYTE[] array
  */
int decodeBase64core(unsigned char *out, unsigned char * in, int len) {
    int ptr1 = 0;
    int ptr2 = 0;
    int len2;
    unsigned char * in2;

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

    // DEBUG("base64 [%s] > [%s]\n",in, out);
    // not here, binnary data is also decoded  out[ptr2]=0;  // put \0
    return ptr2;
}


/**
 * remove space CR
 */
unsigned char * removeCR(unsigned char *in, int *len) {
    unsigned char *out;
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
            out[j]=in[i];
            j++;
        }
    }

    *len = j;

    return out;
}

/**
  * Decode Base64(with CRLF) string to BYTE[] 
  *
  * return size of BYTE[] array
  */
int decodeBase64(unsigned char *out, unsigned char * in, int len) {
    int rc;
    unsigned char * in2;
    int len2 = len;

    in2 = removeCR(in, &len2);

    rc = decodeBase64core(out, in2, len2);

    free(in2);

    return rc;
}
