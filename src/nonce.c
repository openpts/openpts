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
 * \file src/nonce.c
 * \brief calc D-H nonce
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-08-19
 * cleanup 2011-01-22 SM
 *
 * PTS IF-M DH-Nonce protocol
 *
 * D-H Nonce Parameters Request
 *   nonce len
 *   D-H group set
 *   
 * D-H Nonce Parameters Responce
 *   nonce length
 *   Selected D-H Group
 *   Hash Algorithm Set
 *   D-H Responder Nonce
 *   D-H Responder Public Value
 *
 * D-H Nonce Finish
 *   nonce length
 *   Selected Hash Algorithm
 *   D-H Initiater Public Value
 *   D-H Initiater Nonce 
 *
 *  http://www.ietf.org/rfc/rfc2409.txt  IKE group 1-4
 *  http://www.ietf.org/rfc/rfc3526.txt  IKE group 5-18
 *  http://www.ietf.org/rfc/rfc4753.txt  IKE group 19-21?
 *
 * nonce size 16-255 (8bit)
 * TODO random nonce
 */



#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>
#include <openssl/dh.h>

#include <openpts.h>

#define DH_NONCE_SIZE  20
#define DH_GROUP_2_SIZE  128
#define DH_GROUP_5_SIZE  192
#define DH_GROUP_14_SIZE 256

char *group2 =
        "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
        "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
        "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
        "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
        "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE65381"
        "FFFFFFFF" "FFFFFFFF";

char *group5 =
        "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
        "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
        "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
        "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
        "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE45B3D"
        "C2007CB8" "A163BF05" "98DA4836" "1C55D39A" "69163FA8" "FD24CF5F"
        "83655D23" "DCA3AD96" "1C62F356" "208552BB" "9ED52907" "7096966D"
        "670C354E" "4ABC9804" "F1746C08" "CA237327" "FFFFFFFF" "FFFFFFFF";

char *group14 =
        "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
        "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
        "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
        "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
        "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE45B3D"
        "C2007CB8" "A163BF05" "98DA4836" "1C55D39A" "69163FA8" "FD24CF5F"
        "83655D23" "DCA3AD96" "1C62F356" "208552BB" "9ED52907" "7096966D"
        "670C354E" "4ABC9804" "F1746C08" "CA18217C" "32905E46" "2E36CE3B"
        "E39E772C" "180E8603" "9B2783A2" "EC07A28F" "B5C55DF0" "6F4C52C9"
        "DE2BCBF6" "95581718" "3995497C" "EA956AE5" "15D22618" "98FA0510"
        "15728E5A" "8AACAA68" "FFFFFFFF" "FFFFFFFF";

/**
 * New OPENPTS_NONCE
 *
 * malloc -> free@freeNonceContext()
 *  OPENPTS_NONCE ctx
 *  ctx->req
 *  ctx->res
 *  ctx->fin
 */
OPENPTS_NONCE *newNonceContext() {
    OPENPTS_NONCE *ctx = NULL;

    DEBUG_CAL("newNonceContext\n");

    /* malloc */
    ctx = xmalloc(sizeof(OPENPTS_NONCE));
    if (ctx == NULL) {
        ERROR("no memory");
        return NULL;
    }
    memset(ctx, 0, sizeof(OPENPTS_NONCE));

    /* malloc req */
    ctx->req = (PTS_IF_M_DH_Nonce_Parameters_Request *)xmalloc(sizeof(PTS_IF_M_DH_Nonce_Parameters_Request));
    if (ctx->req == NULL) {
        ERROR("no memory");
        xfree(ctx);
        return NULL;
    }
    memset(ctx->req, 0, sizeof(PTS_IF_M_DH_Nonce_Parameters_Request));

    /* malloc res */
    ctx->res = xmalloc(sizeof(PTS_IF_M_DH_Nonce_Parameters_Responce));
    if (ctx->res == NULL) {
        ERROR("no memory");
        xfree(ctx->req);
        xfree(ctx);
        return NULL;
    }
    memset(ctx->res, 0, sizeof(PTS_IF_M_DH_Nonce_Parameters_Responce));

    /* malloc fin */
    ctx->fin = xmalloc(sizeof(PTS_IF_M_DH_Nonce_Finish));
    if (ctx->fin == NULL) {
        ERROR("no memory");
        xfree(ctx->req);
        xfree(ctx->res);
        xfree(ctx);
        return NULL;
    }
    memset(ctx->fin, 0, sizeof(PTS_IF_M_DH_Nonce_Finish));

    return ctx;
}

/**
 * Free OPENPTS_NONCE
 *
 * free
 *   ctx->req
 *   ctx->res->dh_respondor_nonce
 *   ctx->res->dh_respondor_public
 *   ctx->res
 *   ctx->fin->dh_initiator_nonce
 *   ctx->fin->dh_initiator_public
 *   ctx->fin
 *   ctx->secret
 *   ctx->nonce
 */
int freeNonceContext(OPENPTS_NONCE *ctx) {
    DEBUG_CAL("freeNonceContext\n");

    /* check */
    if (ctx == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }

    /* free req */
    if (ctx->req != NULL) {
        xfree(ctx->req);
    }
    /* free res */
    if (ctx->res != NULL) {
        if (ctx->res->dh_respondor_nonce != NULL) {
            xfree(ctx->res->dh_respondor_nonce);
        }
        if (ctx->res->dh_respondor_public != NULL) {
            xfree(ctx->res->dh_respondor_public);
        }
        xfree(ctx->res);
    }
    /* free fin */
    if (ctx->fin != NULL) {
        if (ctx->fin->dh_initiator_nonce != NULL) {
            xfree(ctx->fin->dh_initiator_nonce);
        }
        if (ctx->fin->dh_initiator_public != NULL) {
            xfree(ctx->fin->dh_initiator_public);
        }
        xfree(ctx->fin);
    }
    /* free secret */
    if (ctx->secret != NULL) {
        memset(ctx->secret, 0, ctx->secret_length);
        xfree(ctx->secret);
    }
    /* free nonce */
    if (ctx->nonce != NULL) {
        xfree(ctx->nonce);
    }

    /* free DH */
    if (ctx->dh != NULL) {
        DH_free(ctx->dh);
    }

    xfree(ctx);

    return PTS_SUCCESS;
}

/**
 * Calc ExternalDataValue (=nonce)
 *
 *  nonce = HASH("1" | initiator's nonce | respondor's nonce | secret)
 */
int calcExternalDataValue(OPENPTS_NONCE *ctx) {
    SHA_CTX sha_ctx;
    char c = '1';

    // DEBUG("calcExternalDataValue\n");
    /* check */
    if (ctx == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }

    ctx->nonce_length = SHA1_DIGEST_SIZE;
    ctx->nonce = xmalloc_assert(SHA1_DIGEST_SIZE);
    if (ctx->nonce == NULL) {
        ERROR("no memory");
        return PTS_FATAL;
    }

    SHA1_Init(&sha_ctx);
    SHA1_Update(&sha_ctx, &c, 1);
    SHA1_Update(&sha_ctx, ctx->initiator_nonce, ctx->initiator_nonce_length);
    SHA1_Update(&sha_ctx, ctx->respondor_nonce, ctx->respondor_nonce_length);
    SHA1_Update(&sha_ctx, ctx->secret, ctx->secret_length);
    SHA1_Final(ctx->nonce, &sha_ctx);

    if (isDebugFlagSet(DEBUG_FLAG)) {
        TODO("calcExternalDataValue - nonce\n");
        debugHex("\t\tinitiator_nonce:", ctx->initiator_nonce, ctx->initiator_nonce_length, "\n");
        debugHex("\t\trespondor_nonce:", ctx->respondor_nonce, ctx->respondor_nonce_length, "\n");
        debugHex("\t\tsecret         :", ctx->secret, ctx->secret_length, "\n");
        debugHex("\t\tnonce          :", ctx->nonce, 20, "\n");
    }

    return PTS_SUCCESS;
}


/**
 * Respondor
 *
 * malloc -> free@freeNonceContext()
 *   res->dh_respondor_nonce
 *   res->dh_respondor_public
 */
int getDhResponce(OPENPTS_NONCE *ctx) {
    int rc = 0;
    BIGNUM *p, *g;
    PTS_IF_M_DH_Nonce_Parameters_Request  *req;
    PTS_IF_M_DH_Nonce_Parameters_Responce *res;

    // DEBUG("getDhResponce at Respondor\n");

    /* check */
    if (ctx == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }
    req = ctx->req;
    if (req == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }
    res = ctx->res;
    if (res == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }
    if (req->reserved != 0) {
        ERROR("reserved must be 0\n");
        return PTS_INTERNAL_ERROR;
    }

    /* select nonce size */
    if (req->min_nonce_len > 20) {
        ctx->nonce_length = req->min_nonce_len;
    } else {
        ctx->nonce_length = 20;
    }
    res->nonce_length = ctx->nonce_length;

    /* set DH Hash Alg */
    res->hash_alg_set = DH_HASH_SHA1;
    ctx->selected_hash_alg = DH_HASH_SHA1;

    /* setup DH */
    p = BN_new();
    g = BN_new();
    ctx->dh = DH_new();

    /* select DH group */
    if (req->dh_group_set & DH_GROUP_2) {
        res->selected_dh_group = DH_GROUP_2;
        ctx->selected_dh_group = DH_GROUP_2;
        ctx->pubkey_length = DH_GROUP_2_SIZE;
        BN_hex2bn(&p, group2);
    } else if (req->dh_group_set & DH_GROUP_5) {
        res->selected_dh_group = DH_GROUP_5;
        ctx->selected_dh_group = DH_GROUP_5;
        ctx->pubkey_length = DH_GROUP_5_SIZE;
        BN_hex2bn(&p, group5);
    } else if (req->dh_group_set & DH_GROUP_14) {
        res->selected_dh_group = DH_GROUP_14;
        ctx->selected_dh_group = DH_GROUP_14;
        ctx->pubkey_length = DH_GROUP_14_SIZE;
        BN_hex2bn(&p, group14);
    } else {
        res->selected_dh_group = 0;
        ERROR("Unknown DH group set 0x%x", req->dh_group_set);
        return PTS_DENIED;
    }

    BN_set_word(g, 2);

    ctx->dh->p = BN_dup(p);
    ctx->dh->g = BN_dup(g);

    /* DH gen key */
    rc = DH_generate_key(ctx->dh);

    /* respondor nonce */

    /* malloc */
    res->dh_respondor_nonce = xmalloc(res->nonce_length);
    if (res->dh_respondor_nonce == NULL) {
        ERROR("dh_respondor_nonce is null");
        return PTS_INTERNAL_ERROR;
    }

    /* set random */
    rc = getRandom(res->dh_respondor_nonce, res->nonce_length);
    if (rc != TSS_SUCCESS) {
        ERROR("get random fail\n");
        return PTS_INTERNAL_ERROR;
    }

    /* respondor nonce (local copy)*/
    ctx->respondor_nonce_length = res->nonce_length;
    ctx->respondor_nonce = res->dh_respondor_nonce;

    /* pubkey */

    /* malloc */
    res->dh_respondor_public = xmalloc(DH_size(ctx->dh));
    if (res->dh_respondor_public == NULL) {
        ERROR("no memory");
        return PTS_FATAL;
    }

    /* set */
    BN_bn2bin(ctx->dh->pub_key, res->dh_respondor_public);
    ctx->pubkey = res->dh_respondor_public;

    /* reserved */
    res->reserved[0] = 0;
    res->reserved[1] = 0;
    res->reserved[2] = 0;

    /* free */
    BN_free(p);
    BN_free(g);
    // DH_free(ctx->dh);

    return PTS_SUCCESS;
}

/**
 *
 */
int setDhPubkeylength(OPENPTS_NONCE *ctx) {
    PTS_IF_M_DH_Nonce_Parameters_Responce *res = ctx->res;

    /* check */
    if (ctx == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }

    /* select DH group */
    if (res->selected_dh_group == DH_GROUP_2) {
        ctx->pubkey_length = DH_GROUP_2_SIZE;
    } else if (res->selected_dh_group == DH_GROUP_5) {
        ctx->pubkey_length = DH_GROUP_5_SIZE;
    } else if (res->selected_dh_group == DH_GROUP_14) {
        ctx->pubkey_length = DH_GROUP_14_SIZE;
    } else {
        ERROR("Bad DH group 0x%x\n", res->selected_dh_group);
        return PTS_DENIED;  // TODO
    }

    return PTS_SUCCESS;
}


/**
 * Initiator
 *
 * malloc -> free@freeNonceContext()
 *   fin->dh_initiator_nonce
 *   fin->dh_initiator_public 
 *   ctx->secret
 */
int calcDh(OPENPTS_NONCE *ctx) {
    int rc = 0;
    BIGNUM *p, *g;
    BIGNUM *pub_key;
    PTS_IF_M_DH_Nonce_Parameters_Responce *res;
    PTS_IF_M_DH_Nonce_Finish *fin;

    /* check */
    if (ctx == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }
    res = ctx->res;
    if (res == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }
    fin = ctx->fin;
    if (fin == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }

    if (res->reserved[0] != 0) {
        // TODO check 1,2 too
        ERROR("reserved must be 0\n");
        return PTS_INTERNAL_ERROR;
    }

    /* set DH Hash Alg */
    if (res->hash_alg_set & DH_HASH_SHA1) {
        // OK
        fin->selected_hash_alg = DH_HASH_SHA1;
        ctx->selected_hash_alg = DH_HASH_SHA1;
    } else {
        ERROR("Bad DH hash set 0x%x\n", res->hash_alg_set);
        return PTS_DENIED;
    }

    /* store respondor nonce */
    ctx->respondor_nonce_length = res->nonce_length;
    ctx->respondor_nonce = res->dh_respondor_nonce;

    /* select initiator nonce size */
    ctx->nonce_length = res->nonce_length;  // same length
    fin->nonce_length = ctx->nonce_length;

    /* setup DH */
    p = BN_new();
    g = BN_new();
    ctx->dh = DH_new();

    /* select DH group */
    if (res->selected_dh_group == DH_GROUP_2) {
        BN_hex2bn(&p, group2);
        ctx->pubkey_length = DH_GROUP_2_SIZE;
    } else if (res->selected_dh_group == DH_GROUP_5) {
        BN_hex2bn(&p, group5);
        ctx->pubkey_length = DH_GROUP_5_SIZE;
    } else if (res->selected_dh_group == DH_GROUP_14) {
        BN_hex2bn(&p, group14);
        ctx->pubkey_length = DH_GROUP_14_SIZE;
    } else {
        ERROR("Bad DH group 0x%x\n", res->selected_dh_group);
        return  PTS_DENIED;
    }

    BN_set_word(g, 2);

    ctx->dh->p = BN_dup(p);
    ctx->dh->g = BN_dup(g);

    /* DH gen key */
    rc = DH_generate_key(ctx->dh);

    pub_key = BN_new();
    BN_bin2bn(res->dh_respondor_public, ctx->pubkey_length, pub_key);

    /* secret */
    ctx->secret_length = DH_size(ctx->dh);

    /* malloc */
    ctx->secret = xmalloc(ctx->secret_length);
    if (ctx->secret == NULL) {
        ERROR("no memory");
        return PTS_FATAL;
    }

    /* calc key */
    DH_compute_key(ctx->secret, pub_key, ctx->dh);

    /* initiator nonce */
    fin->dh_initiator_nonce = xmalloc(fin->nonce_length);
    if (fin->dh_initiator_nonce == NULL) {
        ERROR("no memory");
        return PTS_FATAL;
    }

    /* set random */
    rc = getRandom(fin->dh_initiator_nonce, fin->nonce_length);
    if (rc != TSS_SUCCESS) {
        ERROR("get random fail\n");
        return PTS_INTERNAL_ERROR;
    }

    /* initiator nonce (local copy) */
    ctx->initiator_nonce_length = fin->nonce_length;
    ctx->initiator_nonce = fin->dh_initiator_nonce;

    /* pubkey */
    fin->dh_initiator_public = xmalloc(DH_size(ctx->dh));
    if (fin->dh_initiator_public == NULL) {
        return PTS_INTERNAL_ERROR;
    }
    BN_bn2bin(ctx->dh->pub_key, fin->dh_initiator_public);

    ctx->pubkey = fin->dh_initiator_public;

    /* calc ExternalDataValue */
    calcExternalDataValue(ctx);

    /* free */
    BN_free(p);
    BN_free(g);
    BN_free(pub_key);

    return PTS_SUCCESS;
}

/**
 * Respondor
 */
int calcDhFin(OPENPTS_NONCE *ctx) {
    BIGNUM *pub_key;
    PTS_IF_M_DH_Nonce_Finish *fin;

    // DEBUG("calcDhFin at Respondor\n");
    // printHex("fin->dh_initiator_nonce :",fin->dh_initiator_nonce,fin->nonce_length,"\n");
    // printHex("fin->dh_initiator_public:",fin->dh_initiator_public,ctx->pubkey_length,"\n");

    /* check */
    if (ctx == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }
    fin = ctx->fin;
    if (fin == NULL) {
        ERROR("null input");
        return PTS_FATAL;
    }

    /* initiator nonce */
    ctx->initiator_nonce_length = fin->nonce_length;
    ctx->initiator_nonce = fin->dh_initiator_nonce;

    /* initiator pubkey */
    pub_key = BN_new();
    BN_bin2bn(fin->dh_initiator_public, ctx->pubkey_length, pub_key);

    /* calc secret */
    ctx->secret_length = DH_size(ctx->dh);
    ctx->secret = xmalloc_assert(ctx->secret_length);
    DH_compute_key(ctx->secret, pub_key, ctx->dh);

    /* calc ExternalDataValue */
    calcExternalDataValue(ctx);

    /* free */
    BN_free(pub_key);
    // DH_free(ctx->dh);

    return PTS_SUCCESS;
}
