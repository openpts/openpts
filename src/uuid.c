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
 * \file src/uuid.c
 * \brief UUID wrapper (Generic part, OPENPTS_UUID)
 * @author Seiji Munetoh <munetoh@users.sourceforge.jp>
 * @date 2010-11-29
 * cleanup 2011-07-06 SM
 *
 * Linux uses libuuid
 *
 * UUID (as of v0.2.4)
 *
 * Program  UUID   Description         When               Files
 * ---------------------------------------------------------------------------------------------------
 * ptsc     CID    Colelctor ID        System install     => /var/lib/openpts/uuid (UUID of sign key)
 *          RM     RM ID               RM Gen xid in RM,  path /var/lib/openpts/$UUID/rm_files
 *          RunID  ID of this daemon   Daemon start       => /var/lib/openpts/run_uuid  TODO ptsc requires uuid file
 * ---------------------------------------------------------------------------------------------------
 * openpts  VID    Verifier ID         1st run            => 'HOME/.openpts/uuid
 *          CID    Colelctor ID        Enrollment         => 'HOME/.openpts/$UUID  (dir name)
 *          RM     Colelctor RM ID     Enrollment         => 'HOME/.openpts/$UUID/rm_uuid
 *          NEWRM  Colelctor New RM ID Update             => 'HOME/.openpts/$UUID/newrm_uuid
 *          OLDRM  Colelctor Old RM ID Update             => 'HOME/.openpts/$UUID/oldrm_uuid
 * ---------------------------------------------------------------------------------------------------
 *
 * Unit Test: check_uuid.c
 *
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include <sys/types.h>
#include <fcntl.h>

#include <errno.h>

// DIR
#include <unistd.h>
#include <dirent.h>

#include <openpts.h>

#define SEP_LINE "------------------------------------------------------------------------------------"


/******************************/
/* OPENPTS_UUID               */
/******************************/

/**
 * Create new OPENPTS_UUID, no contents
 *
 * @return OPENPTS_UUID
 */
OPENPTS_UUID *newOpenptsUuid() {
    OPENPTS_UUID *uuid;

    uuid = malloc(sizeof(OPENPTS_UUID));  // BYTE[16]
    if (uuid == NULL) {
        ERROR("no memory\n");
        return NULL;
    }
    memset(uuid, 0, sizeof(OPENPTS_UUID));

    return uuid;
}

/**
 * Create new OPENPTS_UUID, with contents
 *
 * @return OPENPTS_UUID
 */
OPENPTS_UUID *newOpenptsUuid2(PTS_UUID *pts_uuid) {
    OPENPTS_UUID *uuid;

    uuid = malloc(sizeof(OPENPTS_UUID));  // BYTE[16]
    if (uuid == NULL) {
        ERROR("no memory\n");
        return NULL;
    }
    memset(uuid, 0, sizeof(OPENPTS_UUID));

    uuid->uuid = malloc(16);
    memcpy(uuid->uuid, pts_uuid, 16);

    uuid->str    = getStringOfUuid(uuid->uuid);
    uuid->time   = getDateTimeOfUuid(uuid->uuid);
    uuid->status = OPENPTS_UUID_UUID_ONLY;

    return uuid;
}

/**
 * init UUID from file
 * status = OPENPTS_UUID_EMPTY
 * @return OPENPTS_UUID
 */
OPENPTS_UUID *newOpenptsUuidFromFile(char * filename) {
    OPENPTS_UUID *uuid;
    int rc;

    uuid = newOpenptsUuid();
    if (uuid == NULL) {
        ERROR("no memory");
        return NULL;
    }

    /* set the filename */
    uuid->filename = smalloc(filename);

    /* load the filename */
    rc = readOpenptsUuidFile(uuid);
    if (rc != PTS_SUCCESS) {
        ERROR("newOpenptsUuidFromFile() - readOpenptsUuidFile() fail rc=%d\n", rc);
        freeOpenptsUuid(uuid);
        return NULL;
    }

    return uuid;
}

/**
 * free OPENPTS_UUID
 */
void freeOpenptsUuid(OPENPTS_UUID *uuid) {
    /* check */
    if (uuid == NULL) {
        ERROR("null input\n");
        return;
    }

    if (uuid->filename != NULL) {
        free(uuid->filename);
    }
    if (uuid->uuid  != NULL) {
        free(uuid->uuid);
    }
    if (uuid->str  != NULL) {
        free(uuid->str);
    }
    if (uuid->time  != NULL) {
        free(uuid->time);
    }

    free(uuid);
}

/**
 * generate new UUID
 *
 * @retval PTS_SUCCESS
 * @retval PTS_INTERNAL_ERROR
 */
int genOpenptsUuid(OPENPTS_UUID *uuid) {
    /* check */
    if (uuid == NULL) {
        ERROR("\n");
        return PTS_INTERNAL_ERROR;
    }



    /* check the status */
    if (uuid->status == OPENPTS_UUID_EMPTY) {
        // hold UUID only, no binding with the file
        uuid->status = OPENPTS_UUID_UUID_ONLY;
    } else if (uuid->status == OPENPTS_UUID_FILENAME_ONLY) {
        // TODO Re genenation happen, before load the UUID from file
        ERROR("genOpenptsUuid() %s filled, before load the UUID from file\n", uuid->str);
        uuid->status = OPENPTS_UUID_FILLED;
    } else if (uuid->status == OPENPTS_UUID_FILLED) {
        // TODO Re genenation happen
        uuid->status = OPENPTS_UUID_CHANGED;
        ERROR("genOpenptsUuid() %s - changed\n", uuid->str);
    } else if (uuid->status == OPENPTS_UUID_CHANGED) {
        // TODO Re genenation happen
        uuid->status = OPENPTS_UUID_CHANGED;
        ERROR("genOpenptsUuid() %s - changed again\n", uuid->str);
    } else if (uuid->status == OPENPTS_UUID_UUID_ONLY) {
        // TODO Re genenation happen
        uuid->status = OPENPTS_UUID_UUID_ONLY;
        ERROR("genOpenptsUuid() %s - changed again (no binding to the file)\n", uuid->str);
    } else {
        ERROR("genOpenptsUuid() - bad status\n");
    }


    /* free */
    if (uuid->uuid != NULL) free(uuid->uuid);
    if (uuid->str != NULL) free(uuid->str);
    if (uuid->time != NULL) free(uuid->time);

    /* set */
    uuid->uuid = newUuid();
    uuid->str  = getStringOfUuid(uuid->uuid);
    uuid->time = getDateTimeOfUuid(uuid->uuid);
    // TODO check

    DEBUG("genOpenptsUuid() - %s\n", uuid->str);

    return PTS_SUCCESS;
}

/**
 * read UUID from file(uuid->filename), and fill OPENPTS_UUID
 *
 * @retval PTS_SUCCESS
 * @retval PTS_INTERNAL_ERROR
 */
int readOpenptsUuidFile(OPENPTS_UUID *uuid) {
    int rc = PTS_SUCCESS;
    FILE *fp;
    char line[BUF_SIZE];
    int i;

    /* check */
    if (uuid == NULL) {
        ERROR("\n");
        return PTS_INTERNAL_ERROR;
    }
    if (uuid->filename == NULL) {
        ERROR("\n");
        return PTS_INTERNAL_ERROR;
    }

    DEBUG("readOpenptsUuidFile()      : %s\n", uuid->filename);

    // TODO check UUID status?
    if (uuid->status == OPENPTS_UUID_FILENAME_ONLY) {
        // OK
    } else {
        //  reload UUID from same? file
        DEBUG("reload UUID, current UUID=%s, filename=%s\n",
            uuid->str, uuid->filename);
    }

    /* free */
    if (uuid->uuid != NULL) free(uuid->uuid);
    if (uuid->str != NULL) free(uuid->str);
    if (uuid->time != NULL) free(uuid->time);

    /* open */
    if ((fp = fopen(uuid->filename, "r")) == NULL) {
        // DEBUG("readUuidFile - UUID File %s open was failed\n", filename);
        return PTS_DENIED;  // TODO
    }

    /* init buf */
    memset(line, 0, BUF_SIZE);

    /* read */
    if (fgets(line, BUF_SIZE, fp) != NULL) {
        /* trim \n */
        /* remove LR at the end otherwise getUuidFromString() go bad */
        for (i = 0; i < BUF_SIZE; i++) {
            if (line[i] == 0x0a) {
                /* hit */
                line[i] = 0;
            }
        }
        /* parse */
        uuid->uuid = getUuidFromString(line);
        if (uuid->uuid  == NULL) {
            ERROR("readUuidFile() - UUID is NULL, file %s\n", uuid->filename);
            rc = PTS_INTERNAL_ERROR;
            goto close;
        }
        uuid->str = getStringOfUuid(uuid->uuid);
        if (uuid->str == NULL) {
            ERROR("readUuidFile() - STR UUID is NULL, file %s\n", uuid->filename);
            rc = PTS_INTERNAL_ERROR;
            goto close;
        }
        uuid->time = getDateTimeOfUuid(uuid->uuid);
        if (uuid->time == NULL) {
            ERROR("readUuidFile() - TIME UUID is NULL, file %s\n", uuid->filename);
            rc = PTS_INTERNAL_ERROR;
            goto close;
        }
        uuid->status = OPENPTS_UUID_FILLED;
    } else {
        ERROR("readOpenptsUuidFile() - read UUID fail\n");
    }

 close:
    fclose(fp);
    return rc;
}

/**
 *
 * @retval PTS_SUCCESS
 * @retval PTS_INTERNAL_ERROR
 */
int writeOpenptsUuidFile(OPENPTS_UUID *uuid, int overwrite) {
    FILE *fp;
    int fd;
    int mode = S_IRUSR | S_IWUSR | S_IRGRP;

    /* check */
    if (uuid == NULL) {
        ERROR("writeOpenptsUuidFile() - uuid == NULL\n");
        return PTS_INTERNAL_ERROR;
    }
    if (uuid->filename == NULL) {
        ERROR("writeOpenptsUuidFile() - uuid->filename == NULL\n");
        return PTS_INTERNAL_ERROR;
    }
    if ((uuid->status != OPENPTS_UUID_FILLED) && (uuid->status != OPENPTS_UUID_CHANGED)) {
        ERROR("writeOpenptsUuidFile() - uuid->status = %d (!= FILLED or CHANGED)\n", uuid->status);
        // 1 => OPENPTS_UUID_FILENAME_ONLY, UUID is missing
        return PTS_INTERNAL_ERROR;
    }
    if (uuid->str == NULL) {
        ERROR("writeOpenptsUuidFile() - uuid->str == NULL\n");
        return PTS_INTERNAL_ERROR;
    }

    /* open File */
    if (overwrite == 1) {
        /* overwrite */
        if ((fp = fopen(uuid->filename, "w")) == NULL) {
            ERROR("UUID File %s open was failed\n", uuid->filename);
            return PTS_INTERNAL_ERROR;
        }
    } else {
        /* new */
        if ((fd = open(uuid->filename, O_CREAT | O_EXCL | O_WRONLY, mode)) == -1) {
            if (errno == EEXIST) {
                /* exist, keep the current UUID file */
                return PTS_SUCCESS;  // TODO
            } else {
                ERROR("UUID File %s open was failed\n", uuid->filename);
                return PTS_INTERNAL_ERROR;
            }
        }
        if ((fp = fdopen(fd, "w")) == NULL) {
            ERROR("UUID File %s open was failed\n", uuid->filename);
            return PTS_INTERNAL_ERROR;
        }
    }

    /* write UUID */
    fprintf(fp, "%s", uuid->str);

    fclose(fp);  // this close fd also

    DEBUG("writeOpenptsUuidFile() %s -> %s\n", uuid->str, uuid->filename);

    return PTS_SUCCESS;
}
