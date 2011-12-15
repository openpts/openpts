/*
 * This file is part of the OpenPTS project.
 *
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2011 International Business
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
 * \file src/ptsevt.c
 * \brief doorbell ringer
 * @author David Sherwood <davidshe@uk.ibm.com>
 * @date 2010-09-27
 * cleanup 2011-10-07 SM
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <openpts_log.h>
#include <ptsevt_msg.h>

#ifdef AIX
#define MAXSUBS      100                  /* max subscribers */
#define CF_DIR       "/var/ptsc/"         /* config files are here */
#define CF_FILE      CF_DIR "subscribers" /* list of subscribers */
#define CF_LOCK      CF_FILE ".lock"      /* protects the list */
#define CF_FILE_TMP  CF_FILE ".tmp"       /* temp list */
#define UUID_FILE    "/var/ptsc/uuid"     /* where to load uuid from */
#else  // LINUX
#define MAXSUBS      100                  /* max subscribers */
#define CF_DIR       "/var/lib/openpts/"         /* config files are here */
#define CF_FILE      CF_DIR "subscribers" /* list of subscribers */
#define CF_LOCK      CF_FILE ".lock"      /* protects the list */
#define CF_FILE_TMP  CF_FILE ".tmp"       /* temp list */
#define UUID_FILE    "/var/lib/openpts/uuid"     /* where to load uuid from */
#endif
/*
 * a possibly connected subscriber
 */
struct sub {
    struct sub *next;
    char *host;        /* IP/IPv6 address of the subscriber */
    char *serv;        /* port it's listening on */
    int blocking;        /* connect() is blocking */
    int fd;            /* connection socket */
};

struct sub *sublist = NULL;    /* list of subscribers */
unsigned nsub;            /* number of subscribers */
int lock_fd;            /* config file lock */
char *uuid;            /* uuid of this machine */

/*
 * create a new subscriber structure (without connecting)
 */
struct sub *sub_new(char *host, char *serv) {
    struct sub *c;

    if (nsub == MAXSUBS) {
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_PTSEVT_TOO_MANY_CONN,
            "Exceeded the maximum number (%d) of subscriptions\n"), MAXSUBS);
        exit(1);
    }
    c = malloc(sizeof(struct sub));
    if (c == NULL) {
        perror("malloc");
        exit(1);
    }
    c->host = strdup(host);
    if (c->host == NULL) {
        perror("malloc");
        exit(1);
    }
    c->serv = strdup(serv);
    if (c->serv == NULL) {
        perror("malloc");
        exit(1);
    }
    c->fd = -1;
    c->blocking = 0;
    c->next = sublist;
    sublist = c;
    nsub++;
    return c;
}

/*
 * delete a subscriber structure
 */
void sub_del(struct sub *p) {
    struct sub **i;

    for (i = &sublist; *i != 0; i = &(*i)->next) {
        if (*i == p) {
            *i = p->next;
            if (p->fd >= 0)
                close(p->fd);
            free(p->host);
            free(p->serv);
            free(p);
            nsub--;
            return;
        }
    }
    /*ERROR("sub_del: sub not found (bug)\n");*/
    exit(1);
}

/*
 * send an event message to a connected subscriber
 */
void sub_deliver(struct sub *c) {
    struct msg msg;

    msg.type = MSG_UPDATE;
    msg.version = MSG_VERSION;
    strncpy(msg.uuid, uuid, MSG_UUIDMAX);
    if (write(c->fd, &msg, sizeof(struct msg)) < 0) {
        perror("write");
        return;
    }
    c->blocking = 0;
}

/*
 * attempt to connect and possibly deliver an event. If the connection
 * blocks (EINPROGRESS) then just raise the ``blocking'' flag
 */
void sub_ev(struct sub *c) {
    int s, gai_err, save_errno = 0;
    struct addrinfo *ailist, *ai, aihints;

    memset(&aihints, 0, sizeof(struct addrinfo));
    aihints.ai_family = AF_UNSPEC;
    aihints.ai_socktype = SOCK_STREAM;
        gai_err = getaddrinfo(c->host, c->serv, &aihints, &ailist);
    if (gai_err) {
        OUTPUT("%s %s: getaddrinfo: %s\n", c->host, c->serv, gai_strerror(gai_err));
        return;
    }
    for (ai = ailist; ; ai = ai->ai_next) {
        if (ai == NULL) {
            OUTPUT("%s %s: connect: %s\n", c->host, c->serv, strerror(save_errno));
            return;
        }
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) {
            OUTPUT("socket: %s\n", strerror(errno));
            exit(1);
        }
        if (fcntl(s, F_SETFL, O_NONBLOCK) < 0) {
            OUTPUT("fcntl: %s\n", strerror(errno));
            exit(1);
        }
        if (connect(s, ai->ai_addr, ai->ai_addrlen) < 0) {
            if (errno == EINPROGRESS) {
                c->blocking = 1;
                break;
            }
            save_errno = errno;
            close(s);
            continue;
        }
        break;
    }
    freeaddrinfo(ailist);
    c->fd = s;

    if (!c->blocking)
        sub_deliver(c);
}

/*
 * lock the configuration file
 */
void cf_lock(void) {
    lock_fd = open(CF_LOCK, O_RDWR | O_CREAT | O_TRUNC, 0660);
    if (lock_fd < 0) {
        perror(CF_LOCK);
        exit(1);
    }
    if (lockf(lock_fd, F_LOCK, 0) < 0) {
        perror(CF_LOCK);
        exit(1);
    }
}

/*
 * unlock the configuration file
 */
void cf_unlock(void) {
    close(lock_fd);
}

/*
 * read the (locked) configuration file
 */
void cf_read(void) {
    FILE *f;
    char host[NI_MAXHOST + 1], serv[NI_MAXSERV + 1], fmt[100];

    f = fopen(CF_FILE, "rb");
    if (f == NULL) {
        if (errno == ENOENT)
            return;
        perror(CF_FILE);
        exit(1);
    }
    snprintf(fmt, sizeof(fmt), "%%%zus %%%zus", sizeof(host), sizeof(serv));  // TODO snprintf
    for (;;) {
        if (fscanf(f, fmt, host, serv) != 2) {
            if (feof(f))
                break;
            OUTPUT(NLS(MS_OPENPTS, OPENPTS_PTSEVT_CONF_ERR,
                "Encountered an error whilst parsing config file '%s'\n"
                "Please ensure the contents are correct\n"),
                   CF_FILE);
            exit(1);
        }
        sub_new(host, serv);
    }
    fclose(f);
}

/*
 * read the UUID
 */
char *getuuid(void) {
    static char uuidbuf[MSG_UUIDMAX];
    FILE *f;
    size_t s;
    int c;

    f = fopen(UUID_FILE, "rb");
    if (f == NULL) {
        perror(UUID_FILE);
        exit(1);
    }
    s = fread(uuidbuf, 1, sizeof(uuidbuf) - 1, f);
    if (!feof(f) || ferror(f)) {
        OUTPUT(NLS(MS_OPENPTS, OPENPTS_PTSEVT_UUID_ERR,
            "Encountered an error whilst parsing uuid file '%s'\n"
            "Please ensure the contents are correct\n"),
            UUID_FILE);
        exit(1);
    }
    fclose(f);

    for (;;) {
        uuidbuf[s] = '\0';
        if (s == 0)
            break;
        /*
         * remove trailing spaces
         */
        c = uuidbuf[--s];
        if (c != ' ' && c != '\n' && c != '\r' && c != '\t')
            break;
    }
    return uuidbuf;
}

/*
 * atomically write the (locked) configuration file
 */
void cf_write(void) {
    FILE *f;
    struct sub *c;

    f = fopen(CF_FILE_TMP, "wb+");
    if (f == NULL) {
        perror(CF_FILE_TMP);
        exit(1);
    }
    for (c = sublist; c != NULL; c = c->next)
        fprintf(f, "%s %s\n", c->host, c->serv);
    rename(CF_FILE_TMP, CF_FILE);
    fclose(f);
}

int
main(int argc, char **argv) {
    struct sub *c, *cnext;
    int ch, a_flag = 0, r_flag = 0, c_flag = 0, e_flag = 0;
    struct pollfd *pfd, pfds[MAXSUBS];
    socklen_t serrlen;
    int serr;

        initCatalog();

    while ((ch = getopt(argc, argv, "cerau:")) != -1) {
        switch (ch) {
        case 'a':
            a_flag = 1;
            break;
        case 'c':
            c_flag = 1;
            break;
        case 'e':
            e_flag = 1;
            break;
        case 'r':
            r_flag = 1;
            break;
        case 'u':
            if (strlen(optarg) >= MSG_UUIDMAX - 1) {
                OUTPUT(NLS(MS_OPENPTS, OPENPTS_PTSEVT_UUID_LONG,
                    "%s: UUID too long\n"), optarg);
                exit(1);
            }
            uuid = optarg;
            break;
        default:
            goto err;
        }
    }
    argc -= optind;
    argv += optind;
    if (((a_flag || r_flag) && argc != 2) ||
        ((e_flag || c_flag) && argc != 0) ||
        ((a_flag + r_flag + c_flag + e_flag) != 1)) {
    err:
        fputs(NLS(MS_OPENPTS, OPENPTS_PTSEVT_USAGE,
            "usage: ptsevt [-acer] [-u uuid] [host port]\n"),
            stderr);
        return 0;
    }
    umask(002);
    if (a_flag) {
        /*
         * add a subscriber
         */
        cf_lock();
        cf_read();
        sub_new(argv[0], argv[1]);
        cf_write();
        cf_unlock();
    }
    if (r_flag) {
        /*
         * remove a subscriber
         */
        cf_lock();
        cf_read();
        for (c = sublist; c != NULL; c = cnext) {
            cnext = c->next;
            if (strcmp(c->host, argv[0]) == 0 &&
                strcmp(c->serv, argv[1]) == 0)
                sub_del(c);
        }
        cf_write();
        cf_unlock();
    }
    if (c_flag) {
        /*
         * write an empty subscriber list
         */
        cf_lock();
        cf_write();
        cf_unlock();
    }
    if (e_flag) {
        if (uuid == NULL)
            uuid = getuuid();

        /*
         * read the subscriber list
         */
        cf_lock();
        cf_read();
        cf_unlock();

        /*
         * try to send an event to each subscriber,
         * and delete connections that haven't blocked
         */
        for (c = sublist; c != NULL; c = cnext) {
            cnext = c->next;
            sub_ev(c);
            if (!c->blocking)
                sub_del(c);
        }

        for (;;) {
            /*
             * fill a list of descriptors to poll()
             */
            for (pfd = pfds, c = sublist; c != NULL; c = c->next, pfd++) {
                pfd->fd = c->fd;
                pfd->events = POLLOUT;
            }
            if (pfd - pfds == 0)
                break;

            /*
             * wait until at least one connection is
             * established (or refused)
             */
            if (poll(pfds, pfd - pfds, -1) < 0) {
                perror("poll");
                exit(1);
            }

            /*
             * scan sockets with established/refused connections
             */
            for (pfd = pfds, c = sublist; c != NULL; c = cnext, pfd++) {
                cnext = c->next;
                if (!(pfd->revents & POLLOUT))
                    continue;
                serrlen = sizeof(int);
                if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR,
                    &serr, &serrlen) < 0) {
                    perror("getsockopt");
                    exit(1);
                }
                if (serr == 0) {
                    /* connection established */
                    sub_deliver(c);
                } else {
                    /* connection refused */
                    OUTPUT("%s:%s: %s\n", c->host, c->serv, strerror(serr));
                    sub_del(c);
                }
                if (!c->blocking) {
                    /* we're done */
                    sub_del(c);
                }
            }
        }
    }
    return 0;
}
