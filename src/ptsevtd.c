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
 * \brief doorbell listener
 * @author David Sherwood <davidshe@uk.ibm.com>
 * @date 2011-09-27
 * cleanup 2011-10-07 SM
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <openpts_log.h>
#include <ptsevt_msg.h>

#define MAXLISTEN      10        /* max addresses to listen on */
#define MAXPEER        0x1000    /* max connections to accept */
#define MAXCHLD        10        /* max child processes */

/*
 * the state machine for the lifetime of an event
 */
struct peer {
    struct peer *next;
    int fd;                     /* incoming connection socket */
    struct pollfd *pfd;         /* array entry for poll() */
    char addr[NI_MAXHOST + 1];  /* string with source IP/IPv6 */
#define PEER_RECV      0        /* reading the message */
#define PEER_FORK      1        /* too many childs to fork, waiting */
#define PEER_WAITPID   2        /* waiting the child to terminate */
#define PEER_ENDING    3        /* done, keeping track of the evt */
    int state;                  /* one of above */
#define TIMO_RECV       5000000000LL    /* ns before we drop connection */
#define TIMO_WAITPID    60000000000LL   /* ns before we kill the child */
#define TIMO_ENDING     3000000000LL    /* ns between fork()'s */
    int64_t timeout;            /* expires when 0 is reached */
    int restart;                /* if 1, fork() openpts again */
    pid_t pid;                  /* openpts */
    unsigned msglen;            /* bytes received */
    struct msg msg;             /* actual message */
};

int listen_fd[MAXLISTEN];      /* sockets we're listening on */
unsigned nlisten;              /* number of sockets we're listening on */
struct peer *peerlist = NULL;  /* list of events being processed */
unsigned npeer;                /* number of connections */
unsigned nchild;               /* number of child processes */
unsigned loglevel = 0;         /* 0 = err, 1 = warn, 2 = debug */
unsigned foreground = 1;       /* don't become a daemon */
char *command = "openpts";     /* command to run on each event */
char *port = MSG_PORT;         /* port to listen on */

/*
 * log using syslog or stderr depending whether the program is
 * deamonized or not. Messages have "priorities", and are actually
 * printed only of the log level is high enough
 */
void vlogn(unsigned msglevel, char *fmt, va_list ap) {
#define LOGMAX    160
    char buf[LOGMAX];

    if (msglevel > loglevel)
        return;
    vsnprintf(buf, LOGMAX, fmt, ap);
    va_end(ap);
    if (foreground) {
        fprintf(stderr, "%s\n", buf);
        fflush(stderr);
    } else {
        syslog(msglevel ? LOG_INFO : LOG_CRIT, "%s", buf);
    }
}

/*
 * log a fatal error and exit
 */
void log_err(char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    vlogn(0, fmt, ap);
    va_end(ap);
    exit(1);
}

/*
 * log an error
 */
void log_warn(char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    vlogn(0, fmt, ap);
    va_end(ap);
}

/*
 * log a debug message (if the log level is verbose enough)
 */
void log_debug(char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    vlogn(2, fmt, ap);
    va_end(ap);
}

/*
 * accept a new connection from the given socket, allocate its peer
 * structure in the PEER_RECV state and add it to the list of peers.  If
 * a peer structure already exists for the source address, then its used
 * and no new structure is allocated.
 */
void peer_accept(int fd) {
    struct peer *p;
    struct sockaddr_storage caddr;
    socklen_t clen;
    int s, gai_err;
    char addr[NI_MAXHOST + 1];

    clen = sizeof(struct sockaddr_storage);
    s = accept(fd, (struct sockaddr *)&caddr, &clen);
    if (s < 0) {
        log_warn("accept: %s", strerror(errno));
        return;
    }
    gai_err = getnameinfo((struct sockaddr *)&caddr, clen, addr,
        NI_MAXHOST, NULL, 0, NI_NUMERICHOST | NI_NUMERICSERV);
    if (gai_err) {
        log_warn("getnameinfo: %s", gai_strerror(gai_err));
        return;
    }
    if (npeer == MAXPEER) {
        log_warn("too many connections, %s rejected", addr);
        return;
    }
    for (p = peerlist; p != NULL; p = p->next) {
        if (strcmp(addr, p->addr) == 0) {
            if (p->state == PEER_WAITPID ||
                p->state == PEER_ENDING)
                p->restart = 1;
            log_debug("%s: already in progress", addr);
            return;
        }
    }
    p = malloc(sizeof(struct peer));
    if (p == NULL) {
        log_warn("%s: malloc: %s", addr, strerror(errno));
        return;
    }
    p->fd = s;
    p->msglen = 0;
    p->state = PEER_RECV;
    p->pfd = NULL;
    p->timeout = TIMO_RECV;
    p->restart = 0;
    strncpy(p->addr, addr, NI_MAXHOST + 1);
    p->next = peerlist;
    peerlist = p;
    npeer++;
    log_debug("%s: connected", p->addr);
}

/*
 * remove a peer structure and free any resources
 */
void peer_del(struct peer *p) {
    struct peer **i;

    for (i = &peerlist; *i != 0; i = &(*i)->next) {
        if (*i == p) {
            *i = p->next;
            close(p->fd);
            free(p);
            npeer--;
            return;
        }
    }
    log_err("peer_del: peer not found");
}

/*
 * attempt to fork() and exec() a command. If there
 * are too many childs running, then switch to the
 * PEER_FORK state to wait
 */
void peer_fork(struct peer *p) {
    if (nchild >= MAXCHLD) {
        p->state = PEER_FORK;
        return;
    }
    p->pid = fork();
    if (p->pid < 0) {
        log_warn("%s: fork: %s", p->addr, strerror(errno));
        p->state = PEER_ENDING;
        p->timeout = TIMO_ENDING;
        p->restart = 1;
        return;
    }
    if (p->pid == 0) {
        execlp(command, command, p->msg.uuid, (char *)NULL);
        log_err("%s: exec of %s: %s", p->addr, command, strerror(errno));
    }
    log_debug("%s: forked pid %d", p->addr, p->pid);
    p->state = PEER_WAITPID;
    p->timeout = TIMO_WAITPID;
    nchild++;
}

/*
 * receive bytes from the socket, as soon as the message is complete,
 * attempt to fork() a child process
 */
void peer_recv(struct peer *p) {
    unsigned char *buf, *endl;
    int n;

    buf = (unsigned char *)&p->msg;
    buf += p->msglen;
    n = read(p->fd, buf, sizeof(struct msg) - p->msglen);
    if (n < 0) {
        log_warn("%s: read failed: %s", p->addr, strerror(errno));
        peer_del(p);
        return;
    } else if (n == 0) {
        peer_del(p);
        return;
    }
    p->msglen += n;
    if (p->msglen == sizeof(struct msg)) {
        endl = memchr(p->msg.uuid, '\0', MSG_UUIDMAX);
        if (endl == NULL) {
            log_warn("%s: corrupted uuid", p->addr);
            peer_del(p);
            return;
        }
        peer_fork(p);
    }
}

/*
 * the timeout expired, move to the next state
 */
void peer_timeout(struct peer *p) {
    switch (p->state) {
    case PEER_RECV:
        peer_del(p);
        break;
    case PEER_WAITPID:
        log_debug("%s: pid %d killed", p->addr, p->pid);
        p->timeout = TIMO_WAITPID;
        kill(p->pid, SIGKILL);
        break;
    case PEER_ENDING:
        if (p->restart) {
            p->restart = 0;
            peer_fork(p);
            break;
        }
        log_debug("%s: expired", p->addr);
        peer_del(p);
        break;
    }
}

/*
 * dummy signal handler. We have nothing to do here, but we must use a
 * signal handler for poll() to be interrupted by SIGALRM or SIGCHLD
 */
void
dummy(int s) {
}

int
main(int argc, char **argv) {
    pid_t pid;
    sigset_t set;
    struct sigaction sa;
    struct itimerval it;
    struct peer *p, *pnext;
    struct pollfd *pfd, pfds[MAXPEER + MAXLISTEN];
    struct addrinfo *ailist, *ai, aihints;
    struct timespec ts, ts_last;
    int64_t delta;  // long long
    int fd, c, res, status, s, gai_err, save_errno = 0, opt;
    unsigned i;
    int f_flag = 0;

        initCatalog();

    while ((c = getopt(argc, argv, "c:dfp:")) != -1) {
        switch (c) {
        case 'c':
            command = optarg;
            break;
        case 'd':
            if (loglevel < 2)
                loglevel++;
            break;
        case 'f':
            f_flag = 1;
            break;
        case 'p':
            port = optarg;
            break;
        default:
            goto usage;
        }
    }
    argc -= optind;
    argv += optind;

    if (argc > 0) {
    usage:
        fprintf(stderr, NLS(MS_OPENPTS, OPENPTS_PTSEVTD_USAGE,
            "syntax: ptsevtd [-df] [-p port] [-c command]\n"));
        exit(1);
    }

    /*
     * block SIGPIPE, overwise write() may kill the process
     */
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    if (sigprocmask(SIG_BLOCK, &set, NULL))
        log_err("sigprocmask: %s", strerror(errno));

    /*
     * install a dummy handler for SIGCHLD and SIGALRM
     */
        sa.sa_flags = SA_RESTART;
        sa.sa_handler = dummy;
        sigfillset(&sa.sa_mask);
        if (sigaction(SIGCHLD, &sa, NULL) < 0)
        log_err("sigaction: %s", strerror(errno));
    if (sigaction(SIGALRM, &sa, NULL) < 0)
        log_err("sigaction: %s", strerror(errno));

    /*
     * listen on default address
     */
    memset(&aihints, 0, sizeof(struct addrinfo));
    aihints.ai_flags = AI_PASSIVE;
    aihints.ai_family = AF_UNSPEC;
    aihints.ai_socktype = SOCK_STREAM;
    gai_err = getaddrinfo(NULL, port, &aihints, &ailist);
    if (gai_err)
        log_err("getaddrinfo: %s", gai_strerror(gai_err));
    for (ai = ailist; ai != NULL; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0)
            log_err("socket: %s", strerror(errno));
        opt = 1;
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int)) < 0)
            log_err("setsockopt: %s", strerror(errno));
        if (bind(s, ai->ai_addr, ai->ai_addrlen) < 0) {
            save_errno = errno;
            close(s);
            continue;
        }
        if (listen(s, 1) < 0)
            log_err("listen: %s", strerror(errno));
        listen_fd[nlisten++] = s;
    }
    freeaddrinfo(ailist);

    if (nlisten == 0)
        log_err("bind: %s", strerror(save_errno));

    /*
     * daemonize
     */
    if (!f_flag) {
        pid = fork();
        if (pid < 0)
            log_err("fork: %s", strerror(errno));
        if (pid > 0)
            _exit(0);
        foreground = 0;
        openlog("ptsevtd", LOG_PID, LOG_DAEMON);
        setsid();
        fd = open("/dev/null", O_RDWR, 0666);
        if (fd < 0)
            log_err("/dev/null: %s\n", strerror(errno));
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > 2)
            close(fd);
    }

    /*
     * start periodic timer
     */
    it.it_interval.tv_sec = 0;
    it.it_interval.tv_usec = 100000;
    it.it_value.tv_sec = 0;
    it.it_value.tv_usec = 100000;
    if (setitimer(ITIMER_REAL, &it, NULL) < 0)
        log_err("setitimer: %s", strerror(errno));
    if (clock_gettime(CLOCK_MONOTONIC, &ts_last) < 0)
        log_err("clock_gettime: %s", strerror(errno));

    /*
     * main loop
     */
    for (;;) {
        /*
         * fill table for descriptor to poll
         */
        pfd = pfds;
        for (i = 0; i < nlisten; i++) {
            pfd->fd = listen_fd[i];
            pfd->events = POLLIN;
            pfd++;
        }
        for (p = peerlist; p != NULL; p = p->next) {
            if (p->state != PEER_RECV)
                continue;
            pfd->fd = p->fd;
            pfd->events = POLLIN;
            p->pfd = pfd;
            pfd++;
        }

        /*
         * wait
         */
        res = poll(pfds, pfd - pfds, -1);
        if (res < 0 && errno != EINTR)
            log_err("poll: %s", strerror(errno));

        /*
         * scan descriptors that have changed
         */
        if (res > 0) {
            pfd = pfds;
            for (i = 0; i < nlisten; i++) {
                if (pfd->revents & POLLIN)
                    peer_accept(pfd->fd);
                pfd++;
            }
            for (p = peerlist; p != NULL; p = pnext) {
                pnext = p->next;
                if (p->state != PEER_RECV || p->pfd == NULL)
                    continue;
                if (p->pfd->revents & POLLIN)
                    peer_recv(p);
            }
        }

        /*
         * scan for terminated childs
         */
        pid = waitpid(-1, &status, WNOHANG);
        if (pid > 0) {
            i = 0;
            for (p = peerlist; p != NULL; p = pnext) {
                pnext = p->next;
                if (p->state != PEER_WAITPID)
                    continue;
                if (p->pid != pid)
                    continue;
                log_debug("%s: pid %d reaped", p->addr, p->pid);
                nchild--;
                p->state = PEER_ENDING;
                p->timeout = TIMO_ENDING;
                i++;
            }
            for (p = peerlist; i > 0 && p != NULL; p = pnext) {
                pnext = p->next;
                if (p->state != PEER_FORK)
                    continue;
                peer_fork(p);
                i--;
            }
        }

        /*
         * advance timeouts
         */
        if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
            log_err("clock_gettime: %s", strerror(errno));
        delta = 1000000000LL * (ts.tv_sec - ts_last.tv_sec);
        delta += ts.tv_nsec - ts_last.tv_nsec;
        if (delta > 0) {
            ts_last = ts;
            for (p = peerlist; p != NULL; p = pnext) {
                pnext = p->next;
                if (p->timeout > delta) {
                    p->timeout -= delta;
                    continue;
                }
                peer_timeout(p);
            }
        }
    }
    return 0;
}
