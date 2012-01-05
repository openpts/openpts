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
 * \file src/ssh.c
 * \brief SSH conenction
 * @author Olivier Valentin <olivier.valentin@us.ibm.com>
 * @author Alexandre Ratchov <alexandre.ratchov@bull.net>
 * @date 2010-03-31
 * cleanup 2012-01-05 SM
 *
 */

#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/socket.h>

#include <openpts.h>

/* chanegd by unit test */
char *ptsc_command = "/usr/sbin/ptsc -m";

/** 
 * ssh_connect
 *
 * opens a communication channel (a socket) to a target using ssh.
 * 
 * @param host host name of the target. Is used as the SSH host name parameter.
 * @param ssh_username If not NULL, specifies the SSH user name to login as
 *        (defaults to the current user).
 * @param ssh_port If not 0, specifiesd the port of the remote SSH daemon.
 * @param key_file If not NULL, specifies the key to use.
 * @param socket Filed with the result socket. Use it for later communication.
 * @result the PID of the child SSH process or -1 in case of an error.
 */
pid_t ssh_connect(char *host, char *ssh_username, char *ssh_port, char *key_file, int *socket) {
    pid_t pid;
    int socket_pair[2];  // socket[1] is the SSH side

    /* check */
    if (host == NULL) {
        LOG(LOG_ERR, "null input");
        return -1;
    }

    /* socket */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socket_pair) == -1) {
        LOG(LOG_ERR, "socketpair() fail");
        goto err;
    }

    /* fork */
    if ((pid = fork()) == -1) {
        LOG(LOG_ERR, "fork() fail");
        goto err_close;
    }
    if (pid == 0) {
        /* child process */
        char *arguments[16];
        int arg_idx = 0;
        char identity_string[PATH_MAX + /* "IdentityFile " */ 13];

        // these belong to father
        close(socket_pair[0]);
        close(0);
        close(1);

        // replace stdin and stdout with the socket end
        dup2(socket_pair[1], 0);
        dup2(socket_pair[1], 1);
        close(socket_pair[1]);  // no longer needed

        arguments[arg_idx++] = "ssh";
        arguments[arg_idx++] = "-2";
        if (ssh_username != NULL) {
            arguments[arg_idx++] = "-l";
            arguments[arg_idx++] = ssh_username;
        }
        if (ssh_port != NULL) {
            arguments[arg_idx++] = "-p";
            arguments[arg_idx++] = ssh_port;
        }
        /* // should be specified in the ssh_conf file 
        arguments[arg_idx++] = "-o";
        arguments[arg_idx++] = "BatchMode yes";
        */
        if (key_file != NULL) {
            snprintf(identity_string, PATH_MAX + 13, "IdentityFile %s", key_file);
            arguments[arg_idx++] = "-o";
            arguments[arg_idx++] = identity_string;
        }
        arguments[arg_idx++] = host;
        arguments[arg_idx++] = ptsc_command;
#if 0
        // TODO
        /* Sync verbose level between verifier and collector? */
        if (verbose_sync) {
           int verboseLevel;
            for ( verboseLevel = 0; (verboseLevel < getVerbosity()) && (arg_idx < 15); verboseLevel++ ) {
                arguments[arg_idx++] = "-v";
            }
        }
#endif
        arguments[arg_idx++] = NULL;

        DEBUG("ptsc_command %s\n", ptsc_command);

        execvp("ssh", arguments);
        LOG(LOG_ERR, "execvp(ssh)");
        exit(1);
    }

    close(socket_pair[1]);
    *socket = socket_pair[0];

    fcntl(*socket, F_SETFD, FD_CLOEXEC);

    // success
    return pid;

  err_close:
    close(socket_pair[0]);
    close(socket_pair[1]);
  err:
    return -1;
}

