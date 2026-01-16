// +build ignore
/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2026 Authors of KubeArmor */

#ifndef __SYSCALLS_H
#define __SYSCALLS_H
enum
{
    // file
    _FILE_OPEN = 450,
    _FILE_PERMISSION = 451,
    _FILE_MKNOD = 452,
    _FILE_UNLINK = 453,
    _FILE_MKDIR = 454,
    _FILE_RMDIR= 455,
    _FILE_SYMLINK = 456,
    _FILE_LINK = 457,
    _FILE_RENAME = 8458,
    _FILE_CHMOD = 459,
    _FILE_TRUNCATE = 460,
 

    // network
    _SOCKET_CREATE = 461,
    _SOCKET_CONNECT = 462,
    _SOCKET_ACCEPT = 463,

    //process
    _SECURITY_BPRM_CHECK = 352,

    // capabilities
    _CAPABLE = 464,

    // dropping alert
    _DROPPING_ALERT = 0,


};
#endif /* __SYSCALLS_H */