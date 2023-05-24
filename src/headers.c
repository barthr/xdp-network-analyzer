#pragma once

#include "vmlinux.h"

struct dnshdr {
    __u16 transaction_id;
    __u8 rd : 1;
    __u8 tc : 1;
    __u8 aa : 1;
    __u8 opcode : 4;
    __u8 qr : 1;
    __u8 rcode : 4;
    __u8 cd : 1;
    __u8 ad : 1;
    __u8 z : 1;
    __u8 ra : 1;
    __u16 q_count;
    __u16 ans_count;
    __u16 auth_count;
    __u16 add_count;
};