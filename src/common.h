#ifndef COMMON_H
#define COMMON_H

/* This is the data record stored in the map */
struct datarec {
	__u64 rx_packets;
	/* Assignment#1: Add byte counters */
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif
#endif