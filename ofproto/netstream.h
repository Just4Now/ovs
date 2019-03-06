#ifndef OFPROTO_NETSTREAM_H
#define OFPROTO_NETSTREAM_H 1

#include <stdint.h>
#include "sset.h"

#define MAX_PATH_LENGTH 64
#define NS_SAMPLE_MODE_DEFAULT RANDOM_PACKETS
#define NS_SAMPLE_VALUE_DEFAULT 100
#define NS_INACTIVE_TIMEOUT_DEFAULT 30
#define NS_ACTIVE_TIMEOUT_DEFAULT 30
#define NS_FLOW_CACHE_NUMBER_DEFAULT 10240
#define NS_SAVE_TO_LOCAL_DEFAULT false
#define NS_TCP_FLAGS_DEFAULT false

#define NETSTREAM_V5_VERSION 5

enum SAMPLE_MODE {
    FIX_PACKETS,
    RANDOM_PACKETS
}

enum FLOW_TYPE {
    INACTIVE_FLOW,
    ACTIVE_FLOW
}

struct netstream_options {
    struct sset collectors;
    uint8_t engine_type;
    uint8_t engine_id;
    bool add_id_to_iface;
    enum SAMPLE_MODE sample_mode;
    int sample_value;
    int inactive_timeout;
    int active_timeout;
    int flow_cache_number;
    bool save_to_local;
    char save_to_local_path[MAX_PATH_LENGTH];
    bool tcp_flag;
};

struct netstream {
    uint8_t engine_type;          /* Value of engine_type to use. */
    uint8_t engine_id;            /* Value of engine_id to use. */
    uint64_t boot_time;      /* Time when netstream_create() was called. */
    struct collectors *collectors; /* NetStream collectors. */
    bool add_id_to_iface;         /* Put the 7 least significiant bits of
                                   * 'engine_id' into the most significant
                                   * bits of the interface fields. */
    bool tcp_flag;

    enum SAMPLE_MODE sample_mode;
    uint32_t sample_value;

    bool save_to_local;
    char save_to_local_path[MAX_PATH_LENGTH];

    uint64_t inactive_timeout; /* Timeout for flows that are expired. */ 
    uint64_t active_timeout; /* Timeout for flows that are still active. */
    uint64_t next_timeout;   /* Next scheduled timeout. */
    uint64_t reconfig_active_timeout;  /* When we reconfigured the timeouts. */

    long long int flow_cache_number;

    uint32_t netstream_cnt;         /* Flow sequence number for NetStream. */
    struct ofpbuf packet;         /* NetStream packet being accumulated. */

    struct hmap flows;            /* Contains 'netstream_flows'. */

    struct ovs_refcount ref_cnt;
};

struct netstream_flow {
    struct hmap_node hmap_node;

    uint64_t last_expired;   /* Time this active flow last timed out. */
    uint64_t created;        /* Time flow was created since time out. */

    ofp_port_t output_iface;      /* Output interface index. */
    uint16_t tcp_flags;           /* Bitwise-OR of all TCP flags seen. */

    ofp_port_t in_port;           /* Input port. */
    uint32_t nw_src;              /* IPv4 source address. */
    uint32_t nw_dst;              /* IPv4 destination address. */
    uint8_t nw_tos;               /* IP ToS (including DSCP and ECN). */
    uint8_t nw_proto;             /* IP protocol. */
    uint16_t tp_src;              /* TCP/UDP/SCTP source port. */
    uint16_t tp_dst;              /* TCP/UDP/SCTP destination port. */

    uint32_t packet_count;        /* Packets from subrules. */
    uint32_t byte_count;          /* Bytes from subrules. */
    uint64_t used;           /* Last-used time (0 if never used). */
};

/* Every NetStream v5 message contains the header that follows.  This is
 * followed by up to thirty records that describe a terminating flow.
 * We only send a single record per NetFlow message.
 */
struct netstream_v5_header {
    uint16_t version;              /* NetStream version is 5. */
    uint16_t count;                /* Number of records in this message. */
    uint32_t sysuptime;            /* System uptime in milliseconds. */
    uint32_t unix_secs;            /* Number of seconds since Unix epoch. */
    uint32_t unix_nsecs;           /* Number of residual nanoseconds
                                      after epoch seconds. */
    uint32_t flow_seq;             /* Number of flows since sending
                                      messages began. */
    uint8_t  engine_type;          /* Engine type. */
    uint8_t  engine_id;            /* Engine id. */
    uint16_t sampling_interval;    /* Sample interval. */
};

/* A NetStream v5 description of a terminating flow.  It is preceded by a
 * NetStream v5 header.
 */
struct netstream_v5_record {
    uint32_t src_addr;             /* Source IP address. */
    uint32_t dst_addr;             /* Destination IP address. */
    uint32_t nexthop;              /* IP address of next hop.  Set to 0. */
    uint16_t input;                /* Input interface index. */
    uint16_t output;               /* Output interface index. */
    uint32_t packet_count;         /* Number of packets. */
    uint32_t byte_count;           /* Number of bytes. */
    uint32_t init_time;            /* Value of sysuptime on first packet. */
    uint32_t used_time;            /* Value of sysuptime on last packet. */

    /* The 'src_port' and 'dst_port' identify the source and destination
     * port, respectively, for TCP and UDP.  For ICMP, the high-order
     * byte identifies the type and low-order byte identifies the code
     * in the 'dst_port' field. */
    uint16_t src_port;
    uint16_t dst_port;

    uint8_t  pad1;
    uint8_t  tcp_flags;            /* Union of seen TCP flags. */
    uint8_t  ip_proto;             /* IP protocol. */
    uint8_t  ip_tos;               /* IP TOS value. */
    uint16_t src_as;               /* Source AS ID.  Set to 0. */
    uint16_t dst_as;               /* Destination AS ID.  Set to 0. */
    uint8_t  src_mask;             /* Source mask bits.  Set to 0. */
    uint8_t  dst_mask;             /* Destination mask bits.  Set to 0. */
    uint8_t  pad[2];
};


struct netstream *netstream_create(void);
void netstream_unref(struct netstream *);

#endif /* netstream.h */