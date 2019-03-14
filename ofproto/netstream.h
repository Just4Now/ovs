#ifndef OFPROTO_NETSTREAM_H
#define OFPROTO_NETSTREAM_H 1

#include <stdint.h>
#include "flow.h"
#include "sset.h"
#include "ofproto.h"

#define NS_MAX_BRIDGE_NAME_LENGTH 16
#define NS_MAX_PATH_LOG_LENGTH 48
#define NS_LOG_DIR_MODE 0755
#define NS_MAX_DB_PATH_LENGTH 64
#define NS_MAX_STRING_READABLE 32
#define NS_ICMP 1
#define NS_TCP 6
#define NS_UDP 17
#define NS_MAX_SQL_CMD_LENGTH 512
#define NS_SQL_TABLE_INDEX_NUM 7

#define NS_SAMPLE_MODE_DEFAULT RANDOM_PACKETS
#define NS_SAMPLE_INTERVAL_DEFAULT 100
#define NS_INACTIVE_TIMEOUT_DEFAULT 30
#define NS_ACTIVE_TIMEOUT_DEFAULT 30
#define NS_FLOW_CACHE_NUMBER_DEFAULT 10240
#define NS_log_DEFAULT false
#define NS_TCP_FLAGS_DEFAULT false

#define NS_DB_FILE_NAME "netstream.db"

#define NETSTREAM_V5_VERSION 5

enum SAMPLE_MODE {
    FIX_PACKETS,
    RANDOM_PACKETS
};

struct netstream_db_record{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port; 
    uint16_t input;
    uint16_t output;

    uint64_t start_time;
    uint64_t end_time;
    uint32_t packet_count;
    uint32_t byte_count;

    char src_ip_port[NS_MAX_STRING_READABLE];
    char dst_ip_port[NS_MAX_STRING_READABLE];
    char s_time_read[NS_MAX_STRING_READABLE];
    char e_time_read[NS_MAX_STRING_READABLE];
    
    uint32_t duration;
    char protocol[NS_MAX_STRING_READABLE];
    uint64_t bytes_per_pkt;
    uint8_t ip_tos;
    uint16_t sample_interval;
    uint8_t pad[3];
};

struct netstream_db_queue{
    uint32_t front;
    uint32_t rear;
    uint32_t maxlength;
    struct netstream_db_record *ns_db_node;
};

struct netstream_options {
    struct sset collectors;
    uint8_t engine_type;
    uint8_t engine_id;
    bool add_id_to_iface;
    enum SAMPLE_MODE sample_mode;
    int sample_interval;
    int inactive_timeout;
    int active_timeout;
    int flow_cache_number;
    bool log;
    bool tcp_flag;
    bool forced_expired;
};

struct netstream {
    char bridge_name[NS_MAX_BRIDGE_NAME_LENGTH];
    uint8_t engine_type;          /* Value of engine_type to use. */
    uint8_t engine_id;            /* Value of engine_id to use. */
    uint64_t boot_time;           /* Time when netstream_create() was called. */
    struct collectors *collectors; /* NetStream collectors. */
    bool add_id_to_iface;         /* Put the 7 least significiant bits of
                                   * 'engine_id' into the most significant
                                   * bits of the interface fields. */
    bool tcp_flag;
    bool forced_expiring;

    enum SAMPLE_MODE sample_mode;
    uint32_t sample_interval;

    bool log;
    char log_path[NS_MAX_PATH_LOG_LENGTH];
    struct netstream_db_queue ns_db_que;

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
 * We only send a single record per NetStream message.
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

struct netstream *netstream_create(char *);
void netstream_unref(struct netstream *);
void netstream_run(struct netstream *);
int netstream_set_options(struct netstream *, const struct netstream_options *);
void netstream_wait(struct netstream *);
void netstream_flow_update(struct netstream *, const struct flow *, ofp_port_t, const struct dpif_flow_stats *);
struct netstream *netstream_ref(const struct netstream *);
void netstream_mask_wc(const struct flow *, struct flow_wildcards *);
uint32_t netstream_get_probability(const struct netstream *ns);

#endif /* netstream.h */