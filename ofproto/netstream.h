#ifndef OFPROTO_NETSTREAM_H
#define OFPROTO_NETSTREAM_H 1

#include <stdint.h>
#include "flow.h"
#include "sset.h"
#include "ofproto.h"

#define NS_MAX_BRIDGE_NAME_LENGTH 16
#define NS_MAX_PATH_LOG_LENGTH 64
#define NS_LOG_DIR_MODE 0755
#define NS_MAX_DB_PATH_LENGTH 64
#define NS_MAX_STRING_READABLE 32
#define NS_ICMP 1
#define NS_TCP 6
#define NS_UDP 17
#define NS_MAX_SQL_CMD_LENGTH 1024
#define NS_SQL_TABLE_INDEX_NUM 7


#define NS_SAMPLE_INTERVAL_DEFAULT 100
#define NS_INACTIVE_TIMEOUT_DEFAULT 30
#define NS_ACTIVE_TIMEOUT_DEFAULT 30
#define NS_MAX_N_FLOW_CACHE_DEFAULT 50000
#define NS_log_DEFAULT false
#define NS_TCP_FLAGS_DEFAULT false

#define NS_DB_FILE_NAME "netstream.db"

#define NETSTREAM_V5_VERSION 5



struct netstream_db_record{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port; 
    uint16_t input;
    uint16_t output;

    time_t start_time;
    time_t end_time;
    uint32_t packet_count;
    uint32_t byte_count;

    char src_ip_port[NS_MAX_STRING_READABLE];
    char dst_ip_port[NS_MAX_STRING_READABLE];
    char s_time_read[NS_MAX_STRING_READABLE];
    char e_time_read[NS_MAX_STRING_READABLE];
    char pro_read[NS_MAX_STRING_READABLE];  
    uint32_t duration;

    uint64_t bytes_per_pkt;
    uint8_t protocol;
    uint8_t ip_tos;
    uint16_t sample_interval;
    uint8_t tcp_flags;
    uint8_t pad[2];
};

struct netstream_db_queue{
    uint32_t front;
    uint32_t rear;
    uint32_t maxlength;
    struct netstream_db_record *ns_db_node;
};

struct netstream_options {
    struct sset collectors;    /* NetStream报文输出地址 */
    uint8_t engine_type;    /* 引擎类型 */
    uint8_t engine_id;    /* 引擎id */
    bool add_id_to_iface;    /* add_id_to_iface使能标记 */
    int sample_interval;    /* 采样间隔 */
    int inactive_timeout;    /* 非活跃流老化时间 */
    int active_timeout;    /* 活跃流老化时间 */
    int max_flow;    /* 最大流缓存数目 */
    bool log;    /* 流信息数据库写入使能标记 */
    bool tcp_flags;    /* TCP FIN/RST报文老化使能标记 */
    bool forced_expiring;    /* TCP FIN/RST报文老化使能标记 */
};

struct netstream {
    char bridge_name[NS_MAX_BRIDGE_NAME_LENGTH];    /* OVS网桥名称,支持最大长度为15 */
    uint8_t engine_type;          
    uint8_t engine_id;            /* Value of engine_id to use. */
    uint64_t boot_time;           /* 配置创建时间 */
    struct collectors *collectors; /* NetStream collectors. */
    bool add_id_to_iface;         /* Put the 7 least significiant bits of
                                   * 'engine_id' into the most significant
                                   * bits of the interface fields. */
    bool tcp_flags;
    bool forced_expiring;

    uint32_t sample_interval;

    bool log;
    char log_path[NS_MAX_PATH_LOG_LENGTH];    /* 流信息数据库文件绝对路径 */
    struct netstream_db_queue ns_db_que;    /* 存储老化流的环形队列 */

    uint64_t inactive_timeout; /* Timeout for flows that are expired. */ 
    uint64_t active_timeout; /* Timeout for flows that are still active. */
    uint64_t next_timeout;   /* 下一次超时时间 */

    long long int max_flow;

    uint32_t netstream_cnt;         /* NetStream流序列号 */
    struct ofpbuf packet;         /* 缓存的NetStream报文 */
    struct hmap flows;            /* NetStream流缓存区，包含NetStream流 */

    struct ovs_refcount ref_cnt;
};

struct netstream_flow {
    struct hmap_node hmap_node;    /* 哈希节点 */
    uint64_t active_flow_expired;    /* 上一次活跃流老化时间 */
    uint64_t created;    /* 流被创建的时间 */
    ofp_port_t output_iface;    /* 输出接口索引 */
    uint16_t tcp_flags;    /* TCP标记进行“或”后的值 */
    ofp_port_t in_port;    /* 输入端口 */
    uint32_t nw_src;    /* 源IP地址 */
    uint32_t nw_dst;    /* 目的IP地址 */
    uint8_t nw_tos;    /* IP服务类型 */
    uint8_t nw_proto;    /* IP协议号 */
    uint16_t tp_src;    /* 源端口号 */
    uint16_t tp_dst;    /* 目的端口号 */
    uint32_t packet_count;    /* 报文数目 */
    uint32_t byte_count;    /* 总的字节数 */
    uint64_t used;    /* 上一次使用时间 */
    time_t first_timestamp;    /* 流第一次使用的时间戳 */
    time_t last_timestamp;    /* 流最后一次使用的时间戳 */
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
    uint8_t  pad[2];             /* First two bits hold the sampling mode; remaining 14 bits hold value of sampling interval */
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
    uint32_t init_time;            /* Value of sysuptime on first packet.第一个包到NS开启之间的时间 */
    uint32_t used_time;            /* Value of sysuptime on last packet.最后一个包到NS开启之间的时间 */

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
    uint8_t  pad2[2];
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