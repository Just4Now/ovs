#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>
#include <unistd.h>

#include "collectors.h"
#include "dpif.h"
#include "flow.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "ofproto/netstream.h"
#include "timeval.h"
#include "sqlite3.h"
#include "dirs.h"



VLOG_DEFINE_THIS_MODULE(netstream);

static void netstream_run__(struct netstream *ns) OVS_REQUIRES(mutex);
static void netstream_expire__(struct netstream *, struct netstream_flow *)
    OVS_REQUIRES(mutex);
static void gen_netstream_rec(struct netstream *, struct netstream_flow *)
    OVS_REQUIRES(mutex);
static void netstream_create_database(struct netstream *);
static inline void netstream_db_createque(struct netstream_db_queue *, int);
static inline void netstream_db_destroyque(struct netstream_db_queue *);
static inline bool netstream_db_isfullq(struct netstream_db_queue *);
static inline bool netstream_db_isemptyq(struct netstream_db_queue *);
static inline int netstream_db_enqueue(struct netstream_db_queue *, struct netstream_db_record *);    
static inline bool netstream_db_dequeue(struct netstream_db_queue *, struct netstream_db_record *);
static bool netstream_write_into_db(sqlite3 *, struct netstream *);
static void netstream_log_path_init(struct netstream *);
static struct netstream_flow *netstream_flow_lookup(const struct netstream *, const struct flow *);
static uint32_t netstream_flow_hash(const struct flow *);

static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;
static atomic_count netstream_count = ATOMIC_COUNT_INIT(0);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

const char *sql_index_name[] = {
    "SRC_IP_INDEX", "SRC_IP",
    "DST_IP_INDEX", "DST_IP",
    "SRC_PORT_INDEX", "SRC_PORT",
    "DST_PORT_INDEX", "DST_PORT",
    "PROTOCOL_INDEX", "PROTOCOL",
    "START_TIME_INDEX", "START_TIME",
    "END_TIME_INDEX", "END_TIME"
};

struct netstream *
netstream_create(char *bridge_name)
{
    struct netstream *ns = xzalloc(sizeof *ns);

    memset(ns->bridge_name, 0, sizeof(ns->bridge_name));
    memset(ns->log_path, 0, sizeof(ns->log_path));
    memset(&ns->ns_db_que, 0, sizeof(ns->ns_db_que));
    strcpy(ns->bridge_name, bridge_name);
    ns->engine_type = 0;
    ns->engine_id = 0;
    ns->boot_time = time_msec();
    ns->collectors = NULL;
    ns->add_id_to_iface = false;
    ns->netstream_cnt = 0;
    ns->tcp_flag = false;
    ns->log = false;
    hmap_init(&ns->flows);
    ovs_refcount_init(&ns->ref_cnt);
    ofpbuf_init(&ns->packet, 1500);
    atomic_count_inc(&netstream_count);
    return ns;
};

int
netstream_set_options(struct netstream *ns,
                      const struct netstream_options *ns_options)
    OVS_EXCLUDED(mutex)
{
    int error = 0;
    long long int old_timeout;

    ovs_mutex_lock(&mutex);
    ns->engine_type = ns_options->engine_type;
    ns->engine_id = ns_options->engine_id;
    ns->add_id_to_iface = ns_options->add_id_to_iface;
    ns->sample_mode = ns_options->sample_mode;
    ns->sample_interval = ns_options->sample_interval;
    ns->flow_cache_number = ns_options->flow_cache_number;
    ns->tcp_flag = ns_options->tcp_flag;

    ns->log = ns_options->log;
    /* 日志功能开关发生了变化 */
    if (ns->log) {
        /* 创建目录、环形队列以及数据库(不存在的情况下) */
        netstream_log_path_init(ns);
        netstream_db_createque(&ns->ns_db_que, ns->flow_cache_number);
        netstream_create_database(ns);
    } else
    {
        netstream_db_destroyque(&ns->ns_db_que);
    }

    ns->forced_expiring = ns_options->forced_expiring;
    /* 强制老化并删除流 */
    if (ns->forced_expiring) {
        struct netstream_flow *ns_flow, *next;
        HMAP_FOR_EACH_SAFE (ns_flow, next, hmap_node, &ns->flows) {
            netstream_expire__(ns, ns_flow);
            hmap_remove(&ns->flows, &ns_flow->hmap_node);
            free(ns_flow);
        }
    }

    collectors_destroy(ns->collectors);
    collectors_create(&ns_options->collectors, -1, &ns->collectors);

    ns->inactive_timeout = ns_options->inactive_timeout * 1000;

    old_timeout = ns->active_timeout;
    ns->active_timeout = ns_options->active_timeout * 1000 * 60;
    if (old_timeout != ns->active_timeout) {
        ns->reconfig_active_timeout = time_msec();
        ns->next_timeout = time_msec();
    }
    ovs_mutex_unlock(&mutex);

    return error;
}

void
netstream_unref(struct netstream *ns)
{
    if (ns && ovs_refcount_unref_relaxed(&ns->ref_cnt) == 1) {
        atomic_count_dec(&netstream_count);
        collectors_destroy(ns->collectors);
        ofpbuf_uninit(&ns->packet);

        struct netstream_flow *ns_flow, *next;
        HMAP_FOR_EACH_SAFE (ns_flow, next, hmap_node, &ns->flows) {
            hmap_remove(&ns->flows, &ns_flow->hmap_node);
            free(ns_flow);
        }
        hmap_destroy(&ns->flows);
        if (ns->log) {
            netstream_db_destroyque(&ns->ns_db_que);
        }
        free(ns);
    }
}

void
netstream_run(struct netstream *ns)
{
    ovs_mutex_lock(&mutex);
    netstream_run__(ns);
    ovs_mutex_unlock(&mutex);
}

/* Returns true if it's time to send out a round of NetStream timeouts,
 * false otherwise. */
static void
netstream_run__(struct netstream *ns) OVS_REQUIRES(mutex)
{
    long long int now = time_msec();
    struct netstream_flow *ns_flow, *next;

    /* 发送已经累积的NetStream报文 */
    if (ns->packet.size) {
        collectors_send(ns->collectors, ns->packet.data, ns->packet.size);
        ns->packet.size = 0;
    }

    /* 距离上一次进入该函数还未超过1秒则直接返回 */
    if (now < ns->next_timeout) {
        return;
    }

    ns->next_timeout = now + 1000;

    HMAP_FOR_EACH_SAFE (ns_flow, next, hmap_node, &ns->flows) {
        /* 非活跃流老化 */
        if (now > ns_flow->used + ns->inactive_timeout) {
            netstream_expire__(ns, ns_flow);
            /* 将超时的非活跃流移除 */
            hmap_remove(&ns->flows, &ns_flow->hmap_node);
            free(ns_flow);
            continue;
        }
        /* 活跃流老化 */
        if (now > ns_flow->last_expired + ns->active_timeout) {
            ns_flow->last_expired += ns->active_timeout;    //更新上一次活跃流超时的时间
            netstream_expire__(ns, ns_flow);
        }
    }

    /* Netstream日志功能开启后并且有老化流才会将流记录写入本地数据库文件中 */
    if (ns->log && !netstream_db_isemptyq(&ns->ns_db_que)) {
        char db_file_path[NS_MAX_DB_PATH_LENGTH];
        sqlite3* db;
        char *errmsg = NULL;
        int rc;

        sprintf(db_file_path, "%s/%s-%s", ns->log_path, ns->bridge_name, NS_DB_FILE_NAME);
        rc = sqlite3_open(db_file_path, &db);
        if (rc != SQLITE_OK) {
            VLOG_ERR_RL(&rl, "Can't open netstream log database(%s), please check "
                   "if it is bad.(Error message:%s)", db_file_path, sqlite3_errmsg(db));
            goto err_open;
        }else{
            rc = sqlite3_exec(db, "PRAGMA synchronous = OFF;", 0, 0, &errmsg);  //关闭同步
            if (rc != SQLITE_OK) {  //关闭同步失败
                VLOG_ERR_RL(&rl, "Turn off synchronous failed.(Error message:%s)", errmsg);
                goto err_excute;
            }
            rc = sqlite3_exec(db, "BEGIN;", 0, 0, &errmsg); //开启事务
            if (rc != SQLITE_OK) {  //开启事务失败
                VLOG_ERR_RL(&rl, "Excuting begin failed.(Error message:%s)", errmsg);
                goto err_excute;
            }
        }

        if(netstream_write_into_db(db, ns))
        {
            rc = sqlite3_exec(db, "COMMIT;", 0, 0, &errmsg); //提交事务
            if (rc != SQLITE_OK) {  //提交事务失败
                VLOG_ERR_RL(&rl, "Excuting commit failed.(Error message:%s)", errmsg);
                goto err_excute;
            }
        }else
        {
            rc = sqlite3_exec(db, "ROLLBACK;", 0, 0, &errmsg); //提交事务
            if (rc != SQLITE_OK) {  //提交事务失败
                VLOG_ERR_RL(&rl, "Excuting rollback failed.(Error message:%s)", errmsg);
                goto err_excute;
            }
        }

        err_excute:
        sqlite3_free(errmsg);
        err_open:
        sqlite3_close(db);
    }
}

static void
netstream_expire__(struct netstream *ns, struct netstream_flow *ns_flow)
    OVS_REQUIRES(mutex)
{
    uint64_t pkts;

    pkts = ns_flow->packet_count;

    if (pkts == 0) {
        return;
    }

    /* 生成netstream record */        
    gen_netstream_rec(ns, ns_flow);

    /* Update flow tracking data. */
    ns_flow->packet_count = 0;
    ns_flow->byte_count = 0;
    ns_flow->tcp_flags = 0;
}

static void
gen_netstream_rec(struct netstream *ns, struct netstream_flow *ns_flow)
    OVS_REQUIRES(mutex)
{
    struct netstream_v5_header *ns_hdr;
    struct netstream_v5_record *ns_rec;

    if (!ns->packet.size) {
        struct timespec now;

        time_wall_timespec(&now);

        ns_hdr = ofpbuf_put_zeros(&ns->packet, sizeof *ns_hdr);
        ns_hdr->version = htons(NETSTREAM_V5_VERSION);
        ns_hdr->count = htons(0);
        ns_hdr->sysuptime = htonl(time_msec() - ns->boot_time);
        ns_hdr->unix_secs = htonl(now.tv_sec);
        ns_hdr->unix_nsecs = htonl(now.tv_nsec);
        ns_hdr->engine_type = ns->engine_type;  //单字节不需要大小段转换
        ns_hdr->engine_id = ns->engine_id;
        ns_hdr->sampling = htons((((uint16_t)ns->sample_mode << 14) & 0xc000) | (ns->sample_interval & 0x3fff));
    }

    ns_hdr = ns->packet.data;
    ns_hdr->count = htons(ntohs(ns_hdr->count) + 1);
    ns_hdr->flow_seq = htonl(ns->netstream_cnt++);

    ns_rec = ofpbuf_put_zeros(&ns->packet, sizeof *ns_rec);
    ns_rec->src_addr = ns_flow->nw_src;
    ns_rec->dst_addr = ns_flow->nw_dst;
    ns_rec->nexthop = htonl(0);
    if (ns->add_id_to_iface) {
        uint16_t iface = (ns->engine_id & 0x7f) << 9;
        ns_rec->input = htons(iface | (ofp_to_u16(ns_flow->in_port) & 0x1ff));
        ns_rec->output = htons(iface
            | (ofp_to_u16(ns_flow->output_iface) & 0x1ff));
    } else {
        ns_rec->input = htons(ofp_to_u16(ns_flow->in_port));
        ns_rec->output = htons(ofp_to_u16(ns_flow->output_iface));
    }
    ns_rec->packet_count = htonl(ns_flow->packet_count);
    ns_rec->byte_count = htonl(ns_flow->byte_count);
    ns_rec->init_time = htonl(ns_flow->created - ns->boot_time);
    ns_rec->used_time = htonl(MAX(ns_flow->created, ns_flow->used)
                             - ns->boot_time);
    if (ns_flow->nw_proto == IPPROTO_ICMP) {
        /* In NetStream, the ICMP type and code are concatenated and
         * placed in the 'dst_port' field. */
        uint8_t type = ntohs(ns_flow->tp_src);
        uint8_t code = ntohs(ns_flow->tp_dst);
        ns_rec->src_port = htons(0);
        ns_rec->dst_port = htons((type << 8) | code);
    } else {
        ns_rec->src_port = ns_flow->tp_src;
        ns_rec->dst_port = ns_flow->tp_dst;
    }
    ns_rec->tcp_flags = (uint8_t) ns_flow->tcp_flags;
    ns_rec->ip_proto = ns_flow->nw_proto;
    ns_rec->ip_tos = ns_flow->nw_tos & IP_DSCP_MASK;

    if (ns->log) {
        struct netstream_db_record ns_db_record;
        struct tm s_tm, e_tm;

        memset(&ns_db_record, 0, sizeof(ns_db_record));
        memset(&s_tm, 0, sizeof(s_tm));
        memset(&e_tm, 0, sizeof(e_tm));

        ns_db_record.src_ip = ntohl(ns_flow->nw_src);
        ns_db_record.dst_ip = ntohl(ns_flow->nw_dst);
        ns_db_record.src_port = ntohs(ns_rec->src_port);
        ns_db_record.dst_port = ntohs(ns_rec->dst_port);
        ns_db_record.input = ns_flow->in_port;
        ns_db_record.output = ns_flow->output_iface;
        ns_db_record.start_time = ns_flow->first_timestamp;
        ns_db_record.end_time = ns_flow->last_timestamp;
        ns_db_record.packet_count = ns_flow->packet_count;
        ns_db_record.byte_count = ns_flow->byte_count;
        ns_db_record.duration = ns_db_record.end_time - ns_db_record.start_time;
        ns_db_record.ip_tos = ns_flow->nw_tos & IP_DSCP_MASK;
        ns_db_record.sample_interval = ns->sample_interval;
        ns_db_record.bytes_per_pkt = ns_db_record.byte_count / ns_db_record.packet_count;
        ns_db_record.protocol = ns_flow->nw_proto;
        ns_db_record.tcp_flags = ns_rec->tcp_flags;

        if (ns_flow->nw_proto == NS_TCP || ns_flow->nw_proto == NS_UDP) {
            if (ns_flow->nw_proto == NS_TCP) {
                strcpy(ns_db_record.pro_read, "TCP");
            }else
            {
                strcpy(ns_db_record.pro_read, "UDP");
            }       
            struct in_addr addr;
            addr.s_addr = htonl(ns_db_record.src_ip);
            sprintf(ns_db_record.src_ip_port, "%s:%u", inet_ntoa(addr), ns_db_record.src_port);
            addr.s_addr = htonl(ns_db_record.dst_ip);
            sprintf(ns_db_record.dst_ip_port, "%s:%u", inet_ntoa(addr), ns_db_record.dst_port);
        }else
        {
            if (ns_flow->nw_proto == NS_ICMP) {
                strcpy(ns_db_record.pro_read, "ICMP");
            }else
            {
                strcpy(ns_db_record.pro_read, "IP-Other");
            }
            struct in_addr addr;
            addr.s_addr = htonl(ns_db_record.src_ip);
            sprintf(ns_db_record.src_ip_port, "%s", inet_ntoa(addr));
            addr.s_addr = htonl(ns_db_record.dst_ip);
            sprintf(ns_db_record.dst_ip_port, "%s", inet_ntoa(addr));
        }

        localtime_r(&ns_flow->first_timestamp, &s_tm);
        localtime_r(&ns_flow->last_timestamp, &e_tm);
        strftime(ns_db_record.s_time_read, NS_MAX_STRING_READABLE, "%F %T", &s_tm);
        strftime(ns_db_record.e_time_read, NS_MAX_STRING_READABLE, "%F %T", &e_tm);

        if (!netstream_db_enqueue(&ns->ns_db_que, &ns_db_record))
        {
            VLOG_WARN_RL(&rl, "%s:the netstream db queue is full!", ns->bridge_name);
        }
    }

    /* NetStream messages are limited to 30 records. */
    if (ntohs(ns_hdr->count) >= 30) {
        netstream_run__(ns);
    }
}

void
netstream_wait(struct netstream *ns) OVS_EXCLUDED(mutex)
{
    ovs_mutex_lock(&mutex);
    poll_timer_wait_until(ns->next_timeout);
    if (ns->packet.size) {
        poll_immediate_wake();
    }
    ovs_mutex_unlock(&mutex);
}

static void
netstream_create_database(struct netstream *ns)
{
    char db_file_path[NS_MAX_DB_PATH_LENGTH];
    sqlite3* db;
    char *errmsg = NULL;
    int rc;
    char *sqlcmd = (char *)malloc(NS_MAX_SQL_CMD_LENGTH);

    sprintf(db_file_path, "%s/%s-%s", ns->log_path, ns->bridge_name, NS_DB_FILE_NAME);

    if (access(db_file_path, F_OK) == 0) {
        return; /* 如果数据库文件存在则不需要重新创建 */
    }
    
    rc = sqlite3_open(db_file_path, &db);
    if (rc != SQLITE_OK) {
        VLOG_ERR_RL(&rl, "Can't open netstream log database(%s), please " 
                 "check if it is bad.(Error message:%s)", db_file_path, sqlite3_errmsg(db));
        goto err_open;
    }

    memset(sqlcmd, 0, NS_MAX_SQL_CMD_LENGTH);
    sprintf(sqlcmd, \
            "CREATE TABLE IF NOT EXISTS NETSTREAM("
            "BRIDGE_NAME   CHAR(16),"
            "SRC_IP        INTEGER,"
            "DST_IP        INTEGER,"
            "SRC_PORT      INTEGER,"
            "DST_PORT      INTEGER,"
            "PROTOCOL      CHAR(32),"
            "START_TIME    INTEGER,"
            "END_TIME      INTEGER,"
            "DURATION      INTEGER,"
            "SRC_IP_PORT   CHAR(32),"
            "DST_IP_PORT   CHAR(32),"
            "S_TIME_READ   CHAR(32),"
            "E_TIME_READ   CHAR(32),"
            "PRO_READ      CHAR(32),"
            "INPUT         INTEGER,"
            "OUTPUT        INTEGER,"
            "PACKET_COUNT  INTEGER,"
            "BYTE_COUNT    INTEGER,"
            "TOS           INTEGER,"
            "SAMPLE_INT    INTEGER,"
            "BYTES_PER_PKT INTEGER,"
            "TCP_FLAGS     INTEGER);");
    rc = sqlite3_exec(db, sqlcmd, 0, 0, &errmsg);
    if( rc != SQLITE_OK ){
        VLOG_ERR_RL(&rl, "Can't create main table netstream in %s."
                    "(Error message:%s)", db_file_path, errmsg);
        goto err_create;
    }

    for(size_t i = 1; i < NS_SQL_TABLE_INDEX_NUM * 2; i += 2)
    {
        memset(sqlcmd, 0, NS_MAX_SQL_CMD_LENGTH);
        sprintf(sqlcmd,
                "CREATE TABLE IF NOT EXISTS %s("
                "VALUE INTEGER PRIMARY KEY,"
                "COUNT INTEGER);", sql_index_name[i]);
        rc = sqlite3_exec(db, sqlcmd, 0, 0, &errmsg);
        if( rc != SQLITE_OK ){
            VLOG_ERR_RL(&rl, "%s: Can't create table %s.(Error message:%s)", \
                        ns->bridge_name, sql_index_name[i], errmsg);
            goto err_create;
        }
    }

    for(size_t i = 0; i < NS_SQL_TABLE_INDEX_NUM * 2; i += 2)
    {
        memset(sqlcmd, 0, NS_MAX_SQL_CMD_LENGTH);
        sprintf(sqlcmd, "CREATE INDEX %s ON NETSTREAM (%s);", \
                sql_index_name[i], sql_index_name[i + 1]);
        rc = sqlite3_exec(db, sqlcmd, 0, 0, &errmsg);
        if( rc != SQLITE_OK ){
            VLOG_ERR_RL(&rl, "%s: Can't create index(%s) on NETSTREAM (%s).(Error message:%s)", \
                        ns->bridge_name, sql_index_name[i], sql_index_name[i + 1], errmsg);
            goto err_create;
        }
    }

    err_create:
    sqlite3_free(errmsg);
    err_open:
    sqlite3_close(db);
    free(sqlcmd);
    return;
}


static inline void
netstream_db_createque(struct netstream_db_queue *ns_db_q, int maxlength)
{
    if (ns_db_q && ns_db_q->ns_db_node) {
        return;
    }
    ns_db_q->ns_db_node = (struct netstream_db_record *)malloc(sizeof(struct netstream_db_record) * maxlength);
    memset(ns_db_q->ns_db_node, 0, sizeof(struct netstream_db_record) * maxlength);
    ns_db_q->front = 0;
    ns_db_q->rear = 0;
    ns_db_q->maxlength = maxlength;
}

static inline void
netstream_db_destroyque(struct netstream_db_queue *ns_db_q)
{
    if (!ns_db_q) {
        return;
    }
    free(ns_db_q->ns_db_node);
    ns_db_q->ns_db_node = NULL;
}

static inline bool
netstream_db_isfullq(struct netstream_db_queue *ns_db_q)  
{  
    if(ns_db_q->front == (ns_db_q->rear + 1) % ns_db_q->maxlength) {     
        return true;
    } else {
        return false;
    }  
} 
 
static inline bool
netstream_db_isemptyq(struct netstream_db_queue *ns_db_q)
{  
    if(ns_db_q->front == ns_db_q->rear) {                   
        return true;
    } else {
        return false;
    }
}

static inline int
netstream_db_enqueue(struct netstream_db_queue *ns_db_q,struct netstream_db_record *ns_db_rec)  
{  
    if(netstream_db_isfullq(ns_db_q)) {  
        return false; 
    } else {
        memcpy(&(ns_db_q->ns_db_node[ns_db_q->rear]), ns_db_rec, sizeof (struct netstream_db_record));
        ns_db_q->rear = (ns_db_q->rear + 1 ) % ns_db_q->maxlength;
        return true;  
    }      
}  
  
static inline bool
netstream_db_dequeue(struct netstream_db_queue *ns_db_q, struct netstream_db_record *ns_db_record)
{  
    if(netstream_db_isemptyq(ns_db_q)) {  
        return false;  
    } else {
        memcpy(ns_db_record, &ns_db_q->ns_db_node[ns_db_q->front], sizeof(struct netstream_db_record));
        ns_db_q->front = (ns_db_q->front + 1) % ns_db_q->maxlength;  
        return true;  
    }
}

static bool
netstream_write_into_db(sqlite3 *db, struct netstream *ns)
{
    /* sqlite 执行准备 */
    sqlite3_stmt *stmt_main_table;
    sqlite3_stmt *stmt_sub_table[NS_SQL_TABLE_INDEX_NUM][2];
    int rc;
    char *sqlcmd = (char *)malloc(NS_MAX_SQL_CMD_LENGTH);
    bool flag = true;

    memset(sqlcmd, 0, NS_MAX_SQL_CMD_LENGTH);
    sprintf(sqlcmd, "%s", "INSERT INTO NETSTREAM VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);");
    rc = sqlite3_prepare_v2(db, sqlcmd, strlen(sqlcmd), &stmt_main_table, NULL);
    if(rc != SQLITE_OK)
    {
        flag = false;
        goto err;
    }

    for(size_t i = 0; i < NS_SQL_TABLE_INDEX_NUM; i++)
    {
        memset(sqlcmd, 0, NS_MAX_SQL_CMD_LENGTH);
        sprintf(sqlcmd, "INSERT OR IGNORE INTO %s VALUES(?,0);", sql_index_name[i * 2 + 1]);
        rc = sqlite3_prepare(db, sqlcmd, strlen(sqlcmd), &stmt_sub_table[i][0], NULL);
        if(rc != SQLITE_OK)
        {
            flag = false;
            goto err;
        }
        memset(sqlcmd, 0, NS_MAX_SQL_CMD_LENGTH);
        sprintf(sqlcmd, "UPDATE %s SET COUNT = COUNT + 1 WHERE VALUE = ?;", sql_index_name[i * 2 + 1]);  
        rc = sqlite3_prepare(db, sqlcmd, strlen(sqlcmd), &stmt_sub_table[i][1], NULL);
        if(rc != SQLITE_OK)
        {
            flag = false;
            goto err;
        }
    }

    struct netstream_db_record ns_db_record;
    while(netstream_db_dequeue(&ns->ns_db_que, &ns_db_record)){

        sqlite3_reset(stmt_main_table);

        sqlite3_bind_text(stmt_main_table, 1, ns->bridge_name, strlen(ns->bridge_name), NULL);
        sqlite3_bind_int(stmt_main_table, 2, ns_db_record.src_ip);
        sqlite3_bind_int(stmt_main_table, 3, ns_db_record.dst_ip);
        sqlite3_bind_int(stmt_main_table, 4, ns_db_record.src_port);
        sqlite3_bind_int(stmt_main_table, 5, ns_db_record.dst_port);
        sqlite3_bind_int(stmt_main_table, 6, ns_db_record.protocol);
        sqlite3_bind_int(stmt_main_table, 7, ns_db_record.start_time);
        sqlite3_bind_int(stmt_main_table, 8, ns_db_record.end_time);
        sqlite3_bind_int(stmt_main_table, 9, ns_db_record.duration);
        sqlite3_bind_text(stmt_main_table, 10, ns_db_record.src_ip_port, strlen(ns_db_record.src_ip_port), NULL);
        sqlite3_bind_text(stmt_main_table, 11, ns_db_record.dst_ip_port, strlen(ns_db_record.dst_ip_port), NULL);
        sqlite3_bind_text(stmt_main_table, 12, ns_db_record.s_time_read, strlen(ns_db_record.s_time_read), NULL);
        sqlite3_bind_text(stmt_main_table, 13, ns_db_record.e_time_read, strlen(ns_db_record.e_time_read), NULL);
        sqlite3_bind_text(stmt_main_table, 14, ns_db_record.pro_read, strlen(ns_db_record.pro_read), NULL);
        sqlite3_bind_int(stmt_main_table, 15, ns_db_record.input);
        sqlite3_bind_int(stmt_main_table, 16, ns_db_record.output);
        sqlite3_bind_int(stmt_main_table, 17, ns_db_record.packet_count);
        sqlite3_bind_int(stmt_main_table, 18, ns_db_record.byte_count);
        sqlite3_bind_int(stmt_main_table, 19, ns_db_record.ip_tos);
        sqlite3_bind_int(stmt_main_table, 20, ns_db_record.sample_interval);
        sqlite3_bind_int(stmt_main_table, 21, ns_db_record.bytes_per_pkt);
        sqlite3_bind_int(stmt_main_table, 22, ns_db_record.tcp_flags);
        
        rc = sqlite3_step(stmt_main_table);
        if(rc != SQLITE_DONE)
        {
            flag = false;
            goto err;
        }

        for(size_t i = 0; i < NS_SQL_TABLE_INDEX_NUM; i++)
        {
            for(size_t j = 0; j < 2; j++)
            {
                sqlite3_reset(stmt_sub_table[i][j]);
            }
        }

        for(size_t i = 0; i < 2; i++)
        {
            sqlite3_bind_int(stmt_sub_table[0][i], 1, ns_db_record.src_ip);
            sqlite3_bind_int(stmt_sub_table[1][i], 1, ns_db_record.dst_ip);
            sqlite3_bind_int(stmt_sub_table[2][i], 1, ns_db_record.src_port);
            sqlite3_bind_int(stmt_sub_table[3][i], 1, ns_db_record.dst_port);
            sqlite3_bind_int(stmt_sub_table[4][i], 1, ns_db_record.protocol);
            sqlite3_bind_int(stmt_sub_table[5][i], 1, ns_db_record.start_time);
            sqlite3_bind_int(stmt_sub_table[6][i], 1, ns_db_record.start_time);
        }

        for(size_t i = 0; i < NS_SQL_TABLE_INDEX_NUM; i++)
        {
            for(size_t j = 0; j < 2; j++)
            {
                rc = sqlite3_step(stmt_sub_table[i][j]);
                if(rc != SQLITE_DONE)
                {
                    flag = false;
                    goto err;
                }
            }
        }

        memset(&ns_db_record, 0, sizeof ns_db_record);
    }

    err:
    for(size_t i = 0; i < NS_SQL_TABLE_INDEX_NUM; i++)
    {
        for(size_t j = 0; j < 2; j++)
        {
            sqlite3_finalize(stmt_sub_table[i][j]);
        }
    }
    sqlite3_finalize(stmt_main_table);
    free(sqlcmd);
    return flag;
}

static void
netstream_log_path_init(struct netstream *ns)
{
    char ns_log_dir[NS_MAX_PATH_LOG_LENGTH] = {0};

    sprintf(ns_log_dir, "%s/netstream", ovs_pkgdatadir());  /* /usr/local/share/openvswitch */
    
    /* 文件夹不存在时则创建该目录 */
    if(access(ns_log_dir, F_OK) != 0)  
    {  
        if(mkdir(ns_log_dir, NS_LOG_DIR_MODE) != 0)  
        {
            VLOG_ERR_RL(&rl, "Can't create netstream log path(%s)", ns_log_dir);
            ns->log = false;
            return;   
        } 
    }
    strcpy(ns->log_path, ns_log_dir);
    return;
}

void
netstream_flow_update(struct netstream *ns, const struct flow *flow, 
                      ofp_port_t output_iface, const struct dpif_flow_stats *stats)
    OVS_EXCLUDED(mutex)
{
    struct netstream_flow *ns_flow;
    uint32_t n_bytes;
    long long int used;

    /* NetStream only reports on IP packets. */
    if (flow->dl_type != htons(ETH_TYPE_IP)) {
        return;
    }

    ovs_mutex_lock(&mutex);
    ns_flow = netstream_flow_lookup(ns, flow);
    if (!ns_flow) {
        
        if (hmap_count(&ns->flows) >= ns->flow_cache_number) {
            VLOG_ERR_RL(&rl, "The maximum number of streams has been reached.\n");
            goto end;
        } 

        ns_flow = xzalloc(sizeof *ns_flow);
        ns_flow->nw_src = flow->nw_src;
        ns_flow->nw_dst = flow->nw_dst;
        ns_flow->nw_tos = flow->nw_tos;
        ns_flow->nw_proto = flow->nw_proto;
        ns_flow->tp_src = flow->tp_src;
        ns_flow->tp_dst = flow->tp_dst;
        ns_flow->created = stats->used;
        ns_flow->last_expired = stats->used;
        ns_flow->output_iface = output_iface;
        ns_flow->in_port = flow->in_port.ofp_port;
        ns_flow->first_timestamp = ns_flow->last_timestamp = time_wall();
        hmap_insert(&ns->flows, &ns_flow->hmap_node, netstream_flow_hash(flow));
    }

    ns_flow->last_timestamp = time_wall();

    /* 对于TCP连接，当有标志为FIN或RST的报文发送时，表示一次会话结束。当一条已经存在的NetStream流中流过
    一条标志为FIN或RST的报文时，可以立即老化相应的NetStream流，节省内存空间。因此建议在设备上开启由TCP
    连接的FIN和RST报文触发老化的老化方式。 */
    if (ns_flow->nw_proto == NS_TCP && ns_flow->packet_count > 1 &&
        (stats->tcp_flags & (TCP_FIN | TCP_RST))) {
        netstream_expire__(ns, ns_flow);
        hmap_remove(&ns->flows, &ns_flow->hmap_node);
        free(ns_flow);
        goto end;
    }

    if (ns_flow->output_iface != output_iface) {
        netstream_expire__(ns, ns_flow);
        ns_flow->created = stats->used;
        ns_flow->output_iface = output_iface;
    }

    /* 字节数翻转了直接进行老化 */
    n_bytes = ns_flow->byte_count + stats->n_bytes;
    if (n_bytes < ns_flow->byte_count && n_bytes < stats->n_bytes) {
        netstream_expire__(ns, ns_flow);
    }

    ns_flow->byte_count += stats->n_bytes;
    ns_flow->packet_count += stats->n_packets;
    ns_flow->tcp_flags |= stats->tcp_flags;

    used = MAX(ns_flow->used, stats->used);
    if (ns_flow->used != used) {
        ns_flow->used = used;   //更新流上次使用时间
    }

    end:
    ovs_mutex_unlock(&mutex);
}

static struct netstream_flow *
netstream_flow_lookup(const struct netstream *ns, const struct flow *flow)
    OVS_REQUIRES(mutex)
{
    struct netstream_flow *ns_flow;

    HMAP_FOR_EACH_WITH_HASH (ns_flow, hmap_node, netstream_flow_hash(flow),
                             &ns->flows) {
        if (flow->in_port.ofp_port == ns_flow->in_port
            && flow->nw_src == ns_flow->nw_src
            && flow->nw_dst == ns_flow->nw_dst
            && flow->nw_tos == ns_flow->nw_tos
            && flow->nw_proto == ns_flow->nw_proto
            && flow->tp_src == ns_flow->tp_src
            && flow->tp_dst == ns_flow->tp_dst) {
            return ns_flow;
        }
    }
    return NULL;
}

static uint32_t
netstream_flow_hash(const struct flow *flow)
{
    uint32_t hash = 0;

    hash = hash_add(hash, (OVS_FORCE uint32_t) flow->in_port.ofp_port);
    hash = hash_add(hash, ntohl(flow->nw_src));
    hash = hash_add(hash, ntohl(flow->nw_dst));
    hash = hash_add(hash, flow->nw_tos);
    hash = hash_add(hash, flow->nw_proto);
    hash = hash_add(hash, ntohs(flow->tp_src));
    hash = hash_add(hash, ntohs(flow->tp_dst));

    return hash_finish(hash, 28);
}

struct netstream *
netstream_ref(const struct netstream *ns_)
{
    struct netstream *ns = CONST_CAST(struct netstream *, ns_);
    if (ns) {
        ovs_refcount_ref(&ns->ref_cnt);
    }
    return ns;
}

void
netstream_mask_wc(const struct flow *flow, struct flow_wildcards *wc)
{
    if (flow->dl_type != htons(ETH_TYPE_IP)) {
        return;
    }
    memset(&wc->masks.nw_proto, 0xff, sizeof wc->masks.nw_proto);
    memset(&wc->masks.nw_src, 0xff, sizeof wc->masks.nw_src);
    memset(&wc->masks.nw_dst, 0xff, sizeof wc->masks.nw_dst);
    flow_unwildcard_tp_ports(flow, wc);
    wc->masks.nw_tos |= IP_DSCP_MASK;
}

uint32_t
netstream_get_probability(const struct netstream *ns) OVS_EXCLUDED(mutex)
{
    uint32_t probability;
    ovs_mutex_lock(&mutex);
    probability = UINT32_MAX / ns->sample_interval;
    ovs_mutex_unlock(&mutex);
    return probability;
}