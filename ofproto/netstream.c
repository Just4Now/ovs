#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "openvswitch/ofpbuf.h"
#include "netstream.h"
#include "sqlite3.h"
#include "dirs.h"
#include "vlog.h"


VLOG_DEFINE_THIS_MODULE(netstream);

static struct ovs_mutex mutex = OVS_MUTEX_INITIALIZER;
static atomic_count netstream_count = ATOMIC_COUNT_INIT(0);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

const char sql_index_name[] = {
    "SRC_IP_INDEX", "SRC_IP",
    "DST_IP_INDEX", "DST_IP",
    "SRC_PORT_INDEX", "SRC_PORT"
    "DST_PORT_INDEX", "DST_PORT"
    "PROTOCOL_INDEX", "PROTOCOL"
    "START_TIME_INDEX", "START_TIME"
    "END_TIME_INDEX", "END_TIME"
}

struct netstream *
netstream_create(char *bridge_name)
{
    struct netstream *ns = xzalloc(sizeof *ns);

    memset(ns->bridge_name, 0, sizeof(ns->bridge_name));
    memset(ns->log_path, 0, sizeof(ns->log_path));
    memset(ns->ns_db_que, 0, sizeof(ns->ns_db_queue));
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
}

int
netstream_set_options(struct netstream *ns,
                    const struct netstream_options *ns_options)
    OVS_EXCLUDED(mutex)
{
    int error = 0;
    long long int old_timeout;
    bool old_log;

    ovs_mutex_lock(&mutex);
    ns->engine_type = ns_options->engine_type;
    ns->engine_id = ns_options->engine_id;
    ns->add_id_to_iface = ns_options->add_id_to_iface;
    ns->sample_mode = ns_options->sample_mode;
    ns->sample_interval = ns_options->sample_interval;
    ns->flow_cache_number = ns_options->flow_cache_number;
    ns->tcp_flag = ns_options->tcp_flag;
    
    old_log = ns->log;
    ns->log = ns_options->log;
    
    /* 日志功能开关发生了变化 */
    if (ns->log != old_log) {
        if(ns->log)
        {
            netstream_log_path_init(ns);
            if (ns->log) {
                netstream_db_createque(&ns->ns_db_que, ns->flow_cache_number);
            }
        }
        else 
        {
            netstream_db_destroyque(&ns->ns_db_que);   
        }
    }

    collectors_destroy(ns->collectors);
    collectors_create(&ns_options->collectors, -1, &ns->collectors);

    ns->inactive_timeout = ns_options->inactive_timeout * 1000;

    old_timeout = ns->active_timeout;
    ns->active_timeout = ns_options->inactive_timeout * 1000 * 60;
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

    if (now < ns->next_timeout) {
        return;
    }

    ns->next_timeout = now + 1000;

    HMAP_FOR_EACH_SAFE (ns_flow, next, hmap_node, &ns->flows) {
        /* 非活跃流老化 */
        if (now > ns_flow->used + ns->inactive_timeout) {
            netstream_expire__(ns, ns_flow, INACTIVE_FLOW);
            /* 将超时的非活跃流移除 */
            hmap_remove(&ns->flows, &ns_flow->hmap_node);
            free(ns_flow);
            continue;
        }
        /* 活跃流老化 */
        if (now > ns_flow->last_expired + ns->active_timeout) {
            memset(ns_db_record, 0, sizeof ns_db_record);
            netstream_expire__(ns, ns_flow, ACTIVE_FLOW);
        }
    }

    /* Netstream日志功能开启后会将流记录写入本地数据库文件中 */
    if (ns->log) {
        char db_file_path[NS_MAX_DB_PATH_LENGTH];
        sqlite3* db;
        char *errmsg = NULL;
        int rc;
        char *sqlcmd;

        sprintf(db_file_path, "%s/%s-%s", ns->log_path, ns->bridge_name, NS_DB_FILE_NAME);
        rc = sqlite3_open(db_file_path, &db);
        if (rc != SQLITE_OK) {
            VLOG_ERR_RL(&rl, "Can't open netstream log database(%s), please check "
                         "if it is bad.(Error message:%s)", db_file_path，sqlite3_errmsg(db));
            goto err_open;
        }else{
            rc = sqlite3_exec(db, "PRRAGMA synchronous = OFF", 0, 0, &errmsg);  //关闭同步
            if (rc != SQLITE_OK) {  //关闭同步失败
                VLOG_ERR_RL(&rl, "Turn off synchronous failed.(Error message:%s)", db_file_path，errmsg);
                goto err_excute;
            }
            rc = sqlite3_exec(db, "BEGIN", 0, 0, &errmsg); //开启事务
            if (rc != SQLITE_OK) {  //开启事务失败
                VLOG_ERR_RL(&rl, "Excuting begin failed.(Error message:%s)", db_file_path，errmsg);
                goto err_excute;
            }
        }

        if(netstream_write_into_db(db, ns))
        {
            rc = sqlite3_exec(db, "COMMIT", 0, 0, &errmsg); //提交事务
            if (rc != SQLITE_OK) {  //提交事务失败
                VLOG_ERR_RL(&rl, "Excuting commit failed.(Error message:%s)", db_file_path，errmsg);
                goto err_excute;
            }
        }else
        {
            rc = sqlite3_exec(db, "ROLLBACK", 0, 0, &errmsg); //提交事务
            if (rc != SQLITE_OK) {  //提交事务失败
                VLOG_ERR_RL(&rl, "Excuting rollback failed.(Error message:%s)", db_file_path，errmsg);
                goto err_excute;
            }
        }

        err_excute:
        sqlite3_free(zErrMsg);
        err_open:
        sqlite3_close(db);
    }
}

static void
netstream_expire__(struct netstream *ns, struct netstream_flow *ns_flow, enum FLOW_TYPE flow_type)
    OVS_REQUIRES(mutex)
{
    uint64_t pkts, bytes;

    pkts = ns_flow->packet_count;

    if (flow_type == ACTIVE_FLOW) {
        ns_flow->last_expired += ns->active_timeout;    //更新上一次超时的时间
    }

    if (pkts == 0) {
        return;
    }

    /* 生成netstream record */        
    gen_netstream_rec(ns, ns_flow, ACTIVE_FLOW);

    /* Update flow tracking data. */
    ns_flow->packet_count = 0;
    ns_flow->byte_count = 0;
    ns_flow->tcp_flags = 0;
}

static void
gen_netstream_rec(struct netstream *ns, struct netstream_flow *ns_flow, enum FLOW_TYPE flow_type)
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
        ns_hdr->sampling_interval = htonl(ns->sample_interval);
    }

    ns_hdr = ns->packet.data;
    ns_hdr->count = htons(ntohs(ns_hdr->count) + 1);
    ns_hdr->flow_seq = htonl(ns->netstream_cnt++);

    ns_rec = ofpbuf_put_zeros(&ns->packet, sizeof *ns_rec);
    ns_rec->src_addr = htonl(ns_flow->nw_src);
    ns_rec->dst_addr = htonl(ns_flow->nw_dst);
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
        time_t s_time, e_time;

        memset(ns_db_record, 0, sizeof(netstream_db_record));
        memset(s_tm, 0, sizeof(s_tm));
        memset(e_tm, 0, sizeof(e_tm));

        ns_db_record.src_ip = ns_rec->src_addr;
        ns_db_record.dst_ip = ns_rec->dst_addr;
        ns_db_record.src_port = ns_rec->src_port;
        ns_db_record.dst_port = ns_rec->dst_port;
        ns_db_record.input = ns_rec->input;
        ns_db_record.output = ns_rec->output;
        ns_db_record.start_time = ns_flow->created;
        ns_db_record.end_time = ns_flow->used;
        ns_db_record.packet_count = ns_rec->packet_count;
        ns_db_record.byte_count = ns_rec->byte_count;
        ns_db_record.duration = ns_db_record.end_time - ns_db_record.start_time;
        ns_db_record.protocol = ns_rec->ip_proto;
        ns_db_record.ip_tos = ns_rec->ip_tos;
        ns_db_record.flow_type = (uint8_t)flow_type;

        if (ns_db_record.protocol == NS_TCP || ns_db_record.protocol == NS_UDP) {
            struct in_addr addr;
            addr.s_addr = ns_record.src_ip;
            sprintf(ns_db_record.src_ip_port, "%s:%u", inet_ntoa(addr), ns_db_record.src_port);
            addr.s_addr = ns_record.dst_ip;
            sprintf(ns_db_record.dst_ip_port, "%s:%u", inet_ntoa(addr), ns_db_record.dst_port);
        }else
        {
            struct in_addr addr;
            addr.s_addr = ns_record.src_ip;
            sprintf(ns_db_record.src_ip_port, "%s", inet_ntoa(addr);
            addr.s_addr = ns_record.dst_ip;
            sprintf(ns_db_record.dst_ip_port, "%s", inet_ntoa(addr);
        }

        localtime_r(&s_time, &s_tm);
        localtime_r(&e_time, &e_tm);
        strftime(s_time_read, NS_MAX_STRING_READABLE, "%F %T", &s_tm);
        strftime(e_time_read, NS_MAX_STRING_READABLE, "%F %T", &e_tm);

        if (!netstream_db_enqueue(ns->ns_db_que, &ns_db_record))
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
    OVS_REQUIRES(mutex)
{
    char db_file_path[NS_MAX_DB_PATH_LENGTH];
    sqlite3* db;
    char *errmsg = NULL;
    int rc;
    char *sqlcmd = (char *)malloc(NS_MAX_SQL_CML_LENGTH);

    sprintf(db_file_path, "%s/%s-%s", ns->log_path, ns->bridge_name, NS_DB_FILE_NAME);
    
    rc = sqlite3_open(db_file_path, &db);
    if (rc != SQLITE_OK) {
        VLOG_ERR("Can't open netstream log database(%s), please" 
                 "check if it is bad.(Error message:%s)", db_file_path, sqlite3_errmsg(db);
        goto err_open;
    }

    memset(sqlcmd, 0, sizeof sqlcmd);
    sprintf(sqlcmd, \
            "CREATE TABLE IF NOT EXISTS NESTREAM("
            "BRIDEG_NAME   CHAR(16),"
            "SRC_IP        INTEGER,"
            "DST_IP        INTEGER,"
            "SRC_PORT      INTEGER,"
            "DST_PORT      INTEGER,"
            "PROTOCOL      INTEGER,"
            "START_TIME    INTEGER,"
            "END_TIME      INTEGER,"
            "DURATION      INTEGER,"
            "SRC_IP_PORT   CHAR(32),"
            "DST_IP_PORT   CHAR(32),"
            "S_TIME_READ   CHAR(32)"
            "E_TIME_READ   CHAR(32)"
            "INPUT         INTEGER,"
            "OUTPUT        INTEGER,"
            "PACKET_COUNT  INTEGER,"
            "BYTE_COUNT    INTEGER,"
            "TOS           INTEGER,"
            "FLOW_TYPE     INTEGER);");
    rc = sqlite3_exec(db, sqlcmd, 0, 0, &errmsg);
    if( rc != SQLITE_OK ){
        VLOG_ERR("Can't create main table netstream in %s."
                 "(Error message:%s)", db_file_path, zErrMsg);
        goto err_create;
    }

    for(size_t i = 0; i < NS_SQL_TABLE_INDEX_NUM; i++)
    {
        memset(sqlcmd, 0, sizeof sqlcmd);
        sprintf(sqlcmd, \ 
                "CREATE TABLE IF NOT EXISTS %s("
                "VALUE INTEGER PRIMARY KEY,"
                "COUNT INTEGER);", sql_index_name[i + 1]);
        rc = sqlite3_exec(db, sqlcmd, 0, 0, &errmsg);
        if( rc != SQLITE_OK ){
            VLOG_ERR("%s:Can't create subtable (%s).(Error message:%s)", \
                     sql_index_name[i], db_file_path, zErrMsg);
            goto err_create;
        }
    }

    for(size_t i = 0; i < NS_SQL_TABLE_INDEX_NUM; i++)
    {
        memset(sqlcmd, 0, sizeof sqlcmd);
        sprintf(sqlcmd, "CREATE INDEX %s IF NOT EXISTS ON NETSTREAM (%s);", \
                sql_index_name[i], sql_index_name[i + 1]);
        rc = sqlite3_exec(db, sqlcmd, 0, 0, &errmsg);
        if( rc != SQLITE_OK ){
            VLOG_ERR("%s:Can't create index(%s) on netstream (%s).(Error message:%s)", \
                     sql_index_name[i], db_file_path, zErrMsg);
            goto err_create;
        }
    }

    err_create:
    sqlite3_free(zErrMsg);
    err_open:
    sqlite3_close(db);
    free(sqlcmd);
    return;
}

static inline void
netstream_db_createque(netstream_db_queue *ns_db_q, int maxlength)
{
    ns_db_q->ns_db_node = (netstream_db_record *)malloc(sizeof(netstream_db_record) * maxlength);
    memset(ns_db_q, 0, sizeof(netstream_db_record) * maxlength);
    ns_db_q->front = 0;
    ns_db_q->rear = 0;
    ns_db_q->maxlength = maxlength;
}

static inline void
netstream_db_destroyque(netstream_db_queue *ns_db_q)
{
    free(ns_db_q->ns_db_node)
    ns_db_q->ns_db_node = NULL;
}

static inline bool
netstream_db_isfullq(netstream_db_queue *ns_db_q)  
{  
    if(ns_db_q->front == (ns_db_q->rear + 1) % ns_db_q->maxsize) {     
        return true;
    } else {
        return false;
    }  
} 
 
static inline bool
netstream_db_isemptyq(netstream_db_queue *ns_db_q)
{  
    if(ns_db_q->front == ns_db_q->rear) {                   
        return true;
    } else {
        return false;
    }
}  

static inline int
netstream_db_enqueue(netstream_db_queue *ns_db_q,struct netstream_db_record *ns_db_rec)  
{  
    if(netstream_db_isfullq(ns_db_q)) {  
        return false; 
    } else {
        memcpy(&(ns_db_q->data[ns_db_q->rear]), ns_db_rec, sizeof netstream_db_record);
        ns_db_q->rear = (ns_db_q->rear + 1 ) % Q->maxsize;
        return true;  
    }      
}  
  
static inline bool
netstream_db_dequeue(struct netstream_db_queue *ns_db_q, struct netstream_db_record *ns_db_record)
{  
    if(netstream_db_isemptyq(ns_db_q)) {  
        return false;  
    } else {
        memcpy(ns_db_record, &ns_db_q->ns_db_node[front], sizeof(netstream_db_record));
        ns_db_q->front = (ns_db_q->front + 1) % ns_db_q->maxsize;  
        return true;  
    }
}

static bool
netstream_write_into_db(sqlite3 *db, struct netstream *ns)
{
    /* sqlite 执行准备 */
    sqlite3_stmt *stmt_main_table;
    sqlite3_stmt *stmt_sub_table[NS_SQL_TABLE_INDEX_NUM];
    int rc;
    char *sqlcmd = (char *)malloc(NS_MAX_SQL_CMD_LENGTH);

    memset(sqlcmd, 0, sizeof sqlcmd);
    sprintf(sql, "%s", "INSERT INTO NETSTRTEAM VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);");
    rc = sqlite3_prepare(db, sqlcmd, strlen(sqlcmd), &stmt_main_table, 0);
    if(rc != SQLITE_OK)
    {
        goto err_main;
    }

    for(size_t i = 0; i < NS_SQL_TABLE_INDEX_NUM; i++)
    {
        memset(sqlcmd, 0, sizeof sqlcmd);
        /* 如果在INSERT语句末尾指定了ON DUPLICATE KEY UPDATE，
           如果插入行后会导致在一个UNIQUE索引或PRIMARY KEY中出现重复值，
           则执行UPDATE；如果不会导致唯一值列重复的问题，则插入新行。 */
        sprintf(sql, "INSERT INTO %s (VALUE,COUNT) VALUES(?,1) "
                "ON DUPLICATE KEY UPDATE COUNT=COUNT+1;", sql_index_name[i]);
        rc = sqlite3_prepare(db, sqlcmd, strlen(sqlcmd), &stmt_sub_table[i], 0);
        if(rc != SQLITE_OK)
        {
            goto err_sub;
        }
    }

    struct netstream_db_record ns_db_record;
    while(netstream_db_dequeue(ns->ns_db_que, &ns_db_record){
        sqlite3_reset(stmt_main_table);
        sqlite3_bind_text(stmt_main_table, 1, ns->bridge_name, strlen(ns->bridge_name), NULL);
        sqlite3_bind_int(stmt_main_table, 2, ns_db_record->src_ip);
        sqlite3_bind_int(stmt_main_table, 3, ns_db_record->dst_ip);
        sqlite3_bind_int(stmt_main_table, 4, ns_db_record->src_port);
        sqlite3_bind_int(stmt_main_table, 5, ns_db_record->dst_port);
        sqlite3_bind_int(stmt_main_table, 6, ns_db_record->protocol);
        sqlite3_bind_int(stmt_main_table, 7, ns_db_record->start_time);
        sqlite3_bind_int(stmt_main_table, 8, ns_db_record->end_time);
        sqlite3_bind_int(stmt_main_table, 9, ns_db_record->duration);
        sqlite3_bind_text(stmt_main_table, 10, ns_db_record->src_ip_port, strlen(ns_db_record->src_ip_port), NULL);
        sqlite3_bind_text(stmt_main_table, 11, ns_db_record->dst_ip_port, strlen(ns_db_record->dst_ip_port), NULL);
        sqlite3_bind_text(stmt_main_table, 12, ns_db_record->s_time_read, strlen(ns_db_record->s_time_read), NULL);
        sqlite3_bind_text(stmt_main_table, 13, ns_db_record->e_time_read, strlen(ns_db_record->e_time_read), NULL);
        sqlite3_bind_int(stmt_main_table, 14, ns_db_record->input);
        sqlite3_bind_int(stmt_main_table, 15, ns_db_record->output);
        sqlite3_bind_int(stmt_main_table, 16, ns_db_record->packet_count);
        sqlite3_bind_int(stmt_main_table, 17, ns_db_record->byte_count);
        sqlite3_bind_int(stmt_main_table, 18, ns_db_record->ip_tos);
        sqlite3_bind_int(stmt_main_table, 19, ns_db_record->flow_type);
        rc = sqlite3_step(stmt_main_table);
        if(rc != SQLITE_OK)
        {
            goto err_main;
        }

        sqlite3_bind_int(stmt_sub_table[0], 1, ns_db_record->src_ip);
        sqlite3_bind_int(stmt_sub_table[1], 1, ns_db_record->dst_ip);
        sqlite3_bind_int(stmt_sub_table[2], 1, ns_db_record->src_port);
        sqlite3_bind_int(stmt_sub_table[3], 1, ns_db_record->dst_port);
        sqlite3_bind_int(stmt_sub_table[4], 1, ns_db_record->protocol);
        sqlite3_bind_int(stmt_sub_table[5], 1, ns_db_record->start_time);
        sqlite3_bind_int(stmt_sub_table[6], 1, ns_db_record->start_time);
        for(size_t i = 0; i < NS_SQL_TABLE_INDEX_NUM; i++)
        {
            rc = sqlite3_step(stmt_sub_table[i]);
            if(rc != SQLITE_OK)
            {
                goto err_sub;
            }
        }

        memset(&ns_db_record, 0, sizeof ns_db_record);
    }

    sqlite3_finalize(stmt_main_table);
    return true;

    err_main:
    sqlite3_finalize(stmt_main_table);
    return false;

    err_sub:
    sqlite3_finalize(stmt_main_table);
    for(size_t i = 0; i < NS_SQL_TABLE_INDEX_NUM; i++)
    {
        sqlite3_finalize(stmt_sub_table[i]);
    }
    free(sqlcmd);
    return false;
}

void
netstream_log_path_init(struct netstream *ns)
{
    char ns_log_dir[NS_MAX_PATH_LOG_LENGTH] = {0}; 
    sprintf(ns_log_dir, "%s/NetStream", ovs_pkgdatadir());  /* /usr/local/share/openvswitch */
    
    /* 文件夹不存在时则创建该目录 */
    if(access(ns_log_dir, F_OK) != 0)  
    {  
        if(mkdir(ns_log_dir, NS_LOG_DIR_MODE) != 0)  
        {
            VLOG_ERR("%s:Can't create netstream log path(%s)", ns_log_dir);
            ns->log = false;
            return;   
        } 
    }
    strcpy(ns->log_path, ns_log_dir);
    return;
}