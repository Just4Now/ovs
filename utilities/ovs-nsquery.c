#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <time.h>
#include <dirent.h>
#include <unistd.h>
#include <termios.h>

#include "sqlite3.h"
#include "vlog.h"

#define NS_MAX_QUERY_CONDITION 8
#define NS_MAX_INDEX_LENGTH 8
#define NS_MAX_ARG_LENGTH 24
#define NS_MAX_BRIDGE_NAME_LENGTH 16
#define NS_MAX_PATH_LOG_LENGTH 48
#define NS_MAX_QUERY_ROW 72
#define NS_MAX_VALUE_LENGTH 32
#define NS_MAX_SQL_CMD_LENGTH 512
#define NS_DISPLAY_MORE_LENGTH 24
#define NS_DISPLAY_MORE_LENGTH_VERBOSE 6

#define NS_ICMP 1
#define NS_TCP 6
#define NS_UDP 17


#define MAX(a,b)  (((a)>(b))?(a):(b))

struct query_single_cond
{
    bool is_specified;
    char value[NS_MAX_VALUE_LENGTH];
};

struct query_conditions
{
    bool verbose;
    bool is_specified;
    bool cond_br_only;
    struct query_single_cond q_s_cond[NS_MAX_QUERY_CONDITION];
};

const char *condition_name = {
    "BRI_NAME",
    "SRC_IP",
    "DST_IP",
    "SRC_IP",
    "DST_IP",
    "PROTOCOL",
    "START_TIME",
    "END_TIME"
}

const char *index_name = {
    "",
    "SRC_IP_INDEX",
    "DST_IP_INDEX",
    "SRC_IP_INDEX",
    "DST_IP_INDEX",
    "PROTOCOL_INDEX",
    "START_TIME_INDEX",
    "END_TIME_INDEX"
}

enum OPTION{
    BR_NAME,
    SRC_IP,
    DST_IP,
    SRC_PORT,
    DST_PORT,
    PROTOCOL,
    START_TIME,
    END_TIME,
    HELP,
    VERBOSE
};

static void nsquery_usage();
static bool nsquery_check_ip(char *, struct in_addr *);
static bool ns_str2uint16(char *, uint16_t *);
static bool ns_str2uint8(char *, uint8_t *);
static bool ns_str2timestamp(char *, uint64_t *);
static bool ns_check_time(struct query_conditions *);
static void ns_query_database(struct query_conditions *);
static void parser_commands(int , char **, struct query_conditions *);

char* const short_options = "";

static const struct option long_options[] = {
    { "help", no_argument, NULL,  HELP},
    { "verbose", no_argument, NULL,  VERBOSE},
    { "br-name", required_argument, NULL,  BR_NAME},
    { "src-ip", required_argument, NULL,  SRC_IP},
    { "dst-ip", required_argument, NULL,  DST_IP},
    { "src-port", required_argument, NULL,  SRC_PORT},
    { "dst-port", required_argument, NULL,  DST_PORT},
    { "protocol", required_argument, NULL,  PROTOCOL},
    { "start-time", required_argument, NULL,  START_TIME},
    { "end-time", required_argument, NULL,  END_TIME},
    { 0, 0, 0, 0 }
};

int main(int argc, char **argv)
{
    struct query_conditions q_c;
    memset(&q_c, 0, sizeof q_c);
    
    parser_commands(argc, argv, &q_c);

    ns_query_database(&q_c);

    return 0;
}

static void
nsquery_usage()
{
    printf("ovs-nsquery: Open vSwitch NetStream log database query tool\n"
           "usage: ovs-nsquery options [ARG...]\n"
           "\nThis tool is just used to query NetStream log database, and you can "
           "specify multiple conditions while querying. The conditions are described below:\n"
           "\n  br-name [BRIDGE NAME]\n"
           "    Query the NetStream log database by specifying the bridge name\n"
           "\n  src-ip [SOURCE IP ADDRESSS]\n"
           "    Query the NetStream log database by specifying the source ip address\n"
           "\n  dst-ip [DESTINATION IP ADDRESSS]\n"
           "    Query the NetStream log database by specifying the destination ip address\n"
           "\n  src-port [SOURCE PORT]\n"
           "    Query the NetStream log database by specifying the source TCP/UDP port\n"
           "    Notes:this condition is only meaningful to TCP and UDP streams.\n"
           "\n  dst-port [DESTINATION PORT]\n"
           "    Query the NetStream log database by specifying the destination TCP/UDP port\n"
           "    Notes:this condition is only meaningful to TCP and UDP streams.\n"
           "\n  protocol [IP PROTOCOL]\n"
           "    Query the NetStream log database by specifying the ip protocol\n"
           "    Notes: ICMP -- 1    TCP -- 6    UDP -- 17\n"
           "\n  start-time [START TIME]\n"
           "    Query the NetStream log database by specifying the start time\n"
           "    Format:Y-M-D H:M:S,such as \"2018-01-01 00:00:00\"\n"
           "\n  end-time [END TIME]\n"
           "    Query the NetStream log database by specifying the end time\n"
           "    Format:Y-M-D H:M:S,such as \"2018-01-01 24:00:00\"\n"
           "    Notes:if you specify the start-time condition and the end-time condition at"
           "    the same time, Keep in mind that the start-time should be earlier than the "
           "    end time.\n"
           "\n  Of course,it's ok to specify nothing and specify multiple conditions.There "
           "are some query examples below:\n"
           "    # ovs-nsquery\n"
           "    # ovs-nsquery --br-name=s1\n"
           "    # ovs-nsquery --src-ip=10.0.0.1 --dst-ip=20.0.0.1 --src-port=12 --dst-port=63\n"
           "    # ovs-nsquery --start-time=\"2018-01-01 00:00:00\" --end-time=\"2018-01-01 24:00:00\"\n"
           "    # ovs-nsquery --protocol=6 --verbose\n");     
    printf("\nOther options:\n"
           "  --help                  display this help message\n"
           "  --verbose               display the streams in more details");
}

static void parser_commands(int argc, char **argv, struct query_conditions *q_c)
{
    char c;
    uint16_t port;
    uint8_t protocol;
    uint64_t timestamp;
    int longindex = NS_MAX_QUERY_CONDITION + 2;

    do{
        c = getopt_long (argc, argv, short_options, long_options, &longindex);

        if (longindex > NS_MAX_QUERY_CONDITION) {
            printf("unknown command; use --help for help\n");
            exit(EXIT_FAILURE);
        }
        
        if (c == -1) {
            break;
        }
         
        switch (c)
        {
            struct in_addr addr;
            case HELP:
                if (argc == 2) {
                    nsquery_usage();
                    exit(EXIT_SUCCESS);
                }else
                {
                    printf("if you want to konw the usage of ovs-nsquery, "
                            "please just use \"ovs-nsquery -h\" or \"ovs-nsqurey --help\"\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case VERBOSE:
                q_c->verbose = true;
                break;
            case BR_NAME:
                q_c->q_s_cond[BR_NAME].is_specified = true;
                q_c->cond_br_only = true;
                strcpy(q_c->q_s_cond[BR_NAME].value, optarg);
                break;
            case SRC_IP:
                if (nsquery_check_ip(optarg, &addr)) {
                    q_c->q_s_cond[SRC_IP].is_specified = true;
                    q_c->cond_br_only = false;
                    sprintf(q_c->q_s_cond[SRC_IP].value, "%u", (uint32_t)addr.s_addr);
                }else
                {
                    printf("Invalid source ip addresss:%s.\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case DST_IP:
                if (nsquery_check_ip(optarg, &addr)) {
                    q_c->q_s_cond[DST_IP].is_specified = true;
                    q_c->cond_br_only = false;
                    sprintf(q_c->q_s_cond[DST_IP].value, "%u", (uint32_t)addr.s_addr);
                }else
                {
                    printf("Invalid destination ip addresss:%s.\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case SRC_PORT:
                if (ns_str2uint16(optarg, &port)) {
                    if (port >=0 && port <= 65535) {
                        q_c->q_s_cond[SRC_PORT].is_specified = true;
                        q_c->cond_br_only = false;
                        sprintf(q_c->q_s_cond[SRC_PORT].value, "%u", port);
                    }else
                    {
                        printf("The port number(%u) is out of range.(0 to 65535 is valid)\n", port);
                        exit(EXIT_FAILURE);
                    }
                }else
                {
                    printf("Invalid port number(%s).\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case DST_PORT:
                if (ns_str2uint16(optarg, &port)) {
                    if (port >=0 && port <= 65535) {
                        q_c->q_s_cond[DST_PORT].is_specified = true;
                        q_c->cond_br_only = false;
                        sprintf(q_c->q_s_cond[DST_PORT].value, "%u", port);
                    }else
                    {
                        printf("The port number(%u) is out of range.(0 to 65535 is valid)\n", port);
                        exit(EXIT_FAILURE);
                    }
                }else
                {
                    printf("Invalid port number(%s).\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case PROTOCOL:
                if (ns_str2uint8(optarg, &protocol)) {
                    if (protocol >=0 && protocol <= 255) {
                        q_c->q_s_cond[PROTOCOL].is_specified = true;
                        q_c->cond_br_only = false;
                        sprintf(q_c->q_s_cond[SRC_PORT].value, "%u", protocol);
                    }else
                    {
                        printf("The protocol number(%u) is out of range.(0 to 255 is valid)\n", protocol);
                        exit(EXIT_FAILURE);
                    }
                }else
                {
                    printf("Invalid protocol number(%s).\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case START_TIME:
                if(ns_str2timestamp(optarg, &timestamp))
                {
                    q_c->q_s_cond[START_TIME].is_specified = true;
                    q_c->cond_br_only = false;
                    sprintf(q_c->q_s_cond[START_TIME].value, "%u", timestamp);
                }else
                {
                    printf("Invalid start time(%s).\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case END_TIME:
                if(ns_str2timestamp(optarg, &timestamp))
                {
                    q_c->q_s_cond[END_TIME].is_specified = true;
                    q_c->cond_br_only = false;
                    sprintf(q_c->q_s_cond[END_TIME].value, "%u", timestamp);
                }else
                {
                    printf("Invalid end time(%s).\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            default:
                exit(EXIT_FAILURE);
                break;
        }
    } while(true); 


    if (!ns_check_time(q_c)) {
        printf("The start time must be earlier than the end time.\n");
        exit(EXIT_FAILURE);
    }
}

static bool
nsquery_check_ip(char *ip, struct in_addr *addr)
{
    if(inet_aton(ip, addr) != 0)
	{
		return true;
	}
	return false;
}

static bool
ns_str2uint16(char *str_port, uint16_t *port)
{
    int i = 0;
    while(str_port[i] != '\0'){
        if (str_port[i] >= '0' && str_port[i] <= '9') {
            *port = *port * 10 + str_port[i] - '0';
        }else
        {
            return false;
        }
        ++i;
    }
    return true;
}

static bool
ns_str2uint8(char *str_protocpl, uint8_t *protocol)
{
    int i = 0;
    while(str_protocpl[i] != '\0'){
        if (str_protocpl[i] >= '0' && str_protocpl[i] <= '9') {
            *protocol = *protocol * 10 + str_protocpl[i] - '0';
        }else
        {
            return false;
        }
        ++i;
    }
    return true;
}

static bool
ns_str2timestamp(char *str_timestamp, uint64_t *timestamp)
{
    struct tm tm_tmp;
    memset(&tm_tmp, 0, sizeof tm_tmp);
    if(sscanf(optarg, "%d-%d-%d %d:%d:%d", &tm_tmp.tm_year, &tm_tmp.tm_mon, \
              &tm_tmp.tm_mday, &tm_tmp.tm_hour, &tm_tmp.tm_min, &tm_tmp.tm_sec) == 6){
        *timestamp = (uint64_t)mktime(&tm_tmp);
        return true;
    }
    return false;
}

static bool
ns_check_time(struct query_conditions *q_c)
{
    if (q_c->q_s_cond[].is_specified[START_TIME] && q_c->q_s_cond[].is_specified[END_TIME]) {
        if (q_c->q_s_cond[].start_time > q_c->q_s_cond[].end_time) {
            return false;
        }
        return true;
    }
    return true; 
}

static void
ns_query_database(struct query_conditions *q_c)
{
    char ns_log_dir_path[NS_MAX_PATH_LOG_LENGTH] = {0}; 
    char ns_log_file_path[NS_MAX_PATH_LOG_LENGTH] = {0};
    char *sqlcmd = (char *)malloc(NS_MAX_SQL_CMD_LENGTH);
    bool q_s_cond[].is_specified = false;
    sqlite3 *db;
    int n_stable = 0;

    DIR *ns_dir;   //描述一个打开的文件夹
    struct dirent *ns_ptr;

    memset(sqlcmd, 0, NS_MAX_SQL_CMD_LENGTH);
    
    sprintf(ns_log_dir_path, "%s/NetStream", ovs_pkgdatadir());  /* /usr/local/share/openvswitch */

    if ((ns_dir = opendir(ns_log_dir_path)) == NULL)
    {
        printf("Open directory(%s) error\n", ns_log_dir_path);
        exit(EXIT_FAILURE);
    }

    if (q_c->verbose) {
        n_stable += sprintf(sqlcmd, "SELECT BR_NAME,PROTOCOL,DURATION,SRC_IP_PORT,DST_IP_PORT,"
                "S_TIME_READ,E_TIME_READ,INPUT,OUTPUT,PACKET_COUNT,BYTE_COUNT,"
                "TOS,SAMPLE_INT,BYTES_PER_PKT,FLOW_TYPE FROM NETSTREAM ");
    }else
    {
        n_stable += sprintf(sqlcmd, "SELECT BR_NAME,PROTOCOL,SRC_IP_PORT,DST_IP_PORT,"
                "INPUT,OUTPUT,PACKET_COUNT FROM NETSTREAM ");
    }

    for(size_t i = 0; i < NS_MAX_QUERY_CONDITION; i++)
    {
        if (q_c.q_s_cond[i].is_specified) {
            q_c.is_specified = true;
            break;
        }
    }

    while ((ns_ptr = readdir(ns_dir)) != NULL)
    {
        int n = n_stable;
        if(strstr(ns_ptr->d_name, "-netstream.db") != NULL){
            sprintf(ns_log_file_path, "%s/%s", ns_log_dir_path, ns_ptr->d_name);
            rc = sqlite3_open(ns_log_file_path, &db);
            if (rc != SQLITE_OK) {
                VLOG_ERR("Can't open netstream log database(%s), please" 
                         "check if it is bad.(Error message:%s)", \
                         ns_log_file_path, sqlite3_errmsg(db);
                sqlite3_close(db);
                continue;
            }else
            {   
                if (q_c.is_specified) {
                    /* 如果查询条件只有bridge name将不会查找最佳索引，因为没有为BRI_NAME设置索引 */
                    if (!q_c.cond_br_only) {
                        char best_index[NS_MAX_INDEX_LENGTH];
                        if(ns_query_find_best_index(db, q_c, best_index))
                        {
                            n += sprintf(sqlcmd + n, "INDEXED BY %s ", best_index);
                        }else
                        {
                            continue;
                        }
                        
                    }
                    bool first_flag = true;
                    for(size_t i = 0; i < NS_MAX_QUERY_CONDITION; i++)
                    {
                        if (q_c->q_s_cond[i].is_specified) {
                            if (first_flag) {
                                strcat(sqlcmd, "WHERE ");
                            }else
                            {
                                strcat(sqlcmd, " AND ");
                                first_flag = false;
                            }
                            strcat(sqlcmd, condition_name[i]);
                            /* 找包含于输入起始、终止时间之间的流 */
                            if (i == START_TIME) {
                                strcat(sqlcmd, " >= ");
                            }else if (i == END_TIME)
                            {
                                strcat(sqlcmd, " <= ");
                            }else
                            {
                                strcat(sqlcmd, " = ");
                            }
                            strcat(sqlcmd, q_c->q_s_cond[i].value);
                        }                       
                    }
                }   
                ns_query_get_table(db, sqlcmd, q_c->verbose);
            }    
        }else
        {
            continue;
        }    
    }
    closedir(ns_dir);
    free(sqlcmd);
}

/* 查找辅助表以count值越少越好为标准 */
static bool
ns_query_find_best_index(sqlite3 *db, struct query_conditions *q_c, char *best_index)
{
    int rc;
    int n_row;
    int n_column;
    char *err_msg;
    char **result;
    char *sqlcmd = (char *)malloc(NS_MAX_SQL_CMD_LENGTH);
    size_t best_i = 0
    uint64_t count = 0;
    uint64_t best_count = INT64_MAX;

    memset(index, 0, NS_MAX_INDEX_LENGTH);

    for(size_t i = 1; i < NS_MAX_QUERY_CONDITION; i++)
    {
        if (q_c->q_s_cond[i].is_specified) {
            int n = 0;
            memset(sqlcmd, 0, NS_MAX_SQL_CMD_LENGTH);
            n += sprintf(sqlcmd, "SELECT COUNT FROM %s WHERE VALUE ", condition_name[i]);
            /* 找包含于输入起始、终止时间之间的流 */
            if (i == START_TIME) {
                strcat(sqlcmd, " >= ");
            }else if (i == END_TIME)
            {
                strcat(sqlcmd, " <= ");
            }else
            {
                strcat(sqlcmd, " = ");
            }
            n += sprintf(sqlcmd, "%s;", q_c->q_s_cond[i].value);

            rc = sqlite3_get_table(db, sqlcmd, &result, &n_row, &n_column, &err_msg);
            if (rc != SQLITE_OK) {
                VLOG_ERR("Find best index error(Error message:%s)." ,errmsg);
                free(sqlcmd);
                sqlite3_free(errmsg);
                return false;
            }else
            {
                if (n_row == 0) {
                    best_i = i;
                    break;
                }
                
                sscanf(result[1], "%u", &count);
                
                if (count < bestcount) {
                    bestcount = count;
                    best_i = i;
                }
                
            }
        }
    }
    strcpy(best_index, index_name[best_i]);
    sqlite3_free_table(result);
    free(sqlcmd);
    return true;
}

static void
ns_query_get_table(sqlite3 *db, char *sqlcmd, bool verbose)
{
    int rc;
    int n_row;
    int n_column;
    char *err_msg;
    char **result;
    int query_offset = 0;
    int first_flag = true;
    char *sqlcmd_tmp = (char *)malloc(NS_MAX_SQL_CMD_LENGTH); 
    struct termios new_setting,init_setting;
   
    if (tcgetattr(0, &init_setting) != 0)
    {
        VLOG_ERR("Cannot get the attribution of the terminal.");
        goto quit;
    }
    memcpy(&new_setting, &init_setting, sizeof(struct termios));

    new_setting.c_lflag &= ~(ICANON | ECHO);

    if (tcsetattr(0, TCSANOW, &new_setting) != 0)
    {
        VLOG_ERR("Cannot set the attribution of the terminal.");
        goto quit;
    }

    printf("Bri-name Protocol SrcIP(Port)       DstIP(Port)       Input Output Pkts\n");
    printf("------   -------- ----------------- ----------------- ----  ----   --------\n");

    do
    {
        memset(sqlcmd_tmp, 0, NS_MAX_SQL_CMD_LENGTH);
        /* 加入limit offset限制 */
        sprintf("%s LIMIT %d OFFSET %d;", NS_MAX_SQL_CMD_LENGTH, query_offset);
        rc = sqlite3_get_table(db, sqlcmd, &result, &n_row, &n_column, &err_msg);
        if (rc != SQLITE_OK) {
            VLOG_ERR("Find best index error(Error message:%s)." ,errmsg);
            sqlite3_free(errmsg);
            free(sqlcmd_tmp);
            return;
        }

        int left_n_column = n_column;
        while(left_n_column > 0){
            int max_display_records = verbose ? NS_DISPLAY_MORE_LENGTH_VERBOSE : NS_DISPLAY_MORE_LENGTH;
            int actual_records = MAX(left_n_column, max_display_records);
            for(int i = 1; i < actual_records; i++)
            {
                /* "SELECT BR_NAME,PROTOCOL,DURATION,SRC_IP_PORT,DST_IP_PORT," 0-4
                   "S_TIME_READ,E_TIME_READ,INPUT,OUTPUT,PACKET_COUNT,BYTE_COUNT," 5-10
                   "TOS,SAMPLE_MODE,SAMPLE_INT,BYTES_PER_PKT,FLOW_TYPE FROM NETSTREAM; 11-15 */
                if (verbose) {
                    printf("-6s %-8s %-22s %-22s %-4s %-4s %-8s\n", result[i *  n_columns], \
                           result[i *  n_columns + 1], result[i *  n_columns + 3], \
                           result[i *  n_columns + 4], result[i *  n_columns + 7], \
                           result[i *  n_columns + 8], result[i *  n_columns + 9]);
                    printf("FlowType: %-16s     SampleMode: %-16s SampleInterval: %-5s\n", \
                           result[i *  n_columns + 15], result[i *  n_columns + 12], \
                           result[i *  n_columns + 13]);
                    printf("Bytes: %-20s    Bytes/Pkts: %-16s Tos: %-16s\n",  \
                           result[i *  n_columns + 10], result[i *  n_columns + 14], \
                           result[i *  n_columns + 11]);
                    printf("StartTime: %-19s EndTime: %-19s Durations: %-8s s\n", \
                           result[i *  n_columns + 5], result[i *  n_columns + 6], \
                           result[i *  n_columns + 2]); 
                    if (first_flag) {
                        first_flag = false;
                    }else
                    {
                        printf("\n");
                    }               
                }else
                {
                    /* SELECT BR_NAME,PROTOCOL,SRC_IP_PORT,DST_IP_PORT,
                       INPUT,OUTPUT,PACKET_COUNT FROM NETSTREAM; */
                    printf("%-6s %-8s %-22s %-22s %-4s %-4s %-8s\n", result[i *  n_columns], \
                           result[i *  n_columns + 1], result[i *  n_columns + 2], \
                           result[i *  n_columns + 3], result[i *  n_columns + 4], \
                           result[i *  n_columns + 5], result[i *  n_columns + 6]);
                }
                
            }

            left_n_column -= NS_DISPLAY_MORE_LENGTH;    //最多一次显示24行
            if (left_n_column > 0) {
                /* 实现简单的more效果 */
                int c;
                do
                {
                    printf("---- Enter space to display more records or 'q' to quit. ----\n");
                    c = getchar();
                    if (c == 'q') {
                        goto quit;
                    }else if (c == ' ') {
                        break;
                    }else
                    {
                        /* do nothing */
                    }
                } while (c != EOF);
            }
        }
        query_offset += NS_MAX_QUERY_ROW;
    } while (n_row != 0);
    quit:
    if (tcsetattr(0, TCSANOW, &init_setting) != 0)
    {
        VLOG_ERR("Cannot set the attribution of the terminal.");
    }
    free(sqlcmd_tmp);
}