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
#include "dirs.h"
#include "openvswitch/vlog.h"

#define NS_MAX_QUERY_CONDITION 8
#define NS_MAX_INDEX_LENGTH 24
#define NS_MAX_ARG_LENGTH 24
#define NS_MAX_BRIDGE_NAME_LENGTH 16
#define NS_MAX_PATH_LOG_LENGTH 64
#define NS_MAX_QUERY_ROW 72
#define NS_MAX_VALUE_LENGTH 32
#define NS_MAX_SQL_CMD_LENGTH 1024
#define NS_DISPLAY_MORE_LENGTH 24
#define NS_DISPLAY_MORE_LENGTH_VERBOSE 4

#define NS_ICMP 1
#define NS_TCP 6
#define NS_UDP 17


#define MIN(a,b)  (((a)<(b))?(a):(b))

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

const char *condition_name[NS_MAX_QUERY_CONDITION] = {
    "BRIDGE_NAME",
    "SRC_IP",
    "DST_IP",
    "SRC_PORT",
    "DST_PORT",
    "PROTOCOL",
    "START_TIME",
    "END_TIME"
};

const char *index_name[NS_MAX_QUERY_CONDITION] = {
    "",
    "SRC_IP_INDEX",
    "DST_IP_INDEX",
    "SRC_PORT_INDEX",
    "DST_PORT_INDEX",
    "PROTOCOL_INDEX",
    "START_TIME_INDEX",
    "END_TIME_INDEX"
};

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
static bool ns_str2timestamp(char *, time_t *);
static bool ns_check_time(struct query_conditions *q_c, uint64_t start_time, uint64_t end_time);
static void ns_query_database(struct query_conditions *);
static void parser_commands(int , char **, struct query_conditions *);
static void ns_query_get_table(sqlite3 *, char *, bool);
static bool ns_query_find_best_index(sqlite3 *, struct query_conditions *, char *);

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
           "\n  Of course,it's ok to specify nothing or specify multiple conditions.There "
           "are some query examples below:\n"
           "    # ovs-nsquery\n"
           "    # ovs-nsquery --br-name=\"s1\"\n"
           "    # ovs-nsquery --src-ip=10.0.0.1 --dst-ip=20.0.0.1 --src-port=12 --dst-port=63\n"
           "    # ovs-nsquery --start-time=\"2018-01-01 00:00:00\" --end-time=\"2018-01-01 24:00:00\"\n"
           "    # ovs-nsquery --src-ip=10.0.0.1 --protocol=TCP\n"
           "    # ovs-nsquery --protocol=6 --verbose\n");     
    printf("\nOther options:\n"
           "  --help                  display this help message\n"
           "  --verbose               display the streams in more details\n");
}

static void parser_commands(int argc, char **argv, struct query_conditions *q_c)
{
    char c;
    uint16_t port;
    uint8_t protocol;
    time_t  start_time, end_time;
    int longindex = NS_MAX_QUERY_CONDITION + 2;

    do{
        if (argc == 1) {
            q_c->verbose = false;
            q_c->is_specified = false;
            q_c->cond_br_only = false;
            return;
        }

        c = getopt_long (argc, argv, short_options, long_options, &longindex);

        if (longindex > NS_MAX_QUERY_CONDITION + 1) {
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
                sprintf(q_c->q_s_cond[BR_NAME].value, "\"%s\"", optarg);
                break;
            case SRC_IP:
                if (nsquery_check_ip(optarg, &addr)) {
                    q_c->q_s_cond[SRC_IP].is_specified = true;
                    q_c->cond_br_only = false;
                    sprintf(q_c->q_s_cond[SRC_IP].value, "%u", ntohl((uint32_t)addr.s_addr));
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
                    sprintf(q_c->q_s_cond[DST_IP].value, "%u", ntohl((uint32_t)addr.s_addr));
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
                        sprintf(q_c->q_s_cond[PROTOCOL].value, "%u", protocol);
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
                if(ns_str2timestamp(optarg, &start_time))
                {
                    q_c->q_s_cond[START_TIME].is_specified = true;
                    q_c->cond_br_only = false;
                    sprintf(q_c->q_s_cond[START_TIME].value, "%ld", start_time);
                }else
                {
                    printf("Invalid start time(%s).\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case END_TIME:
                if(ns_str2timestamp(optarg, &end_time))
                {
                    q_c->q_s_cond[END_TIME].is_specified = true;
                    q_c->cond_br_only = false;
                    sprintf(q_c->q_s_cond[END_TIME].value, "%ld", end_time);
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

    if (!ns_check_time(q_c, start_time, end_time)) {
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
    if (strcmp(str_protocpl, "ICMP") == 0) {
        *protocol = NS_ICMP;
    }else if (strcmp(str_protocpl, "TCP") == 0) {
        *protocol = NS_TCP;
    }else if (strcmp(str_protocpl, "UDP") == 0) {
        *protocol = NS_UDP;
    }else
    {
        while(str_protocpl[i] != '\0'){
        if (str_protocpl[i] >= '0' && str_protocpl[i] <= '9') {
            *protocol = *protocol * 10 + str_protocpl[i] - '0';
        }else
        {
            return false;
        }
        ++i;
        }
    }
    return true;
}

static bool
ns_str2timestamp(char *str_timestamp, time_t *timestamp)
{
    struct tm tm_tmp;
    int year, month, day, hour, minute, second;
    memset(&tm_tmp, 0, sizeof tm_tmp);
    if(sscanf(str_timestamp, "%d-%d-%d %d:%d:%d", &year, &month, &day, &hour, &minute, &second) == 6){
        tm_tmp.tm_year = year -1900;
        tm_tmp.tm_mon = month - 1;
        tm_tmp.tm_mday = day;
        tm_tmp.tm_hour = hour;
        tm_tmp.tm_min = minute;
        tm_tmp.tm_sec = second;
        *timestamp = mktime(&tm_tmp);
        return true;
    }
    return false;
}

static bool
ns_check_time(struct query_conditions *q_c, uint64_t start_time, uint64_t end_time)
{
    if (q_c->q_s_cond[START_TIME].is_specified && q_c->q_s_cond[END_TIME].is_specified) {
        if (start_time > end_time) {
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
    sqlite3 *db;
    int rc;
    int n_stable = 0;

    DIR *ns_dir;   //描述一个打开的文件夹
    struct dirent *ns_ptr;

    memset(sqlcmd, 0, NS_MAX_SQL_CMD_LENGTH);


    //sprintf(ns_log_dir_path, "%s/netstream", "/usr/local/share/openvswitch");
    sprintf(ns_log_dir_path, "%s/netstream", ovs_pkgdatadir());  /* /usr/local/share/openvswitch */

    if ((ns_dir = opendir(ns_log_dir_path)) == NULL)
    {
        printf("Open directory(%s) error\n", ns_log_dir_path);
        exit(EXIT_FAILURE);
    }

    if (q_c->verbose) {
        n_stable += sprintf(sqlcmd, "SELECT BRIDGE_NAME,PRO_READ,DURATION,SRC_IP_PORT,DST_IP_PORT,"
                "S_TIME_READ,E_TIME_READ,INPUT,OUTPUT,PACKET_COUNT,BYTE_COUNT,"
                "TOS,SAMPLE_INT,BYTES_PER_PKT,TCP_FLAGS FROM NETSTREAM ");
    }else
    {
        n_stable += sprintf(sqlcmd, "SELECT BRIDGE_NAME,PRO_READ,SRC_IP_PORT,DST_IP_PORT,"
                "INPUT,OUTPUT,PACKET_COUNT FROM NETSTREAM ");
    }

    for(size_t i = 0; i < NS_MAX_QUERY_CONDITION; i++)
    {
        if (q_c->q_s_cond[i].is_specified) {
            q_c->is_specified = true;
            break;
        }
    }

    while ((ns_ptr = readdir(ns_dir)) != NULL)
    {
        int n = n_stable;
        if(strstr(ns_ptr->d_name, "-netstream.db") && !strstr(ns_ptr->d_name, "journal")){
            sprintf(ns_log_file_path, "%s/%s", ns_log_dir_path, ns_ptr->d_name);
            rc = sqlite3_open(ns_log_file_path, &db);
            if (rc != SQLITE_OK) {
                printf("Can't open netstream log database(%s), please" 
                         "check if it is bad.(Error message:%s)\n", \
                         ns_log_file_path, sqlite3_errmsg(db));
                sqlite3_close(db);
                continue;
            }else
            {   
                if (q_c->is_specified) {
                    /* 如果查询条件只有bridge name将不会查找最佳索引，因为没有为BRI_NAME设置索引 */
                    if (!q_c->cond_br_only) {
                        char best_index[NS_MAX_INDEX_LENGTH] = {0};
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
                                first_flag = false;
                            }else
                            {
                                strcat(sqlcmd, " AND ");
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
    size_t best_i = 0;
    uint64_t count = 0;
    uint64_t best_count = INT64_MAX;

    for(size_t i = 1; i < NS_MAX_QUERY_CONDITION; i++)
    {
        if (q_c->q_s_cond[i].is_specified) {
            int n = 0;
            memset(sqlcmd, 0, NS_MAX_SQL_CMD_LENGTH);
            n += sprintf(sqlcmd, "SELECT SUM(COUNT) FROM %s WHERE VALUE", condition_name[i]);
            /* 找包含于输入起始、终止时间之间的流 */
            if (i == START_TIME) {
                n += sprintf(sqlcmd + n, ">= %s;", q_c->q_s_cond[i].value);
            }else if (i == END_TIME)
            {
                n += sprintf(sqlcmd + n, "<= %s;", q_c->q_s_cond[i].value);
            }else
            {
                n += sprintf(sqlcmd + n, "= %s;", q_c->q_s_cond[i].value);
            }

            rc = sqlite3_get_table(db, sqlcmd, &result, &n_row, &n_column, &err_msg);
            if (rc != SQLITE_OK) {
                printf("Find best index error(Error message:%s).\n" ,err_msg);
                free(sqlcmd);
                sqlite3_free(err_msg);
                return false;
            }else
            {
                if (n_row == 1) {   //reslut[0] = "SUM(COUNT)"
                    best_i = i;
                    sqlite3_free_table(result);
                    break;
                }
                
                sscanf(result[1], "%lu", &count);
                
                if (count < best_count) {
                    best_count = count;
                    best_i = i;
                }
                
            }
            sqlite3_free_table(result);
        }
    }
    strcpy(best_index, index_name[best_i]);
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
    char *sqlcmd_tmp = (char *)malloc(NS_MAX_SQL_CMD_LENGTH); 
    struct termios new_setting,init_setting;
   
    if (tcgetattr(0, &init_setting) != 0)
    {
        printf("Cannot get the attribution of the terminal.\n");
        goto quit;
    }
    memcpy(&new_setting, &init_setting, sizeof(struct termios));

    new_setting.c_lflag &= ~(ICANON | ECHO);

    if (tcsetattr(0, TCSANOW, &new_setting) != 0)
    {
        printf("Cannot set the attribution of the terminal.\n");
        goto quit;
    }

    printf("Bri-name Protocol SrcIP(Port)         DstIP(Port)         Input Output Pkts\n");
    printf("------   -------- ------------------- ------------------- ----- -----  ---------\n");

    do
    {
        memset(sqlcmd_tmp, 0, NS_MAX_SQL_CMD_LENGTH);
        /* 加入limit offset限制 */
        sprintf(sqlcmd_tmp, "%s LIMIT %d OFFSET %d;", sqlcmd, NS_MAX_QUERY_ROW, query_offset);
        rc = sqlite3_get_table(db, sqlcmd_tmp, &result, &n_row, &n_column, &err_msg);
        if (rc != SQLITE_OK) {
            printf("Get table error(Error message:%s).\n" ,err_msg);
            sqlite3_free(err_msg);
            goto quit;
        }

        int left_n_row = n_row;
        bool verbose_first_flag = true;
        int i = 1;
        int j = 0;
        int max_display_records = verbose ? NS_DISPLAY_MORE_LENGTH_VERBOSE : NS_DISPLAY_MORE_LENGTH;
        while(left_n_row > 0){
            int actual_records = MIN(left_n_row, max_display_records);
            for(; i <= actual_records + j; i++)
            {
                /* SELECT BRIDGE_NAME,PROTOCOL,DURATION,SRC_IP_PORT,DST_IP_PORT, 0-4
                   S_TIME_READ,E_TIME_READ,INPUT,OUTPUT,PACKET_COUNT,BYTE_COUNT, 5-10
                   TOS,SAMPLE_INT,BYTES_PER_PKT,TCP_FLAGS FROM NETSTREAM 11-14 */
                if (verbose) {
                    if (!verbose_first_flag) {
                        printf("\n");
                    }else
                    {
                        verbose_first_flag = false;
                    }
                    printf("%-8s %-8s %-19s %-19s %-5s %-5s  %-9s\n", result[i *  n_column], \
                           result[i *  n_column + 1], result[i *  n_column + 3], \
                           result[i *  n_column + 4], result[i *  n_column + 7], \
                           result[i *  n_column + 8], result[i *  n_column + 9]);
                    uint8_t tos;
                    sscanf(result[i *  n_column + 11], "%u", &tos);
                    printf("SampleInterval: %16s      Tos:                      0x%02x\n", result[i *  n_column + 12], tos);
                    printf("Bytes: %25s      Bytes/Pkts: %18s\n",  \
                           result[i *  n_column + 10], result[i *  n_column + 13]);
                    printf("StartTime: %21s      EndTime: %21s\n", \
                           result[i *  n_column + 5], result[i *  n_column + 6]);
                    printf("Durations: %20ss",result[i *  n_column + 2]);
                    if (strcmp(result[i *  n_column + 1], "TCP") == 0) {
                        uint8_t tcp_flags;
                        sscanf(result[i *  n_column + 14], "%u", &tcp_flags);
                        printf("      TCP_FLAGS:                0x%02x\n", tcp_flags);
                    }else
                    {
                        printf("\n");
                    }             
                }else
                {
                    /* SELECT BR_NAME,PROTOCOL,SRC_IP_PORT,DST_IP_PORT,
                       INPUT,OUTPUT,PACKET_COUNT FROM NETSTREAM; */
                    printf("%-8s %-8s %-19s %-19s %-5s %-5s  %-9s\n", result[i *  n_column], \
                           result[i *  n_column + 1], result[i *  n_column + 2], \
                           result[i *  n_column + 3], result[i *  n_column + 4], \
                           result[i *  n_column + 5], result[i *  n_column + 6]);
                }
                
            }
            j = (i - 1);
            left_n_row -= max_display_records;    //最多一次显示24或6行
            if (left_n_row > 0) {
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
    sqlite3_close(db);
    if (tcsetattr(0, TCSANOW, &init_setting) != 0)
    {
        printf("Cannot set the attribution of the terminal.\n");
    }
    free(sqlcmd_tmp);
}