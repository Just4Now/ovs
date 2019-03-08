#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <time.h>

//#include "sqlite3.h"

#define NS_MAX_QUERY_CONDITION 8
#define NS_MAX_ARG_LENGTH 24
#define NS_MAX_BRIDGE_NAME_LENGTH 16

struct query_single_cond
{
    char br_name[NS_MAX_BRIDGE_NAME_LENGTH];
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port; 
    uint8_t protocol;
    uint64_t start_time;
    uint64_t end_time;
};

struct query_conditions
{
    bool is_specified[NS_MAX_QUERY_CONDITION];
    struct query_single_cond q_s_cond;
};

enum OPTION{
    BR_NAME,
    SRC_IP,
    DST_IP,
    SRC_PORT,
    DST_PORT,
    PROTOCOL,
    START_TIME,
    END_TIME
};

static void nsquery_usage();
static bool nsquery_check_ip(char *, struct in_addr *);
static bool ns_str2uint16(char *, uint16_t *);
static bool ns_str2uint8(char *, uint8_t *);
static bool ns_str2timestamp(char *, uint64_t *);
static bool ns_check_time(struct query_conditions *);
static void ns_query_database(struct query_conditions *);
static void parser_options(int , char **, struct query_conditions *);

static const char short_options[] = "h";
static const struct option long_options[] = {
    { "help", no_argument, NULL, 'h' },
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
    
    parser_options(argc, argv, &q_c);

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
           "    # ovs-nsquery --protocol=6\n");     
    printf("\nOther options:\n"
           "  -h, --help                  display this help message\n");
    exit(EXIT_SUCCESS);
}

static void parser_options(int argc, char **argv, struct query_conditions *q_c)
{
    char c;
    uint16_t port;
    uint8_t protocol;
    uint64_t timestamp;

    while((c = getopt_long (argc, argv, short_options, long_options, NULL)) != -1){
        switch (c)
        {
            struct in_addr addr;
            case 'h':
                if (argc == 2) {
                    nsquery_usage();
                }else
                {
                    printf("if you want to konw the usage of ovs-nsquery, "
                            "please just use \"ovs-nsquery -h\" or \"ovs-nsqurey --help\"\n");
                    exit(EXIT_FAILURE);
                }
                break;
            case BR_NAME:
                q_c->is_specified[BR_NAME] = true;
                memcpy(q_c->q_s_cond.br_name, optarg, strlen(optarg));
                break;
            case SRC_IP:
                if (nsquery_check_ip(optarg, &addr)) {
                    q_c->is_specified[SRC_IP] = true;
                    q_c->q_s_cond.src_ip = (uint32_t)addr.s_addr;
                }else
                {
                    printf("Invalid source ip addresss:%s.\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case DST_IP:
                if (nsquery_check_ip(optarg, &addr)) {
                    q_c->is_specified[DST_IP] = true;
                    q_c->q_s_cond.dst_ip = (uint32_t)addr.s_addr;
                }else
                {
                    printf("Invalid destination ip addresss:%s.\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case SRC_PORT:
                if (ns_str2uint16(optarg, &port)) {
                    if (port >=0 && port <= 65535) {
                        q_c->is_specified[SRC_PORT] = true;
                        q_c->q_s_cond.src_port = port;
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
                        q_c->is_specified[DST_PORT] = true;
                        q_c->q_s_cond.dst_port = port;
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
                        q_c->is_specified[PROTOCOL] = true;
                        q_c->q_s_cond.protocol = protocol;
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
                    q_c->is_specified[START_TIME] = true;
                    q_c->q_s_cond.start_time = timestamp;
                }else
                {
                    printf("Invalid start time(%s).\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case END_TIME:
                if(ns_str2timestamp(optarg, &timestamp))
                {
                    q_c->is_specified[END_TIME] = true;
                    q_c->q_s_cond.end_time = timestamp;
                }else
                {
                    printf("Invalid end time(%s).\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            default:
                printf("invalid condition name(%s); use --help for help\n", optarg);
                exit(EXIT_FAILURE);
                break;
        }
    }

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
    if (q_c->is_specified[START_TIME] && q_c->is_specified[END_TIME]) {
        if (q_c->q_s_cond.start_time > q_c->q_s_cond.end_time) {
            return false;
        }
        return true;
    }
    return true; 
}

static void
ns_query_database(struct query_conditions *q_c)
{
    
}