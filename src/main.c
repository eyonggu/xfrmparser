#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <arpa/inet.h>

/************* DEFINE ****************/
#define OFFSET(T, m)  ((size_t)&(((T *)0)->m))

#define PRINT(depth, ...)           \
{                                   \
    printf("%s", indent[(depth)]);  \
    printf(__VA_ARGS__);            \
    printf("\n");                   \
}

/************* GLOBAL ****************/
struct nlmsghdr *g_nlmsghdr = NULL;

uint8_t msg[2048];
uint32_t g_offset = 0;

/************** SCANNER *************/
extern int yylex(void);
extern FILE *yyin;

void read_byte(char *byte)
{
    uint32_t n;
    char    *c;

    n = (uint32_t)strtoul(byte, &c, 16);
    if (c == byte) {
        fprintf(stderr, "FATAL ERROR: Bad hex number? [%s]\n", byte);
        exit(1);
    }

    msg[g_offset++] = (uint8_t)n;
}

/************** ENUM STRING *************/
char indent[][64] = {
    [0] = "",
    [1] = "    ",
    [2] = "        ",
    [3] = "            ",
    [4] = "                ",
    [5] = "                    "
};

char xfrm_msg_str[][64] = {
    [XFRM_MSG_NEWSA]       = "NEWSA",
    [XFRM_MSG_DELSA]       = "DELSA",
    [XFRM_MSG_GETSA]       = "GETSA",
    [XFRM_MSG_NEWPOLICY]   = "NEWPOLICY",
    [XFRM_MSG_DELPOLICY]   = "DELPOLICY",
    [XFRM_MSG_GETPOLICY]   = "GETPOLICY",
    [XFRM_MSG_ALLOCSPI]    = "ALLOCSPI",
    [XFRM_MSG_ACQUIRE]     = "ACQUIRE",
    [XFRM_MSG_EXPIRE]      = "EXPIRE",
    [XFRM_MSG_UPDPOLICY]   = "UPDPOLICY",
    [XFRM_MSG_UPDSA]       = "UPDSA",
    [XFRM_MSG_POLEXPIRE]   = "POLEXPLORE",
    [XFRM_MSG_FLUSHSA]     = "FLUSHSA",
    [XFRM_MSG_FLUSHPOLICY] = "FLUSHPOLICY",
    [XFRM_MSG_NEWAE]       = "NEWAE",
    [XFRM_MSG_GETAE]       = "GETAE",
    [XFRM_MSG_REPORT]      = "REPORT",
    [XFRM_MSG_MIGRATE]     = "MIGRATE",
    [XFRM_MSG_NEWSADINFO]  = "NEWSAINFO",
    [XFRM_MSG_GETSADINFO]  = "GETSAINFO",
    [XFRM_MSG_NEWSPDINFO]  = "NEWSPDINFO",
    [XFRM_MSG_GETSPDINFO]  = "GETSPDINFO",
    [XFRM_MSG_MAPPING]     = "MAPPING",
};

char xfrm_mode_str[][64] = {
    [XFRM_MODE_TRANSPORT]         = "TRANSPORT",
    [XFRM_MODE_TUNNEL]            = "TUNNEL",
    [XFRM_MODE_ROUTEOPTIMIZATION] = "ROUTEOPTIMIZATION",
    [XFRM_MODE_IN_TRIGGER]        = "IN_TRIGGER",
    [XFRM_MODE_BEET]              = "BEET"
};

char xfrm_dir_str[][64] = {
    [0] = "POLICY_IN",
    [1] = "POLICY_OUT",
    [2] = "POLICY_FWD"
};

char xfrm_action_str[][64] = {
    [XFRM_POLICY_ALLOW] = "POLICY_ALLOW",
    [XFRM_POLICY_BLOCK] = "POLICY_BLOCK"
};

char* byte_to_str(uint8_t *p, int len)
{
    int i = 0;
    static char buf[1024];
    memset(buf, 0, sizeof(buf));

    for (i = 0; i < len; i++) {
        snprintf((buf + i*2), 3, "%02X", p[i]);
    }

    return buf;
}

/***************** COMMON STRUCT **********************/
void print_xfrm_id(void *p, char *label, int depth)
{
    struct xfrm_id *id = (struct xfrm_id *)p;

    PRINT(depth,  "%s {", label);
    PRINT(depth+1, "daddr = %s", inet_ntoa(*(struct in_addr*)&(id->daddr.a4)));
    PRINT(depth+1, "spi = %u",   ntohl(id->spi));
    PRINT(depth+1, "proto = %u", id->proto);
    PRINT(depth,  "}");
}

void print_xfrm_selector(void *p, char *label, int depth)
{
    struct xfrm_selector *selector = (struct xfrm_selector *)p;

    PRINT(depth,  "%s {", label);
    PRINT(depth+1, "daddr = %s",       inet_ntoa(*(struct in_addr*)&(selector->daddr.a4)));
    PRINT(depth+1, "saddr = %s",       inet_ntoa(*(struct in_addr*)&(selector->saddr.a4)));
    PRINT(depth+1, "dport = %u",       ntohs(selector->dport));
    PRINT(depth+1, "dport_mask = %u",  ntohs(selector->dport_mask));
    PRINT(depth+1, "sport = %u",       ntohs(selector->sport));
    PRINT(depth+1, "sport_mask = %u",  ntohs(selector->sport_mask));
    PRINT(depth+1, "family = %u",      selector->family);
    PRINT(depth+1, "prefixlen_d = %u", selector->prefixlen_d);
    PRINT(depth+1, "prefixlen_s = %u", selector->prefixlen_s);
    PRINT(depth+1, "proto = %u",       selector->proto);
    PRINT(depth+1, "ifindex = %d",     selector->ifindex);
    //__kernel_uid32_t	user;
    PRINT(depth,  "}");
}

void print_xfrm_lifetime_cfg(void *p, char *label, int depth)
{
    struct xfrm_lifetime_cfg *lifetime_cfg = (struct xfrm_lifetime_cfg *)p;

    PRINT(depth,  "%s {", label);
    PRINT(depth+1, "soft_byte_limit = %llu",          lifetime_cfg->soft_byte_limit);
    PRINT(depth+1, "hard_byte_limit = %llu",          lifetime_cfg->hard_byte_limit);
    PRINT(depth+1, "soft_packet_limit = %llu",        lifetime_cfg->soft_packet_limit);
    PRINT(depth+1, "hard_packet_limit = %llu",        lifetime_cfg->hard_packet_limit);
    PRINT(depth+1, "soft_add_expires_seconds = %llu", lifetime_cfg->soft_add_expires_seconds);
    PRINT(depth+1, "hard_add_expires_seconds = %llu", lifetime_cfg->hard_add_expires_seconds);
    PRINT(depth+1, "soft_use_expires_seconds = %llu", lifetime_cfg->soft_use_expires_seconds);
    PRINT(depth+1, "hard_use_expires_seconds = %llu", lifetime_cfg->hard_use_expires_seconds);
    PRINT(depth,  "}");
}

void print_xfrm_lifetime_cur(void *p, char *label, int depth)
{
    struct xfrm_lifetime_cur *lifetime_cur = (struct xfrm_lifetime_cur *)p;

    PRINT(depth,  "%s {", label);
    PRINT(depth+1, "bytes = %llu",    lifetime_cur->bytes);
    PRINT(depth+1, "packets = %llu",  lifetime_cur->packets);
    PRINT(depth+1, "add_time = %llu", lifetime_cur->add_time);
    PRINT(depth+1, "use_time = %llu", lifetime_cur->use_time);
    PRINT(depth,  "}");
}

void print_xfrm_stats(void *p, char *label, int depth)
{
    struct xfrm_stats *stats = (struct xfrm_stats *)p;

    PRINT(depth,  "%s {", label);
    PRINT(depth+1, "replay_window = %u",    stats->replay_window);
    PRINT(depth+1, "replay = %u",           stats->replay);
    PRINT(depth+1, "integrity_failed = %u", stats->integrity_failed);
    PRINT(depth,  "}");
}

/************************ RTA **************************/
void print_xfrm_algo(void *p, char *label, int depth, size_t size)
{
    struct xfrm_algo *algo = (struct xfrm_algo *)p;

    PRINT(depth,  "%s(%dB)", label, size);
    PRINT(depth+1, "alg_name = %s", algo->alg_name);
    PRINT(depth+1, "alg_key_len = %u", algo->alg_key_len);
    PRINT(depth+1, "alg_key = %s", byte_to_str((uint8_t *)algo->alg_key, algo->alg_key_len/8));
}

void print_xfrm_mark(void *p, char *label, int depth, size_t size)
{
    struct xfrm_mark *mark = (struct xfrm_mark *)p;

    PRINT(depth,  "%s(%dB)", label, size);
    PRINT(depth+1, "v = %u", mark->v);
    PRINT(depth+1, "m = %u", mark->m);
}

void print_xfrm_tmpl(void *p, char *label, int depth, size_t size)
{
    struct xfrm_user_tmpl *user_tmpl = (struct xfrm_user_tmpl *)p;

    PRINT(depth,  "%s(%dB)", label, size);
    print_xfrm_id(p+OFFSET(struct xfrm_user_tmpl, id),  "id",  depth+1);
    PRINT(depth+1, "family = %u", user_tmpl->family);
    PRINT(depth+1, "saddr = %s",  inet_ntoa(*(struct in_addr*)&(user_tmpl->saddr.a4)));
    PRINT(depth+1, "reqid = %u", user_tmpl->reqid);
    PRINT(depth+1, "mode = %u(%s)", user_tmpl->mode, xfrm_mode_str[user_tmpl->mode]);
    PRINT(depth+1, "share = %u", user_tmpl->share);
    PRINT(depth+1, "optional = %u", user_tmpl->optional);
    PRINT(depth+1, "aalgos = %u", user_tmpl->aalgos);
    PRINT(depth+1, "ealgos = %u", user_tmpl->ealgos);
    PRINT(depth+1, "calgos = %u", user_tmpl->calgos);
}

void print_rta(struct rtattr *rta)
{
    /* RTA indent from level 0 ? */
    switch(rta->rta_type) {
        case XFRMA_ALG_CRYPT:
            print_xfrm_algo(RTA_DATA(rta), "xfrma_alg_crypt", 0, rta->rta_len);
            break;
        case XFRMA_ALG_AUTH:
            print_xfrm_algo(RTA_DATA(rta), "xfrma_alg_auth", 0, rta->rta_len);
            break;
        case XFRMA_MARK:
            print_xfrm_algo(RTA_DATA(rta), "xfrma_mark", 0, rta->rta_len);
            break;
        case XFRMA_TMPL:
            print_xfrm_tmpl(RTA_DATA(rta), "xfrma_tmpl", 0, rta->rta_len);
            break;
        default:
            printf("unknown rta_type(%u:%u)\n", rta->rta_type, rta->rta_len);
            break;
    }
}

/********************* XXX ********************************/

void print_xfrm_usersa_info(void *p, char *label, int depth)
{
    struct xfrm_usersa_info *usersa_info = (struct xfrm_usersa_info *)p;

    PRINT(depth,  "%s(%uB)", label, NLMSG_ALIGN(sizeof(struct xfrm_usersa_info)));
    print_xfrm_selector(p+OFFSET(struct xfrm_usersa_info, sel), "sel", depth+1);
    print_xfrm_id(      p+OFFSET(struct xfrm_usersa_info, id),  "id",  depth+1);
    PRINT(depth+1, "saddr = %s", inet_ntoa(*(struct in_addr*)&(usersa_info->saddr.a4)));
    print_xfrm_lifetime_cfg(p+OFFSET(struct xfrm_usersa_info, lft), "lft", depth+1);
    print_xfrm_lifetime_cur(p+OFFSET(struct xfrm_usersa_info, curlft), "curlft", depth+1);
    print_xfrm_stats(p+OFFSET(struct xfrm_usersa_info, stats), "stats", depth+1);
    PRINT(depth+1, "seq = %u",           usersa_info->seq);
    PRINT(depth+1, "reqid = %u",         usersa_info->reqid);
    PRINT(depth+1, "family = %u",        usersa_info->family);
    PRINT(depth+1, "mode = %u(%s)",      usersa_info->mode, xfrm_mode_str[usersa_info->mode]);
    PRINT(depth+1, "replay_window = %u", usersa_info->replay_window);
    PRINT(depth+1, "flags = %u",         usersa_info->flags);
}

void print_xfrm_userpolicy_info(void *p, char *label, int depth)
{
    struct xfrm_userpolicy_info *userpolicy_info = (struct xfrm_userpolicy_info *)p;

    PRINT(depth,  "%s(%uB)", label, NLMSG_ALIGN(sizeof(struct xfrm_userpolicy_info)));
    print_xfrm_selector(p+OFFSET(struct xfrm_userpolicy_info, sel), "sel", depth+1);
    print_xfrm_lifetime_cfg(p+OFFSET(struct xfrm_userpolicy_info, lft), "lft", depth+1);
    print_xfrm_lifetime_cur(p+OFFSET(struct xfrm_userpolicy_info, curlft), "curlft", depth+1);
    PRINT(depth+1, "priority = %u",  userpolicy_info->priority);
    PRINT(depth+1, "index = %u",     userpolicy_info->index);
    PRINT(depth+1, "dir = %u(%s)",   userpolicy_info->dir, xfrm_dir_str[userpolicy_info->dir]);
    PRINT(depth+1, "action = %u(%s)", userpolicy_info->action, xfrm_action_str[userpolicy_info->action]);
    PRINT(depth+1, "flags = %u",     userpolicy_info->flags);
    PRINT(depth+1, "share = %u",     userpolicy_info->share);
}

/************************** XXX ****************************/
void print_xfrmmsg(void *p)
{
    switch(g_nlmsghdr->nlmsg_type) {
        case XFRM_MSG_NEWSA:
        case XFRM_MSG_DELSA:
        case XFRM_MSG_GETSA:
        case XFRM_MSG_UPDSA:
            print_xfrm_usersa_info(p, "xfrm_usersa_info", 0);
            g_offset = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));
            break;

        case XFRM_MSG_NEWPOLICY:
        case XFRM_MSG_DELPOLICY:
        case XFRM_MSG_GETPOLICY:
            print_xfrm_userpolicy_info(p, "xfrm_userpolicy_info", 0);
            g_offset = NLMSG_LENGTH(sizeof(struct xfrm_userpolicy_info));
            break;

        default:
            break;
    }

    while (g_nlmsghdr->nlmsg_len > g_offset) {
        /* more RTA follow */
        struct rtattr *rta;
        rta = (struct rtattr*)(((char *)g_nlmsghdr) + g_offset);
        print_rta(rta);
        g_offset += rta->rta_len;
    }
}

void print_nlmsghdr(void *p)
{
    struct nlmsghdr *nlmsghdr = (struct nlmsghdr *)p;

    PRINT(0, "nlmsghdr(%dB)", NLMSG_HDRLEN);
    PRINT(1, "nlmsg_len    = %u",       nlmsghdr->nlmsg_len);
    PRINT(1, "nlmsg_type   = %u(%s)", nlmsghdr->nlmsg_type, xfrm_msg_str[nlmsghdr->nlmsg_type]);
    PRINT(1, "nlmsg_flags  = %X",     nlmsghdr->nlmsg_flags);
    PRINT(1, "nlmsg_seq    = %u",     nlmsghdr->nlmsg_seq);
    PRINT(1, "nlmsg_pid    = %u",     nlmsghdr->nlmsg_pid);
}

void print_msg(void *p)
{
    g_offset = 0;

    print_nlmsghdr(p);

    print_xfrmmsg(p + NLMSG_ALIGN(NLMSG_HDRLEN));
}


/************************** MAIN *************************/
void usage()
{
    printf("Usage: xfrmparser hexdumpfile\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        usage();
    }

    yyin = fopen(argv[1], "r");
    yylex();

    g_nlmsghdr = (struct nlmsghdr *)msg;

    print_msg(g_nlmsghdr);

    if (g_offset != g_nlmsghdr->nlmsg_len) {
        printf("ERROR: something wrong?\n");
    }
}
