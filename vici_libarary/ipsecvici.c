#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <libvici.h>
#include "ipsecvici.h"

#define INITIAL_RESPONSE_SIZE 1024

int get_ip(char *intf);
int is_ipaddr(char *str);

static int append_res(char **response, size_t *offset,
            size_t *resp_size, const char *format, ...)
{
    if(!response || !*response || !offset || !resp_size) return -1;

    va_list args;
    va_start(args, format);
    va_list args_copy;
    va_copy(args_copy, args);
    int needed = vsnprintf(NULL, 0, format, args_copy) + 1;
    va_end(args_copy);
    if(needed <= 0) {
        va_end(args);
        return -1;
    }
    if(*offset + needed > *resp_size) {
        size_t new_size = *resp_size * 2 > *offset + needed ? *resp_size * 2 : *offset + needed;
        char *new_buffer = (char *)realloc(*response, new_size);
        if(!new_buffer) {
            fprintf(stderr, "IPsec: realloc() failed: %s\n", strerror(errno));
            va_end(args);
            return -1;
        }
        *response = new_buffer;
        *resp_size = new_size;
    }
    int written = vsnprintf(*response + *offset, *resp_size - *offset, format, args);
    va_end(args);
    if(written < 0 || written >= (int)(*resp_size - *offset)) return -1;
    *offset += written;
    return 0;
}

static int sa_values(void *user, vici_res_t *res,
                    char *name, void *value, int len)
{   
    conn_info_t *ctx = (conn_info_t *)user;
    if(!ctx || !ctx->response || !ctx->offset || !ctx->resp_size) return -1;

    char clean_v[len];
    strncpy(clean_v, (char *)value, len); clean_v[len] = '\0';
    if(!strcmp("state", name) || !strcmp("local-host", name) ||
        !strcmp("remote-host", name) || !strcmp("established", name) ||
        !strcmp("initiator", name))
        append_res(ctx->response, ctx->offset, ctx->resp_size, 
                         "%s=%s\n", name, clean_v);
    return 0;
}

static int sa_list(void *user, vici_res_t *res,
                    char *name, void *value, int len)
{
    conn_info_t *ctx = (conn_info_t *)user;
    if(!ctx || !ctx->response || !ctx->offset || !ctx->resp_size) return -1;

    char clean_v[len]; clean_v[len] = '\0';
    strncpy(clean_v, (char *)value, len);
    return append_res(ctx->response, ctx->offset, ctx->resp_size, 
                     "%s=%s\n", name, clean_v);
}

static int child_sas(void *user, vici_res_t *res, char *name)
{
    return vici_parse_cb(res, NULL, NULL, sa_list, user);
}

static int ike_sa(void *user, vici_res_t *res, char *name)
{
    if(!strncmp(name, "child-sas", 9)) 
        return vici_parse_cb(res, child_sas, NULL, sa_list, user);
    return 0;
}

static int ike_sas(void *user, vici_res_t *res, char *name)
{
    conn_info_t *ctx = (conn_info_t *)user;
    if(!ctx || !ctx->response || !ctx->offset || !ctx->resp_size) return -1;

    int ret = append_res(ctx->response, ctx->offset, ctx->resp_size, 
                        "conn=%s\n", name);
    if(ret) return ret;
    return vici_parse_cb(res, ike_sa, sa_values, NULL, user);
}

static void list_cb(void *user, char *name, vici_res_t *res)
{   
    conn_info_t *ctx = (conn_info_t *)user;
    if(vici_parse_cb(res, ike_sas, sa_values, sa_list, ctx))
        append_res(ctx->response, ctx->offset, ctx->resp_size,
                  "Error: parsing SA event failed: %s\n", strerror(errno));
}

static int list_sas(vici_conn_t *conn, IKE_CONN_T *ike_conn,
                    char **response, size_t *offset, size_t *resp_size)
{
    vici_req_t *req;
    vici_res_t *res;
    int ret=0;
    conn_info_t ctx = {response, offset, resp_size};

    if(vici_register(conn, "list-sa", list_cb, &ctx)) {
        append_res(response, offset, resp_size,
            "IPsec: registering '%s' for SAs failed: %s\n",
            ike_conn->name, strerror(errno));
        return -1;
    }

    req = vici_begin("list-sas");
    vici_add_key_valuef(req, "ike", "%s", ike_conn->name);
    vici_add_key_valuef(req, "noblock", "yes");
    res = vici_submit(req, conn);
    if(!res) {
        append_res(response, offset, resp_size,
            "IPsec: list-sa '%s' request failed.\n", ike_conn->name);
        return -1;
    }
    if(!strncmp(vici_find_str(res, "no", "success"), "yes", 3)) {
        append_res(response, offset, resp_size,
            "IPsec: list-sa completed.\n");
        ret = 0;
    } else {
        append_res(response, offset, resp_size,
            "IPsec: list-sa failed: %s\n", vici_find_str(res, "", "errmsg"));
        ret = -1;
    }
    vici_free_res(res);
    return ret;
}

static int terminate_conn(vici_conn_t *conn, IKE_CONN_T *ike_conn,
            char **response, size_t *offset, size_t *resp_size)
{
    vici_req_t *req;
    vici_res_t *res;
    int ret=0;

    append_res(response, offset, resp_size,
        "IPsec: terminating %s...\n", ike_conn->name);

    req = vici_begin("terminate");
    vici_add_key_valuef(req, "ike", "%s", ike_conn->name);
    vici_add_key_valuef(req, "force", "yes");
    vici_add_key_valuef(req, "timeout", "%d", -1*1000);
    res = vici_submit(req, conn);
    if(!res) {
        append_res(response, offset, resp_size,
            "IPsec: terminate request failed: %s\n", strerror(errno));
        return -1;
    }
    if(!strncmp(vici_find_str(res, "no", "success"), "yes", 3)) {
        append_res(response, offset, resp_size,
            "IPsec: terminate completed successfully.\n");
        ret = 0;
    } else {
        append_res(response, offset, resp_size,
            "IPsec: terminate failed: %s\n", vici_find_str(res, "", "errmsg"));
        ret = -1;
    }
    vici_free_res(res);
    return ret;
}

static int unload_conn(vici_conn_t * conn, IKE_CONN_T *ike_conn,
            char **response, size_t *offset, size_t *resp_size)
{
    vici_req_t *req;
    vici_res_t *res;
    int ret = 0;

    req = vici_begin("unload-conn");
    vici_add_key_valuef(req, "name", "%s", ike_conn->name);
    res = vici_submit(req, conn);
    if(!res) {
        append_res(response, offset, resp_size,
            "IPsec: unload-conn request for '%s' failed: %s\n",
            ike_conn->name, strerror(errno));
        return -1;
    }
    if(!strncmp(vici_find_str(res, "no", "success"), "yes", 3)) {
        append_res(response, offset, resp_size,
            "IPsec: unload connection '%s' completed.\n", ike_conn->name);
        ret = 0;
    } else {
        append_res(response, offset, resp_size,
            "IPsec: unload connection '%s' failed: %s\n",
            ike_conn->name, vici_find_str(res, "", "errmsg"));
        ret = -1;
    }
    vici_free_res(res);

    req = vici_begin("unload-shared");
    vici_add_key_valuef(req, "id", "%s", ike_conn->name);
    res = vici_submit(req, conn);
    if(!res) {
        append_res(response, offset, resp_size,
            "IPsec: unload-shared key '%s' request failed: %s\n",
            ike_conn->name, strerror(errno));
        return -1;
    }
    if(!strncmp(vici_find_str(res, "no", "success"), "yes", 3)) {
        append_res(response, offset, resp_size,
            "IPsec: unload-shared key '%s' completed.\n", ike_conn->name);
        ret = 0;
    } else {
        append_res(response, offset, resp_size,
            "IPsec: unload-shared key '%s' failed: %s\n",
            ike_conn->name, vici_find_str(res, "", "errmsg"));
        ret = -1;
    }
    vici_free_res(res);

    if(ike_conn->bypass_lan) {
        char conn_name[INSTANCE_LEN+8];
        snprintf(conn_name, INSTANCE_LEN+8, "%spass", ike_conn->name);
        req = vici_begin("unload-conn");
        vici_add_key_valuef(req, "name", "%s", conn_name);
        res = vici_submit(req, conn);
        if(!res) {
            append_res(response, offset, resp_size,
                "IPsec: unload-conn shunt request for '%s' failed: %s\n",
                conn_name, strerror(errno));
            return -1;
        }
        if(!strncmp(vici_find_str(res, "no", "success"), "yes", 3)){
            append_res(response, offset, resp_size,
                "IPsec: unload-conn shunt '%s' completed.\n", conn_name);
            ret = 0;
        } else {
            append_res(response, offset, resp_size,
                "IPsec: unload-conn shunt '%s' failed: %s\n",
                conn_name, vici_find_str(res, "", "errmsg"));
            ret = -1;
        }
        vici_free_res(res);
    }
    return ret;
}

static int load_conn(vici_conn_t *conn, IKE_CONN_T *ike_conn,
            char **response, size_t *offset, size_t *resp_size)
{    
    if(!ike_conn->enabled)
       return append_res(response, offset, resp_size,
                    "IPsec: conn '%s' disabled, load-conn failed.\n", ike_conn->name);

    if(!is_ipaddr(ike_conn->local_addrs)) {
        append_res(response, offset, resp_size,
            "IPsec: '%s' isn't an ip address.\nload-conn '%s' failed.\n",
            ike_conn->local_addrs, ike_conn->name);
        return -1;
    }

    int ret = 0;
    vici_res_t *res;
    vici_req_t *req = vici_begin("load-conn");
    vici_begin_section(req, ike_conn->name);
    vici_begin_list(req, "local_addrs");
    vici_add_list_itemf(req, "%s", ike_conn->local_addrs);
    vici_end_list(req);
    vici_begin_list(req, "remote_addrs");
    vici_add_list_itemf(req, "%s", ike_conn->remote_addrs);
    vici_end_list(req);
    vici_begin_section(req, "local");
    vici_add_key_valuef(req, "auth", "%s", ike_conn->auth);
    vici_add_key_valuef(req, "id", "%s", ike_conn->local_id);
    vici_end_section(req);
    vici_begin_section(req, "remote");
    vici_add_key_valuef(req, "auth", "%s", ike_conn->auth);
    vici_add_key_valuef(req, "id", "%s", ike_conn->remote_id);
    vici_end_section(req);
    vici_begin_list(req, "proposals");
    vici_add_list_itemf(req, "%s", ike_conn->ike_proposal);
    vici_end_list(req);
    vici_add_key_valuef(req, "version", "%d", ike_conn->ike_version);
    if(1 == ike_conn->ike_aggressive)
        vici_add_key_valuef(req, "aggressive", "%s", "yes");
    vici_add_key_valuef(req, "rekey_time", "%s", ike_conn->ike_rekey);
    vici_add_key_valuef(req, "dpd_delay", "%s", ike_conn->dpd_delay);
    vici_add_key_valuef(req, "keyingtries", "%d", 3);
    vici_add_key_valuef(req, "mobike", "%s", "no");
    vici_begin_section(req, "children");
    for(int i=0; i<ike_conn->child_cnt; ++i) {
        vici_begin_section(req, ike_conn->child_sa[i].name);
        vici_add_key_valuef(req, "mode", "%s", ike_conn->tunnel_mode);
        vici_add_key_valuef(req, "start_action", "%s", ike_conn->start_action);
        vici_add_key_valuef(req, "dpd_action", "%s", ike_conn->dpd_action);
        vici_add_key_valuef(req, "rekey_time", "%s", ike_conn->esp_rekey);
        vici_begin_list(req, "esp_proposals");
        vici_add_list_itemf(req, "%s", ike_conn->esp_proposal);
        vici_end_list(req);
        vici_add_key_valuef(req, "updown", "/usr/share/swanctl/ipsec_updown");
        if(!strncmp(ike_conn->tunnel_mode, "transport", 9)) continue;
        vici_begin_list(req, "local_ts");
        vici_add_list_itemf(req, "%s", ike_conn->local_net[ike_conn->child_sa[i].left]);
        vici_end_list(req);
        vici_begin_list(req, "remote_ts");
        vici_add_list_itemf(req, "%s", ike_conn->remote_net[ike_conn->child_sa[i].right]);
        vici_end_list(req);
        vici_end_section(req);
    }
    vici_end_section(req);
    vici_end_section(req);
    res = vici_submit(req, conn);
    if(!res) {
        append_res(response, offset, offset,
            "IPsec: load-conn '%s' request failed: %s\n",
            ike_conn->name, strerror(errno));
        return -1;
    }
    if(strncmp(vici_find_str(res, "no", "success"), "yes", 3)) {
        append_res(response, offset, resp_size,
            "IPsec: load-conn '%s' failed: %s\n",
            ike_conn->name, vici_find_str(res, "", "errmsg"));
        ret = -1;
    } else
        append_res(response, offset, resp_size,
            "IPsec: load-conn '%s' completed.\n", ike_conn->name);
    vici_free_res(res);

    req = vici_begin("load-shared");
    vici_add_key_valuef(req, "id", "%s", ike_conn->name);
    vici_add_key_valuef(req, "type", "%s", "ike");
    vici_add_key_value(req, "data", ike_conn->psk, strlen(ike_conn->psk) );
    vici_begin_list(req, "owners");
    vici_add_list_itemf(req, "%s", ike_conn->local_id);
    vici_add_list_itemf(req, "%s", ike_conn->remote_id);
    vici_end_list(req);
    res = vici_submit(req, conn);
    if(!res) {
        append_res(response, offset, resp_size,
            "IPsec: load-shared key '%s' request failed: %s\n",
            ike_conn->name, strerror(errno));
        return -1;
    }
    if(strncmp(vici_find_str(res, "no", "success"), "yes", 3)) {
        append_res(response, offset, resp_size,
            "IPsec: load-shared key '%s' failed: %s\n",
            ike_conn->name, vici_find_str(res, "", "errmsg"));
        ret = -1;
    } else
        append_res(response, offset, resp_size,
            "IPsec: load-shared key '%s'\n", ike_conn->name);
    vici_free_res(res);

    if(ike_conn->bypass_lan) {
        char conn_name[INSTANCE_LEN+8], child_name[INSTANCE_LEN+24];
        snprintf(conn_name, INSTANCE_LEN+8, "%spass", ike_conn->name);
        req = vici_begin("load-conn");
        vici_begin_section(req, conn_name);
        vici_begin_section(req, "children");        
        for(int i=0; i<ike_conn->bypass_lan; ++i) {
            snprintf(child_name, INSTANCE_LEN+24, "%s_child%d", conn_name, i+1);
            vici_begin_section(req, child_name);
            vici_add_key_valuef(req, "mode", "%s", "pass");
            vici_add_key_valuef(req, "start_action", "%s", "trap");
            vici_begin_list(req, "local_ts");
            vici_add_list_itemf(req, "%s", ike_conn->bypass_net[i]);
            vici_end_list(req);
            vici_begin_list(req, "remote_ts");
            if(strstr(ike_conn->bypass_net[i], ":")) vici_add_list_itemf(req, "%s", "::/0");
            else vici_add_list_itemf(req, "%s", "0.0.0.0/0");
            vici_end_list(req);
            vici_end_section(req);
        }
        vici_end_section(req);
        vici_end_section(req);
        res = vici_submit(req, conn);
        if(!res) {
            append_res(response, offset, offset,
                "IPsec: load-conn shunt '%s' request failed: %s\n",
                conn_name, strerror(errno));
            return -1;
        }
        if(strncmp(vici_find_str(res, "no", "success"), "yes", 3)) {
            append_res(response, offset, resp_size,
                "IPsec: load-conn shunt '%s' failed: %s\n",
                conn_name, vici_find_str(res, "", "errmsg"));
            ret = -1;
        } else
            append_res(response, offset, resp_size,
                "IPsec: load-conn shunt '%s' completed.\n", ike_conn->name);
    
        vici_free_res(res);
    }
    return ret;
}

int is_ipaddr(char *str)
{
    if (!str || !strlen(str) || strlen(str) > INET6_ADDRSTRLEN) return 0;
    struct in_addr ipv4;
    struct in6_addr ipv6;
    char buf[INET6_ADDRSTRLEN];

    if(1 == inet_pton(AF_INET, str, &ipv4))
        if(inet_ntop(AF_INET, &ipv4, buf, INET_ADDRSTRLEN)
            && !strcmp(buf, str)) return 1;
    if(1 == inet_pton(AF_INET6, str, &ipv6))
        if(inet_ntop(AF_INET6, &ipv6, buf, INET6_ADDRSTRLEN)) return 1;
    return 0;  // Not a valid IP address
}
int parse_addr(struct nlmsghdr *nlh, char *ifname, int default_rt, int *sockfd_ptr)
{
    void *msg_data = NLMSG_DATA(nlh);
    struct rtattr *rta;
    int len,
        family,
        oif_index=-1;
        // prefixlen;
    if(default_rt) {
        struct rtmsg *rtm = (struct rtmsg *)msg_data;
        rta = RTM_RTA(rtm);
        len = RTM_PAYLOAD(nlh);
        family = rtm->rtm_family;
    } else {
        struct ifaddrmsg *ifa = (struct ifaddrmsg *)msg_data;
        char tmp_ifname[IF_NAMESIZE] = {0};
        if(strcmp(if_indextoname(ifa->ifa_index, tmp_ifname), ifname)) return -1;
        rta = IFA_RTA(ifa);
        len = IFA_PAYLOAD(nlh);
        family = ifa->ifa_family;
        // prefixlen = ifa->ifa_prefixlen;
    }

    for( ;RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        if(default_rt) {
            if(rta->rta_type == RTA_OIF) {
                oif_index = *(int *)RTA_DATA(rta);
                if_indextoname(oif_index, ifname);
                close(*sockfd_ptr);
                *sockfd_ptr = -1;
                return get_ip(ifname);
            }
        } else if(rta->rta_type == IFA_ADDRESS) {
            inet_ntop(family, RTA_DATA(rta), ifname, INET6_ADDRSTRLEN);
            return 0;
        }
    }
    return 0;
}
int get_ip(char *intf)
{
    int sockfd,
        isv6=0,
        len=0,
        default_rt=0;
    char buf[4096]={'\0'};

    if(strstr(intf, "v6")) isv6 = 1;
    else isv6 = 0;

    if(strstr(intf, "ETH")) {
        int intf_no = intf[3] - 49;
        snprintf(intf, 8, "lan%d", intf_no);
    } else if(strstr(intf, "Cellular")) strncpy(intf, "usb0", 8);
    else if (strstr(intf, "Any")) default_rt = 1;
    else if(strstr(intf, "lan")) ;
    else if(strstr(intf, "usb")) ;
    else if(is_ipaddr(intf)) return 0;
    else return -1;

    sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if(sockfd < 0) {
        perror("socket");
        return -1;
    }

    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
        char buf[1024];
    } req = {0};

    req.nlh.nlmsg_type = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.nlh.nlmsg_seq = 1;
    req.rtm.rtm_family = isv6 ? AF_INET6 : AF_INET;
    req.rtm.rtm_table = RT_TABLE_MAIN;

    if(default_rt) {
        struct rtattr *rta = (struct rtattr *)req.buf;
        rta->rta_type = RTA_DST;
        if (isv6) {
            rta->rta_len = RTA_LENGTH(16);
            inet_pton(AF_INET6, "2001:4860:4860::8888", RTA_DATA(rta));
            req.rtm.rtm_dst_len = 128;
        } else {
            rta->rta_len = RTA_LENGTH(4);
            inet_pton(AF_INET, "8.8.8.8", RTA_DATA(rta));
            req.rtm.rtm_dst_len = 32;
        }
        req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)) + rta->rta_len;
    } else {
        req.nlh.nlmsg_type = RTM_GETADDR;
        req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
        req.nlh.nlmsg_flags |= NLM_F_DUMP;
    }
    if(send(sockfd, &req, req.nlh.nlmsg_len, 0) < 0) {
        perror("send");
        close(sockfd);
        return -1;
    }

   while((len = recv(sockfd, buf, sizeof(buf), 0)) > 0) {
        for(struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
                NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
            if(nlh->nlmsg_type == NLMSG_DONE) {
                close(sockfd);
                return *intf ? 0 : -1;
            }
            if(nlh->nlmsg_type == RTM_NEWROUTE || nlh->nlmsg_type == RTM_NEWADDR)
                parse_addr(nlh, intf, default_rt, &sockfd);
        }
    }

    close(sockfd);
    return 0;
}

int check_ip_in_subnet(char* ip, char* subnet,
        char **response, size_t *offset, size_t *resp_size)
{
    char *subnet_ip=NULL,
         *prefix_str=NULL;
    int prefix=0,
        ret=0;

    subnet_ip = (char *)calloc(1,48);
    prefix_str = (char *)calloc(1,4);
    if(!subnet_ip || !prefix_str) {
        append_res(response, offset, resp_size, "IPsec: calloc() failed.\n");
        free(subnet_ip); free(prefix_str);
        return -1;
    }

    for(prefix = 0; prefix < 48 && subnet[prefix] != '\0'; ++prefix) {
        if('/' == subnet[prefix]) {
            subnet_ip[prefix] = '\0';
            break;
        }
        subnet_ip[prefix] = subnet[prefix];
    }
    int j;prefix_str[0] = '\0';
    for(j=0, ++prefix; subnet[prefix] != '\0' && j < 3; ++prefix, ++j)
        *(prefix_str+j) = subnet[prefix];
    *(prefix_str+j) = '\0';
    prefix = atoi(prefix_str);
    for(j=0; ip[j]!='#'; ++j);
    ip[j] = '\0';
    if(strchr(ip, ':') && strchr(subnet, ':')) { 
        struct in6_addr ip6, subnet6;
        inet_pton(AF_INET6, ip, &ip6);
        inet_pton(AF_INET6, subnet_ip, &subnet6);
        int bytes = prefix / 8;
        int bits = prefix % 8;
        ret = 0;
        if(memcmp(&ip6, &subnet6, bytes)) ret = -1;
        else if(bits > 0) {
            unsigned char mask = 0xFF << (8 - bits);
            if((ip6.s6_addr[bytes] & mask) != (subnet6.s6_addr[bytes] & mask)) ret = -1;
        }
    } else if(strchr(ip, '.') && strchr(subnet, '.')) {
        struct in_addr ip4, subnet4;
        inet_pton(AF_INET, ip, &ip4);
        inet_pton(AF_INET, subnet_ip, &subnet4);
        uint32_t ip_num = ntohl(ip4.s_addr);
        uint32_t subnet_num = ntohl(subnet4.s_addr);
        uint32_t mask = 0 == prefix ? 0 : ~((1U << (32 - prefix)) - 1);
        ret = ((ip_num & mask) == (subnet_num & mask)) ? 0 : -1;
    } else 
        ret = -1;

    free(subnet_ip);
    free(prefix_str);
    return ret;
}

void determine_childs(IKE_CONN_T *ike_conn, char **local_acl,
        char **remote_acl, char **response, size_t *offset, size_t *resp_size)
{
    for(int i=0, j; i<ike_conn->child_cnt; ++i) {
        for(j=0; j<ike_conn->cnt_l; ++j)
            if(!check_ip_in_subnet(local_acl[i], ike_conn->local_net[j],
                    response, offset, resp_size)) {
                ike_conn->child_sa[i].left = j;
                break;
            }
        for(j=0; j<ike_conn->cnt_r; ++j)
            if(!check_ip_in_subnet(remote_acl[i], ike_conn->remote_net[j],
                    response, offset, resp_size)) {
                ike_conn->child_sa[i].right = j;
                break;
            }
        snprintf(ike_conn->child_sa[i].name, INSTANCE_LEN+16, "%s_child%d", ike_conn->name, i+1);
    }
}

int read_config(IKE_CONN_T *ike_conn, const char *ike,
        char **response, size_t *offset, size_t *resp_size)
{   
    char buff[512]={'\0'},
         ike_name[INSTANCE_LEN]={'\0'},
         local_gateway[IP_LEN]={'\0'},
         ike_version[16]={'\0'};
    char *local_acl[MAX_SUBNETS*MAX_SUBNETS],
         *remote_acl[MAX_SUBNETS*MAX_SUBNETS];
    int cnt_l=0,
        cnt_r=0,
        acl_cnt1=0,
        acl_cnt2=0,
        is_en=1,
        ret=0,
        bypassnet_cnt=0;

    for(int i=0; i<MAX_SUBNETS*MAX_SUBNETS; ++i) {
        local_acl[i] = (char *)calloc(1,IP_LEN);
        remote_acl[i] = (char *)calloc(1,IP_LEN);
        if(!local_acl[i] || !local_acl[i]) {
            append_res(response, offset, resp_size, "IPsec: calloc() failed.\n");
            return -1;
        }
    }

    FILE *fp = NULL;
    fp = fopen("/etc/config/ipsec", "r");
    if(!fp) {
        append_res(response, offset, resp_size,
            "IPsec: can't open file '/etc/config/ipsec' %s\n", strerror(errno));
        ret = -1;
        goto END;
    }
    ike_conn->ike_aggressive = 0;

    while(fgets(buff, sizeof(buff), fp)) {
        buff[strlen(buff)-1] = '\0';
        if(!strncmp("config ipsec", buff, 12)) {
            sscanf(buff, "config ipsec '%[^']'", ike_name);
            if(!is_en) break;
            is_en = 0;
        }
        if(strncmp(ike_name, ike, strlen(ike))) {
            is_en = 1;   // config not found flag
            continue;   //conn not found go for next
        }
        if(!strncmp(buff, "\toption ", 8)) {
            char key[IP_LEN], value[IP_LEN];
            if(2 != sscanf(buff, "\toption %40s '%40[^']'", key, value)){
                append_res(response, offset, resp_size,
                    "IPsec: malformed config line: %s\n", buff);
                continue;
            }
            if(!strncmp(key, "enabled", 7)) ike_conn->enabled = value[0]-48;
            else if(!strncmp(key, "local_gateway", 13)) strncpy(local_gateway, value, IP_LEN);
            else if(!strncmp(key, "remote_gateway", 14)) strncpy(ike_conn->remote_addrs, value, IP_LEN);
            else if(!strncmp(key, "local_identifier", 16)) strncpy(ike_conn->local_id, value, INSTANCE_LEN);
            else if(!strncmp(key, "remote_identifier", 17)) strncpy(ike_conn->remote_id, value, INSTANCE_LEN);
            else if(!strncmp(key, "auth_method", 11)) strncpy(ike_conn->auth, value, 8);
            else if(!strncmp(key, "keyexchange", 11)) strncpy(ike_version, value, 16);
            else if(!strncmp(key, "preshared_key", 13)) strncpy(ike_conn->psk, value, INSTANCE_LEN);
            else if(!strncmp(key, "ike_proposal", 12)) strncpy(ike_conn->ike_proposal, value, INSTANCE_LEN);
            else if(!strncmp(key, "ike_rekeytime", 13)) strncpy(ike_conn->ike_rekey, value, 8);
            else if(!strncmp(key, "dpddelay", 8)) strncpy(ike_conn->dpd_delay, value, 8);
            else if(!strncmp(key, "dpdaction", 9)) strncpy(ike_conn->dpd_action, value, 8);
            else if(!strncmp(key, "esp_rekeytime", 13)) strncpy(ike_conn->esp_rekey, value, 8);
            else if(!strncmp(key, "tunnel_mode", 11)) strncpy(ike_conn->tunnel_mode, value, 16);
            else if(!strncmp(key, "bypasslan_en", 12)) ike_conn->bypass_lan = value[0]-48;
            else if(!strncmp(key, "peer_mode", 9)) {
                strncpy(ike_conn->peer_mode, value, 8);
                if(!strncmp("local", ike_conn->peer_mode, 5))
                    strncpy(ike_conn->start_action, "trap", 5);
                else if(!strncmp("remote", ike_conn->peer_mode, 6))
                    strncpy(ike_conn->start_action, "none", 5);
            }
            else if(!strncmp(key, "esp_proposal", 12)) {
                char *ptr;
                if((ptr = strstr(value, "-no"))) *ptr = '\0';
                strncpy(ike_conn->esp_proposal, value, INSTANCE_LEN);
            }
        }
        if(!strncmp(buff, "\tlist ", 6)) {
            char key[IP_LEN], value[IP_LEN];
            sscanf(buff, "\tlist %s '%[^']'", key, value);
            if(!strncmp(key, "local_subnet", 12)) strncpy(ike_conn->local_net[cnt_l++], value, IP_LEN);
            else if(!strncmp(key, "remote_subnet", 13)) strncpy(ike_conn->remote_net[cnt_r++], value, IP_LEN);
            else if(!strncmp(key, "local_acl", 9)) strncpy(local_acl[acl_cnt1++], value, IP_LEN);
            else if(!strncmp(key, "remote_acl", 10)) strncpy(remote_acl[acl_cnt2++], value, IP_LEN);
            else if(!strncmp(key, "bypasslan_subnet", 16)) strncpy(ike_conn->bypass_net[bypassnet_cnt++], value, IP_LEN);
        }
    }
    if(is_en) {
        append_res(response, offset, resp_size,
            "IPsec: conn '%s' not found, load-conn failed.\n", ike); 
        ret = -1;
        goto END;
    }
    ike_conn->cnt_l = cnt_l;
    ike_conn->cnt_r = cnt_r;
    ike_conn->bypass_lan = bypassnet_cnt;
    if(!strncmp("ikev2", ike_version, 5)) ike_conn->ike_version = 2;
    else if(!strncmp("main", ike_version, 4)) ike_conn->ike_version = 1;
    else if(!strncmp("aggressive", ike_version, 10)) {
        ike_conn->ike_version = 1;
        ike_conn->ike_aggressive = 1;
    }
    if(-1 == get_ip(local_gateway)) {
        append_res(response, offset, resp_size,
            "IPsec: can't get the ipaddr of '%s': %s\n", local_gateway, strerror(errno));
        ret = -1;
        goto END;
    }
    if(!is_ipaddr(local_gateway)) {
        append_res(response, offset, resp_size,
            "IPsec: '%s' isn't an ip address.\n", local_gateway);
        goto END;
    }

    strncpy(ike_conn->local_addrs, local_gateway, strlen(local_gateway)+1);
    if(!strlen(ike_conn->local_id))
        strncpy( ike_conn->local_id, local_gateway, strlen(local_gateway)+1 );
    if(!strlen(ike_conn->remote_id))
        strncpy( ike_conn->remote_id, ike_conn->remote_addrs, strlen(ike_conn->remote_addrs)+1 );

    ike_conn->child_cnt = acl_cnt1;
    determine_childs(ike_conn, local_acl, remote_acl, response, offset, resp_size);
END:
    for(int i=0; i<MAX_SUBNETS*MAX_SUBNETS; ++i){
        free(local_acl[i]);
        free(remote_acl[i]);
    }
    return ret;
}

char *charon_connect(int action, const char *ike)
{
    size_t resp_size = INITIAL_RESPONSE_SIZE;
    char *response = (char *)calloc(1, resp_size);
    if(!response) {
        fprintf(stderr, "IPsec: calloc failed\n");
        return strdup("calloc() failed.\n");
    }
    size_t offset=0;

    int (*charon_func[4])(vici_conn_t *, IKE_CONN_T *,
                            char **, size_t *, size_t *) = {load_conn, unload_conn,
                                                            terminate_conn, list_sas};

    IKE_CONN_T *ike_conn;
    ike_conn = (IKE_CONN_T *)calloc(1, sizeof(IKE_CONN_T));
    if(!ike_conn) {
        append_res(&response, &offset, &resp_size, "IPsec: calloc() failed.\n");
        goto END;
    }
    for(int i=0; i<MAX_SUBNETS; ++i) {
        ike_conn->local_net[i] = (char *)calloc(1, IP_LEN);
        ike_conn->remote_net[i] = (char *)calloc(1, IP_LEN);
        if(!ike_conn->local_net[i] || !ike_conn->remote_net[i]) {
            append_res(&response, &offset, &resp_size, "IPsec: calloc() failed.\n");
            goto END;
        }
    }
    for(int i=0; i<MAX_BYPASSNETS; ++i) {
        ike_conn->bypass_net[i] = (char *)calloc(1,IP_LEN);
        if(!ike_conn->bypass_net[i]) {
            append_res(&response, &offset, &resp_size, "IPsec: calloc() failed.\n");
            goto END;
        }
    }
    strncpy(ike_conn->name, ike, INSTANCE_LEN);
    if(read_config(ike_conn, ike, &response, &offset, &resp_size)) {
        append_res(&response, &offset, &resp_size, "IPsec: read_config() failed.\n");
        goto END;
    }

    vici_conn_t *conn;
    vici_init(); //connect to charon
    conn = vici_connect(NULL);
    if(conn) {
        charon_func[action](conn, ike_conn, &response, &offset, &resp_size);
        vici_disconnect(conn); // diconnect from charon
    } else
        append_res(&response, &offset, &resp_size,
            "IPsec: connecting to charon failed: %s\n", strerror(errno));
    vici_deinit();
END:
    if(ike_conn) {
        for(int i=0; i<MAX_SUBNETS; ++i) {
            free(ike_conn->local_net[i]);
            free(ike_conn->remote_net[i]);
        }
        for(int i=0; i<MAX_BYPASSNETS; ++i)
            free(ike_conn->bypass_net[i]);
        free(ike_conn);
    }
    return response;
}
