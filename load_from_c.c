#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <libvici.h>

#define INSTANCE_LEN 40
#define IP_LEN 48
#define MAX_SUBNETS 10
#define MAX_CHILD_SA 100

typedef struct child_sa_t {
    char name[INSTANCE_LEN];
    int left;
    int right;
}CHILD_SA_T;

typedef struct ike_conn_t {
    char name[INSTANCE_LEN];
    char local_addrs[IP_LEN];
    char remote_addrs[IP_LEN];
    char local_id[INSTANCE_LEN];
    char remote_id[INSTANCE_LEN];
    int ike_version;
    int ike_aggressive;
    char auth[8];
    char psk[INSTANCE_LEN];
    char ike_proposal[INSTANCE_LEN];
    char ike_rekey[8];
    char dpd_delay[8];
    char dpd_timeout[8];
    char tunnel_mode[12];
    char peer_mode[8];
    char esp_proposal[INSTANCE_LEN];
    char esp_rekey[8];
    char dpd_action[8];
    char start_action[8];
    int cnt_l;
    int cnt_r;
    char *local_net[MAX_SUBNETS];
    char *remote_net[MAX_SUBNETS];
    int child_cnt;
    CHILD_SA_T child_sa[MAX_CHILD_SA];
}IKE_CONN_T;

static int terminate_conn(vici_conn_t *conn, IKE_CONN_T *ike_conn)
{
    vici_req_t *req;
    vici_res_t *res;
    int ret=0;

    fprintf(stderr, "IPsec terminating -%s-\n", ike_conn->name);
    // execl("/bin/bash", "/bin/bash", "-c", "kill -9 $(pgrep -fx \"/bin/bash /usr/share/swanctl/ipsec_functions ping_acl %s\")", ike, (char *)0);

    req = vici_begin("terminate");
    vici_add_key_valuef(req, "ike", "%s", ike_conn->name);
    vici_add_key_valuef(req, "force", "yes");
    vici_add_key_valuef(req, "timeout", "%d", -1 * 1000);
    res = vici_submit(req, conn);
    if(!res){
        fprintf(stderr, "IPsec: terminate request failed: %s\n", strerror(errno));
        return -1;
    }
    if(!strcmp(vici_find_str(res, "no", "success"), "yes")){
        fprintf(stderr, "IPsec: terminate completed successfully\n");
        ret = 0;
    }
    else {
        fprintf(stderr, "IPsec: terminate failed: %s\n", vici_find_str(res, "", "errmsg") );
        ret = -1;
    }
    vici_free_res(res);
    return ret;
}

static int unload_conn(vici_conn_t * conn, IKE_CONN_T *ike_conn)
{
    vici_req_t *req;
    vici_res_t *res;
    int ret = 0;

    req = vici_begin("unload-conn");
    vici_add_key_valuef(req, "name", "%s", ike_conn->name);
    res = vici_submit(req, conn);
    if(!res) {
        fprintf(stderr, "IPsec: unload-conn request failed: %s\n", strerror(errno));
        ret = -1;
    }
    if( !strcmp(vici_find_str(res, "no", "success"), "yes") ){
        fprintf(stderr, "IPsec: unloading connection '%s' completed\n",
                ike_conn->name);
        ret = 0;
    } else {
        fprintf(stderr, "IPsec: unloading connection '%s' failed: %s\n",
                ike_conn->name, vici_find_str(res, "", "errmsg"));
        ret = -1;
    }

    req = vici_begin("unload-shared");
    vici_add_key_valuef(req, "id", "%s", ike_conn->name);
    res = vici_submit(req, conn);
    if(!res) {
        fprintf(stderr, "IPsec: unload-shared request failed: %s\n", strerror(errno));
        return -1;
    }
    if( 0 != strncmp(vici_find_str(res, "no", "success"), "yes", 3) ) {
        fprintf(stderr, "IPsec: unloading shared key '%s' failed: %s\n",
                ike_conn->name, vici_find_str(res, "", "errmsg"));
        ret = -1;
    }
    vici_free_res(res);
    return ret;
}

static int load_conn(vici_conn_t *conn, IKE_CONN_T *ike_conn)
{    
    int ret = 0;
    char buff[64]={'\0'};

    vici_res_t *res;
    vici_req_t *req = vici_begin("load-conn");
    if (!req) {
        fprintf(stderr, "IPsec: Failed to create VICI request\n");
        return -1;
    }
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
    if( 1==ike_conn->ike_aggressive )
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
        if( 0 == strncmp(ike_conn->tunnel_mode, "transport", 9) )
            continue;
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
        fprintf(stderr, "IPsec: load-conn %s request failed: %s\n", ike_conn->name, strerror(errno));
        return -1;
    }
    if( 0 != strcmp(vici_find_str(res, "no", "success"), "yes") ) {
        fprintf(stderr, "IPsec: loading connection '%s' failed: %s\n",
                ike_conn->name, vici_find_str(res, "", "errmsg"));
        ret = -1;
    } else {
        fprintf(stderr, "IPsec: loaded connection '%s'\n", ike_conn->name);
    }

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
        fprintf(stderr, "IPsec: load-shared request failed: %s\n", strerror(errno));
        return -1;
    }
    if( 0 != strcmp(vici_find_str(res, "no", "success"), "yes")) {
        fprintf(stderr, "IPsec: loading shared secret failed: %s\n",
                vici_find_str(res, "", "errmsg"));
        ret = -1;
    } else
        fprintf(stderr, "IPsec: loaded %s secret '%s'\n", "ike", ike_conn->name);

    vici_free_res(res);
    return ret;
}

void parse_addr(struct nlmsghdr *nlh, char *ifname)
{
    struct ifaddrmsg *ifa = NLMSG_DATA(nlh);
    struct rtattr *rta = IFA_RTA(ifa);
    int len = IFA_PAYLOAD(nlh);

    if( strcmp(if_indextoname(ifa->ifa_index, (char[IF_NAMESIZE]){0}), ifname) )
        return;

    for(; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        if (rta->rta_type == IFA_ADDRESS && (ifa->ifa_family == AF_INET || ifa->ifa_family == AF_INET6)) {
            inet_ntop(ifa->ifa_family, RTA_DATA(rta), ifname, INET6_ADDRSTRLEN);
            // fprintf(stderr, "IPsec: %s %s/%d\n", 
            //        ifa->ifa_family == AF_INET ? "inet" : "inet6", 
            //        ifname, 
            //        ifa->ifa_prefixlen);
        }
    }
}

int get_ip(char *intf)
{
    int sockfd, isv6 = 0, len = 0;
    char version_buff[8] = {'\0'}, buf[4096] = {'\0'};
    struct ifreq ifr;

    if( NULL != strstr(intf, "v6"))
        isv6=1;
    else
        isv6=0;

    if( NULL != strstr(intf, "ETH") ){
        int intf_no = intf[3]-49;
        snprintf(intf, 6, "lan%d", intf_no);
    } else if( NULL != strstr(intf, "Cellular") ){
        strncpy(intf, "usb0", 4);
    } 
    // else if(NULL!=strstr(intf, "Any") )
    // to find intf is an ipaddr send it o grepcidr

    sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if(sockfd < 0) {
        perror("socket");
        return -1;
    }

    // Build Netlink request for addresses
    struct {
        struct nlmsghdr nlh;
        struct rtgenmsg rt;
    } req = {
        .nlh = { .nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg)),
                 .nlmsg_type = RTM_GETADDR,
                 .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
                 .nlmsg_seq = 1 },
        .rt = { .rtgen_family = (1==isv6)?AF_INET6:AF_INET } // Both IPv4 and IPv6
    };

    // Send request
    if (send(sockfd, &req, req.nlh.nlmsg_len, 0) < 0) {
        perror("send");
        close(sockfd);
        return 1;
    }

    // Receive and process response
    while( (len = recv(sockfd, buf, sizeof(buf), 0)) > 0 ) {
        for (struct nlmsghdr *nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_type == NLMSG_DONE)
                goto DONE;
            if (nlh->nlmsg_type == RTM_NEWADDR) {
                parse_addr(nlh, intf);
            }
        }
    }

DONE:
    close(sockfd);
    return 0;
}

int check_ip_in_subnet(char* ip, char* subnet) {
    char* subnet_ip = NULL;
    char* prefix_str = NULL;
    int prefix = 0, ret = 0;

    subnet_ip = malloc(48);
    prefix_str = malloc(4);
    if(!subnet_ip || !prefix_str) {
        fprintf(stderr, "IPsec: malloc() failed.\n");
        free(subnet_ip); free(prefix_str);
        return -1;
    }

    for (prefix = 0; prefix < 48 && subnet[prefix] != '\0'; ++prefix) {
        if (subnet[prefix] == '/') {
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
    if (strchr(ip, ':') && strchr(subnet, ':')) { 
        struct in6_addr ip6, subnet6;
        inet_pton(AF_INET6, ip, &ip6);
        inet_pton(AF_INET6, subnet_ip, &subnet6);
        int bytes = prefix / 8;
        int bits = prefix % 8;
        ret = 0;
        if (memcmp(&ip6, &subnet6, bytes) != 0) ret = -1;
        else if (bits > 0) {
            unsigned char mask = 0xFF << (8 - bits);
            if ((ip6.s6_addr[bytes] & mask) != (subnet6.s6_addr[bytes] & mask))
                ret = -1;
        }
    } else if (strchr(ip, '.') && strchr(subnet, '.')) {
        struct in_addr ip4, subnet4;
        inet_pton(AF_INET, ip, &ip4);
        inet_pton(AF_INET, subnet_ip, &subnet4);
        uint32_t ip_num = ntohl(ip4.s_addr);
        uint32_t subnet_num = ntohl(subnet4.s_addr);
        uint32_t mask = prefix == 0 ? 0 : ~((1U << (32 - prefix)) - 1);
        ret = ((ip_num & mask) == (subnet_num & mask)) ? 0 : -1;
    } else 
        ret = -1;

    free(subnet_ip);
    free(prefix_str);
    return ret;
}

void determine_childs(IKE_CONN_T *ike_conn, char **local_acl, char **remote_acl)
{
    for(int i=0, j; i<ike_conn->child_cnt; ++i) {
        for(j=0; j<ike_conn->cnt_l; ++j)
            if( !check_ip_in_subnet(local_acl[i], ike_conn->local_net[j]) )
                break;
        ike_conn->child_sa[i].left=j;
        for(j=0; j<ike_conn->cnt_r; ++j)
            if( !check_ip_in_subnet(remote_acl[i], ike_conn->remote_net[j]) )
                break;
        ike_conn->child_sa[i].right=j;
        snprintf(ike_conn->child_sa[i].name, INSTANCE_LEN+10, "%s_child%d", ike_conn->name, i+1);
        // fprintf(stderr, "IPsec: child_sa=%s-\n", ike_conn->child_sa[i].name);
    }
}

int read_config(IKE_CONN_T *ike_conn, char *ike)
{   
    char is_en = '0';
    char buff[256] = {'\0'}, ike_name[INSTANCE_LEN] = {'\0'},
            local_gateway[IP_LEN] = {'\0'}, ike_version[12] = {'\0'};
    char *local_acl[MAX_CHILD_SA], *remote_acl[MAX_CHILD_SA];
    int cnt_l = 0, cnt_r = 0, acl_cnt1=0, acl_cnt2=0;

    // alloc memory for child_sa
    for(int i=0; i<100; ++i){
        local_acl[i] = (char *)malloc(IP_LEN);
        remote_acl[i] = (char *)malloc(IP_LEN);
        if( !local_acl[i] || !local_acl[i] ) {
            fprintf(stderr, "IPsec: malloc() failed.\n");
            return -1;
        }
    }

    FILE *fp = NULL;
    fp=fopen("/etc/config/ipsec", "r");
    if( NULL == fp ) {
        fprintf(stderr, "IPsec: can't open file '/etc/config/ipsec' %s\n", strerror(errno));
        return -1;
    }
    ike_conn->ike_aggressive = 0;

    while( NULL != fgets(buff, sizeof(buff), fp) ) {
        buff[strlen(buff)-1] = '\0';
        if( !strncmp("config ipsec", buff, 12) )
            sscanf(buff, "config ipsec '%[^']'", ike_name);
        if( strncmp(ike_name, ike, strlen(ike)) ){
            continue;   //conn not found go for next
        }
        if( !strncmp(buff, "\toption ", 8) ) {
            char key[IP_LEN], value[IP_LEN];
            sscanf(buff, "\toption %s '%[^']'", key, value);

            if( strncmp(key, "enabled", 7) == 0 ) {
                is_en=value[0];
                if( !(is_en-48) )
                    continue;   // conn is diabled go for next
            }
            if( strncmp(key, "local_gateway", 13) == 0 ) strncpy(local_gateway, value, IP_LEN);
            else if( strncmp(key, "remote_gateway", 14) == 0 ) strncpy(ike_conn->remote_addrs, value, IP_LEN);
            else if( strncmp(key, "local_identifier", 16) == 0 ) strncpy(ike_conn->local_id, value, INSTANCE_LEN);
            else if( strncmp(key, "remote_identifier", 17) == 0 ) strncpy(ike_conn->remote_id, value, INSTANCE_LEN);
            else if( strncmp(key, "auth_method", 11) == 0 ) strncpy(ike_conn->auth, value, 8);
            else if( strncmp(key, "keyexchange", 11) == 0 ) strncpy(ike_version, value, 6);
            else if( strncmp(key, "preshared_key", 13) == 0 ) strncpy(ike_conn->psk, value, INSTANCE_LEN);
            else if( strncmp(key, "ike_proposal", 12) == 0 ) strncpy(ike_conn->ike_proposal, value, INSTANCE_LEN);
            else if( strncmp(key, "ike_rekeytime", 13) == 0 ) strncpy(ike_conn->ike_rekey, value, 8);
            else if( strncmp(key, "dpddelay", 8) == 0 ) strncpy(ike_conn->dpd_delay, value, 8);
            else if( strncmp(key, "dpdaction", 9) == 0 ) strncpy(ike_conn->dpd_action, value, 8);
            else if( strncmp(key, "esp_proposal", 12) == 0 ) strncpy(ike_conn->esp_proposal, value, INSTANCE_LEN);
            else if( strncmp(key, "esp_rekeytime", 13) == 0 ) strncpy(ike_conn->esp_rekey, value, 8);
            else if( strncmp(key, "tunnel_mode", 11) == 0 ) strncpy(ike_conn->tunnel_mode, value, 12);
            else if( strncmp(key, "peer_mode", 9) == 0 ) {
                strncpy(ike_conn->peer_mode, value, 8);
                if( !strncmp("local", ike_conn->peer_mode, 5) )
                    strncpy(ike_conn->start_action, "trap", 5);
                else if( !strncmp("remote", ike_conn->peer_mode, 6) )
                    strncpy(ike_conn->start_action, "none", 5);
            }
        }
        if( !strncmp(buff, "\tlist ", 6) ) {
            char key[IP_LEN], value[IP_LEN];
            sscanf(buff, "\tlist %s '%[^']'", key, value);

            if( strncmp(key, "local_subnet", 12) == 0 ) strncpy(ike_conn->local_net[cnt_l++], value, IP_LEN);
            else if( strncmp(key, "remote_subnet", 13) == 0 ) strncpy(ike_conn->remote_net[cnt_r++], value, IP_LEN);
            else if( strncmp(key, "local_acl", 9) == 0 ) strncpy(local_acl[acl_cnt1++], value, IP_LEN);
            else if( strncmp(key, "remote_acl", 10) == 0 ) strncpy(remote_acl[acl_cnt2++], value, IP_LEN);
        }
    }
    ike_conn->cnt_l = cnt_l;
    ike_conn->cnt_r = cnt_r;
    if( !strncmp("ikev2", ike_version, 5) )
        ike_conn->ike_version = 2;
    else if( !strncmp("main", ike_version, 4) )
        ike_conn->ike_version = 1;
    else if( !strncmp("aggressive", ike_version, 10) ){
        ike_conn->ike_version = 1;
        ike_conn->ike_aggressive = 1;
    }

    // fprintf(stderr, "IPsec: local_gateway=%s--\n", local_gateway);
    if( -1 == get_ip(local_gateway) ){
        fprintf(stderr, "IPsec: can't get the ipaddr of -%s-=%s-\n", local_gateway, strerror(errno));
        return -1;
    }
    // fprintf(stderr, "IPsec: local_addr=%s--\n", local_gateway);
    strncpy(ike_conn->local_addrs, local_gateway, strlen(local_gateway));

    if( strlen(ike_conn->local_id) <= 0 )
        strncpy( ike_conn->local_id, ike_conn->local_addrs, strlen(ike_conn->local_addrs) );
    if( strlen(ike_conn->remote_id) <= 0 )
        strncpy( ike_conn->remote_id, ike_conn->remote_addrs, strlen(ike_conn->remote_addrs) );

    ike_conn->child_cnt = acl_cnt1;
    determine_childs(ike_conn, local_acl, remote_acl);

    for(int i=0; i<100; ++i){
        free(local_acl[i]);
        free(remote_acl[i]);
    }
    return 0;
}

int charon_connect(int action, char *ike)
{
    int return_flag = 0;

    int (*charon_func[3])(vici_conn_t *, IKE_CONN_T *) = {load_conn, unload_conn, terminate_conn};

    // memory alloc for conn struct
    IKE_CONN_T *ike_conn;
    ike_conn = (IKE_CONN_T *)malloc(1*sizeof(IKE_CONN_T));
    if(NULL == ike_conn){
        fprintf(stderr, "IPsec: malloc() failed.\n");
        return_flag = -1;
        goto END;
    }

    //memory alloc for subnets
    for(int i = 0; i < MAX_SUBNETS; i++) {
        ike_conn->local_net[i] = (char *)malloc(IP_LEN);
        ike_conn->remote_net[i] = (char *)malloc(IP_LEN);
        if(!ike_conn->local_net[i] || !ike_conn->remote_net[i]) {
            fprintf(stderr, "IPsec: malloc() failed.\n");
            return_flag = -1;
            goto END;
        }
    }

    strncpy(ike_conn->name, ike, strlen(ike) );

    if( -1 == read_config(ike_conn, ike) ) {
        return_flag = -1;
        goto END;
    }

    vici_conn_t *conn;

    vici_init(); //connect to charon
    conn = vici_connect(NULL);
    if(conn) {
        charon_func[action](conn, ike_conn);
        vici_disconnect(conn); // diconnect from charon
    } else
        fprintf(stderr, "IPsec: connecting to charon failed: %s\n", strerror(errno));

END:
    vici_deinit();

    if(ike_conn) {
        for(int i = 0; i < MAX_SUBNETS; i++) {
            free(ike_conn->local_net[i]);
            free(ike_conn->remote_net[i]);
        }
        free(ike_conn);
    }

    if(1 == return_flag)
        return -1;
    return 0;
}

int main(int argc, char *argv[])
{
    int action=0;

    if( !strncmp("load", argv[1], 4) ) action=0;
    else if( !strncmp("unload", argv[1], 6) ) action=1;
    else if( !strncmp("terminate", argv[1], 6) ) action=2;
    action=charon_connect(action, argv[2]);
    if(-1==action)
        fprintf(stderr, "IPsec: implementation failed\n");
    return 0;
}
