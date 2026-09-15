// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 MediaTek Inc.
 */
#define MTK_IMPL
#define HAL_NETLINK_IMPL
#define _GNU_SOURCE /* needed for strcasestr */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdbool.h>
#include "wifi_hal.h"

#ifdef HAL_NETLINK_IMPL
#include <errno.h>
#include <netlink/attr.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>
#include<net/if.h>
#endif

#include <ev.h>
#include <wpa_ctrl.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>

#define MAC_ALEN 6

#define MAX_BUF_SIZE 256
#define MAX_CMD_SIZE 256
#define IF_NAME_SIZE 16
#define CONFIG_PREFIX "/nvram/hostapd"
#define ACL_PREFIX "/nvram/hostapd-acl"
#define DENY_PREFIX "/nvram/hostapd-deny"
//#define ACL_PREFIX "/tmp/wifi_acl_list" //RDKB convention
#define SOCK_PREFIX "/var/run/hostapd/wifi"
#define VAP_STATUS_FILE "/nvram/vap-status"
#define ESSID_FILE "/tmp/essid"
#define GUARD_INTERVAL_FILE "/nvram/guard-interval"
#define CHANNEL_STATS_FILE "/tmp/channel_stats"
#define DFS_ENABLE_FILE "/nvram/dfs_enable.txt"
#define VLAN_FILE "/nvram/hostapd.vlan"
#define PSK_FILE "/nvram/hostapd"
#define MCS_FILE "/tmp/MCS"
#define NOACK_MAP_FILE "/tmp/NoAckMap"

#define BRIDGE_NAME "brlan0"

/*
   MAX_APS - Number of all AP available in system
   2x Home AP
   2x Backhaul AP
   2x Guest AP
   2x Secure Onboard AP
   2x Service AP

*/


#define MAX_APS ((MAX_NUM_RADIOS)*(MAX_NUM_VAP_PER_RADIO))
#ifndef AP_PREFIX
#define AP_PREFIX	"wifi"
#endif

#ifndef RADIO_PREFIX
#define RADIO_PREFIX	"wlan"
#endif

#define MAX_ASSOCIATED_STA_NUM 2007     // hostapd default

//Uncomment to enable debug logs
//#define WIFI_DEBUG

#ifdef WIFI_DEBUG
#define wifi_dbg_printf printf
#define WIFI_ENTRY_EXIT_DEBUG printf
#else
#define wifi_dbg_printf(format, args...) printf("")
#define WIFI_ENTRY_EXIT_DEBUG(format, args...) printf("")
#endif

#define HOSTAPD_CONF_0 "/nvram/hostapd0.conf"   //private-wifi-2g
#define HOSTAPD_CONF_1 "/nvram/hostapd1.conf"   //private-wifi-5g
#define HOSTAPD_CONF_4 "/nvram/hostapd4.conf"   //public-wifi-2g
#define HOSTAPD_CONF_5 "/nvram/hostapd5.conf"   //public-wifi-5g
#define DEF_HOSTAPD_CONF_0 "/usr/ccsp/wifi/hostapd0.conf"
#define DEF_HOSTAPD_CONF_1 "/usr/ccsp/wifi/hostapd1.conf"
#define DEF_HOSTAPD_CONF_4 "/usr/ccsp/wifi/hostapd4.conf"
#define DEF_HOSTAPD_CONF_5 "/usr/ccsp/wifi/hostapd5.conf"
#define DEF_RADIO_PARAM_CONF "/usr/ccsp/wifi/radio_param_def.cfg"
#define LM_DHCP_CLIENT_FORMAT   "%63d %17s %63s %63s"

#define HOSTAPD_HT_CAPAB "[LDPC][SHORT-GI-20][SHORT-GI-40][MAX-AMSDU-7935]"

#define BW_FNAME "/nvram/bw_file.txt"

#define PS_MAX_TID 16


#ifdef SINGLE_WIPHY_SUPPORT
#define single_wiphy TRUE
#else
#define single_wiphy FALSE
#endif

static wifi_radioQueueType_t _tid_ac_index_get[PS_MAX_TID] = {
    WIFI_RADIO_QUEUE_TYPE_BE,      /* 0 */
    WIFI_RADIO_QUEUE_TYPE_BK,      /* 1 */
    WIFI_RADIO_QUEUE_TYPE_BK,      /* 2 */
    WIFI_RADIO_QUEUE_TYPE_BE,      /* 3 */
    WIFI_RADIO_QUEUE_TYPE_VI,      /* 4 */
    WIFI_RADIO_QUEUE_TYPE_VI,      /* 5 */
    WIFI_RADIO_QUEUE_TYPE_VO,      /* 6 */
    WIFI_RADIO_QUEUE_TYPE_VO,      /* 7 */
    WIFI_RADIO_QUEUE_TYPE_BE,      /* 8 */
    WIFI_RADIO_QUEUE_TYPE_BK,      /* 9 */
    WIFI_RADIO_QUEUE_TYPE_BK,      /* 10 */
    WIFI_RADIO_QUEUE_TYPE_BE,      /* 11 */
    WIFI_RADIO_QUEUE_TYPE_VI,      /* 12 */
    WIFI_RADIO_QUEUE_TYPE_VI,      /* 13 */
    WIFI_RADIO_QUEUE_TYPE_VO,      /* 14 */
    WIFI_RADIO_QUEUE_TYPE_VO,      /* 15 */
};

typedef unsigned long long  u64;

/* Enum to define WiFi Bands */
typedef enum
{
    band_invalid = -1,
    band_2_4 = 0,
    band_5 = 1,
    band_6 = 2,
} wifi_band;

typedef enum {
    WIFI_MODE_A = 0x01,
    WIFI_MODE_B = 0x02,
    WIFI_MODE_G = 0x04,
    WIFI_MODE_N = 0x08,
    WIFI_MODE_AC = 0x10,
    WIFI_MODE_AX = 0x20,
    WIFI_MODE_BE = 0x40,
} wifi_ieee80211_Mode;

#ifdef WIFI_HAL_VERSION_3

// Return number of elements in array
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)       (sizeof(x) / sizeof(x[0]))
#endif /* ARRAY_SIZE */

#ifndef ARRAY_AND_SIZE
#define ARRAY_AND_SIZE(x)   (x),ARRAY_SIZE(x)
#endif /* ARRAY_AND_SIZE */

#define WIFI_ITEM_STR(key, str)        {0, sizeof(str)-1, (int)key, (intptr_t)str}

typedef struct {
    int32_t         value;
    int32_t         param;
    intptr_t        key;
    intptr_t        data;
} wifi_secur_list;

static int util_unii_5g_centerfreq(const char *ht_mode, int channel);
static int util_unii_6g_centerfreq(const char *ht_mode, int channel);
static int util_get_sec_chan_offset(int channel, const char* ht_mode);
wifi_secur_list *       wifi_get_item_by_key(wifi_secur_list *list, int list_sz, int key);
wifi_secur_list *       wifi_get_item_by_str(wifi_secur_list *list, int list_sz, const char *str);
char *                  wifi_get_str_by_key(wifi_secur_list *list, int list_sz, int key);
static int ieee80211_channel_to_frequency(int chan, wifi_band band);

static wifi_secur_list map_security[] =
{
    WIFI_ITEM_STR(wifi_security_mode_none,                    "None"),
    WIFI_ITEM_STR(wifi_security_mode_wep_64,                  "WEP-64"),
    WIFI_ITEM_STR(wifi_security_mode_wep_128,                 "WEP-128"),
    WIFI_ITEM_STR(wifi_security_mode_wpa_personal,            "WPA-Personal"),
    WIFI_ITEM_STR(wifi_security_mode_wpa_enterprise,          "WPA-Enterprise"),
    WIFI_ITEM_STR(wifi_security_mode_wpa2_personal,           "WPA2-Personal"),
    WIFI_ITEM_STR(wifi_security_mode_wpa2_enterprise,         "WPA2-Enterprise"),
    WIFI_ITEM_STR(wifi_security_mode_wpa_wpa2_personal,       "WPA-WPA2-Personal"),
    WIFI_ITEM_STR(wifi_security_mode_wpa_wpa2_enterprise,     "WPA-WPA2-Enterprise"),
    WIFI_ITEM_STR(wifi_security_mode_wpa3_personal,           "WPA3-Personal"),
    WIFI_ITEM_STR(wifi_security_mode_wpa3_transition,         "WPA3-Personal-Transition"),
    WIFI_ITEM_STR(wifi_security_mode_wpa3_enterprise,         "WPA3-Enterprise")
};

typedef struct {
    char    ssid[MAX_BUF_SIZE];
    char    wpa[MAX_BUF_SIZE];
    char    wpa_key_mgmt[MAX_BUF_SIZE];
    char    wpa_passphrase[MAX_BUF_SIZE];
    char    ap_isolate[MAX_BUF_SIZE];
    char    macaddr_acl[MAX_BUF_SIZE];
    char    bss_transition[MAX_BUF_SIZE];
    char    ignore_broadcast_ssid[MAX_BUF_SIZE];
    char    max_sta[MAX_BUF_SIZE];
} __attribute__((packed)) wifi_vap_cfg_t;

pthread_t pthread_id;
int result = 0, tflag = 0;
wifi_vap_cfg_t vap_info[MAX_NUM_RADIOS*MAX_NUM_VAP_PER_RADIO];
int syn_flag = 0;

wifi_secur_list * wifi_get_item_by_key(wifi_secur_list *list, int list_sz, int key)
{
    wifi_secur_list    *item;
    int                i;

    for (item = list,i = 0;i < list_sz; item++, i++) {
        if ((int)(item->key) == key) {
            return item;
        }
    }

    return NULL;
}

char * wifi_get_str_by_key(wifi_secur_list *list, int list_sz, int key)
{
    wifi_secur_list    *item = wifi_get_item_by_key(list, list_sz, key);

    if (!item) {
        return "";
    }

    return (char *)(item->data);
}

wifi_secur_list * wifi_get_item_by_str(wifi_secur_list *list, int list_sz, const char *str)
{
    wifi_secur_list    *item;
    int                i;

    for (item = list,i = 0;i < list_sz; item++, i++) {
        if (strcmp((char *)(item->data), str) == 0) {
            return item;
        }
    }

    return NULL;
}
#endif /* WIFI_HAL_VERSION_3 */

#ifdef HAL_NETLINK_IMPL
typedef struct {
    int id;
    struct nl_sock* socket;
    struct nl_cb* cb;
} Netlink;

static int mac_addr_aton(unsigned char *mac_addr, char *arg)
{
    unsigned int mac_addr_int[6]={};
    sscanf(arg, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", mac_addr_int+0, mac_addr_int+1, mac_addr_int+2, mac_addr_int+3, mac_addr_int+4, mac_addr_int+5);
    mac_addr[0] = mac_addr_int[0];
    mac_addr[1] = mac_addr_int[1];
    mac_addr[2] = mac_addr_int[2];
    mac_addr[3] = mac_addr_int[3];
    mac_addr[4] = mac_addr_int[4];
    mac_addr[5] = mac_addr_int[5];
    return 0;
}

static void mac_addr_ntoa(char *mac_addr, unsigned char *arg)
{
    unsigned int mac_addr_int[6]={};
    mac_addr_int[0] = arg[0];
    mac_addr_int[1] = arg[1];
    mac_addr_int[2] = arg[2];
    mac_addr_int[3] = arg[3];
    mac_addr_int[4] = arg[4];
    mac_addr_int[5] = arg[5];
    snprintf(mac_addr, 20, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", mac_addr_int[0], mac_addr_int[1],mac_addr_int[2],mac_addr_int[3],mac_addr_int[4],mac_addr_int[5]);
    return;
}

static int ieee80211_frequency_to_channel(int freq)
{
    /* see 802.11-2007 17.3.8.3.2 and Annex J */
    if (freq == 2484)
        return 14;
    /* see 802.11ax D6.1 27.3.23.2 and Annex E */
    else if (freq == 5935)
        return 2;
    else if (freq < 2484)
        return (freq - 2407) / 5;
    else if (freq >= 4910 && freq <= 4980)
        return (freq - 4000) / 5;
    else if (freq < 5950)
        return (freq - 5000) / 5;
    else if (freq <= 45000) /* DMG band lower limit */
        /* see 802.11ax D6.1 27.3.23.2 */
        return (freq - 5950) / 5;
    else if (freq >= 58320 && freq <= 70200)
        return (freq - 56160) / 2160;
    else
        return 0;
}

static int initSock80211(Netlink* nl) {
    nl->socket = nl_socket_alloc();
    if (!nl->socket) {
        fprintf(stderr, "Failing to allocate the  sock\n");
        return -ENOMEM;
    }

    nl_socket_set_buffer_size(nl->socket, 8192, 8192);

    if (genl_connect(nl->socket)) {
        fprintf(stderr, "Failed to connect\n");
        nl_close(nl->socket);
        nl_socket_free(nl->socket);
        return -ENOLINK;
    }

    nl->id = genl_ctrl_resolve(nl->socket, "nl80211");
    if (nl->id< 0) {
        fprintf(stderr, "interface not found.\n");
        nl_close(nl->socket);
        nl_socket_free(nl->socket);
        return -ENOENT;
    }

    nl->cb = nl_cb_alloc(NL_CB_DEFAULT);
    if ((!nl->cb)) {
        fprintf(stderr, "Failed to allocate netlink callback.\n");
        nl_close(nl->socket);
        nl_socket_free(nl->socket);
        return ENOMEM;
    }

    return nl->id;
}

static int nlfree(Netlink *nl)
{
    nl_cb_put(nl->cb);
    nl_close(nl->socket);
    nl_socket_free(nl->socket);
    return 0;
}

static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
    [NL80211_STA_INFO_TX_BITRATE] = { .type = NLA_NESTED },
    [NL80211_STA_INFO_RX_BITRATE] = { .type = NLA_NESTED },
    [NL80211_STA_INFO_TID_STATS] = { .type = NLA_NESTED }
};

static struct nla_policy rate_policy[NL80211_RATE_INFO_MAX + 1] = {
};

static struct nla_policy tid_policy[NL80211_TID_STATS_MAX + 1] = {
};

typedef struct _wifi_channelStats_loc {
    INT array_size;
    INT  ch_number;
    BOOL ch_in_pool;
    INT  ch_noise;
    BOOL ch_radar_noise;
    INT  ch_max_80211_rssi;
    INT  ch_non_80211_noise;
    INT  ch_utilization;
    ULLONG ch_utilization_total;
    ULLONG ch_utilization_busy;
    ULLONG ch_utilization_busy_tx;
    ULLONG ch_utilization_busy_rx;
    ULLONG ch_utilization_busy_self;
    ULLONG ch_utilization_busy_ext;
} wifi_channelStats_t_loc;

typedef struct wifi_device_info {
    INT  wifi_devIndex;
    UCHAR wifi_devMacAddress[6];
    CHAR wifi_devIPAddress[64];
    BOOL wifi_devAssociatedDeviceAuthentiationState;
    INT  wifi_devSignalStrength;
    INT  wifi_devTxRate;
    INT  wifi_devRxRate;
} wifi_device_info_t;

#endif

//For 5g Alias Interfaces
static BOOL priv_flag = TRUE;
static BOOL pub_flag = TRUE;
static BOOL Radio_flag = TRUE;
//wifi_setApBeaconRate(1, beaconRate);

BOOL multiple_set = FALSE;

/* Forward declarations for functions used before their definitions */
static int is_valid_ifname(const char *s);
static int is_valid_mac(const char *s);
INT wifi_halgetRadioExtChannel(CHAR *file, CHAR *Value);

struct params
{
    char * name;
    char * value;
};

static int _syscmd(char *cmd, char *retBuf, int retBufSize)
{
    FILE *f;
    char *ptr = retBuf;
    int bufSize=retBufSize, bufbytes=0, readbytes=0, cmd_ret=0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if((f = popen(cmd, "r")) == NULL) {
        fprintf(stderr,"\npopen %s error\n", cmd);
        return RETURN_ERR;
    }

    while(!feof(f))
    {
        *ptr = 0;
        if(bufSize>=128) {
            bufbytes=128;
        } else {
            bufbytes=bufSize-1;
        }

        fgets(ptr,bufbytes,f);
        readbytes=strlen(ptr);

        if(!readbytes)
            break;

        bufSize-=readbytes;
        ptr += readbytes;
    }
    cmd_ret = pclose(f);
    retBuf[retBufSize-1]=0;
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return cmd_ret >> 8;
}

INT radio_index_to_phy(int radioIndex)
{
    char cmd[128] = {0};
    char buf[64] = {0};
    int phyIndex = 0;
    snprintf(cmd, sizeof(cmd), "ls /tmp | grep wifi%d | cut -d '-' -f1 | tr -d '\n'", radioIndex);
    _syscmd(cmd, buf, sizeof(buf));

    if (strlen(buf) == 0 || strstr(buf, "phy") == NULL) {
        fprintf(stderr, "%s: failed to get phy index with: %d\n", __func__, radioIndex);
        return RETURN_ERR;
    }
    sscanf(buf, "phy%d", &phyIndex);
    
    return phyIndex;      
}

INT wifi_getMaxRadioNumber(INT *max_radio_num)
{
    char cmd[64] = {0};
    char buf[4] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if (single_wiphy)
        snprintf(cmd, sizeof(cmd), "iw list | grep Idx | wc -l");
    else
        snprintf(cmd, sizeof(cmd), "ls /sys/class/ieee80211 | wc -l");
    _syscmd(cmd, buf, sizeof(buf));
    *max_radio_num = strtoul(buf, NULL, 10) > MAX_NUM_RADIOS ? MAX_NUM_RADIOS:strtoul(buf, NULL, 10);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

static int wifi_hostapdRead(char *conf_file, char *param, char *output, int output_size)
{
    FILE *fp;
    char line[MAX_BUF_SIZE];
    size_t param_len;

    if (!conf_file || !param || !output || output_size <= 0)
        return -1;

    fp = fopen(conf_file, "r");
    if (!fp)
        return -1;

    param_len = strlen(param);
    output[0] = '\0';

    while (fgets(line, sizeof(line), fp)) {
        size_t line_len = strlen(line);
        /* strip trailing newline */
        if (line_len > 0 && line[line_len - 1] == '\n')
            line[--line_len] = '\0';

        if (strncmp(line, param, param_len) == 0 && line[param_len] == '=') {
            snprintf(output, output_size, "%s", line + param_len + 1);
            break;
        }
    }

    fclose(fp);
    return 0;
}

static int wifi_hostapdWrite(char *conf_file, struct params *list, int item_count)
{
    FILE *rfp, *wfp;
    char tmp_file[MAX_BUF_SIZE];
    char line[MAX_BUF_SIZE * 2];
    int found[item_count];
    int i;

    if (!conf_file || !list || item_count <= 0)
        return -1;

    memset(found, 0, sizeof(found));

    snprintf(tmp_file, sizeof(tmp_file), "%s.tmp", conf_file);

    wfp = fopen(tmp_file, "w");
    if (!wfp)
        return -1;

    rfp = fopen(conf_file, "r");
    if (rfp) {
        while (fgets(line, sizeof(line), rfp)) {
            int replaced = 0;
            for (i = 0; i < item_count; i++) {
                size_t name_len = strlen(list[i].name);
                if (strncmp(line, list[i].name, name_len) == 0 &&
                    line[name_len] == '=') {
                    fprintf(wfp, "%s=%s\n", list[i].name, list[i].value);
                    found[i] = 1;
                    replaced = 1;
                    break;
                }
            }
            if (!replaced)
                fputs(line, wfp);
        }
        fclose(rfp);
    }

    /* append keys that were not already present */
    for (i = 0; i < item_count; i++) {
        if (!found[i])
            fprintf(wfp, "%s=%s\n", list[i].name, list[i].value);
    }

    if (fflush(wfp) != 0 || fsync(fileno(wfp)) != 0) {
        fclose(wfp);
        unlink(tmp_file);
        return -1;
    }
    fclose(wfp);

    if (rename(tmp_file, conf_file) != 0) {
        unlink(tmp_file);
        return -1;
    }

    return 0;
}

wifi_band wifi_index_to_band(int apIndex)
{
    char cmd[128] = {0};
    char buf[64] = {0};
    char config_file[128] = {0};
    int nl80211_band = 0;
    int i = 0;
    int phyIndex = 0;
    int radioIndex = 0;
    int max_radio_num = 0;
    wifi_band band = band_invalid;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    wifi_getMaxRadioNumber(&max_radio_num);
    radioIndex = apIndex % max_radio_num;
    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
    wifi_hostapdRead(config_file, "op_class", buf, sizeof(buf));
    if (strlen(buf) > 0)
        return band_6;

    memset(buf, 0, sizeof(buf));
    wifi_hostapdRead(config_file, "hw_mode", buf, sizeof(buf));
    if (strncmp(buf, "a", 1) == 0)
        return band_5;
    else
        return band_2_4;

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return band;
}

//For Getting Current Interface Name from corresponding hostapd configuration
static int wifi_GetInterfaceName(int apIndex, char *interface_name)
{
    char config_file[128] = {0};

    if (interface_name == NULL)
        return RETURN_ERR;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
#ifdef DYNAMIC_IF_NAME
    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
    wifi_hostapdRead(config_file, "interface", interface_name, 16);
    if (strlen(interface_name) == 0)
        return RETURN_ERR;
#else
    snprintf(interface_name, 16, "%s%d", AP_PREFIX, apIndex);
#endif
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

// wifi agent will call this function, do not change the parameter
void GetInterfaceName(char *interface_name, char *conf_file)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    wifi_hostapdRead(conf_file,"interface",interface_name, IF_NAME_SIZE);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

static int wifi_hostapdProcessUpdate(int apIndex, struct params *list, int item_count)
{
    char interface_name[16] = {0};
    if (multiple_set == TRUE)
        return RETURN_OK;
    char cmd[MAX_CMD_SIZE]="", output[32]="";
    FILE *fp;
    int i;
    //NOTE RELOAD should be done in ApplySSIDSettings
    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    for(i=0; i<item_count; i++, list++)
    {
        if (snprintf(cmd, sizeof(cmd), "hostapd_cli -i%s SET %s %s",
                     interface_name, list->name, list->value) >= (int)sizeof(cmd))
            return -1;
        if((fp = popen(cmd, "r"))==NULL)
        {
            perror("popen failed");
            return -1;
        }
        if(!fgets(output, sizeof(output), fp) || strncmp(output, "OK", 2))
        {
	    pclose(fp);
            perror("fgets failed");
            return -1;
        }
	pclose(fp);
    }
    return 0;
}

static int wifi_reloadAp(int apIndex)
{
    char interface_name[16] = {0};
    if (multiple_set == TRUE)
        return RETURN_OK;
    char cmd[MAX_CMD_SIZE]="";
    char buf[MAX_BUF_SIZE]="";

    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s reload", interface_name);
    if (_syscmd(cmd, buf, sizeof(buf)) == RETURN_ERR)
        return RETURN_ERR;

    snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s disable", interface_name);
    if (_syscmd(cmd, buf, sizeof(buf)) == RETURN_ERR)
        return RETURN_ERR;

    snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s enable", interface_name);
    if (_syscmd(cmd, buf, sizeof(buf)) == RETURN_ERR)
        return RETURN_ERR;

    return RETURN_OK;
}

INT File_Reading(CHAR *file, char *Value)
{
    FILE *fp = NULL;
    char buf[MAX_CMD_SIZE] = {0};
    int count = 0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if (!file || !Value)
        return RETURN_ERR;

    /* Reject obvious shell metacharacters to prevent command injection */
    {
        size_t i;
        for (i = 0; file[i]; i++) {
            char c = file[i];
            if (c == ';' || c == '|' || c == '&' || c == '`' ||
                c == '$' || c == '>' || c == '<' || c == '\n' || c == '\r')
                return RETURN_ERR;
        }
    }

    fp = popen(file, "r");
    if(fp == NULL)
        return RETURN_ERR;

    if(fgets(buf, sizeof(buf) - 1, fp) != NULL)
    {
        for(count = 0; buf[count] != '\n' && buf[count] != '\0' &&
                        count < MAX_CMD_SIZE - 1; count++)
            ; /* find end */
        buf[count] = '\0';
    }
    /* Use snprintf to avoid overflow into unknown-size caller buffer */
    snprintf(Value, MAX_CMD_SIZE, "%s", buf);
    pclose(fp);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

void wifi_RestartHostapd_2G()
{
    int Public2GApIndex = 4;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    wifi_setApEnable(Public2GApIndex, FALSE);
    wifi_setApEnable(Public2GApIndex, TRUE);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

void wifi_RestartHostapd_5G()
{
    int Public5GApIndex = 5;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    wifi_setApEnable(Public5GApIndex, FALSE);
    wifi_setApEnable(Public5GApIndex, TRUE);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

void wifi_RestartPrivateWifi_2G()
{
    int PrivateApIndex = 0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    wifi_setApEnable(PrivateApIndex, FALSE);
    wifi_setApEnable(PrivateApIndex, TRUE);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

void wifi_RestartPrivateWifi_5G()
{
    int Private5GApIndex = 1;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    wifi_setApEnable(Private5GApIndex, FALSE);
    wifi_setApEnable(Private5GApIndex, TRUE);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
}

/* Allowed bandwidth values — whitelist prevents shell injection via bw_value. */
static int is_valid_bw(const char *bw)
{
    static const char * const allowed[] = {
        "20MHz","40MHz","80MHz","160MHz","320MHz",
        "80+80MHz","Auto",NULL
    };
    int i;
    if (!bw) return 0;
    for (i = 0; allowed[i]; i++)
        if (strcmp(bw, allowed[i]) == 0) return 1;
    return 0;
}

static int writeBandWidth(int radioIndex, char *bw_value)
{
    FILE *rfp, *wfp;
    char tmp_file[128], line[128], key[32];
    int found = 0;

    if (!is_valid_bw(bw_value))
        return RETURN_ERR;

    snprintf(tmp_file, sizeof(tmp_file), "%s.tmp", BW_FNAME);
    snprintf(key, sizeof(key), "SET_BW%d=", radioIndex);

    wfp = fopen(tmp_file, "w");
    if (!wfp)
        return RETURN_ERR;

    rfp = fopen(BW_FNAME, "r");
    if (rfp) {
        while (fgets(line, sizeof(line), rfp)) {
            if (strncmp(line, key, strlen(key)) == 0) {
                fprintf(wfp, "%s%s\n", key, bw_value);
                found = 1;
            } else {
                fputs(line, wfp);
            }
        }
        fclose(rfp);
    }
    if (!found)
        fprintf(wfp, "%s%s\n", key, bw_value);

    fclose(wfp);
    rename(tmp_file, BW_FNAME);
    return RETURN_OK;
}

static int readBandWidth(int radioIndex,char *bw_value)
{
    char buf[MAX_BUF_SIZE] = {0};
    char cmd[MAX_CMD_SIZE] = {0};
    sprintf(cmd,"grep 'SET_BW%d=' %s | sed 's/^.*=//'",radioIndex,BW_FNAME);
    _syscmd(cmd,buf,sizeof(buf));
    if(NULL!=strstr(buf,"20MHz"))
        strcpy(bw_value,"20MHz");
    else if(NULL!=strstr(buf,"40MHz"))
        strcpy(bw_value,"40MHz");
    else if(NULL!=strstr(buf,"80MHz"))
        strcpy(bw_value,"80MHz");
    else if(NULL!=strstr(buf,"160MHz"))
        strcpy(bw_value,"160MHz");
    else if(NULL!=strstr(buf,"320MHz"))
        strcpy(bw_value,"320MHz");
    else
        return RETURN_ERR;
    return RETURN_OK;
}

// Input could be "1Mbps"; "5.5Mbps"; "6Mbps"; "2Mbps"; "11Mbps"; "12Mbps"; "24Mbps"
INT wifi_setApBeaconRate(INT radioIndex,CHAR *beaconRate)
{
    struct params params={'\0'};
    char config_file[MAX_BUF_SIZE] = {0};
    char buf[MAX_BUF_SIZE] = {'\0'};
    size_t rate_len;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if (!beaconRate)
        return RETURN_ERR;
    rate_len = strlen(beaconRate);
    if (rate_len == 0)
        return RETURN_ERR;

    /* Strip trailing "Mbps" suffix (4 chars) into buf safely.
     * Reserve 2 bytes: 1 for the appended "0" digit, 1 for NUL. */
    if (rate_len >= 5) {
        size_t num_len = rate_len - 4;
        if (num_len >= sizeof(buf) - 1)  /* need room for appended "0" */
            return RETURN_ERR;
        memcpy(buf, beaconRate, num_len);
        buf[num_len] = '\0';
    } else {
        if (rate_len >= sizeof(buf) - 1)
            return RETURN_ERR;
        memcpy(buf, beaconRate, rate_len);
        buf[rate_len] = '\0';
    }

    params.name = "beacon_rate";
    /* hostapd config unit is 100 kbps. To convert Mbps to 100kbps, multiply by 10. */
    if (strncmp(buf, "5.5", 3) == 0) {
        snprintf(buf, sizeof(buf), "55");
        params.value = buf;
    } else {
        /* Safe: buf has at least 1 byte of slack guaranteed above */
        size_t cur = strlen(buf);
        buf[cur]     = '0';
        buf[cur + 1] = '\0';
        params.value = buf;
    }

    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radioIndex);
    wifi_hostapdWrite(config_file, &params, 1);
    wifi_hostapdProcessUpdate(radioIndex, &params, 1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT wifi_getApBeaconRate(INT radioIndex, CHAR *beaconRate)
{
    char config_file[128] = {'\0'};
    char temp_output[128] = {'\0'};
    char buf[128] = {'\0'};
    char cmd[128] = {'\0'};
    int rate = 0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == beaconRate)
        return RETURN_ERR;

    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radioIndex);
    wifi_hostapdRead(config_file, "beacon_rate", buf, sizeof(buf));
    // Hostapd unit is 100kbps. To convert to 100kbps to Mbps, the value need to divide 10.
    if(strlen(buf) > 0) {
        if (strncmp(buf, "55", 2) == 0)
            snprintf(temp_output, sizeof(temp_output), "5.5Mbps");
        else {
            rate = strtol(buf, NULL, 10)/10;
            snprintf(temp_output, sizeof(temp_output), "%dMbps", rate);
        }
    } else {
        // config not set, so we would use lowest rate as default
        sprintf(cmd, "hostapd_cli -i wifi%d status | grep supported_rates | sed 's/=/ 0x/' | awk '{print $2}'", radioIndex);
        _syscmd(cmd, buf, sizeof(buf));
        snprintf(temp_output, sizeof(temp_output), "%dMbps", strtol(buf, NULL, 0)*5/10);
    }
    strncpy(beaconRate, temp_output, sizeof(temp_output));
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT wifi_setLED(INT radioIndex, BOOL enable)
{
   return 0;
}
INT wifi_setRadioAutoChannelRefreshPeriod(INT radioIndex, ULONG seconds)
{
   return RETURN_OK;
}
/**********************************************************************************
 *
 *  Wifi Subsystem level function prototypes 
 *
**********************************************************************************/
//---------------------------------------------------------------------------------------------------
//Wifi system api
//Get the wifi hal version in string, eg "2.0.0".  WIFI_HAL_MAJOR_VERSION.WIFI_HAL_MINOR_VERSION.WIFI_HAL_MAINTENANCE_VERSION
INT wifi_getHalVersion(CHAR *output_string)   //RDKB   
{
    if(!output_string)
        return RETURN_ERR;
    snprintf(output_string, 64, "%d.%d.%d", WIFI_HAL_MAJOR_VERSION, WIFI_HAL_MINOR_VERSION, WIFI_HAL_MAINTENANCE_VERSION);

    return RETURN_OK;
}


/* wifi_factoryReset() function */
/**
* @description Clears internal variables to implement a factory reset of the Wi-Fi 
* subsystem. Resets Implementation specifics may dictate some functionality since different hardware implementations may have different requirements.
*
* @param None
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_factoryReset()
{
    char cmd[128];

    /*delete running hostapd conf files*/
    wifi_dbg_printf("\n[%s]: deleting hostapd conf file",__func__);
    sprintf(cmd, "rm -rf /nvram/hostapd*");
    system(cmd);
    system("systemctl restart hostapd.service");

    return RETURN_OK;
}

/* wifi_factoryResetRadios() function */
/**
* @description Restore all radio parameters without touching access point parameters. Resets Implementation specifics may dictate some functionality since different hardware implementations may have different requirements.
*
* @param None
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
*
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_factoryResetRadios()
{
    int max_radio_num = 0;
    wifi_getMaxRadioNumber(&max_radio_num);
    for (int radioIndex = 0; radioIndex < max_radio_num; radioIndex++)
        wifi_factoryResetRadio(radioIndex);

    return RETURN_OK;
}


/* wifi_factoryResetRadio() function */
/**
* @description Restore selected radio parameters without touching access point parameters
*
* @param radioIndex - Index of Wi-Fi Radio channel
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_factoryResetRadio(int radioIndex) 	//RDKB
{
    char cmd[128] = {0};
    char buf[128] = {0};
    int max_radio_num = 0;

    wifi_getMaxRadioNumber(&max_radio_num);
    if (radioIndex < 0 || radioIndex > max_radio_num)
        return RETURN_ERR;

    snprintf(cmd, sizeof(cmd), "systemctl stop hostapd.service");
    _syscmd(cmd, buf, sizeof(buf));

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    snprintf(cmd, sizeof(cmd), "rm /nvram/hostapd%d* %s%d.txt", radioIndex, GUARD_INTERVAL_FILE, radioIndex);
    _syscmd(cmd, buf, sizeof(buf));

    snprintf(cmd, sizeof(cmd), "systemctl start hostapd.service");
    _syscmd(cmd, buf, sizeof(buf));
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

/* wifi_initRadio() function */
/**
* Description: This function call initializes the specified radio.
*  Implementation specifics may dictate the functionality since 
*  different hardware implementations may have different initilization requirements.
* Parameters : radioIndex - The index of the radio. First radio is index 0. 2nd radio is index 1   - type INT
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_initRadio(INT radioIndex)
{
    //TODO: Initializes the wifi subsystem (for specified radio)
    return RETURN_OK;
}
static void macfilter_init()
{
    char count[4]={'\0'};
    char buf[253]={'\0'};
    char tmp[19]={'\0'};
    int dev_count,block,mac_entry=0;
    char res[4]={'\0'};
    char acl_file_path[64] = {'\0'};
    FILE *fp = NULL;
    int index=0;
    char iface[10]={'\0'};
    char config_file[MAX_BUF_SIZE] = {0};


    sprintf(acl_file_path,"/tmp/mac_filter.sh");

    fp=fopen(acl_file_path,"w+");
    if (fp == NULL) {
        fprintf(stderr, "%s: failed to open file %s.\n", __func__, acl_file_path);
        return;
    }
    sprintf(buf,"#!/bin/sh \n");
    fprintf(fp,"%s\n",buf);

    system("chmod 0777 /tmp/mac_filter.sh");

    for(index=0;index<=1;index++)
    {
        sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,index);
        wifi_hostapdRead(config_file, "interface", iface, sizeof(iface));
        sprintf(buf,"syscfg get %dcountfilter",index);
        _syscmd(buf,count,sizeof(count));
        mac_entry=atoi(count);

        sprintf(buf,"syscfg get %dblockall",index);
        _syscmd(buf,res,sizeof(res));
        block = atoi(res);

        //Allow only those macs mentioned in ACL
        if(block==1)
        {
             sprintf(buf,"iptables -N  WifiServices%d\n iptables -I INPUT 21 -j WifiServices%d\n",index,index);
             fprintf(fp,"%s\n",buf);
             for(dev_count=1;dev_count<=mac_entry;dev_count++)
             {
                 sprintf(buf,"syscfg get %dmacfilter%d",index,dev_count);
                 _syscmd(buf,tmp,sizeof(tmp));
                 fprintf(stderr,"MAcs to be Allowed  *%s*  ###########\n",tmp);
                 sprintf(buf,"iptables -I WifiServices%d -m physdev --physdev-in %s -m mac --mac-source %s -j RETURN",index,iface,tmp);
                 fprintf(fp,"%s\n",buf);
             }
             sprintf(buf,"iptables -A WifiServices%d -m physdev --physdev-in %s -m mac ! --mac-source %s -j DROP",index,iface,tmp);
             fprintf(fp,"%s\n",buf);
       }

       //Block all the macs mentioned in ACL
       else if(block==2)
       {
             sprintf(buf,"iptables -N  WifiServices%d\n iptables -I INPUT 21 -j WifiServices%d\n",index,index);
             fprintf(fp,"%s\n",buf);

             for(dev_count=1;dev_count<=mac_entry;dev_count++)
             {
                  sprintf(buf,"syscfg get %dmacfilter%d",index,dev_count);
                  _syscmd(buf,tmp,sizeof(tmp));
                  fprintf(stderr,"MAcs to be blocked  *%s*  ###########\n",tmp);
                  sprintf(buf,"iptables -A WifiServices%d -m physdev --physdev-in %s -m mac --mac-source %s -j DROP",index,iface,tmp);
                  fprintf(fp,"%s\n",buf);
             }
       }
    }
    fclose(fp);
}

// Initializes the wifi subsystem (all radios)
INT wifi_init()                            //RDKB
{
    char interface[MAX_BUF_SIZE]={'\0'};
    char bridge_name[MAX_BUF_SIZE]={'\0'};
    INT len=0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    //Not intitializing macfilter for Turris-Omnia Platform for now
    //macfilter_init();

    system("/usr/sbin/iw reg set US");
    // system("systemctl start hostapd.service");
    sleep(2);//sleep to wait for hostapd to start

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

/* wifi_reset() function */
/**
* Description: Resets the Wifi subsystem.  This includes reset of all AP varibles.
*  Implementation specifics may dictate what is actualy reset since 
*  different hardware implementations may have different requirements.
* Parameters : None
*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous.
* @sideeffect None.
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_reset()
{
    //TODO: resets the wifi subsystem, deletes all APs
    system("systemctl stop hostapd.service");
    sleep(2);
    system("systemctl start hostapd.service");
    sleep(5);
    return RETURN_OK;
}

/* wifi_down() function */
/**
* @description Turns off transmit power for the entire Wifi subsystem, for all radios.
* Implementation specifics may dictate some functionality since 
* different hardware implementations may have different requirements.
*
* @param None
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_down()
{
    //TODO: turns off transmit power for the entire Wifi subsystem, for all radios
    int max_num_radios = 0;
    wifi_getMaxRadioNumber(&max_num_radios);
    for (int radioIndex = 0; radioIndex < max_num_radios; radioIndex++)
        wifi_setRadioEnable(radioIndex, FALSE);

    return RETURN_OK;
}


/* wifi_createInitialConfigFiles() function */
/**
* @description This function creates wifi configuration files. The format
* and content of these files are implementation dependent.  This function call is 
* used to trigger this task if necessary. Some implementations may not need this 
* function. If an implementation does not need to create config files the function call can 
* do nothing and return RETURN_OK.
*
* @param None
*
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
* @execution Synchronous
* @sideeffect None
*
* @note This function must not suspend and must not invoke any blocking system
* calls. It should probably just send a message to a driver event handler task.
*
*/
INT wifi_createInitialConfigFiles()
{
    //TODO: creates initial implementation dependent configuration files that are later used for variable storage.  Not all implementations may need this function.  If not needed for a particular implementation simply return no-error (0)
    return RETURN_OK;
}

// outputs the country code to a max 64 character string
INT wifi_getRadioCountryCode(INT radioIndex, CHAR *output_string)
{
    char interface_name[16] = {0};
    char buf[MAX_BUF_SIZE] = {0}, cmd[MAX_CMD_SIZE] = {0}, *value;
    if(!output_string || (radioIndex >= MAX_NUM_RADIOS))
        return RETURN_ERR;

    if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    sprintf(cmd,"hostapd_cli -i %s status driver | grep country | cut -d '=' -f2", interface_name);
    _syscmd(cmd, buf, sizeof(buf));
    if(strlen(buf) > 0)
        snprintf(output_string, 64, "%s", buf);
    else
        return RETURN_ERR;

    return RETURN_OK;
}

INT wifi_setRadioCountryCode(INT radioIndex, CHAR *CountryCode)
{
    //Set wifi config. Wait for wifi reset to apply
    char str[MAX_BUF_SIZE]={'\0'};
    char cmd[MAX_CMD_SIZE]={'\0'};
    struct params params;
    char config_file[MAX_BUF_SIZE] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(NULL == CountryCode || strlen(CountryCode) >= 32 )
        return RETURN_ERR;

    if (strlen(CountryCode) == 0)
        strcpy(CountryCode, "US");

    params.name = "country_code";
    params.value = CountryCode;
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX, radioIndex);
    int ret = wifi_hostapdWrite(config_file, &params, 1);
    if (ret) {
        WIFI_ENTRY_EXIT_DEBUG("Inside %s: wifi_hostapdWrite() return %d\n"
                ,__func__, ret);
    }

    ret = wifi_hostapdProcessUpdate(radioIndex, &params, 1);
    if (ret) {
        WIFI_ENTRY_EXIT_DEBUG("Inside %s: wifi_hostapdProcessUpdate() return %d\n"
                ,__func__, ret);
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT wifi_getRadioChannelStats2(INT radioIndex, wifi_channelStats2_t *outputChannelStats2)
{
    char interface_name[16] = {0};
    char channel_util_file[64] = {0};
    char cmd[128] =  {0};
    char buf[128] = {0};
    char line[256] = {0};
  	char *param = NULL, *value = NULL;
    unsigned int ActiveTime = 0, BusyTime = 0, TransmitTime = 0;
    unsigned int preActiveTime = 0, preBusyTime = 0, preTransmitTime = 0;
    FILE *f = NULL;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    snprintf(cmd, sizeof(cmd), "iw %s scan | grep signal | awk '{print $2}' | sort -n | tail -n1", interface_name);
    _syscmd(cmd, buf, sizeof(buf));
    outputChannelStats2->ch_Max80211Rssi = strtol(buf, NULL, 10);

    memset(cmd, 0, sizeof(cmd));
    memset(buf, 0, sizeof(buf));
    snprintf(cmd, sizeof(cmd), "iw %s survey dump | grep 'in use' -A6", interface_name);
    if ((f = popen(cmd, "r")) == NULL) {
        wifi_dbg_printf("%s: popen %s error\n", __func__, cmd);
        return RETURN_ERR;
    }

    while (fgets(line, sizeof(line), f) != NULL) {
        param = strtok(line, ":\t");
        value = strtok(NULL, " ");
        if (param == NULL || value == NULL)
            continue;
        if(strstr(param, "frequency") != NULL) {
            outputChannelStats2->ch_Frequency = strtol(value, NULL, 10);
        }
        if(strstr(param, "noise") != NULL) {
            outputChannelStats2->ch_NoiseFloor = strtol(value, NULL, 10);
            outputChannelStats2->ch_Non80211Noise = strtol(value, NULL, 10);
        }
        if(strstr(param, "channel active time") != NULL) {
            ActiveTime = strtol(value, NULL, 10);
        }
        if(strstr(param, "channel busy time") != NULL) {
            BusyTime = strtol(value, NULL, 10);
        }
        if(strstr(param, "channel transmit time") != NULL) {
            TransmitTime = strtol(value, NULL, 10);
        }
    }
    pclose(f);

    // The file should store the last active, busy and transmit time
    snprintf(channel_util_file, sizeof(channel_util_file), "%s%d.txt", CHANNEL_STATS_FILE, radioIndex);
    f = fopen(channel_util_file, "r");
    if (f != NULL) {
        if (fgets(line, sizeof(line), f)) preActiveTime  = strtoul(line, NULL, 10);
        if (fgets(line, sizeof(line), f)) preBusyTime     = strtoul(line, NULL, 10);
        if (fgets(line, sizeof(line), f)) preTransmitTime = strtoul(line, NULL, 10);
        fclose(f);
    }

    if (ActiveTime > preActiveTime) {
        outputChannelStats2->ch_ObssUtil = (BusyTime - preBusyTime)*100/(ActiveTime - preActiveTime);
        outputChannelStats2->ch_SelfBssUtil = (TransmitTime - preTransmitTime)*100/(ActiveTime - preActiveTime);
    } else {
        outputChannelStats2->ch_ObssUtil = 0;
        outputChannelStats2->ch_SelfBssUtil = 0;
    }

    f = fopen(channel_util_file, "w");
    if (f != NULL) {
        fprintf(f, "%u\n%u\n%u\n", ActiveTime, BusyTime, TransmitTime);
        fclose(f);
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

/**********************************************************************************
 *
 *  Wifi radio level function prototypes
 *
**********************************************************************************/

//Get the total number of radios in this wifi subsystem
INT wifi_getRadioNumberOfEntries(ULONG *output) //Tr181
{
    if (NULL == output)
        return RETURN_ERR;
    *output = MAX_NUM_RADIOS;

    return RETURN_OK;
}

//Get the total number of SSID entries in this wifi subsystem 
INT wifi_getSSIDNumberOfEntries(ULONG *output) //Tr181
{
    if (NULL == output)
        return RETURN_ERR;
    *output = MAX_APS;

    return RETURN_OK;
}

//Get the Radio enable config parameter
INT wifi_getRadioEnable(INT radioIndex, BOOL *output_bool)      //RDKB
{
    char interface_name[16] = {0};
    char buf[128] = {0}, cmd[128] = {0};
    int apIndex;
    int max_radio_num = 0;

    if (NULL == output_bool)
        return RETURN_ERR;

    *output_bool = FALSE;

    wifi_getMaxRadioNumber(&max_radio_num);

    if (radioIndex >= max_radio_num)
        return RETURN_ERR;

	/* loop all interface in radio, if any is enable, reture true, else return false */
	for(apIndex=radioIndex; apIndex<MAX_APS; apIndex+=max_radio_num)
	{
		if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
			continue;
		sprintf(cmd, "hostapd_cli -i %s status | grep state | cut -d '=' -f2", interface_name);
		_syscmd(cmd, buf, sizeof(buf));

		if(strncmp(buf, "ENABLED", 7) == 0 || strncmp(buf, "ACS", 3) == 0 ||
			strncmp(buf, "HT_SCAN", 7) == 0 || strncmp(buf, "DFS", 3) == 0) {
			/* return true if any interface is eanble */
			*output_bool = TRUE;
			break;
		}
	}
    return RETURN_OK;
}

INT wifi_setRadioEnable(INT radioIndex, BOOL enable)
{
    char interface_name[16] = {0};
    char cmd[MAX_CMD_SIZE] = {0};
    char buf[MAX_CMD_SIZE] = {0};
    int apIndex, ret;
    int max_radio_num = 0; 
    int phyId = 0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    phyId = radio_index_to_phy(radioIndex);

    wifi_getMaxRadioNumber(&max_radio_num);

    if(enable==FALSE)
    {
        /* disable from max apindex to min, to avoid fail in mbss case */
		for(apIndex=(MAX_APS-max_radio_num+radioIndex); apIndex>=0; apIndex-=max_radio_num)
        {
            if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
                continue;

            //Detaching %s%d from hostapd daemon
            snprintf(cmd, sizeof(cmd), "hostapd_cli -i global raw REMOVE %s", interface_name);
            _syscmd(cmd, buf, sizeof(buf));
            if(strncmp(buf, "OK", 2))
                fprintf(stderr, "Could not detach %s from hostapd daemon", interface_name);

            if (!(apIndex/max_radio_num)) {
                snprintf(cmd, sizeof(cmd), "iw %s del", interface_name);
                _syscmd(cmd, buf, sizeof(buf));
            }
        }
    }
    else
    {
        for(apIndex=radioIndex; apIndex<MAX_APS; apIndex+=max_radio_num)
        {
            if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
                continue;

            snprintf(cmd, sizeof(cmd), "cat %s | grep %s= | cut -d'=' -f2", VAP_STATUS_FILE, interface_name);
            _syscmd(cmd, buf, sizeof(buf));
            if(*buf == '1') {
                if (!(apIndex/max_radio_num)) {
                    if (single_wiphy)
                        snprintf(cmd, sizeof(cmd), "iw phy0 interface add %s type __ap radios %d", interface_name, radioIndex);
                    else
                        snprintf(cmd, sizeof(cmd), "iw phy%d interface add %s type __ap", phyId, interface_name);
                    ret = _syscmd(cmd, buf, sizeof(buf));
                    if ( ret == RETURN_ERR) {
                        fprintf(stderr, "VAP interface creation failed\n");
                        continue;
                    }
                }
                if (single_wiphy)
                    snprintf(cmd, sizeof(cmd), "hostapd_cli -i global raw ADD bss_config=phy0.%d:/nvram/hostapd%d.conf",
                             radioIndex, apIndex);
                else
                    snprintf(cmd, sizeof(cmd), "hostapd_cli -i global raw ADD bss_config=phy%d:/nvram/hostapd%d.conf",
                             phyId, apIndex);
                _syscmd(cmd, buf, sizeof(buf));
                if(strncmp(buf, "OK", 2))
                    fprintf(stderr, "Could not detach %s from hostapd daemon", interface_name);
            }
        }
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Get the Radio enable status
INT wifi_getRadioStatus(INT radioIndex, BOOL *output_bool)	//RDKB
{
    if (NULL == output_bool)
        return RETURN_ERR;

    return wifi_getRadioEnable(radioIndex, output_bool);
}

//Get the Radio Interface name from platform, eg "wlan0"
INT wifi_getRadioIfName(INT radioIndex, CHAR *output_string) //Tr181
{
    if (NULL == output_string || radioIndex>=MAX_NUM_RADIOS || radioIndex<0)
        return RETURN_ERR;
    return wifi_GetInterfaceName(radioIndex, output_string);
}

//Get the maximum PHY bit rate supported by this interface. eg: "216.7 Mb/s", "1.3 Gb/s"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioMaxBitRate(INT radioIndex, CHAR *output_string) //RDKB
{
    // The formula to coculate bit rate is "Subcarriers * Modulation * Coding rate * Spatial stream / (Data interval + Guard interval)"
    // For max bit rate, we should always choose the best MCS
    char mode[64] = {0};
    char channel_bandwidth_str[64] = {0};
    char *tmp = NULL;
    UINT mode_map = 0;
    UINT num_subcarrier = 0;
    UINT code_bits = 0;
    float code_rate = 0;    // use max code rate
    int NSS = 0;
    UINT Symbol_duration = 0;
    UINT GI_duration = 0; 
    wifi_band band = band_invalid;
    wifi_guard_interval_t gi = wifi_guard_interval_auto;
    BOOL enable = FALSE;
    float bit_rate = 0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output_string)
        return RETURN_ERR;

    wifi_getRadioEnable(radioIndex, &enable);
    if (enable == FALSE) {
        snprintf(output_string, 64, "0 Mb/s");
        return RETURN_OK;
    }

    if (wifi_getRadioMode(radioIndex, mode, &mode_map) == RETURN_ERR) {
        fprintf(stderr, "%s: wifi_getRadioMode return error.\n", __func__);
        return RETURN_ERR;
    }

    if (wifi_getGuardInterval(radioIndex, &gi) == RETURN_ERR) {
        fprintf(stderr, "%s: wifi_getGuardInterval return error.\n", __func__);
        return RETURN_ERR;
    }

    if (gi == wifi_guard_interval_3200)
        GI_duration = 32;
    else if (gi == wifi_guard_interval_1600)
        GI_duration = 16;
    else if (gi == wifi_guard_interval_800)
        GI_duration = 8;
    else    // auto, 400
        GI_duration = 4;

    if (wifi_getRadioOperatingChannelBandwidth(radioIndex, channel_bandwidth_str) != RETURN_OK) {
        fprintf(stderr, "%s: wifi_getRadioOperatingChannelBandwidth return error\n", __func__);
        return RETURN_ERR;
    }

    if (strstr(channel_bandwidth_str, "80+80") != NULL)
        strcpy(channel_bandwidth_str, "160");

    if (mode_map & WIFI_MODE_AX) {
        if (strstr(channel_bandwidth_str, "160") != NULL)
            num_subcarrier = 1960;
        else if (strstr(channel_bandwidth_str, "80") != NULL)
            num_subcarrier = 980;
        else if (strstr(channel_bandwidth_str, "40") != NULL)
            num_subcarrier = 468;
        else if (strstr(channel_bandwidth_str, "20") != NULL)
            num_subcarrier = 234;
        code_bits = 10;
        code_rate = (float)5/6;
        Symbol_duration = 128;
    } else if (mode_map & WIFI_MODE_AC) {
        if (strstr(channel_bandwidth_str, "160") != NULL)
            num_subcarrier = 468;
        else if (strstr(channel_bandwidth_str, "80") != NULL)
            num_subcarrier = 234;
        else if (strstr(channel_bandwidth_str, "40") != NULL)
            num_subcarrier = 108;
        else if (strstr(channel_bandwidth_str, "20") != NULL)
            num_subcarrier = 52;
        code_bits = 8;
        code_rate = (float)5/6;
        Symbol_duration = 32;
    } else if (mode_map & WIFI_MODE_N) {
        if (strstr(channel_bandwidth_str, "160") != NULL)
            num_subcarrier = 468;
        else if (strstr(channel_bandwidth_str, "80") != NULL)
            num_subcarrier = 234;
        else if (strstr(channel_bandwidth_str, "40") != NULL)
            num_subcarrier = 108;
        else if (strstr(channel_bandwidth_str, "20") != NULL)
            num_subcarrier = 52;
        code_bits = 6;
        code_rate = (float)3/4;
        Symbol_duration = 32;
    } else if ((mode_map & WIFI_MODE_G || mode_map & WIFI_MODE_B) || mode_map & WIFI_MODE_A) {
        // mode b must run with mode g, so we output mode g bitrate in 2.4 G.
        snprintf(output_string, 64, "65 Mb/s");
        return RETURN_OK;
    } else {
        snprintf(output_string, 64, "0 Mb/s");
        return RETURN_OK;
    }

    // Spatial streams
    if (wifi_getRadioTxChainMask(radioIndex, &NSS) != RETURN_OK) {
        fprintf(stderr, "%s: wifi_getRadioTxChainMask return error\n", __func__);
        return RETURN_ERR;
    }

    // multiple 10 is to align duration unit (0.1 us)
    bit_rate = (num_subcarrier * code_bits * code_rate * NSS) / (Symbol_duration + GI_duration) * 10;
    snprintf(output_string, 64, "%.1f Mb/s", bit_rate);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}
#if 0
INT wifi_getRadioMaxBitRate(INT radioIndex, CHAR *output_string)	//RDKB
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char cmd[64];
    char buf[1024];
    int apIndex;

    if (NULL == output_string) 
        return RETURN_ERR;

    apIndex=(radioIndex==0)?0:1;

    snprintf(cmd, sizeof(cmd), "iwconfig %s | grep \"Bit Rate\" | cut -d':' -f2 | cut -d' ' -f1,2", interface_name);
    _syscmd(cmd,buf, sizeof(buf));

    snprintf(output_string, 64, "%s", buf);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}
#endif


//Get Supported frequency bands at which the radio can operate. eg: "2.4GHz,5GHz"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioSupportedFrequencyBands(INT radioIndex, CHAR *output_string)	//RDKB
{
    wifi_band band = band_invalid;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output_string)
        return RETURN_ERR;

    band = wifi_index_to_band(radioIndex);

    memset(output_string, 0, 10);
    if (band == band_2_4)
        strcpy(output_string, "2.4GHz");
    else if (band == band_5)
        strcpy(output_string, "5GHz");
    else if (band == band_6)
        strcpy(output_string, "6GHz");
    else
        return RETURN_ERR;
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
#if 0
        char buf[MAX_BUF_SIZE]={'\0'};
        char str[MAX_BUF_SIZE]={'\0'};
        char cmd[MAX_CMD_SIZE]={'\0'};
        char *ch=NULL;
        char *ch2=NULL;

        WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
        if (NULL == output_string)
            return RETURN_ERR;


        sprintf(cmd,"grep 'channel=' %s%d.conf",CONFIG_PREFIX,radioIndex);

   		if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
        {
    	    printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
            return RETURN_ERR;
        }
        ch=strchr(buf,'\n');
        *ch='\0';
        ch=strchr(buf,'=');
        if(ch==NULL)
          return RETURN_ERR;


        ch++;

 /* prepend 0 for channel with single digit. for ex, 6 would be 06  */
        strcpy(buf,"0");
       if(strlen(ch) == 1)
           ch=strcat(buf,ch);


       sprintf(cmd,"grep 'interface=' %s%d.conf",CONFIG_PREFIX,radioIndex);

        if(_syscmd(cmd,str,64) ==  RETURN_ERR)
        {
                wifi_dbg_printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
                return RETURN_ERR;
        }


        ch2=strchr(str,'\n');
        //replace \n with \0
        *ch2='\0';
        ch2=strchr(str,'=');
        if(ch2==NULL)
        {
        	wifi_dbg_printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
       		return RETURN_ERR;
        }
        else
         wifi_dbg_printf("%s",ch2+1);


        ch2++;


        sprintf(cmd,"iwlist %s frequency|grep 'Channel %s'",ch2,ch);

        memset(buf,'\0',sizeof(buf));
        if(_syscmd(cmd,buf,sizeof(buf))==RETURN_ERR)
        {
            wifi_dbg_printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
            return RETURN_ERR;
        }
        if (strstr(buf,"2.4") != NULL )
            strcpy(output_string,"2.4GHz");
        else if(strstr(buf,"5.") != NULL )
            strcpy(output_string,"5GHz");
        WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
#endif
}

//Get the frequency band at which the radio is operating, eg: "2.4GHz"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioOperatingFrequencyBand(INT radioIndex, CHAR *output_string) //Tr181
{
    wifi_band band = band_invalid;
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output_string)
        return RETURN_ERR;
    band = wifi_index_to_band(radioIndex);

    if (band == band_2_4) 
        snprintf(output_string, 64, "2.4GHz");
    else if (band == band_5)
        snprintf(output_string, 64, "5GHz");   
    else if (band == band_6)
        snprintf(output_string, 64, "6GHz");

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
#if 0
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char buf[MAX_BUF_SIZE]={'\0'};
    char str[MAX_BUF_SIZE]={'\0'};
    char cmd[MAX_CMD_SIZE]={'\0'};
    char *ch=NULL;
    char *ch2=NULL;
    char ch1[5]="0";

    sprintf(cmd,"grep 'channel=' %s%d.conf",CONFIG_PREFIX,radioIndex);

    if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
    {
        printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
        return RETURN_ERR;
    }

    ch=strchr(buf,'\n');
    *ch='\0';
    ch=strchr(buf,'=');
    if(ch==NULL)
        return RETURN_ERR;
    ch++;

    if(strlen(ch)==1)
    {
        strcat(ch1,ch);

    }
    else
    {
        strcpy(ch1,ch);
    }



    sprintf(cmd,"grep 'interface=' %s%d.conf",CONFIG_PREFIX,radioIndex);
    if(_syscmd(cmd,str,64) ==  RETURN_ERR)
    {
        wifi_dbg_printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
        return RETURN_ERR;
    }


    ch2=strchr(str,'\n');
    //replace \n with \0
    *ch2='\0';
    ch2=strchr(str,'=');
    if(ch2==NULL)
    {
        wifi_dbg_printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
        return RETURN_ERR;
    }
    else
        wifi_dbg_printf("%s",ch2+1);
    ch2++;


    sprintf(cmd,"iwlist %s frequency|grep 'Channel %s'",ch2,ch1);
    memset(buf,'\0',sizeof(buf));
    if(_syscmd(cmd,buf,sizeof(buf))==RETURN_ERR)
    {
        wifi_dbg_printf("\nError %d:%s:%s\n",__LINE__,__func__,__FILE__);
        return RETURN_ERR;
    }


    if(strstr(buf,"2.4")!=NULL)
    {
        strcpy(output_string,"2.4GHz");
    }
    if(strstr(buf,"5.")!=NULL)
    {
        strcpy(output_string,"5GHz");
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
#endif
}

//Get the Supported Radio Mode. eg: "b,g,n"; "n,ac"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioSupportedStandards(INT radioIndex, CHAR *output_string) //Tr181
{
    char cmd[256]={0};
    char buf[128]={0};
    char temp_output[128] = {0};
    wifi_band band;
    int phyId = 0, band_remap = 0, range_remap = 0;;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output_string)
        return RETURN_ERR;

    band = wifi_index_to_band(radioIndex);
    switch (band) {
        case band_2_4:
            band_remap = 1;
            range_remap = 2;
            strcat(temp_output, "b,g,");
        break;
        case band_5:
            band_remap = 2;
            range_remap = 4;
            strcat(temp_output, "a,");
        break;
        case band_6:
            band_remap = 4;
            range_remap = 4;
        break;
    }
    phyId = radio_index_to_phy(radioIndex);
    // ht capabilities
    snprintf(cmd, sizeof(cmd),
             "iw phy%d info | grep 'Band \\|[^PHY|MAC|VHT].Capabilities' | sed -n '/Band %d/,/Band %d/{/Band %d/n;/Band %d/b;p}' | head -n 1 | cut -d ':' -f2 | sed 's/^.//' | tr -d '\\n'",
             phyId, band_remap, range_remap, band_remap, range_remap);
    _syscmd(cmd, buf, sizeof(buf));
    if (strlen(buf) >= 4 && strncmp(buf, "0x00", 4) != 0) {
        strcat(temp_output, "n,");
    }

    // vht capabilities
    if (band == band_5) {
        snprintf(cmd, sizeof(cmd),
                 "iw phy%d info | grep 'Band \\|VHT Capabilities' | sed -n '/Band %d/,/Band %d/{/Band %d/n;/Band %d/b;p}' | cut -d '(' -f2 | cut -c1-10 | tr -d '\\n'",
                 phyId, band_remap, range_remap, band_remap, range_remap);
        _syscmd(cmd, buf, sizeof(buf));
        if (strlen(buf) >= 10 && strncmp(buf, "0x00000000", 10) != 0) {
            strcat(temp_output, "ac,");
        }
    }

    // he capabilities
    snprintf(cmd, sizeof(cmd),
             "iw phy%d info | grep 'Band \\|HE MAC Capabilities' | sed -n '/Band %d/,/Band %d/{/Band %d/n;/Band %d/b;p}' | head -n 2 | tail -n 1 | cut -d '(' -f2 | cut -c1-6 | tr -d '\\n'",
             phyId, band_remap, range_remap, band_remap, range_remap);
    _syscmd(cmd, buf, sizeof(buf));
    if (strlen(buf) >= 6 && strncmp (buf, "0x0000", 6) != 0) {
        strcat(temp_output, "ax,");
    }

    // eht capabilities
    snprintf(cmd, sizeof(cmd),
             "iw phy%d info | grep 'Band \\|EHT MAC Capabilities' | sed -n '/Band %d/,/Band %d/{/Band %d/n;/Band %d/b;p}' | head -n 2 | tail -n 1 | cut -d '(' -f2 | cut -c1-6 | tr -d '\\n'",
             phyId, band_remap, range_remap, band_remap, range_remap);
    _syscmd(cmd, buf, sizeof(buf));
    if (strlen(buf) >= 6 && strncmp (buf, "0x0000", 6) != 0) {
        strcat(temp_output, "be,");
    }

    // Remove the last comma
    if (strlen(temp_output) != 0)
        temp_output[strlen(temp_output)-1] = '\0';
    strncpy(output_string, temp_output, strlen(temp_output));
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Get the radio operating mode, and pure mode flag. eg: "ac"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioStandard(INT radioIndex, CHAR *output_string, BOOL *gOnly, BOOL *nOnly, BOOL *acOnly)	//RDKB
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output_string)
        return RETURN_ERR;

    if (radioIndex == 0) {
        snprintf(output_string, 64, "n");               //"ht" needs to be translated to "n" or others
        *gOnly = FALSE;
        *nOnly = TRUE;
        *acOnly = FALSE;
    } else {
        snprintf(output_string, 64, "ac");              //"vht" needs to be translated to "ac"
        *gOnly = FALSE;
        *nOnly = FALSE;
        *acOnly = FALSE;
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
#if 0
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char buf[64] = {0};
    char config_file[MAX_BUF_SIZE] = {0};

    if ((NULL == output_string) || (NULL == gOnly) || (NULL == nOnly) || (NULL == acOnly)) 
        return RETURN_ERR;

    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radioIndex);
    wifi_hostapdRead(config_file, "hw_mode", buf, sizeof(buf));

    wifi_dbg_printf("\nhw_mode=%s\n",buf);
    if (strlen(buf) == 0) 
    {
        wifi_dbg_printf("\nwifi_hostapdRead returned none\n");
        return RETURN_ERR;
    }
    if(strcmp(buf,"g")==0)
    {
        wifi_dbg_printf("\nG\n");
        *gOnly=TRUE;
        *nOnly=FALSE;
        *acOnly=FALSE;
    }
    else if(strcmp(buf,"n")==0)
    {
        wifi_dbg_printf("\nN\n");
        *gOnly=FALSE;
        *nOnly=TRUE;
        *acOnly=FALSE;
    }
    else if(strcmp(buf,"ac")==0)
    {
        wifi_dbg_printf("\nac\n");
        *gOnly=FALSE;
        *nOnly=FALSE;
        *acOnly=TRUE;
    }
    /* hostapd-5G.conf has "a" as hw_mode */
    else if(strcmp(buf,"a")==0)
    {
        wifi_dbg_printf("\na\n");
        *gOnly=FALSE;
        *nOnly=FALSE;
        *acOnly=FALSE;
    }
    else
        wifi_dbg_printf("\nInvalid Mode %s\n", buf);

    //for a,n mode
    if(radioIndex == 1)
    {
        wifi_hostapdRead(config_file, "ieee80211n", buf, sizeof(buf));
        if(strcmp(buf,"1")==0)
        {
            strncpy(output_string, "n", 1);
            *nOnly=FALSE;
        }
    }

    wifi_dbg_printf("\nReturning from getRadioStandard\n");
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
#endif
}

INT wifi_getRadioMode(INT radioIndex, CHAR *output_string, UINT *pureMode)
{
    char cmd[128] = {0};
    char buf[64] = {0};
    char config_file[64] = {0};
    wifi_band band;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(NULL == output_string || NULL == pureMode)
        return RETURN_ERR;

    // grep all of the ieee80211 protocol config set to 1
    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
    snprintf(cmd, sizeof(cmd), "cat %s | grep -E \"ieee.*=1\" | cut -d '=' -f1 | sed \"s/ieee80211\\.*/\1/\"", config_file);
    _syscmd(cmd, buf, sizeof(buf));

    band = wifi_index_to_band(radioIndex);
    // puremode is a bit map
    *pureMode = 0;
    if (band == band_2_4) {
        strcat(output_string, "b,g");
        *pureMode |= WIFI_MODE_B | WIFI_MODE_G;
        if (strstr(buf, "n") != NULL) {
            strcat(output_string, ",n");
            *pureMode |= WIFI_MODE_N;
        }
        if (strstr(buf, "ax") != NULL) {
            strcat(output_string, ",ax");
            *pureMode |= WIFI_MODE_AX;
        }
        if (strstr(buf, "be") != NULL) {
            strcat(output_string, ",be");
            *pureMode |= WIFI_MODE_BE;
        }
    } else if (band == band_5) {
        strcat(output_string, "a");
        *pureMode |= WIFI_MODE_A;
        if (strstr(buf, "n") != NULL) {
            strcat(output_string, ",n");
            *pureMode |= WIFI_MODE_N;
        }
        if (strstr(buf, "ac") != NULL) {
            strcat(output_string, ",ac");
            *pureMode |= WIFI_MODE_AC;
        }
        if (strstr(buf, "ax") != NULL) {
            strcat(output_string, ",ax");
            *pureMode |= WIFI_MODE_AX;
        }
        if (strstr(buf, "be") != NULL) {
            strcat(output_string, ",be");
            *pureMode |= WIFI_MODE_BE;
        }
    } else if (band == band_6) {
        if (strstr(buf, "ax") != NULL) {
            strcat(output_string, "ax");
            *pureMode |= WIFI_MODE_AX;
        }
        if (strstr(buf, "be") != NULL) {
            strcat(output_string, ",be");
            *pureMode |= WIFI_MODE_BE;
        }
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

// Set the radio operating mode, and pure mode flag.
INT wifi_setRadioChannelMode(INT radioIndex, CHAR *channelMode, BOOL gOnlyFlag, BOOL nOnlyFlag, BOOL acOnlyFlag)	//RDKB
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s_%s_%d_%d:%d\n",__func__,channelMode,nOnlyFlag,gOnlyFlag,__LINE__);  
    if (strcmp (channelMode,"11A") == 0)
    {
        writeBandWidth(radioIndex,"20MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
        printf("\nChannel Mode is 802.11a (5GHz)\n");
    }
    else if (strcmp (channelMode,"11NAHT20") == 0)
    {
        writeBandWidth(radioIndex,"20MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
        printf("\nChannel Mode is 802.11n-20MHz(5GHz)\n");
    }
    else if (strcmp (channelMode,"11NAHT40PLUS") == 0)
    {
        writeBandWidth(radioIndex,"40MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
        printf("\nChannel Mode is 802.11n-40MHz(5GHz)\n");
    }
    else if (strcmp (channelMode,"11NAHT40MINUS") == 0)
    {
        writeBandWidth(radioIndex,"40MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
        printf("\nChannel Mode is 802.11n-40MHz(5GHz)\n");
    }
    else if (strcmp (channelMode,"11ACVHT20") == 0)
    {
        writeBandWidth(radioIndex,"20MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
        printf("\nChannel Mode is 802.11ac-20MHz(5GHz)\n");
    }
    else if (strcmp (channelMode,"11ACVHT40PLUS") == 0)
    {
        writeBandWidth(radioIndex,"40MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
        printf("\nChannel Mode is 802.11ac-40MHz(5GHz)\n");
    }
    else if (strcmp (channelMode,"11ACVHT40MINUS") == 0)
    {
        writeBandWidth(radioIndex,"40MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
        printf("\nChannel Mode is 802.11ac-40MHz(5GHz)\n");
    }
    else if (strcmp (channelMode,"11ACVHT80") == 0)
    {
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"80MHz");
        printf("\nChannel Mode is 802.11ac-80MHz(5GHz)\n");
    }
    else if (strcmp (channelMode,"11ACVHT160") == 0)
    {
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"160MHz");
        printf("\nChannel Mode is 802.11ac-160MHz(5GHz)\n");
    }      
    else if (strcmp (channelMode,"11B") == 0)
    {
        writeBandWidth(radioIndex,"20MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
        printf("\nChannel Mode is 802.11b(2.4GHz)\n");
    }
    else if (strcmp (channelMode,"11G") == 0)
    {
        writeBandWidth(radioIndex,"20MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
        printf("\nChannel Mode is 802.11g(2.4GHz)\n");
    }
    else if (strcmp (channelMode,"11NGHT20") == 0)
    {
        writeBandWidth(radioIndex,"20MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"20MHz");
        printf("\nChannel Mode is 802.11n-20MHz(2.4GHz)\n");
    }
    else if (strcmp (channelMode,"11NGHT40PLUS") == 0)
    {
        writeBandWidth(radioIndex,"40MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
        printf("\nChannel Mode is 802.11n-40MHz(2.4GHz)\n");
    }
    else if (strcmp (channelMode,"11NGHT40MINUS") == 0)
    {
        writeBandWidth(radioIndex,"40MHz");
        wifi_setRadioOperatingChannelBandwidth(radioIndex,"40MHz");
        printf("\nChannel Mode is 802.11n-40MHz(2.4GHz)\n");
    }
    else 
    {
        return RETURN_ERR;
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

// Set the radio operating mode, and pure mode flag.
INT wifi_setRadioMode(INT radioIndex, CHAR *channelMode, UINT pureMode)
{
    int num_hostapd_support_mode = 4;   // n, ac, ax, be
    struct params list[num_hostapd_support_mode];
    char config_file[64] = {0};
    char bandwidth[16] = {0};
    char supported_mode[32] = {0};
    int mode_check_bit = 1 << 3;    // n mode
    bool eht_support = FALSE;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s_%d:%d\n", __func__, channelMode, pureMode, __LINE__);
    // Set radio mode
    list[0].name = "ieee80211n";
    list[1].name = "ieee80211ac";
    list[2].name = "ieee80211ax";
    list[3].name = "ieee80211be";
    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);

    // check the bit map from n to ax, and set hostapd config
    if (pureMode & WIFI_MODE_N)
        list[0].value = "1";
    else
        list[0].value = "0";
    if (pureMode & WIFI_MODE_AC)
        list[1].value = "1";
    else
        list[1].value = "0";
    if (pureMode & WIFI_MODE_AX)
        list[2].value = "1";
    else
        list[2].value = "0";
    if (pureMode & WIFI_MODE_BE)
        list[3].value = "1";
    else
        list[3].value = "0";

    wifi_getRadioSupportedStandards(radioIndex, supported_mode);
    if (strstr(supported_mode, "be") != NULL)
        eht_support = TRUE;

    if (eht_support)
        wifi_hostapdWrite(config_file, list, num_hostapd_support_mode);
    else
        wifi_hostapdWrite(config_file, list, num_hostapd_support_mode-1);

    if (channelMode == NULL || strlen(channelMode) == 0)
        return RETURN_OK;
    // Set bandwidth
    if (strstr(channelMode, "40") != NULL)
        strcpy(bandwidth, "40MHz");
    else if (strstr(channelMode, "80") != NULL)
        strcpy(bandwidth, "80MHz");
    else if (strstr(channelMode, "160") != NULL)
        strcpy(bandwidth, "160MHz");
    else if (strstr(channelMode, "320") != NULL)
        strcpy(bandwidth, "320MHz");
    else    // 11A, 11B, 11G....
        strcpy(bandwidth, "20MHz");

    writeBandWidth(radioIndex, bandwidth);
    wifi_setRadioOperatingChannelBandwidth(radioIndex, bandwidth);

    wifi_reloadAp(radioIndex);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT wifi_setRadioHwMode(INT radioIndex, CHAR *hw_mode) {

    char config_file[64] = {0};
    char buf[64] = {0};
    struct params params = {0};
    wifi_band band = band_invalid;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

    band = wifi_index_to_band(radioIndex);

    if (strncmp(hw_mode, "a", 1) == 0 && (band != band_5 && band != band_6))
        return RETURN_ERR;
    else if ((strncmp(hw_mode, "b", 1) == 0 || strncmp(hw_mode, "g", 1) == 0) && band != band_2_4)
        return RETURN_ERR;
    else if ((strncmp(hw_mode, "a", 1) && strncmp(hw_mode, "b", 1) && strncmp(hw_mode, "g", 1)) || band == band_invalid)
        return RETURN_ERR;

    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radioIndex);
    params.name = "hw_mode";
    params.value = hw_mode;
    wifi_hostapdWrite(config_file, &params, 1);
    wifi_hostapdProcessUpdate(radioIndex, &params, 1);

    if (band == band_2_4) {
        if (strncmp(hw_mode, "b", 1) == 0) {
            wifi_setRadioMode(radioIndex, "20MHz", WIFI_MODE_B);
            snprintf(buf, sizeof(buf), "%s", "1,2,5.5,11");
            wifi_setRadioOperationalDataTransmitRates(radioIndex, buf);
            snprintf(buf, sizeof(buf), "%s", "1,2");
            wifi_setRadioBasicDataTransmitRates(radioIndex, buf);
        } else {
            // We don't set mode here, because we don't know whitch mode should be set (g, n or ax?).

            snprintf(buf, sizeof(buf), "%s", "6,9,12,18,24,36,48,54");
            wifi_setRadioOperationalDataTransmitRates(radioIndex, buf);
            snprintf(buf, sizeof(buf), "%s", "6,12,24");
            wifi_setRadioBasicDataTransmitRates(radioIndex, buf);
        }
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_setNoscan(INT radioIndex, CHAR *noscan)
{
    char config_file[64] = {0};
    struct params params = {0};
    wifi_band band = band_invalid;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

    band = wifi_index_to_band(radioIndex);

    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radioIndex);
    params.name = "noscan";
    params.value = noscan;
    wifi_hostapdWrite(config_file, &params, 1);
    wifi_hostapdProcessUpdate(radioIndex, &params, 1);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Get the list of supported channel. eg: "1-11"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioPossibleChannels(INT radioIndex, CHAR *output_string)	//RDKB
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output_string) 
        return RETURN_ERR;
    char cmd[256] = {0};
    char buf[128] = {0};
    BOOL dfs_enable = false;
    int phyId = 0, band_remap = 0, range_remap = 0;
    wifi_band band = band_invalid;

    band = wifi_index_to_band(radioIndex);
    switch (band) {
        case band_2_4:
            band_remap = 1;
            range_remap = 2;
            break;
        case band_5:
            band_remap = 2;
            range_remap = 4;
            break;
        case band_6:
            band_remap = 4;
            range_remap = 4;
            break;
        default:
            break;
    }
    // Parse possible channel number and separate them with commas.
    wifi_getRadioDfsEnable(radioIndex, &dfs_enable);
    phyId = radio_index_to_phy(radioIndex);
    // Channel 68 and 96 only allow bandwidth 20MHz, so we remove them with their frequency.
    if (dfs_enable)
        snprintf(cmd, sizeof(cmd),
                 "iw phy phy%d info | grep -e '\\*.*MHz .*dBm\\|Band ' | sed -n '/Band %d/,/Band %d/{/Band %d/n;/Band %d/b;p}' | grep -v 'no IR\\|5340\\|5480' | cut -d '[' -f2 | cut -d ']' -f1 | tr '\\n' ',' | sed 's/.$//'",
                 phyId, band_remap, range_remap, band_remap, range_remap);
    else 
        snprintf(cmd, sizeof(cmd),
                 "iw phy phy%d info | grep -e '\\*.*MHz .*dBm\\|Band ' | sed -n '/Band %d/,/Band %d/{/Band %d/n;/Band %d/b;p}' | grep -v 'radar\\|no IR\\|5340\\|5480' | cut -d '[' -f2 | cut -d ']' -f1 | tr '\\n' ',' | sed 's/.$//'",
                 phyId, band_remap, range_remap, band_remap, range_remap);

    _syscmd(cmd,buf,sizeof(buf));
    strncpy(output_string, buf, sizeof(buf));

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Get the list for used channel. eg: "1,6,9,11"
//The output_string is a max length 256 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioChannelsInUse(INT radioIndex, CHAR *output_string)	//RDKB
{
    char interface_name[16] = {0};
    char cmd[128] = {0};
    char buf[128] = {0};
    char config_file[64] = {0};
    int channel = 0;
    int freq = 0;
    int bandwidth = 0;
    int center_freq = 0;
    int center_channel = 0;
    int channel_delta = 0;
    wifi_band band = band_invalid;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

    if (NULL == output_string)
        return RETURN_ERR;

    if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    sprintf(cmd, "iw %s info | grep channel | sed -e 's/[^0-9 ]//g'", interface_name);
    _syscmd(cmd, buf, sizeof(buf));
    if (strlen(buf) == 0) {
        fprintf(stderr, "%s: failed to get channel information from iw.\n", __func__);
        return RETURN_ERR;
    }
    sscanf(buf, "%d %d %d %*d %d", &channel, &freq, &bandwidth, &center_freq);

    if (bandwidth == 20) {
        snprintf(output_string, 256, "%d", channel);
        return RETURN_OK;
    }

    center_channel = ieee80211_frequency_to_channel(center_freq);

    band = wifi_index_to_band(radioIndex);
    if (band == band_2_4 && bandwidth == 40) {
        sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radioIndex);
        memset(buf, 0, sizeof(buf));
        wifi_halgetRadioExtChannel(config_file, buf);       // read ht_capab for HT40+ or -

        if (strncmp(buf, "AboveControlChannel", strlen("AboveControlChannel")) == 0 && channel < 10) {
            snprintf(output_string, 256, "%d,%d", channel, channel+4);
        } else if (strncmp(buf, "BelowControlChannel", strlen("BelowControlChannel")) == 0 && channel > 4) {
            snprintf(output_string, 256, "%d,%d", channel-4, channel);
        } else {
            fprintf(stderr, "%s: invalid channel %d set with %s\n.", __func__, channel, buf);
            return RETURN_ERR;
        }
    } else if (band == band_5 || band == band_6){
        // to minus 20 is an offset, because frequence of a channel have a range. We need to use offset to calculate correct channel.
        // example: bandwidth 80: center is 42 (5210), channels are "36,40,44,48" (5170-5250). The delta should be 6.
        channel_delta = (bandwidth-20)/10;
        memset(output_string, 0, 256);
        for (int i = center_channel-channel_delta; i <= center_channel+channel_delta; i+=4) {
            // If i is not the last channel, we add a comma.
            snprintf(buf, sizeof(buf), "%d%s", i, i==center_channel+channel_delta?"":",");
            strncat(output_string, buf, strlen(buf));
        }
    } else
        return RETURN_ERR;

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
    return RETURN_OK;
}

//Get the running channel number 
INT wifi_getRadioChannel(INT radioIndex,ULONG *output_ulong)	//RDKB
{
    char channel_str[16] = {0};
    char config_file[128] = {0};

    if (output_ulong == NULL)
        return RETURN_ERR;

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
    wifi_hostapdRead(config_file, "channel", channel_str, sizeof(channel_str));

    *output_ulong = strtoul(channel_str, NULL, 10);

    return RETURN_OK;
}


INT wifi_getApChannel(INT apIndex,ULONG *output_ulong) //RDKB
{
    char cmd[1024] = {0}, buf[5] = {0};
    char interface_name[16] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output_ulong)
        return RETURN_ERR;

    if (wifi_getApName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    snprintf(cmd, sizeof(cmd), "iw dev %s info |grep channel | cut -d ' ' -f2", interface_name);
    _syscmd(cmd, buf, sizeof(buf));
    *output_ulong = (strlen(buf) >= 1)? atol(buf): 0;
    if (*output_ulong == 0) {
        return RETURN_ERR;
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Storing the previous channel value
INT wifi_storeprevchanval(INT radioIndex)
{
    char output[8] = {'\0'};
    char config_file[MAX_BUF_SIZE] = {0};
    const char *chanval_file = NULL;
    FILE *fp;
    size_t i;

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
    wifi_hostapdRead(config_file, "channel", output, sizeof(output));

    /* Reject any non-digit characters to prevent injection */
    for (i = 0; i < strlen(output); i++) {
        if (!isdigit((unsigned char)output[i]))
            return RETURN_ERR;
    }

    if (radioIndex == 0)
        chanval_file = "/var/prevchanval2G_AutoChannelEnable";
    else if (radioIndex == 1)
        chanval_file = "/var/prevchanval5G_AutoChannelEnable";
    else
        return RETURN_ERR;

    fp = fopen(chanval_file, "w");
    if (!fp)
        return RETURN_ERR;
    fprintf(fp, "%s\n", output);
    fclose(fp);

    Radio_flag = FALSE;
    return RETURN_OK;
}

//Set the running channel number
INT wifi_setRadioChannel(INT radioIndex, ULONG channel)	//RDKB	//AP only
{
    // We only write hostapd config here
    char str_channel[8]={0};
    char *list_channel;
    char config_file[128] = {0};
    char possible_channels[256] = {0};
    int max_radio_num = 0;
    struct params list = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    // Check valid
    sprintf(str_channel, "%lu", channel);

    wifi_getRadioPossibleChannels(radioIndex, possible_channels);
    list_channel = strtok(possible_channels, ",");
    while(true)
    {
        if(list_channel == NULL) {   // input not in the list
            fprintf(stderr, "%s: Channel %s is not in possible list\n", __func__, str_channel);
            return RETURN_ERR;
        }
        if (strncmp(str_channel, list_channel, strlen(list_channel)) == 0 || strncmp(str_channel, "0", 1) == 0)
            break;
        list_channel = strtok(NULL, ",");
    }

    list.name = "channel";
    list.value = str_channel;
    wifi_getMaxRadioNumber(&max_radio_num);
    for(int i=0; i<=MAX_APS/max_radio_num;i++)
    {
        sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radioIndex+(max_radio_num*i));
        wifi_hostapdWrite(config_file, &list, 1);
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
    return RETURN_OK;
}

INT wifi_setRadioCenterChannel(INT radioIndex, ULONG channel)
{
    struct params list[3];
    char str_idx[16] = {0};
    char supported_mode[32] = {0};
    char config_file[64] = {0};
    int max_num_radios = 0;
    wifi_band band = band_invalid;
    bool eht_support = FALSE;

    band = wifi_index_to_band(radioIndex);
    if (band == band_2_4)
        return RETURN_OK;

    wifi_getRadioSupportedStandards(radioIndex, supported_mode);
    if (strstr(supported_mode, "be") != NULL)
        eht_support = TRUE;

    snprintf(str_idx, sizeof(str_idx), "%lu", channel);
    list[0].name = "vht_oper_centr_freq_seg0_idx";
    list[0].value = str_idx;
    list[1].name = "he_oper_centr_freq_seg0_idx";
    list[1].value = str_idx;
    list[2].name = "eht_oper_centr_freq_seg0_idx";
    list[2].value = str_idx;

    wifi_getMaxRadioNumber(&max_num_radios);
    for(int i=0; i<=MAX_APS/max_num_radios; i++)
    {
        snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex+(max_num_radios*i));
        if (eht_support)
            wifi_hostapdWrite(config_file, list, 3);
        else
            wifi_hostapdWrite(config_file, list, 2);
    }

    return RETURN_OK;
}

//Enables or disables a driver level variable to indicate if auto channel selection is enabled on this radio
//This "auto channel" means the auto channel selection when radio is up. (which is different from the dynamic channel/frequency selection (DFC/DCS))
INT wifi_setRadioAutoChannelEnable(INT radioIndex, BOOL enable) //RDKB
{
    //Set to wifi config only. Wait for wifi reset to apply.
    char buf[256] = {0};
    char str_channel[256] = {0};
    int count = 0;
    ULONG Value = 0;
    FILE *fp = NULL;
    if(enable == TRUE)
    {
        wifi_setRadioChannel(radioIndex,Value);
    }
    return RETURN_OK;
}

INT wifi_getRadioAutoChannelSupported(INT radioIndex, BOOL *output_bool)
{
    if (output_bool == NULL)
        return RETURN_ERR;

    *output_bool = TRUE;

    return RETURN_OK;
}

INT wifi_getRadioDCSSupported(INT radioIndex, BOOL *output_bool) 	//RDKB
{
    if (NULL == output_bool) 
        return RETURN_ERR;
    *output_bool=FALSE;
    return RETURN_OK;
}

INT wifi_getRadioDCSEnable(INT radioIndex, BOOL *output_bool)		//RDKB
{
    if (NULL == output_bool) 
        return RETURN_ERR;
    *output_bool=FALSE;
    return RETURN_OK;
}

INT wifi_setRadioDCSEnable(INT radioIndex, BOOL enable)            //RDKB
{
    //Set to wifi config only. Wait for wifi reset to apply.
    return RETURN_OK;
}

INT wifi_setApEnableOnLine(ULONG wlanIndex,BOOL enable)
{
   return RETURN_OK;
}

INT wifi_factoryResetAP(int apIndex)
{
    char ap_config_file[64] = {0};
    char cmd[128] = {0};
    char buf[128] = {0};
    int max_radio_num = 0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    wifi_setApEnable(apIndex, FALSE);
    sprintf(ap_config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
    sprintf(cmd, "rm %s && sh /lib/rdk/hostapd-init.sh", ap_config_file);
    _syscmd(cmd, buf, sizeof(buf));
    wifi_getMaxRadioNumber(&max_radio_num);
    if (apIndex <= max_radio_num)       // The ap is default radio interface, we should default up it.
        wifi_setApEnable(apIndex, TRUE);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

//To set Band Steering AP group
//To-do
INT wifi_setBandSteeringApGroup(char *ApGroup)
{
    return RETURN_OK;
}

INT wifi_getApDTIMInterval(INT apIndex, INT *dtimInterval)
{
    char config_file[128] = {'\0'};
    char buf[128] = {'\0'};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (dtimInterval == NULL)
        return RETURN_ERR;

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
    wifi_hostapdRead(config_file, "dtime_period", buf, sizeof(buf));

    if (strlen(buf) == 0) {
        *dtimInterval = 2;
    } else {
        *dtimInterval = strtoul(buf, NULL, 10);
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_setApDTIMInterval(INT apIndex, INT dtimInterval)
{
    struct params params={0};
    char config_file[MAX_BUF_SIZE] = {'\0'};
    char buf[MAX_BUF_SIZE] = {'\0'};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (dtimInterval < 1 || dtimInterval > 255) {
        WIFI_ENTRY_EXIT_DEBUG("Invalid dtimInterval: %d\n", dtimInterval);
        return RETURN_ERR;
    }
    
    params.name = "dtim_period";
    snprintf(buf, sizeof(buf), "%d", dtimInterval);
    params.value = buf;

    sprintf(config_file,"%s%d.conf", CONFIG_PREFIX, apIndex);
    wifi_hostapdWrite(config_file, &params, 1);
    wifi_hostapdProcessUpdate(apIndex, &params, 1);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Check if the driver support the Dfs
INT wifi_getRadioDfsSupport(INT radioIndex, BOOL *output_bool) //Tr181
{
    wifi_band band = band_invalid;
    if (NULL == output_bool) 
        return RETURN_ERR;
    *output_bool=FALSE;

    band = wifi_index_to_band(radioIndex);
    if (band == band_5)
        *output_bool = TRUE;
    return RETURN_OK;
}

//The output_string is a max length 256 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
//The value of this parameter is a comma seperated list of channel number
INT wifi_getRadioDCSChannelPool(INT radioIndex, CHAR *output_pool)			//RDKB
{
    if (NULL == output_pool) 
        return RETURN_ERR;
    if (radioIndex==1)
        return RETURN_OK;//TODO need to handle for 5GHz band, i think 
    snprintf(output_pool, 256, "1,2,3,4,5,6,7,8,9,10,11");

    return RETURN_OK;
}

INT wifi_setRadioDCSChannelPool(INT radioIndex, CHAR *pool)			//RDKB
{
    //Set to wifi config. And apply instantly.
    return RETURN_OK;
}

INT wifi_getRadioDCSScanTime(INT radioIndex, INT *output_interval_seconds, INT *output_dwell_milliseconds)
{
    if (NULL == output_interval_seconds || NULL == output_dwell_milliseconds) 
        return RETURN_ERR;
    *output_interval_seconds=1800;
    *output_dwell_milliseconds=40;

    return RETURN_OK;
}

INT wifi_setRadioDCSScanTime(INT radioIndex, INT interval_seconds, INT dwell_milliseconds)
{
    //Set to wifi config. And apply instantly.
    return RETURN_OK;
}

INT wifi_getRadioDfsAtBootUpEnable(INT radioIndex, BOOL *output_bool)	//Tr181
{
    if (output_bool == NULL)
         return RETURN_ERR;
     *output_bool = true;   
    return RETURN_OK;     
}

INT wifi_setRadioDfsAtBootUpEnable(INT radioIndex, BOOL enable)	//Tr181
{
    return RETURN_OK;
}

//Get the Dfs enable status
INT wifi_getRadioDfsEnable(INT radioIndex, BOOL *output_bool)	//Tr181
{
    char buf[16] = {0};
    FILE *f = NULL;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if (output_bool == NULL)
        return RETURN_ERR;

    *output_bool = TRUE;        // default
    f = fopen(DFS_ENABLE_FILE, "r");
    if (f != NULL) {
        fgets(buf, 2, f);
        if (strncmp(buf, "0", 1) == 0)
            *output_bool = FALSE;
        fclose(f);
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Set the Dfs enable status
INT wifi_setRadioDfsEnable(INT radioIndex, BOOL enable)	//Tr181
{
    char config_file[128] = {0};
    FILE *f = NULL;
    struct params params={0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    f = fopen(DFS_ENABLE_FILE, "w");
    if (f == NULL)
        return RETURN_ERR;
    fprintf(f, "%d", enable);
    fclose(f);

    params.name = "acs_exclude_dfs";
    params.value = enable?"0":"1";
    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radioIndex);
    wifi_hostapdWrite(config_file, &params, 1);
    wifi_hostapdProcessUpdate(radioIndex, &params, 1);

    wifi_setRadioIEEE80211hEnabled(radioIndex, enable);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Check if the driver support the AutoChannelRefreshPeriod
INT wifi_getRadioAutoChannelRefreshPeriodSupported(INT radioIndex, BOOL *output_bool) //Tr181
{
    if (NULL == output_bool) 
        return RETURN_ERR;
    *output_bool=FALSE;		//not support

    return RETURN_OK;
}

//Get the ACS refresh period in seconds
INT wifi_getRadioAutoChannelRefreshPeriod(INT radioIndex, ULONG *output_ulong) //Tr181
{
    if (NULL == output_ulong) 
        return RETURN_ERR;
    *output_ulong=300;

    return RETURN_OK;
}

//Set the ACS refresh period in seconds
INT wifi_setRadioDfsRefreshPeriod(INT radioIndex, ULONG seconds) //Tr181
{
    return RETURN_ERR;
}

INT getEHT320ChannelBandwidthSet(int radioIndex, int *BandwidthSet)
{
    int center_channel = 0;
    char config_file[32] = {0};
    char buf[32] = {0};

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
    wifi_hostapdRead(config_file, "eht_oper_centr_freq_seg0_idx", buf, sizeof(buf));

    center_channel = strtoul(buf, NULL, 10);
    center_channel += 1;   // Add 1 to become muiltiple of 16
    if (center_channel % 64 == 32)
        *BandwidthSet = WIFI_CHANNELBANDWIDTH_320_1MHZ;
    else if (center_channel % 64 == 0)
        *BandwidthSet = WIFI_CHANNELBANDWIDTH_320_2MHZ;
    else
        return RETURN_ERR;
    return RETURN_OK;
}

//Get the Operating Channel Bandwidth. eg "20MHz", "40MHz", "80MHz", "80+80", "160"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioOperatingChannelBandwidth(INT radioIndex, CHAR *output_string) //Tr181
{
    char buf[64] = {0};
    char extchannel[128] = {0};
    char config_file[128] = {0};
    BOOL radio_enable = FALSE;
    wifi_band band;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if (NULL == output_string)
        return RETURN_ERR;

    if (wifi_getRadioEnable(radioIndex, &radio_enable) == RETURN_ERR)
        return RETURN_ERR;

    if (radio_enable != TRUE)
        return RETURN_OK;

    band = wifi_index_to_band(radioIndex);
    if (band == band_2_4) {
        wifi_getRadioExtChannel(radioIndex, extchannel);
        if (strncmp(extchannel, "Auto", 4) == 0)    // Auto means that we did not set ht_capab HT40+/-
            snprintf(output_string, 64, "20MHz");
        else
            snprintf(output_string, 64, "40MHz");

    } else {
        snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
        wifi_hostapdRead(config_file, "he_oper_chwidth", buf, sizeof(buf));
        if (strncmp(buf, "0", 1) == 0) {        // Check whether we set central channel
            wifi_hostapdRead(config_file, "he_oper_centr_freq_seg0_idx", buf, sizeof(buf));
            if (strncmp(buf, "0", 1) == 0)
                snprintf(output_string, 64, "20MHz");
            else
                snprintf(output_string, 64, "40MHz");

        } else if (strncmp(buf, "1", 1) == 0)
            snprintf(output_string, 64, "80MHz");
        else if (strncmp(buf, "2", 1) == 0) {
            snprintf(output_string, 64, "160MHz");
            wifi_hostapdRead(config_file, "eht_oper_chwidth", buf, sizeof(buf));
            if (strncmp(buf, "9", 1) == 0) {
                int BandwidthSet = 0;
                if (getEHT320ChannelBandwidthSet(radioIndex, &BandwidthSet) != RETURN_OK)
                    return RETURN_ERR;
                if (BandwidthSet == WIFI_CHANNELBANDWIDTH_320_1MHZ)
                    snprintf(output_string, 64, "320-1MHz");
                else if (BandwidthSet == WIFI_CHANNELBANDWIDTH_320_2MHZ)
                    snprintf(output_string, 64, "320-2MHz");
            }
        }
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

//Set the Operating Channel Bandwidth.
INT wifi_setRadioOperatingChannelBandwidth(INT radioIndex, CHAR *bandwidth) //Tr181	//AP only
{
    char config_file[128];
    char set_value[16];
    char supported_mode[32] = {0};
    struct params params[3];
    int max_radio_num = 0;
    bool eht_support = FALSE;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if(NULL == bandwidth)
        return RETURN_ERR;

    if(strstr(bandwidth,"160") != NULL || strstr(bandwidth,"320") != NULL)
        strcpy(set_value, "2");
    else if(strstr(bandwidth,"80") != NULL)
        strcpy(set_value, "1");
    else if(strstr(bandwidth,"20") != NULL || strstr(bandwidth,"40") != NULL)
        strcpy(set_value, "0");
    else if (strstr(bandwidth, "Auto") != NULL)
        return RETURN_OK;
    else {
        fprintf(stderr, "%s: Invalid Bandwidth %s\n", __func__, bandwidth);
        return RETURN_ERR;
    }

    wifi_getRadioSupportedStandards(radioIndex, supported_mode);
    if (strstr(supported_mode, "be") != NULL)
        eht_support = TRUE;

    params[0].name = "vht_oper_chwidth";
    params[0].value = set_value;
    params[1].name = "he_oper_chwidth";
    params[1].value = set_value;
    params[2].name = "eht_oper_chwidth";
    if (strstr(bandwidth,"320") != NULL)     // We set oper_chwidth to 9 for EHT320
        params[2].value = "9";
    else
        params[2].value = set_value;

    wifi_getMaxRadioNumber(&max_radio_num);
    for(int i=0; i<=MAX_APS/max_radio_num; i++)
    {
        snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex+(max_radio_num*i));
        if (eht_support == TRUE)
            wifi_hostapdWrite(config_file, params, 3);
        else
            wifi_hostapdWrite(config_file, params, 2);
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Getting current radio extension channel
INT wifi_halgetRadioExtChannel(CHAR *file,CHAR *Value)
{
    CHAR buf[150] = {0};
    CHAR cmd[150] = {0};
    sprintf(cmd,"%s%s%s","cat ",file," | grep -w ht_capab=");
    _syscmd(cmd, buf, sizeof(buf));
    if(NULL != strstr(buf,"HT40+"))
        strcpy(Value,"AboveControlChannel");
    else if(NULL != strstr(buf,"HT40-"))
        strcpy(Value,"BelowControlChannel");
    return RETURN_OK;
}

//Get the secondary extension channel position, "AboveControlChannel" or "BelowControlChannel". (this is for 40MHz and 80MHz bandwith only)
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioExtChannel(INT radioIndex, CHAR *output_string) //Tr181
{
    char config_file[64] = {0};
    wifi_band band;

    if (output_string == NULL)
        return RETURN_ERR;

    band = wifi_index_to_band(radioIndex);
    if (band == band_invalid)
        return RETURN_ERR;

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);

    snprintf(output_string, 64, "Auto");
    wifi_halgetRadioExtChannel(config_file, output_string);

    return RETURN_OK;
}

// This function handle 20MHz to remove HT40+/- in hostapd config, other bandwidths are handled in wifi_setRadioExtChannel.
INT wifi_RemoveRadioExtChannel(INT radioIndex, CHAR *ext_str)
{
    struct params params={0};
    char config_file[64] = {0};
    char ht_capab[128]={0};
    char buf[128] = {0};
    char cmd[128] = {0};
    int max_radio_num =0;
    bool stbcEnable = FALSE;

    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radioIndex);
    snprintf(cmd, sizeof(cmd), "cat %s | grep STBC", config_file);
    _syscmd(cmd, buf, sizeof(buf));
    if (strlen(buf) != 0)
        stbcEnable = TRUE;

    strcpy(ht_capab, HOSTAPD_HT_CAPAB);
    params.value = ht_capab;
    params.name = "ht_capab";

    wifi_getMaxRadioNumber(&max_radio_num);
    for(int i=0; i<=MAX_APS/max_radio_num; i++)
    {
        sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radioIndex+(max_radio_num*i));
        wifi_hostapdWrite(config_file, &params, 1);
    }
    wifi_setRadioSTBCEnable(radioIndex, stbcEnable);
    return RETURN_OK;
}

//Set the extension channel.
INT wifi_setRadioExtChannel(INT radioIndex, CHAR *string) //Tr181	//AP only
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    struct params params={0};
    char config_file[64] = {0};
    char ext_channel[128]={0};
    char buf[128] = {0};
    char cmd[128] = {0};
    int max_radio_num =0, ret = 0, bandwidth = 0;
    unsigned long channel = 0;
    bool stbcEnable = FALSE;
    params.name = "ht_capab";
    wifi_band band;

    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radioIndex);
    snprintf(cmd, sizeof(cmd), "cat %s | grep STBC", config_file);
    _syscmd(cmd, buf, sizeof(buf));
    if (strlen(buf) != 0)
        stbcEnable = TRUE;

    // readBandWidth get empty file will return error, that means we don't set new bandwidth
    if (readBandWidth(radioIndex, buf) != RETURN_OK) {
        // Get current bandwidth
        if (wifi_getRadioOperatingChannelBandwidth(radioIndex, buf) != RETURN_OK)
            return RETURN_ERR;
    }
    bandwidth = strtol(buf, NULL, 10);
    // TDK expected to get error with 20MHz
    // we handle 20MHz in function wifi_RemoveRadioExtChannel().
    if (bandwidth == 20 || strstr(buf, "80+80") != NULL)
        return RETURN_ERR;

    band = wifi_index_to_band(radioIndex);
    if (band == band_invalid)
        return RETURN_ERR;

    if (wifi_getRadioChannel(radioIndex, &channel) != RETURN_OK)
        return RETURN_ERR;

    snprintf(buf, sizeof(buf), "HT%d", bandwidth);
    ret = util_get_sec_chan_offset(channel, buf);
    if (ret == -EINVAL)
        return RETURN_ERR;

    if(NULL!= strstr(string,"Above")) {
        if ((band == band_2_4 && channel > 9) || (band == band_5 && ret == -1))
            return RETURN_OK;
        strcpy(ext_channel, HOSTAPD_HT_CAPAB "[HT40+]");
    } else if(NULL!= strstr(string,"Below")) {
        if ((band == band_2_4 && channel < 5) || (band == band_5 && ret == 1))
            return RETURN_OK;
        strcpy(ext_channel, HOSTAPD_HT_CAPAB "[HT40-]");
    } else {
        fprintf(stderr, "%s: unknow extchannel %s\n", __func__, string);
        return RETURN_ERR;
    }

    params.value = ext_channel;

    wifi_getMaxRadioNumber(&max_radio_num);
    for(int i=0; i<=MAX_APS/max_radio_num; i++)
    {
        sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,radioIndex+(max_radio_num*i));
        wifi_hostapdWrite(config_file, &params, 1);
    }
    wifi_setRadioSTBCEnable(radioIndex, stbcEnable);

    //Set to wifi config only. Wait for wifi reset or wifi_pushRadioChannel to apply.
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Get the guard interval value. eg "400nsec" or "800nsec"
//The output_string is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioGuardInterval(INT radioIndex, CHAR *output_string)	//Tr181
{
    wifi_guard_interval_t GI;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if (output_string == NULL || wifi_getGuardInterval(radioIndex, &GI) == RETURN_ERR)
        return RETURN_ERR;

    if (GI == wifi_guard_interval_400)
        strcpy(output_string, "400nsec");
    else if (GI == wifi_guard_interval_800)
        strcpy(output_string, "800nsec");
    else if (GI == wifi_guard_interval_1600)
        strcpy(output_string, "1600nsec");
    else if (GI == wifi_guard_interval_3200)
        strcpy(output_string, "3200nsec");
    else
        strcpy(output_string, "Auto");

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Set the guard interval value.
INT wifi_setRadioGuardInterval(INT radioIndex, CHAR *string)	//Tr181
{
    wifi_guard_interval_t GI;
    int ret = 0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if (strcmp(string, "400nsec") == 0)
        GI = wifi_guard_interval_400;
    else if (strcmp(string , "800nsec") == 0)
        GI = wifi_guard_interval_800;
    else if (strcmp(string , "1600nsec") == 0)
        GI = wifi_guard_interval_1600;
    else if (strcmp(string , "3200nsec") == 0)
        GI = wifi_guard_interval_3200;
    else
        GI = wifi_guard_interval_auto;

    ret = wifi_setGuardInterval(radioIndex, GI);

    if (ret == RETURN_ERR) {
        wifi_dbg_printf("%s: wifi_setGuardInterval return error\n", __func__);
        return RETURN_ERR;
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Get the Modulation Coding Scheme index, eg: "-1", "1", "15"
INT wifi_getRadioMCS(INT radioIndex, INT *output_int) //Tr181
{
    char buf[32]={0};
    char mcs_file[64] = {0};
    char cmd[64] = {0};
    int mode_bitmap = 0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(output_int == NULL)
        return RETURN_ERR;
    snprintf(mcs_file, sizeof(mcs_file), "%s%d.txt", MCS_FILE, radioIndex);

    snprintf(cmd, sizeof(cmd), "cat %s 2> /dev/null", mcs_file);
    _syscmd(cmd, buf, sizeof(buf));
    if (strlen(buf) > 0)
        *output_int = strtol(buf, NULL, 10);
    else {
        // output the max MCS for the current radio mode
        if (wifi_getRadioMode(radioIndex, buf, &mode_bitmap) == RETURN_ERR) {
            wifi_dbg_printf("%s: wifi_getradiomode return error.\n", __func__);
            return RETURN_ERR;
        }
        if (mode_bitmap & WIFI_MODE_AX) {
            *output_int = 11;
        } else if (mode_bitmap & WIFI_MODE_AC) {
            *output_int = 9;
        } else if (mode_bitmap & WIFI_MODE_N) {
            *output_int = 7;
        }
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

//Set the Modulation Coding Scheme index
INT wifi_setRadioMCS(INT radioIndex, INT MCS) //Tr181
{
    // Only HE mode can specify MCS capability. We don't support MCS in HT mode, because that would be ambiguous (MCS code 8~11 refer to 2 NSS in HT but 1 NSS in HE adn VHT).
    char config_file[64] = {0};
    char set_value[16] = {0};
    char mcs_file[32] = {0};
    wifi_band band = band_invalid;
    struct params set_config = {0};
    FILE *f = NULL;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);

    // -1 means auto
    if (MCS > 15 || MCS < -1) {
        fprintf(stderr, "%s: invalid MCS %d\n", __func__, MCS);
        return RETURN_ERR;
    }

    if (MCS > 9 || MCS == -1)
        strcpy(set_value, "2");
    else if (MCS > 7)
        strcpy(set_value, "1");
    else
        strcpy(set_value, "0");

    set_config.name = "he_basic_mcs_nss_set";
    set_config.value = set_value;

    wifi_hostapdWrite(config_file, &set_config, 1);
    wifi_hostapdProcessUpdate(radioIndex, &set_config, 1);

    // For pass tdk test, we need to record last MCS setting. No matter whether it is effective or not.
    snprintf(mcs_file, sizeof(mcs_file), "%s%d.txt", MCS_FILE, radioIndex);
    f = fopen(mcs_file, "w");
    if (f == NULL) {
        fprintf(stderr, "%s: fopen failed\n", __func__);
        return RETURN_ERR;
    }
    fprintf(f, "%d", MCS);
    fclose(f);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Get supported Transmit Power list, eg : "0,25,50,75,100"
//The output_list is a max length 64 octet string that is allocated by the RDKB code.  Implementations must ensure that strings are not longer than this.
INT wifi_getRadioTransmitPowerSupported(INT radioIndex, CHAR *output_list) //Tr181
{
        if (NULL == output_list)
                return RETURN_ERR;
        snprintf(output_list, 64,"0,12,25,50,75,100");
        return RETURN_OK;
}

// Get current Transmit Power in percent
INT wifi_getRadioTransmitPower(INT radioIndex, ULONG *output_ulong)	//RDKB
{
    char cmd[128]={'\0'};
    char buf[128]={'\0'};
    int phyIndex = -1;
    bool enabled = false;
    int cur_tx_dbm = 0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if(output_ulong == NULL)
        return RETURN_ERR;

    phyIndex = radio_index_to_phy(radioIndex);

    // Get the maximum tx power of the device
    if (single_wiphy)
        snprintf(cmd, sizeof(cmd), "cat /sys/kernel/debug/ieee80211/phy0/mt76/band%d/txpower_info | "
                                   "grep 'Percentage Control:' | awk '{print $3}' | tr -d '\\n'", radioIndex);
    else
        snprintf(cmd, sizeof(cmd), "cat /sys/kernel/debug/ieee80211/phy%d/mt76/txpower_info | "
                                   "grep 'Percentage Control:' | awk '{print $3}' | tr -d '\\n'", phyIndex);
    _syscmd(cmd, buf, sizeof(buf));
    if (strcmp(buf, "enable") == 0)
        enabled = true;

    if (!enabled) {
        *output_ulong = 100;
        return RETURN_OK;
    }

    memset(cmd, 0, sizeof(cmd));
    memset(buf, 0, sizeof(buf));
    if (single_wiphy)
        snprintf(cmd, sizeof(cmd), "cat /sys/kernel/debug/ieee80211/phy0/mt76/band%d/txpower_info | "
                                   "grep 'Power Drop:' | awk '{print $3}' | tr -d '\\n'", radioIndex);
    else
        snprintf(cmd, sizeof(cmd),  "cat /sys/kernel/debug/ieee80211/phy%d/mt76/txpower_info | "
                                    "grep 'Power Drop:' | awk '{print $3}' | tr -d '\\n'", phyIndex);
    _syscmd(cmd, buf, sizeof(buf));
    cur_tx_dbm = strtol(buf, NULL, 10);

    switch (cur_tx_dbm) {
        case 0:
            *output_ulong = 100; // range 91-100
            break;
        case 1:
            *output_ulong = 75;  // range 61-90
            break;
        case 3:
            *output_ulong = 50;  // range 31-60
            break;
        case 6:
            *output_ulong = 25;  // range 16-30
            break;
        case 9:
            *output_ulong = 12; // range 10-15
            break;
        case 12:
            *output_ulong = 6;  // range 1-9
            break;
        default:
            *output_ulong = 100; // 0
    }

    return RETURN_OK;
}

// TransmitPower: the the percentage relative to the maximum power,
// only support 0,12,25,50,75,100, But 0 means disable Power limit,
// so the power is 100%
INT wifi_setRadioTransmitPower(INT radioIndex, ULONG TransmitPower)	//RDKB
{
    char interface_name[16] = {0};
    char *support;
    char cmd[128]={0};
    char buf[128]={0};
    char txpower_str[64] = {0};
    int phyId = 0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;

    // Get the Tx power supported list and check that is the input in the list
    snprintf(txpower_str, sizeof(txpower_str), "%lu", TransmitPower);
    wifi_getRadioTransmitPowerSupported(radioIndex, buf);
    support = strtok(buf, ",");
    while(true)
    {
        if(support == NULL) {   // input not in the list
            wifi_dbg_printf("Input value is invalid.\n");
            return RETURN_ERR;
        }
        if (strncmp(txpower_str, support, strlen(support)) == 0) {
            break;
        }
        support = strtok(NULL, ",");
    }

    phyId = radio_index_to_phy(radioIndex);
    if (single_wiphy)
        snprintf(cmd, sizeof(cmd),  "echo %lu > /sys/kernel/debug/ieee80211/phy0/mt76/band%d/txpower_level",
                 TransmitPower, radioIndex);
    else
        snprintf(cmd, sizeof(cmd),  "echo %lu > /sys/kernel/debug/ieee80211/phy%d/mt76/txpower_level",
                 TransmitPower, phyId);
    _syscmd(cmd, buf, sizeof(buf));

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

//get 80211h Supported.  80211h solves interference with satellites and radar using the same 5 GHz frequency band
INT wifi_getRadioIEEE80211hSupported(INT radioIndex, BOOL *Supported)  //Tr181
{
    if (NULL == Supported) 
        return RETURN_ERR;
    *Supported = TRUE;

    return RETURN_OK;
}

//Get 80211h feature enable
INT wifi_getRadioIEEE80211hEnabled(INT radioIndex, BOOL *enable) //Tr181
{
    char buf[64]={'\0'};
    char config_file[64] = {'\0'};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(enable == NULL)
        return RETURN_ERR;

    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radioIndex);
    wifi_hostapdRead(config_file, "ieee80211h", buf, sizeof(buf));

    if (strncmp(buf, "1", 1) == 0)
        *enable = TRUE;
    else
        *enable = FALSE;

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Set 80211h feature enable
INT wifi_setRadioIEEE80211hEnabled(INT radioIndex, BOOL enable)  //Tr181
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    struct params params={'\0'};
    char config_file[MAX_BUF_SIZE] = {0};

    params.name = "ieee80211h";

    if (enable) {
        params.value = "1";
    } else {
        params.value = "0";
    }

    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radioIndex);
    wifi_hostapdWrite(config_file, &params, 1);
    
    wifi_hostapdProcessUpdate(radioIndex, &params, 1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Indicates the Carrier Sense ranges supported by the radio. It is measured in dBm. Refer section A.2.3.2 of CableLabs Wi-Fi MGMT Specification.
INT wifi_getRadioCarrierSenseThresholdRange(INT radioIndex, INT *output)  //P3
{
    if (NULL == output)
        return RETURN_ERR;
    *output=100;

    return RETURN_OK;
}

//The RSSI signal level at which CS/CCA detects a busy condition. This attribute enables APs to increase minimum sensitivity to avoid detecting busy condition from multiple/weak Wi-Fi sources in dense Wi-Fi environments. It is measured in dBm. Refer section A.2.3.2 of CableLabs Wi-Fi MGMT Specification.
INT wifi_getRadioCarrierSenseThresholdInUse(INT radioIndex, INT *output)	//P3
{
    if (NULL == output)
        return RETURN_ERR;
    *output = -99;

    return RETURN_OK;
}

INT wifi_setRadioCarrierSenseThresholdInUse(INT radioIndex, INT threshold)	//P3
{
    return RETURN_ERR;
}


//Time interval between transmitting beacons (expressed in milliseconds). This parameter is based ondot11BeaconPeriod from [802.11-2012].
INT wifi_getRadioBeaconPeriod(INT radioIndex, UINT *output)
{
    char interface_name[16] = {0};
    char cmd[MAX_BUF_SIZE]={'\0'};
    char buf[MAX_CMD_SIZE]={'\0'};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(output == NULL)
        return RETURN_ERR;

    if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    snprintf(cmd, sizeof(cmd),  "hostapd_cli -i %s status | grep beacon_int | cut -d '=' -f2 | tr -d '\n'", interface_name);
    _syscmd(cmd, buf, sizeof(buf));
    *output = atoi(buf);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}
 
INT wifi_setRadioBeaconPeriod(INT radioIndex, UINT BeaconPeriod)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    struct params params={'\0'};
    char buf[MAX_BUF_SIZE] = {'\0'};
    char config_file[MAX_BUF_SIZE] = {'\0'};

    if (BeaconPeriod < 15 || BeaconPeriod > 65535)
        return RETURN_ERR;

    params.name = "beacon_int";
    snprintf(buf, sizeof(buf), "%u", BeaconPeriod);
    params.value = buf;

    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radioIndex);
    wifi_hostapdWrite(config_file, &params, 1);
    
    wifi_hostapdProcessUpdate(radioIndex, &params, 1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Comma-separated list of strings. The set of data rates, in Mbps, that have to be supported by all stations that desire to join this BSS. The stations have to be able to receive and transmit at each of the data rates listed inBasicDataTransmitRates. For example, a value of "1,2", indicates that stations support 1 Mbps and 2 Mbps. Most control packets use a data rate in BasicDataTransmitRates.
INT wifi_getRadioBasicDataTransmitRates(INT radioIndex, CHAR *output)
{
    //TODO: need to revisit below implementation
    char *temp;
    char temp_output[128] = {0};
    char temp_TransmitRates[64] = {0};
    char config_file[64] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output)
        return RETURN_ERR;
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,radioIndex);
    wifi_hostapdRead(config_file,"basic_rates",temp_TransmitRates,64);
 
    if (strlen(temp_TransmitRates) == 0) {  // config not set, use supported rate
        wifi_getRadioSupportedDataTransmitRates(radioIndex, output);
    } else {
        temp = strtok(temp_TransmitRates," ");
        while(temp!=NULL)
        {
            // Convert 100 kbps to Mbps
            temp[strlen(temp)-1]=0;
            if((temp[0]=='5') && (temp[1]=='\0'))
            {
                temp="5.5";
            }
            strcat(temp_output,temp);
            temp = strtok(NULL," ");
            if(temp!=NULL)
            {
                strcat(temp_output,",");
            }
        }
        strcpy(output,temp_output);
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_setRadioBasicDataTransmitRates(INT radioIndex, CHAR *TransmitRates)
{
    char *temp;
    char temp1[128];
    char temp_output[128];
    char temp_TransmitRates[128];
    char set[128];
    char sub_set[128];
    int set_count=0,subset_count=0;
    int set_index=0,subset_index=0;
    char *token;
    int flag=0, i=0;
    struct params params={'\0'};
    char config_file[MAX_BUF_SIZE] = {0};
    wifi_band band = wifi_index_to_band(radioIndex);

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(NULL == TransmitRates)
        return RETURN_ERR;
    if (strlen(TransmitRates) >= sizeof(sub_set))
        return RETURN_ERR;
    snprintf(sub_set, sizeof(sub_set), "%s", TransmitRates);

    //Allow only supported Data transmit rate to be set
    wifi_getRadioSupportedDataTransmitRates(radioIndex,set);
    token = strtok(sub_set,",");
    while( token != NULL  )  /* split the basic rate to be set, by comma */
    {
        sub_set[subset_count]=atoi(token);
        subset_count++;
        token=strtok(NULL,",");
    }
    token=strtok(set,",");
    while(token!=NULL)   /* split the supported rate by comma */
    {
        set[set_count]=atoi(token);
        set_count++;
        token=strtok(NULL,",");
    }
    for(subset_index=0;subset_index < subset_count;subset_index++) /* Compare each element of subset and set */
    {
        for(set_index=0;set_index < set_count;set_index++)
        {
            flag=0;
            if(sub_set[subset_index]==set[set_index])
                break;
            else
                flag=1; /* No match found */
        }
        if(flag==1)
            return RETURN_ERR; //If value not found return Error
    }
    strcpy(temp_TransmitRates,TransmitRates);

    for(i=0;i<strlen(temp_TransmitRates);i++)
    {
    //if (((temp_TransmitRates[i]>=48) && (temp_TransmitRates[i]<=57)) | (temp_TransmitRates[i]==32))
        if (((temp_TransmitRates[i]>='0') && (temp_TransmitRates[i]<='9')) || (temp_TransmitRates[i]==' ') || (temp_TransmitRates[i]=='.') || (temp_TransmitRates[i]==','))
        {
            continue;
        }
        else
        {
            return RETURN_ERR;
        }
    }
    strcpy(temp_output,"");
    temp = strtok(temp_TransmitRates,",");
    while(temp!=NULL)
    {
        strcpy(temp1,temp);
        if(band == band_5)
        {
            if((strcmp(temp,"1")==0) || (strcmp(temp,"2")==0) || (strcmp(temp,"5.5")==0))
            {
                return RETURN_ERR;
            }
        }

        if(strcmp(temp,"5.5")==0)
        {
            strcpy(temp1,"55");
        }
        else
        {
            strcat(temp1,"0");
        }
        strcat(temp_output,temp1);
        temp = strtok(NULL,",");
        if(temp!=NULL)
        {
            strcat(temp_output," ");
        }
    }
    strcpy(TransmitRates,temp_output);

    params.name= "basic_rates";
    params.value =TransmitRates;

    wifi_dbg_printf("\n%s:",__func__);
    wifi_dbg_printf("\nparams.value=%s\n",params.value);
    wifi_dbg_printf("\n******************Transmit rates=%s\n",TransmitRates);
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,radioIndex);
    wifi_hostapdWrite(config_file,&params,1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//passing the hostapd configuration file and get the virtual interface of xfinity(2g)
INT wifi_GetInterfaceName_virtualInterfaceName_2G(char interface_name[50])
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);
    FILE *fp = NULL;
    char path[256] = {0}, output_string[256] = {0};
    int count = 0;
    char *interface = NULL;

    fp = popen("cat /nvram/hostapd0.conf | grep -w bss", "r");
    if (fp == NULL)
    {
        printf("Failed to run command in Function %s\n", __FUNCTION__);
        return RETURN_ERR;
    }
    if (fgets(path, sizeof(path) - 1, fp) != NULL)
    {
        interface = strchr(path, '=');

        if (interface != NULL)
        {
            strcpy(output_string, interface + 1);
            for (count = 0; output_string[count] != '\n' && output_string[count] != '\0'; count++)
                interface_name[count] = output_string[count];

            interface_name[count] = '\0';
        }
    }
    pclose(fp);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
    return RETURN_OK;
}

INT wifi_halGetIfStatsNull(wifi_radioTrafficStats2_t *output_struct)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);
    output_struct->radio_BytesSent = 0;
    output_struct->radio_BytesReceived = 0;
    output_struct->radio_PacketsSent = 0;
    output_struct->radio_PacketsReceived = 0;
    output_struct->radio_ErrorsSent = 0;
    output_struct->radio_ErrorsReceived = 0;
    output_struct->radio_DiscardPacketsSent = 0;
    output_struct->radio_DiscardPacketsReceived = 0;
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
    return RETURN_OK;
}


INT wifi_halGetIfStats(char *ifname, wifi_radioTrafficStats2_t *pStats)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);
    CHAR buf[MAX_CMD_SIZE] = {0};
    CHAR Value[MAX_BUF_SIZE] = {0};
    FILE *fp = NULL;

    if (ifname == NULL || strlen(ifname) <= 1)
        return RETURN_OK;

    snprintf(buf, sizeof(buf), "ifconfig -a %s > /tmp/Radio_Stats.txt", ifname);
    system(buf);

    fp = fopen("/tmp/Radio_Stats.txt", "r");
    if(fp == NULL)
    {
        printf("/tmp/Radio_Stats.txt not exists \n");
        return RETURN_ERR;
    }
    fclose(fp);

    sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
    File_Reading(buf, Value);
    pStats->radio_PacketsReceived = strtoul(Value, NULL, 10);

    sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
    File_Reading(buf, Value);
    pStats->radio_PacketsSent = strtoul(Value, NULL, 10);

    sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'RX bytes' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
    File_Reading(buf, Value);
    pStats->radio_BytesReceived = strtoul(Value, NULL, 10);

    sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'TX bytes' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
    File_Reading(buf, Value);
    pStats->radio_BytesSent = strtoul(Value, NULL, 10);

    sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
    File_Reading(buf, Value);
    pStats->radio_ErrorsReceived = strtoul(Value, NULL, 10);

    sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
    File_Reading(buf, Value);
    pStats->radio_ErrorsSent = strtoul(Value, NULL, 10);

    sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f4 | cut -d ' ' -f1");
    File_Reading(buf, Value);
    pStats->radio_DiscardPacketsReceived = strtoul(Value, NULL, 10);

    sprintf(buf, "cat /tmp/Radio_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f4 | cut -d ' ' -f1");
    File_Reading(buf, Value);
    pStats->radio_DiscardPacketsSent = strtoul(Value, NULL, 10);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
    return RETURN_OK;
}

INT GetIfacestatus(CHAR *interface_name, CHAR *status)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);
    CHAR buf[MAX_CMD_SIZE] = {0};
    FILE *fp = NULL;
    INT count = 0;

    if (interface_name != NULL && (strlen(interface_name) > 1) && status != NULL &&
        is_valid_ifname(interface_name))
    {
        snprintf(buf, sizeof(buf), "ifconfig -a %s | grep %s | wc -l",
                 interface_name, interface_name);
        File_Reading(buf, status);
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
    return RETURN_OK;
}

//Get detail radio traffic static info
INT wifi_getRadioTrafficStats2(INT radioIndex, wifi_radioTrafficStats2_t *output_struct) //Tr181
{

#if 0	
    //ifconfig radio_x	
    output_struct->radio_BytesSent=250;	//The total number of bytes transmitted out of the interface, including framing characters.
    output_struct->radio_BytesReceived=168;	//The total number of bytes received on the interface, including framing characters.
    output_struct->radio_PacketsSent=25;	//The total number of packets transmitted out of the interface.
    output_struct->radio_PacketsReceived=20; //The total number of packets received on the interface.

    output_struct->radio_ErrorsSent=0;	//The total number of outbound packets that could not be transmitted because of errors.
    output_struct->radio_ErrorsReceived=0;    //The total number of inbound packets that contained errors preventing them from being delivered to a higher-layer protocol.
    output_struct->radio_DiscardPacketsSent=0; //The total number of outbound packets which were chosen to be discarded even though no errors had been detected to prevent their being transmitted. One possible reason for discarding such a packet could be to free up buffer space.
    output_struct->radio_DiscardPacketsReceived=0; //The total number of inbound packets which were chosen to be discarded even though no errors had been detected to prevent their being delivered. One possible reason for discarding such a packet could be to free up buffer space.

    output_struct->radio_PLCPErrorCount=0;	//The number of packets that were received with a detected Physical Layer Convergence Protocol (PLCP) header error.	
    output_struct->radio_FCSErrorCount=0;	//The number of packets that were received with a detected FCS error. This parameter is based on dot11FCSErrorCount from [Annex C/802.11-2012].
    output_struct->radio_InvalidMACCount=0;	//The number of packets that were received with a detected invalid MAC header error.
    output_struct->radio_PacketsOtherReceived=0;	//The number of packets that were received, but which were destined for a MAC address that is not associated with this interface.
    output_struct->radio_NoiseFloor=-99; 	//The noise floor for this radio channel where a recoverable signal can be obtained. Expressed as a signed integer in the range (-110:0).  Measurement should capture all energy (in dBm) from sources other than Wi-Fi devices as well as interference from Wi-Fi devices too weak to be decoded. Measured in dBm
    output_struct->radio_ChannelUtilization=35; //Percentage of time the channel was occupied by the radios own activity (Activity Factor) or the activity of other radios.  Channel utilization MUST cover all user traffic, management traffic, and time the radio was unavailable for CSMA activities, including DIFS intervals, etc.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1.  Units in Percentage
    output_struct->radio_ActivityFactor=2; //Percentage of time that the radio was transmitting or receiving Wi-Fi packets to/from associated clients. Activity factor MUST include all traffic that deals with communication between the radio and clients associated to the radio as well as management overhead for the radio, including NAV timers, beacons, probe responses,time for receiving devices to send an ACK, SIFC intervals, etc.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.   If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage
    output_struct->radio_CarrierSenseThreshold_Exceeded=20; //Percentage of time that the radio was unable to transmit or receive Wi-Fi packets to/from associated clients due to energy detection (ED) on the channel or clear channel assessment (CCA). The metric is calculated and updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage
    output_struct->radio_RetransmissionMetirc=0; //Percentage of packets that had to be re-transmitted. Multiple re-transmissions of the same packet count as one.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".   The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units  in percentage

    output_struct->radio_MaximumNoiseFloorOnChannel=-1; //Maximum Noise on the channel during the measuring interval.  The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1.  Units in dBm
    output_struct->radio_MinimumNoiseFloorOnChannel=-1; //Minimum Noise on the channel. The metric is updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm
    output_struct->radio_MedianNoiseFloorOnChannel=-1;  //Median Noise on the channel during the measuring interval.   The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm
    output_struct->radio_StatisticsStartTime=0; 	    //The date and time at which the collection of the current set of statistics started.  This time must be updated whenever the radio statistics are reset.

    return RETURN_OK;
#endif

    CHAR interface_name[64] = {0};
    BOOL iface_status = FALSE;
    wifi_radioTrafficStats2_t radioTrafficStats = {0};
	INT max_radio_num = 0, apIndex = 0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);
    if (NULL == output_struct)
        return RETURN_ERR;

    wifi_getMaxRadioNumber(&max_radio_num);

	memset(output_struct, 0, sizeof(wifi_radioTrafficStats2_t));

	for(apIndex = radioIndex; apIndex < MAX_APS; apIndex += max_radio_num) {
	    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
	        continue;
	    wifi_getApEnable(radioIndex, &iface_status);

	    if (iface_status == TRUE)
	        wifi_halGetIfStats(interface_name, &radioTrafficStats);
	    else
	        wifi_halGetIfStatsNull(&radioTrafficStats);     // just set some transmission statistic value to 0

		    output_struct->radio_BytesSent += radioTrafficStats.radio_BytesSent;
		    output_struct->radio_BytesReceived += radioTrafficStats.radio_BytesReceived;
		    output_struct->radio_PacketsSent += radioTrafficStats.radio_PacketsSent;
		    output_struct->radio_PacketsReceived += radioTrafficStats.radio_PacketsReceived;
		    output_struct->radio_ErrorsSent += radioTrafficStats.radio_ErrorsSent;
		    output_struct->radio_ErrorsReceived += radioTrafficStats.radio_ErrorsReceived;
		    output_struct->radio_DiscardPacketsSent += radioTrafficStats.radio_DiscardPacketsSent;
		    output_struct->radio_DiscardPacketsReceived += radioTrafficStats.radio_DiscardPacketsReceived;
	}

    output_struct->radio_PLCPErrorCount = 0;				  //The number of packets that were received with a detected Physical Layer Convergence Protocol (PLCP) header error.
    output_struct->radio_FCSErrorCount = 0;					  //The number of packets that were received with a detected FCS error. This parameter is based on dot11FCSErrorCount from [Annex C/802.11-2012].
    output_struct->radio_InvalidMACCount = 0;				  //The number of packets that were received with a detected invalid MAC header error.
    output_struct->radio_PacketsOtherReceived = 0;			  //The number of packets that were received, but which were destined for a MAC address that is not associated with this interface.
    output_struct->radio_NoiseFloor = -99;					  //The noise floor for this radio channel where a recoverable signal can be obtained. Expressed as a signed integer in the range (-110:0).  Measurement should capture all energy (in dBm) from sources other than Wi-Fi devices as well as interference from Wi-Fi devices too weak to be decoded. Measured in dBm
    output_struct->radio_ChannelUtilization = 35;			  //Percentage of time the channel was occupied by the radio\92s own activity (Activity Factor) or the activity of other radios.  Channel utilization MUST cover all user traffic, management traffic, and time the radio was unavailable for CSMA activities, including DIFS intervals, etc.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1.  Units in Percentage
    output_struct->radio_ActivityFactor = 2;				  //Percentage of time that the radio was transmitting or receiving Wi-Fi packets to/from associated clients. Activity factor MUST include all traffic that deals with communication between the radio and clients associated to the radio as well as management overhead for the radio, including NAV timers, beacons, probe responses,time for receiving devices to send an ACK, SIFC intervals, etc.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.   If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage
    output_struct->radio_CarrierSenseThreshold_Exceeded = 20; //Percentage of time that the radio was unable to transmit or receive Wi-Fi packets to/from associated clients due to energy detection (ED) on the channel or clear channel assessment (CCA). The metric is calculated and updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in Percentage
    output_struct->radio_RetransmissionMetirc = 0;			  //Percentage of packets that had to be re-transmitted. Multiple re-transmissions of the same packet count as one.  The metric is calculated and updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".   The calculation of this metric MUST only use the data collected from the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units  in percentage

    output_struct->radio_MaximumNoiseFloorOnChannel = -1; //Maximum Noise on the channel during the measuring interval.  The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1.  Units in dBm
    output_struct->radio_MinimumNoiseFloorOnChannel = -1; //Minimum Noise on the channel. The metric is updated in this Parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm
    output_struct->radio_MedianNoiseFloorOnChannel = -1;  //Median Noise on the channel during the measuring interval.   The metric is updated in this parameter at the end of the interval defined by "Radio Statistics Measuring Interval".  The calculation of this metric MUST only use the data collected in the just completed interval.  If this metric is queried before it has been updated with an initial calculation, it MUST return -1. Units in dBm
    output_struct->radio_StatisticsStartTime = 0;		  //The date and time at which the collection of the current set of statistics started.  This time must be updated whenever the radio statistics are reset.

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);

    return RETURN_OK;
}

//Set radio traffic static Measureing rules
INT wifi_setRadioTrafficStatsMeasure(INT radioIndex, wifi_radioTrafficStatsMeasure_t *input_struct) //Tr181
{
    //zqiu:  If the RadioTrafficStats process running, and the new value is different from old value, the process needs to be reset. The Statistics date, such as MaximumNoiseFloorOnChannel, MinimumNoiseFloorOnChannel and MedianNoiseFloorOnChannel need to be reset. And the "StatisticsStartTime" must be reset to the current time. Units in Seconds
    //       Else, save the MeasuringRate and MeasuringInterval for future usage

    return RETURN_OK;
}

//To start or stop RadioTrafficStats
INT wifi_setRadioTrafficStatsRadioStatisticsEnable(INT radioIndex, BOOL enable)
{
    //zqiu:  If the RadioTrafficStats process running
    //          	if(enable)
    //					return RETURN_OK.
    //				else
    //					Stop RadioTrafficStats process
    //       Else 
    //				if(enable)
    //					Start RadioTrafficStats process with MeasuringRate and MeasuringInterval, and reset "StatisticsStartTime" to the current time, Units in Seconds
    //				else
    //					return RETURN_OK.

    return RETURN_OK;
}

//Clients associated with the AP over a specific interval.  The histogram MUST have a range from -110to 0 dBm and MUST be divided in bins of 3 dBM, with bins aligning on the -110 dBm end of the range.  Received signal levels equal to or greater than the smaller boundary of a bin and less than the larger boundary are included in the respective bin.  The bin associated with the client?s current received signal level MUST be incremented when a client associates with the AP.   Additionally, the respective bins associated with each connected client?s current received signal level MUST be incremented at the interval defined by "Radio Statistics Measuring Rate".  The histogram?s bins MUST NOT be incremented at any other time.  The histogram data collected during the interval MUST be published to the parameter only at the end of the interval defined by "Radio Statistics Measuring Interval".  The underlying histogram data MUST be cleared at the start of each interval defined by "Radio Statistics Measuring Interval?. If any of the parameter's representing this histogram is queried before the histogram has been updated with an initial set of data, it MUST return -1. Units dBm
INT wifi_getRadioStatsReceivedSignalLevel(INT radioIndex, INT signalIndex, INT *SignalLevel) //Tr181
{
    //zqiu: Please ignor signalIndex.
    if (NULL == SignalLevel) 
        return RETURN_ERR;
    *SignalLevel=(radioIndex==0)?-19:-19;

    return RETURN_OK;
}

//Not all implementations may need this function.  If not needed for a particular implementation simply return no-error (0)
INT wifi_applyRadioSettings(INT radioIndex)
{
    return RETURN_OK;
}

//Get the radio index assocated with this SSID entry
INT wifi_getSSIDRadioIndex(INT ssidIndex, INT *radioIndex)
{
    if(NULL == radioIndex)
        return RETURN_ERR;
    int max_radio_num = 0;
    wifi_getMaxRadioNumber(&max_radio_num);
    *radioIndex = ssidIndex%max_radio_num;
    return RETURN_OK;
}

//Device.WiFi.SSID.{i}.Enable
//Get SSID enable configuration parameters (not the SSID enable status)
INT wifi_getSSIDEnable(INT ssidIndex, BOOL *output_bool) //Tr181
{
    if (NULL == output_bool) 
        return RETURN_ERR;

    return wifi_getApEnable(ssidIndex, output_bool);
}

//Device.WiFi.SSID.{i}.Enable
//Set SSID enable configuration parameters
INT wifi_setSSIDEnable(INT ssidIndex, BOOL enable) //Tr181
{
    return wifi_setApEnable(ssidIndex, enable);
}

//Device.WiFi.SSID.{i}.Status
//Get the SSID enable status
INT wifi_getSSIDStatus(INT ssidIndex, CHAR *output_string) //Tr181
{
    char cmd[MAX_CMD_SIZE]={0};
    char buf[MAX_BUF_SIZE]={0};
    BOOL output_bool;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output_string)
        return RETURN_ERR;
 
    wifi_getApEnable(ssidIndex,&output_bool);
    snprintf(output_string, 32, output_bool==1?"Enabled":"Disabled");

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

// Outputs a 32 byte or less string indicating the SSID name.  Sring buffer must be preallocated by the caller.
INT wifi_getSSIDName(INT apIndex, CHAR *output)
{
    char config_file[MAX_BUF_SIZE] = {0};

    if (NULL == output) 
        return RETURN_ERR;

    if (!syn_flag) {
        sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
        wifi_hostapdRead(config_file,"ssid",output,32);
    } else
        snprintf(output, 32, "%s", vap_info[apIndex].ssid);

    wifi_dbg_printf("\n[%s]: SSID Name is : %s",__func__,output);
    return RETURN_OK;
}

// Set a max 32 byte string and sets an internal variable to the SSID name          
INT wifi_setSSIDName(INT apIndex, CHAR *ssid_string)
{
    struct params params;
    char config_file[MAX_BUF_SIZE] = {0};
    size_t ssid_len;
    size_t i;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(NULL == ssid_string)
        return RETURN_ERR;
    ssid_len = strlen(ssid_string);
    if(ssid_len == 0 || ssid_len > 32)
        return RETURN_ERR;
    /* Reject control characters and newlines to prevent config injection */
    for (i = 0; i < ssid_len; i++) {
        unsigned char c = (unsigned char)ssid_string[i];
        if (c < 0x20 || c == 0x7f)
            return RETURN_ERR;
    }

    params.name = "ssid";
    params.value = ssid_string;
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdWrite(config_file, &params, 1);
    wifi_hostapdProcessUpdate(apIndex, &params, 1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

//Get the BSSID
INT wifi_getBaseBSSID(INT ssidIndex, CHAR *output_string)	//RDKB
{
    char cmd[MAX_CMD_SIZE]="";

    if (NULL == output_string)
        return RETURN_ERR;

    if(ssidIndex >= 0 && ssidIndex < MAX_APS)
    {
        snprintf(cmd, sizeof(cmd), "cat %s%d.conf | grep bssid | cut -d '=' -f2 | tr -d '\n'", CONFIG_PREFIX, ssidIndex);
        _syscmd(cmd, output_string, 64);
        return RETURN_OK;
    }
    strncpy(output_string, "\0", 1);

    return RETURN_ERR;
}

//Get the MAC address associated with this Wifi SSID
INT wifi_getSSIDMACAddress(INT ssidIndex, CHAR *output_string) //Tr181
{
    wifi_getBaseBSSID(ssidIndex,output_string);
    return RETURN_OK;
}

//Get the basic SSID traffic static info
//Apply SSID and AP (in the case of Acess Point devices) to the hardware
//Not all implementations may need this function.  If not needed for a particular implementation simply return no-error (0)
INT wifi_applySSIDSettings(INT ssidIndex)
{
    char interface_name[16] = {0};
    BOOL status = false;
    char cmd[MAX_CMD_SIZE] = {0};
    char buf[MAX_CMD_SIZE] = {0};
    int apIndex, ret;
    int max_radio_num = 0;
    int radioIndex = 0;

    wifi_getMaxRadioNumber(&max_radio_num);

    radioIndex = ssidIndex % max_radio_num;

    wifi_getApEnable(ssidIndex,&status);
    // Do not apply when ssid index is disabled
    if (status == false)
        return RETURN_OK;

    /* Doing full remove and add for ssid Index
     * Not all hostapd options are supported with reload
     * for example macaddr_acl
     */
    if(wifi_setApEnable(ssidIndex,false) != RETURN_OK)
           return RETURN_ERR;

    ret = wifi_setApEnable(ssidIndex,true);

    /* Workaround for hostapd issue with multiple bss definitions
     * when first created interface will be removed
     * then all vaps other vaps on same phy are removed
     * after calling setApEnable to false readd all enabled vaps */
    for(int i=0; i < MAX_APS/max_radio_num; i++) {
        apIndex = max_radio_num*i+radioIndex;
        if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
            continue;
        snprintf(cmd, sizeof(cmd), "cat %s | grep %s= | cut -d'=' -f2", VAP_STATUS_FILE, interface_name);
        _syscmd(cmd, buf, sizeof(buf));
        if(*buf == '1')
               wifi_setApEnable(apIndex, true);
    }

    return ret;
}

struct channels_noise {
    int channel;
    int noise;
};

// Return noise array for each channel
int get_noise(int radioIndex, struct channels_noise *channels_noise_arr, int channels_num)
{
    char interface_name[16] = {0};
    FILE *f = NULL;
    char cmd[128] = {0};
    char line[256] = {0};
    size_t len = 0;
    ssize_t read = 0;
    int tmp = 0, arr_index = -1;

    if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    sprintf(cmd, "iw dev %s survey dump | grep 'frequency\\|noise' | awk '{print $2}'", interface_name);

    if ((f = popen(cmd, "r")) == NULL) {
        wifi_dbg_printf("%s: popen %s error\n", __func__, cmd);
        return RETURN_ERR;
    }
    
    while(fgets(line, sizeof(line), f) != NULL) {
        if(arr_index < channels_num){
            sscanf(line, "%d", &tmp);
            if (tmp > 0) {      // channel frequency, the first line must be frequency
                arr_index++;
                channels_noise_arr[arr_index].channel = ieee80211_frequency_to_channel(tmp);
            } else if (arr_index >= 0) {  // noise — only valid after at least one frequency
                channels_noise_arr[arr_index].noise = tmp;
            }
        }else{
            break;
        }
    }
    pclose(f);
    return RETURN_OK;
}

//Start the wifi scan and get the result into output buffer for RDKB to parser. The result will be used to manage endpoint list
//HAL funciton should allocate an data structure array, and return to caller with "neighbor_ap_array"
INT wifi_getNeighboringWiFiDiagnosticResult2(INT radioIndex, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size) //Tr181	
{
    int index = -1;
    wifi_neighbor_ap2_t *scan_array = NULL;
    char cmd[256]={0};
    char buf[128]={0};
    char file_name[32] = {0};
    char filter_SSID[32] = {0};
    char line[256] = {0};
    char interface_name[16] = {0};
    char *ret = NULL;
    int freq=0;
    FILE *f = NULL;
    size_t len=0;
    int channels_num = 0;
    int vht_channel_width = 0;
    int get_noise_ret = RETURN_ERR;
    bool filter_enable = false;
    bool filter_BSS = false;     // The flag determine whether the BSS information need to be filterd.
    int phyId = 0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s: %d\n", __func__, __LINE__);

    if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;

    snprintf(file_name, sizeof(file_name), "%s%d.txt", ESSID_FILE, radioIndex);
    f = fopen(file_name, "r");
    if (f != NULL) {
        fgets(buf, sizeof(buf), f);
        if ((strncmp(buf, "0", 1)) != 0) {
            fgets(filter_SSID, sizeof(filter_SSID), f);
            /* strip trailing newline before using in strcmp */
            filter_SSID[strcspn(filter_SSID, "\n")] = '\0';
            if (strlen(filter_SSID) != 0)
                filter_enable = true;
        }
        fclose(f);
    }

    phyId = radio_index_to_phy(radioIndex);
    snprintf(cmd, sizeof(cmd), "iw phy phy%d channels | grep * | grep -v disable | wc -l", phyId);
    _syscmd(cmd, buf, sizeof(buf));
    channels_num = strtol(buf, NULL, 10);



    sprintf(cmd, "iw dev %s scan | grep '%s\\|SSID\\|freq\\|beacon interval\\|capabilities\\|signal\\|Supported rates\\|DTIM\\| \
    // WPA\\|RSN\\|Group cipher\\|HT operation\\|secondary channel offset\\|channel width\\|HE.*GHz' | grep -v -e '*.*BSS'", interface_name, interface_name);
    fprintf(stderr, "cmd: %s\n", cmd);
    if ((f = popen(cmd, "r")) == NULL) {
        wifi_dbg_printf("%s: popen %s error\n", __func__, cmd);
        return RETURN_ERR;
    }
	
    struct channels_noise *channels_noise_arr = (channels_num > 0) ?
        calloc(channels_num, sizeof(struct channels_noise)) : NULL;
    if (channels_num > 0 && channels_noise_arr == NULL)
        channels_num = 0; /* treat as no-noise-data rather than crashing */
    get_noise_ret = get_noise(radioIndex, channels_noise_arr, channels_num);
	
    ret = fgets(line, sizeof(line), f);
    while (ret != NULL) {
        if(strstr(line, "BSS") != NULL) {    // new neighbor info
            // The SSID field is not in the first field. So, we should store whole BSS informations and the filter flag. 
            // And we will determine whether we need the previous BSS infomation when parsing the next BSS field or end of while loop.
            // If we don't want the BSS info, we don't realloc more space, and just clean the previous BSS.

            if (!filter_BSS) {
                index++;
                wifi_neighbor_ap2_t *tmp;
                tmp = realloc(scan_array, sizeof(wifi_neighbor_ap2_t)*(index+1));
                if (tmp == NULL) {              // no more memory to use
                    index--;
                    wifi_dbg_printf("%s: realloc failed\n", __func__);
                    break;
                }
                scan_array = tmp;
            }
            memset(&(scan_array[index]), 0, sizeof(wifi_neighbor_ap2_t));

            filter_BSS = false;
            sscanf(line, "BSS %17s", scan_array[index].ap_BSSID);
            strncpy(scan_array[index].ap_Mode, "Infrastructure", strlen("Infrastructure"));
            strncpy(scan_array[index].ap_SecurityModeEnabled, "None", strlen("None"));
            strncpy(scan_array[index].ap_EncryptionMode, "None", strlen("None"));
        } else if (strstr(line, "freq") != NULL) {
            sscanf(line,"	freq: %d", &freq);
            scan_array[index].ap_Channel = ieee80211_frequency_to_channel(freq);

            if (freq >= 2412 && freq <= 2484) {
                strncpy(scan_array[index].ap_OperatingFrequencyBand, "2.4GHz", strlen("2.4GHz"));
                strncpy(scan_array[index].ap_SupportedStandards, "b,g", strlen("b,g"));
                strncpy(scan_array[index].ap_OperatingStandards, "g", strlen("g"));
            }
            else if (freq >= 5160 && freq <= 5805) {
                strncpy(scan_array[index].ap_OperatingFrequencyBand, "5GHz", strlen("5GHz"));
                strncpy(scan_array[index].ap_SupportedStandards, "a", strlen("a"));
                strncpy(scan_array[index].ap_OperatingStandards, "a", strlen("a"));
            }

            scan_array[index].ap_Noise = 0;
            if (get_noise_ret == RETURN_OK) {
                for (int i = 0; i < channels_num; i++) {
                    if (scan_array[index].ap_Channel == channels_noise_arr[i].channel) {
                        scan_array[index].ap_Noise = channels_noise_arr[i].noise;
                        break;
                    }
                }
            }
        } else if (strstr(line, "beacon interval") != NULL) {
            sscanf(line,"	beacon interval: %d TUs", &(scan_array[index].ap_BeaconPeriod));
        } else if (strstr(line, "signal") != NULL) {
            sscanf(line,"	signal: %d", &(scan_array[index].ap_SignalStrength));
        } else if (strstr(line,"SSID") != NULL) {
            sscanf(line,"	SSID: %63s", scan_array[index].ap_SSID);
            if (filter_enable && strcmp(scan_array[index].ap_SSID, filter_SSID) != 0) {
                filter_BSS = true;
            }
        } else if (strstr(line, "Supported rates") != NULL) {
            char SRate[80] = {0}, *tmp = NULL;
            memset(buf, 0, sizeof(buf));
            strncpy(SRate, line, sizeof(SRate) - 1);
            SRate[sizeof(SRate) - 1] = '\0';
            tmp = strtok(SRate, ":");
            tmp = strtok(NULL, ":");
            if (tmp == NULL)
                continue;
            snprintf(buf, sizeof(buf), "%s", tmp);
            memset(SRate, 0, sizeof(SRate));

            tmp = strtok(buf, " \n");
            while (tmp != NULL) {
                if (strlen(SRate) + strlen(tmp) + 2 < sizeof(SRate)) {
                    strcat(SRate, tmp);
                    if (SRate[strlen(SRate) - 1] == '*') {
                        SRate[strlen(SRate) - 1] = '\0';
                    }
                    strcat(SRate, ",");
                }
                tmp = strtok(NULL, " \n");
            }
            if (strlen(SRate) > 0)
                SRate[strlen(SRate) - 1] = '\0';
            snprintf(scan_array[index].ap_SupportedDataTransferRates,
                     sizeof(scan_array[index].ap_SupportedDataTransferRates), "%s", SRate);
        } else if (strstr(line, "DTIM") != NULL) {
            sscanf(line,"DTIM Period %u", &scan_array[index].ap_DTIMPeriod);
        } else if (strstr(line, "VHT capabilities") != NULL) {
            strcat(scan_array[index].ap_SupportedStandards, ",ac");
            strcpy(scan_array[index].ap_OperatingStandards, "ac");
        } else if (strstr(line, "HT capabilities") != NULL) {
            strcat(scan_array[index].ap_SupportedStandards, ",n");
            strcpy(scan_array[index].ap_OperatingStandards, "n");
        } else if (strstr(line, "VHT operation") != NULL) {
            ret = fgets(line, sizeof(line), f);
            sscanf(line,"		 * channel width: %d", &vht_channel_width);
            if(vht_channel_width == 1) {
                snprintf(scan_array[index].ap_OperatingChannelBandwidth, sizeof(scan_array[index].ap_OperatingChannelBandwidth), "11AC_VHT80");
            } else {
                snprintf(scan_array[index].ap_OperatingChannelBandwidth, sizeof(scan_array[index].ap_OperatingChannelBandwidth), "11AC_VHT40");
            }
            if (strstr(line, "BSS") != NULL)   // prevent to get the next neighbor information
                continue;
        } else if (strstr(line, "HT operation") != NULL) {
            ret = fgets(line, sizeof(line), f);
            sscanf(line,"		 * secondary channel offset: %127s", &buf);
            if (!strcmp(buf, "above")) {
                //40Mhz +
                snprintf(scan_array[index].ap_OperatingChannelBandwidth, sizeof(scan_array[index].ap_OperatingChannelBandwidth), "11N%s_HT40PLUS", radioIndex%1 ? "A": "G");
            }
            else if (!strcmp(buf, "below")) {
                //40Mhz -
                snprintf(scan_array[index].ap_OperatingChannelBandwidth, sizeof(scan_array[index].ap_OperatingChannelBandwidth), "11N%s_HT40MINUS", radioIndex%1 ? "A": "G");
            } else {
                //20Mhz
                snprintf(scan_array[index].ap_OperatingChannelBandwidth, sizeof(scan_array[index].ap_OperatingChannelBandwidth), "11N%s_HT20", radioIndex%1 ? "A": "G");
            }
            if (strstr(line, "BSS") != NULL)   // prevent to get the next neighbor information
                continue;
        } else if (strstr(line, "HE capabilities") != NULL) {
            strcat(scan_array[index].ap_SupportedStandards, ",ax");
            strcpy(scan_array[index].ap_OperatingStandards, "ax");
            ret = fgets(line, sizeof(line), f);
            if (strncmp(scan_array[index].ap_OperatingFrequencyBand, "2.4GHz", strlen("2.4GHz")) == 0) {
                if (strstr(line, "HE40/2.4GHz") != NULL)
                    strcpy(scan_array[index].ap_OperatingChannelBandwidth, "11AXHE40PLUS");
                else
                    strcpy(scan_array[index].ap_OperatingChannelBandwidth, "11AXHE20");
            } else if (strncmp(scan_array[index].ap_OperatingFrequencyBand, "5GHz", strlen("5GHz")) == 0) {
                if (strstr(line, "HE80/5GHz") != NULL) {
                    strcpy(scan_array[index].ap_OperatingChannelBandwidth, "11AXHE80");
                    ret = fgets(line, sizeof(line), f);
                } else
                    continue;
                if (strstr(line, "HE160/5GHz") != NULL)
                    strcpy(scan_array[index].ap_OperatingChannelBandwidth, "11AXHE160");
            }
            continue;
        } else if (strstr(line, "WPA") != NULL) {
            strcpy(scan_array[index].ap_SecurityModeEnabled, "WPA");
        } else if (strstr(line, "RSN") != NULL) {
            strcpy(scan_array[index].ap_SecurityModeEnabled, "RSN");
        } else if (strstr(line, "Group cipher") != NULL) {
            sscanf(line, "		 * Group cipher: %63s", scan_array[index].ap_EncryptionMode);
            if (strncmp(scan_array[index].ap_EncryptionMode, "CCMP", strlen("CCMP")) == 0) {
                strcpy(scan_array[index].ap_EncryptionMode, "AES");
            }
        }
        ret = fgets(line, sizeof(line), f);
    }

    if (!filter_BSS) {
        *output_array_size = index + 1;
    } else {
        memset(&(scan_array[index]), 0, sizeof(wifi_neighbor_ap2_t));
        *output_array_size = index;
    }
    *neighbor_ap_array = scan_array;
    pclose(f);
    free(channels_noise_arr);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//>> Deprecated: used for old RDKB code.
INT wifi_getRadioWifiTrafficStats(INT radioIndex, wifi_radioTrafficStats_t *output_struct)
{
    INT status = RETURN_ERR;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    output_struct->wifi_PLCPErrorCount = 0;
    output_struct->wifi_FCSErrorCount = 0;
    output_struct->wifi_InvalidMACCount = 0;
    output_struct->wifi_PacketsOtherReceived = 0;
    output_struct->wifi_Noise = 0;
    status = RETURN_OK;
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return status;
}

INT wifi_getBasicTrafficStats(INT apIndex, wifi_basicTrafficStats_t *output_struct)
{
    char interface_name[16] = {0};
    char cmd[128] = {0};
    char buf[1280] = {0};
    char *pos = NULL;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output_struct)
        return RETURN_ERR;

    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;

    memset(output_struct, 0, sizeof(wifi_basicTrafficStats_t));

    snprintf(cmd, sizeof(cmd), "ifconfig %s", interface_name);
    _syscmd(cmd, buf, sizeof(buf));

    pos = buf;
    if ((pos = strstr(pos, "RX packets:")) == NULL)
        return RETURN_ERR;
    output_struct->wifi_PacketsReceived = atoi(pos+strlen("RX packets:"));

    if ((pos = strstr(pos, "TX packets:")) == NULL)
        return RETURN_ERR;
    output_struct->wifi_PacketsSent = atoi(pos+strlen("TX packets:"));

    if ((pos = strstr(pos, "RX bytes:")) == NULL)
        return RETURN_ERR;
    output_struct->wifi_BytesReceived = atoi(pos+strlen("RX bytes:"));

    if ((pos = strstr(pos, "TX bytes:")) == NULL)
        return RETURN_ERR;
    output_struct->wifi_BytesSent = atoi(pos+strlen("TX bytes:"));

    sprintf(cmd, "hostapd_cli -i %s list_sta | wc -l | tr -d '\n'", interface_name);
    _syscmd(cmd, buf, sizeof(buf));
    sscanf(buf, "%lu", &output_struct->wifi_Associations);

#if 0
    //TODO: need to revisit below implementation
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char interface_name[MAX_BUF_SIZE] = {0};
    char interface_status[MAX_BUF_SIZE] = {0};
    char Value[MAX_BUF_SIZE] = {0};
    char buf[MAX_CMD_SIZE] = {0};
    char cmd[MAX_CMD_SIZE] = {0};
    FILE *fp = NULL;

    if (NULL == output_struct) {
        return RETURN_ERR;
    }

    memset(output_struct, 0, sizeof(wifi_basicTrafficStats_t));

    if((apIndex == 0) || (apIndex == 1) || (apIndex == 4) || (apIndex == 5))
    {
        if(apIndex == 0) //private_wifi for 2.4G
        {
            wifi_GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
        }
        else if(apIndex == 1) //private_wifi for 5G
        {
            wifi_GetInterfaceName(interface_name,"/nvram/hostapd1.conf");
        }
        else if(apIndex == 4) //public_wifi for 2.4G
        {
            sprintf(cmd,"%s","cat /nvram/hostapd0.conf | grep bss=");
            if(_syscmd(cmd,buf,sizeof(buf)) == RETURN_ERR)
            {
                return RETURN_ERR;
            }
            if(buf[0] == '#')//tp-link
                wifi_GetInterfaceName(interface_name,"/nvram/hostapd4.conf");
            else//tenda
                wifi_GetInterfaceName_virtualInterfaceName_2G(interface_name);
        }
        else if(apIndex == 5) //public_wifi for 5G
        {
            wifi_GetInterfaceName(interface_name,"/nvram/hostapd5.conf");
        }

        GetIfacestatus(interface_name, interface_status);

        if(0 != strcmp(interface_status, "1"))
            return RETURN_ERR;

        snprintf(cmd, sizeof(cmd), "ifconfig %s > /tmp/SSID_Stats.txt", interface_name);
        system(cmd);

        fp = fopen("/tmp/SSID_Stats.txt", "r");
        if(fp == NULL)
        {
            printf("/tmp/SSID_Stats.txt not exists \n");
            return RETURN_ERR;
        }
        fclose(fp);

        sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
        File_Reading(buf, Value);
        output_struct->wifi_PacketsReceived = strtoul(Value, NULL, 10);

        sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
        File_Reading(buf, Value);
        output_struct->wifi_PacketsSent = strtoul(Value, NULL, 10);

        sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'RX bytes' | tr -s ' ' | cut -d ':' -f2 | cut -d ' ' -f1");
        File_Reading(buf, Value);
        output_struct->wifi_BytesReceived = strtoul(Value, NULL, 10);

        sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'TX bytes' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
        File_Reading(buf, Value);
        output_struct->wifi_BytesSent = strtoul(Value, NULL, 10);

        /* There is no specific parameter from caller to associate the value wifi_Associations */
        //sprintf(cmd, "iw dev %s station dump | grep Station | wc -l", interface_name);
        //_syscmd(cmd, buf, sizeof(buf));
        //sscanf(buf,"%lu", &output_struct->wifi_Associations);
    }
#endif
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_getWifiTrafficStats(INT apIndex, wifi_trafficStats_t *output_struct)
{
    char interface_name[MAX_BUF_SIZE] = {0};
    char interface_status[MAX_BUF_SIZE] = {0};
    char Value[MAX_BUF_SIZE] = {0};
    char buf[MAX_CMD_SIZE] = {0};
    char cmd[MAX_CMD_SIZE] = {0};
    FILE *fp = NULL;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output_struct)
        return RETURN_ERR;

    memset(output_struct, 0, sizeof(wifi_trafficStats_t));

    if (wifi_GetInterfaceName(apIndex,interface_name) != RETURN_OK)
        return RETURN_ERR;
    GetIfacestatus(interface_name, interface_status);

    if(0 != strcmp(interface_status, "1"))
        return RETURN_ERR;

    snprintf(cmd, sizeof(cmd), "ifconfig %s > /tmp/SSID_Stats.txt", interface_name);
    system(cmd);

    fp = fopen("/tmp/SSID_Stats.txt", "r");
    if(fp == NULL)
    {
        printf("/tmp/SSID_Stats.txt not exists \n");
        return RETURN_ERR;
    }
    fclose(fp);

    sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
    File_Reading(buf, Value);
    output_struct->wifi_ErrorsReceived = strtoul(Value, NULL, 10);

    sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f3 | cut -d ' ' -f1");
    File_Reading(buf, Value);
    output_struct->wifi_ErrorsSent = strtoul(Value, NULL, 10);

    sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'RX packets' | tr -s ' ' | cut -d ':' -f4 | cut -d ' ' -f1");
    File_Reading(buf, Value);
    output_struct->wifi_DiscardedPacketsReceived = strtoul(Value, NULL, 10);

    sprintf(buf, "cat /tmp/SSID_Stats.txt | grep 'TX packets' | tr -s ' ' | cut -d ':' -f4 | cut -d ' ' -f1");
    File_Reading(buf, Value);
    output_struct->wifi_DiscardedPacketsSent = strtoul(Value, NULL, 10);

    output_struct->wifi_UnicastPacketsSent = 0;
    output_struct->wifi_UnicastPacketsReceived = 0;
    output_struct->wifi_MulticastPacketsSent = 0;
    output_struct->wifi_MulticastPacketsReceived = 0;
    output_struct->wifi_BroadcastPacketsSent = 0;
    output_struct->wifi_BroadcastPacketsRecevied = 0;
    output_struct->wifi_UnknownPacketsReceived = 0;

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_getSSIDTrafficStats(INT apIndex, wifi_ssidTrafficStats_t *output_struct)
{
    INT status = RETURN_ERR;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    //Below values should get updated from hal
    output_struct->wifi_RetransCount=0;
    output_struct->wifi_FailedRetransCount=0;
    output_struct->wifi_RetryCount=0;
    output_struct->wifi_MultipleRetryCount=0;
    output_struct->wifi_ACKFailureCount=0;
    output_struct->wifi_AggregatedPacketCount=0;

    status = RETURN_OK;
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return status;
}

INT wifi_getNeighboringWiFiDiagnosticResult(wifi_neighbor_ap_t **neighbor_ap_array, UINT *output_array_size)
{
    INT status = RETURN_ERR;
    UINT index;
    wifi_neighbor_ap_t *pt=NULL;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    *output_array_size=2;
    //zqiu: HAL alloc the array and return to caller. Caller response to free it.
    *neighbor_ap_array=(wifi_neighbor_ap_t *)calloc(sizeof(wifi_neighbor_ap_t), *output_array_size);
    for (index = 0, pt=*neighbor_ap_array; index < *output_array_size; index++, pt++) {
        strcpy(pt->ap_Radio,"");
        strcpy(pt->ap_SSID,"");
        strcpy(pt->ap_BSSID,"");
        strcpy(pt->ap_Mode,"");
        pt->ap_Channel=1;
        pt->ap_SignalStrength=0;
        strcpy(pt->ap_SecurityModeEnabled,"");
        strcpy(pt->ap_EncryptionMode,"");
        strcpy(pt->ap_OperatingFrequencyBand,"");
        strcpy(pt->ap_SupportedStandards,"");
        strcpy(pt->ap_OperatingStandards,"");
        strcpy(pt->ap_OperatingChannelBandwidth,"");
        pt->ap_BeaconPeriod=1;
        pt->ap_Noise=0;
        strcpy(pt->ap_BasicDataTransferRates,"");
        strcpy(pt->ap_SupportedDataTransferRates,"");
        pt->ap_DTIMPeriod=1;
        pt->ap_ChannelUtilization = 1;
    }

    status = RETURN_OK;
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return status;
}

//----------------- AP HAL -------------------------------

//>> Deprecated: used for old RDKB code.
INT wifi_getAllAssociatedDeviceDetail(INT apIndex, ULONG *output_ulong, wifi_device_t **output_struct)
{
    if (NULL == output_ulong || NULL == output_struct)
        return RETURN_ERR;
    *output_ulong = 0;
    *output_struct = NULL;
    return RETURN_OK;
}

#ifdef HAL_NETLINK_IMPL
static int AssoDevInfo_callback(struct nl_msg *msg, void *arg) {
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
    struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
    char mac_addr[20];
    static int count=0;
    int rate=0;

    wifi_device_info_t *out = (wifi_device_info_t*)arg;

    nla_parse(tb,
              NL80211_ATTR_MAX,
              genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0),
              NULL);

    if(!tb[NL80211_ATTR_STA_INFO]) {
        fprintf(stderr, "sta stats missing!\n");
        return NL_SKIP;
    }


    if(nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,tb[NL80211_ATTR_STA_INFO], stats_policy)) {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return NL_SKIP;
    }

    //devIndex starts from 1
    if( ++count == out->wifi_devIndex )
    {
        mac_addr_ntoa(mac_addr, nla_data(tb[NL80211_ATTR_MAC]));
        //Getting the mac addrress
        mac_addr_aton(out->wifi_devMacAddress,mac_addr);

        if(nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_TX_BITRATE], rate_policy)) {
            fprintf(stderr, "failed to parse nested rate attributes!");
            return NL_SKIP;
        }

        if(sinfo[NL80211_STA_INFO_TX_BITRATE]) {
            if(rinfo[NL80211_RATE_INFO_BITRATE])
                rate=nla_get_u16(rinfo[NL80211_RATE_INFO_BITRATE]);
                out->wifi_devTxRate = rate/10;
        }

        if(nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_RX_BITRATE], rate_policy)) {
            fprintf(stderr, "failed to parse nested rate attributes!");
            return NL_SKIP;
        }

        if(sinfo[NL80211_STA_INFO_RX_BITRATE]) {
            if(rinfo[NL80211_RATE_INFO_BITRATE])
                rate=nla_get_u16(rinfo[NL80211_RATE_INFO_BITRATE]);
                out->wifi_devRxRate = rate/10;
        }
        if(sinfo[NL80211_STA_INFO_SIGNAL_AVG])
            out->wifi_devSignalStrength = (int8_t)nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL_AVG]);

        out->wifi_devAssociatedDeviceAuthentiationState = 1;
        count = 0; //starts the count for next cycle
        return NL_STOP;
    }

    return NL_SKIP;

}
#endif

INT wifi_getAssociatedDeviceDetail(INT apIndex, INT devIndex, wifi_device_t *output_struct)
{
#ifdef HAL_NETLINK_IMPL
    Netlink nl = {0};
    char if_name[10] = {0};
    char interface_name[16] = {0};

    wifi_device_info_t info = {0};
    info.wifi_devIndex = devIndex;

    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;

    snprintf(if_name,sizeof(if_name),"%s", interface_name);

    nl.id = initSock80211(&nl);

    if (nl.id < 0) {
        fprintf(stderr, "Error initializing netlink \n");
        return -1;
    }

    struct nl_msg* msg = nlmsg_alloc();

    if (!msg) {
        fprintf(stderr, "Failed to allocate netlink message.\n");
        nlfree(&nl);
        return -2;
    }

    genlmsg_put(msg,
                NL_AUTO_PORT,
                NL_AUTO_SEQ,
                nl.id,
                0,
                NLM_F_DUMP,
                NL80211_CMD_GET_STATION,
                0);

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(if_name));
    nl_send_auto(nl.socket, msg);
    nl_cb_set(nl.cb,NL_CB_VALID,NL_CB_CUSTOM,AssoDevInfo_callback,&info);
    nl_recvmsgs(nl.socket, nl.cb);
    nlmsg_free(msg);
    nlfree(&nl);

    output_struct->wifi_devAssociatedDeviceAuthentiationState = info.wifi_devAssociatedDeviceAuthentiationState;
    output_struct->wifi_devRxRate = info.wifi_devRxRate;
    output_struct->wifi_devTxRate = info.wifi_devTxRate;
    output_struct->wifi_devSignalStrength = info.wifi_devSignalStrength;
    memcpy(&output_struct->wifi_devMacAddress, &info.wifi_devMacAddress, sizeof(info.wifi_devMacAddress));
    return RETURN_OK;
#else
    //iw utility to retrieve station information
#define ASSODEVFILE "/tmp/AssociatedDevice_Stats.txt"
#define SIGNALFILE "/tmp/wifi_signalstrength.txt"
#define MACFILE "/tmp/wifi_AssoMac.txt"
#define TXRATEFILE "/tmp/wifi_txrate.txt"
#define RXRATEFILE "/tmp/wifi_rxrate.txt"
    FILE *file = NULL;
    char if_name[10] = {'\0'};
    char pipeCmd[256] = {'\0'};
    char line[256] = {0};
    char interface_name[16] = {0};
    int count = 0, device = 0;

    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;

    snprintf(if_name,sizeof(if_name),"%s", interface_name);

    sprintf(pipeCmd, "iw dev %s station dump | grep %s | wc -l", if_name, if_name);
    file = popen(pipeCmd, "r");

    if(file == NULL)
        return RETURN_ERR; //popen failed

    fgets(line, sizeof line, file);
    device = atoi(line);
    pclose(file);

    if(device == 0)
        return RETURN_ERR; //No devices are connected

    sprintf(pipeCmd,"iw dev %s station dump > "ASSODEVFILE, if_name);
    system(pipeCmd);

    system("cat "ASSODEVFILE" | grep 'signal avg' | cut -d ' ' -f2 | cut -d ':' -f2 | cut -f 2 | tr -s '\n' > "SIGNALFILE);

    system("cat  "ASSODEVFILE" | grep Station | cut -d ' ' -f 2  > "MACFILE);

    system("cat  "ASSODEVFILE" | grep 'tx bitrate' | cut -d ' ' -f2 | cut -d ':' -f2 |  cut -f 2 | tr -s '\n' | cut -d '.' -f1 > "TXRATEFILE);

    system("cat  "ASSODEVFILE" | grep 'rx bitrate' | cut -d ' ' -f2 | cut -d ':' -f2 |  cut -f 2 | tr -s '\n' | cut -d '.' -f1 > "RXRATEFILE);

    //devIndex starts from 1, ++count
    if((file = fopen(SIGNALFILE, "r")) != NULL )
    {
        for(count =0;fgets(line, sizeof line, file) != NULL;)
        {
            if (++count == devIndex)
            {
                output_struct->wifi_devSignalStrength = atoi(line);
                break;
            }
        }
        fclose(file);
    }
    else
        fprintf(stderr,"fopen wifi_signalstrength.txt failed");

    if((file = fopen(MACFILE, "r")) != NULL )
    {
        for(count =0;fgets(line, sizeof line, file) != NULL;)
        {
            if (++count == devIndex)
            {
                sscanf(line, "%02x:%02x:%02x:%02x:%02x:%02x",&output_struct->wifi_devMacAddress[0],&output_struct->wifi_devMacAddress[1],&output_struct->wifi_devMacAddress[2],&output_struct->wifi_devMacAddress[3],&output_struct->wifi_devMacAddress[4],&output_struct->wifi_devMacAddress[5]);
                break;
            }
        }
        fclose(file);
    }
    else
        fprintf(stderr,"fopen wifi_AssoMac.txt failed");

    if((file = fopen(TXRATEFILE, "r")) != NULL )
    {
        for(count =0;fgets(line, sizeof line, file) != NULL;)
        {
            if (++count == devIndex)
            {
                output_struct->wifi_devTxRate = atoi(line);
                break;
            }
        }
        fclose(file);
    }
    else
        fprintf(stderr,"fopen wifi_txrate.txt failed");

    if((file = fopen(RXRATEFILE, "r")) != NULL)
    {
        for(count =0;fgets(line, sizeof line, file) != NULL;)
        {
            if (++count == devIndex)
            {
                output_struct->wifi_devRxRate = atoi(line);
                break;
            }
        }
        fclose(file);
    }
    else
        fprintf(stderr,"fopen wifi_rxrate.txt failed");

    output_struct->wifi_devAssociatedDeviceAuthentiationState = 1;

    return RETURN_OK;
#endif
}

INT wifi_kickAssociatedDevice(INT apIndex, wifi_device_t *device)
{
    if (NULL == device)
        return RETURN_ERR;
    return RETURN_OK;
}
//<<


//--------------wifi_ap_hal-----------------------------
//enables CTS protection for the radio used by this AP
INT wifi_setRadioCtsProtectionEnable(INT apIndex, BOOL enable)
{
    //save config and Apply instantly
    return RETURN_ERR;
}

// enables OBSS Coexistence - fall back to 20MHz if necessary for the radio used by this ap
INT wifi_setRadioObssCoexistenceEnable(INT apIndex, BOOL enable)
{
    char config_file[64] = {'\0'};
    char buf[64] = {'\0'};
    struct params list;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    list.name = "ht_coex";
    snprintf(buf, sizeof(buf), "%d", enable);
    list.value = buf;

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
    wifi_hostapdWrite(config_file, &list, 1);
    wifi_hostapdProcessUpdate(apIndex, &list, 1);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

//P3 // sets the fragmentation threshold in bytes for the radio used by this ap
INT wifi_setRadioFragmentationThreshold(INT apIndex, UINT threshold)
{
    char config_file[MAX_BUF_SIZE] = {'\0'};
    char buf[MAX_BUF_SIZE] = {'\0'};
    struct params list;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (threshold < 256 || threshold > 2346 )
        return RETURN_ERR;
    list.name = "fragm_threshold";
    snprintf(buf, sizeof(buf), "%d", threshold);
    list.value = buf;

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
    wifi_hostapdWrite(config_file, &list, 1);
    wifi_hostapdProcessUpdate(apIndex, &list, 1);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

// enable STBC mode in the hardwarwe, 0 == not enabled, 1 == enabled
INT wifi_setRadioSTBCEnable(INT radioIndex, BOOL STBC_Enable)
{
    char config_file[64] = {'\0'};
    char cmd[512] = {'\0'};
    char buf[512] = {'\0'};
    char stbc_config[16] = {'\0'};
    wifi_band band;
    int iterator = 0;
    BOOL current_stbc = FALSE;
    int ant_count = 0;
    int ant_bitmap = 0;
    struct params list;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    band = wifi_index_to_band(radioIndex);
    if (band == band_invalid)
        return RETURN_ERR;

    if (band == band_2_4)
        iterator = 1;
    else if (band == band_5)
        iterator = 2;
    else
        return RETURN_OK;

    wifi_getRadioTxChainMask(radioIndex, &ant_bitmap);
    for (; ant_bitmap > 0; ant_bitmap >>= 1)
        ant_count += ant_bitmap & 1;

    if (ant_count == 1 && STBC_Enable == TRUE) {
        fprintf(stderr, "%s: can not enable STBC when using only one antenna\n", __func__);
        return RETURN_OK;
    }

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);

    // set ht and vht config
    for (int i = 0; i < iterator; i++) {
        memset(stbc_config, 0, sizeof(stbc_config));
        memset(cmd, 0, sizeof(cmd));
        memset(buf, 0, sizeof(buf));
        list.name = (i == 0)?"ht_capab":"vht_capab";
        snprintf(stbc_config, sizeof(stbc_config), "%s", list.name);
        snprintf(cmd, sizeof(cmd), "cat %s | grep -E '^%s' | grep 'STBC'", config_file, stbc_config);
        _syscmd(cmd, buf, sizeof(buf));
        if (strlen(buf) != 0)
            current_stbc = TRUE;
        if (current_stbc == STBC_Enable)
            continue;

        if (STBC_Enable == TRUE) {
            // Append the STBC flags in capab config
            memset(cmd, 0, sizeof(cmd));
            if (i == 0)
                snprintf(cmd, sizeof(cmd), "sed -r -i '/^ht_capab=.*/s/$/[TX-STBC][RX-STBC1]/' %s", config_file);
            else
                snprintf(cmd, sizeof(cmd), "sed -r -i '/^vht_capab=.*/s/$/[TX-STBC-2BY1][RX-STBC-1]/' %s", config_file);
            _syscmd(cmd, buf, sizeof(buf));
        } else if (STBC_Enable == FALSE) {
            // Remove the STBC flags and remain other flags in capab
            memset(cmd, 0, sizeof(cmd));
            snprintf(cmd, sizeof(cmd), "sed -r -i 's/\\[TX-STBC(-2BY1)?*\\]//' %s", config_file);
            _syscmd(cmd, buf, sizeof(buf));
            memset(cmd, 0, sizeof(cmd));
            snprintf(cmd, sizeof(cmd), "sed -r -i 's/\\[RX-STBC-?[1-3]*\\]//' %s", config_file);
            _syscmd(cmd, buf, sizeof(buf));
        }
        wifi_hostapdRead(config_file, list.name, buf, sizeof(buf));
        list.value = buf;
        wifi_hostapdProcessUpdate(radioIndex, &list, 1);
    }

    wifi_reloadAp(radioIndex);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

// outputs A-MSDU enable status, 0 == not enabled, 1 == enabled
INT wifi_getRadioAMSDUEnable(INT radioIndex, BOOL *output_bool)
{
    char cmd[128] = {0};
    char buf[128] = {0};
    char interface_name[16] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if(output_bool == NULL)
        return RETURN_ERR;

    if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;

    sprintf(cmd, "hostapd_cli -i %s get_amsdu | awk '{print $3}'", interface_name);
    _syscmd(cmd, buf, sizeof(buf));

    if (strncmp(buf, "1", 1) == 0)
        *output_bool = TRUE;
    else
        *output_bool = FALSE;

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

// enables A-MSDU in the hardware, 0 == not enabled, 1 == enabled
INT wifi_setRadioAMSDUEnable(INT radioIndex, BOOL amsduEnable)
{
    char config_file[128] = {0};
    struct params list = {0};
    BOOL enable;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if (wifi_getRadioAMSDUEnable(radioIndex, &enable) != RETURN_OK)
        return RETURN_ERR;

    if (amsduEnable == enable)
        return RETURN_OK;

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
    list.name = "amsdu";
    list.value = amsduEnable? "1":"0";
    wifi_hostapdWrite(config_file, &list, 1);
    wifi_hostapdProcessUpdate(radioIndex, &list, 1);
    wifi_reloadAp(radioIndex);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//P2  // outputs the number of Tx streams
INT wifi_getRadioTxChainMask(INT radioIndex, INT *output_int)
{
    char buf[8] = {0};
    char cmd[128] = {0};
    int phyId = 0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    phyId = radio_index_to_phy(radioIndex);
    snprintf(cmd, sizeof(cmd), "iw phy%d info | grep 'Configured Antennas' | awk '{print $4}'", phyId);
    _syscmd(cmd, buf, sizeof(buf));

    *output_int = (INT)strtol(buf, NULL, 16);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT fitChainMask(INT radioIndex, int antcount)
{
    char buf[128] = {0};
    char cmd[128] = {0};
    char config_file[64] = {0};
    wifi_band band;
    struct params list[2] = {0};

    band = wifi_index_to_band(radioIndex);
    if (band == band_invalid)
        return RETURN_ERR;

    list[0].name = "he_mu_beamformer";
    list[1].name = "he_su_beamformer";

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
    if (antcount == 1) {
        // remove config about multiple antennas
        snprintf(cmd, sizeof(cmd), "sed -r -i 's/\\[TX-STBC(-2BY1)?*\\]//' %s", config_file);
        _syscmd(cmd, buf, sizeof(buf));

        snprintf(cmd, sizeof(cmd), "sed -r -i 's/\\[SOUNDING-DIMENSION-.\\]//' %s", config_file);
        _syscmd(cmd, buf, sizeof(buf));

        snprintf(cmd, sizeof(cmd), "sed -r -i 's/\\[SU-BEAMFORMER\\]//' %s", config_file);
        _syscmd(cmd, buf, sizeof(buf));

        snprintf(cmd, sizeof(cmd), "sed -r -i 's/\\[MU-BEAMFORMER\\]//' %s", config_file);
        _syscmd(cmd, buf, sizeof(buf));

        list[0].value = "0";
        list[1].value = "0";
    } else {
        // If we only set RX STBC means STBC is enable and TX STBC is disable when last time set one antenna. so we need to add it back.
        if (band == band_2_4 || band == band_5) {
            snprintf(cmd, sizeof(cmd), "cat %s | grep '^ht_capab=.*RX-STBC' | grep -v 'TX-STBC'", config_file);
            _syscmd(cmd, buf, sizeof(buf));
            if (strlen(buf) > 0) {
                snprintf(cmd, sizeof(cmd), "sed -r -i '/^ht_capab=.*/s/$/[TX-STBC]/' %s", config_file);
                _syscmd(cmd, buf, sizeof(buf));
            }
        }
        if (band == band_5) {
            snprintf(cmd, sizeof(cmd), "cat %s | grep '^vht_capab=.*RX-STBC' | grep -v 'TX-STBC'", config_file);
            _syscmd(cmd, buf, sizeof(buf));
            if (strlen(buf) > 0) {
                snprintf(cmd, sizeof(cmd), "sed -r -i '/^vht_capab=.*/s/$/[TX-STBC-2BY1]/' %s", config_file);
                _syscmd(cmd, buf, sizeof(buf));
            }
        }

        snprintf(cmd, sizeof(cmd), "cat %s | grep '\\[SU-BEAMFORMER\\]'", config_file);
        _syscmd(cmd, buf, sizeof(buf));
        if (strlen(buf) == 0) {
            snprintf(cmd, sizeof(cmd), "sed -r -i '/^vht_capab=.*/s/$/[SU-BEAMFORMER]/' %s", config_file);
            _syscmd(cmd, buf, sizeof(buf));
        }

        snprintf(cmd, sizeof(cmd), "cat %s | grep '\\[MU-BEAMFORMER\\]'", config_file);
        _syscmd(cmd, buf, sizeof(buf));
        if (strlen(buf) == 0) {
            snprintf(cmd, sizeof(cmd), "sed -r -i '/^vht_capab=.*/s/$/[MU-BEAMFORMER]/' %s", config_file);
            _syscmd(cmd, buf, sizeof(buf));
        }

        snprintf(cmd, sizeof(cmd), "cat %s | grep '\\[SOUNDING-DIMENSION-.\\]'", config_file);
        _syscmd(cmd, buf, sizeof(buf));
        if (strlen(buf) == 0) {
            snprintf(cmd, sizeof(cmd), "sed -r -i '/^vht_capab=.*/s/$/[SOUNDING-DIMENSION-%d]/' %s", antcount, config_file);
        } else {
            snprintf(cmd, sizeof(cmd), "sed -r -i 's/(SOUNDING-DIMENSION-)./\\1%d/' %s", antcount, config_file);
        }
        _syscmd(cmd, buf, sizeof(buf));

        list[0].value = "1";
        list[1].value = "1";
    }
    wifi_hostapdWrite(config_file, list, 2);
}

//P2  // sets the number of Tx streams to an enviornment variable
INT wifi_setRadioTxChainMask(INT radioIndex, INT numStreams)
{
    char cmd[128] = {0};
    char buf[128] = {0};
    int phyId = 0;
    int cur_mask = 0;
    int antcount = 0;
    wifi_band band;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if (numStreams <= 0) {
        fprintf(stderr, "%s: chainmask is not supported %d.\n", __func__, numStreams);
        return RETURN_ERR;
    }

    wifi_getRadioTxChainMask(radioIndex, &cur_mask);
    if (cur_mask == numStreams)
        return RETURN_OK;

    wifi_setRadioEnable(radioIndex, FALSE);

    phyId = radio_index_to_phy(radioIndex);
    sprintf(cmd, "iw phy%d set antenna 0x%x 2>&1", phyId, numStreams);
    _syscmd(cmd, buf, sizeof(buf));

    if (strlen(buf) > 0) {
        fprintf(stderr, "%s: cmd %s error, output: %s\n", __func__, cmd, buf);
        return RETURN_ERR;
    }

    // if chain mask changed, we need to make the hostapd config valid.
    for (cur_mask = numStreams; cur_mask > 0; cur_mask >>= 1) {
        antcount += cur_mask & 1;
    }
    fitChainMask(radioIndex, antcount);

    wifi_setRadioEnable(radioIndex, TRUE);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//P2  // outputs the number of Rx streams
INT wifi_getRadioRxChainMask(INT radioIndex, INT *output_int)
{
    char buf[8] = {0};
    char cmd[128] = {0};
    int phyId = 0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    phyId = radio_index_to_phy(radioIndex);
    sprintf(cmd, "iw phy%d info | grep 'Configured Antennas' | awk '{print $6}'", phyId);
    _syscmd(cmd, buf, sizeof(buf));

    *output_int = (INT)strtol(buf, NULL, 16);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

//P2  // sets the number of Rx streams to an enviornment variable
INT wifi_setRadioRxChainMask(INT radioIndex, INT numStreams)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (wifi_setRadioTxChainMask(radioIndex, numStreams) == RETURN_ERR) {
        fprintf(stderr, "%s: wifi_setRadioTxChainMask return error.\n", __func__);
        return RETURN_ERR;
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_ERR;
}

//Get radio RDG enable setting
INT wifi_getRadioReverseDirectionGrantSupported(INT radioIndex, BOOL *output_bool)
{
    if (NULL == output_bool)
        return RETURN_ERR;
    *output_bool = TRUE;
    return RETURN_OK;
}

//Get radio RDG enable setting
INT wifi_getRadioReverseDirectionGrantEnable(INT radioIndex, BOOL *output_bool)
{
    if (NULL == output_bool)
        return RETURN_ERR;
    *output_bool = TRUE;
    return RETURN_OK;
}

//Set radio RDG enable setting
INT wifi_setRadioReverseDirectionGrantEnable(INT radioIndex, BOOL enable)
{
    return RETURN_ERR;
}

//Get radio ADDBA enable setting
INT wifi_getRadioDeclineBARequestEnable(INT radioIndex, BOOL *output_bool)
{
    if (NULL == output_bool)
        return RETURN_ERR;
    *output_bool = TRUE;
    return RETURN_OK;
}

//Set radio ADDBA enable setting
INT wifi_setRadioDeclineBARequestEnable(INT radioIndex, BOOL enable)
{
    return RETURN_ERR;
}

//Get radio auto block ack enable setting
INT wifi_getRadioAutoBlockAckEnable(INT radioIndex, BOOL *output_bool)
{
    if (NULL == output_bool)
        return RETURN_ERR;
    *output_bool = TRUE;
    return RETURN_OK;
}

//Set radio auto block ack enable setting
INT wifi_setRadioAutoBlockAckEnable(INT radioIndex, BOOL enable)
{
    return RETURN_ERR;
}

//Get radio 11n pure mode enable support
INT wifi_getRadio11nGreenfieldSupported(INT radioIndex, BOOL *output_bool)
{
    if (NULL == output_bool)
        return RETURN_ERR;
    *output_bool = TRUE;
    return RETURN_OK;
}

//Get radio 11n pure mode enable setting
INT wifi_getRadio11nGreenfieldEnable(INT radioIndex, BOOL *output_bool)
{
    if (NULL == output_bool)
        return RETURN_ERR;
    *output_bool = TRUE;
    return RETURN_OK;
}

//Set radio 11n pure mode enable setting
INT wifi_setRadio11nGreenfieldEnable(INT radioIndex, BOOL enable)
{
    return RETURN_ERR;
}

//Get radio IGMP snooping enable setting
INT wifi_getRadioIGMPSnoopingEnable(INT radioIndex, BOOL *output_bool)
{
    char interface_name[16] = {0};
    char cmd[128]={0};
    char buf[4]={0};
    bool bridge = FALSE, mac80211 = FALSE;
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if(output_bool == NULL)
        return RETURN_ERR;

    *output_bool = FALSE;

    snprintf(cmd, sizeof(cmd),  "cat /sys/devices/virtual/net/%s/bridge/multicast_snooping", BRIDGE_NAME);
    _syscmd(cmd, buf, sizeof(buf));
    if (strncmp(buf, "1", 1) == 0)
        bridge = TRUE;

    if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    snprintf(cmd, sizeof(cmd),  "cat /sys/devices/virtual/net/%s/brif/%s/multicast_to_unicast", BRIDGE_NAME, interface_name);
    _syscmd(cmd, buf, sizeof(buf));
    if (strncmp(buf, "1", 1) == 0)
        mac80211 = TRUE;

    if (bridge && mac80211)
        *output_bool = TRUE;

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Set radio IGMP snooping enable setting
INT wifi_setRadioIGMPSnoopingEnable(INT radioIndex, BOOL enable)
{
    char interface_name[16] = {0};
    char cmd[128]={0};
    char buf[4]={0};
    int max_num_radios = 0;
    int apIndex = 0;
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    // bridge
    snprintf(cmd, sizeof(cmd),  "echo %d > /sys/devices/virtual/net/%s/bridge/multicast_snooping", enable, BRIDGE_NAME);
    _syscmd(cmd, buf, sizeof(buf));

    wifi_getMaxRadioNumber(&max_num_radios);
    // mac80211
    for (int i = 0; i < MAX_NUM_VAP_PER_RADIO; i++) {
        apIndex = radioIndex + i*max_num_radios;
        if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
            continue;
        snprintf(cmd, sizeof(cmd),  "echo %d > /sys/devices/virtual/net/%s/brif/%s/multicast_to_unicast", enable, BRIDGE_NAME, interface_name);
        _syscmd(cmd, buf, sizeof(buf));
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Get the Reset count of radio
INT wifi_getRadioResetCount(INT radioIndex, ULONG *output_int) 
{
    if (NULL == output_int) 
        return RETURN_ERR;
    *output_int = (radioIndex==0)? 1: 3;

    return RETURN_OK;
}


//---------------------------------------------------------------------------------------------------
//
// Additional Wifi AP level APIs used for Access Point devices
//
//---------------------------------------------------------------------------------------------------

// creates a new ap and pushes these parameters to the hardware
INT wifi_createAp(INT apIndex, INT radioIndex, CHAR *essid, BOOL hideSsid)
{
    // Deprecated when use hal version 3, use wifi_createVap() instead.
    return RETURN_OK;
}

// deletes this ap entry on the hardware, clears all internal variables associaated with this ap
INT wifi_deleteAp(INT apIndex)
{
    char interface_name[16] = {0};
    char buf[128] = {0};
    char cmd[128] = {0};

    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;

    if (wifi_setApEnable(apIndex, FALSE) != RETURN_OK)
        return RETURN_ERR;

    snprintf(cmd,sizeof(cmd),  "iw %s del", interface_name);
    _syscmd(cmd, buf, sizeof(buf));

    wifi_removeApSecVaribles(apIndex);
    return RETURN_OK;
}

// Outputs a 16 byte or less name assocated with the AP.  String buffer must be pre-allocated by the caller
INT wifi_getApName(INT apIndex, CHAR *output_string)
{
    char interface_name[16] = {0};
    if(NULL == output_string)
        return RETURN_ERR;

    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        snprintf(output_string, 16, "%s%d", AP_PREFIX, apIndex);    // For wifiagent generating data model.
    else
        snprintf(output_string, 16, "%s", interface_name);
    return RETURN_OK;
}

// Outputs the index number in that corresponds to the SSID string
INT wifi_getIndexFromName(CHAR *inputSsidString, INT *output_int)
{
    char cmd [128] = {0};
    char buf[32] = {0};
    char *apIndex_str = NULL;
    bool enable = FALSE;

#ifdef DYNAMIC_IF_NAME
    snprintf(cmd, sizeof(cmd), "grep -rn ^interface=%s$ /nvram/hostapd*.conf | cut -d '.' -f1 | cut -d 'd' -f2 | tr -d '\\n'", inputSsidString);
    _syscmd(cmd, buf, sizeof(buf));

    if (strlen(buf) != 0) {
        apIndex_str = strtok(buf, "\n");
        *output_int = strtoul(apIndex_str, NULL, 10);
        return RETURN_OK;
    }
#endif
    // If interface name is not in hostapd config, the caller maybe wifi agent to generate data model.
    apIndex_str = strstr(inputSsidString, AP_PREFIX);
    if (apIndex_str) {
        sscanf(apIndex_str + strlen(AP_PREFIX), "%d", output_int);
        return RETURN_OK;
    }
    *output_int = -1;
    return RETURN_OK;
}

INT wifi_getApIndexFromName(CHAR *inputSsidString, INT *output_int)
{
    return wifi_getIndexFromName(inputSsidString, output_int);
}

// Outputs a 32 byte or less string indicating the beacon type as "None", "Basic", "WPA", "11i", "WPAand11i"
INT wifi_getApBeaconType(INT apIndex, CHAR *output_string)
{
    char buf[MAX_BUF_SIZE] = {0};
    char cmd[MAX_CMD_SIZE] = {0};
    char config_file[MAX_BUF_SIZE] = {0};

    if(NULL == output_string)
        return RETURN_ERR;

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    if (!syn_flag)
        wifi_hostapdRead(config_file, "wpa", buf, sizeof(buf));
    else
        snprintf(buf, sizeof(buf), "%s", vap_info[apIndex].wpa);
    if((strcmp(buf,"3")==0))
        snprintf(output_string, 32, "WPAand11i");
    else if((strcmp(buf,"2")==0))
        snprintf(output_string, 32, "11i");
    else if((strcmp(buf,"1")==0))
        snprintf(output_string, 32, "WPA");
    else
        snprintf(output_string, 32, "None");

    return RETURN_OK;
}

// Sets the beacon type enviornment variable. Allowed input strings are "None", "Basic", "WPA, "11i", "WPAand11i"
INT wifi_setApBeaconType(INT apIndex, CHAR *beaconTypeString)
{
    char config_file[MAX_BUF_SIZE] = {0};
    struct params list;

    if (NULL == beaconTypeString)
        return RETURN_ERR;
    list.name = "wpa";
    list.value = "0";

    if((strcmp(beaconTypeString,"WPAand11i")==0))
        list.value="3";
    else if((strcmp(beaconTypeString,"11i")==0))
        list.value="2";
    else if((strcmp(beaconTypeString,"WPA")==0))
        list.value="1";

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdWrite(config_file, &list, 1);
    wifi_hostapdProcessUpdate(apIndex, &list, 1);
    snprintf(vap_info[apIndex].wpa, MAX_BUF_SIZE, "%s", list.value);
    //save the beaconTypeString to wifi config and hostapd config file. Wait for wifi reset or hostapd restart to apply
    return RETURN_OK;
}

// sets the beacon interval on the hardware for this AP
INT wifi_setApBeaconInterval(INT apIndex, INT beaconInterval)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    struct params params={'\0'};
    char buf[MAX_BUF_SIZE] = {'\0'};
    char config_file[MAX_BUF_SIZE] = {'\0'};

    params.name = "beacon_int";
    snprintf(buf, sizeof(buf), "%u", beaconInterval);
    params.value = buf;

    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
    wifi_hostapdWrite(config_file, &params, 1);
    
    wifi_hostapdProcessUpdate(apIndex, &params, 1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_setDTIMInterval(INT apIndex, INT dtimInterval)
{
    if (wifi_setApDTIMInterval(apIndex, dtimInterval) != RETURN_OK)
        return RETURN_ERR;
    return RETURN_OK;
}

// Get the packet size threshold supported.
INT wifi_getApRtsThresholdSupported(INT apIndex, BOOL *output_bool)
{
    //save config and apply instantly
    if (NULL == output_bool)
        return RETURN_ERR;
    *output_bool = TRUE;
    return RETURN_OK;
}

// sets the packet size threshold in bytes to apply RTS/CTS backoff rules.
INT wifi_setApRtsThreshold(INT apIndex, UINT threshold)
{
    char buf[16] = {0};
    char config_file[128] = {0};
    struct params param = {0};

    if (threshold > 65535) {
        fprintf(stderr, "%s: rts threshold %u is too big.\n", __func__, threshold);
        return RETURN_ERR;
    }

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
    snprintf(buf, sizeof(buf), "%u", threshold);
    param.name = "rts_threshold";
    param.value = buf;
    wifi_hostapdWrite(config_file, &param, 1);
    wifi_hostapdProcessUpdate(apIndex, &param, 1);
    wifi_reloadAp(apIndex);

    return RETURN_OK;
}

// outputs up to a 32 byte string as either "TKIPEncryption", "AESEncryption", or "TKIPandAESEncryption"
INT wifi_getApWpaEncryptoinMode(INT apIndex, CHAR *output_string)
{
    if (NULL == output_string)
        return RETURN_ERR;
    snprintf(output_string, 32, "TKIPandAESEncryption");
    return RETURN_OK;

}

// outputs up to a 32 byte string as either "TKIPEncryption", "AESEncryption", or "TKIPandAESEncryption"
INT wifi_getApWpaEncryptionMode(INT apIndex, CHAR *output_string)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char *param_name = NULL;
    char buf[32] = {0}, config_file[MAX_BUF_SIZE] = {0};

    if(NULL == output_string)
        return RETURN_ERR;

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    if (!syn_flag)
        wifi_hostapdRead(config_file,"wpa",buf,sizeof(buf));
    else
        snprintf(buf, sizeof(buf), "%s", vap_info[apIndex].wpa);

    if(strcmp(buf,"0")==0)
    {
        printf("%s: wpa_mode is %s ......... \n", __func__, buf);
        snprintf(output_string, 32, "None");
        return RETURN_OK;
    }
    else if((strcmp(buf,"3")==0) || (strcmp(buf,"2")==0))
        param_name = "rsn_pairwise";
    else if((strcmp(buf,"1")==0))
        param_name = "wpa_pairwise";
    else
        return RETURN_ERR;
    memset(output_string,'\0',32);
    wifi_hostapdRead(config_file,param_name,output_string,32);
    if (strlen(output_string) == 0) {       // rsn_pairwise is optional. When it is empty use wpa_pairwise instead.
        param_name = "wpa_pairwise";
        memset(output_string, '\0', 32);
        wifi_hostapdRead(config_file, param_name, output_string, 32);
    }
    wifi_dbg_printf("\n%s output_string=%s",__func__,output_string);

    if(strcmp(output_string,"TKIP CCMP") == 0)
        strncpy(output_string,"TKIPandAESEncryption", strlen("TKIPandAESEncryption"));
    else if(strcmp(output_string,"TKIP") == 0)
        strncpy(output_string,"TKIPEncryption", strlen("TKIPEncryption"));
    else if(strcmp(output_string,"CCMP") == 0)
        strncpy(output_string,"AESEncryption", strlen("AESEncryption"));

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

// sets the encyption mode enviornment variable.  Valid string format is "TKIPEncryption", "AESEncryption", or "TKIPandAESEncryption"
INT wifi_setApWpaEncryptionMode(INT apIndex, CHAR *encMode)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    struct params params={'\0'};
    char output_string[32];
    char config_file[64] = {0};

    memset(output_string,'\0',32);
    wifi_getApBeaconType(apIndex,output_string);

    if(strcmp(encMode, "TKIPEncryption") == 0)
        params.value = "TKIP";
    else if(strcmp(encMode,"AESEncryption") == 0)
        params.value = "CCMP";
    else if(strcmp(encMode,"TKIPandAESEncryption") == 0)
        params.value = "TKIP CCMP";

    if((strcmp(output_string,"WPAand11i")==0))
    {
        params.name = "wpa_pairwise";
        sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
        wifi_hostapdWrite(config_file, &params, 1);
        wifi_hostapdProcessUpdate(apIndex, &params, 1);

        params.name = "rsn_pairwise";
        sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
        wifi_hostapdWrite(config_file, &params, 1);
        wifi_hostapdProcessUpdate(apIndex, &params, 1);

        return RETURN_OK;
    }
    else if((strcmp(output_string,"11i")==0))
    {
        params.name = "rsn_pairwise";
        sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
        wifi_hostapdWrite(config_file, &params, 1);
        wifi_hostapdProcessUpdate(apIndex, &params, 1);
        return RETURN_OK;
    }
    else if((strcmp(output_string,"WPA")==0))
    {
        params.name = "wpa_pairwise";
        sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
        wifi_hostapdWrite(config_file, &params, 1);
        wifi_hostapdProcessUpdate(apIndex, &params, 1);
        return RETURN_OK;
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

// deletes internal security varable settings for this ap
INT wifi_removeApSecVaribles(INT apIndex)
{
    //TODO: remove the entry in hostapd config file
    //snprintf(cmd,sizeof(cmd), "sed -i 's/\\/nvram\\/etc\\/wpa2\\/WSC_%s.conf//g' /tmp/conf_filename", interface_name);
    //_syscmd(cmd, buf, sizeof(buf));

    //snprintf(cmd,sizeof(cmd), "sed -i 's/\\/tmp\\//sec%s//g' /tmp/conf_filename", interface_name);
    //_syscmd(cmd, buf, sizeof(buf));
    return RETURN_ERR;
}

// changes the hardware settings to disable encryption on this ap
INT wifi_disableApEncryption(INT apIndex)
{
    //Apply instantly
    return RETURN_ERR;
}

// set the authorization mode on this ap
// mode mapping as: 1: open, 2: shared, 4:auto
INT wifi_setApAuthMode(INT apIndex, INT mode)
{
    struct params params={0};
    char config_file[64] = {0};
    int ret;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

    wifi_dbg_printf("\n%s algo_mode=%d", __func__, mode);
    params.name = "auth_algs";

    if ((mode & 1 && mode & 2) || mode & 4)
        params.value = "3";
    else if (mode & 2)
        params.value = "2";
    else if (mode & 1)
        params.value = "1";
    else
        params.value = "0";

    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
    wifi_hostapdWrite(config_file, &params, 1);
    wifi_hostapdProcessUpdate(apIndex, &params, 1);
    wifi_reloadAp(apIndex);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);

    return RETURN_OK;
}

// sets an enviornment variable for the authMode. Valid strings are "None", "EAPAuthentication" or "SharedAuthentication"
INT wifi_setApBasicAuthenticationMode(INT apIndex, CHAR *authMode)
{
    //save to wifi config, and wait for wifi restart to apply
    struct params params={'\0'};
    char config_file[MAX_BUF_SIZE] = {0};
    int ret;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(authMode ==  NULL)
        return RETURN_ERR;

    wifi_dbg_printf("\n%s AuthMode=%s",__func__,authMode);
    params.name = "wpa_key_mgmt";

    if((strcmp(authMode,"PSKAuthentication") == 0) || (strcmp(authMode,"SharedAuthentication") == 0))
        params.value = "WPA-PSK";
    else if(strcmp(authMode,"EAPAuthentication") == 0)
        params.value = "WPA-EAP";
    else if (strcmp(authMode, "SAEAuthentication") == 0)
        params.value = "SAE";
    else if (strcmp(authMode, "EAP_192-bit_Authentication") == 0)
        params.value = "WPA-EAP-SUITE-B-192";
    else if (strcmp(authMode, "PSK-SAEAuthentication") == 0)
        params.value = "WPA-PSK WPA-PSK-SHA256 SAE";
    else if (strcmp(authMode, "Enhanced_Open") == 0)
        params.value = "OWE";
    else if(strcmp(authMode,"None") == 0) //Donot change in case the authMode is None
        return RETURN_OK;			  //This is taken careof in beaconType

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    ret=wifi_hostapdWrite(config_file,&params,1);
    if(!ret)
        ret=wifi_hostapdProcessUpdate(apIndex, &params, 1);
    snprintf(vap_info[apIndex].wpa_key_mgmt, MAX_BUF_SIZE, "%s", params.value);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return ret;
}

// sets an enviornment variable for the authMode. Valid strings are "None", "EAPAuthentication" or "SharedAuthentication"
INT wifi_getApBasicAuthenticationMode(INT apIndex, CHAR *authMode)
{
    //save to wifi config, and wait for wifi restart to apply
    char BeaconType[50] = {0};
    char config_file[MAX_BUF_SIZE] = {0};

    *authMode = 0;
    wifi_getApBeaconType(apIndex,BeaconType);
    printf("%s____%s \n",__FUNCTION__,BeaconType);

    if(strcmp(BeaconType,"None") == 0)
        strcpy(authMode,"None");
    else
    {
        sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
        if (!syn_flag)
            wifi_hostapdRead(config_file, "wpa_key_mgmt", authMode, 32);
        else
            snprintf(authMode, 32, "%s", vap_info[apIndex].wpa_key_mgmt);
        wifi_dbg_printf("\n[%s]: AuthMode Name is : %s",__func__,authMode);
        if(strcmp(authMode,"WPA-PSK") == 0)
            strcpy(authMode,"SharedAuthentication");
        else if(strcmp(authMode,"WPA-EAP") == 0)
            strcpy(authMode,"EAPAuthentication");
    }

    return RETURN_OK;
}

// Outputs the number of stations associated per AP
INT wifi_getApNumDevicesAssociated(INT apIndex, ULONG *output_ulong)
{
    char interface_name[16] = {0};
    char cmd[128]={0};
    char buf[128]={0};
    BOOL status = false;

    if(apIndex > MAX_APS)
        return RETURN_ERR;

    wifi_getApEnable(apIndex,&status);
    if (!status)
        return RETURN_OK;

    //sprintf(cmd, "iw dev %s station dump | grep Station | wc -l", interface_name);//alternate method
    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    sprintf(cmd, "hostapd_cli -i %s list_sta | wc -l", interface_name);
    _syscmd(cmd, buf, sizeof(buf));
    sscanf(buf,"%lu", output_ulong);

    return RETURN_OK;
}

/* Validate a network interface name: alphanumeric, dot, hyphen, underscore only. */
static int is_valid_ifname(const char *s)
{
    size_t i, len;
    if (!s) return 0;
    len = strlen(s);
    if (len == 0 || len >= IF_NAME_SIZE) return 0;
    for (i = 0; i < len; i++) {
        char c = s[i];
        if (!isalnum((unsigned char)c) && c != '.' && c != '-' && c != '_')
            return 0;
    }
    return 1;
}

/* Validate that s is a MAC address in XX:XX:XX:XX:XX:XX hex format. */
static int is_valid_mac(const char *s)
{
    int i;
    if (!s || strlen(s) != 17)
        return 0;
    for (i = 0; i < 17; i++) {
        if (i % 3 == 2) {
            if (s[i] != ':') return 0;
        } else {
            if (!isxdigit((unsigned char)s[i])) return 0;
        }
    }
    return 1;
}

// manually removes any active wi-fi association with the device specified on this ap
INT wifi_kickApAssociatedDevice(INT apIndex, CHAR *client_mac)
{
    char interface_name[16] = {0};
    char buf[64]={'\0'};

    if (!client_mac || !is_valid_mac(client_mac))
        return RETURN_ERR;
    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    snprintf(buf, sizeof(buf), "hostapd_cli -i%s disassociate %s", interface_name, client_mac);
    _syscmd(buf, buf, sizeof(buf));

    return RETURN_OK;
}

// outputs the radio index for the specified ap. similar as wifi_getSsidRadioIndex
INT wifi_getApRadioIndex(INT apIndex, INT *output_int)
{
    if(NULL == output_int)
        return RETURN_ERR;
    int max_radio_num = 0;
    wifi_getMaxRadioNumber(&max_radio_num);
    *output_int = apIndex%max_radio_num;
    return RETURN_OK;
}

// sets the radio index for the specific ap
INT wifi_setApRadioIndex(INT apIndex, INT radioIndex)
{
    //set to config only and wait for wifi reset to apply settings
    return RETURN_ERR;
}

// Get the ACL MAC list per AP
INT wifi_getApAclDevices(INT apIndex, CHAR *macArray, UINT buf_size)
{
    char interface_name[16] = {0};
    char cmd[MAX_CMD_SIZE]={'\0'};
    int ret = 0;

    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    sprintf(cmd, "hostapd_cli -i %s accept_acl SHOW | awk '{print $1}'", interface_name);
    ret = _syscmd(cmd,macArray,buf_size);
    if (ret != 0)
        return RETURN_ERR;

    return RETURN_OK;
}

INT wifi_getApDenyAclDevices(INT apIndex, CHAR *macArray, UINT buf_size)
{
    char interface_name[16] = {0};
    char cmd[MAX_CMD_SIZE]={'\0'};
    int ret = 0;

    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    sprintf(cmd, "hostapd_cli -i %s deny_acl SHOW | awk '{print $1}'", interface_name);
    ret = _syscmd(cmd,macArray,buf_size);
    if (ret != 0)
        return RETURN_ERR;

    return RETURN_OK;
}

// Get the list of stations associated per AP
INT wifi_getApDevicesAssociated(INT apIndex, CHAR *macArray, UINT buf_size)
{
    char interface_name[16] = {0};
    char cmd[128];

    if(apIndex > 3) //Currently supporting apIndex upto 3
        return RETURN_ERR;
    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    sprintf(cmd, "hostapd_cli -i %s list_sta", interface_name);
    //sprintf(buf,"iw dev %s station dump | grep Station  | cut -d ' ' -f2", interface_name);//alternate method
    _syscmd(cmd, macArray, buf_size);

    return RETURN_OK;
}

INT getAddressControlMode(INT apIndex, INT *mode)
{
    char buf [16] = {0};
    char config_file[64] = {0};

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
    if (!syn_flag)
        wifi_hostapdRead(config_file, "macaddr_acl", buf, sizeof(buf));
    else
        snprintf(buf, sizeof(buf), "%s", vap_info[apIndex].macaddr_acl);

    *mode = -1;
    // 0 use deny file, 1 use accept file
    if (strncmp(buf, "0", 1) == 0 || strncmp(buf, "1", 1) == 0)
        *mode = (INT)strtol(buf, NULL, 10);

    return RETURN_OK;
}

/* Append a MAC address as a new line to an ACL file without using a shell. */
static int acl_file_append(const char *filepath, const char *mac)
{
    FILE *fp = fopen(filepath, "a");
    if (!fp)
        return -1;
    fprintf(fp, "%s\n", mac);
    fclose(fp);
    return 0;
}

/* Remove all lines matching mac from filepath (exact whole-line match). */
static int acl_file_remove(const char *filepath, const char *mac)
{
    char tmp_path[MAX_BUF_SIZE];
    char line[64];
    FILE *rfp, *wfp;

    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", filepath);
    rfp = fopen(filepath, "r");
    if (!rfp)
        return 0; /* file absent is OK — nothing to remove */

    wfp = fopen(tmp_path, "w");
    if (!wfp) {
        fclose(rfp);
        return -1;
    }

    while (fgets(line, sizeof(line), rfp)) {
        size_t len = strlen(line);
        /* strip trailing newline for comparison */
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';
        if (strcmp(line, mac) != 0)
            fprintf(wfp, "%s\n", line);
    }
    fclose(rfp);
    fclose(wfp);
    rename(tmp_path, filepath);
    return 0;
}

// adds the mac address to the filter list
//DeviceMacAddress is in XX:XX:XX:XX:XX:XX format
INT wifi_addApAclDevice(INT apIndex, CHAR *DeviceMacAddress)
{
    char acl_file[MAX_BUF_SIZE] = {0};

    if (!is_valid_mac(DeviceMacAddress))
        return RETURN_ERR;
    if (wifi_delApAclDevice(apIndex, DeviceMacAddress) != RETURN_OK)
        return RETURN_ERR;

    snprintf(acl_file, sizeof(acl_file), "%s%d", ACL_PREFIX, apIndex);
    if (acl_file_append(acl_file, DeviceMacAddress) != 0)
        return RETURN_ERR;

    return RETURN_OK;
}

INT wifi_addApDenyAclDevice(INT apIndex, CHAR *DeviceMacAddress)
{
    char deny_file[MAX_BUF_SIZE] = {0};

    if (!is_valid_mac(DeviceMacAddress))
        return RETURN_ERR;
    if (wifi_delApAclDevice(apIndex, DeviceMacAddress) != RETURN_OK)
        return RETURN_ERR;

    snprintf(deny_file, sizeof(deny_file), "%s%d", DENY_PREFIX, apIndex);
    if (acl_file_append(deny_file, DeviceMacAddress) != 0)
        return RETURN_ERR;

    return RETURN_OK;
}

// deletes the mac address from the filter list
//DeviceMacAddress is in XX:XX:XX:XX:XX:XX format
INT wifi_delApAclDevice(INT apIndex, CHAR *DeviceMacAddress)
{
    char acl_file[MAX_BUF_SIZE] = {0};
    char deny_file[MAX_BUF_SIZE] = {0};

    if (!is_valid_mac(DeviceMacAddress))
        return RETURN_ERR;

    snprintf(acl_file,  sizeof(acl_file),  "%s%d", ACL_PREFIX,  apIndex);
    snprintf(deny_file, sizeof(deny_file), "%s%d", DENY_PREFIX, apIndex);
    acl_file_remove(acl_file,  DeviceMacAddress);
    acl_file_remove(deny_file, DeviceMacAddress);

    return RETURN_OK;
}

// outputs the number of devices in the filter list
INT wifi_getApAclDeviceNum(INT apIndex, UINT *output_uint)
{
    char cmd[MAX_BUF_SIZE]={0};
    char buf[MAX_CMD_SIZE]={0};
    int mode = -1;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(output_uint == NULL)
        return RETURN_ERR;

    getAddressControlMode(apIndex, &mode);
    if (mode == -1)
        return RETURN_OK;

    if (mode == 0)
        snprintf(cmd, sizeof(cmd), "cat %s%d | wc -l | tr -d '\\n'", DENY_PREFIX, apIndex);
    else if (mode == 1)
        snprintf(cmd, sizeof(cmd), "cat %s%d | wc -l | tr -d '\\n'", ACL_PREFIX, apIndex);
    _syscmd(cmd, buf, sizeof(buf));

    *output_uint = strtol(buf, NULL, 10);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT apply_rules(INT apIndex, CHAR *client_mac, CHAR *action, CHAR *interface)
{
        char buf[256]={'\0'};

        if (!is_valid_mac(client_mac))
            return RETURN_ERR;

        if(strcmp(action,"DENY")==0)
        {
            snprintf(buf, sizeof(buf),
                "iptables -A WifiServices%d -m physdev --physdev-in %s -m mac --mac-source %s -j DROP",
                apIndex, interface, client_mac);
            system(buf);
            return RETURN_OK;
        }

        if(strcmp(action,"ALLOW")==0)
        {
            snprintf(buf, sizeof(buf),
                "iptables -I WifiServices%d -m physdev --physdev-in %s -m mac --mac-source %s -j RETURN",
                apIndex, interface, client_mac);
            system(buf);
            return RETURN_OK;
        }

        return RETURN_ERR;
}

// enable kick for devices on acl black list
INT wifi_kickApAclAssociatedDevices(INT apIndex, BOOL enable)
{
    char aclArray[512] = {0}, *acl = NULL;
    char assocArray[512] = {0}, *asso = NULL;

    wifi_getApDenyAclDevices(apIndex, aclArray, sizeof(aclArray));
    wifi_getApDevicesAssociated(apIndex, assocArray, sizeof(assocArray));

    // if there are no devices connected there is nothing to do
    if (strlen(assocArray) < 17)
        return RETURN_OK;

    if (enable == TRUE)
    {
        //kick off the MAC which is in ACL array (deny list)
        acl = strtok(aclArray, "\r\n");
        while (acl != NULL) {
            if (strlen(acl) >= 17 && strcasestr(assocArray, acl))
                wifi_kickApAssociatedDevice(apIndex, acl);

            acl = strtok(NULL, "\r\n");
        }
		wifi_setApMacAddressControlMode(apIndex, 2);
    }
    else
    {
		wifi_setApMacAddressControlMode(apIndex, 0);
    }

#if 0
    //TODO: need to revisit below implementation
    char aclArray[512]={0}, *acl=NULL;
    char assocArray[512]={0}, *asso=NULL;
    char buf[256]={'\0'};
    char action[10]={'\0'};
    FILE *fr=NULL;
    char interface[10]={'\0'};
    char config_file[MAX_BUF_SIZE] = {0};

    wifi_getApAclDevices( apIndex, aclArray, sizeof(aclArray));
    wifi_getApDevicesAssociated( apIndex, assocArray, sizeof(assocArray));
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdRead(config_file,"interface",interface,sizeof(interface));

    sprintf(buf,"iptables -F  WifiServices%d",apIndex);
    system(buf);
    sprintf(buf,"iptables -D INPUT  -j WifiServices%d",apIndex);
    system(buf);
    sprintf(buf,"iptables -X  WifiServices%d",apIndex);
    system(buf);
    sprintf(buf,"iptables -N  WifiServices%d",apIndex);
    system(buf);
    sprintf(buf,"iptables -I INPUT 21 -j WifiServices%d",apIndex);
    system(buf);

    if ( enable == TRUE )
    {
        int device_count=0;
        strcpy(action,"DENY");
        //kick off the MAC which is in ACL array (deny list)
        acl = strtok (aclArray,",");
        while (acl != NULL) {
            if(strlen(acl)>=17)
            {
                apply_rules(apIndex, acl,action,interface);
                device_count++;
                //Register mac to be blocked ,in syscfg.db persistent storage 
                sprintf(buf,"syscfg set %dmacfilter%d %s",apIndex,device_count,acl);
                system(buf);
                sprintf(buf,"syscfg set %dcountfilter %d",apIndex,device_count);
                system(buf);
                system("syscfg commit");

                wifi_kickApAssociatedDevice(apIndex, acl);
            }
            acl = strtok (NULL, ",");
        }
    }
    else
    {
        int device_count=0;
        char cmdmac[20]={'\0'};
        strcpy(action,"ALLOW");
        //kick off the MAC which is not in ACL array (allow list)
        acl = strtok (aclArray,",");
        while (acl != NULL) {
            if(strlen(acl)>=17)
            {
                apply_rules(apIndex, acl,action,interface);
                device_count++;
                //Register mac to be Allowed ,in syscfg.db persistent storage 
                sprintf(buf,"syscfg set %dmacfilter%d %s",apIndex,device_count,acl);
                system(buf);
                sprintf(buf,"syscfg set %dcountfilter %d",apIndex,device_count);
                system(buf);
                sprintf(cmdmac,"%s",acl);
            }
            acl = strtok (NULL, ",");
        }
        sprintf(buf,"iptables -A WifiServices%d -m physdev --physdev-in %s -m mac ! --mac-source %s -j DROP",apIndex,interface,cmdmac);
        system(buf);

        //Disconnect the mac which is not in ACL
        asso = strtok (assocArray,",");
        while (asso != NULL) {
            if(strlen(asso)>=17 && !strcasestr(aclArray, asso))
                wifi_kickApAssociatedDevice(apIndex, asso);
            asso = strtok (NULL, ",");
        }
    }
#endif
    return RETURN_OK;
}

INT wifi_setPreferPrivateConnection(BOOL enable)
{
    return RETURN_OK;
}

// sets the mac address filter control mode.  0 == filter disabled, 1 == filter as whitelist, 2 == filter as blacklist
INT wifi_setApMacAddressControlMode(INT apIndex, INT filterMode)
{
    char interface_name[16] = {0};
    int items = 1;
    struct params list[2];
    char buf[MAX_BUF_SIZE] = {0};
    char config_file[MAX_BUF_SIZE] = {0}, acl_file[MAX_BUF_SIZE] = {0};
    char deny_file[MAX_BUF_SIZE] = {0};

    list[0].name = "macaddr_acl";

    if (filterMode == 0) {
        sprintf(buf, "%d", 0);
        list[0].value = buf;

        char cmd[128] = {0};
        char cmd_out[128] = {0};
        if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
            return RETURN_ERR;
        snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s deny_acl CLEAR 2> /dev/null", interface_name);
        _syscmd(cmd, cmd_out, sizeof(cmd_out));
        memset(cmd, 0, sizeof(cmd));
        // Delete deny_mac_file in hostapd configuration
        snprintf(cmd, sizeof(cmd), "sed -i '/deny_mac_file=/d' %s%d.conf ", CONFIG_PREFIX, apIndex);
        _syscmd(cmd, cmd_out, sizeof(cmd_out));
    }
    else if (filterMode == 1) {
        sprintf(buf, "%d", filterMode);
        list[0].value = buf;
        sprintf(acl_file,"%s%d",ACL_PREFIX,apIndex);
        list[1].name = "accept_mac_file";
        list[1].value = acl_file;
        items = 2;
    } else if (filterMode == 2) {
        //TODO: deny_mac_file
        sprintf(buf, "%d", 0);
        list[0].value = buf;
        list[1].name = "deny_mac_file";
        sprintf(deny_file,"%s%d", DENY_PREFIX,apIndex);
        list[1].value = deny_file;
        items = 2;
    } else {
        return RETURN_ERR;
    }

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdWrite(config_file, list, items);
    if (multiple_set == FALSE) {
        wifi_setApEnable(apIndex, FALSE);
        wifi_setApEnable(apIndex, TRUE);
    }
    snprintf(vap_info[apIndex].macaddr_acl, MAX_BUF_SIZE, "%s", list[0].value);

    return RETURN_OK;

#if 0
    if(apIndex==0 || apIndex==1)
    {
        //set the filtermode
        sprintf(buf,"syscfg set %dblockall %d",apIndex,filterMode);
        system(buf);
        system("syscfg commit");

        if(filterMode==0)
        {
            sprintf(buf,"iptables -F  WifiServices%d",apIndex);
            system(buf);
            return RETURN_OK;
        }
    }
    return RETURN_OK;
#endif
}

// enables internal gateway VLAN mode.  In this mode a Vlan tag is added to upstream (received) data packets before exiting the Wifi driver.  VLAN tags in downstream data are stripped from data packets before transmission.  Default is FALSE.
INT wifi_setApVlanEnable(INT apIndex, BOOL VlanEnabled)
{
    return RETURN_ERR;
}

// gets the vlan ID for this ap from an internal enviornment variable
INT wifi_getApVlanID(INT apIndex, INT *output_int)
{
    if(apIndex==0)
    {
        *output_int=100;
        return RETURN_OK;
    }

    return RETURN_ERR;
}

// sets the vlan ID for this ap to an internal enviornment variable
INT wifi_setApVlanID(INT apIndex, INT vlanId)
{
    //save the vlanID to config and wait for wifi reset to apply (wifi up module would read this parameters and tag the AP with vlan id)
    return RETURN_ERR;
}

// gets bridgeName, IP address and Subnet. bridgeName is a maximum of 32 characters,
INT wifi_getApBridgeInfo(INT index, CHAR *bridgeName, CHAR *IP, CHAR *subnet)
{
    snprintf(bridgeName, 32, "brlan0");
    snprintf(IP, 32, "10.0.0.1");
    snprintf(subnet, 32, "255.255.255.0");

    return RETURN_OK;
}

//sets bridgeName, IP address and Subnet to internal enviornment variables. bridgeName is a maximum of 32 characters
INT wifi_setApBridgeInfo(INT apIndex, CHAR *bridgeName, CHAR *IP, CHAR *subnet)
{
    //save settings, wait for wifi reset or wifi_pushBridgeInfo to apply.
    return RETURN_ERR;
}

// reset the vlan configuration for this ap
INT wifi_resetApVlanCfg(INT apIndex)
{
    char original_config_file[64] = {0};
    char current_config_file[64] = {0};
    char buf[64] = {0};
    char cmd[64] = {0};
    char vlan_file[64] = {0};
    char vlan_tagged_interface[16] = {0};
    char vlan_bridge[16] = {0};
    char vlan_naming[16] = {0};
    struct params list[4] = {0};
    wifi_band band;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    band = wifi_index_to_band(apIndex);
    if (band == band_2_4)
        sprintf(original_config_file, "/etc/hostapd-2G.conf");
    else if (band == band_5)
        sprintf(original_config_file, "/etc/hostapd-5G.conf");
    else if (band == band_6)
        sprintf(original_config_file, "/etc/hostapd-6G.conf");

    wifi_hostapdRead(original_config_file, "vlan_file", vlan_file, sizeof(vlan_file));

    if (strlen(vlan_file) == 0)
        strcpy(vlan_file, VLAN_FILE);

    /* Create the file atomically if absent — avoids TOCTOU from access()+shell */
    {
        int _fd = open(vlan_file, O_CREAT | O_WRONLY, 0600);
        if (_fd >= 0) close(_fd);
    }
    list[0].name = "vlan_file";
    list[0].value = vlan_file;

    wifi_hostapdRead(original_config_file, "vlan_tagged_interface", vlan_tagged_interface, sizeof(vlan_tagged_interface));
    list[1].name = "vlan_tagged_interface";
    list[1].value = vlan_tagged_interface;

    wifi_hostapdRead(original_config_file, "vlan_bridge", vlan_bridge, sizeof(vlan_bridge));
    list[2].name = "vlan_bridge";
    list[2].value = vlan_bridge;

    wifi_hostapdRead(original_config_file, "vlan_naming", vlan_naming, sizeof(vlan_naming));
    list[3].name = "vlan_naming";
    list[3].value = vlan_naming;

    sprintf(current_config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
    wifi_hostapdWrite(current_config_file, list, 4);
    //Reapply vlan settings
    // wifi_pushBridgeInfo(apIndex);

    // restart this ap
    wifi_setApEnable(apIndex, FALSE);
    wifi_setApEnable(apIndex, TRUE);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

// creates configuration variables needed for WPA/WPS.  These variables are implementation dependent and in some implementations these variables are used by hostapd when it is started.  Specific variables that are needed are dependent on the hostapd implementation. These variables are set by WPA/WPS security functions in this wifi HAL.  If not needed for a particular implementation this function may simply return no error.
INT wifi_createHostApdConfig(INT apIndex, BOOL createWpsCfg)
{
    return RETURN_ERR;
}

// starts hostapd, uses the variables in the hostapd config with format compatible with the specific hostapd implementation
INT wifi_startHostApd()
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    system("systemctl start hostapd.service");
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
    //sprintf(cmd, "hostapd  -B `cat /tmp/conf_filename` -e /nvram/etc/wpa2/entropy -P /tmp/hostapd.pid 1>&2");
}

// stops hostapd
INT wifi_stopHostApd()                                        
{
    char cmd[128] = {0};
    char buf[128] = {0};

    sprintf(cmd,"systemctl stop hostapd");
    _syscmd(cmd, buf, sizeof(buf));

    return RETURN_OK;
}

// restart hostapd dummy function
INT wifi_restartHostApd()
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    system("systemctl restart hostapd-global");
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

static int align_hostapd_config(int index)
{
    ULONG lval;
    wifi_getRadioChannel(index%2, &lval);
    wifi_setRadioChannel(index%2, lval);
    return RETURN_OK;
}

// sets the AP enable status variable for the specified ap.
INT wifi_setApEnable(INT apIndex, BOOL enable)
{
    char interface_name[16] = {0};
    char config_file[MAX_BUF_SIZE] = {0};
    char cmd[MAX_CMD_SIZE] = {0};
    char buf[MAX_BUF_SIZE] = {0};
    BOOL status;
    int  max_radio_num = 0;
    int phyId = 0;

    wifi_getApEnable(apIndex,&status);

    wifi_getMaxRadioNumber(&max_radio_num);
    if (enable == status)
        return RETURN_OK;

    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;

    if (enable == TRUE) {
        int radioIndex = apIndex % max_radio_num;
        phyId = radio_index_to_phy(radioIndex);
        sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
        //Hostapd will bring up this interface
        sprintf(cmd, "hostapd_cli -i global raw REMOVE %s", interface_name);
        _syscmd(cmd, buf, sizeof(buf));
        if (!(apIndex/max_radio_num)) {
	        sprintf(cmd, "iw %s del", interface_name);
	        _syscmd(cmd, buf, sizeof(buf));
            if (single_wiphy)
                sprintf(cmd, "iw phy phy0 interface add %s type __ap radios %d", interface_name, radioIndex);
            else
	            sprintf(cmd, "iw phy phy%d interface add %s type __ap", phyId, interface_name);
	        _syscmd(cmd, buf, sizeof(buf));
        }
        if (single_wiphy)
            sprintf(cmd, "hostapd_cli -i global raw ADD bss_config=phy0.%d:%s", radioIndex, config_file);
        else
            sprintf(cmd, "hostapd_cli -i global raw ADD bss_config=phy%d:%s", phyId, config_file);
        _syscmd(cmd, buf, sizeof(buf));
    }
    else {
        sprintf(cmd, "hostapd_cli -i global raw REMOVE %s", interface_name);
        _syscmd(cmd, buf, sizeof(buf));
        sprintf(cmd, "ip link set %s down", interface_name);
        _syscmd(cmd, buf, sizeof(buf));
    }

    snprintf(cmd, sizeof(cmd), "sed -i -n -e '/^%s=/!p' -e '$a%s=%d' %s",
                  interface_name, interface_name, enable, VAP_STATUS_FILE);
    _syscmd(cmd, buf, sizeof(buf));
    //Wait for wifi up/down to apply
    return RETURN_OK;
}

// Outputs the setting of the internal variable that is set by wifi_setApEnable().
INT wifi_getApEnable(INT apIndex, BOOL *output_bool)
{
    char interface_name[16] = {0};
    char cmd[MAX_CMD_SIZE] = {'\0'};
    char buf[MAX_BUF_SIZE] = {'\0'};

    if((!output_bool) || (apIndex < 0) || (apIndex >= MAX_APS))
        return RETURN_ERR;

    *output_bool = 0;

    if((apIndex >= 0) && (apIndex < MAX_APS))//Handling 6 APs
    {
        if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK) {
            *output_bool = FALSE;
            return RETURN_OK;
        }
        sprintf(cmd, "ifconfig %s 2> /dev/null | grep UP", interface_name);
        *output_bool = _syscmd(cmd,buf,sizeof(buf))?0:1;
    }

    return RETURN_OK;
}

// Outputs the AP "Enabled" "Disabled" status from driver 
INT wifi_getApStatus(INT apIndex, CHAR *output_string) 
{
    char cmd[128] = {0};
    char buf[128] = {0};
    BOOL output_bool;

    if ( NULL == output_string)
        return RETURN_ERR;
    wifi_getApEnable(apIndex,&output_bool);

    if(output_bool == 1) 
        snprintf(output_string, 32, "Up");
    else
        snprintf(output_string, 32, "Disable");

    return RETURN_OK;
}

//Indicates whether or not beacons include the SSID name.
// outputs a 1 if SSID on the AP is enabled, else outputs 0
INT wifi_getApSsidAdvertisementEnable(INT apIndex, BOOL *output)
{
    //get the running status
    char config_file[MAX_BUF_SIZE] = {0};
    char buf[16] = {0};

    if (!output)
        return RETURN_ERR;

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    if (!syn_flag)
        wifi_hostapdRead(config_file, "ignore_broadcast_ssid", buf, sizeof(buf));
    else
        snprintf(buf, sizeof(buf), "%s",vap_info[apIndex].ignore_broadcast_ssid);
    // default is enable
    if (strlen(buf) == 0 || strncmp("0", buf, 1) == 0)
        *output = TRUE;

    return RETURN_OK;
}

// sets an internal variable for ssid advertisement.  Set to 1 to enable, set to 0 to disable
INT wifi_setApSsidAdvertisementEnable(INT apIndex, BOOL enable)
{
    //store the config, apply instantly
    char config_file[MAX_BUF_SIZE] = {0};
    struct params list;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    list.name = "ignore_broadcast_ssid";
    list.value = enable?"0":"1";

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdWrite(config_file, &list, 1);
    wifi_hostapdProcessUpdate(apIndex, &list, 1);
    //TODO: call hostapd_cli for dynamic_config_control
    wifi_reloadAp(apIndex);
    snprintf(vap_info[apIndex].ignore_broadcast_ssid, MAX_BUF_SIZE, "%s", list.value);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

//The maximum number of retransmission for a packet. This corresponds to IEEE 802.11 parameter dot11ShortRetryLimit.
INT wifi_getApRetryLimit(INT apIndex, UINT *output_uint)
{
    //get the running status
    if(!output_uint)
        return RETURN_ERR;
    *output_uint=16;
    return RETURN_OK;
}

INT wifi_setApRetryLimit(INT apIndex, UINT number)
{
    //apply instantly
    return RETURN_ERR;
}

//Indicates whether this access point supports WiFi Multimedia (WMM) Access Categories (AC).
INT wifi_getApWMMCapability(INT apIndex, BOOL *output)
{
    if(!output)
        return RETURN_ERR;
    *output=TRUE;
    return RETURN_OK;
}

//Indicates whether this access point supports WMM Unscheduled Automatic Power Save Delivery (U-APSD). Note: U-APSD support implies WMM support.
INT wifi_getApUAPSDCapability(INT apIndex, BOOL *output)
{
    //get the running status from driver
    char cmd[128] = {0};
    char buf[128] = {0};
    int max_radio_num = 0, radioIndex = 0;
    int phyId = 0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    wifi_getMaxRadioNumber(&max_radio_num);
    radioIndex = apIndex % max_radio_num;
    phyId = radio_index_to_phy(radioIndex);
    snprintf(cmd, sizeof(cmd), "iw phy phy%d info | grep u-APSD", phyId);
    _syscmd(cmd,buf, sizeof(buf));

    if (strlen(buf) > 0)
        *output = true;

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

//Whether WMM support is currently enabled. When enabled, this is indicated in beacon frames.
INT wifi_getApWmmEnable(INT apIndex, BOOL *output)
{
    //get the running status from driver
    if(!output)
        return RETURN_ERR;

    char config_file[MAX_BUF_SIZE] = {0};
    char buf[16] = {0};

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdRead(config_file, "wmm_enabled", buf, sizeof(buf));
    if (strlen(buf) == 0 || strncmp("1", buf, 1) == 0)
        *output = TRUE;
    else
        *output = FALSE;

    return RETURN_OK;
}

// enables/disables WMM on the hardwawre for this AP.  enable==1, disable == 0
INT wifi_setApWmmEnable(INT apIndex, BOOL enable)
{
    //Save config and apply instantly.
    char config_file[MAX_BUF_SIZE] = {0};
    struct params list;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    list.name = "wmm_enabled";
    list.value = enable?"1":"0";

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdWrite(config_file, &list, 1);
    wifi_hostapdProcessUpdate(apIndex, &list, 1);
    wifi_reloadAp(apIndex);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

//Whether U-APSD support is currently enabled. When enabled, this is indicated in beacon frames. Note: U-APSD can only be enabled if WMM is also enabled.
INT wifi_getApWmmUapsdEnable(INT apIndex, BOOL *output)
{
    //get the running status from driver
    if(!output)
        return RETURN_ERR;

    char config_file[128] = {0};
    char buf[16] = {0};

    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
    wifi_hostapdRead(config_file, "uapsd_advertisement_enabled", buf, sizeof(buf));
    if (strlen(buf) == 0 || strncmp("1", buf, 1) == 0)
        *output = TRUE;
    else
        *output = FALSE;

    return RETURN_OK;
}

// enables/disables Automatic Power Save Delivery on the hardwarwe for this AP
INT wifi_setApWmmUapsdEnable(INT apIndex, BOOL enable)
{
    //save config and apply instantly.
    char config_file[MAX_BUF_SIZE] = {0};
    struct params list;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    list.name = "uapsd_advertisement_enabled";
    list.value = enable?"1":"0";

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdWrite(config_file, &list, 1);
    wifi_hostapdProcessUpdate(apIndex, &list, 1);
    wifi_reloadAp(apIndex);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

// Sets the WMM ACK policy on the hardware. AckPolicy false means do not acknowledge, true means acknowledge
INT wifi_setApWmmOgAckPolicy(INT apIndex, INT class, BOOL ackPolicy)  //RDKB
{
    char interface_name[16] = {0};
    // assume class 0->BE, 1->BK, 2->VI, 3->VO
    char cmd[128] = {0};
    char buf[128] = {0};
    char ack_filepath[128] = {0};
    uint16_t bitmap = 0;
    uint16_t class_map[4] = {0x0009, 0x0006, 0x0030, 0x00C0};
    FILE *f = NULL;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

    // Get current setting
    snprintf(ack_filepath, sizeof(ack_filepath), "%s%d.txt", NOACK_MAP_FILE, apIndex);
    snprintf(cmd, sizeof(cmd), "cat %s 2> /dev/null", ack_filepath);
    _syscmd(cmd, buf, sizeof(buf));
    if (strlen(buf) > 0)
        bitmap = strtoul(buf, NULL, 10);

    bitmap = strtoul(buf, NULL, 10);

    if (ackPolicy == TRUE) {    // True, unset this class
        bitmap &= ~class_map[class];
    } else {                    // False, set this class
        bitmap |= class_map[class];
    }

    f = fopen(ack_filepath, "w");
    if (f == NULL) {
        fprintf(stderr, "%s: fopen failed\n", __func__);
        return RETURN_ERR;
    }
    fprintf(f, "%hu", bitmap);
    fclose(f);

    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    snprintf(cmd, sizeof(cmd), "iw dev %s set noack_map 0x%04x\n", interface_name, bitmap);
    _syscmd(cmd, buf, sizeof(buf));

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
    return RETURN_OK;
}

//The maximum number of devices that can simultaneously be connected to the access point. A value of 0 means that there is no specific limit.
INT wifi_getApMaxAssociatedDevices(INT apIndex, UINT *output_uint)
{
    //get the running status from driver
    if(!output_uint)
        return RETURN_ERR;

    char output[16]={'\0'};
    char config_file[MAX_BUF_SIZE] = {0};

    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
    if (!syn_flag)
        wifi_hostapdRead(config_file, "max_num_sta", output, sizeof(output));
    else
        snprintf(output, sizeof(output), "%s", vap_info[apIndex].max_sta);
    if (strlen(output) == 0) *output_uint = MAX_ASSOCIATED_STA_NUM;
    else {
        int device_num = atoi(output);
        if (device_num > MAX_ASSOCIATED_STA_NUM || device_num < 0) {
            wifi_dbg_printf("\n[%s]: get max_num_sta error: %d", __func__, device_num);
            return RETURN_ERR;
        }
        else {
            *output_uint = device_num;
        }
    }

    return RETURN_OK;
}

INT wifi_setApMaxAssociatedDevices(INT apIndex, UINT number)
{
    //store to wifi config, apply instantly
    char str[MAX_BUF_SIZE]={'\0'};
    char cmd[MAX_CMD_SIZE]={'\0'};
    struct params params;
    char config_file[MAX_BUF_SIZE] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (number > MAX_ASSOCIATED_STA_NUM) {
        WIFI_ENTRY_EXIT_DEBUG("%s: Invalid input\n",__func__);
        return RETURN_OK;
    }
    sprintf(str, "%d", number);
    params.name = "max_num_sta";
    params.value = str;

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX, apIndex);
    int ret = wifi_hostapdWrite(config_file, &params, 1);
    if (ret) {
        WIFI_ENTRY_EXIT_DEBUG("Inside %s: wifi_hostapdWrite() return %d\n"
                ,__func__, ret);
    }

    ret = wifi_hostapdProcessUpdate(apIndex, &params, 1);
    if (ret) {
        WIFI_ENTRY_EXIT_DEBUG("Inside %s: wifi_hostapdProcessUpdate() return %d\n"
                ,__func__, ret);
    }
    wifi_reloadAp(apIndex);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

//The HighWatermarkThreshold value that is lesser than or equal to MaxAssociatedDevices. Setting this parameter does not actually limit the number of clients that can associate with this access point as that is controlled by MaxAssociatedDevices.	MaxAssociatedDevices or 50. The default value of this parameter should be equal to MaxAssociatedDevices. In case MaxAssociatedDevices is 0 (zero), the default value of this parameter should be 50. A value of 0 means that there is no specific limit and Watermark calculation algorithm should be turned off.
INT wifi_getApAssociatedDevicesHighWatermarkThreshold(INT apIndex, UINT *output_uint)
{
    //get the current threshold
    if(!output_uint)
        return RETURN_ERR;
    wifi_getApMaxAssociatedDevices(apIndex, output_uint);
    if (*output_uint == 0)
        *output_uint = 50;
    return RETURN_OK;
}

INT wifi_setApAssociatedDevicesHighWatermarkThreshold(INT apIndex, UINT Threshold)
{
    //store the config, reset threshold, reset AssociatedDevicesHighWatermarkThresholdReached, reset AssociatedDevicesHighWatermarkDate to current time
    if (!wifi_setApMaxAssociatedDevices(apIndex, Threshold))
        return RETURN_OK;
    return RETURN_ERR;
}

//Number of times the current total number of associated device has reached the HighWatermarkThreshold value. This calculation can be based on the parameter AssociatedDeviceNumberOfEntries as well. Implementation specifics about this parameter are left to the product group and the device vendors. It can be updated whenever there is a new client association request to the access point.
INT wifi_getApAssociatedDevicesHighWatermarkThresholdReached(INT apIndex, UINT *output_uint)
{
    if(!output_uint)
        return RETURN_ERR;
    *output_uint = 3;
    return RETURN_OK;
}

//Maximum number of associated devices that have ever associated with the access point concurrently since the last reset of the device or WiFi module.
INT wifi_getApAssociatedDevicesHighWatermark(INT apIndex, UINT *output_uint)
{
    if(!output_uint)
        return RETURN_ERR;
    *output_uint = 3;
    return RETURN_OK;
}

//Date and Time at which the maximum number of associated devices ever associated with the access point concurrenlty since the last reset of the device or WiFi module (or in short when was X_COMCAST-COM_AssociatedDevicesHighWatermark updated). This dateTime value is in UTC.
INT wifi_getApAssociatedDevicesHighWatermarkDate(INT apIndex, ULONG *output_in_seconds)
{
    if(!output_in_seconds)
        return RETURN_ERR;
    *output_in_seconds = 0;
    return RETURN_OK;
}

//Comma-separated list of strings. Indicates which security modes this AccessPoint instance is capable of supporting. Each list item is an enumeration of: None,WEP-64,WEP-128,WPA-Personal,WPA2-Personal,WPA-WPA2-Personal,WPA-Enterprise,WPA2-Enterprise,WPA-WPA2-Enterprise
INT wifi_getApSecurityModesSupported(INT apIndex, CHAR *output)
{
    if(!output || apIndex>=MAX_APS)
        return RETURN_ERR;
    //snprintf(output, 128, "None,WPA-Personal,WPA2-Personal,WPA-WPA2-Personal,WPA-Enterprise,WPA2-Enterprise,WPA-WPA2-Enterprise");
    snprintf(output, 128, "None,WPA2-Personal,WPA-WPA2-Personal,WPA2-Enterprise,WPA-WPA2-Enterprise,WPA3-Personal,WPA3-Enterprise");
    return RETURN_OK;
}		

//The value MUST be a member of the list reported by the ModesSupported parameter. Indicates which security mode is enabled.
INT wifi_getApSecurityModeEnabled(INT apIndex, CHAR *output)
{
    char config_file[128] = {0};
    char wpa[16] = {0};
    char key_mgmt[64] = {0};
    char buf[16] = {0};
    if (!output)
        return RETURN_ERR;

    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
    if (!syn_flag)
        wifi_hostapdRead(config_file, "wpa", wpa, sizeof(wpa));
    else
        snprintf(wpa, sizeof(wpa), "%s", vap_info[apIndex].wpa);

    strcpy(output, "None");//Copying "None" to output string for default case
    if (!syn_flag)
        wifi_hostapdRead(config_file, "wpa_key_mgmt", key_mgmt, sizeof(key_mgmt));
    else
        snprintf(key_mgmt, sizeof(key_mgmt), "%s", vap_info[apIndex].wpa_key_mgmt);
    if (strstr(key_mgmt, "WPA-PSK") && strstr(key_mgmt, "SAE") == NULL) {
        if (!strcmp(wpa, "1"))
            snprintf(output, 32, "WPA-Personal");
        else if (!strcmp(wpa, "2"))
            snprintf(output, 32, "WPA2-Personal");
        else if (!strcmp(wpa, "3"))
            snprintf(output, 32, "WPA-WPA2-Personal");

    } else if (strstr(key_mgmt, "WPA-EAP-SUITE-B-192")) {
        snprintf(output, 32, "WPA3-Enterprise");
    } else if (strstr(key_mgmt, "WPA-EAP")) {
        if (!strcmp(wpa, "1"))
            snprintf(output, 32, "WPA-Enterprise");
        else if (!strcmp(wpa, "2"))
            snprintf(output, 32, "WPA2-Enterprise");
        else if (!strcmp(wpa, "3"))
            snprintf(output, 32, "WPA-WPA2-Enterprise");
    } else if (strstr(key_mgmt, "SAE")) {
        if (strstr(key_mgmt, "WPA-PSK") == NULL)
            snprintf(output, 32, "WPA3-Personal");
        else
            snprintf(output, 32, "WPA3-Personal-Transition");
    }

    //save the beaconTypeString to wifi config and hostapd config file. Wait for wifi reset or hostapd restart to apply
    return RETURN_OK;
#if 0
    //TODO: need to revisit below implementation
    char securityType[32], authMode[32];
    int enterpriseMode=0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(!output)
        return RETURN_ERR;

    wifi_getApBeaconType(apIndex, securityType);
    strcpy(output,"None");//By default, copying "None" to output string
    if (strncmp(securityType,"None", strlen("None")) == 0)
        return RETURN_OK;

    wifi_getApBasicAuthenticationMode(apIndex, authMode);
    enterpriseMode = (strncmp(authMode, "EAPAuthentication", strlen("EAPAuthentication")) == 0)? 1: 0;

    if (strncmp(securityType, "WPAand11i", strlen("WPAand11i")) == 0)
        snprintf(output, 32, enterpriseMode==1? "WPA-WPA2-Enterprise": "WPA-WPA2-Personal");
    else if (strncmp(securityType, "WPA", strlen("WPA")) == 0)
        snprintf(output, 32, enterpriseMode==1? "WPA-Enterprise": "WPA-Personal");
    else if (strncmp(securityType, "11i", strlen("11i")) == 0)
        snprintf(output, 32, enterpriseMode==1? "WPA2-Enterprise": "WPA2-Personal");
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
#endif
}
  
INT wifi_setApSecurityModeEnabled(INT apIndex, CHAR *encMode)
{
    char securityType[32];
    char authMode[32];

    //store settings and wait for wifi up to apply
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(!encMode)
        return RETURN_ERR;

    if (strcmp(encMode, "None")==0)
    {
        strcpy(securityType,"None");
        strcpy(authMode,"None");
    }
    else if (strcmp(encMode, "WPA-WPA2-Personal")==0)
    {
        strcpy(securityType,"WPAand11i");
        strcpy(authMode,"PSKAuthentication");
    }
    else if (strcmp(encMode, "WPA-WPA2-Enterprise")==0)
    {
        strcpy(securityType,"WPAand11i");
        strcpy(authMode,"EAPAuthentication");
    }
    else if (strcmp(encMode, "WPA-Personal")==0)
    {
        strcpy(securityType,"WPA");
        strcpy(authMode,"PSKAuthentication");
    }
    else if (strcmp(encMode, "WPA-Enterprise")==0)
    {
        strcpy(securityType,"WPA");
        strcpy(authMode,"EAPAuthentication");
    }
    else if (strcmp(encMode, "WPA2-Personal")==0)
    {
        strcpy(securityType,"11i");
        strcpy(authMode,"PSKAuthentication");
    }
    else if (strcmp(encMode, "WPA2-Enterprise")==0)
    {
        strcpy(securityType,"11i");
        strcpy(authMode,"EAPAuthentication");
    }
    else if (strcmp(encMode, "WPA3-Personal") == 0)
    {
        strcpy(securityType,"11i");
        strcpy(authMode,"SAEAuthentication");
    }
    else if (strcmp(encMode, "WPA3-Personal-Transition") == 0)
    {
        strcpy(securityType, "11i");
        strcpy(authMode, "PSK-SAEAuthentication");
    }
    else if (strcmp(encMode, "WPA3-Enterprise") == 0)
    {
        strcpy(securityType,"11i");
        strcpy(authMode,"EAP_192-bit_Authentication");
    }
    else if (strcmp(encMode, "OWE") == 0)
    {
        strcpy(securityType,"11i");
        strcpy(authMode,"Enhanced_Open");
    }
    else
    {
        strcpy(securityType,"None");
        strcpy(authMode,"None");
    }
    wifi_setApBeaconType(apIndex, securityType);
    wifi_setApBasicAuthenticationMode(apIndex, authMode);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}   


// Get PreSharedKey associated with a Access Point.
//A literal PreSharedKey (PSK) expressed as a hexadecimal string.
INT wifi_getApSecurityPreSharedKey(INT apIndex, CHAR *output_string)
{
    char buf[16] = {0};
    char config_file[MAX_BUF_SIZE] = {0};

    if(output_string==NULL)
        return RETURN_ERR;

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    if (!syn_flag)
        wifi_hostapdRead(config_file,"wpa",buf,sizeof(buf));
    else
        snprintf(buf, sizeof(buf), "%s", vap_info[apIndex].wpa);
    if(strcmp(buf,"0")==0)
    {
        printf("wpa_mode is %s ......... \n",buf);
        return RETURN_ERR;
    }

    wifi_dbg_printf("\nFunc=%s\n",__func__);
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdRead(config_file,"wpa_psk",output_string,65);
    wifi_dbg_printf("\noutput_string=%s\n",output_string);

    return RETURN_OK;
}

// Set PreSharedKey associated with a Access Point.
// A literal PreSharedKey (PSK) expressed as a hexadecimal string.
INT wifi_setApSecurityPreSharedKey(INT apIndex, CHAR *preSharedKey)
{
    //save to wifi config and hotapd config. wait for wifi reset or hostapd restet to apply
    struct params params={'\0'};
    int ret;
    char config_file[MAX_BUF_SIZE] = {0};

    if(NULL == preSharedKey)
        return RETURN_ERR;

    params.name = "wpa_psk";

    if(strlen(preSharedKey) != 64)
    {
        wifi_dbg_printf("\nCannot Set Preshared Key length of preshared key should be 64 chars\n");
        return RETURN_ERR;
    }
    params.value = preSharedKey;
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    ret = wifi_hostapdWrite(config_file, &params, 1);
    if(!ret) {
        ret = wifi_hostapdProcessUpdate(apIndex, &params, 1);
        wifi_reloadAp(apIndex);
    }
    return ret;
    //TODO: call hostapd_cli for dynamic_config_control
}

//A passphrase from which the PreSharedKey is to be generated, for WPA-Personal or WPA2-Personal or WPA-WPA2-Personal security modes.
// outputs the passphrase, maximum 63 characters
INT wifi_getApSecurityKeyPassphrase(INT apIndex, CHAR *output_string)
{
    char config_file[MAX_BUF_SIZE] = {0}, buf[32] = {0};

    wifi_dbg_printf("\nFunc=%s\n",__func__);
    if (NULL == output_string)
        return RETURN_ERR;

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    if (!syn_flag)
        wifi_hostapdRead(config_file,"wpa",buf,sizeof(buf));
    else
        snprintf(buf, sizeof(buf), "%s", vap_info[apIndex].wpa);
    if(strcmp(buf,"0")==0)
    {
        printf("wpa_mode is %s ......... \n",buf);
        return RETURN_ERR;
    }

    if (!syn_flag)
        wifi_hostapdRead(config_file,"wpa_passphrase",output_string,64);
    else
        snprintf(output_string, 64, "%s", vap_info[apIndex].wpa_passphrase);
    wifi_dbg_printf("\noutput_string=%s\n",output_string);

    return RETURN_OK;
}

// sets the passphrase enviornment variable, max 63 characters
INT wifi_setApSecurityKeyPassphrase(INT apIndex, CHAR *passPhrase)
{
    //save to wifi config and hotapd config. wait for wifi reset or hostapd restet to apply
    struct params params={'\0'};
    char config_file[MAX_BUF_SIZE] = {0};
    int ret;

    if(NULL == passPhrase)
        return RETURN_ERR;

    {
        size_t pp_len = strlen(passPhrase);
        size_t pp_i;
        if (pp_len < 8 || pp_len > 63) {
            wifi_dbg_printf("\nCannot Set Preshared Key length of preshared key should be 8 to 63 chars\n");
            return RETURN_ERR;
        }
        /* Reject control characters and newlines to prevent config injection */
        for (pp_i = 0; pp_i < pp_len; pp_i++) {
            unsigned char c = (unsigned char)passPhrase[pp_i];
            if (c < 0x20 || c == 0x7f)
                return RETURN_ERR;
        }
    }
    params.name = "wpa_passphrase";
    params.value = passPhrase;
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    ret=wifi_hostapdWrite(config_file,&params,1);
    if(!ret) {
        wifi_hostapdProcessUpdate(apIndex, &params, 1);
        wifi_reloadAp(apIndex);
    }
    snprintf(vap_info[apIndex].wpa_passphrase, MAX_BUF_SIZE, "%s", passPhrase);

    return ret;
}

//When set to true, this AccessPoint instance's WiFi security settings are reset to their factory default values. The affected settings include ModeEnabled, WEPKey, PreSharedKey and KeyPassphrase.
INT wifi_setApSecurityReset(INT apIndex)
{
    char original_config_file[64] = {0};
    char current_config_file[64] = {0};
    char buf[64] = {0};
    char cmd[64] = {0};
    char wpa[4] = {0};
    char wpa_psk[64] = {0};
    char wpa_passphrase[64] = {0};
    char wpa_psk_file[128] = {0};
    char wpa_key_mgmt[64] = {0};
    char wpa_pairwise[32] = {0};
    wifi_band band;
    struct params list[6];

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    band = wifi_index_to_band(apIndex);
    if (band == band_2_4)
        sprintf(original_config_file, "/etc/hostapd-2G.conf");
    else if (band == band_5)
        sprintf(original_config_file, "/etc/hostapd-5G.conf");
    else if (band == band_6)
        sprintf(original_config_file, "/etc/hostapd-6G.conf");
    else
        return RETURN_ERR;

    wifi_hostapdRead(original_config_file, "wpa", wpa, sizeof(wpa));
    list[0].name = "wpa";
    list[0].value = wpa;
    
    wifi_hostapdRead(original_config_file, "wpa_psk", wpa_psk, sizeof(wpa_psk));
    list[1].name = "wpa_psk";
    list[1].value = wpa_psk;

    wifi_hostapdRead(original_config_file, "wpa_passphrase", wpa_passphrase, sizeof(wpa_passphrase));
    list[2].name = "wpa_passphrase";
    list[2].value = wpa_passphrase;

    wifi_hostapdRead(original_config_file, "wpa_psk_file", wpa_psk_file, sizeof(wpa_psk_file));

    if (strlen(wpa_psk_file) == 0)
        strcpy(wpa_psk_file, PSK_FILE);

    /* Create the file atomically if absent — avoids TOCTOU from access()+shell */
    {
        int _fd = open(wpa_psk_file, O_CREAT | O_WRONLY, 0600);
        if (_fd >= 0) close(_fd);
    }
    list[3].name = "wpa_psk_file";
    list[3].value = wpa_psk_file;

    wifi_hostapdRead(original_config_file, "wpa_key_mgmt", wpa_key_mgmt, sizeof(wpa_key_mgmt));
    list[4].name = "wpa_key_mgmt";
    list[4].value = wpa_key_mgmt;

    wifi_hostapdRead(original_config_file, "wpa_pairwise", wpa_pairwise, sizeof(wpa_pairwise));
    list[5].name = "wpa_pairwise";
    list[5].value = wpa_pairwise;

    sprintf(current_config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
    wifi_hostapdWrite(current_config_file, list, 6);

    wifi_setApEnable(apIndex, FALSE);
    wifi_setApEnable(apIndex, TRUE);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//The IP Address and port number of the RADIUS server used for WLAN security. RadiusServerIPAddr is only applicable when ModeEnabled is an Enterprise type (i.e. WPA-Enterprise, WPA2-Enterprise or WPA-WPA2-Enterprise).
INT wifi_getApSecurityRadiusServer(INT apIndex, CHAR *IP_output, UINT *Port_output, CHAR *RadiusSecret_output)
{
    char config_file[64] = {0};
    char buf[64] = {0};
    char cmd[256] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if(!IP_output || !Port_output || !RadiusSecret_output)
        return RETURN_ERR;

    // Read the first matched config
    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
    sprintf(cmd, "cat %s | grep \"^auth_server_addr=\" | cut -d \"=\" -f 2 | head -n1 | tr -d \"\\n\"", config_file);
    _syscmd(cmd, buf, sizeof(buf));
    strncpy(IP_output, buf, 64);

    memset(buf, 0, sizeof(buf));
    sprintf(cmd, "cat %s | grep \"^auth_server_port=\" | cut -d \"=\" -f 2 | head -n1 | tr -d \"\\n\"", config_file);
    _syscmd(cmd, buf, sizeof(buf));
    *Port_output = atoi(buf);

    memset(buf, 0, sizeof(buf));
    sprintf(cmd, "cat %s | grep \"^auth_server_shared_secret=\" | cut -d \"=\" -f 2 | head -n1 | tr -d \"\\n\"", config_file);
    _syscmd(cmd, buf, sizeof(buf));
    strncpy(RadiusSecret_output, buf, 64);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

/*
 * Rewrite the RADIUS server block identified by `marker` (e.g. "# radius 1")
 * in conf_file.  The three keys that follow the marker line are replaced with
 * the supplied values.  If the marker is absent the block is appended.
 * All parameters are validated; no shell is invoked.
 */
static int radius_set_block(const char *conf_file, const char *marker,
                            const char *ip, const char *port_str,
                            const char *secret)
{
    char tmp_file[MAX_BUF_SIZE];
    char line[MAX_BUF_SIZE];
    FILE *rfp, *wfp;
    int found = 0, skip = 0;

    snprintf(tmp_file, sizeof(tmp_file), "%s.tmp", conf_file);

    wfp = fopen(tmp_file, "w");
    if (!wfp)
        return -1;

    rfp = fopen(conf_file, "r");
    if (rfp) {
        while (fgets(line, sizeof(line), rfp)) {
            /* strip trailing newline for comparison */
            size_t ll = strlen(line);
            char stripped[MAX_BUF_SIZE];
            snprintf(stripped, sizeof(stripped), "%s", line);
            if (ll > 0 && stripped[ll-1] == '\n') stripped[ll-1] = '\0';

            if (!found && strcmp(stripped, marker) == 0) {
                found = 1;
                skip = 3; /* skip the next 3 key=value lines */
                fprintf(wfp, "%s\n", marker);
                fprintf(wfp, "auth_server_addr=%s\n", ip);
                fprintf(wfp, "auth_server_port=%s\n", port_str);
                fprintf(wfp, "auth_server_shared_secret=%s\n", secret);
                continue;
            }
            if (skip > 0) {
                /* skip old addr/port/secret lines after the marker */
                if (strncmp(stripped, "auth_server_addr=", 17) == 0 ||
                    strncmp(stripped, "auth_server_port=", 17) == 0 ||
                    strncmp(stripped, "auth_server_shared_secret=", 26) == 0) {
                    skip--;
                    continue;
                }
                skip = 0;
            }
            fputs(line, wfp);
        }
        fclose(rfp);
    }

    if (!found) {
        fprintf(wfp, "%s\n", marker);
        fprintf(wfp, "auth_server_addr=%s\n", ip);
        fprintf(wfp, "auth_server_port=%s\n", port_str);
        fprintf(wfp, "auth_server_shared_secret=%s\n", secret);
    }

    if (fflush(wfp) != 0 || fsync(fileno(wfp)) != 0) {
        fclose(wfp);
        unlink(tmp_file);
        return -1;
    }
    fclose(wfp);

    if (rename(tmp_file, conf_file) != 0) {
        unlink(tmp_file);
        return -1;
    }
    return 0;
}

/* Validate an IPv4/IPv6 address string: printable, no shell metacharacters. */
static int is_valid_ip(const char *s)
{
    size_t i, len;
    if (!s) return 0;
    len = strlen(s);
    if (len == 0 || len > 64) return 0;
    for (i = 0; i < len; i++) {
        char c = s[i];
        if (!isalnum((unsigned char)c) && c != '.' && c != ':' && c != '[' && c != ']')
            return 0;
    }
    return 1;
}

/* Validate a RADIUS shared secret: printable ASCII, no shell metacharacters. */
static int is_valid_radius_secret(const char *s)
{
    size_t i, len;
    if (!s) return 0;
    len = strlen(s);
    if (len == 0 || len > 128) return 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x21 || c > 0x7e) /* printable non-space ASCII only */
            return 0;
    }
    return 1;
}

INT wifi_setApSecurityRadiusServer(INT apIndex, CHAR *IPAddress, UINT port, CHAR *RadiusSecret)
{
    char config_file[64] = {0};
    char port_str[8] = {0};
    char buf[128] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if (!is_valid_ip(IPAddress) || !is_valid_radius_secret(RadiusSecret))
        return RETURN_ERR;

    if (wifi_getApSecurityModeEnabled(apIndex, buf) != RETURN_OK)
        return RETURN_ERR;

    if (strstr(buf, "Enterprise") == NULL)
        return RETURN_ERR;

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
    snprintf(port_str, sizeof(port_str), "%u", port);

    if (radius_set_block(config_file, "# radius 1", IPAddress, port_str, RadiusSecret) != 0)
        return RETURN_ERR;

    wifi_reloadAp(apIndex);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_getApSecuritySecondaryRadiusServer(INT apIndex, CHAR *IP_output, UINT *Port_output, CHAR *RadiusSecret_output)
{
    char config_file[64] = {0};
    char buf[64] = {0};
    char cmd[256] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if(!IP_output || !Port_output || !RadiusSecret_output)
        return RETURN_ERR;

    // Read the second matched config
    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
    sprintf(cmd, "cat %s | grep \"^auth_server_addr=\" | cut -d \"=\" -f 2 | tail -n +2 | head -n1 | tr -d \"\\n\"", config_file);
    _syscmd(cmd, buf, sizeof(buf));
    strncpy(IP_output, buf, 64);

    memset(buf, 0, sizeof(buf));
    sprintf(cmd, "cat %s | grep \"^auth_server_port=\" | cut -d \"=\" -f 2 | tail -n +2 | head -n1 | tr -d \"\\n\"", config_file);
    _syscmd(cmd, buf, sizeof(buf));
    *Port_output = atoi(buf);

    memset(buf, 0, sizeof(buf));
    sprintf(cmd, "cat %s | grep \"^auth_server_shared_secret=\" | cut -d \"=\" -f 2 | tail -n +2 | head -n1 | tr -d \"\\n\"", config_file);
    _syscmd(cmd, buf, sizeof(buf));
    strncpy(RadiusSecret_output, buf, 64);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_setApSecuritySecondaryRadiusServer(INT apIndex, CHAR *IPAddress, UINT port, CHAR *RadiusSecret)
{
    char config_file[64] = {0};
    char port_str[8] = {0};
    char buf[128] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if (!is_valid_ip(IPAddress) || !is_valid_radius_secret(RadiusSecret))
        return RETURN_ERR;

    if (wifi_getApSecurityModeEnabled(apIndex, buf) != RETURN_OK)
        return RETURN_ERR;

    if (strstr(buf, "Enterprise") == NULL)
        return RETURN_ERR;

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
    snprintf(port_str, sizeof(port_str), "%u", port);

    if (radius_set_block(config_file, "# radius 2", IPAddress, port_str, RadiusSecret) != 0)
        return RETURN_ERR;

    wifi_reloadAp(apIndex);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//RadiusSettings
INT wifi_getApSecurityRadiusSettings(INT apIndex, wifi_radius_setting_t *output)
{
    if(!output)
        return RETURN_ERR;

    output->RadiusServerRetries = 3; 				//Number of retries for Radius requests.
    output->RadiusServerRequestTimeout = 5; 		//Radius request timeout in seconds after which the request must be retransmitted for the # of retries available.	
    output->PMKLifetime = 28800; 					//Default time in seconds after which a Wi-Fi client is forced to ReAuthenticate (def 8 hrs).	
    output->PMKCaching = FALSE; 					//Enable or disable caching of PMK.	
    output->PMKCacheInterval = 300; 				//Time interval in seconds after which the PMKSA (Pairwise Master Key Security Association) cache is purged (def 5 minutes).	
    output->MaxAuthenticationAttempts = 3; 		//Indicates the # of time, a client can attempt to login with incorrect credentials. When this limit is reached, the client is blacklisted and not allowed to attempt loging into the network. Settings this parameter to 0 (zero) disables the blacklisting feature.
    output->BlacklistTableTimeout = 600; 			//Time interval in seconds for which a client will continue to be blacklisted once it is marked so.	
    output->IdentityRequestRetryInterval = 5; 	//Time Interval in seconds between identity requests retries. A value of 0 (zero) disables it.	
    output->QuietPeriodAfterFailedAuthentication = 5;  	//The enforced quiet period (time interval) in seconds following failed authentication. A value of 0 (zero) disables it.	
    //snprintf(output->RadiusSecret, 64, "12345678");		//The secret used for handshaking with the RADIUS server [RFC2865]. When read, this parameter returns an empty string, regardless of the actual value.

    return RETURN_OK;
}

INT wifi_setApSecurityRadiusSettings(INT apIndex, wifi_radius_setting_t *input)
{
    //store the paramters, and apply instantly
    return RETURN_ERR;
}

//Device.WiFi.AccessPoint.{i}.WPS.Enable
//Enables or disables WPS functionality for this access point.
// outputs the WPS enable state of this ap in output_bool
INT wifi_getApWpsEnable(INT apIndex, BOOL *output_bool)
{
    char interface_name[16] = {0};
    char buf[MAX_BUF_SIZE] = {0}, cmd[MAX_CMD_SIZE] = {0}, *value;

    if(!output_bool)
        return RETURN_ERR;
    *output_bool=FALSE;
    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_OK;
    sprintf(cmd,"hostapd_cli -i %s get_config | grep wps_state | cut -d '=' -f2", interface_name);
    _syscmd(cmd, buf, sizeof(buf));
    if(strstr(buf, "configured"))
        *output_bool=TRUE;

    return RETURN_OK;
}

//Device.WiFi.AccessPoint.{i}.WPS.Enable
// sets the WPS enable enviornment variable for this ap to the value of enableValue, 1==enabled, 0==disabled
INT wifi_setApWpsEnable(INT apIndex, BOOL enable)
{
    char config_file[MAX_BUF_SIZE] = {0};
    char buf[128] = {0};
    struct params params;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    //store the paramters, and wait for wifi up to apply
    params.name = "wps_state";
    if (enable == TRUE) {
        wifi_getApBeaconType(apIndex, buf);
        if (strncmp(buf, "None", 4) == 0)   // If ap didn't set encryption
            params.value = "1";
        else                                // If ap set encryption
            params.value = "2";
    } else {
        params.value = "0";
    }

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
    wifi_hostapdWrite(config_file, &params, 1);
    wifi_hostapdProcessUpdate(apIndex, &params, 1);
    wifi_reloadAp(apIndex);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

//Comma-separated list of strings. Indicates WPS configuration methods supported by the device. Each list item is an enumeration of: USBFlashDrive,Ethernet,ExternalNFCToken,IntegratedNFCToken,NFCInterface,PushButton,PIN
INT wifi_getApWpsConfigMethodsSupported(INT apIndex, CHAR *output)
{
    if(!output)
        return RETURN_ERR;
    snprintf(output, 128, "PushButton,PIN");
    return RETURN_OK;
}

//Device.WiFi.AccessPoint.{i}.WPS.ConfigMethodsEnabled
//Comma-separated list of strings. Each list item MUST be a member of the list reported by the ConfigMethodsSupported parameter. Indicates WPS configuration methods enabled on the device.
// Outputs a common separated list of the enabled WPS config methods, 64 bytes max
INT wifi_getApWpsConfigMethodsEnabled(INT apIndex, CHAR *output)
{
    if(!output)
        return RETURN_ERR;
    snprintf(output, 64, "PushButton,PIN");//Currently, supporting these two methods

    return RETURN_OK;
}

//Device.WiFi.AccessPoint.{i}.WPS.ConfigMethodsEnabled
// sets an enviornment variable that specifies the WPS configuration method(s).  methodString is a comma separated list of methods USBFlashDrive,Ethernet,ExternalNFCToken,IntegratedNFCToken,NFCInterface,PushButton,PIN
INT wifi_setApWpsConfigMethodsEnabled(INT apIndex, CHAR *methodString)
{
    //apply instantly. No setting need to be stored.
    char methods[MAX_BUF_SIZE], *token, *next_token;
    char config_file[MAX_BUF_SIZE], config_methods[MAX_BUF_SIZE] = {0};
    struct params params;

    if(!methodString)
        return RETURN_ERR;
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    //store the paramters, and wait for wifi up to apply

    snprintf(methods, sizeof(methods), "%s", methodString);
    for(token=methods; *token; token=next_token)
    {
        strtok_r(token, ",", &next_token);
        if(*token=='U' && !strcmp(methods, "USBFlashDrive"))
            snprintf(config_methods, sizeof(config_methods), "%s ", "usba");
        else if(*token=='E')
        {
            if(!strcmp(methods, "Ethernet"))
                snprintf(config_methods, sizeof(config_methods), "%s ", "ethernet");
            else if(!strcmp(methods, "ExternalNFCToken"))
                snprintf(config_methods, sizeof(config_methods), "%s ", "ext_nfc_token");
            else
                printf("%s: Unknown WpsConfigMethod\n", __func__);
        }
        else if(*token=='I' && !strcmp(token, "IntegratedNFCToken"))
            snprintf(config_methods, sizeof(config_methods), "%s ", "int_nfc_token");
        else if(*token=='N' && !strcmp(token, "NFCInterface"))
            snprintf(config_methods, sizeof(config_methods), "%s ", "nfc_interface");
        else if(*token=='P' )
        {
            if(!strcmp(token, "PushButton"))
                snprintf(config_methods, sizeof(config_methods), "%s ", "push_button");
            else if(!strcmp(token, "PIN"))
                snprintf(config_methods, sizeof(config_methods), "%s ", "keypad");
            else
                printf("%s: Unknown WpsConfigMethod\n", __func__);
        }
        else
            printf("%s: Unknown WpsConfigMethod\n", __func__);
    }
    params.name = "config_methods";
    params.value = config_methods;
    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
    wifi_hostapdWrite(config_file, &params, 1);
    wifi_hostapdProcessUpdate(apIndex, &params, 1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

// outputs the pin value, ulong_pin must be allocated by the caller
INT wifi_getApWpsDevicePIN(INT apIndex, ULONG *output_ulong)
{
    char buf[MAX_BUF_SIZE] = {0};
    char cmd[MAX_CMD_SIZE] = {0};

    if(!output_ulong)
        return RETURN_ERR;
    snprintf(cmd, sizeof(cmd), "cat %s%d.conf | grep ap_pin | cut -d '=' -f2", CONFIG_PREFIX, apIndex);
    _syscmd(cmd, buf, sizeof(buf));
    if(strlen(buf) > 0)
        *output_ulong=strtoul(buf, NULL, 10);

    return RETURN_OK;
}

// set an enviornment variable for the WPS pin for the selected AP. Normally, Device PIN should not be changed.
INT wifi_setApWpsDevicePIN(INT apIndex, ULONG pin)
{
    //set the pin to wifi config and hostpad config. wait for wifi reset or hostapd reset to apply
    char ap_pin[16] = {0};
    char buf[MAX_BUF_SIZE] = {0};
    char config_file[MAX_BUF_SIZE] = {0};
    ULONG prev_pin = 0;
    struct params params;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    snprintf(ap_pin, sizeof(ap_pin), "%lu", pin);
    params.name = "ap_pin";
    params.value = ap_pin;
    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
    wifi_hostapdWrite(config_file, &params, 1);
    wifi_hostapdProcessUpdate(apIndex, &params, 1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

// Output string is either Not configured or Configured, max 32 characters
INT wifi_getApWpsConfigurationState(INT apIndex, CHAR *output_string)
{
    char interface_name[16] = {0};
    char cmd[MAX_CMD_SIZE];
    char buf[MAX_BUF_SIZE]={0};

    if(!output_string)
        return RETURN_ERR;
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    snprintf(output_string, 32, "Not configured");
    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s get_config | grep wps_state | cut -d'=' -f2", interface_name);
    _syscmd(cmd, buf, sizeof(buf));

    if(!strncmp(buf, "configured", 10))
        snprintf(output_string, 32, "Configured");
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

// sets the WPS pin for this AP
INT wifi_setApWpsEnrolleePin(INT apIndex, CHAR *pin)
{
    char interface_name[16] = {0};
    char cmd[MAX_CMD_SIZE];
    char buf[MAX_BUF_SIZE]={0};
    BOOL enable;

    wifi_getApEnable(apIndex, &enable);
    if (!enable)
        return RETURN_ERR;
    wifi_getApWpsEnable(apIndex, &enable);
    if (!enable)
        return RETURN_ERR;

    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;

    /* WPS PIN must be 4 or 8 decimal digits only */
    {
        size_t plen, pi;
        if (!pin) return RETURN_ERR;
        plen = strlen(pin);
        if (plen != 4 && plen != 8) return RETURN_ERR;
        for (pi = 0; pi < plen; pi++)
            if (!isdigit((unsigned char)pin[pi])) return RETURN_ERR;
    }

    snprintf(cmd, sizeof(cmd), "hostapd_cli -i%s wps_pin any %s", interface_name, pin);
    _syscmd(cmd, buf, sizeof(buf));
    if((strstr(buf, "OK"))!=NULL)
        return RETURN_OK;

    return RETURN_ERR;
}

// This function is called when the WPS push button has been pressed for this AP
INT wifi_setApWpsButtonPush(INT apIndex)
{
    char cmd[MAX_CMD_SIZE];
    char buf[MAX_BUF_SIZE]={0};
    char interface_name[16] = {0};
    BOOL enable=FALSE;

    wifi_getApEnable(apIndex, &enable);
    if (!enable)
        return RETURN_ERR;

    wifi_getApWpsEnable(apIndex, &enable);
    if (!enable)
        return RETURN_ERR;

    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;

    snprintf(cmd, sizeof(cmd), "sleep 1 && hostapd_cli -i%s wps_cancel && hostapd_cli -i%s wps_pbc", interface_name, interface_name);
    _syscmd(cmd, buf, sizeof(buf));

    if((strstr(buf, "OK"))!=NULL)
        return RETURN_OK;
    return RETURN_ERR;
}

// cancels WPS mode for this AP
INT wifi_cancelApWPS(INT apIndex)
{
    char interface_name[16] = {0};
    char cmd[MAX_CMD_SIZE];
    char buf[MAX_BUF_SIZE]={0};

    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    snprintf(cmd, sizeof(cmd), "hostapd_cli -i%s wps_cancel", interface_name);
    _syscmd(cmd,buf, sizeof(buf));

    if((strstr(buf, "OK"))!=NULL)
        return RETURN_OK;
    return RETURN_ERR;
}

//Device.WiFi.AccessPoint.{i}.AssociatedDevice.*
//HAL funciton should allocate an data structure array, and return to caller with "associated_dev_array"
INT wifi_getApAssociatedDeviceDiagnosticResult(INT apIndex, wifi_associated_dev_t **associated_dev_array, UINT *output_array_size)
{
    char interface_name[16] = {0};
    FILE *f = NULL;
    int read_flag=0, auth_temp=0, mac_temp=0,i=0;
    char cmd[256] = {0}, buf[2048] = {0};
    char *param = NULL, *value = NULL, *line=NULL;
    size_t len = 0;
    ssize_t nread = 0;
    wifi_associated_dev_t *dev=NULL;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    *associated_dev_array = NULL;
    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    sprintf(cmd, "hostapd_cli -i%s all_sta | grep AUTHORIZED | wc -l", interface_name);
    _syscmd(cmd,buf,sizeof(buf));
    *output_array_size = atoi(buf);

    if (*output_array_size <= 0)
        return RETURN_OK;

    dev=(wifi_associated_dev_t *) calloc (*output_array_size, sizeof(wifi_associated_dev_t));
    if (dev == NULL) {
        *output_array_size = 0;
        return RETURN_ERR;
    }
    *associated_dev_array = dev;
    sprintf(cmd, "hostapd_cli -i%s all_sta > /tmp/connected_devices.txt" , interface_name);
    _syscmd(cmd,buf,sizeof(buf));
    f = fopen("/tmp/connected_devices.txt", "r");
    if (f==NULL)
    {
        *output_array_size=0;
        free(dev);
        *associated_dev_array = NULL;
        return RETURN_ERR;
    }
    while ((getline(&line, &len, f)) != -1)
    {
        param = strtok(line,"=");
        value = strtok(NULL,"=");

        if( param == NULL || value == NULL )
            continue;
        if( strcmp("flags",param) == 0 )
        {
            value[strlen(value)-1]='\0';
            if(strstr (value,"AUTHORIZED") != NULL )
            {
                if (auth_temp >= (int)*output_array_size)
                    break;
                dev[auth_temp].cli_AuthenticationState = 1;
                dev[auth_temp].cli_Active = 1;
                auth_temp++;
                read_flag=1;
            }
        }
        if(read_flag==1)
        {
            if( strcmp("dot11RSNAStatsSTAAddress",param) == 0 )
            {
                value[strlen(value)-1]='\0';
                sscanf(value, "%x:%x:%x:%x:%x:%x",
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[0],
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[1],
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[2],
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[3],
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[4],
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[5] );
                mac_temp++;
                read_flag=0;
            }
        }
    }
    *output_array_size = auth_temp;
    auth_temp=0;
    mac_temp=0;
    free(line);
    fclose(f);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

#define MACADDRESS_SIZE 6

INT wifihal_AssociatedDevicesstats3(INT apIndex,CHAR *interface_name,wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size)
{
    FILE *fp = NULL;
    char str[MAX_BUF_SIZE] = {0};
    int wificlientindex = 0 ;
    int count = 0;
    int signalstrength = 0;
    int arr[MACADDRESS_SIZE] = {0};
    unsigned char mac[MACADDRESS_SIZE] = {0};
    UINT wifi_count = 0;
    char virtual_interface_name[MAX_BUF_SIZE] = {0};
    char pipeCmd[MAX_CMD_SIZE] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    *output_array_size = 0;
    *associated_dev_array = NULL;

    if (!is_valid_ifname(interface_name))
        return RETURN_ERR;

    snprintf(pipeCmd, sizeof(pipeCmd), "iw dev %s station dump | grep %s | wc -l", interface_name, interface_name);
    fp = popen(pipeCmd, "r");
    if (fp == NULL) 
    {
        printf("Failed to run command inside function %s\n",__FUNCTION__ );
        return RETURN_ERR;
    }

    /* Read the output a line at a time - output it. */
    fgets(str, sizeof(str)-1, fp);
    wifi_count = (unsigned int) atoi ( str );
    *output_array_size = wifi_count;
    printf(" In rdkb hal ,Wifi Client Counts and index %d and  %d \n",*output_array_size,apIndex);
    pclose(fp);

    if(wifi_count == 0)
    {
        return RETURN_OK;
    }
    else
    {
        wifi_associated_dev3_t* temp = NULL;
        temp = (wifi_associated_dev3_t*)calloc(1, sizeof(wifi_associated_dev3_t)*wifi_count) ;
        if(temp == NULL)
        {
            printf("Error Statement. Insufficient memory \n");
            return RETURN_ERR;
        }

        snprintf(pipeCmd, sizeof(pipeCmd), "iw dev %s station dump > /tmp/AssociatedDevice_Stats.txt", interface_name);
        system(pipeCmd);
        memset(pipeCmd,0,sizeof(pipeCmd));
        if(apIndex == 0)
            snprintf(pipeCmd, sizeof(pipeCmd), "iw dev %s station dump | grep Station >> /tmp/AllAssociated_Devices_2G.txt", interface_name);
        else if(apIndex == 1)
            snprintf(pipeCmd, sizeof(pipeCmd), "iw dev %s station dump | grep Station >> /tmp/AllAssociated_Devices_5G.txt", interface_name);
        system(pipeCmd);

        fp = fopen("/tmp/AssociatedDevice_Stats.txt", "r");
        if(fp == NULL)
        {
            printf("/tmp/AssociatedDevice_Stats.txt not exists \n");
            free(temp);
            return RETURN_ERR;
        }
        fclose(fp);

        sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep Station | cut -d ' ' -f 2");
        fp = popen(pipeCmd, "r");
        if(fp)
        {
            for(count =0 ; count < wifi_count; count++)
            {
                fgets(str, MAX_BUF_SIZE, fp);
                if( MACADDRESS_SIZE == sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",&arr[0],&arr[1],&arr[2],&arr[3],&arr[4],&arr[5]) )
                {
                    for( wificlientindex = 0; wificlientindex < MACADDRESS_SIZE; ++wificlientindex )
                    {
                        mac[wificlientindex] = (unsigned char) arr[wificlientindex];

                    }
                    memcpy(temp[count].cli_MACAddress,mac,(sizeof(unsigned char))*6);
                    printf("MAC %d = %X:%X:%X:%X:%X:%X \n", count, temp[count].cli_MACAddress[0],temp[count].cli_MACAddress[1], temp[count].cli_MACAddress[2], temp[count].cli_MACAddress[3], temp[count].cli_MACAddress[4], temp[count].cli_MACAddress[5]);
                }
                temp[count].cli_AuthenticationState = 1; //TODO
                temp[count].cli_Active = 1; //TODO
            }
            pclose(fp);
        }

        sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep signal | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrength.txt");
        fp = popen(pipeCmd, "r");
        if(fp)
        { 
            pclose(fp);
        }
        fp = popen("cat /tmp/wifi_signalstrength.txt | tr -s ' ' | cut -f 2","r");
        if(fp)
        {
            for(count =0 ; count < wifi_count ;count++)
            {
                fgets(str, MAX_BUF_SIZE, fp);
                signalstrength = atoi(str);
                temp[count].cli_SignalStrength = signalstrength;
                temp[count].cli_RSSI = signalstrength;
                temp[count].cli_SNR = signalstrength + 95;
            }
            pclose(fp);
        }


        if((apIndex == 0) || (apIndex == 4))
        {
            for(count =0 ; count < wifi_count ;count++)
            {	
                strcpy(temp[count].cli_OperatingStandard,"g");
                strcpy(temp[count].cli_OperatingChannelBandwidth,"20MHz");
            }

            //BytesSent
            sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx bytes' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bytes_Send.txt");
            fp = popen(pipeCmd, "r");
            if(fp)
            { 
                pclose(fp);
            }
            fp = popen("cat /tmp/Ass_Bytes_Send.txt | tr -s ' ' | cut -f 2","r");
            if(fp)
            {
                for (count = 0; count < wifi_count; count++)
                {
                    fgets(str, MAX_BUF_SIZE, fp);
                    temp[count].cli_BytesSent = strtoul(str, NULL, 10);
                }
                pclose(fp);
            }

            //BytesReceived
            sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'rx bytes' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bytes_Received.txt");
            fp = popen(pipeCmd, "r");
            if (fp)
            {
                pclose(fp);
            }
            fp = popen("cat /tmp/Ass_Bytes_Received.txt | tr -s ' ' | cut -f 2", "r");
            if (fp)
            {
                for (count = 0; count < wifi_count; count++)
                {
                    fgets(str, MAX_BUF_SIZE, fp);
                    temp[count].cli_BytesReceived = strtoul(str, NULL, 10);
                }
                pclose(fp);
            }

            //PacketsSent
            sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx packets' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Packets_Send.txt");
            fp = popen(pipeCmd, "r");
            if (fp)
            {
                pclose(fp);
            }

            fp = popen("cat /tmp/Ass_Packets_Send.txt | tr -s ' ' | cut -f 2", "r");
            if (fp)
            {
                for (count = 0; count < wifi_count; count++)
                {
                    fgets(str, MAX_BUF_SIZE, fp);
                    temp[count].cli_PacketsSent = strtoul(str, NULL, 10);
                }
                pclose(fp);
            }

            //PacketsReceived
            sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'rx packets' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Packets_Received.txt");
            fp = popen(pipeCmd, "r");
            if (fp)
            {
                pclose(fp);
            }
            fp = popen("cat /tmp/Ass_Packets_Received.txt | tr -s ' ' | cut -f 2", "r");
            if (fp)
            {
                for (count = 0; count < wifi_count; count++)
                {
                    fgets(str, MAX_BUF_SIZE, fp);
                    temp[count].cli_PacketsReceived = strtoul(str, NULL, 10);
                }
                pclose(fp);
            }

            //ErrorsSent
            sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx failed' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Tx_Failed.txt");
            fp = popen(pipeCmd, "r");
            if (fp)
            {
                pclose(fp);
            }
            fp = popen("cat /tmp/Ass_Tx_Failed.txt | tr -s ' ' | cut -f 2", "r");
            if (fp)
            {
                for (count = 0; count < wifi_count; count++)
                {
                    fgets(str, MAX_BUF_SIZE, fp);
                    temp[count].cli_ErrorsSent = strtoul(str, NULL, 10);
                }
                pclose(fp);
            }

            //ErrorsSent
            sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx failed' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Tx_Failed.txt");
            fp = popen(pipeCmd, "r");
            if (fp)
            {
                pclose(fp);
            }
            fp = popen("cat /tmp/Ass_Tx_Failed.txt | tr -s ' ' | cut -f 2", "r");
            if (fp)
            {
                for (count = 0; count < wifi_count; count++)
                {
                    fgets(str, MAX_BUF_SIZE, fp);
                    temp[count].cli_ErrorsSent = strtoul(str, NULL, 10);
                }
                pclose(fp);
            }

            //LastDataDownlinkRate
            sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Send.txt");
            fp = popen(pipeCmd, "r");
            if (fp)
            {
                pclose(fp);
            }
            fp = popen("cat /tmp/Ass_Bitrate_Send.txt | tr -s ' ' | cut -f 2", "r");
            if (fp)
            {
                for (count = 0; count < wifi_count; count++)
                {
                    fgets(str, MAX_BUF_SIZE, fp);
                    temp[count].cli_LastDataDownlinkRate = strtoul(str, NULL, 10);
                    temp[count].cli_LastDataDownlinkRate = (temp[count].cli_LastDataDownlinkRate * 1024); //Mbps -> Kbps
                }
                pclose(fp);
            }

            //LastDataUplinkRate
            sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'rx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Received.txt");
            fp = popen(pipeCmd, "r");
            if (fp)
            {
                pclose(fp);
            }
            fp = popen("cat /tmp/Ass_Bitrate_Received.txt | tr -s ' ' | cut -f 2", "r");
            if (fp)
            {
                for (count = 0; count < wifi_count; count++)
                {
                    fgets(str, MAX_BUF_SIZE, fp);
                    temp[count].cli_LastDataUplinkRate = strtoul(str, NULL, 10);
                    temp[count].cli_LastDataUplinkRate = (temp[count].cli_LastDataUplinkRate * 1024); //Mbps -> Kbps
                }
                pclose(fp);
            }

        }
        else if ((apIndex == 1) || (apIndex == 5))
        {
            for (count = 0; count < wifi_count; count++)
            {
                strcpy(temp[count].cli_OperatingStandard, "a");
                strcpy(temp[count].cli_OperatingChannelBandwidth, "20MHz");
                temp[count].cli_BytesSent = 0;
                temp[count].cli_BytesReceived = 0;
                temp[count].cli_LastDataUplinkRate = 0;
                temp[count].cli_LastDataDownlinkRate = 0;
                temp[count].cli_PacketsSent = 0;
                temp[count].cli_PacketsReceived = 0;
                temp[count].cli_ErrorsSent = 0;
            }
        }

        for (count = 0; count < wifi_count; count++)
        {
            temp[count].cli_Retransmissions = 0;
            temp[count].cli_DataFramesSentAck = 0;
            temp[count].cli_DataFramesSentNoAck = 0;
            temp[count].cli_MinRSSI = 0;
            temp[count].cli_MaxRSSI = 0;
            strncpy(temp[count].cli_InterferenceSources, "", 64);
            memset(temp[count].cli_IPAddress, 0, 64);
            temp[count].cli_RetransCount = 0;
            temp[count].cli_FailedRetransCount = 0;
            temp[count].cli_RetryCount = 0;
            temp[count].cli_MultipleRetryCount = 0;
        }
        *associated_dev_array = temp;
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

int wifihal_interfacestatus(CHAR *wifi_status,CHAR *interface_name)
{
    FILE *fp = NULL;
    char path[512] = {0},status[MAX_BUF_SIZE] = {0};
    char cmd[MAX_CMD_SIZE];
    int count = 0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    sprintf(cmd, "ifconfig %s | grep RUNNING | tr -s ' ' | cut -d ' ' -f4", interface_name);
    fp = popen(cmd,"r");
    if(fp == NULL)
    {
        printf("Failed to run command in Function %s\n",__FUNCTION__);
        return 0;
    }
    if(fgets(path, sizeof(path)-1, fp) != NULL)
    {
        for(count=0; path[count]!='\n' && path[count]!='\0' && count < (int)(sizeof(status)-1); count++)
            status[count]=path[count];
        status[count]='\0';
    }
    snprintf(wifi_status, MAX_BUF_SIZE, "%s", status);
    pclose(fp);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

/* #define HOSTAPD_STA_PARAM_ENTRIES 29
struct hostapd_sta_param {
    char key[50];
    char value[100];
}

static char * hostapd_st_get_param(struct hostapd_sta_param * params, char *key){
    int i = 0;

    while(i<HOSTAPD_STA_PARAM_ENTRIES) {
        if (strncmp(params[i].key,key,50) == 0){
            return &params[i].value;
        }
        i++;
    }
    return NULL;

} */

static unsigned int count_occurences(const char *buf, const char *word)
{
    unsigned int n = 0;
    char *ptr = strstr(buf, word);

    while (ptr++) {
        n++;
        ptr = strstr(ptr, word);
    }

    wifi_dbg_printf("%s: found %u of '%s'\n",  __FUNCTION__, n, word);
    return n;
}

static const char *get_line_from_str_buf(const char *buf, char *line)
{
    int i;
    int n = strlen(buf);

    for (i = 0; i < n; i++) {
        line[i] = buf[i];
        if (buf[i] == '\n') {
            line[i] = '\0';
            return &buf[i + 1];
        }
    }

    return NULL;
}

static INT wifi_getAssocConnectMode(INT apIndex, CHAR *input_string, CHAR *OperatingStandard)
{
    wifi_band band;
	int ieee80211_mode = 0;

	if (!input_string || !OperatingStandard)
		return RETURN_ERR;

	band = wifi_index_to_band(apIndex);

	if (strstr(input_string, "HE"))
		ieee80211_mode = WIFI_MODE_AX;
	else if (strstr(input_string, "VHT"))
		ieee80211_mode = WIFI_MODE_AC;
	else if (strstr(input_string, "EHT"))
		ieee80211_mode = WIFI_MODE_BE;

	switch (ieee80211_mode) {
		case WIFI_MODE_AC:
			snprintf(OperatingStandard, 64, "ac");
			break;
		case WIFI_MODE_AX:
			snprintf(OperatingStandard, 64, "ax");
			break;
		case WIFI_MODE_BE:
			snprintf(OperatingStandard, 64, "be");
			break;
		default:
			if(band == band_2_4)
				snprintf(OperatingStandard, 64, "b,g,n");
			else if(band == band_5)
				snprintf(OperatingStandard, 64, "a,n");
			else if(band == band_6)
				snprintf(OperatingStandard, 64, "ax");
			else {
				wifi_dbg_printf("%s: failed to parse band %d\n", __FUNCTION__, band);
				return RETURN_ERR;
			}
	}


	return RETURN_OK;
}

INT wifi_getApAssociatedDeviceDiagnosticResult3(INT apIndex, wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size)
{
    unsigned int assoc_cnt = 0;
    char interface_name[50] = {0};
    char buf[MAX_BUF_SIZE * 50]= {'\0'}; // Increase this buffer if more fields are added to 'iw dev' output filter
    char cmd[MAX_CMD_SIZE] = {'\0'};
    char line[256] = {'\0'};
    int i = 0;
    int ret = 0;
    const char *ptr = NULL;
    char *key = NULL;
    char *val = NULL;
    wifi_associated_dev3_t *temp = NULL;
    int rssi;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if (wifi_getApName(apIndex, interface_name) != RETURN_OK) {
        wifi_dbg_printf("%s: wifi_getApName failed\n",  __FUNCTION__);
        return RETURN_ERR;
    }

    // Example filtered output of 'iw dev' command:
    //    Station 0a:69:72:10:d2:fa (on wifi0)
    //    signal avg:-67 [-71, -71] dBm
    //    Station 28:c2:1f:25:5f:99 (on wifi0)
    //    signal avg:-67 [-71, -70] dBm
    if (sprintf(cmd,"iw dev %s station dump | tr -d '\t' | grep -E 'Station|signal avg"
		"|tx bitrate|rx bitrate'", interface_name) < 0) {
		wifi_dbg_printf("%s: failed to build iw dev command for %s\n", __FUNCTION__, interface_name);
        return RETURN_ERR;
    }

    ret = _syscmd(cmd, buf, sizeof(buf));
    if (ret == RETURN_ERR) {
        wifi_dbg_printf("%s: failed to execute '%s' for %s\n", __FUNCTION__, cmd, interface_name);
        return RETURN_ERR;
    }

    *output_array_size = count_occurences(buf, "Station");
    if (*output_array_size == 0) return RETURN_OK;

    temp = calloc(*output_array_size, sizeof(wifi_associated_dev3_t));
    if (temp == NULL) {
        wifi_dbg_printf("%s: failed to allocate dev array for %s\n", __FUNCTION__, interface_name);
        return RETURN_ERR;
    }
    *associated_dev_array = temp;

    wifi_dbg_printf("%s: array_size = %u\n", __FUNCTION__, *output_array_size);
    ptr = get_line_from_str_buf(buf, line);
    i = -1;
    while (ptr) {
        if (strstr(line, "Station")) {
            i++;
            key = strtok(line, " ");
            val = strtok(NULL, " ");
            if (val == NULL) {
                wifi_dbg_printf("%s: malformed Station line\n", __FUNCTION__);
                ptr = get_line_from_str_buf(ptr, line);
                continue;
            }
            if (sscanf(val, "%02x:%02x:%02x:%02x:%02x:%02x",
                &temp[i].cli_MACAddress[0],
                &temp[i].cli_MACAddress[1],
                &temp[i].cli_MACAddress[2],
                &temp[i].cli_MACAddress[3],
                &temp[i].cli_MACAddress[4],
                &temp[i].cli_MACAddress[5]) != MACADDRESS_SIZE) {
                    wifi_dbg_printf("%s: failed to parse MAC of client connected to %s\n", __FUNCTION__, interface_name);
                    free(*associated_dev_array);
                    return RETURN_ERR;
            }
        }
        else if (i < 0) {
			wifi_dbg_printf("%s: not find station\n", __FUNCTION__);
            ptr = get_line_from_str_buf(ptr, line);
            continue; // We didn't detect 'station' entry yet
        }
        else if (strstr(line, "signal avg")) {
            key = strtok(line, ":");
            val = strtok(NULL, " ");
            if (val == NULL || sscanf(val, "%d", &rssi) <= 0 ) {
                wifi_dbg_printf("%s: failed to parse RSSI of client connected to %s\n", __FUNCTION__, interface_name);
                free(*associated_dev_array);
                return RETURN_ERR;
            }
            temp[i].cli_RSSI = rssi;
            temp[i].cli_SNR = 95 + rssi; // We use constant -95 noise floor
        }
        else if (strstr(line, "tx bitrate")) {
			ret = wifi_getAssocConnectMode(apIndex, line, temp[i].cli_OperatingStandard);
			if (ret == RETURN_ERR) {
				wifi_dbg_printf("%s: failed to execute tx get assoc connect mode command.\n", __FUNCTION__);
				return ret;
			}
        }
        else if (strstr(line, "rx bitrate")) {
			/* if tx get ac, ax, be mode, need not get mode from rx */
			if (strncmp(temp[i].cli_OperatingStandard,"ac", 2) &&
				strncmp(temp[i].cli_OperatingStandard,"ax", 2) &&
				strncmp(temp[i].cli_OperatingStandard,"be", 2)) {
				ret = wifi_getAssocConnectMode(apIndex, line, temp[i].cli_OperatingStandard);
				if (ret == RETURN_ERR) {
					wifi_dbg_printf("%s: failed to execute rx get assoc connect mode command.\n", __FUNCTION__);
					return ret;
				}
			}
		}
        // Here other fields can be parsed if added to filter of 'iw dev' command
        ptr = get_line_from_str_buf(ptr, line);
	}

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

#if 0
//To-do
INT wifi_getApAssociatedDeviceDiagnosticResult3(INT apIndex, wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    //Using different approach to get required WiFi Parameters from system available commands
#if 0 
    FILE *f;
    int read_flag=0, auth_temp=0, mac_temp=0,i=0;
    char cmd[256], buf[2048];
    char *param , *value, *line=NULL;
    size_t len = 0;
    ssize_t nread;
    wifi_associated_dev3_t *dev=NULL;
    *associated_dev_array = NULL;
    sprintf(cmd, "hostapd_cli -i%s all_sta | grep AUTHORIZED | wc -l", interface_name);
    _syscmd(cmd,buf,sizeof(buf));
    *output_array_size = atoi(buf);

    if (*output_array_size <= 0)
        return RETURN_OK;

    dev=(wifi_associated_dev3_t *) AnscAllocateMemory(*output_array_size * sizeof(wifi_associated_dev3_t));
    *associated_dev_array = dev;
    sprintf(cmd, "hostapd_cli -i%s all_sta > /tmp/connected_devices.txt", interface_name);
    _syscmd(cmd,buf,sizeof(buf));
    f = fopen("/tmp/connected_devices.txt", "r");
    if (f==NULL)
    {
        *output_array_size=0;
        return RETURN_ERR;
    }
    while ((nread = getline(&line, &len, f)) != -1)
    {
        param = strtok(line,"=");
        value = strtok(NULL,"=");

        if( strcmp("flags",param) == 0 )
        {
            value[strlen(value)-1]='\0';
            if(strstr (value,"AUTHORIZED") != NULL )
            {
                dev[auth_temp].cli_AuthenticationState = 1;
                dev[auth_temp].cli_Active = 1;
                auth_temp++;
                read_flag=1;
            }
        }
        if(read_flag==1)
        {
            if( strcmp("dot11RSNAStatsSTAAddress",param) == 0 )
            {
                value[strlen(value)-1]='\0';
                sscanf(value, "%x:%x:%x:%x:%x:%x",
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[0],
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[1],
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[2],
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[3],
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[4],
                        (unsigned int *)&dev[mac_temp].cli_MACAddress[5] );

            }
            else if( strcmp("rx_packets",param) == 0 )
            {
                sscanf(value, "%d", &(dev[mac_temp].cli_PacketsReceived));
            }

            else if( strcmp("tx_packets",param) == 0 )
            {
                sscanf(value, "%d", &(dev[mac_temp].cli_PacketsSent));				
            }

            else if( strcmp("rx_bytes",param) == 0 )
            {
                sscanf(value, "%d", &(dev[mac_temp].cli_BytesReceived));
            }

            else if( strcmp("tx_bytes",param) == 0 )
            {
                sscanf(value, "%d", &(dev[mac_temp].cli_BytesSent));		
                mac_temp++;
                read_flag=0;
            }						
        }
    }

    *output_array_size = auth_temp;
    auth_temp=0;
    mac_temp=0;
    free(line);
    fclose(f);
#endif
    char interface_name[MAX_BUF_SIZE] = {0};
    char wifi_status[MAX_BUF_SIZE] = {0};
    char hostapdconf[MAX_BUF_SIZE] = {0};

    wifi_associated_dev3_t *dev_array = NULL;
    ULONG wifi_count = 0;

    *associated_dev_array = NULL;
    *output_array_size = 0;

    printf("wifi_getApAssociatedDeviceDiagnosticResult3 apIndex = %d \n", apIndex);
    //if(apIndex == 0 || apIndex == 1 || apIndex == 4 || apIndex == 5) // These are availble in RPI.
    {
        sprintf(hostapdconf, "/nvram/hostapd%d.conf", apIndex);

        wifi_GetInterfaceName(interface_name, hostapdconf);

        if(strlen(interface_name) > 1)
        {
            wifihal_interfacestatus(wifi_status,interface_name);
            if(strcmp(wifi_status,"RUNNING") == 0)
            {
                wifihal_AssociatedDevicesstats3(apIndex,interface_name,&dev_array,&wifi_count);

                *associated_dev_array = dev_array;
                *output_array_size = wifi_count;		
            }
            else
            {
                *associated_dev_array = NULL;
            }
        }
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}
#endif

/* getIPAddress function */
/**
* @description Returning IpAddress of the Matched String
*
* @param 
* @str Having MacAddress
* @ipaddr Having ipaddr 
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
*/

INT getIPAddress(char *str,char *ipaddr)
{
    FILE *fp = NULL;
    char buf[1024] = {0},ipAddr[50] = {0},phyAddr[100] = {0},hostName[100] = {0};
    int LeaseTime = 0,ret = 0;
    if ( (fp=fopen("/nvram/dnsmasq.leases", "r")) == NULL )
    {
        return RETURN_ERR;
    }

    while ( fgets(buf, sizeof(buf), fp)!= NULL )
    {
        /*
        Sample:sss
        1560336751 00:cd:fe:f3:25:e6 10.0.0.153 NallamousiPhone 01:00:cd:fe:f3:25:e6
        1560336751 12:34:56:78:9a:bc 10.0.0.154 NallamousiPhone 01:00:cd:fe:f3:25:e6
        */
        ret = sscanf(buf, LM_DHCP_CLIENT_FORMAT,
            &(LeaseTime),
            phyAddr,
            ipAddr,
            hostName
            );
        if(ret != 4)
            continue;
        if(strcmp(str,phyAddr) == 0)
            strcpy(ipaddr,ipAddr);
    }
    fclose(fp);
    return RETURN_OK;
}

/* wifi_getApInactiveAssociatedDeviceDiagnosticResult function */
/**
* @description Returning Inactive wireless connected clients informations
*
* @param 
* @filename Holding private_wifi 2g/5g content files
* @associated_dev_array  Having inactiv wireless clients informations
* @output_array_size Returning Inactive wireless counts
* @return The status of the operation
* @retval RETURN_OK if successful
* @retval RETURN_ERR if any error is detected
*
*/

INT wifi_getApInactiveAssociatedDeviceDiagnosticResult(char *filename,wifi_associated_dev3_t **associated_dev_array, UINT *output_array_size)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    int count = 0, maccount = 0, i = 0, wificlientindex = 0;
    FILE *fp = NULL;
    int arr[MACADDRESS_SIZE] = {0};
    unsigned char mac[MACADDRESS_SIZE] = {0};
    char line[256] = {0}, str[64] = {0}, ipaddr[50] = {0};
    char ping_cmd[64] = {0};
    wifi_associated_dev3_t *temp = NULL;

    if (!filename || !associated_dev_array || !output_array_size)
        return RETURN_ERR;

    /* Pass 1: count Station lines without a shell */
    fp = fopen(filename, "r");
    if (!fp)
        return RETURN_ERR;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Station ", 8) == 0)
            maccount++;
    }
    fclose(fp);

    *output_array_size = maccount;
    temp = (wifi_associated_dev3_t *)calloc(maccount, sizeof(wifi_associated_dev3_t));
    *associated_dev_array = temp;
    if (!temp) {
        printf("Error Statement. Insufficient memory \n");
        return RETURN_ERR;
    }

    /* Pass 2: collect MAC addresses and probe liveness */
    fp = fopen(filename, "r");
    if (!fp)
        return RETURN_ERR;

    while (fgets(line, sizeof(line), fp) && count < maccount) {
        if (strncmp(line, "Station ", 8) != 0)
            continue;

        /* Extract MAC token after "Station " */
        if (sscanf(line, "Station %63s", str) != 1)
            continue;

        /* Must be a valid MAC before using it anywhere */
        if (!is_valid_mac(str))
            continue;

        memset(ipaddr, 0, sizeof(ipaddr));
        getIPAddress(str, ipaddr);

        if (strlen(ipaddr) > 0) {
            /* Validate IP before building ping command */
            if (!is_valid_ip(ipaddr)) {
                memset(ipaddr, 0, sizeof(ipaddr));
            } else {
                snprintf(ping_cmd, sizeof(ping_cmd),
                         "ping -q -c 1 -W 1 %s > /dev/null 2>&1", ipaddr);
            }
        }

        if (strlen(ipaddr) > 0 && WEXITSTATUS(system(ping_cmd)) != 0) {
            /* InActive */
            if (MACADDRESS_SIZE == sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
                    &arr[0],&arr[1],&arr[2],&arr[3],&arr[4],&arr[5])) {
                for (wificlientindex = 0; wificlientindex < MACADDRESS_SIZE; wificlientindex++)
                    mac[wificlientindex] = (unsigned char)arr[wificlientindex];
                memcpy(temp[count].cli_MACAddress, mac, sizeof(unsigned char)*6);
                fprintf(stderr, "%sMAC %d = %X:%X:%X:%X:%X:%X \n", __FUNCTION__, count,
                    temp[count].cli_MACAddress[0], temp[count].cli_MACAddress[1],
                    temp[count].cli_MACAddress[2], temp[count].cli_MACAddress[3],
                    temp[count].cli_MACAddress[4], temp[count].cli_MACAddress[5]);
            }
            temp[count].cli_AuthenticationState = 0;
            temp[count].cli_Active = 0;
            temp[count].cli_SignalStrength = 0;
        } else {
            /* Active */
            if (MACADDRESS_SIZE == sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
                    &arr[0],&arr[1],&arr[2],&arr[3],&arr[4],&arr[5])) {
                for (wificlientindex = 0; wificlientindex < MACADDRESS_SIZE; wificlientindex++)
                    mac[wificlientindex] = (unsigned char)arr[wificlientindex];
                memcpy(temp[count].cli_MACAddress, mac, sizeof(unsigned char)*6);
                fprintf(stderr, "%sMAC %d = %X:%X:%X:%X:%X:%X \n", __FUNCTION__, count,
                    temp[count].cli_MACAddress[0], temp[count].cli_MACAddress[1],
                    temp[count].cli_MACAddress[2], temp[count].cli_MACAddress[3],
                    temp[count].cli_MACAddress[4], temp[count].cli_MACAddress[5]);
            }
            temp[count].cli_Active = 1;
        }
        count++;
    }
    fclose(fp);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}
//Device.WiFi.X_RDKCENTRAL-COM_BandSteering object
//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.Capability bool r/o
//To get Band Steering Capability
INT wifi_getBandSteeringCapability(BOOL *support)
{
    *support = FALSE;
    return RETURN_OK;
}


//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.Enable bool r/w
//To get Band Steering enable status
INT wifi_getBandSteeringEnable(BOOL *enable)
{
    *enable = FALSE;
    return RETURN_OK;
}

//To turn on/off Band steering
INT wifi_setBandSteeringEnable(BOOL enable)
{
    return RETURN_OK;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.APGroup string r/w
//To get Band Steering AP group
INT wifi_getBandSteeringApGroup(char *output_ApGroup)
{
    if (NULL == output_ApGroup)
        return RETURN_ERR;

    strcpy(output_ApGroup, "1,2");
    return RETURN_OK;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.UtilizationThreshold int r/w
//to set and read the band steering BandUtilizationThreshold parameters
INT wifi_getBandSteeringBandUtilizationThreshold (INT radioIndex, INT *pBuThreshold)
{
    return RETURN_ERR;
}

INT wifi_setBandSteeringBandUtilizationThreshold (INT radioIndex, INT buThreshold)
{
    return RETURN_ERR;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.RSSIThreshold int r/w
//to set and read the band steering RSSIThreshold parameters
INT wifi_getBandSteeringRSSIThreshold (INT radioIndex, INT *pRssiThreshold)
{
    return RETURN_ERR;
}

INT wifi_setBandSteeringRSSIThreshold (INT radioIndex, INT rssiThreshold)
{
    return RETURN_ERR;
}


//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.PhyRateThreshold int r/w
//to set and read the band steering physical modulation rate threshold parameters
INT wifi_getBandSteeringPhyRateThreshold (INT radioIndex, INT *pPrThreshold)
{
    //If chip is not support, return -1
    return RETURN_ERR;
}

INT wifi_setBandSteeringPhyRateThreshold (INT radioIndex, INT prThreshold)
{
    //If chip is not support, return -1
    return RETURN_ERR;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.OverloadInactiveTime int r/w
//to set and read the inactivity time (in seconds) for steering under overload condition
INT wifi_getBandSteeringOverloadInactiveTime(INT radioIndex, INT *pPrThreshold)
{
    return RETURN_ERR;
}

INT wifi_setBandSteeringOverloadInactiveTime(INT radioIndex, INT prThreshold)
{
    return RETURN_ERR;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.BandSetting.{i}.IdleInactiveTime int r/w
//to set and read the inactivity time (in seconds) for steering under Idle condition
INT wifi_getBandSteeringIdleInactiveTime(INT radioIndex, INT *pPrThreshold)
{
    return RETURN_ERR;
}

INT wifi_setBandSteeringIdleInactiveTime(INT radioIndex, INT prThreshold)
{
    return RETURN_ERR;
}

//Device.WiFi.X_RDKCENTRAL-COM_BandSteering.History string r/o
//pClientMAC[64]
//pSourceSSIDIndex[64]
//pDestSSIDIndex[64]
//pSteeringReason[256]
INT wifi_getBandSteeringLog(INT record_index, ULONG *pSteeringTime, CHAR *pClientMAC, INT *pSourceSSIDIndex, INT *pDestSSIDIndex, INT *pSteeringReason)
{
    //if no steering or redord_index is out of boundary, return -1. pSteeringTime returns the UTC time in seconds. pClientMAC is pre allocated as 64bytes. pSteeringReason returns the predefined steering trigger reason
    *pSteeringTime=time(NULL);
    *pSteeringReason = 0; //TODO: need to assign correct steering reason (INT numeric, i suppose)
    return RETURN_OK;
}

INT wifi_ifConfigDown(INT apIndex)
{
  INT status = RETURN_OK;
  char cmd[64];

  snprintf(cmd, sizeof(cmd), "ifconfig ath%d down", apIndex);
  printf("%s: %s\n", __func__, cmd);
  system(cmd);

  return status;
}

INT wifi_ifConfigUp(INT apIndex)
{
    char interface_name[16] = {0};
    char cmd[128];
    char buf[1024];

    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    snprintf(cmd, sizeof(cmd), "ifconfig %s up 2>/dev/null", interface_name);
    _syscmd(cmd, buf, sizeof(buf));
    return 0;
}

//>> Deprecated. Replace with wifi_applyRadioSettings
INT wifi_pushBridgeInfo(INT apIndex)
{
    char interface_name[16] = {0};
    char ip[32] = {0};
    char subnet[32] = {0};
    char bridge[32] = {0};
    int vlanId = 0;
    char cmd[128] = {0};
    char buf[1024] = {0};

    wifi_getApBridgeInfo(apIndex,bridge,ip,subnet);
    wifi_getApVlanID(apIndex,&vlanId);

    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    snprintf(cmd, sizeof(cmd), "cfgVlan %s %s %d %s ", interface_name, bridge, vlanId, ip);
    _syscmd(cmd,buf, sizeof(buf));

    return 0;
}

INT wifi_pushChannel(INT radioIndex, UINT channel)
{
    char interface_name[16] = {0};
    char cmd[128];
    char buf[1024];
    int  apIndex;

    apIndex=(radioIndex==0)?0:1;	
    if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    snprintf(cmd, sizeof(cmd), "iwconfig %s freq %d",interface_name,channel);
    _syscmd(cmd,buf, sizeof(buf));

    return 0;
}

INT wifi_pushChannelMode(INT radioIndex)
{
    //Apply Channel mode, pure mode, etc that been set by wifi_setRadioChannelMode() instantly
    return RETURN_ERR;
}

INT wifi_pushDefaultValues(INT radioIndex)
{
    //Apply Comcast specified default radio settings instantly
    //AMPDU=1
    //AMPDUFrames=32
    //AMPDULim=50000
    //txqueuelen=1000

    return RETURN_ERR;
}

INT wifi_pushTxChainMask(INT radioIndex)
{
    //Apply default TxChainMask instantly
    return RETURN_ERR;
}

INT wifi_pushRxChainMask(INT radioIndex)
{
    //Apply default RxChainMask instantly
    return RETURN_ERR;
}

INT wifi_pushSSID(INT apIndex, CHAR *ssid)
{
    INT status;

    status = wifi_setSSIDName(apIndex,ssid);
    wifi_setApEnable(apIndex,FALSE);
    wifi_setApEnable(apIndex,TRUE);

    return status;
}

INT wifi_pushSsidAdvertisementEnable(INT apIndex, BOOL enable)
{
    //Apply default Ssid Advertisement instantly
    return RETURN_ERR;
}

INT wifi_getRadioUpTime(INT radioIndex, ULONG *output)
{
    INT status = RETURN_ERR;
    *output = 0;
    return RETURN_ERR;
}

INT wifi_getApEnableOnLine(INT wlanIndex, BOOL *enabled)
{
   return RETURN_OK;
}

INT wifi_getApSecurityWpaRekeyInterval(INT apIndex, INT *output_int)
{
   return RETURN_OK;
}

//To-do
INT wifi_getApSecurityMFPConfig(INT apIndex, CHAR *output_string)
{
    char output[16]={'\0'};
    char config_file[MAX_BUF_SIZE] = {0};

    if (!output_string)
        return RETURN_ERR;

    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
    wifi_hostapdRead(config_file, "ieee80211w", output, sizeof(output));

    if (strlen(output) == 0)
        snprintf(output_string, 64, "Disabled");
    else if (strncmp(output, "0", 1) == 0)
        snprintf(output_string, 64, "Disabled");
    else if (strncmp(output, "1", 1) == 0)
        snprintf(output_string, 64, "Optional");
    else if (strncmp(output, "2", 1) == 0)
        snprintf(output_string, 64, "Required");
    else {
        wifi_dbg_printf("\n[%s]: Unexpected ieee80211w=%s", __func__, output);
        return RETURN_ERR;
    }

    wifi_dbg_printf("\n[%s]: ieee80211w is : %s", __func__, output);
    return RETURN_OK;
}
INT wifi_setApSecurityMFPConfig(INT apIndex, CHAR *MfpConfig)
{
    char str[MAX_BUF_SIZE]={'\0'};
    char cmd[MAX_CMD_SIZE]={'\0'};
    struct params params;
    char config_file[MAX_BUF_SIZE] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(NULL == MfpConfig || strlen(MfpConfig) >= 32 )
        return RETURN_ERR;

    params.name = "ieee80211w";
    if (strncmp(MfpConfig, "Disabled", strlen("Disabled")) == 0)
        params.value = "0";
    else if (strncmp(MfpConfig, "Optional", strlen("Optional")) == 0)
        params.value = "1";
    else if (strncmp(MfpConfig, "Required", strlen("Required")) == 0)
        params.value = "2";
    else{
        wifi_dbg_printf("%s: invalid MfpConfig. Input has to be Disabled, Optional or Required \n", __func__);
        return RETURN_ERR;
    }
    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
    wifi_hostapdWrite(config_file, &params, 1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
    return RETURN_OK;
}
INT wifi_getRadioAutoChannelEnable(INT radioIndex, BOOL *output_bool)
{
    char output[16]={'\0'};
    char config_file[MAX_BUF_SIZE] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,radioIndex);
    wifi_hostapdRead(config_file,"channel",output,sizeof(output));

    *output_bool = (strncmp(output, "0", 1)==0) ?  TRUE : FALSE;
    WIFI_ENTRY_EXIT_DEBUG("Exit %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT wifi_getRouterEnable(INT wlanIndex, BOOL *enabled)
{
   return RETURN_OK;
}

INT wifi_setApSecurityWpaRekeyInterval(INT apIndex, INT *rekeyInterval)
{
   return RETURN_OK;
}

INT wifi_setRouterEnable(INT wlanIndex, INT *RouterEnabled)
{
   return RETURN_OK;
}

INT wifi_getRadioSupportedDataTransmitRates(INT wlanIndex,CHAR *output)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char config_file[MAX_BUF_SIZE] = {0};

    if (NULL == output)
        return RETURN_ERR;
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,wlanIndex);
    wifi_hostapdRead(config_file,"hw_mode",output,64);

    if(strcmp(output,"b")==0)
        sprintf(output, "%s", "1,2,5.5,11");
    else if (strcmp(output,"a")==0)
        sprintf(output, "%s", "6,9,11,12,18,24,36,48,54");
    else if ((strcmp(output,"n")==0) | (strcmp(output,"g")==0))
        sprintf(output, "%s", "1,2,5.5,6,9,11,12,18,24,36,48,54");

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_getRadioOperationalDataTransmitRates(INT wlanIndex,CHAR *output)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char *temp;
    char temp_output[128];
    char temp_TransmitRates[128];
    char config_file[MAX_BUF_SIZE] = {0};

    if (NULL == output)
        return RETURN_ERR;

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,wlanIndex);
    wifi_hostapdRead(config_file,"supported_rates",output,64);

    if (strlen(output) == 0) {
        wifi_getRadioSupportedDataTransmitRates(wlanIndex, output);
        return RETURN_OK;
    }
    strcpy(temp_TransmitRates,output);
    strcpy(temp_output,"");
    temp = strtok(temp_TransmitRates," ");
    while(temp!=NULL)
    {
        temp[strlen(temp)-1]=0;
        if((temp[0]=='5') && (temp[1]=='\0'))
        {
            temp="5.5";
        }
        strcat(temp_output,temp);
        temp = strtok(NULL," ");
        if(temp!=NULL)
        {
            strcat(temp_output,",");
        }
    }
    strcpy(output,temp_output);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT wifi_setRadioSupportedDataTransmitRates(INT wlanIndex,CHAR *output)
{
        return RETURN_OK;
}


INT wifi_setRadioOperationalDataTransmitRates(INT wlanIndex,CHAR *output)
{
    int i=0;
    char *temp;
    char temp1[128] = {0};
    char temp_output[128] = {0};
    char temp_TransmitRates[128] = {0};
    struct params params={'\0'};
    char config_file[MAX_BUF_SIZE] = {0};
    wifi_band band = wifi_index_to_band(wlanIndex);

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(NULL == output)
        return RETURN_ERR;
    strcpy(temp_TransmitRates,output);

    for(i=0;i<strlen(temp_TransmitRates);i++)
    {
        if (((temp_TransmitRates[i]>='0') && (temp_TransmitRates[i]<='9')) || (temp_TransmitRates[i]==' ') || (temp_TransmitRates[i]=='.') || (temp_TransmitRates[i]==','))
        {
            continue;
        }
        else
        {
            return RETURN_ERR;
        }
    }
    strcpy(temp_output,"");
    temp = strtok(temp_TransmitRates,",");
    while(temp!=NULL)
    {
        strcpy(temp1,temp);
        if(band == band_5)
        {
            if((strcmp(temp,"1")==0) || (strcmp(temp,"2")==0) || (strcmp(temp,"5.5")==0))
            {
                return RETURN_ERR;
            }
        }

        if(strcmp(temp,"5.5")==0)
        {
            strcpy(temp1,"55");
        }
        else
        {
            strcat(temp1,"0");
        }
        strcat(temp_output,temp1);
        temp = strtok(NULL,",");
        if(temp!=NULL)
        {
            strcat(temp_output," ");
        }
    }
    strcpy(output,temp_output);

    params.name = "supported_rates";
    params.value = output;

    wifi_dbg_printf("\n%s:",__func__);
    wifi_dbg_printf("params.value=%s\n",params.value);
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,wlanIndex);
    wifi_hostapdWrite(config_file,&params,1);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}


static char *sncopy(char *dst, int dst_sz, const char *src)
{
    if (src && dst && dst_sz > 0) {
        strncpy(dst, src, dst_sz);
        dst[dst_sz - 1] = '\0';
    }
    return dst;
}

static int util_get_sec_chan_offset(int channel, const char* ht_mode)
{
    if (0 == strcmp(ht_mode, "HT40") ||
        0 == strcmp(ht_mode, "HT80") ||
        0 == strcmp(ht_mode, "HT160") ||
        0 == strcmp(ht_mode, "HT320")) {
        switch (channel) {
            case 0 ... 7:
            case 36:
            case 44:
            case 52:
            case 60:
            case 100:
            case 108:
            case 116:
            case 124:
            case 132:
            case 140:
            case 149:
            case 157:
                return 1;
            case 8 ... 13:
            case 40:
            case 48:
            case 56:
            case 64:
            case 104:
            case 112:
            case 120:
            case 128:
            case 136:
            case 144:
            case 153:
            case 161:
                return -1;
            default:
                return -EINVAL;
        }
    }

    return -EINVAL;
}

static int util_get_6g_sec_chan_offset(int channel, const char* ht_mode)
{
    int idx = channel%8;
    if (0 == strcmp(ht_mode, "HT40") ||
        0 == strcmp(ht_mode, "HT80") ||
        0 == strcmp(ht_mode, "HT160") ||
        0 == strcmp(ht_mode, "HT320")) {
        switch (idx) {
            case 1:
                return 1;
            case 5:
                return -1;
            default:
                return -EINVAL;
        }
    }

    return -EINVAL;
}
static void util_hw_mode_to_bw_mode(const char* hw_mode, char *bw_mode, int bw_mode_len)
{
    if (NULL == hw_mode) return;

    if (0 == strcmp(hw_mode, "ac"))
        sncopy(bw_mode, bw_mode_len, "ht vht");

    if (0 == strcmp(hw_mode, "n"))
        sncopy(bw_mode, bw_mode_len, "ht");

    return;
}

static int util_chan_to_freq(int chan)
{
    if (chan == 14)
        return 2484;
    else if (chan < 14)
        return 2407 + chan * 5;
    else if (chan >= 182 && chan <= 196)
        return 4000 + chan * 5;
    else
        return 5000 + chan * 5;
    return 0;
}

static int util_6G_chan_to_freq(int chan)
{
    if (chan)
        return 5950 + chan * 5;
    else
        return 0;
        
}
const int *util_unii_5g_chan2list(int chan, int width)
{
    static const int lists[] = {
        // <width>, <chan1>, <chan2>..., 0,
        20, 36,  0,
        20, 40,  0,
        20, 44,  0,
        20, 48,  0,
        20, 52,  0,
        20, 56,  0,
        20, 60,  0,
        20, 64,  0,
        20, 100, 0,
        20, 104, 0,
        20, 108, 0,
        20, 112, 0,
        20, 116, 0,
        20, 120, 0,
        20, 124, 0,
        20, 128, 0,
        20, 132, 0,
        20, 136, 0,
        20, 140, 0,
        20, 144, 0,
        20, 149, 0,
        20, 153, 0,
        20, 157, 0,
        20, 161, 0,
        20, 165, 0,
        20, 169, 0,
        20, 173, 0,
        20, 177, 0,
        40, 36,  40,  0,
        40, 44,  48,  0,
        40, 52,  56,  0,
        40, 60,  64,  0,
        40, 100, 104, 0,
        40, 108, 112, 0,
        40, 116, 120, 0,
        40, 124, 128, 0,
        40, 132, 136, 0,
        40, 140, 144, 0,
        40, 149, 153, 0,
        40, 157, 161, 0,
        40, 165, 169, 0,
        40, 173, 177, 0,
        80, 36,  40,  44,  48,  0,
        80, 52,  56,  60,  64,  0,
        80, 100, 104, 108, 112, 0,
        80, 116, 120, 124, 128, 0,
        80, 132, 136, 140, 144, 0,
        80, 149, 153, 157, 161, 0,
        80, 165, 169, 173, 177, 0,
        160,36,  40,  44,  48,  52,  56,  60,  64,  0,
        160,100, 104, 108, 112, 116, 120, 124, 128, 0,
        160,149, 153, 157, 161, 165, 169, 173, 177, 0,
        -1 // final delimiter
    };
    const int *start;
    const int *p;

    for (p = lists; *p != -1; p++) {
        if (*p == width) {
            for (start = ++p; *p != 0; p++) {
                if (*p == chan)
                    return start;
            }
        }
        // move to the end of channel list of given width
        while (*p != 0) {
            p++;
        }
    }

    return NULL;
}

static int util_unii_5g_centerfreq(const char *ht_mode, int channel)
{
    if (NULL == ht_mode)
        return 0;

    const int width = atoi(strlen(ht_mode) > 2 ? ht_mode + 2 : "20");
    const int *chans = util_unii_5g_chan2list(channel, width);
    int sum = 0;
    int cnt = 0;

    if (NULL == chans)
        return 0;

    while (*chans) {
        sum += *chans;
        cnt++;
        chans++;
    }
    if (cnt == 0)
        return 0;
    return sum / cnt;
}

static int util_unii_6g_centerfreq(const char *ht_mode, int channel)
{
    if (NULL == ht_mode)
        return 0;

    int width = strtol((ht_mode + 2), NULL, 10);

    int idx = 0 ;
    int centerchan = 0;
    int chan_ofs = 1;

    if (width == 40){
        idx = ((channel/4) + chan_ofs)%2;
        switch (idx) {
            case 0:
                centerchan = (channel - 2);
                break;
            case 1:
                centerchan = (channel + 2);
                break;                 
            default:
                return -EINVAL;
        }
    }else if (width == 80){
        idx = ((channel/4) + chan_ofs)%4; 
        switch (idx) {
            case 0:
                centerchan = (channel - 6);
                break;
            case 1:
                centerchan = (channel + 6);
                break;
            case 2:
                centerchan = (channel + 2);
                break;
            case 3:
                centerchan = (channel - 2);
                break;
            default:
                return -EINVAL;
        }    
    }else if (width == 160){
        switch (channel) {
            case 1 ... 29:
                centerchan = 15;
                break;
            case 33 ... 61:
                centerchan = 47;
                break;
            case 65 ... 93:
                centerchan = 79;
                break;
            case 97 ... 125:
                centerchan = 111;
                break;
            case 129 ... 157:
                centerchan = 143;
                break;
            case 161 ... 189:
                centerchan = 175;
                break;
            case 193 ... 221:
                centerchan = 207;
                break;
            default:
                return -EINVAL;
        }        
    }else if (width == 320){
        switch (channel) {
            case 1 ... 29:
                centerchan = 31;
                break;
            case 33 ... 93:
                centerchan = 63;
                break;
            case 97 ... 157:
                centerchan = 127;
                break;
            case 161 ... 221:
                centerchan = 191;
                break;
            default:
                return -EINVAL;
        }
    }
    return centerchan;
}
static int util_radio_get_hw_mode(int radioIndex, char *hw_mode, int hw_mode_size)
{
    BOOL onlyG, onlyN, onlyA;
    CHAR tmp[64];
    int ret = wifi_getRadioStandard(radioIndex, tmp, &onlyG, &onlyN, &onlyA);
    if (ret == RETURN_OK) {
        sncopy(hw_mode, hw_mode_size, tmp);
    }
    return ret;
}

struct wifi_hal_freq_params {
	/**
	 * freq - Primary channel center frequency in MHz
	 */
	int freq;

	/**
	 * channel - Channel number
	 */
	int channel;

	/**
	 * sec_channel_offset - Secondary channel offset for HT40
	 *
	 * 0 = HT40 disabled,
	 * -1 = HT40 enabled, secondary channel below primary,
	 * 1 = HT40 enabled, secondary channel above primary
	 */
	int sec_channel_offset;

	/**
	 * center_freq1 - Segment 0 center frequency in MHz
	 *
	 * Valid for both HT and VHT.
	 */
	int center_freq1;

	/**
	 * center_freq2 - Segment 1 center frequency in MHz
	 *
	 * Non-zero only for bandwidth 80 and an 80+80 channel
	 */
	int center_freq2;

	/**
	 * bandwidth - Channel bandwidth in MHz (20, 40, 80, 160)
	 */
	int bandwidth;
};

static int util_check_freq_params(struct wifi_hal_freq_params *params)
{
   fprintf(stdout, "chanswitch: bandwidth %d freq %d center_freq1 %d"
           " center_freq2 %d sec_channel_offset %d\n",
           params->bandwidth,
           params->freq,
           params->center_freq1,
           params->center_freq2,
           params->sec_channel_offset);

	switch (params->bandwidth) {
	case 0:
		/* bandwidth not specified: use 20 MHz by default */
		/* fall-through */
	case 20:
		if (params->center_freq1 &&
		    params->center_freq1 != params->freq)
			return -1;

		if (params->center_freq2 || params->sec_channel_offset)
			return -1;
		break;
	case 40:
		if (params->center_freq2 || !params->sec_channel_offset)
			return -1;

		if (!params->center_freq1)
			break;
		switch (params->sec_channel_offset) {
		case 1:
			if (params->freq + 10 != params->center_freq1)
				return -1;
			break;
		case -1:
			if (params->freq - 10 != params->center_freq1)
				return -1;
			break;
		default:
			return -1;
		}
		break;
	case 80:
		if (!params->center_freq1 || !params->sec_channel_offset)
			return 1;

		switch (params->sec_channel_offset) {
		case 1:
			if (params->freq - 10 != params->center_freq1 &&
			    params->freq + 30 != params->center_freq1)
				return 1;
			break;
		case -1:
			if (params->freq + 10 != params->center_freq1 &&
			    params->freq - 30 != params->center_freq1)
				return -1;
			break;
		default:
			return -1;
		}

		/* Adjacent and overlapped are not allowed for 80+80 */
		if (params->center_freq2 &&
		    params->center_freq1 - params->center_freq2 <= 80 &&
		    params->center_freq2 - params->center_freq1 <= 80)
			return 1;
		break;
	case 160:
		if (!params->center_freq1 || params->center_freq2 ||
		    !params->sec_channel_offset)
			return -1;

		switch (params->sec_channel_offset) {
		case 1:
			if (params->freq + 70 != params->center_freq1 &&
			    params->freq + 30 != params->center_freq1 &&
			    params->freq - 10 != params->center_freq1 &&
			    params->freq - 50 != params->center_freq1)
				return -1;
			break;
		case -1:
			if (params->freq + 50 != params->center_freq1 &&
			    params->freq + 10 != params->center_freq1 &&
			    params->freq - 30 != params->center_freq1 &&
			    params->freq - 70 != params->center_freq1)
				return -1;
			break;
		default:
			return -1;
		}
		break;
	default:
		return -1;
	}

	return 0;
}
INT wifi_pushRadioChannel2(INT radioIndex, UINT channel, UINT channel_width_MHz, UINT csa_beacon_count)
{
    // Sample commands:
    //   hostapd_cli -i wifi1 chan_switch 30 5200 sec_channel_offset=-1 center_freq1=5190 bandwidth=40 ht vht
    //   hostapd_cli -i wifi0 chan_switch 30 2437
    char cmd[MAX_CMD_SIZE] = {0};
    char buf[MAX_BUF_SIZE] = {0};
    int freq = 0, ret = 0;
    char center_freq1_str[32] = ""; // center_freq1=%d
    char opt_chan_info_str[32] = ""; // bandwidth=%d ht vht
    char sec_chan_offset_str[32] = ""; // sec_channel_offset=%d
    char hw_mode[16] = ""; // n|ac
    char bw_mode[16] = ""; // ht|ht vht
    char ht_mode[16] = ""; // HT20|HT40|HT80|HT160
    char interface_name[16] = {0};
    int sec_chan_offset;
    int width;
    char config_file[64] = {0};
    BOOL stbcEnable = FALSE;
    BOOL setEHT320 = FALSE;
    char *ext_str = "None";
    wifi_band band = band_invalid;
    int center_chan = 0;
    int center_freq1 = 0;
    struct wifi_hal_freq_params params = {0};

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);

    if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    band = wifi_index_to_band(radioIndex);

    width = channel_width_MHz > 20 ? channel_width_MHz : 20;

    // Get radio mode HT20|HT40|HT80 etc.
    if (channel){
        if (band == band_6){
            freq = util_6G_chan_to_freq(channel);
        }else{
            freq = util_chan_to_freq(channel);
        }
        if (width == 320) {
            width = 160;    // We should set HE central channel as 160, and additionally modify EHT central channel with 320
            setEHT320 = TRUE;
        }
        snprintf(ht_mode, sizeof(ht_mode), "HT%d", width);

        // Provide bandwith if specified
        if (channel_width_MHz > 20) {
            // Select bandwidth mode from hardware n --> ht | ac --> ht vht
            util_radio_get_hw_mode(radioIndex, hw_mode, sizeof(hw_mode));
            util_hw_mode_to_bw_mode(hw_mode, bw_mode, sizeof(bw_mode));

            snprintf(opt_chan_info_str, sizeof(opt_chan_info_str), "bandwidth=%d %s", width, bw_mode);
        }else if (channel_width_MHz == 20){
            snprintf(opt_chan_info_str, sizeof(opt_chan_info_str), "bandwidth=%d ht", width);
        }


        if (channel_width_MHz > 20) {
            if (band == band_6){
                center_chan = util_unii_6g_centerfreq(ht_mode, channel);
                if(center_chan){
                    center_freq1 = util_6G_chan_to_freq(center_chan);
                }
            }else{
                center_chan = util_unii_5g_centerfreq(ht_mode, channel);
                if(center_chan){
                    center_freq1 = util_chan_to_freq(center_chan);
                }
            }
            
            if (center_freq1)
                snprintf(center_freq1_str, sizeof(center_freq1_str), "center_freq1=%d", center_freq1);
            
        }

        // Find channel offset +1/-1 for wide modes (HT40|HT80|HT160)
        if (band == band_6){
            sec_chan_offset = util_get_6g_sec_chan_offset(channel, ht_mode);
        }else{
            sec_chan_offset = util_get_sec_chan_offset(channel, ht_mode);
        }
        if (sec_chan_offset != -EINVAL)
            snprintf(sec_chan_offset_str, sizeof(sec_chan_offset_str), "sec_channel_offset=%d", sec_chan_offset);

        params.channel = channel;
        params.freq = freq;
        params.bandwidth = width;
        params.center_freq1 = center_freq1;
        if (sec_chan_offset != -EINVAL)
            params.sec_channel_offset = sec_chan_offset;

        /* add channel parameter check to avoid error channel setting write to hostapd conf file */
        if (util_check_freq_params(&params)) {
            fprintf(stderr, "util_check_freq_params: return fail\n");
            return RETURN_ERR;
        }


        // Only the first AP, other are hanging on the same radio
        int apIndex = radioIndex;
        snprintf(cmd, sizeof(cmd), "hostapd_cli  -i %s chan_switch %d %d %s %s %s",
            interface_name, csa_beacon_count, freq,
            sec_chan_offset_str, center_freq1_str, opt_chan_info_str);

        ret = _syscmd(cmd, buf, sizeof(buf));
        fprintf(stdout, "execute: '%s' return %s\n", cmd, buf);

        wifi_reloadAp(radioIndex);

        ret = wifi_setRadioChannel(radioIndex, channel);
        if (ret != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setRadioChannel return error.\n", __func__);
            return RETURN_ERR;
        }

        if (sec_chan_offset == 1) ext_str = "Above";
        else if (sec_chan_offset == -1) ext_str = "Below";

        wifi_setRadioCenterChannel(radioIndex, center_chan);

    } else {
        if (channel_width_MHz > 20)
            ext_str = "Above";
    }

    char mhz_str[16];
    snprintf(mhz_str, sizeof(mhz_str), "%dMHz", width);
    if (setEHT320 == TRUE)
        wifi_setRadioOperatingChannelBandwidth(radioIndex, "320MHz");
    else
        wifi_setRadioOperatingChannelBandwidth(radioIndex, mhz_str);

    writeBandWidth(radioIndex, mhz_str);
    if (band == band_2_4 || band == band_5) {
        if (width == 20)
            wifi_RemoveRadioExtChannel(radioIndex, ext_str);
        else
            wifi_setRadioExtChannel(radioIndex, ext_str);
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT wifi_getNeighboringWiFiStatus(INT radio_index, wifi_neighbor_ap2_t **neighbor_ap_array, UINT *output_array_size)
{
    int index = -1;
    wifi_neighbor_ap2_t *scan_array = NULL;
    char cmd[256]={0};
    char buf[128]={0};
    char file_name[32] = {0};
    char filter_SSID[32] = {0};
    char line[256] = {0};
    char interface_name[16] = {0};
    char *ret = NULL;
    int freq=0;
    FILE *f = NULL;
    size_t len=0;
    int channels_num = 0;
    int vht_channel_width = 0;
    int get_noise_ret = RETURN_ERR;
    bool filter_enable = false;
    bool filter_BSS = false;     // The flag determine whether the BSS information need to be filterd.
    int phyId = 0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s: %d\n", __func__, __LINE__);

    snprintf(file_name, sizeof(file_name), "%s%d.txt", ESSID_FILE, radio_index);
    f = fopen(file_name, "r");
    if (f != NULL) {
        fgets(buf, sizeof(buf), f);
        if ((strncmp(buf, "0", 1)) != 0) {
            fgets(filter_SSID, sizeof(filter_SSID), f);
            /* strip trailing newline before using in strcmp */
            filter_SSID[strcspn(filter_SSID, "\n")] = '\0';
            if (strlen(filter_SSID) != 0)
                filter_enable = true;
        }
        fclose(f);
    }

    if (wifi_GetInterfaceName(radio_index, interface_name) != RETURN_OK)
        return RETURN_ERR;

    phyId = radio_index_to_phy(radio_index);

    snprintf(cmd, sizeof(cmd), "iw phy phy%d channels | grep * | grep -v disable | wc -l", phyId);
    _syscmd(cmd, buf, sizeof(buf));
    channels_num = strtol(buf, NULL, 10);

    sprintf(cmd, "iw dev %s scan dump | grep '%s\\|SSID\\|freq\\|beacon interval\\|capabilities\\|signal\\|Supported rates\\|DTIM\\| \
    // WPA\\|RSN\\|Group cipher\\|HT operation\\|secondary channel offset\\|channel width\\|HE.*GHz' | grep -v -e '*.*BSS'", interface_name, interface_name);
    fprintf(stderr, "cmd: %s\n", cmd);
    if ((f = popen(cmd, "r")) == NULL) {
        wifi_dbg_printf("%s: popen %s error\n", __func__, cmd);
        return RETURN_ERR;
    }
	
    struct channels_noise *channels_noise_arr = calloc(channels_num, sizeof(struct channels_noise));
    get_noise_ret = get_noise(radio_index, channels_noise_arr, channels_num);
	
    ret = fgets(line, sizeof(line), f);
    while (ret != NULL) {
        if(strstr(line, "BSS") != NULL) {    // new neighbor info
            // The SSID field is not in the first field. So, we should store whole BSS informations and the filter flag. 
            // And we will determine whether we need the previous BSS infomation when parsing the next BSS field or end of while loop.
            // If we don't want the BSS info, we don't realloc more space, and just clean the previous BSS.

            if (!filter_BSS) {
                index++;
                wifi_neighbor_ap2_t *tmp;
                tmp = realloc(scan_array, sizeof(wifi_neighbor_ap2_t)*(index+1));
                if (tmp == NULL) {              // no more memory to use
                    index--;
                    wifi_dbg_printf("%s: realloc failed\n", __func__);
                    break;
                }
                scan_array = tmp;
            }
            memset(&(scan_array[index]), 0, sizeof(wifi_neighbor_ap2_t));

            filter_BSS = false;
            sscanf(line, "BSS %17s", scan_array[index].ap_BSSID);
            strncpy(scan_array[index].ap_Mode, "Infrastructure", strlen("Infrastructure"));
            strncpy(scan_array[index].ap_SecurityModeEnabled, "None", strlen("None"));
            strncpy(scan_array[index].ap_EncryptionMode, "None", strlen("None"));
        } else if (strstr(line, "freq") != NULL) {
            sscanf(line,"	freq: %d", &freq);
            scan_array[index].ap_Channel = ieee80211_frequency_to_channel(freq);

            if (freq >= 2412 && freq <= 2484) {
                strncpy(scan_array[index].ap_OperatingFrequencyBand, "2.4GHz", strlen("2.4GHz"));
                strncpy(scan_array[index].ap_SupportedStandards, "b,g", strlen("b,g"));
                strncpy(scan_array[index].ap_OperatingStandards, "g", strlen("g"));
            }
            else if (freq >= 5160 && freq <= 5805) {
                strncpy(scan_array[index].ap_OperatingFrequencyBand, "5GHz", strlen("5GHz"));
                strncpy(scan_array[index].ap_SupportedStandards, "a", strlen("a"));
                strncpy(scan_array[index].ap_OperatingStandards, "a", strlen("a"));
            }

            scan_array[index].ap_Noise = 0;
            if (get_noise_ret == RETURN_OK) {
                for (int i = 0; i < channels_num; i++) {
                    if (scan_array[index].ap_Channel == channels_noise_arr[i].channel) {
                        scan_array[index].ap_Noise = channels_noise_arr[i].noise;
                        break;
                    }
                }
            }
        } else if (strstr(line, "beacon interval") != NULL) {
            sscanf(line,"	beacon interval: %d TUs", &(scan_array[index].ap_BeaconPeriod));
        } else if (strstr(line, "signal") != NULL) {
            sscanf(line,"	signal: %d", &(scan_array[index].ap_SignalStrength));
        } else if (strstr(line,"SSID") != NULL) {
            sscanf(line,"	SSID: %63s", scan_array[index].ap_SSID);
            if (filter_enable && strcmp(scan_array[index].ap_SSID, filter_SSID) != 0) {
                filter_BSS = true;
            }
        } else if (strstr(line, "Supported rates") != NULL) {
            char SRate[80] = {0}, *tmp = NULL;
            memset(buf, 0, sizeof(buf));
            strncpy(SRate, line, sizeof(SRate) - 1);
            SRate[sizeof(SRate) - 1] = '\0';
            tmp = strtok(SRate, ":");
            tmp = strtok(NULL, ":");
            if (tmp == NULL)
                continue;
            snprintf(buf, sizeof(buf), "%s", tmp);
            memset(SRate, 0, sizeof(SRate));

            tmp = strtok(buf, " \n");
            while (tmp != NULL) {
                if (strlen(SRate) + strlen(tmp) + 2 < sizeof(SRate)) {
                    strcat(SRate, tmp);
                    if (SRate[strlen(SRate) - 1] == '*') {
                        SRate[strlen(SRate) - 1] = '\0';
                    }
                    strcat(SRate, ",");
                }
                tmp = strtok(NULL, " \n");
            }
            if (strlen(SRate) > 0)
                SRate[strlen(SRate) - 1] = '\0';
            snprintf(scan_array[index].ap_SupportedDataTransferRates,
                     sizeof(scan_array[index].ap_SupportedDataTransferRates), "%s", SRate);
        } else if (strstr(line, "DTIM") != NULL) {
            sscanf(line,"DTIM Period %u", &scan_array[index].ap_DTIMPeriod);
        } else if (strstr(line, "VHT capabilities") != NULL) {
            strcat(scan_array[index].ap_SupportedStandards, ",ac");
            strcpy(scan_array[index].ap_OperatingStandards, "ac");
        } else if (strstr(line, "HT capabilities") != NULL) {
            strcat(scan_array[index].ap_SupportedStandards, ",n");
            strcpy(scan_array[index].ap_OperatingStandards, "n");
        } else if (strstr(line, "VHT operation") != NULL) {
            ret = fgets(line, sizeof(line), f);
            sscanf(line,"		 * channel width: %d", &vht_channel_width);
            if(vht_channel_width == 1) {
                snprintf(scan_array[index].ap_OperatingChannelBandwidth, sizeof(scan_array[index].ap_OperatingChannelBandwidth), "11AC_VHT80");
            } else {
                snprintf(scan_array[index].ap_OperatingChannelBandwidth, sizeof(scan_array[index].ap_OperatingChannelBandwidth), "11AC_VHT40");
            }
            if (strstr(line, "BSS") != NULL)   // prevent to get the next neighbor information
                continue;
        } else if (strstr(line, "HT operation") != NULL) {
            ret = fgets(line, sizeof(line), f);
            sscanf(line,"		 * secondary channel offset: %127s", &buf);
            if (!strcmp(buf, "above")) {
                //40Mhz +
                snprintf(scan_array[index].ap_OperatingChannelBandwidth, sizeof(scan_array[index].ap_OperatingChannelBandwidth), "11N%s_HT40PLUS", radio_index%1 ? "A": "G");
            }
            else if (!strcmp(buf, "below")) {
                //40Mhz -
                snprintf(scan_array[index].ap_OperatingChannelBandwidth, sizeof(scan_array[index].ap_OperatingChannelBandwidth), "11N%s_HT40MINUS", radio_index%1 ? "A": "G");
            } else {
                //20Mhz
                snprintf(scan_array[index].ap_OperatingChannelBandwidth, sizeof(scan_array[index].ap_OperatingChannelBandwidth), "11N%s_HT20", radio_index%1 ? "A": "G");
            }
            if (strstr(line, "BSS") != NULL)   // prevent to get the next neighbor information
                continue;
        } else if (strstr(line, "HE capabilities") != NULL) {
            strcat(scan_array[index].ap_SupportedStandards, ",ax");
            strcpy(scan_array[index].ap_OperatingStandards, "ax");
            ret = fgets(line, sizeof(line), f);
            if (strncmp(scan_array[index].ap_OperatingFrequencyBand, "2.4GHz", strlen("2.4GHz")) == 0) {
                if (strstr(line, "HE40/2.4GHz") != NULL)
                    strcpy(scan_array[index].ap_OperatingChannelBandwidth, "11AXHE40PLUS");
                else
                    strcpy(scan_array[index].ap_OperatingChannelBandwidth, "11AXHE20");
            } else if (strncmp(scan_array[index].ap_OperatingFrequencyBand, "5GHz", strlen("5GHz")) == 0) {
                if (strstr(line, "HE80/5GHz") != NULL) {
                    strcpy(scan_array[index].ap_OperatingChannelBandwidth, "11AXHE80");
                    ret = fgets(line, sizeof(line), f);
                } else
                    continue;
                if (strstr(line, "HE160/5GHz") != NULL)
                    strcpy(scan_array[index].ap_OperatingChannelBandwidth, "11AXHE160");
            }
            continue;
        } else if (strstr(line, "WPA") != NULL) {
            strcpy(scan_array[index].ap_SecurityModeEnabled, "WPA");
        } else if (strstr(line, "RSN") != NULL) {
            strcpy(scan_array[index].ap_SecurityModeEnabled, "RSN");
        } else if (strstr(line, "Group cipher") != NULL) {
            sscanf(line, "		 * Group cipher: %63s", scan_array[index].ap_EncryptionMode);
            if (strncmp(scan_array[index].ap_EncryptionMode, "CCMP", strlen("CCMP")) == 0) {
                strcpy(scan_array[index].ap_EncryptionMode, "AES");
            }
        }
        ret = fgets(line, sizeof(line), f);
    }

    if (!filter_BSS) {
        *output_array_size = index + 1;
    } else {
        memset(&(scan_array[index]), 0, sizeof(wifi_neighbor_ap2_t));
        *output_array_size = index;
    }
    *neighbor_ap_array = scan_array;
    pclose(f);
    free(channels_noise_arr);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_getApAssociatedDeviceStats(
        INT apIndex,
        mac_address_t *clientMacAddress,
        wifi_associated_dev_stats_t *associated_dev_stats,
        u64 *handle)
{
    wifi_associated_dev_stats_t *dev_stats = associated_dev_stats;
    char interface_name[50] = {0};
    char cmd[1024] =  {0};
    char mac_str[18] = {0};
    char *key = NULL;
    char *val = NULL;
    FILE *f = NULL;
    char *line = NULL;
    size_t len = 0;

    if(wifi_getApName(apIndex, interface_name) != RETURN_OK) {
        wifi_dbg_printf("%s: wifi_getApName failed\n",  __FUNCTION__);
        return RETURN_ERR;
    }

    sprintf(mac_str, "%x:%x:%x:%x:%x:%x", (*clientMacAddress)[0],(*clientMacAddress)[1],(*clientMacAddress)[2],(*clientMacAddress)[3],(*clientMacAddress)[4],(*clientMacAddress)[5]);
    sprintf(cmd,"iw dev %s station get %s | grep 'rx\\|tx' | tr -d '\t'", interface_name, mac_str);
    if((f = popen(cmd, "r")) == NULL) {
        wifi_dbg_printf("%s: popen %s error\n", __func__, cmd);
        return RETURN_ERR;
    }

    while ((getline(&line, &len, f)) != -1) {
        key = strtok(line,":");
        val = strtok(NULL,":");

        if (key == NULL || val == NULL)
            continue;
	if(!strncmp(key,"rx bytes",8))
	    sscanf(val, "%llu", &dev_stats->cli_rx_bytes);
	if(!strncmp(key,"tx bytes",8))
            sscanf(val, "%llu", &dev_stats->cli_tx_bytes);
	if(!strncmp(key,"rx packets",10))
            sscanf(val, "%llu", &dev_stats->cli_tx_frames);
	if(!strncmp(key,"tx packets",10))
            sscanf(val, "%llu", &dev_stats->cli_tx_frames);
        if(!strncmp(key,"tx retries",10))
            sscanf(val, "%llu", &dev_stats->cli_tx_retries);
        if(!strncmp(key,"tx failed",9))
            sscanf(val, "%llu", &dev_stats->cli_tx_errors);
        if(!strncmp(key,"rx drop misc",13))
            sscanf(val, "%llu", &dev_stats->cli_rx_errors);
        if(!strncmp(key,"rx bitrate",10)) {
            val = strtok(val, " ");
            sscanf(val, "%lf", &dev_stats->cli_rx_rate);
        }
        if(!strncmp(key,"tx bitrate",10)) {
            val = strtok(val, " ");
            sscanf(val, "%lf", &dev_stats->cli_tx_rate);
        }
    }
    free(line);
    pclose(f);
    return RETURN_OK;
}

INT wifi_getSSIDNameStatus(INT apIndex, CHAR *output_string)
{
    char interface_name[16] = {0};
    char cmd[MAX_CMD_SIZE] = {0}, buf[MAX_BUF_SIZE] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == output_string)
        return RETURN_ERR;

    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    snprintf(cmd, sizeof(cmd), "hostapd_cli  -i %s get_config | grep ^ssid | cut -d '=' -f2 | tr -d '\n'", interface_name);
    _syscmd(cmd, buf, sizeof(buf));

    //size of SSID name restricted to value less than 32 bytes
    snprintf(output_string, 32, "%s", buf);
    WIFI_ENTRY_EXIT_DEBUG("Exit %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT wifi_getApMacAddressControlMode(INT apIndex, INT *output_filterMode)
{
    //char cmd[MAX_CMD_SIZE] = {0};
    char config_file[MAX_BUF_SIZE] = {0};
    char buf[32] = {0};

    if (!output_filterMode)
        return RETURN_ERR;

    //snprintf(cmd, sizeof(cmd), "syscfg get %dblockall", apIndex);
    //_syscmd(cmd, buf, sizeof(buf));
    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
    if (!syn_flag)
        wifi_hostapdRead(config_file, "macaddr_acl", buf, sizeof(buf));
    else
        snprintf(buf, sizeof(buf), "%s", vap_info[apIndex].macaddr_acl);
    if(strlen(buf) == 0) {
        *output_filterMode = 0;
    }
    else {
        int macaddr_acl_mode = strtol(buf, NULL, 10);
        if (macaddr_acl_mode == 1) {
            *output_filterMode = 1;
        } else if (macaddr_acl_mode == 0) {
            wifi_hostapdRead(config_file, "deny_mac_file", buf, sizeof(buf));
            if (strlen(buf) == 0) {
                *output_filterMode = 0;
            } else {
                *output_filterMode = 2;
            }
        } else {
            return RETURN_ERR;
        }
    }

    return RETURN_OK;
}

INT wifi_getApAssociatedDeviceDiagnosticResult2(INT apIndex,wifi_associated_dev2_t **associated_dev_array,UINT *output_array_size)
{
    FILE *fp = NULL;
    char str[MAX_BUF_SIZE] = {0};
    int wificlientindex = 0 ;
    int count = 0;
    int signalstrength = 0;
    int arr[MACADDRESS_SIZE] = {0};
    unsigned char mac[MACADDRESS_SIZE] = {0};
    UINT wifi_count = 0;
    char virtual_interface_name[MAX_BUF_SIZE] = {0};
    char pipeCmd[MAX_CMD_SIZE] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    *output_array_size = 0;
    *associated_dev_array = NULL;
    char interface_name[50] = {0};

    if(wifi_getApName(apIndex, interface_name) != RETURN_OK) {
        wifi_dbg_printf("%s: wifi_getApName failed\n",  __FUNCTION__);
        return RETURN_ERR;
    }

    sprintf(pipeCmd, "iw dev %s station dump | grep %s | wc -l", interface_name, interface_name);
    fp = popen(pipeCmd, "r");
    if (fp == NULL)
    {
        printf("Failed to run command inside function %s\n",__FUNCTION__ );
        return RETURN_ERR;
    }

    /* Read the output a line at a time - output it. */
    fgets(str, sizeof(str)-1, fp);
    wifi_count = (unsigned int) atoi ( str );
    *output_array_size = wifi_count;
    wifi_dbg_printf(" In rdkb hal ,Wifi Client Counts and index %d and  %d \n",*output_array_size,apIndex);
    pclose(fp);

    if(wifi_count == 0)
    {
        return RETURN_OK;
    }
    else
    {
        wifi_associated_dev2_t* temp = NULL;
        temp = (wifi_associated_dev2_t*)calloc(wifi_count, sizeof(wifi_associated_dev2_t));
        *associated_dev_array = temp;
        if(temp == NULL)
        {
            printf("Error Statement. Insufficient memory \n");
            return RETURN_ERR;
        }

        snprintf(pipeCmd, sizeof(pipeCmd), "iw dev %s station dump > /tmp/AssociatedDevice_Stats.txt", interface_name);
        system(pipeCmd);

        fp = fopen("/tmp/AssociatedDevice_Stats.txt", "r");
        if(fp == NULL)
        {
            printf("/tmp/AssociatedDevice_Stats.txt not exists \n");
            free(temp);
            *associated_dev_array = NULL;
            return RETURN_ERR;
        }
        fclose(fp);

        sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep Station | cut -d ' ' -f 2");
        fp = popen(pipeCmd, "r");
        if(fp)
        {
            for(count =0 ; count < wifi_count; count++)
            {
                fgets(str, MAX_BUF_SIZE, fp);
                if( MACADDRESS_SIZE == sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",&arr[0],&arr[1],&arr[2],&arr[3],&arr[4],&arr[5]) )
                {
                    for( wificlientindex = 0; wificlientindex < MACADDRESS_SIZE; ++wificlientindex )
                    {
                        mac[wificlientindex] = (unsigned char) arr[wificlientindex];

                    }
                    memcpy(temp[count].cli_MACAddress,mac,(sizeof(unsigned char))*6);
                    wifi_dbg_printf("MAC %d = %X:%X:%X:%X:%X:%X \n", count, temp[count].cli_MACAddress[0],temp[count].cli_MACAddress[1], temp[count].cli_MACAddress[2], temp[count].cli_MACAddress[3], temp[count].cli_MACAddress[4], temp[count].cli_MACAddress[5]);
                }
                temp[count].cli_AuthenticationState = 1; //TODO
                temp[count].cli_Active = 1; //TODO
            }
            pclose(fp);
        }

        //Updating  RSSI per client
        sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep signal | tr -s ' ' | cut -d ' ' -f 2 > /tmp/wifi_signalstrength.txt");
        fp = popen(pipeCmd, "r");
        if(fp)
        {
            pclose(fp);
        }
        fp = popen("cat /tmp/wifi_signalstrength.txt | tr -s ' ' | cut -f 2","r");
        if(fp)
        {
            for(count =0 ; count < wifi_count ;count++)
            {
                fgets(str, MAX_BUF_SIZE, fp);
                signalstrength = atoi(str);
                temp[count].cli_RSSI = signalstrength;
            }
            pclose(fp);
        }


        //LastDataDownlinkRate
        sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'tx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Send.txt");
        fp = popen(pipeCmd, "r");
        if (fp)
        {
            pclose(fp);
        }
        fp = popen("cat /tmp/Ass_Bitrate_Send.txt | tr -s ' ' | cut -f 2", "r");
        if (fp)
        {
            for (count = 0; count < wifi_count; count++)
            {
                fgets(str, MAX_BUF_SIZE, fp);
                temp[count].cli_LastDataDownlinkRate = strtoul(str, NULL, 10);
                temp[count].cli_LastDataDownlinkRate = (temp[count].cli_LastDataDownlinkRate * 1024); //Mbps -> Kbps
            }
            pclose(fp);
        }

        //LastDataUplinkRate
        sprintf(pipeCmd, "cat /tmp/AssociatedDevice_Stats.txt | grep 'rx bitrate' | tr -s ' ' | cut -d ' ' -f 2 > /tmp/Ass_Bitrate_Received.txt");
        fp = popen(pipeCmd, "r");
        if (fp)
        {
            pclose(fp);
        }
        fp = popen("cat /tmp/Ass_Bitrate_Received.txt | tr -s ' ' | cut -f 2", "r");
        if (fp)
        {
            for (count = 0; count < wifi_count; count++)
            {
                fgets(str, MAX_BUF_SIZE, fp);
                temp[count].cli_LastDataUplinkRate = strtoul(str, NULL, 10);
                temp[count].cli_LastDataUplinkRate = (temp[count].cli_LastDataUplinkRate * 1024); //Mbps -> Kbps
            }
            pclose(fp);
        }
    }
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;

}

INT wifi_getSSIDTrafficStats2(INT ssidIndex,wifi_ssidTrafficStats2_t *output_struct)
{
#if 0
    /*char buf[1024] = {0};
    sprintf(cmd, "ifconfig %s ", interface_name);
    _syscmd(cmd, buf, sizeof(buf));*/

    output_struct->ssid_BytesSent = 2048;   //The total number of bytes transmitted out of the interface, including framing characters.
    output_struct->ssid_BytesReceived = 4096;       //The total number of bytes received on the interface, including framing characters.
    output_struct->ssid_PacketsSent = 128;  //The total number of packets transmitted out of the interface.
    output_struct->ssid_PacketsReceived = 128; //The total number of packets received on the interface.

    output_struct->ssid_RetransCount = 0;   //The total number of transmitted packets which were retransmissions. Two retransmissions of the same packet results in this counter incrementing by two.
    output_struct->ssid_FailedRetransCount = 0; //The number of packets that were not transmitted successfully due to the number of retransmission attempts exceeding an 802.11 retry limit. This parameter is based on dot11FailedCount from [802.11-2012].
    output_struct->ssid_RetryCount = 0;  //The number of packets that were successfully transmitted after one or more retransmissions. This parameter is based on dot11RetryCount from [802.11-2012].
    output_struct->ssid_MultipleRetryCount = 0; //The number of packets that were successfully transmitted after more than one retransmission. This parameter is based on dot11MultipleRetryCount from [802.11-2012].
    output_struct->ssid_ACKFailureCount = 0;  //The number of expected ACKs that were never received. This parameter is based on dot11ACKFailureCount from [802.11-2012].
    output_struct->ssid_AggregatedPacketCount = 0; //The number of aggregated packets that were transmitted. This applies only to 802.11n and 802.11ac.

    output_struct->ssid_ErrorsSent = 0;     //The total number of outbound packets that could not be transmitted because of errors.
    output_struct->ssid_ErrorsReceived = 0;    //The total number of inbound packets that contained errors preventing them from being delivered to a higher-layer protocol.
    output_struct->ssid_UnicastPacketsSent = 2;     //The total number of inbound packets that contained errors preventing them from being delivered to a higher-layer protocol.
    output_struct->ssid_UnicastPacketsReceived = 2;  //The total number of received packets, delivered by this layer to a higher layer, which were not addressed to a multicast or broadcast address at this layer.
    output_struct->ssid_DiscardedPacketsSent = 1; //The total number of outbound packets which were chosen to be discarded even though no errors had been detected to prevent their being transmitted. One possible reason for discarding such a packet could be to free up buffer space.
    output_struct->ssid_DiscardedPacketsReceived = 1; //The total number of inbound packets which were chosen to be discarded even though no errors had been detected to prevent their being delivered. One possible reason for discarding such a packet could be to free up buffer space.
    output_struct->ssid_MulticastPacketsSent = 10; //The total number of packets that higher-level protocols requested for transmission and which were addressed to a multicast address at this layer, including those that were discarded or not sent.
    output_struct->ssid_MulticastPacketsReceived = 0; //The total number of received packets, delivered by this layer to a higher layer, which were addressed to a multicast address at this layer.
    output_struct->ssid_BroadcastPacketsSent = 0;  //The total number of packets that higher-level protocols requested for transmission and which were addressed to a broadcast address at this layer, including those that were discarded or not sent.
    output_struct->ssid_BroadcastPacketsRecevied = 1; //The total number of packets that higher-level protocols requested for transmission and which were addressed to a broadcast address at this layer, including those that were discarded or not sent.
    output_struct->ssid_UnknownPacketsReceived = 0;  //The total number of packets received via the interface which were discarded because of an unknown or unsupported protocol.
#endif

    FILE *fp = NULL;
    char interface_name[50] = {0};
    char pipeCmd[128] = {0};
    char str[256] = {0};
    wifi_ssidTrafficStats2_t *out = output_struct;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);
    if (!output_struct)
        return RETURN_ERR;

    memset(out, 0, sizeof(wifi_ssidTrafficStats2_t));
    if (wifi_GetInterfaceName(ssidIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    if (!is_valid_ifname(interface_name))
        return RETURN_ERR;
    snprintf(pipeCmd, sizeof(pipeCmd), "cat /proc/net/dev | grep %s", interface_name);

    fp = popen(pipeCmd, "r");
    if (fp == NULL) {
        fprintf(stderr, "%s: popen failed\n", __func__);
        return RETURN_ERR;
    }
    fgets(str, sizeof(str), fp);
    pclose(fp);

    if (strlen(str) == 0)   // interface not exist
        return RETURN_OK;

    sscanf(str, "%*[^:]: %lu %lu %lu %lu %* %* %* %* %lu %lu %lu %lu", &out->ssid_BytesReceived, &out->ssid_PacketsReceived, &out->ssid_ErrorsReceived, \
    &out->ssid_DiscardedPacketsReceived, &out->ssid_BytesSent, &out->ssid_PacketsSent, &out->ssid_ErrorsSent, &out->ssid_DiscardedPacketsSent);

    memset(str, 0, sizeof(str));
    sprintf(pipeCmd, "tail -n1 /proc/net/netstat");
    fp = popen(pipeCmd, "r");
    if (fp == NULL) {
        fprintf(stderr, "%s: popen failed\n", __func__);
        return RETURN_ERR;
    }
    fgets(str, sizeof(str), fp);

    sscanf(str, "%*[^:]: %* %* %lu %lu %lu %lu", &out->ssid_MulticastPacketsReceived, &out->ssid_MulticastPacketsSent, &out->ssid_BroadcastPacketsRecevied, \
    &out->ssid_BroadcastPacketsSent);
    pclose(fp);

    out->ssid_UnicastPacketsSent = out->ssid_PacketsSent - out->ssid_MulticastPacketsSent - out->ssid_BroadcastPacketsSent - out->ssid_DiscardedPacketsSent;
    out->ssid_UnicastPacketsReceived = out->ssid_PacketsReceived - out->ssid_MulticastPacketsReceived - out->ssid_BroadcastPacketsRecevied - out->ssid_DiscardedPacketsReceived;

    // Not supported
    output_struct->ssid_RetransCount = 0;
    output_struct->ssid_FailedRetransCount = 0;
    output_struct->ssid_RetryCount = 0;
    output_struct->ssid_MultipleRetryCount = 0;
    output_struct->ssid_ACKFailureCount = 0;
    output_struct->ssid_AggregatedPacketCount = 0;

    return RETURN_OK;
}

//Enables or disables device isolation. A value of true means that the devices connected to the Access Point are isolated from all other devices within the home network (as is typically the case for a Wireless Hotspot).
INT wifi_getApIsolationEnable(INT apIndex, BOOL *output)
{
    char output_val[16]={'\0'};
    char config_file[MAX_BUF_SIZE] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (!output)
        return RETURN_ERR;
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    if (!syn_flag)
        wifi_hostapdRead(config_file, "ap_isolate", output_val, sizeof(output_val));
    else
        snprintf(output_val, sizeof(output_val), "%s", vap_info[apIndex].ap_isolate);
    if( strcmp(output_val,"1") == 0 )
        *output = TRUE;
    else
        *output = FALSE;
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT wifi_setApIsolationEnable(INT apIndex, BOOL enable)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    char str[MAX_BUF_SIZE]={'\0'};
    char string[MAX_BUF_SIZE]={'\0'};
    char cmd[MAX_CMD_SIZE]={'\0'};
    char *ch;
    char config_file[MAX_BUF_SIZE] = {0};
    struct params params;

    if(enable == TRUE)
        strcpy(string,"1");
    else
        strcpy(string,"0");

    params.name = "ap_isolate";
    params.value = string;

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdWrite(config_file,&params,1);
    snprintf(vap_info[apIndex].ap_isolate, sizeof(vap_info[apIndex].ap_isolate), "%s", params.value);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT wifi_getApManagementFramePowerControl(INT apIndex, INT *output_dBm)
{
    if (NULL == output_dBm)
        return RETURN_ERR;

    *output_dBm = 0;
    return RETURN_OK;
}

INT wifi_setApManagementFramePowerControl(INT wlanIndex, INT dBm)
{
   return RETURN_OK;
}
INT wifi_getRadioDcsChannelMetrics(INT radioIndex,wifi_channelMetrics_t *input_output_channelMetrics_array,INT size)
{
   return RETURN_OK;
}
INT wifi_setRadioDcsDwelltime(INT radioIndex, INT ms)
{
    return RETURN_OK;
}
INT wifi_getRadioDcsDwelltime(INT radioIndex, INT *ms)
{
    return RETURN_OK;
}
INT wifi_setRadioDcsScanning(INT radioIndex, BOOL enable)
{
    return RETURN_OK;
}
INT wifi_setBSSTransitionActivation(UINT apIndex, BOOL activate)
{
    char config_file[MAX_BUF_SIZE] = {0};
    struct params list;

    list.name = "bss_transition";
    list.value = activate?"1":"0";
    snprintf(config_file, sizeof(config_file), "%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdWrite(config_file, &list, 1);
    snprintf(vap_info[apIndex].bss_transition, MAX_BUF_SIZE, "%s", list.value);

    return RETURN_OK;
}
wifi_apAuthEvent_callback apAuthEvent_cb = NULL;

void wifi_apAuthEvent_callback_register(wifi_apAuthEvent_callback callback_proc)
{
    return;
}

INT wifi_setApCsaDeauth(INT apIndex, INT mode)
{
    // TODO Implement me!
    return RETURN_OK;
}

INT wifi_setApScanFilter(INT apIndex, INT mode, CHAR *essid)
{
    char file_name[128] = {0};
    FILE *f = NULL;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

    if (essid == NULL)
        return RETURN_ERR;

    if (strlen(essid) == 0 || apIndex == -1) {
        // When essid is blank (apIndex==-1), the configured SSID on that interface is used.
        wifi_getSSIDName(apIndex, essid);
    }

    snprintf(file_name, sizeof(file_name), "%s%d.txt", ESSID_FILE, apIndex);
    f = fopen(file_name, "w");
    if (f == NULL)
        return RETURN_ERR;

    // For mode == 0 is to disable filter, just don't write ssid to the file.
    fprintf(f, "%d\n%s", mode, mode?essid:"");
    fclose(f);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
    return RETURN_OK;
}

INT wifi_pushRadioChannel(INT radioIndex, UINT channel)
{
    // TODO Implement me!
    //Apply wifi_pushRadioChannel() instantly
    return RETURN_ERR;
}

INT wifi_setRadioStatsEnable(INT radioIndex, BOOL enable)
{
    // TODO Implement me!
    return RETURN_OK;
}

#ifdef HAL_NETLINK_IMPL
static int tidStats_callback(struct nl_msg *msg, void *arg) {
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
    struct nlattr *stats_info[NL80211_TID_STATS_MAX + 1],*tidattr;
    int rem , tid_index = 0;

    wifi_associated_dev_tid_stats_t *out = (wifi_associated_dev_tid_stats_t*)arg;
    wifi_associated_dev_tid_entry_t *stats_entry;

    static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
                 [NL80211_STA_INFO_TID_STATS] = { .type = NLA_NESTED },
    };
    static struct nla_policy tid_policy[NL80211_TID_STATS_MAX + 1] = {
                 [NL80211_TID_STATS_TX_MSDU] = { .type = NLA_U64 },
    };

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                  genlmsg_attrlen(gnlh, 0), NULL);


    if (!tb[NL80211_ATTR_STA_INFO]) {
        fprintf(stderr, "station stats missing!\n");
        return NL_SKIP;
    }

    if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,
                             tb[NL80211_ATTR_STA_INFO],
                             stats_policy)) {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return NL_SKIP;
    }

    nla_for_each_nested(tidattr, sinfo[NL80211_STA_INFO_TID_STATS], rem)
    {
        stats_entry = &out->tid_array[tid_index];

        stats_entry->tid = tid_index;
        stats_entry->ac = _tid_ac_index_get[tid_index];

        if(sinfo[NL80211_STA_INFO_TID_STATS])
        {
            if(nla_parse_nested(stats_info, NL80211_TID_STATS_MAX,tidattr, tid_policy)) {
                printf("failed to parse nested stats attributes!");
                return NL_SKIP;
            }
        }
        if(stats_info[NL80211_TID_STATS_TX_MSDU])
            stats_entry->num_msdus = (unsigned long long)nla_get_u64(stats_info[NL80211_TID_STATS_TX_MSDU]);

        if(tid_index < (PS_MAX_TID - 1))
            tid_index++;
    }
    //ToDo: sum_time_ms, ewma_time_ms
    return NL_SKIP;
}
#endif

INT wifi_getApAssociatedDeviceTidStatsResult(INT radioIndex,  mac_address_t *clientMacAddress, wifi_associated_dev_tid_stats_t *tid_stats,  ULLONG *handle)
{
#ifdef HAL_NETLINK_IMPL
    Netlink nl;
    char  if_name[10];
    char interface_name[16] = {0};

    if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;

    snprintf(if_name, sizeof(if_name), "%s", interface_name);

    nl.id = initSock80211(&nl);

    if (nl.id < 0) {
        fprintf(stderr, "Error initializing netlink \n");
        return -1;
    }

    struct nl_msg* msg = nlmsg_alloc();

    if (!msg) {
        fprintf(stderr, "Failed to allocate netlink message.\n");
        nlfree(&nl);
        return -2;
    }

    genlmsg_put(msg,
              NL_AUTO_PORT,
              NL_AUTO_SEQ,
              nl.id,
              0,
              0,
              NL80211_CMD_GET_STATION,
              0);

    nla_put(msg, NL80211_ATTR_MAC, MAC_ALEN, clientMacAddress);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(if_name));
    nl_cb_set(nl.cb,NL_CB_VALID,NL_CB_CUSTOM,tidStats_callback,tid_stats);
    nl_send_auto(nl.socket, msg);
    nl_recvmsgs(nl.socket, nl.cb);
    nlmsg_free(msg);
    nlfree(&nl);
    return RETURN_OK;
#else
//iw implementation
#define TID_STATS_FILE "/tmp/tid_stats_file.txt"
#define TOTAL_MAX_LINES 50

    char buf[256] = {'\0'}; /* or other suitable maximum line size */
    char if_name[32] = {0};
    FILE *fp=NULL;
    char pipeCmd[1024]= {'\0'};
    int lines,tid_index=0;
    char mac_addr[20] = {'\0'};

    if (wifi_GetInterfaceName(radioIndex, if_name) != RETURN_OK)
        return RETURN_ERR;

    wifi_associated_dev_tid_entry_t *stats_entry;

    /* Convert binary MAC to string safely; mac_addr is 20 bytes, xx:xx:xx:xx:xx:xx = 17+NUL */
    mac_addr_ntoa(mac_addr, (unsigned char *)clientMacAddress);

    snprintf(pipeCmd,sizeof(pipeCmd),"iw dev %s station dump -v > "TID_STATS_FILE,if_name);
    fp= popen(pipeCmd,"r");
    if(fp == NULL)
    {
        perror("popen for station dump failed\n");
        return RETURN_ERR;
    }
    pclose(fp);

    snprintf(pipeCmd,sizeof(pipeCmd),"grep -n 'Station' "TID_STATS_FILE " | cut -d ':' -f1  | head -2 | tail -1");
    fp=popen(pipeCmd,"r");
    if(fp == NULL)
    {
        perror("popen for grep station failed\n");
        return RETURN_ERR;
    }
    else if(fgets(buf,sizeof(buf),fp) != NULL)
        lines=atoi(buf);
    else
    {
	pclose(fp);
        fprintf(stderr,"No devices are connected \n");
        return RETURN_ERR;
    }
    pclose(fp);

    if(lines == 1)
        lines = TOTAL_MAX_LINES; //only one client is connected , considering next MAX lines of iw output

    for(tid_index=0; tid_index<PS_MAX_TID; tid_index++)
    {
        stats_entry = &tid_stats->tid_array[tid_index];
        stats_entry->tid = tid_index;

        /* Use grep -F for fixed-string match to prevent awk regex injection */
        snprintf(pipeCmd, sizeof(pipeCmd),
            "grep -F -A%d '%s' "TID_STATS_FILE" | grep -F -A%d 'MSDU' | awk '{print $3}' | tail -1",
            lines, mac_addr, tid_index + 2);

        fp=popen(pipeCmd,"r");
        if(fp ==NULL)
        {
            perror("Failed to read from tid file \n");
            return RETURN_ERR;
        }
        else if(fgets(buf,sizeof(buf),fp) != NULL)
            stats_entry->num_msdus = atol(buf);

        pclose(fp);
        stats_entry->ac = _tid_ac_index_get[tid_index];
//      TODO:
//      ULLONG ewma_time_ms;    <! Moving average value based on last couple of transmitted msdus
//      ULLONG sum_time_ms; <! Delta of cumulative msdus times over interval
    }
    return RETURN_OK;
#endif
}


INT wifi_startNeighborScan(INT apIndex, wifi_neighborScanMode_t scan_mode, INT dwell_time, UINT chan_num, UINT *chan_list)
{
    char interface_name[16] = {0};
    char cmd[128]={0};
    char buf[128]={0};
    int freq = 0;
    wifi_band band = band_invalid;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    band = wifi_index_to_band(apIndex);
    // full mode is used to scan all channels.
    // multiple channels is ambiguous, iw can not set multiple frequencies in one time.
    if (scan_mode != WIFI_RADIO_SCAN_MODE_FULL)
        freq = ieee80211_channel_to_frequency(chan_list[0], band);

    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;

    if (freq)
        snprintf(cmd, sizeof(cmd), "iw dev %s scan trigger duration %d freq %d", interface_name, dwell_time, freq);
    else
        snprintf(cmd, sizeof(cmd), "iw dev %s scan trigger duration %d", interface_name, dwell_time);

    _syscmd(cmd, buf, sizeof(buf));
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}


INT wifi_steering_setGroup(UINT steeringgroupIndex, wifi_steering_apConfig_t *cfg_2, wifi_steering_apConfig_t *cfg_5)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_steering_clientSet(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac, wifi_steering_clientConfig_t *config)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_steering_clientRemove(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_steering_clientMeasure(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_steering_clientDisconnect(UINT steeringgroupIndex, INT apIndex, mac_address_t client_mac, wifi_disconnectType_t type, UINT reason)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_steering_eventRegister(wifi_steering_eventCB_t event_cb)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_steering_eventUnregister(void)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_delApAclDevices(INT apIndex)
{
#if 0
    char cmd[MAX_BUF_SIZE] = {0};
    char buf[MAX_BUF_SIZE] = {0};

   /* Not reset proof solution  */
   snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s accept_acl CLEAR", interface_name);
    if(_syscmd(cmd,buf,sizeof(buf)))
        return RETURN_ERR;
#endif
    char cmd[256]={0};
    char buf[64]={0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    sprintf(cmd, "rm %s%d %s%d 2>&1 && touch %s%d %s%d", ACL_PREFIX, apIndex, DENY_PREFIX, apIndex, ACL_PREFIX, apIndex, DENY_PREFIX, apIndex);
    if(_syscmd(cmd, buf, sizeof(buf)))
        return RETURN_ERR;
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

#ifdef HAL_NETLINK_IMPL
static int rxStatsInfo_callback(struct nl_msg *msg, void *arg) {
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
    struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
    struct nlattr *stats_info[NL80211_TID_STATS_MAX + 1];
    char mac_addr[20],dev[20];

    nla_parse(tb,
        NL80211_ATTR_MAX,
        genlmsg_attrdata(gnlh, 0),
        genlmsg_attrlen(gnlh, 0),
        NULL);

    if(!tb[NL80211_ATTR_STA_INFO]) {
        fprintf(stderr, "sta stats missing!\n");
        return NL_SKIP;
    }

    if(nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,tb[NL80211_ATTR_STA_INFO], stats_policy)) {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return NL_SKIP;
    }
    mac_addr_ntoa(mac_addr, nla_data(tb[NL80211_ATTR_MAC]));

    if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);

    if(nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_RX_BITRATE], rate_policy )) {
        fprintf(stderr, "failed to parse nested rate attributes!");
        return NL_SKIP;
    }

   if(sinfo[NL80211_STA_INFO_TID_STATS])
   {
       if(nla_parse_nested(stats_info, NL80211_TID_STATS_MAX,sinfo[NL80211_STA_INFO_TID_STATS], tid_policy)) {
           printf("failed to parse nested stats attributes!");
           return NL_SKIP;
       }
   }

   if( nla_data(tb[NL80211_ATTR_VHT_CAPABILITY]) )
   {
       printf("Type is VHT\n");
       if(rinfo[NL80211_RATE_INFO_VHT_NSS])
           ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->nss = nla_get_u8(rinfo[NL80211_RATE_INFO_VHT_NSS]);

       if(rinfo[NL80211_RATE_INFO_40_MHZ_WIDTH])
            ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 1;
       if(rinfo[NL80211_RATE_INFO_80_MHZ_WIDTH])
            ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 2;
       if(rinfo[NL80211_RATE_INFO_80P80_MHZ_WIDTH])
             ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 2;
       if(rinfo[NL80211_RATE_INFO_160_MHZ_WIDTH])
             ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 2;
       if((rinfo[NL80211_RATE_INFO_10_MHZ_WIDTH]) || (rinfo[NL80211_RATE_INFO_5_MHZ_WIDTH]) )
                         ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 0;
  }
  else
  {
      printf(" OFDM or CCK \n");
      ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bw = 0;
      ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->nss = 0;
  }

  if(sinfo[NL80211_STA_INFO_RX_BITRATE]) {
      if(rinfo[NL80211_RATE_INFO_MCS])
          ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->mcs = nla_get_u8(rinfo[NL80211_RATE_INFO_MCS]);
      }
      if(sinfo[NL80211_STA_INFO_RX_BYTES64])
          ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bytes = nla_get_u64(sinfo[NL80211_STA_INFO_RX_BYTES64]);
      else if (sinfo[NL80211_STA_INFO_RX_BYTES])
          ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->bytes = nla_get_u32(sinfo[NL80211_STA_INFO_RX_BYTES]);

      if(stats_info[NL80211_TID_STATS_RX_MSDU])
          ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->msdus = nla_get_u64(stats_info[NL80211_TID_STATS_RX_MSDU]);

      if (sinfo[NL80211_STA_INFO_SIGNAL])
           ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->rssi_combined = nla_get_u8(sinfo[NL80211_STA_INFO_SIGNAL]);
      //Assigning 0 for RETRIES ,PPDUS and MPDUS as we dont have rx retries attribute in libnl_3.3.0
           ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->retries = 0;
           ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->ppdus = 0;
           ((wifi_associated_dev_rate_info_rx_stats_t*)arg)->msdus = 0;
      //rssi_array need to be filled
      return NL_SKIP;
}
#endif

INT wifi_getApAssociatedDeviceRxStatsResult(INT radioIndex, mac_address_t *clientMacAddress, wifi_associated_dev_rate_info_rx_stats_t **stats_array, UINT *output_array_size, ULLONG *handle)
{
#ifdef HAL_NETLINK_IMPL
    Netlink nl;
    char if_name[32];
    if (wifi_GetInterfaceName(radioIndex, if_name) != RETURN_OK)
        return RETURN_ERR;

    *output_array_size = sizeof(wifi_associated_dev_rate_info_rx_stats_t);

    if (*output_array_size <= 0)
        return RETURN_OK;

    nl.id = initSock80211(&nl);

    if (nl.id < 0) {
    fprintf(stderr, "Error initializing netlink \n");
    return 0;
    }

    struct nl_msg* msg = nlmsg_alloc();

    if (!msg) {
        fprintf(stderr, "Failed to allocate netlink message.\n");
        nlfree(&nl);
        return 0;
    }

    genlmsg_put(msg,
        NL_AUTO_PORT,
        NL_AUTO_SEQ,
        nl.id,
        0,
        0,
        NL80211_CMD_GET_STATION,
        0);

    nla_put(msg, NL80211_ATTR_MAC, MAC_ALEN, *clientMacAddress);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(if_name));
    nl_cb_set(nl.cb, NL_CB_VALID , NL_CB_CUSTOM, rxStatsInfo_callback, stats_array);
    nl_send_auto(nl.socket, msg);
    nl_recvmsgs(nl.socket, nl.cb);
    nlmsg_free(msg);
    nlfree(&nl);
    return RETURN_OK;
#else
    //TODO Implement me
    return RETURN_OK;
#endif
}

#ifdef HAL_NETLINK_IMPL
static int txStatsInfo_callback(struct nl_msg *msg, void *arg) {
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
    struct nlattr *rinfo[NL80211_RATE_INFO_MAX + 1];
    struct nlattr *stats_info[NL80211_TID_STATS_MAX + 1];
    char mac_addr[20],dev[20];

    nla_parse(tb,
              NL80211_ATTR_MAX,
              genlmsg_attrdata(gnlh, 0),
              genlmsg_attrlen(gnlh, 0),
              NULL);

    if(!tb[NL80211_ATTR_STA_INFO]) {
        fprintf(stderr, "sta stats missing!\n");
        return NL_SKIP;
    }

    if(nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,tb[NL80211_ATTR_STA_INFO], stats_policy)) {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return NL_SKIP;
    }

    mac_addr_ntoa(mac_addr, nla_data(tb[NL80211_ATTR_MAC]));

    if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);

    if(nla_parse_nested(rinfo, NL80211_RATE_INFO_MAX, sinfo[NL80211_STA_INFO_TX_BITRATE], rate_policy)) {
        fprintf(stderr, "failed to parse nested rate attributes!");
        return NL_SKIP;
    }

    if(sinfo[NL80211_STA_INFO_TID_STATS])
    {
        if(nla_parse_nested(stats_info, NL80211_TID_STATS_MAX,sinfo[NL80211_STA_INFO_TID_STATS], tid_policy)) {
            printf("failed to parse nested stats attributes!");
            return NL_SKIP;
        }
    }
    if(nla_data(tb[NL80211_ATTR_VHT_CAPABILITY]))
    {
        printf("Type is VHT\n");
        if(rinfo[NL80211_RATE_INFO_VHT_NSS])
            ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->nss = nla_get_u8(rinfo[NL80211_RATE_INFO_VHT_NSS]);

        if(rinfo[NL80211_RATE_INFO_40_MHZ_WIDTH])
            ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 1;
        if(rinfo[NL80211_RATE_INFO_80_MHZ_WIDTH])
            ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 2;
        if(rinfo[NL80211_RATE_INFO_80P80_MHZ_WIDTH])
            ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 2;
        if(rinfo[NL80211_RATE_INFO_160_MHZ_WIDTH])
            ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 2;
        if((rinfo[NL80211_RATE_INFO_10_MHZ_WIDTH]) || (rinfo[NL80211_RATE_INFO_5_MHZ_WIDTH]))
            ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 0;
    }
    else
    {
        printf(" OFDM or CCK \n");
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bw = 0;
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->nss = 0;
    }

    if(sinfo[NL80211_STA_INFO_TX_BITRATE]) {
       if(rinfo[NL80211_RATE_INFO_MCS])
           ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->mcs = nla_get_u8(rinfo[NL80211_RATE_INFO_MCS]);
    }

    if(sinfo[NL80211_STA_INFO_TX_BYTES64])
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bytes = nla_get_u64(sinfo[NL80211_STA_INFO_TX_BYTES64]);
    else if (sinfo[NL80211_STA_INFO_TX_BYTES])
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->bytes = nla_get_u32(sinfo[NL80211_STA_INFO_TX_BYTES]);

    //Assigning  0 for mpdus and ppdus , as we do not have attributes in netlink
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->mpdus = 0;
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->mpdus = 0;

    if(stats_info[NL80211_TID_STATS_TX_MSDU])
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->msdus = nla_get_u64(stats_info[NL80211_TID_STATS_TX_MSDU]);

    if(sinfo[NL80211_STA_INFO_TX_RETRIES])
        ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->retries = nla_get_u32(sinfo[NL80211_STA_INFO_TX_RETRIES]);

    if(sinfo[NL80211_STA_INFO_TX_FAILED])
                 ((wifi_associated_dev_rate_info_tx_stats_t*)arg)->attempts = nla_get_u32(sinfo[NL80211_STA_INFO_TX_PACKETS]) + nla_get_u32(sinfo[NL80211_STA_INFO_TX_FAILED]);

    return NL_SKIP;
}
#endif

INT wifi_getApAssociatedDeviceTxStatsResult(INT radioIndex, mac_address_t *clientMacAddress, wifi_associated_dev_rate_info_tx_stats_t **stats_array, UINT *output_array_size, ULLONG *handle)
{
#ifdef HAL_NETLINK_IMPL
    Netlink nl;
    char if_name[10];
    char interface_name[16] = {0};
    if (wifi_GetInterfaceName(radioIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;

    *output_array_size = sizeof(wifi_associated_dev_rate_info_tx_stats_t);

    if (*output_array_size <= 0)
        return RETURN_OK;

    snprintf(if_name, sizeof(if_name), "%s", interface_name);

    nl.id = initSock80211(&nl);

    if(nl.id < 0) {
        fprintf(stderr, "Error initializing netlink \n");
        return 0;
    }

    struct nl_msg* msg = nlmsg_alloc();

    if(!msg) {
        fprintf(stderr, "Failed to allocate netlink message.\n");
        nlfree(&nl);
        return 0;
    }

    genlmsg_put(msg,
                NL_AUTO_PORT,
                NL_AUTO_SEQ,
                nl.id,
                0,
                0,
                NL80211_CMD_GET_STATION,
                0);

    nla_put(msg, NL80211_ATTR_MAC, MAC_ALEN, clientMacAddress);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(if_name));
    nl_cb_set(nl.cb, NL_CB_VALID , NL_CB_CUSTOM, txStatsInfo_callback, stats_array);
    nl_send_auto(nl.socket, msg);
    nl_recvmsgs(nl.socket, nl.cb);
    nlmsg_free(msg);
    nlfree(&nl);
    return RETURN_OK;
#else
    //TODO Implement me
    return RETURN_OK;
#endif
}

INT wifi_getBSSTransitionActivation(UINT apIndex, BOOL *activate)
{
    // TODO Implement me!
    char buf[MAX_BUF_SIZE] = {0};
    char config_file[MAX_BUF_SIZE] = {0};

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
    if (!syn_flag)
        wifi_hostapdRead(config_file, "bss_transition", buf, sizeof(buf));
    else
        snprintf(buf, sizeof(buf), "%s", vap_info[apIndex].bss_transition);
    *activate = (strncmp("1",buf,1) == 0);

    return RETURN_OK;
}

INT wifi_setNeighborReportActivation(UINT apIndex, BOOL activate)
{
    char config_file[MAX_BUF_SIZE] = {0};
    struct params list;

    list.name = "rrm_neighbor_report";
    list.value = activate?"1":"0";
    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdWrite(config_file, &list, 1);

    return RETURN_OK;
}

INT wifi_getNeighborReportActivation(UINT apIndex, BOOL *activate)
{
    char buf[32] = {0};
    char config_file[MAX_BUF_SIZE] = {0};

    sprintf(config_file,"%s%d.conf",CONFIG_PREFIX,apIndex);
    wifi_hostapdRead(config_file, "rrm_neighbor_report", buf, sizeof(buf));
    *activate = (strncmp("1",buf,1) == 0);

    return RETURN_OK;
}
#undef HAL_NETLINK_IMPL
#ifdef HAL_NETLINK_IMPL
static int chanSurveyInfo_callback(struct nl_msg *msg, void *arg) {
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *sinfo[NL80211_SURVEY_INFO_MAX + 1];
    char dev[20];
    int freq =0 ;
    static int i=0;

    wifi_channelStats_t_loc *out = (wifi_channelStats_t_loc*)arg;

    static struct nla_policy survey_policy[NL80211_SURVEY_INFO_MAX + 1] = {
    };

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),genlmsg_attrlen(gnlh, 0), NULL);

    if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);

    if (!tb[NL80211_ATTR_SURVEY_INFO]) {
        fprintf(stderr, "survey data missing!\n");
        return NL_SKIP;
    }

    if (nla_parse_nested(sinfo, NL80211_SURVEY_INFO_MAX,tb[NL80211_ATTR_SURVEY_INFO],survey_policy))
    {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return NL_SKIP;
    }


    if(out[0].array_size == 1 )
    {
        if(sinfo[NL80211_SURVEY_INFO_IN_USE])
        {
            if (sinfo[NL80211_SURVEY_INFO_FREQUENCY])
                freq = nla_get_u32(sinfo[NL80211_SURVEY_INFO_FREQUENCY]);
            out[0].ch_number = ieee80211_frequency_to_channel(freq);

            if (sinfo[NL80211_SURVEY_INFO_NOISE])
                out[0].ch_noise = nla_get_u8(sinfo[NL80211_SURVEY_INFO_NOISE]);
            if (sinfo[NL80211_SURVEY_INFO_TIME_RX])
                out[0].ch_utilization_busy_rx = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_RX]);
            if (sinfo[NL80211_SURVEY_INFO_TIME_TX])
                out[0].ch_utilization_busy_tx = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_TX]);
            if (sinfo[NL80211_SURVEY_INFO_TIME_BUSY])
                out[0].ch_utilization_busy = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_BUSY]);
            if (sinfo[NL80211_SURVEY_INFO_TIME_EXT_BUSY])
                out[0].ch_utilization_busy_ext = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_EXT_BUSY]);
            if (sinfo[NL80211_SURVEY_INFO_TIME])
                out[0].ch_utilization_total = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME]);
            return NL_STOP;
        }
   }
   else
   {
       if ( i < out[0].array_size )
       {
           if (sinfo[NL80211_SURVEY_INFO_FREQUENCY])
               freq = nla_get_u32(sinfo[NL80211_SURVEY_INFO_FREQUENCY]);
           out[i].ch_number = ieee80211_frequency_to_channel(freq);

           if (sinfo[NL80211_SURVEY_INFO_NOISE])
               out[i].ch_noise = nla_get_u8(sinfo[NL80211_SURVEY_INFO_NOISE]);
           if (sinfo[NL80211_SURVEY_INFO_TIME_RX])
               out[i].ch_utilization_busy_rx = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_RX]);
           if (sinfo[NL80211_SURVEY_INFO_TIME_TX])
               out[i].ch_utilization_busy_tx = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_TX]);
           if (sinfo[NL80211_SURVEY_INFO_TIME_BUSY])
               out[i].ch_utilization_busy = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_BUSY]);
           if (sinfo[NL80211_SURVEY_INFO_TIME_EXT_BUSY])
               out[i].ch_utilization_busy_ext = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME_EXT_BUSY]);
           if (sinfo[NL80211_SURVEY_INFO_TIME])
               out[i].ch_utilization_total = nla_get_u64(sinfo[NL80211_SURVEY_INFO_TIME]);
      }
   }

   i++;
   return NL_SKIP;
}
#endif

static int ieee80211_channel_to_frequency(int chan, wifi_band band)
{
	/* see 802.11 17.3.8.3.2 and Annex J
	 * there are overlapping channel numbers in 5GHz and 2GHz bands */
    if (chan <= 0)
        return -1; /* not supported */
    switch (band) {
        case band_2_4:
            if (chan == 14)
                return 2484;
            else if (chan < 14)
                return (2407 + chan * 5);
            break;
        case band_5:
            if (chan >= 182 && chan <= 196)
                return (4000 + chan * 5);
            else
                return (5000 + chan * 5);
            break;
        case band_6:
            /* see 802.11ax D6.1 27.3.23.2 */
            if (chan == 2)
                return 5935;
            if (chan <= 233)
                return (5950 + chan * 5);
            break;
        default:
            return -1;
            break;
    }
}

static int get_survey_dump_buf(INT radioIndex, int channel, char *buf, size_t bufsz)
{
    int freqMHz = -1;
    char cmd[MAX_CMD_SIZE] = {'\0'};
    char interface_name[16] = {0};
    wifi_band band = band_invalid;

    band = wifi_index_to_band(radioIndex);
    freqMHz = ieee80211_channel_to_frequency(channel, band);
    if (freqMHz == -1) {
        wifi_dbg_printf("%s: failed to get channel frequency for channel: %d\n", __func__, channel);
        return -1;
    }

    wifi_GetInterfaceName(radioIndex, interface_name);
    if (sprintf(cmd,"iw dev %s survey dump | grep -A5 %d | tr -d '\\t'", interface_name, freqMHz) < 0) {
        wifi_dbg_printf("%s: failed to build iw dev command for radioIndex=%d freq=%d\n", __FUNCTION__,
                         radioIndex, freqMHz);
        return -1;
    }

    if (_syscmd(cmd, buf, bufsz) == RETURN_ERR) {
        wifi_dbg_printf("%s: failed to execute '%s' for radioIndex=%d\n", __FUNCTION__, cmd, radioIndex);
        return -1;
    }

    return 0;
}

static int fetch_survey_from_buf(INT radioIndex, const char *buf, wifi_channelStats_t *stats)
{
    const char *ptr = buf;
    char *key = NULL;
    char *val = NULL;
    char line[256] = { '\0' };

    while (ptr = get_line_from_str_buf(ptr, line)) {
        if (strstr(line, "Frequency")) continue;

        key = strtok(line, ":");
        val = strtok(NULL, " ");
        if (key == NULL || val == NULL)
            continue;
        wifi_dbg_printf("%s: key='%s' val='%s'\n", __func__, key, val);

        if (!strcmp(key, "noise")) {
            sscanf(val, "%d", &stats->ch_noise);
            if (stats->ch_noise == 0) {
                // Workaround for missing noise information.
                // Assume -95 for 2.4G and -103 for 5G
                if (radioIndex == 0) stats->ch_noise = -95;
                if (radioIndex == 1) stats->ch_noise = -103;
            }
        }
        else if (!strcmp(key, "channel active time")) {
            sscanf(val, "%llu", &stats->ch_utilization_total);
        }
        else if (!strcmp(key, "channel busy time")) {
            sscanf(val, "%llu", &stats->ch_utilization_busy);
        }
        else if (!strcmp(key, "channel receive time")) {
            sscanf(val, "%llu", &stats->ch_utilization_busy_rx);
        }
        else if (!strcmp(key, "channel transmit time")) {
            sscanf(val, "%llu", &stats->ch_utilization_busy_tx);
        }
    };

    return 0;
}

INT wifi_getRadioChannelStats(INT radioIndex,wifi_channelStats_t *input_output_channelStats_array,INT array_size)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
#ifdef HAL_NETLINK_IMPL
    Netlink nl;
    wifi_channelStats_t_loc local[array_size];
    char  if_name[32];

    local[0].array_size = array_size;

    if (wifi_GetInterfaceName(radioIndex, if_name) != RETURN_OK)
        return RETURN_ERR;

    nl.id = initSock80211(&nl);

    if (nl.id < 0) {
        fprintf(stderr, "Error initializing netlink \n");
        return -1;
    }

    struct nl_msg* msg = nlmsg_alloc();

    if (!msg) {
        fprintf(stderr, "Failed to allocate netlink message.\n");
        nlfree(&nl);
        return -2;
    }

    genlmsg_put(msg,
                NL_AUTO_PORT,
                NL_AUTO_SEQ,
                nl.id,
                0,
                NLM_F_DUMP,
                NL80211_CMD_GET_SURVEY,
                0);

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_nametoindex(if_name));
    nl_send_auto(nl.socket, msg);
    nl_cb_set(nl.cb,NL_CB_VALID,NL_CB_CUSTOM,chanSurveyInfo_callback,local);
    nl_recvmsgs(nl.socket, nl.cb);
    nlmsg_free(msg);
    nlfree(&nl);
    //Copying the Values
    for(int i=0;i<array_size;i++)
    {
        input_output_channelStats_array[i].ch_number = local[i].ch_number;
        input_output_channelStats_array[i].ch_noise = local[i].ch_noise;
        input_output_channelStats_array[i].ch_utilization_busy_rx = local[i].ch_utilization_busy_rx;
        input_output_channelStats_array[i].ch_utilization_busy_tx = local[i].ch_utilization_busy_tx;
        input_output_channelStats_array[i].ch_utilization_busy = local[i].ch_utilization_busy;
        input_output_channelStats_array[i].ch_utilization_busy_ext = local[i].ch_utilization_busy_ext;
        input_output_channelStats_array[i].ch_utilization_total = local[i].ch_utilization_total;
        //TODO: ch_radar_noise, ch_max_80211_rssi, ch_non_80211_noise, ch_utilization_busy_self
    }
#else
    ULONG channel = 0;
    int i;
    int number_of_channels = array_size;
    char buf[512];
    INT ret;
    wifi_channelStats_t tmp_stats;

    if (number_of_channels == 0) {
        if (wifi_getRadioChannel(radioIndex, &channel) != RETURN_OK) {
            wifi_dbg_printf("%s: cannot get current channel for radioIndex=%d\n", __func__, radioIndex);
            return RETURN_ERR;
        }
        number_of_channels = 1;
        input_output_channelStats_array[0].ch_number = channel;
    }

    for (i = 0; i < number_of_channels; i++) {

        input_output_channelStats_array[i].ch_noise = 0;
        input_output_channelStats_array[i].ch_utilization_busy_rx = 0;
        input_output_channelStats_array[i].ch_utilization_busy_tx = 0;
        input_output_channelStats_array[i].ch_utilization_busy = 0;
        input_output_channelStats_array[i].ch_utilization_busy_ext = 0; // XXX: unavailable
        input_output_channelStats_array[i].ch_utilization_total = 0;

        memset(buf, 0, sizeof(buf));
        if (get_survey_dump_buf(radioIndex, input_output_channelStats_array[i].ch_number, buf, sizeof(buf))) {
            return RETURN_ERR;
        }
        if (fetch_survey_from_buf(radioIndex, buf, &input_output_channelStats_array[i])) {
            wifi_dbg_printf("%s: cannot fetch survey from buf for radioIndex=%d\n", __func__, radioIndex);
            return RETURN_ERR;
        }

        // XXX: fake missing 'self' counter which is not available in iw survey output
        //      the 'self' counter (a.k.a 'bss') requires Linux Kernel update
        input_output_channelStats_array[i].ch_utilization_busy_self = input_output_channelStats_array[i].ch_utilization_busy_rx / 8;

        input_output_channelStats_array[i].ch_utilization_busy_rx *= 1000;
        input_output_channelStats_array[i].ch_utilization_busy_tx *= 1000;
        input_output_channelStats_array[i].ch_utilization_busy_self *= 1000;
        input_output_channelStats_array[i].ch_utilization_busy *= 1000;
        input_output_channelStats_array[i].ch_utilization_total *= 1000;

        wifi_dbg_printf("%s: ch_number=%d ch_noise=%d total=%llu busy=%llu busy_rx=%llu busy_tx=%llu busy_self=%llu busy_ext=%llu\n",
                   __func__,
                   input_output_channelStats_array[i].ch_number,
                   input_output_channelStats_array[i].ch_noise,
                   input_output_channelStats_array[i].ch_utilization_total,
                   input_output_channelStats_array[i].ch_utilization_busy,
                   input_output_channelStats_array[i].ch_utilization_busy_rx,
                   input_output_channelStats_array[i].ch_utilization_busy_tx,
                   input_output_channelStats_array[i].ch_utilization_busy_self,
                   input_output_channelStats_array[i].ch_utilization_busy_ext);
    }
#endif
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}
#define HAL_NETLINK_IMPL

/* Hostapd events */

#ifndef container_of
#define offset_of(st, m) ((size_t)&(((st *)0)->m))
#define container_of(ptr, type, member) \
                   ((type *)((char *)ptr - offset_of(type, member)))
#endif /* container_of */

struct ctrl {
    char sockpath[128];
    char sockdir[128];
    char bss[IFNAMSIZ];
    char reply[4096];
    int ssid_index;
    void (*cb)(struct ctrl *ctrl, int level, const char *buf, size_t len);
    void (*overrun)(struct ctrl *ctrl);
    struct wpa_ctrl *wpa;
    unsigned int ovfl;
    size_t reply_len;
    int initialized;
    ev_timer retry;
    ev_timer watchdog;
    ev_stat stat;
    ev_io io;
};
static wifi_newApAssociatedDevice_callback clients_connect_cb;
static wifi_apDisassociatedDevice_callback clients_disconnect_cb;
static struct ctrl wpa_ctrl[MAX_APS];
static int initialized;

static unsigned int ctrl_get_drops(struct ctrl *ctrl)
{
    char cbuf[256] = {};
    struct msghdr msg = { .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
    struct cmsghdr *cmsg;
    unsigned int ovfl = ctrl->ovfl;
    unsigned int drop;

    recvmsg(ctrl->io.fd, &msg, MSG_DONTWAIT);
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_RXQ_OVFL)
            ovfl = *(unsigned int *)CMSG_DATA(cmsg);

    drop = ovfl - ctrl->ovfl;
    ctrl->ovfl = ovfl;

    return drop;
}

static void ctrl_close(struct ctrl *ctrl)
{
    if (ctrl->io.cb)
        ev_io_stop(EV_DEFAULT_ &ctrl->io);
    if (ctrl->retry.cb)
        ev_timer_stop(EV_DEFAULT_ &ctrl->retry);
    if (!ctrl->wpa)
        return;

    wpa_ctrl_detach(ctrl->wpa);
    wpa_ctrl_close(ctrl->wpa);
    ctrl->wpa = NULL;
    printf("WPA_CTRL: closed index=%d\n", ctrl->ssid_index);
}

static void ctrl_process(struct ctrl *ctrl)
{
    const char *str;
    int drops;
    int level;
    int err;

    /* Example events:
     *
     * <3>AP-STA-CONNECTED 60:b4:f7:f0:0a:19
     * <3>AP-STA-CONNECTED 60:b4:f7:f0:0a:19 keyid=sample_keyid
     * <3>AP-STA-DISCONNECTED 60:b4:f7:f0:0a:19
     * <3>CTRL-EVENT-CONNECTED - Connection to 00:1d:73:73:88:ea completed [id=0 id_str=]
     * <3>CTRL-EVENT-DISCONNECTED bssid=00:1d:73:73:88:ea reason=3 locally_generated=1
     */
    if (!(str = index(ctrl->reply, '>')))
        return;
    if (sscanf(ctrl->reply, "<%d>", &level) != 1)
        return;

    str++;

    if (strncmp("AP-STA-CONNECTED ", str, 17) == 0) {
        if (!(str = index(ctrl->reply, ' ')))
            return;
        wifi_associated_dev_t sta;
        memset(&sta, 0, sizeof(sta));

        sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &sta.cli_MACAddress[0], &sta.cli_MACAddress[1], &sta.cli_MACAddress[2],
                &sta.cli_MACAddress[3], &sta.cli_MACAddress[4], &sta.cli_MACAddress[5]);

        sta.cli_Active=true;

        (clients_connect_cb)(ctrl->ssid_index, &sta);
        goto handled;
    }

    if (strncmp("AP-STA-DISCONNECTED ", str, 20) == 0) {
        if (!(str = index(ctrl->reply, ' ')))
            return;

        (clients_disconnect_cb)(ctrl->ssid_index, (char*)str, 0);
        goto handled;
    }

    if (strncmp("CTRL-EVENT-TERMINATING", str, 22) == 0) {
        printf("CTRL_WPA: handle TERMINATING event\n");
        goto retry;
    }

    if (strncmp("AP-DISABLED", str, 11) == 0) {
        printf("CTRL_WPA: handle AP-DISABLED\n");
        goto retry;
    }

    printf("Event not supported!!\n");

handled:

    if ((drops = ctrl_get_drops(ctrl))) {
        printf("WPA_CTRL: dropped %d messages index=%d\n", drops, ctrl->ssid_index);
        if (ctrl->overrun)
            ctrl->overrun(ctrl);
    }

    return;

retry:
    printf("WPA_CTRL: closing\n");
    ctrl_close(ctrl);
    printf("WPA_CTRL: retrying from ctrl prcoess\n");
    ev_timer_again(EV_DEFAULT_ &ctrl->retry);
}

static void ctrl_ev_cb(EV_P_ struct ev_io *io, int events)
{
    struct ctrl *ctrl = container_of(io, struct ctrl, io);
    int err;

    memset(ctrl->reply, 0, sizeof(ctrl->reply));
    ctrl->reply_len = sizeof(ctrl->reply) - 1;
    err = wpa_ctrl_recv(ctrl->wpa, ctrl->reply, &ctrl->reply_len);
    ctrl->reply[ctrl->reply_len] = 0;
    if (err < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        ctrl_close(ctrl);
        ev_timer_again(EV_A_ &ctrl->retry);
        return;
    }

    ctrl_process(ctrl);
}

static int ctrl_open(struct ctrl *ctrl)
{
    int fd;

    if (ctrl->wpa)
        return 0;

    ctrl->wpa = wpa_ctrl_open(ctrl->sockpath);
    if (!ctrl->wpa)
        goto err;

    if (wpa_ctrl_attach(ctrl->wpa) < 0)
        goto err_close;

    fd = wpa_ctrl_get_fd(ctrl->wpa);
    if (fd < 0)
        goto err_detach;

    if (setsockopt(fd, SOL_SOCKET, SO_RXQ_OVFL, (int[]){1}, sizeof(int)) < 0)
        goto err_detach;

    ev_io_init(&ctrl->io, ctrl_ev_cb, fd, EV_READ);
    ev_io_start(EV_DEFAULT_ &ctrl->io);

    return 0;

err_detach:
    wpa_ctrl_detach(ctrl->wpa);
err_close:
    wpa_ctrl_close(ctrl->wpa);
err:
    ctrl->wpa = NULL;
    return -1;
}

static void ctrl_stat_cb(EV_P_ ev_stat *stat, int events)
{
    struct ctrl *ctrl = container_of(stat, struct ctrl, stat);

    printf("WPA_CTRL: index=%d file state changed\n", ctrl->ssid_index);
    ctrl_open(ctrl);
}

static void ctrl_retry_cb(EV_P_ ev_timer *timer, int events)
{
    struct ctrl *ctrl = container_of(timer, struct ctrl, retry);

    printf("WPA_CTRL: index=%d retrying\n", ctrl->ssid_index);
    if (ctrl_open(ctrl) == 0) {
        printf("WPA_CTRL: retry successful\n");
        ev_timer_stop(EV_DEFAULT_ &ctrl->retry);
    }
}

int ctrl_enable(struct ctrl *ctrl)
{
    if (ctrl->wpa)
        return 0;

    if (!ctrl->stat.cb) {
        ev_stat_init(&ctrl->stat, ctrl_stat_cb, ctrl->sockpath, 0.);
        ev_stat_start(EV_DEFAULT_ &ctrl->stat);
    }

    if (!ctrl->retry.cb) {
        ev_timer_init(&ctrl->retry, ctrl_retry_cb, 0., 5.);
    }

    return ctrl_open(ctrl);
}

static void
ctrl_msg_cb(char *buf, size_t len)
{
    struct ctrl *ctrl = container_of(buf, struct ctrl, reply);

    printf("WPA_CTRL: unsolicited message: index=%d len=%zu msg=%s", ctrl->ssid_index, len, buf);
    ctrl_process(ctrl);
}

static int ctrl_request(struct ctrl *ctrl, const char *cmd, size_t cmd_len, char *reply, size_t *reply_len)
{
    int err;

    if (!ctrl->wpa)
        return -1;
    if (*reply_len < 2)
        return -1;

    (*reply_len)--;
    ctrl->reply_len = sizeof(ctrl->reply);
    err = wpa_ctrl_request(ctrl->wpa, cmd, cmd_len, ctrl->reply, &ctrl->reply_len, ctrl_msg_cb);
    printf("WPA_CTRL: index=%d cmd='%s' err=%d\n", ctrl->ssid_index, cmd, err);
    if (err < 0)
        return err;

    if (ctrl->reply_len > *reply_len)
        ctrl->reply_len = *reply_len;

    *reply_len = ctrl->reply_len;
    memcpy(reply, ctrl->reply, *reply_len);
    reply[*reply_len - 1] = 0;
    printf("WPA_CTRL: index=%d reply='%s'\n", ctrl->ssid_index, reply);
    return 0;
}

static void ctrl_watchdog_cb(EV_P_ ev_timer *timer, int events)
{
    const char *pong = "PONG";
    const char *ping = "PING";
    char reply[1024];
    size_t len = sizeof(reply);
    int err;
    ULONG s, snum;
    INT ret;
    BOOL status;

    printf("WPA_CTRL: watchdog cb\n");

    ret = wifi_getSSIDNumberOfEntries(&snum);
    if (ret != RETURN_OK) {
        printf("%s: failed to get SSID count", __func__);
        return;
    }

    if (snum > MAX_APS) {
        printf("more ssid than supported! %lu\n", snum);
        return;
    }

    for (s = 0; s < snum; s++) {
        if (wifi_getApEnable(s, &status) != RETURN_OK) {
            printf("%s: failed to get AP Enable for index: %lu\n", __func__, s);
            continue;
        }
        if (status == false) continue;

        memset(reply, 0, sizeof(reply));
        len = sizeof(reply);
        printf("WPA_CTRL: pinging index=%d\n", wpa_ctrl[s].ssid_index);
        err = ctrl_request(&wpa_ctrl[s], ping, strlen(ping), reply, &len);
        if (err == 0 && len > strlen(pong) && !strncmp(reply, pong, strlen(pong)))
            continue;

        printf("WPA_CTRL: ping timeout index=%d\n", wpa_ctrl[s].ssid_index);
        ctrl_close(&wpa_ctrl[s]);
        printf("WPA_CTRL: ev_timer_again %lu\n", s);
        ev_timer_again(EV_DEFAULT_ &wpa_ctrl[s].retry);
    }
}

static int init_wpa()
{
    int ret = 0, i = 0;
    ULONG s, snum;

    ret = wifi_getSSIDNumberOfEntries(&snum);
    if (ret != RETURN_OK) {
        printf("%s: failed to get SSID count", __func__);
        return RETURN_ERR;
    }

    if (snum > MAX_APS) {
        printf("more ssid than supported! %lu\n", snum);
        return RETURN_ERR;
    }

    for (s = 0; s < snum; s++) {
        memset(&wpa_ctrl[s], 0, sizeof(struct ctrl));
        snprintf(wpa_ctrl[s].sockpath, sizeof(wpa_ctrl[s].sockpath), "%s%lu", SOCK_PREFIX, s);
        wpa_ctrl[s].ssid_index = s;
        ctrl_enable(&wpa_ctrl[s]);
    }

    ev_timer_init(&wpa_ctrl->watchdog, ctrl_watchdog_cb, 0., 30.);
    ev_timer_again(EV_DEFAULT_ &wpa_ctrl->watchdog);

    initialized = 1;
    printf("WPA_CTRL: initialized\n");

    return RETURN_OK;
}

void wifi_newApAssociatedDevice_callback_register(wifi_newApAssociatedDevice_callback callback_proc)
{
    clients_connect_cb = callback_proc;
    if (!initialized)
        init_wpa();
}

void wifi_apDisassociatedDevice_callback_register(wifi_apDisassociatedDevice_callback callback_proc)
{
    clients_disconnect_cb = callback_proc;
    if (!initialized)
        init_wpa();
}

INT wifi_setBTMRequest(UINT apIndex, CHAR *peerMac, wifi_BTMRequest_t *request)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_setRMBeaconRequest(UINT apIndex, CHAR *peer, wifi_BeaconRequest_t *in_request, UCHAR *out_DialogToken)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_getRadioChannels(INT radioIndex, wifi_channelMap_t *outputMap, INT outputMapSize)
{
    int i;
    int phyId = -1, band_remap = 0, range_remap = 0;
    char cmd[256] = {0};
    char channel_numbers_buf[256] = {0};
    char dfs_state_buf[256] = {0};
    char line[256] = {0};
    const char *ptr;
    BOOL dfs_enable = false;
    wifi_band band = band_invalid;

    band = wifi_index_to_band(radioIndex);
    switch (band) {
        case band_2_4:
            band_remap = 1;
            range_remap = 2;
            break;
        case band_5:
            band_remap = 2;
            range_remap = 4;
            break;
        case band_6:
            band_remap = 4;
            range_remap = 4;
            break;
        default:
            break;
    }

    memset(outputMap, 0, outputMapSize*sizeof(wifi_channelMap_t)); // all unused entries should be zero

    wifi_getRadioDfsEnable(radioIndex, &dfs_enable);
    phyId = radio_index_to_phy(radioIndex);

    snprintf(cmd, sizeof (cmd),
             "iw phy phy%d info | grep -e '\\*.*MHz .*dBm\\|Band ' | sed -n '/Band %d/,/Band %d/{/Band %d/n;/Band %d/b;p}' | grep -v '%sno IR\\|5340\\|5480' | awk '{print $4}' | tr -d '[]'",
             phyId, band_remap, range_remap, band_remap, range_remap, dfs_enable?"":"radar\\|");

    if (_syscmd(cmd, channel_numbers_buf, sizeof(channel_numbers_buf)) == RETURN_ERR) {
        wifi_dbg_printf("%s: failed to execute '%s'\n", __FUNCTION__, cmd);
        return RETURN_ERR;
    }

    ptr = channel_numbers_buf;
    i = 0;
    while (ptr = get_line_from_str_buf(ptr, line)) {
        if (i >= outputMapSize) {
                wifi_dbg_printf("%s: DFS map size too small\n", __FUNCTION__);
                return RETURN_ERR;
        }
        sscanf(line, "%d", &outputMap[i].ch_number);

        memset(cmd, 0, sizeof(cmd));
        // Below command should fetch string for DFS state (usable, available or unavailable)
        // Example line: "DFS state: usable (for 78930 sec)"
        if (sprintf(cmd,"iw list | grep -A 2 '\\[%d\\]' | tr -d '\\t' | grep 'DFS state' | awk '{print $3}' | tr -d '\\n'", outputMap[i].ch_number) < 0) {
            wifi_dbg_printf("%s: failed to build dfs state command\n", __FUNCTION__);
            return RETURN_ERR;
        }

        memset(dfs_state_buf, 0, sizeof(dfs_state_buf));
        if (_syscmd(cmd, dfs_state_buf, sizeof(dfs_state_buf)) == RETURN_ERR) {
            wifi_dbg_printf("%s: failed to execute '%s'\n", __FUNCTION__, cmd);
            return RETURN_ERR;
        }

        wifi_dbg_printf("DFS state = '%s'\n", dfs_state_buf);

        if (!strcmp(dfs_state_buf, "usable")) {
            outputMap[i].ch_state = CHAN_STATE_DFS_NOP_FINISHED;
        } else if (!strcmp(dfs_state_buf, "available")) {
            outputMap[i].ch_state = CHAN_STATE_DFS_CAC_COMPLETED;
        } else if (!strcmp(dfs_state_buf, "unavailable")) {
            outputMap[i].ch_state = CHAN_STATE_DFS_NOP_START;
        } else {
            outputMap[i].ch_state = CHAN_STATE_AVAILABLE;
        }
        i++;
    }

    return RETURN_OK;

    wifi_dbg_printf("%s: wrong radio index (%d)\n", __FUNCTION__, radioIndex);
    return RETURN_ERR;
}

INT wifi_chan_eventRegister(wifi_chan_eventCB_t eventCb)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_getRadioBandUtilization (INT radioIndex, INT *output_percentage)
{
    return RETURN_OK;
}

INT wifi_getApAssociatedClientDiagnosticResult(INT apIndex, char *mac_addr, wifi_associated_dev3_t *dev_conn)
{
    // TODO Implement me!
    return RETURN_ERR;
}

INT wifi_switchBand(char *interface_name,INT radioIndex,char *freqBand)
{
    // TODO API refrence Implementaion is present on RPI hal
    return RETURN_ERR;
}


INT wifi_getRadioPercentageTransmitPower(INT apIndex, ULONG *txpwr_pcntg)
{
    char cmd[128]={'\0'};
    char buf[128]={'\0'};
    int radioIndex = -1;
    int phyIndex = -1;
    bool enabled = false;
    int cur_tx_dbm = 0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if(txpwr_pcntg == NULL)
        return RETURN_ERR;

    // The API name as getRadioXXX, I think the input index should be radioIndex,
    // but current we not change the name, but use it as radioIndex
    radioIndex = apIndex;
    phyIndex = radio_index_to_phy(radioIndex);

    // Get the maximum tx power of the device
    if (single_wiphy)
        snprintf(cmd, sizeof(cmd), "cat /sys/kernel/debug/ieee80211/phy0/mt76/band%d/txpower_info | "
                                   "grep 'Percentage Control:' | awk '{print $3}' | tr -d '\\n'", radioIndex);
    else
        snprintf(cmd, sizeof(cmd), "cat /sys/kernel/debug/ieee80211/phy%d/mt76/txpower_info | "
                                   "grep 'Percentage Control:' | awk '{print $3}' | tr -d '\\n'", phyIndex);
    _syscmd(cmd, buf, sizeof(buf));
    if (strcmp(buf, "enable") == 0)
        enabled = true;

    if (!enabled) {
        *txpwr_pcntg = 100;
        return RETURN_OK;
    }

    memset(cmd, 0, sizeof(cmd));
    memset(buf, 0, sizeof(buf));
    if (single_wiphy)
        snprintf(cmd, sizeof(cmd), "cat /sys/kernel/debug/ieee80211/phy0/mt76/band%d/txpower_info | "
                                   "grep 'Power Drop:' | awk '{print $3}' | tr -d '\\n'", radioIndex);
    else
        snprintf(cmd, sizeof(cmd), "cat /sys/kernel/debug/ieee80211/phy%d/mt76/txpower_info | "
                                   "grep 'Power Drop:' | awk '{print $3}' | tr -d '\\n'", phyIndex);
    _syscmd(cmd, buf, sizeof(buf));
    cur_tx_dbm = strtol(buf, NULL, 10);

    switch (cur_tx_dbm) {
        case 0:
            *txpwr_pcntg = 100; // range 91-100
            break;
        case 1:
            *txpwr_pcntg = 75;  // range 61-90
            break;
        case 3:
            *txpwr_pcntg = 50;  // range 31-60
            break;
        case 6:
            *txpwr_pcntg = 25;  // range 16-30
            break;
        case 9:
            *txpwr_pcntg = 12; // range 10-15
            break;
        case 12:
            *txpwr_pcntg = 6;  // range 1-9
            break;
        default:
            *txpwr_pcntg = 100; // 0
    }

    return RETURN_OK;
}

INT wifi_setZeroDFSState(UINT radioIndex, BOOL enable, BOOL precac)
{
    // TODO precac feature.
    struct params params = {0};
    char config_file[128] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    params.name = "enable_background_radar";
    params.value = enable?"1":"0";
    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radioIndex);
    wifi_hostapdWrite(config_file, &params, 1);
    wifi_hostapdProcessUpdate(radioIndex, &params, 1);

    /* TODO precac feature */

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_getZeroDFSState(UINT radioIndex, BOOL *enable, BOOL *precac)
{
    char config_file[128] = {0};
    char buf[64] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (NULL == enable || NULL == precac)
        return RETURN_ERR;

    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radioIndex);
    wifi_hostapdRead(config_file, "enable_background_radar", buf, sizeof(buf));
    if (strncmp(buf, "1", 1) == 0) {
        *enable = true;
        *precac = true;
    } else {
        *enable = false;
        *precac = false;
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_isZeroDFSSupported(UINT radioIndex, BOOL *supported)
{
    *supported = TRUE;
    return RETURN_OK;
}

bool check_is_hemu_vendor_new_patch() {
    char cmd[128] = {0};
    char buf[128] = {0};

    snprintf(cmd, sizeof(cmd), "hostapd_cli -h 2>&1 | grep set_hemu");
    _syscmd(cmd, buf, sizeof(buf));

    if (strlen(buf) > 0)
        return FALSE;
    else
        return TRUE;
}

INT wifi_setDownlinkMuType(INT radio_index, wifi_dl_mu_type_t mu_type)
{
    // hemu onoff=<val> (bitmap- UL MU-MIMO(bit3), DL MU-MIMO(bit2), UL OFDMA(bit1), DL OFDMA(bit0))
    struct params params = {0};
    char config_file[64] = {0};
    char buf[64] = {0};
    char hemu_vendor_cmd[16] = {0};
    unsigned int set_mu_type = 0;
    bool new_vendor_patch = FALSE;
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    wifi_getDownlinkMuType(radio_index, &set_mu_type);

    if (mu_type == WIFI_DL_MU_TYPE_NONE) {
        set_mu_type &= ~0x05;   // unset bit 0, 2
    } else if (mu_type == WIFI_DL_MU_TYPE_OFDMA) {
        set_mu_type |= 0x01;
        set_mu_type &= ~0x04;
    } else if (mu_type == WIFI_DL_MU_TYPE_MIMO) {
        set_mu_type &= ~0x01;
        set_mu_type |= 0x04;
    } else if (mu_type == WIFI_DL_MU_TYPE_OFDMA_MIMO){
        set_mu_type |= 0x05;    // set bit 0, 2
    }

    new_vendor_patch = check_is_hemu_vendor_new_patch();
    if (new_vendor_patch)
        snprintf(hemu_vendor_cmd, sizeof(hemu_vendor_cmd), "mu_onoff");
    else
        snprintf(hemu_vendor_cmd, sizeof(hemu_vendor_cmd), "hemu_onoff");

    params.name = hemu_vendor_cmd;
    sprintf(buf, "%u", set_mu_type);
    params.value = buf;
    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radio_index);
    wifi_hostapdWrite(config_file, &params, 1);
    wifi_hostapdProcessUpdate(radio_index, &params, 1);
    wifi_reloadAp(radio_index);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_getDownlinkMuType(INT radio_index, wifi_dl_mu_type_t *mu_type)
{
    struct params params={0};
    char config_file[64] = {0};
    char buf[64] = {0};
    unsigned int get_mu_type = 0;
    bool new_vendor_patch = FALSE;
    char hemu_vendor_cmd[16] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if (mu_type == NULL)
        return RETURN_ERR;

    new_vendor_patch = check_is_hemu_vendor_new_patch();

    if (new_vendor_patch)
        snprintf(hemu_vendor_cmd, sizeof(hemu_vendor_cmd), "mu_onoff");
    else
        snprintf(hemu_vendor_cmd, sizeof(hemu_vendor_cmd), "hemu_onoff");

    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radio_index);
    wifi_hostapdRead(config_file, hemu_vendor_cmd, buf, sizeof(buf));
    get_mu_type = strtol(buf, NULL, 10);

    if (get_mu_type & 0x04 && get_mu_type & 0x01)
        *mu_type = WIFI_DL_MU_TYPE_OFDMA_MIMO;
    else if (get_mu_type & 0x04)
        *mu_type = WIFI_DL_MU_TYPE_MIMO;
    else if (get_mu_type & 0x01)
        *mu_type = WIFI_DL_MU_TYPE_OFDMA;
    else
        *mu_type = WIFI_DL_MU_TYPE_NONE;

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_setUplinkMuType(INT radio_index, wifi_ul_mu_type_t mu_type)
{
    // hemu onoff=<val> (bitmap- UL MU-MIMO(bit3), DL MU-MIMO(bit2), UL OFDMA(bit1), DL OFDMA(bit0))
    struct params params={0};
    char config_file[64] = {0};
    char buf[64] = {0};
    unsigned int set_mu_type = 0;
    bool new_vendor_patch = FALSE;
    char hemu_vendor_cmd[16] = {0};
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    wifi_getUplinkMuType(radio_index, &set_mu_type);

    // wifi hal only define up link type none and OFDMA, there is NO MU-MIMO.
    if (mu_type == WIFI_UL_MU_TYPE_NONE) {
        set_mu_type &= ~0x0a;
    } else if (mu_type == WIFI_DL_MU_TYPE_OFDMA) {
        set_mu_type |= 0x02;
        set_mu_type &= ~0x08;
    }

    new_vendor_patch = check_is_hemu_vendor_new_patch();

    if (new_vendor_patch)
        snprintf(hemu_vendor_cmd, sizeof(hemu_vendor_cmd), "mu_onoff");
    else
        snprintf(hemu_vendor_cmd, sizeof(hemu_vendor_cmd), "hemu_onoff");

    params.name = hemu_vendor_cmd;
    sprintf(buf, "%u", set_mu_type);
    params.value = buf;
    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radio_index);
    wifi_hostapdWrite(config_file, &params, 1);
    wifi_hostapdProcessUpdate(radio_index, &params, 1);
    wifi_reloadAp(radio_index);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_getUplinkMuType(INT radio_index, wifi_ul_mu_type_t *mu_type)
{
    struct params params={0};
    char config_file[64] = {0};
    char buf[64] = {0};
    unsigned int get_mu_type = 0;
    bool new_vendor_patch = FALSE;
    char hemu_vendor_cmd[16] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    new_vendor_patch = check_is_hemu_vendor_new_patch();

    if (new_vendor_patch)
        snprintf(hemu_vendor_cmd, sizeof(hemu_vendor_cmd), "mu_onoff");
    else
        snprintf(hemu_vendor_cmd, sizeof(hemu_vendor_cmd), "hemu_onoff");

    if (mu_type == NULL)
    return RETURN_ERR;

    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, radio_index);
    wifi_hostapdRead(config_file, hemu_vendor_cmd, buf, sizeof(buf));

    get_mu_type = strtol(buf, NULL, 10);
    if (get_mu_type & 0x02)
        *mu_type = WIFI_DL_MU_TYPE_OFDMA;
    else
        *mu_type = WIFI_DL_MU_TYPE_NONE;

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}


INT wifi_setGuardInterval(INT radio_index, wifi_guard_interval_t guard_interval)
{
    char cmd[128] = {0};
    char buf[256] = {0};
    char config_file[64] = {0};
    char GI[8] = {0};
    int mode_map = 0;
    FILE *f = NULL;
    wifi_band band = band_invalid;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if (wifi_getRadioMode(radio_index, buf, &mode_map) == RETURN_ERR) {
        wifi_dbg_printf("%s: wifi_getRadioMode return error\n", __func__);
        return RETURN_ERR;
    }

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radio_index);
    band = wifi_index_to_band(radio_index);

    // Hostapd are not supported HE mode GI 1600, 3200 ns.
    if (guard_interval == wifi_guard_interval_800) {    // remove all capab about short GI
        snprintf(cmd, sizeof(cmd), "sed -r -i 's/\\[SHORT-GI-(.){1,2}0\\]//g' %s", config_file);
        _syscmd(cmd, buf, sizeof(buf));
    } else if (guard_interval == wifi_guard_interval_400 || guard_interval == wifi_guard_interval_auto){
        wifi_hostapdRead(config_file, "ht_capab", buf, sizeof(buf));
        if (strstr(buf, "[SHORT-GI-") == NULL) {
            snprintf(cmd, sizeof(cmd), "sed -r -i '/^ht_capab=.*/s/$/[SHORT-GI-20][SHORT-GI-40]/' %s", config_file);
            _syscmd(cmd, buf, sizeof(buf));
        }
        if (band == band_5) {
            wifi_hostapdRead(config_file, "vht_capab", buf, sizeof(buf));
            if (strstr(buf, "[SHORT-GI-") == NULL) {
                snprintf(cmd, sizeof(cmd), "sed -r -i '/^vht_capab=.*/s/$/[SHORT-GI-80][SHORT-GI-160]/' %s", config_file);
                _syscmd(cmd, buf, sizeof(buf));
            }
        }
    }
    wifi_reloadAp(radio_index);

    if (guard_interval == wifi_guard_interval_400)
        strcpy(GI, "0.4");
    else if (guard_interval == wifi_guard_interval_800)
        strcpy(GI, "0.8");
    else if (guard_interval == wifi_guard_interval_1600)
        strcpy(GI, "1.6");
    else if (guard_interval == wifi_guard_interval_3200)
        strcpy(GI, "3.2");
    else if (guard_interval == wifi_guard_interval_auto)
        strcpy(GI, "auto");
    // Record GI for get GI function
    snprintf(buf, sizeof(buf), "%s%d.txt", GUARD_INTERVAL_FILE, radio_index);
    f = fopen(buf, "w");
    if (f == NULL)
        return RETURN_ERR;
    fprintf(f, "%s", GI);
    fclose(f);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_getGuardInterval(INT radio_index, wifi_guard_interval_t *guard_interval)
{
    char buf[32] = {0};
    char cmd[64] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    if (guard_interval == NULL)
        return RETURN_ERR;

    snprintf(cmd, sizeof(cmd), "cat %s%d.txt 2> /dev/null", GUARD_INTERVAL_FILE, radio_index);
    _syscmd(cmd, buf, sizeof(buf));

    if (strncmp(buf, "0.4", 3) == 0)
        *guard_interval = wifi_guard_interval_400;
    else if (strncmp(buf, "0.8", 3) == 0)
        *guard_interval = wifi_guard_interval_800;
    else if (strncmp(buf, "1.6", 3) == 0)
        *guard_interval = wifi_guard_interval_1600;
    else if (strncmp(buf, "3.2", 3) == 0)
        *guard_interval = wifi_guard_interval_3200;
    else
        *guard_interval = wifi_guard_interval_auto;

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_setBSSColor(INT radio_index, UCHAR color)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    struct params params = {0};
    char config_file[128] = {0};
    char bss_color[4] ={0};
    UCHAR *color_list;
    int color_num = 0;
    int maxNumberColors = 64;
    BOOL color_is_aval = FALSE;

    if (color > 63 || color == 0)
        return RETURN_ERR;

    color_list = calloc(maxNumberColors, sizeof(UCHAR));
    if (color_list == NULL)
        return RETURN_ERR;
    if (wifi_getAvailableBSSColor(radio_index, maxNumberColors, color_list, &color_num) != RETURN_OK) {
        free(color_list);
        return RETURN_ERR;
    }

    for (int i = 0; i < color_num; i++) {
        if (color_list[i] == color) {
            color_is_aval = TRUE;
            break;
        }
    }
    if (color_is_aval == FALSE) {
        free(color_list);
        fprintf(stderr, "%s: color %hhu is not avaliable.\n", __func__, color);
        return RETURN_ERR;
    }

    params.name = "he_bss_color";
    snprintf(bss_color, sizeof(bss_color), "%hhu", color);
    params.value = bss_color;
    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radio_index);
    wifi_hostapdWrite(config_file, &params, 1);
    wifi_hostapdProcessUpdate(radio_index, &params, 1);
    wifi_reloadAp(radio_index);

    free(color_list);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_getBSSColor(INT radio_index, UCHAR *color)
{
    char buf[64] = {0};
    char cmd[128] = {0};
    char interface_name[16] = {0};

    if (NULL == color)
        return RETURN_ERR;

    if (wifi_GetInterfaceName(radio_index, interface_name) != RETURN_OK)
        return RETURN_ERR;

    snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s get_bss_color | cut -d '=' -f2", interface_name);
    _syscmd(cmd, buf, sizeof(buf));
    *color = (UCHAR)strtoul(buf, NULL, 10);

    return RETURN_OK;
}

INT wifi_getAvailableBSSColor(INT radio_index, INT maxNumberColors, UCHAR* colorList, INT *numColorReturned)
{
    char buf[64] = {0};
    char cmd[128] = {0};
    char interface_name[16] = {0};
    unsigned long long color_bitmap = 0;

    if (NULL == colorList || NULL == numColorReturned)
        return RETURN_ERR;

    if (wifi_GetInterfaceName(radio_index, interface_name) != RETURN_OK)
        return RETURN_ERR;

    snprintf(cmd, sizeof(cmd), "hostapd_cli -i %s get_color_bmp | head -n 1 | cut -d '=' -f2", interface_name);
    _syscmd(cmd, buf, sizeof(buf));
    color_bitmap = strtoull(buf, NULL, 16);

    *numColorReturned = 0;
    for (int i = 0; i < maxNumberColors; i++) {
        if (color_bitmap & 1) {
            colorList[*numColorReturned] = i;
            (*numColorReturned) += 1;
        }
        color_bitmap >>= 1;
    }
    return RETURN_OK;
}

/* multi-psk support */
INT wifi_getMultiPskClientKey(INT apIndex, mac_address_t mac, wifi_key_multi_psk_t *key)
{
    char cmd[256];
    char interface_name[16] = {0};

    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;

    sprintf(cmd, "hostapd_cli -i %s sta %x:%x:%x:%x:%x:%x |grep '^keyid' | cut -f 2 -d = | tr -d '\n'",
        interface_name,
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );
    printf("DEBUG LOG wifi_getMultiPskClientKey(%s)\n",cmd);
    _syscmd(cmd, key->wifi_keyId, 64);


    return RETURN_OK;
}

INT wifi_pushMultiPskKeys(INT apIndex, wifi_key_multi_psk_t *keys, INT keysNumber)
{
    char interface_name[16] = {0};
    FILE *fd      = NULL;
    char fname[100];
    char cmd[128] = {0};
    char out[64] = {0};
    wifi_key_multi_psk_t * key = NULL;
    if(keysNumber < 0)
            return RETURN_ERR;

    snprintf(fname, sizeof(fname), "%s%d.psk", PSK_FILE, apIndex);
    fd = fopen(fname, "w");
    if (!fd) {
            return RETURN_ERR;
    }
    key= (wifi_key_multi_psk_t *) keys;
    for(int i=0; i<keysNumber; ++i, key++) {
        fprintf(fd, "keyid=%s 00:00:00:00:00:00 %s\n", key->wifi_keyId, key->wifi_psk);
    }
    fclose(fd);

    //reload file
    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    sprintf(cmd, "hostapd_cli -i%s raw RELOAD_WPA_PSK", interface_name);
    _syscmd(cmd, out, 64);
    return RETURN_OK;
}

INT wifi_getMultiPskKeys(INT apIndex, wifi_key_multi_psk_t *keys, INT keysNumber)
{
    FILE *fd      = NULL;
    char fname[100];
    char * line = NULL;
    char * pos = NULL;
    size_t len = 0;
    ssize_t read = 0;
    INT ret = RETURN_OK;
    wifi_key_multi_psk_t *keys_it = NULL;

    if (keysNumber < 1) {
        return RETURN_ERR;
    }

    snprintf(fname, sizeof(fname), "%s%d.psk", PSK_FILE, apIndex);
    fd = fopen(fname, "r");
    if (!fd) {
        return RETURN_ERR;
    }

    if (keys == NULL) {
        ret = RETURN_ERR;
        goto close;
    }

    keys_it = keys;
    while ((read = getline(&line, &len, fd)) != -1) {
        //Strip trailing new line if present
        if (read > 0 && line[read-1] == '\n') {
            line[read-1] = '\0';
        }

        if(strcmp(line,"keyid=")) {
            sscanf(line, "keyid=%63s", &(keys_it->wifi_keyId));
            if (!(pos = index(line, ' '))) {
                ret = RETURN_ERR;
                goto close;
            }
            pos++;
            //Here should be 00:00:00:00:00:00
            if (!(strcmp(pos,"00:00:00:00:00:00"))) {
                 printf("Not supported MAC: %s\n", pos);
            }
            if (!(pos = index(pos, ' '))) {
                ret = RETURN_ERR;
                goto close;
            }
            pos++;

            //The rest is PSK
            snprintf(&keys_it->wifi_psk[0], sizeof(keys_it->wifi_psk), "%s", pos);
            keys_it++;

            if(--keysNumber <= 0)
		break;
        }
    }

close:
    free(line);
    fclose(fd);
    return ret;
}
/* end of multi-psk support */

INT wifi_setNeighborReports(UINT apIndex,
                             UINT numNeighborReports,
                             wifi_NeighborReport_t *neighborReports)
{
    char cmd[256] = { 0 };
    char hex_bssid[13] = { 0 };
    char bssid[18] = { 0 };
    char nr[256] = { 0 };
    char ssid[256];
    char hex_ssid[256];
    char interface_name[16] = {0};
    INT ret;

    /*rmeove all neighbors*/
    wifi_dbg_printf("\n[%s]: removing all neighbors from %s\n", __func__, interface_name);
    if (wifi_GetInterfaceName(apIndex, interface_name) != RETURN_OK)
        return RETURN_ERR;
    sprintf(cmd, "hostapd_cli show_neighbor -i %s | awk '{print $1 \" \" $2}' | xargs -n2 -r hostapd_cli remove_neighbor -i %s",interface_name,interface_name);
    system(cmd);

    for(unsigned int i = 0; i < numNeighborReports; i++)
    {
        memset(ssid, 0, sizeof(ssid));
        ret = wifi_getSSIDName(apIndex, ssid);
        if (ret != RETURN_OK)
            return RETURN_ERR;

        memset(hex_ssid, 0, sizeof(hex_ssid));
        /* Reserve 2 bytes for the final hex pair + 1 for NUL: stop at sizeof-3 */
        for(size_t j = 0,k = 0; ssid[j] != '\0' && k < sizeof(hex_ssid) - 2; j++,k+=2 )
            sprintf(hex_ssid + k,"%02x", ssid[j]);

        snprintf(hex_bssid, sizeof(hex_bssid),
                "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
                neighborReports[i].bssid[0], neighborReports[i].bssid[1], neighborReports[i].bssid[2], neighborReports[i].bssid[3], neighborReports[i].bssid[4], neighborReports[i].bssid[5]);
        snprintf(bssid, sizeof(bssid),
                "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                neighborReports[i].bssid[0], neighborReports[i].bssid[1], neighborReports[i].bssid[2], neighborReports[i].bssid[3], neighborReports[i].bssid[4], neighborReports[i].bssid[5]);

        snprintf(nr, sizeof(nr),
                "%s"                                    // bssid
                "%02hhx%02hhx%02hhx%02hhx"              // bssid_info
                "%02hhx"                                // operclass
                "%02hhx"                                // channel
                "%02hhx",                               // phy_mode
                hex_bssid,
                neighborReports[i].info & 0xff, (neighborReports[i].info >> 8) & 0xff,
                (neighborReports[i].info >> 16) & 0xff, (neighborReports[i].info >> 24) & 0xff,
                neighborReports[i].opClass,
                neighborReports[i].channel,
                neighborReports[i].phyTable);

        snprintf(cmd, sizeof(cmd),
                "hostapd_cli set_neighbor "
                "%s "                        // bssid
                "ssid=%s "                   // ssid
                "nr=%s "                    // nr
                "-i %s",
                bssid,hex_ssid,nr, interface_name);

        if (WEXITSTATUS(system(cmd)) != 0)
        {
            wifi_dbg_printf("\n[%s]: %s failed",__func__,cmd);
        }
    }

    return RETURN_OK;
}

INT wifi_getApInterworkingElement(INT apIndex, wifi_InterworkingElement_t *output_struct)
{
    return RETURN_OK;
}

#ifdef _WIFI_HAL_TEST_
int main(int argc,char **argv)
{
    int index;
    INT ret=0;
    char buf[1024]="";

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if(argc<3)
    {
        if(argc==2)
        {
            if(!strcmp(argv[1], "init"))
                return wifi_init();
            if(!strcmp(argv[1], "reset"))
                return wifi_reset();
            if(!strcmp(argv[1], "wifi_getHalVersion"))
            {
                char buffer[64];
                if(wifi_getHalVersion(buffer)==RETURN_OK)
                    printf("Version: %s\n", buffer);
                else
                    printf("Error in wifi_getHalVersion\n");
                return RETURN_OK;
            }
        }
        printf("wifihal <API> <radioIndex> <arg1> <arg2> ...\n");
        exit(-1);
    }

    index = atoi(argv[2]);
    if(strstr(argv[1], "wifi_getApName")!=NULL)
    {
        wifi_getApName(index,buf);
        printf("Ap name is %s \n",buf);
        return 0;
    }
    if(strstr(argv[1], "wifi_getRadioAutoChannelEnable")!=NULL)
    {
        BOOL b = FALSE;
        BOOL *output_bool = &b;
        wifi_getRadioAutoChannelEnable(index,output_bool);
        printf("Channel enabled = %d \n",b);
        return 0;
    }
    if(strstr(argv[1], "wifi_getApWpaEncryptionMode")!=NULL)
    {
        wifi_getApWpaEncryptionMode(index,buf);
        printf("encryption enabled = %s\n",buf);
        return 0;
    }
    if(strstr(argv[1], "wifi_getApSsidAdvertisementEnable")!=NULL)
    {
        BOOL b = FALSE;
        BOOL *output_bool = &b;
        wifi_getApSsidAdvertisementEnable(index,output_bool);
        printf("advertisment enabled =  %d\n",b);
        return 0;
    }
    if(strstr(argv[1],"wifi_getApAssociatedDeviceTidStatsResult")!=NULL)
    {
        if(argc <= 3 )
        {
            printf("Insufficient arguments \n");
            exit(-1);
        }

        char sta[20] = {'\0'};
        ULLONG handle= 0;
        strcpy(sta,argv[3]);
        mac_address_t st;
	mac_addr_aton(st,sta);

        wifi_associated_dev_tid_stats_t tid_stats;
        wifi_getApAssociatedDeviceTidStatsResult(index,&st,&tid_stats,&handle);
        for(int tid_index=0; tid_index<PS_MAX_TID; tid_index++) //print tid stats
            printf(" tid=%d \t ac=%d \t num_msdus=%lld \n" ,tid_stats.tid_array[tid_index].tid,tid_stats.tid_array[tid_index].ac,tid_stats.tid_array[tid_index].num_msdus);
    }

    if(strstr(argv[1], "getApEnable")!=NULL) {
        BOOL enable;
        ret=wifi_getApEnable(index, &enable);
        printf("%s %d: %d, returns %d\n", argv[1], index, enable, ret);
    }
    else if(strstr(argv[1], "setApEnable")!=NULL) {
        BOOL enable = atoi(argv[3]);
        ret=wifi_setApEnable(index, enable);
        printf("%s %d: %d, returns %d\n", argv[1], index, enable, ret);
    }
    else if(strstr(argv[1], "getApStatus")!=NULL) {
        char status[64]; 
        ret=wifi_getApStatus(index, status);
        printf("%s %d: %s, returns %d\n", argv[1], index, status, ret);
    }
    else if(strstr(argv[1], "wifi_getSSIDNameStatus")!=NULL)
    {
        wifi_getSSIDNameStatus(index,buf);
        printf("%s %d: active ssid : %s\n",argv[1], index,buf);
        return 0;
    }
    else if(strstr(argv[1], "getSSIDTrafficStats2")!=NULL) {
        wifi_ssidTrafficStats2_t stats={0};
        ret=wifi_getSSIDTrafficStats2(index, &stats); //Tr181
        printf("%s %d: returns %d\n", argv[1], index, ret);
        printf("     ssid_BytesSent             =%lu\n", stats.ssid_BytesSent);
        printf("     ssid_BytesReceived         =%lu\n", stats.ssid_BytesReceived);
        printf("     ssid_PacketsSent           =%lu\n", stats.ssid_PacketsSent);
        printf("     ssid_PacketsReceived       =%lu\n", stats.ssid_PacketsReceived);
        printf("     ssid_RetransCount          =%lu\n", stats.ssid_RetransCount);
        printf("     ssid_FailedRetransCount    =%lu\n", stats.ssid_FailedRetransCount);
        printf("     ssid_RetryCount            =%lu\n", stats.ssid_RetryCount);
        printf("     ssid_MultipleRetryCount    =%lu\n", stats.ssid_MultipleRetryCount);
        printf("     ssid_ACKFailureCount       =%lu\n", stats.ssid_ACKFailureCount);
        printf("     ssid_AggregatedPacketCount =%lu\n", stats.ssid_AggregatedPacketCount);
        printf("     ssid_ErrorsSent            =%lu\n", stats.ssid_ErrorsSent);
        printf("     ssid_ErrorsReceived        =%lu\n", stats.ssid_ErrorsReceived);
        printf("     ssid_UnicastPacketsSent    =%lu\n", stats.ssid_UnicastPacketsSent);
        printf("     ssid_UnicastPacketsReceived    =%lu\n", stats.ssid_UnicastPacketsReceived);
        printf("     ssid_DiscardedPacketsSent      =%lu\n", stats.ssid_DiscardedPacketsSent);
        printf("     ssid_DiscardedPacketsReceived  =%lu\n", stats.ssid_DiscardedPacketsReceived);
        printf("     ssid_MulticastPacketsSent      =%lu\n", stats.ssid_MulticastPacketsSent);
        printf("     ssid_MulticastPacketsReceived  =%lu\n", stats.ssid_MulticastPacketsReceived);
        printf("     ssid_BroadcastPacketsSent      =%lu\n", stats.ssid_BroadcastPacketsSent);
        printf("     ssid_BroadcastPacketsRecevied  =%lu\n", stats.ssid_BroadcastPacketsRecevied);
        printf("     ssid_UnknownPacketsReceived    =%lu\n", stats.ssid_UnknownPacketsReceived);
    }
    else if(strstr(argv[1], "getNeighboringWiFiDiagnosticResult2")!=NULL) {
        wifi_neighbor_ap2_t *neighbor_ap_array=NULL, *pt=NULL;
        UINT array_size=0;
        UINT i=0;
        ret=wifi_getNeighboringWiFiDiagnosticResult2(index, &neighbor_ap_array, &array_size);
        printf("%s %d: array_size=%d, returns %d\n", argv[1], index, array_size, ret);
        for(i=0, pt=neighbor_ap_array; i<array_size; i++, pt++) {	
            printf("  neighbor %d:\n", i);
            printf("     ap_SSID                =%s\n", pt->ap_SSID);
            printf("     ap_BSSID               =%s\n", pt->ap_BSSID);
            printf("     ap_Mode                =%s\n", pt->ap_Mode);
            printf("     ap_Channel             =%d\n", pt->ap_Channel);
            printf("     ap_SignalStrength      =%d\n", pt->ap_SignalStrength);
            printf("     ap_SecurityModeEnabled =%s\n", pt->ap_SecurityModeEnabled);
            printf("     ap_EncryptionMode      =%s\n", pt->ap_EncryptionMode);
            printf("     ap_SupportedStandards  =%s\n", pt->ap_SupportedStandards);
            printf("     ap_OperatingStandards  =%s\n", pt->ap_OperatingStandards);
            printf("     ap_OperatingChannelBandwidth   =%s\n", pt->ap_OperatingChannelBandwidth);
            printf("     ap_SecurityModeEnabled         =%s\n", pt->ap_SecurityModeEnabled);
            printf("     ap_BeaconPeriod                =%d\n", pt->ap_BeaconPeriod);
            printf("     ap_Noise                       =%d\n", pt->ap_Noise);
            printf("     ap_BasicDataTransferRates      =%s\n", pt->ap_BasicDataTransferRates);
            printf("     ap_SupportedDataTransferRates  =%s\n", pt->ap_SupportedDataTransferRates);
            printf("     ap_DTIMPeriod                  =%d\n", pt->ap_DTIMPeriod);
            printf("     ap_ChannelUtilization          =%d\n", pt->ap_ChannelUtilization);			
        }
        if(neighbor_ap_array)
            free(neighbor_ap_array); //make sure to free the list
    }
    else if(strstr(argv[1], "getApAssociatedDeviceDiagnosticResult")!=NULL) {
        wifi_associated_dev_t *associated_dev_array=NULL, *pt=NULL;
        UINT array_size=0;
        UINT i=0;
        ret=wifi_getApAssociatedDeviceDiagnosticResult(index, &associated_dev_array, &array_size);
        printf("%s %d: array_size=%d, returns %d\n", argv[1], index, array_size, ret);
        for(i=0, pt=associated_dev_array; i<array_size; i++, pt++) {	
            printf("  associated_dev %d:\n", i);
            printf("     cli_OperatingStandard      =%s\n", pt->cli_OperatingStandard);
            printf("     cli_OperatingChannelBandwidth  =%s\n", pt->cli_OperatingChannelBandwidth);
            printf("     cli_SNR                    =%d\n", pt->cli_SNR);
            printf("     cli_InterferenceSources    =%s\n", pt->cli_InterferenceSources);
            printf("     cli_DataFramesSentAck      =%lu\n", pt->cli_DataFramesSentAck);
            printf("     cli_DataFramesSentNoAck    =%lu\n", pt->cli_DataFramesSentNoAck);
            printf("     cli_BytesSent              =%lu\n", pt->cli_BytesSent);
            printf("     cli_BytesReceived          =%lu\n", pt->cli_BytesReceived);
            printf("     cli_RSSI                   =%d\n", pt->cli_RSSI);
            printf("     cli_MinRSSI                =%d\n", pt->cli_MinRSSI);
            printf("     cli_MaxRSSI                =%d\n", pt->cli_MaxRSSI);
            printf("     cli_Disassociations        =%d\n", pt->cli_Disassociations);
            printf("     cli_AuthenticationFailures =%d\n", pt->cli_AuthenticationFailures);
        }
        if(associated_dev_array)
            free(associated_dev_array); //make sure to free the list
    }

    if(strstr(argv[1],"wifi_getRadioChannelStats")!=NULL)
    {
#define MAX_ARRAY_SIZE 64
        int i, array_size;
        char *p, *ch_str;
        wifi_channelStats_t input_output_channelStats_array[MAX_ARRAY_SIZE];

        if(argc != 5)
        {
            printf("Insufficient arguments, Usage: wifihal wifi_getRadioChannelStats <AP-Index> <Array-Size> <Comma-seperated-channel-numbers>\n");
            exit(-1);
        }
        memset(input_output_channelStats_array, 0, sizeof(input_output_channelStats_array));

        for (i=0, array_size=atoi(argv[3]), ch_str=argv[4]; i<array_size; i++, ch_str=p)
        {
            strtok_r(ch_str, ",", &p);
            input_output_channelStats_array[i].ch_number = atoi(ch_str);
        }
        wifi_getRadioChannelStats(atoi(argv[2]), input_output_channelStats_array, array_size);
        if(!array_size)
            array_size=1;//Need to print current channel statistics
        for(i=0; i<array_size; i++)
            printf("chan num = %d \t, noise =%d\t ch_utilization_busy_rx = %lld \t,\
                    ch_utilization_busy_tx = %lld \t,ch_utilization_busy = %lld \t,\
                    ch_utilization_busy_ext = %lld \t, ch_utilization_total = %lld \t \n",\
                    input_output_channelStats_array[i].ch_number,\
                    input_output_channelStats_array[i].ch_noise,\
                    input_output_channelStats_array[i].ch_utilization_busy_rx,\
                    input_output_channelStats_array[i].ch_utilization_busy_tx,\
                    input_output_channelStats_array[i].ch_utilization_busy,\
                    input_output_channelStats_array[i].ch_utilization_busy_ext,\
                    input_output_channelStats_array[i].ch_utilization_total);
    }

    if(strstr(argv[1],"wifi_getAssociatedDeviceDetail")!=NULL)
    {
        if(argc <= 3 )
        {
            printf("Insufficient arguments \n");
            exit(-1);
        }
        char mac_addr[20] = {'\0'};
        wifi_device_t output_struct;
        int dev_index = atoi(argv[3]);

        wifi_getAssociatedDeviceDetail(index,dev_index,&output_struct);
        mac_addr_ntoa(mac_addr,output_struct.wifi_devMacAddress);
        printf("wifi_devMacAddress=%s \t wifi_devAssociatedDeviceAuthentiationState=%d \t, wifi_devSignalStrength=%d \t,wifi_devTxRate=%d \t, wifi_devRxRate =%d \t\n ", mac_addr,output_struct.wifi_devAssociatedDeviceAuthentiationState,output_struct.wifi_devSignalStrength,output_struct.wifi_devTxRate,output_struct.wifi_devRxRate);
    }

    if(strstr(argv[1],"wifi_setNeighborReports")!=NULL)
    {
        if (argc <= 3)
        {
            printf("Insufficient arguments\n");
            exit(-1);
        }
        char args[256];
        wifi_NeighborReport_t *neighborReports;

        neighborReports = calloc(argc - 2, sizeof(*neighborReports));
        if (!neighborReports)
        {
            printf("Failed to allocate memory");
            exit(-1);
        }

        for (int i = 3; i < argc; ++i)
        {
            char *val;
            int j = 0;
            memset(args, 0, sizeof(args));
            strncpy(args, argv[i], sizeof(args));
            val = strtok(args, ";");
            while (val != NULL)
            {
                if (j == 0)
                {
                    mac_addr_aton(neighborReports[i - 3].bssid, val);
                } else if (j == 1)
                {
                    neighborReports[i - 3].info = strtol(val, NULL, 16);
                } else if (j == 2)
                {
                    neighborReports[i - 3].opClass = strtol(val, NULL, 16);
                } else if (j == 3)
                {
                    neighborReports[i - 3].channel = strtol(val, NULL, 16);
                } else if (j == 4)
                {
                    neighborReports[i - 3].phyTable = strtol(val, NULL, 16);
                } else {
                    printf("Insufficient arguments]n\n");
                    exit(-1);
                }
                val = strtok(NULL, ";");
                j++;
            }
        }

        INT ret = wifi_setNeighborReports(index, argc - 3, neighborReports);
        if (ret != RETURN_OK)
        {
            printf("wifi_setNeighborReports ret = %d", ret);
            exit(-1);
        }
    }
    if(strstr(argv[1],"wifi_getRadioIfName")!=NULL)
    {
        if((ret=wifi_getRadioIfName(index, buf))==RETURN_OK)
            printf("%s.\n", buf);
        else
            printf("Error returned\n");
    }
    if(strstr(argv[1],"wifi_getApSecurityModesSupported")!=NULL)
    {
        if((ret=wifi_getApSecurityModesSupported(index, buf))==RETURN_OK)
            printf("%s.\n", buf);
        else
            printf("Error returned\n");
    }
    if(strstr(argv[1],"wifi_getRadioOperatingChannelBandwidth")!=NULL)
    {
        if (argc <= 2)
        {
            printf("Insufficient arguments\n");
            exit(-1);
        }
        char buf[64]= {'\0'};
        wifi_getRadioOperatingChannelBandwidth(index,buf);
        printf("Current bandwidth is %s \n",buf);
        return 0;
    }
    if(strstr(argv[1],"pushRadioChannel2")!=NULL)
    {
        if (argc <= 5)
        {
            printf("Insufficient arguments\n");
            exit(-1);
        }
        UINT channel = atoi(argv[3]);
        UINT width = atoi(argv[4]);
        UINT beacon = atoi(argv[5]);
        INT ret = wifi_pushRadioChannel2(index,channel,width,beacon);
        printf("Result = %d", ret);
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return 0;
}

#endif

#ifdef WIFI_HAL_VERSION_3

INT BitMapToTransmitRates(UINT bitMap, char *BasicRate)
{
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    if (bitMap & WIFI_BITRATE_1MBPS)
        strcat(BasicRate, "1,");
    if (bitMap & WIFI_BITRATE_2MBPS)
        strcat(BasicRate, "2,");
    if (bitMap & WIFI_BITRATE_5_5MBPS)
        strcat(BasicRate, "5.5,");
    if (bitMap & WIFI_BITRATE_6MBPS)
        strcat(BasicRate, "6,");
    if (bitMap & WIFI_BITRATE_9MBPS)
        strcat(BasicRate, "9,");
    if (bitMap & WIFI_BITRATE_11MBPS)
        strcat(BasicRate, "11,");
    if (bitMap & WIFI_BITRATE_12MBPS)
        strcat(BasicRate, "12,");
    if (bitMap & WIFI_BITRATE_18MBPS)
        strcat(BasicRate, "18,");
    if (bitMap & WIFI_BITRATE_24MBPS)
        strcat(BasicRate, "24,");
    if (bitMap & WIFI_BITRATE_36MBPS)
        strcat(BasicRate, "36,");
    if (bitMap & WIFI_BITRATE_48MBPS)
        strcat(BasicRate, "48,");
    if (bitMap & WIFI_BITRATE_54MBPS)
        strcat(BasicRate, "54,");
    if (strlen(BasicRate) != 0)     // remove last comma
        BasicRate[strlen(BasicRate) - 1] = '\0';
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT TransmitRatesToBitMap (char *BasicRatesList, UINT *basicRateBitMap)
{
    UINT BitMap = 0;
    char *rate;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    rate = strtok(BasicRatesList, ",");
    while(rate != NULL)
    {
        if (strcmp(rate, "1") == 0)
            BitMap |= WIFI_BITRATE_1MBPS;
        else if (strcmp(rate, "2") == 0)
            BitMap |= WIFI_BITRATE_2MBPS;
        else if (strcmp(rate, "5.5") == 0)
            BitMap |= WIFI_BITRATE_5_5MBPS;
        else if (strcmp(rate, "6") == 0)
            BitMap |= WIFI_BITRATE_6MBPS;
        else if (strcmp(rate, "9") == 0)
            BitMap |= WIFI_BITRATE_9MBPS;
        else if (strcmp(rate, "11") == 0)
            BitMap |= WIFI_BITRATE_11MBPS;
        else if (strcmp(rate, "12") == 0)
            BitMap |= WIFI_BITRATE_12MBPS;
        else if (strcmp(rate, "18") == 0)
            BitMap |= WIFI_BITRATE_18MBPS;
        else if (strcmp(rate, "24") == 0)
            BitMap |= WIFI_BITRATE_24MBPS;
        else if (strcmp(rate, "36") == 0)
            BitMap |= WIFI_BITRATE_36MBPS;
        else if (strcmp(rate, "48") == 0)
            BitMap |= WIFI_BITRATE_48MBPS;
        else if (strcmp(rate, "54") == 0)
            BitMap |= WIFI_BITRATE_54MBPS;
        rate = strtok(NULL, ",");
    }
    *basicRateBitMap = BitMap;
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT setEHT320CentrlChannel(UINT radioIndex, int channel, wifi_channelBandwidth_t bandwidth)
{
    int center_channel = 0;
    char central_channel_str[16] = {0};
    char config_file[32] = {0};
    struct params param = {0};

    center_channel = util_unii_6g_centerfreq("HT320", channel);
    if (bandwidth == WIFI_CHANNELBANDWIDTH_320_1MHZ) {
        if (channel >= 193)
            return RETURN_ERR;
        if (channel >= 33) {
            if (channel > center_channel)
                center_channel += 32;
            else
                center_channel -= 32;
        }
    } else if (bandwidth == WIFI_CHANNELBANDWIDTH_320_2MHZ) {
        if (channel <= 29)
            return RETURN_ERR;
    }
    snprintf(central_channel_str, sizeof(central_channel_str), "%d", center_channel);
    param.name = "eht_oper_centr_freq_seg0_idx";
    param.value = central_channel_str;
    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
    wifi_hostapdWrite(config_file, &param, 1);

    return RETURN_OK;
}

INT wifi_setRadioOpclass(INT radioIndex, INT bandwidth)
{
    int op_class = 0;
    char config_file[32] = {0};
    char op_class_str[8] = {0};
    struct params param = {0};

    if (bandwidth == 20)
        op_class = 131;
    else if (bandwidth == 40)
        op_class = 132;
    else if (bandwidth == 80)
        op_class = 133;
    else if (bandwidth == 160)
        op_class = 134;
    else if (bandwidth == 320)
        op_class = 137;
    else
        return RETURN_ERR;
    snprintf(op_class_str, sizeof(op_class_str), "%d", op_class);
    param.name = "op_class";
    param.value = op_class_str;
    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
    wifi_hostapdWrite(config_file, &param, 1);
    return RETURN_OK;
}

INT wifi_getRadioOpclass(INT radioIndex, UINT *class)
{
    char config_file[32] = {0};
    char buf [16] = {0};

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, radioIndex);
    if (wifi_hostapdRead(config_file, "op_class", buf, sizeof(buf)) != 0)
        return RETURN_ERR;      // 6g band should set op_class
    *class = (UINT)strtoul(buf, NULL, 10);

    return RETURN_OK;
}

// This API is used to configured all radio operation parameter in a single set. it includes channel number, channelWidth, mode and auto chammel configuration.
INT wifi_setRadioOperatingParameters(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    char buf[128] = {0};
    char cmd[128] = {0};
    char config_file[64] = {0};
    int bandwidth;
    int set_mode = 0;
    wifi_radio_operationParam_t current_param;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    multiple_set = TRUE;
    if (wifi_getRadioOperatingParameters(index, &current_param) != RETURN_OK) {
        fprintf(stderr, "%s: wifi_getRadioOperatingParameters return error.\n", __func__);
        return RETURN_ERR;
    }
    if (current_param.autoChannelEnabled != operationParam->autoChannelEnabled) {
        if (wifi_setRadioAutoChannelEnable(index, operationParam->autoChannelEnabled) != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setRadioAutoChannelEnable return error.\n", __func__);
            return RETURN_ERR;
        }
    }

    if (operationParam->channelWidth == WIFI_CHANNELBANDWIDTH_20MHZ)
        bandwidth = 20;
    else if (operationParam->channelWidth == WIFI_CHANNELBANDWIDTH_40MHZ)
        bandwidth = 40;
    else if (operationParam->channelWidth == WIFI_CHANNELBANDWIDTH_80MHZ)
        bandwidth = 80;
    else if (operationParam->channelWidth == WIFI_CHANNELBANDWIDTH_160MHZ || operationParam->channelWidth == WIFI_CHANNELBANDWIDTH_80_80MHZ)
        bandwidth = 160;
    else if (operationParam->channelWidth == WIFI_CHANNELBANDWIDTH_320_1MHZ || operationParam->channelWidth == WIFI_CHANNELBANDWIDTH_320_2MHZ)
        bandwidth = 320;
    if (operationParam->autoChannelEnabled){
        if (wifi_pushRadioChannel2(index, 0, bandwidth, operationParam->csa_beacon_count) != RETURN_OK) {
            fprintf(stderr, "%s: wifi_pushRadioChannel2 return error.\n", __func__);
            return RETURN_ERR;
        }
    }else{    
        if (wifi_pushRadioChannel2(index, operationParam->channel, bandwidth, operationParam->csa_beacon_count) != RETURN_OK) {
            fprintf(stderr, "%s: wifi_pushRadioChannel2 return error.\n", __func__);
            return RETURN_ERR;
        }
    }

    // if set EHT 320. We need to overide the central channel config set by wifi_pushRadioChannel2.
    if (operationParam->channelWidth == WIFI_CHANNELBANDWIDTH_320_1MHZ || operationParam->channelWidth == WIFI_CHANNELBANDWIDTH_320_2MHZ) {
        if (setEHT320CentrlChannel(index, operationParam->channel, operationParam->channelWidth) != RETURN_OK) {
            fprintf(stderr, "%s: failed to set EHT 320 bandwidth with channel %d and %s setting\n", __func__, operationParam->channel, \
                (operationParam->channelWidth == WIFI_CHANNELBANDWIDTH_320_1MHZ) ? "EHT320-1" : "EHT320-2");
            return RETURN_ERR;
        }
    }

    if (operationParam->band == WIFI_FREQUENCY_6_BAND) {
        if (wifi_setRadioOpclass(index, bandwidth) != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setRadioOpclass return error.\n", __func__);
            return RETURN_ERR;
        }
    }

    if (current_param.variant != operationParam->variant) {
        // Two different definition bit map, so need to check every bit.
        if (operationParam->variant & WIFI_80211_VARIANT_A)
            set_mode |= WIFI_MODE_A;
        if (operationParam->variant & WIFI_80211_VARIANT_B)
            set_mode |= WIFI_MODE_B;
        if (operationParam->variant & WIFI_80211_VARIANT_G)
            set_mode |= WIFI_MODE_G;
        if (operationParam->variant & WIFI_80211_VARIANT_N)
            set_mode |= WIFI_MODE_N;
        if (operationParam->variant & WIFI_80211_VARIANT_AC)
            set_mode |= WIFI_MODE_AC;
        if (operationParam->variant & WIFI_80211_VARIANT_AX)
            set_mode |= WIFI_MODE_AX;
        if (operationParam->variant & WIFI_80211_VARIANT_BE)
            set_mode |= WIFI_MODE_BE;
        // Second parameter is to set channel band width, it is done by wifi_pushRadioChannel2 if changed.
        memset(buf, 0, sizeof(buf));
        if (wifi_setRadioMode(index, buf, set_mode) != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setRadioMode return error.\n", __func__);
            return RETURN_ERR;
        }
    }
    if (current_param.dtimPeriod != operationParam->dtimPeriod) {
        if (wifi_setApDTIMInterval(index, operationParam->dtimPeriod) != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setApDTIMInterval return error.\n", __func__);
            return RETURN_ERR;
        }
    }
    if (current_param.beaconInterval != operationParam->beaconInterval) {
        if (wifi_setRadioBeaconPeriod(index, operationParam->beaconInterval) != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setRadioBeaconPeriod return error.\n", __func__);
            return RETURN_ERR;
        }
    }
    if (current_param.operationalDataTransmitRates != operationParam->operationalDataTransmitRates) {
        BitMapToTransmitRates(operationParam->operationalDataTransmitRates, buf);
        if (wifi_setRadioBasicDataTransmitRates(index, buf) != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setRadioBasicDataTransmitRates return error.\n", __func__);
            return RETURN_ERR;
        }
    }
    if (current_param.fragmentationThreshold != operationParam->fragmentationThreshold) {
        if (wifi_setRadioFragmentationThreshold(index, operationParam->fragmentationThreshold) != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setRadioFragmentationThreshold return error.\n", __func__);
            return RETURN_ERR;
        }
    }
    if (current_param.guardInterval != operationParam->guardInterval) {
        if (wifi_setGuardInterval(index, operationParam->guardInterval) != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setGuardInterval return error.\n", __func__);
            return RETURN_ERR;
        }
    }
    if (current_param.transmitPower != operationParam->transmitPower) {
        if (wifi_setRadioTransmitPower(index, operationParam->transmitPower) != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setRadioTransmitPower return error.\n", __func__);
            return RETURN_ERR;
        }
    }
    if (current_param.rtsThreshold != operationParam->rtsThreshold) {
        if (wifi_setApRtsThreshold(index, operationParam->rtsThreshold) != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setApRtsThreshold return error.\n", __func__);
            return RETURN_ERR;
        }
    }
    if (current_param.obssCoex != operationParam->obssCoex) {
        if (wifi_setRadioObssCoexistenceEnable(index, operationParam->obssCoex) != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setRadioObssCoexistenceEnable return error.\n", __func__);
            return RETURN_ERR;
        }
    }
    if (current_param.stbcEnable != operationParam->stbcEnable) {
        if (wifi_setRadioSTBCEnable(index, operationParam->stbcEnable) != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setRadioSTBCEnable return error.\n", __func__);
            return RETURN_ERR;
        }
    }
    if (current_param.greenFieldEnable != operationParam->greenFieldEnable) {
        if (wifi_setRadio11nGreenfieldEnable(index, operationParam->greenFieldEnable) != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setRadio11nGreenfieldEnable return error.\n", __func__);
            return RETURN_ERR;
        }
    }

    // if enable is true, then restart the radio
    wifi_setRadioEnable(index, FALSE);
    if (operationParam->enable == TRUE)
        wifi_setRadioEnable(index, TRUE);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT wifi_getRadioOperatingParameters(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    char band[64] = {0};
    char buf[256] = {0};
    char config_file[64] = {0};
    char cmd[128] = {0};
    int ret = RETURN_ERR;
    int mode = 0;
    ULONG channel = 0;
    BOOL enabled = FALSE;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    printf("Entering %s index = %d\n", __func__, (int)index);

    memset(operationParam, 0, sizeof(wifi_radio_operationParam_t));
    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, index);
    if (wifi_getRadioEnable(index, &enabled) != RETURN_OK)
    {
        fprintf(stderr, "%s: wifi_getRadioEnable return error.\n", __func__);
        return RETURN_ERR;
    }
    operationParam->enable = enabled;

    memset(band, 0, sizeof(band));
    if (wifi_getRadioOperatingFrequencyBand(index, band) != RETURN_OK)
    {
        fprintf(stderr, "%s: wifi_getRadioOperatingFrequencyBand return error.\n", __func__);
        return RETURN_ERR;
    }

    if (!strcmp(band, "2.4GHz"))
        operationParam->band = WIFI_FREQUENCY_2_4_BAND;
    else if (!strcmp(band, "5GHz"))
        operationParam->band = WIFI_FREQUENCY_5_BAND;
    else if (!strcmp(band, "6GHz"))
        operationParam->band = WIFI_FREQUENCY_6_BAND;
    else
    {
        fprintf(stderr, "%s: cannot decode band for radio index %d ('%s')\n", __func__, index,
            band);
    }

    wifi_hostapdRead(config_file, "channel", buf, sizeof(buf));
    if (strcmp(buf, "0") == 0 || strcmp(buf, "acs_survey") == 0) {
        operationParam->channel = 0;
        operationParam->autoChannelEnabled = TRUE;
    } else {
        operationParam->channel = strtol(buf, NULL, 10);
        operationParam->autoChannelEnabled = FALSE;
    }

    memset(buf, 0, sizeof(buf));
    if (wifi_getRadioOperatingChannelBandwidth(index, buf) != RETURN_OK) {
        fprintf(stderr, "%s: wifi_getRadioOperatingChannelBandwidth return error.\n", __func__);
        return RETURN_ERR;
    }
    if (!strcmp(buf, "20MHz")) operationParam->channelWidth = WIFI_CHANNELBANDWIDTH_20MHZ;
    else if (!strcmp(buf, "40MHz")) operationParam->channelWidth = WIFI_CHANNELBANDWIDTH_40MHZ;
    else if (!strcmp(buf, "80MHz")) operationParam->channelWidth = WIFI_CHANNELBANDWIDTH_80MHZ;
    else if (!strcmp(buf, "160MHz")) operationParam->channelWidth = WIFI_CHANNELBANDWIDTH_160MHZ;
    else if (!strcmp(buf, "320-1MHz")) operationParam->channelWidth = WIFI_CHANNELBANDWIDTH_320_1MHZ;
    else if (!strcmp(buf, "320-2MHz")) operationParam->channelWidth = WIFI_CHANNELBANDWIDTH_320_2MHZ;
    else
    {
        fprintf(stderr, "Unknown channel bandwidth: %s\n", buf);
        return false;
    }

    if (operationParam->band == WIFI_FREQUENCY_6_BAND) {
        UINT tmp_opclass = 0;
        if (wifi_getRadioOpclass(index, &tmp_opclass) != RETURN_OK) {
            fprintf(stderr, "%s: op_class is not set.\n", __func__);
            return RETURN_ERR;
        }
        operationParam->operatingClass = tmp_opclass;
    }

    if (wifi_getRadioMode(index, buf, &mode) != RETURN_OK) {
        fprintf(stderr, "%s: wifi_getRadioMode return error.\n", __func__);
        return RETURN_ERR;
    }
    // Two different definition bit map, so need to check every bit.
    if (mode & WIFI_MODE_A)
        operationParam->variant |= WIFI_80211_VARIANT_A;
    if (mode & WIFI_MODE_B)
        operationParam->variant |= WIFI_80211_VARIANT_B;
    if (mode & WIFI_MODE_G)
        operationParam->variant |= WIFI_80211_VARIANT_G;
    if (mode & WIFI_MODE_N)
        operationParam->variant |= WIFI_80211_VARIANT_N;
    if (mode & WIFI_MODE_AC)
        operationParam->variant |= WIFI_80211_VARIANT_AC;
    if (mode & WIFI_MODE_AX)
        operationParam->variant |= WIFI_80211_VARIANT_AX;
    if (mode & WIFI_MODE_BE)
        operationParam->variant |= WIFI_80211_VARIANT_BE;
    if (wifi_getRadioDCSEnable(index, &operationParam->DCSEnabled) != RETURN_OK) {
        fprintf(stderr, "%s: wifi_getRadioDCSEnable return error.\n", __func__);
        return RETURN_ERR;
    }
    {
        UINT tmp_dtim = 0;
        if (wifi_getApDTIMInterval(index, &tmp_dtim) != RETURN_OK) {
            fprintf(stderr, "%s: wifi_getApDTIMInterval return error.\n", __func__);
            return RETURN_ERR;
        }
        operationParam->dtimPeriod = tmp_dtim;
        if (wifi_getRadioBeaconPeriod(index, &tmp_dtim) != RETURN_OK) {
            fprintf(stderr, "%s: wifi_getRadioBeaconPeriod return error.\n", __func__);
            return RETURN_ERR;
        }
        operationParam->dtimPeriod = tmp_dtim;
    }

    memset(buf, 0, sizeof(buf));
    if (wifi_getRadioSupportedDataTransmitRates(index, buf) != RETURN_OK) {
        fprintf(stderr, "%s: wifi_getRadioSupportedDataTransmitRates return error.\n", __func__);
        return RETURN_ERR;
    }
    {
        UINT tmp_rates = 0;
        TransmitRatesToBitMap(buf, &tmp_rates);
        operationParam->basicDataTransmitRates = tmp_rates;
    }

    memset(buf, 0, sizeof(buf));
    if (wifi_getRadioBasicDataTransmitRates(index, buf) != RETURN_OK) {
        fprintf(stderr, "%s: wifi_getRadioBasicDataTransmitRates return error.\n", __func__);
        return RETURN_ERR;
    }
    {
        UINT tmp_rates = 0;
        TransmitRatesToBitMap(buf, &tmp_rates);
        operationParam->operationalDataTransmitRates = tmp_rates;
    }

    memset(buf, 0, sizeof(buf));
    wifi_hostapdRead(config_file, "fragm_threshold", buf, sizeof(buf));
    operationParam->fragmentationThreshold = strtoul(buf, NULL, 10);

    {
        UINT tmp_gi = 0;
        if (wifi_getGuardInterval(index, &tmp_gi) != RETURN_OK) {
            fprintf(stderr, "%s: wifi_getGuardInterval return error.\n", __func__);
            return RETURN_ERR;
        }
        operationParam->guardInterval = tmp_gi;
    }
    {
        ULONG tmp_txpwr = 0;
        if (wifi_getRadioPercentageTransmitPower(index, &tmp_txpwr) != RETURN_OK) {
            fprintf(stderr, "%s: wifi_getRadioPercentageTransmitPower return error.\n", __func__);
            return RETURN_ERR;
        }
        operationParam->transmitPower = (UINT)tmp_txpwr;
    }

    memset(buf, 0, sizeof(buf));
    wifi_hostapdRead(config_file, "rts_threshold", buf, sizeof(buf));
    if (strcmp(buf, "-1") == 0) {
        operationParam->rtsThreshold = (UINT)-1;    // maxuimum unsigned integer value
        operationParam->ctsProtection = FALSE;
    } else {
        operationParam->rtsThreshold = strtoul(buf, NULL, 10);
        operationParam->ctsProtection = TRUE;
    }

    memset(buf, 0, sizeof(buf));
    wifi_hostapdRead(config_file, "ht_coex", buf, sizeof(buf));
    if (strcmp(buf, "0") == 0)
        operationParam->obssCoex = FALSE;
    else
        operationParam->obssCoex = TRUE;

    snprintf(cmd, sizeof(cmd), "cat %s | grep STBC", config_file);
    _syscmd(cmd, buf, sizeof(buf));
    if (strlen(buf) != 0)
        operationParam->stbcEnable = TRUE;
    else
        operationParam->stbcEnable = FALSE;

    if (wifi_getRadio11nGreenfieldEnable(index, &operationParam->greenFieldEnable) != RETURN_OK) {
        fprintf(stderr, "%s: wifi_getRadio11nGreenfieldEnable return error.\n", __func__);
        return RETURN_ERR;
    }

    // Below value is hardcoded

    operationParam->numSecondaryChannels = 0;
    for (int i = 0; i < MAXNUMSECONDARYCHANNELS; i++) {
        operationParam->channelSecondary[i] = 0;
    }
    operationParam->csa_beacon_count = 15;
    operationParam->countryCode = wifi_countrycode_US;  // hard to convert string to corresponding enum

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

static int array_index_to_vap_index(UINT radioIndex, int arrayIndex)
{
    int max_radio_num = 0;

    wifi_getMaxRadioNumber(&max_radio_num);
    if (radioIndex >= max_radio_num) {
        fprintf(stderr, "%s: Wrong radio index (%d)\n", __func__, radioIndex);
        return RETURN_ERR;
    }

    return (arrayIndex * max_radio_num) + radioIndex;
}

wifi_bitrate_t beaconRate_string_to_enum(char *beaconRate) {
    if (strncmp(beaconRate, "1Mbps", 5) == 0)
        return WIFI_BITRATE_1MBPS;
    else if (strncmp(beaconRate, "2Mbps", 5) == 0)
        return WIFI_BITRATE_2MBPS;
    else if (strncmp(beaconRate, "5.5Mbps", 7) == 0)
        return WIFI_BITRATE_5_5MBPS;
    else if (strncmp(beaconRate, "6Mbps", 5) == 0)
        return WIFI_BITRATE_6MBPS;
    else if (strncmp(beaconRate, "9Mbps", 5) == 0)
        return WIFI_BITRATE_9MBPS;
    else if (strncmp(beaconRate, "11Mbps", 6) == 0)
        return WIFI_BITRATE_11MBPS;
    else if (strncmp(beaconRate, "12Mbps", 6) == 0)
        return WIFI_BITRATE_12MBPS;
    else if (strncmp(beaconRate, "18Mbps", 6) == 0)
        return WIFI_BITRATE_18MBPS;
    else if (strncmp(beaconRate, "24Mbps", 6) == 0)
        return WIFI_BITRATE_24MBPS;
    else if (strncmp(beaconRate, "36Mbps", 6) == 0)
        return WIFI_BITRATE_36MBPS;
    else if (strncmp(beaconRate, "48Mbps", 6) == 0)
        return WIFI_BITRATE_48MBPS;
    else if (strncmp(beaconRate, "54Mbps", 6) == 0)
        return WIFI_BITRATE_54MBPS;
    return WIFI_BITRATE_DEFAULT;
}

INT beaconRate_enum_to_string(wifi_bitrate_t beacon, char *beacon_str)
{
    if (beacon == WIFI_BITRATE_1MBPS)
        strcpy(beacon_str, "1Mbps");
    else if (beacon == WIFI_BITRATE_2MBPS)
        strcpy(beacon_str, "2Mbps");
    else if (beacon == WIFI_BITRATE_5_5MBPS)
        strcpy(beacon_str, "5.5Mbps");
    else if (beacon == WIFI_BITRATE_6MBPS)
        strcpy(beacon_str, "6Mbps");
    else if (beacon == WIFI_BITRATE_9MBPS)
        strcpy(beacon_str, "9Mbps");
    else if (beacon == WIFI_BITRATE_11MBPS)
        strcpy(beacon_str, "11Mbps");
    else if (beacon == WIFI_BITRATE_12MBPS)
        strcpy(beacon_str, "12Mbps");
    else if (beacon == WIFI_BITRATE_18MBPS)
        strcpy(beacon_str, "18Mbps");
    else if (beacon == WIFI_BITRATE_24MBPS)
        strcpy(beacon_str, "24Mbps");
    else if (beacon == WIFI_BITRATE_36MBPS)
        strcpy(beacon_str, "36Mbps");
    else if (beacon == WIFI_BITRATE_48MBPS)
        strcpy(beacon_str, "48Mbps");
    else if (beacon == WIFI_BITRATE_54MBPS)
        strcpy(beacon_str, "54Mbps");
    return RETURN_OK;
}

void checkVapStatus(int apIndex, BOOL *enable)
{
    char if_name[16] = {0};
    char cmd[128] = {0};
    char buf[128] = {0};

    *enable = FALSE;
    if (wifi_GetInterfaceName(apIndex, if_name) != RETURN_OK)
        return;

    snprintf(cmd, sizeof(cmd), "cat %s | grep ^%s=1", VAP_STATUS_FILE, if_name);
    _syscmd(cmd, buf, sizeof(buf));
    if (strlen(buf) > 0)
        *enable = TRUE;
    return;
}

INT wifi_getVapInfoMisc(int vap_index)
{
    char config_file[MAX_BUF_SIZE] = {0};

    sprintf(config_file,"%s%d.conf", CONFIG_PREFIX,vap_index);
    wifi_hostapdRead(config_file,"ssid",vap_info[vap_index].ssid, MAX_BUF_SIZE);
    wifi_hostapdRead(config_file,"wpa", vap_info[vap_index].wpa, MAX_BUF_SIZE);
    wifi_hostapdRead(config_file,"wpa_key_mgmt", vap_info[vap_index].wpa_key_mgmt, MAX_BUF_SIZE);
    wifi_hostapdRead(config_file,"wpa_passphrase", vap_info[vap_index].wpa_passphrase, MAX_BUF_SIZE);
    wifi_hostapdRead(config_file,"ap_isolate", vap_info[vap_index].ap_isolate, MAX_BUF_SIZE);
    wifi_hostapdRead(config_file,"macaddr_acl", vap_info[vap_index].macaddr_acl, MAX_BUF_SIZE);
    wifi_hostapdRead(config_file,"bss_transition", vap_info[vap_index].bss_transition, MAX_BUF_SIZE);
    wifi_hostapdRead(config_file,"ignore_broadcast_ssid", vap_info[vap_index].ignore_broadcast_ssid, MAX_BUF_SIZE);
    wifi_hostapdRead(config_file, "max_num_sta", vap_info[vap_index].max_sta, MAX_BUF_SIZE);
    return RETURN_OK;
}

void *wifi_Syncthread(void *arg)
{
    int radio_idx = 0, i = 0;
    int vap_index = 0;
    int max_radio = 0;

    wifi_getMaxRadioNumber(&max_radio);
    while (1)
    {
        sleep(5);
        for (radio_idx = 0; radio_idx < max_radio; radio_idx++)
        {
            for (i = 0; i < MAX_NUM_VAP_PER_RADIO; i++)
            {
                vap_index = array_index_to_vap_index(radio_idx, i);
                if (vap_index >= 0)
                    wifi_getVapInfoMisc(vap_index);
            }
        }
        syn_flag = 1;
    }
    return NULL;
}

INT wifi_getRadioVapInfoMap(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    INT mode = 0;
    INT ret = -1;
    INT output = 0;
    int i = 0;
    int vap_index = 0;
    BOOL enabled = FALSE;
    char buf[256] = {0};
    wifi_vap_security_t security = {0};


    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    printf("Entering %s index = %d\n", __func__, (int)index);

    for (i = 0; i < MAX_NUM_VAP_PER_RADIO; i++)
    {
        map->vap_array[i].radio_index = index;

        vap_index = array_index_to_vap_index(index, i);
        if (vap_index < 0)
            return RETURN_ERR;

        strcpy(map->vap_array[i].bridge_name, BRIDGE_NAME);

        map->vap_array[i].vap_index = vap_index;

        memset(buf, 0, sizeof(buf));
        ret = wifi_getApName(vap_index, buf);
        if (ret != RETURN_OK) {
            printf("%s: wifi_getApName return error. vap_index=%d\n", __func__, vap_index);

            return RETURN_ERR;
        }
        snprintf(map->vap_array[i].vap_name, sizeof(map->vap_array[i].vap_name), "%s", buf);

        memset(buf, 0, sizeof(buf));
        ret = wifi_getSSIDName(vap_index, buf);
        if (ret != RETURN_OK) {
            printf("%s: wifi_getSSIDName return error\n", __func__);
            return RETURN_ERR;
        }
        snprintf(map->vap_array[i].u.bss_info.ssid, sizeof(map->vap_array[i].u.bss_info.ssid), "%s", buf);

        checkVapStatus(vap_index, &enabled);
        map->vap_array[i].u.bss_info.enabled = enabled;

        ret = wifi_getApSsidAdvertisementEnable(vap_index, &enabled);
        if (ret != RETURN_OK) {
            printf("%s: wifi_getApSsidAdvertisementEnable return error\n", __func__);
            return RETURN_ERR;
        }
        map->vap_array[i].u.bss_info.showSsid = enabled;
        
        ret = wifi_getApIsolationEnable(vap_index, &enabled);
        if (ret != RETURN_OK) {
            printf("%s: wifi_getApIsolationEnable return error\n", __func__);
            return RETURN_ERR;
        }
        map->vap_array[i].u.bss_info.isolation = enabled;

        ret = wifi_getApMaxAssociatedDevices(vap_index, &output);
        if (ret != RETURN_OK) {
            printf("%s: wifi_getApMaxAssociatedDevices return error\n", __func__);
            return RETURN_ERR;
        }
        map->vap_array[i].u.bss_info.bssMaxSta = output;

        ret = wifi_getBSSTransitionActivation(vap_index, &enabled);
        if (ret != RETURN_OK) {
            printf("%s: wifi_getBSSTransitionActivation return error\n", __func__);
            return RETURN_ERR;
        }
        map->vap_array[i].u.bss_info.bssTransitionActivated = enabled;

        ret = wifi_getNeighborReportActivation(vap_index, &enabled);
        if (ret != RETURN_OK) {
            printf("%s: wifi_getNeighborReportActivation return error\n", __func__);
            return RETURN_ERR;
        }
        map->vap_array[i].u.bss_info.nbrReportActivated = enabled;

        ret = wifi_getApSecurity(vap_index, &security);
        if (ret != RETURN_OK) {
            printf("%s: wifi_getApSecurity return error\n", __func__);
            return RETURN_ERR;
        }
        map->vap_array[i].u.bss_info.security = security;

        ret = wifi_getApMacAddressControlMode(vap_index, &mode);
        if (ret != RETURN_OK) {
            printf("%s: wifi_getApMacAddressControlMode return error\n", __func__);
            return RETURN_ERR;
        }
        if (mode == 0) 
            map->vap_array[i].u.bss_info.mac_filter_enable = FALSE;
        else 
            map->vap_array[i].u.bss_info.mac_filter_enable = TRUE;
        if (mode == 1) 
            map->vap_array[i].u.bss_info.mac_filter_mode = wifi_mac_filter_mode_white_list;
        else if (mode == 2) 
            map->vap_array[i].u.bss_info.mac_filter_mode = wifi_mac_filter_mode_black_list;

        ret = wifi_getApWmmEnable(vap_index, &enabled);
        if (ret != RETURN_OK) {
            printf("%s: wifi_getApWmmEnable return error\n", __func__);
            return RETURN_ERR;
        }
        map->vap_array[i].u.bss_info.wmm_enabled = enabled;

        ret = wifi_getApUAPSDCapability(vap_index, &enabled);
        if (ret != RETURN_OK) {
            printf("%s: wifi_getApUAPSDCapability return error\n", __func__);
            return RETURN_ERR;
        }
        map->vap_array[i].u.bss_info.UAPSDEnabled = enabled;

        memset(buf, 0, sizeof(buf));
        ret = wifi_getApBeaconRate(map->vap_array[i].radio_index, buf);
        if (ret != RETURN_OK) {
            printf("%s: wifi_getApBeaconRate return error\n", __func__);
            return RETURN_ERR;
        }
        map->vap_array[i].u.bss_info.beaconRate = beaconRate_string_to_enum(buf);

        memset(buf, 0, sizeof(buf));
        ret = wifi_getBaseBSSID(vap_index, buf);
        if (ret != RETURN_OK) {
            printf("%s: wifi_getBaseBSSID return error\n", __func__);
            return RETURN_ERR;
        }
        sscanf(buf, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &map->vap_array[i].u.bss_info.bssid[0],
            &map->vap_array[i].u.bss_info.bssid[1],
            &map->vap_array[i].u.bss_info.bssid[2],
            &map->vap_array[i].u.bss_info.bssid[3],
            &map->vap_array[i].u.bss_info.bssid[4],
            &map->vap_array[i].u.bss_info.bssid[5]);
        // fprintf(stderr, "%s index %d: mac: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n", __func__, vap_index, map->vap_array[i].u.bss_info.bssid[0], map->vap_array[i].u.bss_info.bssid[1], map->vap_array[i].u.bss_info.bssid[2], map->vap_array[i].u.bss_info.bssid[3], map->vap_array[i].u.bss_info.bssid[4], map->vap_array[i].u.bss_info.bssid[5]);

        ret = wifi_getRadioIGMPSnoopingEnable(map->vap_array[i].radio_index, &enabled);
        if (ret != RETURN_OK) {
            fprintf(stderr, "%s: wifi_getRadioIGMPSnoopingEnable\n", __func__);
            return RETURN_ERR;
        }
        map->vap_array[i].u.bss_info.mcast2ucast = enabled;

        ret = wifi_getApWpsEnable(vap_index, &enabled);
        if (ret != RETURN_OK) {
            fprintf(stderr, "%s: wifi_getApWpsEnable\n", __func__);
            return RETURN_ERR;
        }

        map->vap_array[i].u.bss_info.wps.enable = enabled;

        map->num_vaps++;
        // TODO: wps, noack
    }

    if (!tflag) {
        result = pthread_create(&pthread_id, NULL, wifi_Syncthread,NULL);
        if (result != 0)
            printf("%s %d fail create sync thread\n", __func__, __LINE__);
        else
            tflag = 1;
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}


static int prepareInterface(UINT apIndex, char *new_interface)
{
    char cur_interface[16] = {0};
    char config_file[128] = {0};
    char cmd[128] = {0};
    char buf[16] = {0};
    int max_radio_num = 0;
    int radioIndex = -1;
    int phyIndex = -1;

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, apIndex);
    wifi_hostapdRead(config_file, "interface", cur_interface, sizeof(cur_interface));

    if (strncmp(cur_interface, new_interface, sizeof(cur_interface)) != 0) {
        wifi_getMaxRadioNumber(&max_radio_num);
        radioIndex = apIndex % max_radio_num;
        phyIndex = radio_index_to_phy(radioIndex);
        // disable and del old interface, then add new interface
        wifi_setApEnable(apIndex, FALSE);
        if (!(apIndex/max_radio_num)) {
            if (single_wiphy)
                snprintf(cmd, sizeof(cmd), "iw %s del && iw phy0 interface add %s type __ap radios %d", cur_interface, new_interface, radioIndex);
            else
                snprintf(cmd, sizeof(cmd), "iw %s del && iw phy%d interface add %s type __ap", cur_interface, phyIndex, new_interface);
            _syscmd(cmd, buf, sizeof(buf));
        }
    }
    // update the vap status file
    snprintf(cmd, sizeof(cmd), "sed -i -n -e '/^%s=/!p' -e '$a%s=1' %s", cur_interface, new_interface, VAP_STATUS_FILE);
    _syscmd(cmd, buf, sizeof(buf));
    return RETURN_OK;
}

INT wifi_createVAP(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    char interface_name[16] = {0};
    unsigned int i;
    wifi_vap_info_t *vap_info = NULL;
    int acl_mode;
    int ret = 0;
    char *sec_str = NULL;
    char buf[256] = {0};
    char cmd[128] = {0};
    char config_file[64] = {0};
    char bssid[32] = {0};
    char psk_file[64] = {0};
    BOOL enable = FALSE;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    printf("Entering %s index = %d\n", __func__, (int)index);
    for (i = 0; i < map->num_vaps; i++)
    {
        multiple_set = TRUE;
        vap_info = &map->vap_array[i];

        // Check vap status file to enable multiple ap if the system boot.
        checkVapStatus(vap_info->vap_index, &enable);
        if (vap_info->u.bss_info.enabled == FALSE && enable == FALSE)
            continue;

        fprintf(stderr, "\nCreate VAP for ssid_index=%d (vap_num=%d)\n", vap_info->vap_index, i);

        if (wifi_getApEnable(vap_info->vap_index, &enable) != RETURN_OK)
            enable = FALSE;

        // multi-ap first up need to copy current radio config
        if (vap_info->radio_index != vap_info->vap_index && enable == FALSE) {
            snprintf(cmd, sizeof(cmd), "cp %s%d.conf %s%d.conf", CONFIG_PREFIX, vap_info->radio_index, CONFIG_PREFIX, vap_info->vap_index);
            _syscmd(cmd, buf, sizeof(buf));
            if (strlen(vap_info->vap_name) == 0)    // default name of the interface is wifiX
                snprintf(vap_info->vap_name, 16, "wifi%d", vap_info->vap_index);
        } else {
            // Check whether the interface name is valid or this ap change it.
            int apIndex = -1;
            wifi_getApIndexFromName(vap_info->vap_name, &apIndex);
            if (apIndex != -1 && apIndex != vap_info->vap_index)
                continue;
            prepareInterface(vap_info->vap_index, vap_info->vap_name);
        }

        struct params params[3];
        params[0].name = "interface";
        params[0].value = vap_info->vap_name;
        mac_addr_ntoa(bssid, vap_info->u.bss_info.bssid);
        params[1].name = "bssid";
        params[1].value = bssid;
        snprintf(psk_file, sizeof(psk_file), "/nvram/hostapd%d.psk", vap_info->vap_index);
        params[2].name = "wpa_psk_file";
        params[2].value = psk_file;

        sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, vap_info->vap_index);
        wifi_hostapdWrite(config_file, params, 3);

        snprintf(cmd, sizeof(cmd), "touch %s", psk_file);
        _syscmd(cmd, buf, sizeof(buf));

        ret = wifi_setSSIDName(vap_info->vap_index, vap_info->u.bss_info.ssid);
        if (ret != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setSSIDName return error\n", __func__);
            return RETURN_ERR;
        }

        ret = wifi_setApSsidAdvertisementEnable(vap_info->vap_index, vap_info->u.bss_info.showSsid);
        if (ret != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setApSsidAdvertisementEnable return error\n", __func__);
            return RETURN_ERR;
        }

        ret = wifi_setApIsolationEnable(vap_info->vap_index, vap_info->u.bss_info.isolation);
        if (ret != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setApIsolationEnable return error\n", __func__);
            return RETURN_ERR;
        }

        ret = wifi_setApMaxAssociatedDevices(vap_info->vap_index, vap_info->u.bss_info.bssMaxSta);
        if (ret != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setApMaxAssociatedDevices return error\n", __func__);
            return RETURN_ERR;
        }

        ret = wifi_setBSSTransitionActivation(vap_info->vap_index, vap_info->u.bss_info.bssTransitionActivated);
        if (ret != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setBSSTransitionActivation return error\n", __func__);
            return RETURN_ERR;
        }

        ret = wifi_setNeighborReportActivation(vap_info->vap_index, vap_info->u.bss_info.nbrReportActivated);
        if (ret != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setNeighborReportActivation return error\n", __func__);
            return RETURN_ERR;
        }

        if (vap_info->u.bss_info.mac_filter_enable == false){
            acl_mode = 0;
        }else {
            if (vap_info->u.bss_info.mac_filter_mode == wifi_mac_filter_mode_black_list){
                acl_mode = 2;
                snprintf(cmd, sizeof(cmd), "touch %s%d", DENY_PREFIX, vap_info->vap_index);
                _syscmd(cmd, buf, sizeof(buf));
            }else{
                acl_mode = 1;
            }
        }

        ret = wifi_setApWmmEnable(vap_info->vap_index, vap_info->u.bss_info.wmm_enabled);
        if (ret != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setApWmmEnable return error\n", __func__);
            return RETURN_ERR;
        }

        ret = wifi_setApWmmUapsdEnable(vap_info->vap_index, vap_info->u.bss_info.UAPSDEnabled);
        if (ret != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setApWmmUapsdEnable return error\n", __func__);
            return RETURN_ERR;
        }

        memset(buf, 0, sizeof(buf));
        beaconRate_enum_to_string(vap_info->u.bss_info.beaconRate, buf);
        // fprintf(stderr, "%s: beaconrate: %d, buf: %s\n", __func__, vap_info->u.bss_info.beaconRate, buf);
        ret = wifi_setApBeaconRate(vap_info->radio_index, buf);
        if (ret != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setApBeaconRate return error\n", __func__);
            return RETURN_ERR;
        }

        ret = wifi_setApSecurity(vap_info->vap_index, &vap_info->u.bss_info.security);
        if (ret != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setApSecurity return error\n", __func__);
            return RETURN_ERR;
        }

        ret = wifi_setApMacAddressControlMode(vap_info->vap_index, acl_mode);
        if (ret != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setApMacAddressControlMode return error\n", __func__);
            return RETURN_ERR;
        }

        ret = wifi_setApWpsEnable(vap_info->vap_index, vap_info->u.bss_info.wps.enable);
        if (ret != RETURN_OK) {
            fprintf(stderr, "%s: wifi_setApWpsEnable return error\n", __func__);
            return RETURN_ERR;
        }

        wifi_setApEnable(vap_info->vap_index, FALSE);
        if (vap_info->u.bss_info.enabled == TRUE)
            wifi_setApEnable(vap_info->vap_index, TRUE);

        multiple_set = FALSE;

        // If config use hostapd_cli to set, we calling these type of functions after enable the ap.
        if (vap_info->u.bss_info.wps.enable && vap_info->u.bss_info.wps.methods && WIFI_ONBOARDINGMETHODS_PUSHBUTTON) {
            // The set wps methods function should check whether wps is configured.
            ret = wifi_setApWpsButtonPush(vap_info->vap_index);
            if (ret != RETURN_OK) {
                fprintf(stderr, "%s: wifi_setApWpsButtonPush return error\n", __func__);
                return RETURN_ERR;
            }
            // wifi_setApWpsConfigMethodsEnabled only write to config.
            ret = wifi_setApWpsConfigMethodsEnabled(vap_info->vap_index, "PushButton");
            if (ret != RETURN_OK) {
                fprintf(stderr, "%s: wifi_setApWpsConfigMethodsEnabled return error\n", __func__);
                return RETURN_ERR;
            }
        }

        // TODO mgmtPowerControl, interworking
    }

	// IGMP Snooping enable should be placed after all hostapd_reload.
	if (vap_info == NULL)
		return RETURN_ERR;
	ret = wifi_setRadioIGMPSnoopingEnable(vap_info->radio_index, vap_info->u.bss_info.mcast2ucast);
	if (ret != RETURN_OK) {
		fprintf(stderr, "%s: wifi_setRadioIGMPSnoopingEnable return error\n", __func__);
		return RETURN_ERR;
	}

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

int parse_channel_list_int_arr(char *pchannels, wifi_channels_list_t* chlistptr)
{
    char *token, *next;
    const char s[2] = ",";
    int count =0;

    /* get the first token */
    token = strtok_r(pchannels, s, &next);

    /* walk through other tokens */
    while( token != NULL && count < MAX_CHANNELS) {
        chlistptr->channels_list[count++] = atoi(token);
        token = strtok_r(NULL, s, &next);
    }

    return count;
}

static int getRadioCapabilities(int radioIndex, wifi_radio_capabilities_t *rcap)
{
    INT status;
    wifi_channels_list_t *chlistp;
    CHAR output_string[64];
    CHAR pchannels[128];
    CHAR interface_name[16] = {0};
    wifi_band band;

    if(rcap == NULL)
    {
        return RETURN_ERR;
    }

    rcap->numSupportedFreqBand = 1;
    band = wifi_index_to_band(radioIndex);

    if (band == band_2_4)
        rcap->band[0] = WIFI_FREQUENCY_2_4_BAND;
    else if (band == band_5)
        rcap->band[0] = WIFI_FREQUENCY_5_BAND;
    else if (band == band_6)
        rcap->band[0] = WIFI_FREQUENCY_6_BAND;

    chlistp = &(rcap->channel_list[0]);
    memset(pchannels, 0, sizeof(pchannels));

    /* possible number of radio channels */
    status = wifi_getRadioPossibleChannels(radioIndex, pchannels);
    {
         printf("[wifi_hal dbg] : func[%s] line[%d] error_ret[%d] radio_index[%d] output[%s]\n", __FUNCTION__, __LINE__, status, radioIndex, pchannels);
    }
    /* Number of channels and list*/
    chlistp->num_channels = parse_channel_list_int_arr(pchannels, chlistp);

    /* autoChannelSupported */
    /* always ON with wifi_getRadioAutoChannelSupported */
    rcap->autoChannelSupported = TRUE;

    /* DCSSupported */
    /* always ON with wifi_getRadioDCSSupported */
    rcap->DCSSupported = TRUE;

    /* zeroDFSSupported - TBD */
    rcap->zeroDFSSupported = FALSE;

    /* Supported Country List*/
    memset(output_string, 0, sizeof(output_string));
    status = wifi_getRadioCountryCode(radioIndex, output_string);
    if( status != 0 ) {
        printf("[wifi_hal dbg] : func[%s] line[%d] error_ret[%d] radio_index[%d] output[%s]\n", __FUNCTION__, __LINE__, status, radioIndex, output_string);
        return RETURN_ERR;
    } else {
        printf("[wifi_hal dbg] : func[%s] line[%d], output [%s]\n", __FUNCTION__, __LINE__, output_string);
    }
    if(!strcmp(output_string,"US")){
        rcap->countrySupported[0] = wifi_countrycode_US;
        rcap->countrySupported[1] = wifi_countrycode_CA;
    } else if (!strcmp(output_string,"CA")) {
        rcap->countrySupported[0] = wifi_countrycode_CA;
        rcap->countrySupported[1] = wifi_countrycode_US;
    } else {
        printf("[wifi_hal dbg] : func[%s] line[%d] radio_index[%d] Invalid Country [%s]\n", __FUNCTION__, __LINE__, radioIndex, output_string);
    }

    rcap->numcountrySupported = 2;

    /* csi */
    rcap->csi.maxDevices = 8;
    rcap->csi.soudingFrameSupported = TRUE;

    wifi_GetInterfaceName(radioIndex, interface_name);
    snprintf(rcap->ifaceName, sizeof(interface_name), "%s",interface_name);

    /* channelWidth - all supported bandwidths */
    int i=0;
    rcap->channelWidth[i] = 0;

    /* mode - all supported variants */
    // rcap->mode[i] = WIFI_80211_VARIANT_H;
    wifi_getRadioSupportedStandards(radioIndex, output_string);

    if (rcap->band[i] & WIFI_FREQUENCY_2_4_BAND) {
        rcap->channelWidth[i] |= (WIFI_CHANNELBANDWIDTH_20MHZ |
                                WIFI_CHANNELBANDWIDTH_40MHZ);
        rcap->mode[i] = ( WIFI_80211_VARIANT_B | WIFI_80211_VARIANT_G);

        if (strstr(output_string, "n") != NULL)
            rcap->mode[i] |= WIFI_80211_VARIANT_N;
        if (strstr(output_string, "ax") != NULL)
            rcap->mode[i] |= WIFI_80211_VARIANT_AX;
        if (strstr(output_string, "be") != NULL)
            rcap->mode[i] |= WIFI_80211_VARIANT_BE;
    } else if (rcap->band[i] & WIFI_FREQUENCY_5_BAND) {
        rcap->channelWidth[i] |= (WIFI_CHANNELBANDWIDTH_20MHZ |
                                WIFI_CHANNELBANDWIDTH_40MHZ |
                                WIFI_CHANNELBANDWIDTH_80MHZ | WIFI_CHANNELBANDWIDTH_160MHZ);
        rcap->mode[i] = ( WIFI_80211_VARIANT_A);

        if (strstr(output_string, "n") != NULL)
            rcap->mode[i] |= WIFI_80211_VARIANT_N;
        if (strstr(output_string, "ac") != NULL)
            rcap->mode[i] |= WIFI_80211_VARIANT_AC;
        if (strstr(output_string, "ax") != NULL)
            rcap->mode[i] |= WIFI_80211_VARIANT_AX;
        if (strstr(output_string, "be") != NULL)
            rcap->mode[i] |= WIFI_80211_VARIANT_BE;
    } else if (rcap->band[i] & WIFI_FREQUENCY_6_BAND) {
        rcap->channelWidth[i] |= (WIFI_CHANNELBANDWIDTH_20MHZ |
                                WIFI_CHANNELBANDWIDTH_40MHZ |
                                WIFI_CHANNELBANDWIDTH_80MHZ | WIFI_CHANNELBANDWIDTH_160MHZ);
        rcap->mode[i] = ( WIFI_80211_VARIANT_AX );

        if (strstr(output_string, "be") != NULL) {
            rcap->mode[i] |= WIFI_80211_VARIANT_BE;
            rcap->channelWidth[i] |= WIFI_CHANNELBANDWIDTH_320_1MHZ | WIFI_CHANNELBANDWIDTH_320_2MHZ;
        }
    }

    rcap->maxBitRate[i] = ( rcap->band[i] & WIFI_FREQUENCY_2_4_BAND ) ? 300 :
        ((rcap->band[i] & WIFI_FREQUENCY_5_BAND) ? 1734 : 0);

    /* supportedBitRate - all supported bitrates */
    rcap->supportedBitRate[i] = 0;
    if (rcap->band[i] & WIFI_FREQUENCY_2_4_BAND) {
        rcap->supportedBitRate[i] |= (WIFI_BITRATE_6MBPS | WIFI_BITRATE_9MBPS |
                                    WIFI_BITRATE_11MBPS | WIFI_BITRATE_12MBPS);
    }
    else if (rcap->band[i] & (WIFI_FREQUENCY_5_BAND ) | rcap->band[i] & (WIFI_FREQUENCY_6_BAND )) {
        rcap->supportedBitRate[i] |= (WIFI_BITRATE_6MBPS | WIFI_BITRATE_9MBPS |
                                    WIFI_BITRATE_12MBPS | WIFI_BITRATE_18MBPS | WIFI_BITRATE_24MBPS |
                                    WIFI_BITRATE_36MBPS | WIFI_BITRATE_48MBPS | WIFI_BITRATE_54MBPS);
    }


    rcap->transmitPowerSupported_list[i].numberOfElements = 5;
    rcap->transmitPowerSupported_list[i].transmitPowerSupported[0]=12;
    rcap->transmitPowerSupported_list[i].transmitPowerSupported[1]=25;
    rcap->transmitPowerSupported_list[i].transmitPowerSupported[2]=50;
    rcap->transmitPowerSupported_list[i].transmitPowerSupported[3]=75;
    rcap->transmitPowerSupported_list[i].transmitPowerSupported[4]=100;
    rcap->cipherSupported = 0;
    rcap->cipherSupported |= WIFI_CIPHER_CAPA_ENC_TKIP | WIFI_CIPHER_CAPA_ENC_CCMP;
    rcap->maxNumberVAPs = MAX_NUM_VAP_PER_RADIO;

    return RETURN_OK;
}

INT wifi_getHalCapability(wifi_hal_capability_t *cap)
{
    INT status = 0, radioIndex = 0;
    char cmd[MAX_BUF_SIZE] = {0}, output[MAX_BUF_SIZE] = {0};
    int iter = 0;
    unsigned int j = 0;
    int max_num_radios;
    wifi_interface_name_idex_map_t *iface_info = NULL;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    memset(cap, 0, sizeof(wifi_hal_capability_t));

    /* version */
    cap->version.major = WIFI_HAL_MAJOR_VERSION;
    cap->version.minor = WIFI_HAL_MINOR_VERSION;

    /* number of radios platform property */
    wifi_getMaxRadioNumber(&max_num_radios);
    cap->wifi_prop.numRadios = max_num_radios;

    for(radioIndex=0; radioIndex < cap->wifi_prop.numRadios; radioIndex++)
    {
        status = getRadioCapabilities(radioIndex, &(cap->wifi_prop.radiocap[radioIndex]));
        if (status != 0) {
            printf("%s: getRadioCapabilities idx = %d\n", __FUNCTION__, radioIndex);
            return RETURN_ERR;
        }

        for (j = 0; j < cap->wifi_prop.radiocap[radioIndex].maxNumberVAPs; j++)
        {
            if (iter >= MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO)
            {
                 printf("%s: to many vaps for index map (%d)\n", __func__, iter);
                 return RETURN_ERR;
            }
            iface_info = &cap->wifi_prop.interface_map[iter];
            iface_info->phy_index = radioIndex; // XXX: parse phyX index instead
            iface_info->rdk_radio_index = radioIndex;
            memset(output, 0, sizeof(output));
            if (wifi_getRadioIfName(radioIndex, output) == RETURN_OK)
            {
                strncpy(iface_info->interface_name, output, sizeof(iface_info->interface_name) - 1);
            }
            // TODO: bridge name
            // TODO: vlan id
            // TODO: primary
            iface_info->index = array_index_to_vap_index(radioIndex, j);
            memset(output, 0, sizeof(output));
            if (wifi_getApName(iface_info->index, output) == RETURN_OK)
            {
                 strncpy(iface_info->vap_name, output, sizeof(iface_info->vap_name) - 1);
            }
	    iter++;
        }
    }

    cap->BandSteeringSupported = FALSE;
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

INT wifi_setOpportunisticKeyCaching(int ap_index, BOOL okc_enable)
{
    struct params h_config={0};
    char config_file[64] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

    h_config.name = "okc";
    h_config.value = okc_enable?"1":"0";

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, ap_index);
    wifi_hostapdWrite(config_file, &h_config, 1);
    wifi_hostapdProcessUpdate(ap_index, &h_config, 1);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
    return RETURN_OK;
}

INT wifi_setSAEMFP(int ap_index, BOOL enable)
{
    struct params h_config={0};
    char config_file[64] = {0};
    char buf[128] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

    h_config.name = "sae_require_mfp";
    h_config.value = enable?"1":"0";

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, ap_index);
    wifi_hostapdWrite(config_file, &h_config, 1);
    wifi_hostapdProcessUpdate(ap_index, &h_config, 1);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
    return RETURN_OK;
}

INT wifi_setSAEpwe(int ap_index, int sae_pwe)
{
    struct params h_config={0};
    char config_file[64] = {0};
    char buf[128] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

    h_config.name = "sae_pwe";
    snprintf(buf, sizeof(buf), "%d", sae_pwe);
    h_config.value = buf;

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, ap_index);
    wifi_hostapdWrite(config_file, &h_config, 1);
    wifi_hostapdProcessUpdate(ap_index, &h_config, 1);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
    return RETURN_OK;
}

INT wifi_setDisable_EAPOL_retries(int ap_index, BOOL disable_EAPOL_retries)
{
    // wpa3 use SAE instead of PSK, so we need to disable this feature when using wpa3.
    struct params h_config={0};
    char config_file[64] = {0};

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n", __func__, __LINE__);

    h_config.name = "wpa_disable_eapol_key_retries";
    h_config.value = disable_EAPOL_retries?"1":"0";

    snprintf(config_file, sizeof(config_file), "%s%d.conf", CONFIG_PREFIX, ap_index);
    wifi_hostapdWrite(config_file, &h_config, 1);
    wifi_hostapdProcessUpdate(ap_index, &h_config, 1);

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n", __func__, __LINE__);
    return RETURN_OK;
}

INT wifi_setApSecurity(INT ap_index, wifi_vap_security_t *security)
{
    char buf[128] = {0};
    char config_file[128] = {0};
    char cmd[128] = {0};
    char password[64] = {0};
    char mfp[32] = {0};
    char wpa_mode[32] = {0};
    BOOL okc_enable = FALSE;
    BOOL sae_MFP = FALSE;
    BOOL disable_EAPOL_retries = TRUE;
    int sae_pwe = 0;
    struct params params = {0};
    wifi_band band = band_invalid;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    multiple_set = TRUE;
    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, ap_index);
    if (security->mode == wifi_security_mode_none) {
        strcpy(wpa_mode, "None");
    } else if (security->mode == wifi_security_mode_wpa_personal)
        strcpy(wpa_mode, "WPA-Personal");
    else if (security->mode == wifi_security_mode_wpa2_personal)
        strcpy(wpa_mode, "WPA2-Personal");
    else if (security->mode == wifi_security_mode_wpa_wpa2_personal)
        strcpy(wpa_mode, "WPA-WPA2-Personal");
    else if (security->mode == wifi_security_mode_wpa_enterprise)
        strcpy(wpa_mode, "WPA-Enterprise");
    else if (security->mode == wifi_security_mode_wpa2_enterprise)
        strcpy(wpa_mode, "WPA2-Enterprise");
    else if (security->mode == wifi_security_mode_wpa_wpa2_enterprise)
        strcpy(wpa_mode, "WPA-WPA2-Enterprise");
    else if (security->mode == wifi_security_mode_wpa3_personal) {
        strcpy(wpa_mode, "WPA3-Personal");
        okc_enable = TRUE;
        sae_MFP = TRUE;
        sae_pwe = 2;
        disable_EAPOL_retries = FALSE;
    } else if (security->mode == wifi_security_mode_wpa3_transition) {
        strcpy(wpa_mode, "WPA3-Personal-Transition");
        okc_enable = TRUE;
        sae_MFP = TRUE;
        sae_pwe = 2;
        disable_EAPOL_retries = FALSE;
    } else if (security->mode == wifi_security_mode_wpa3_enterprise) {
        strcpy(wpa_mode, "WPA3-Enterprise");
        sae_MFP = TRUE;
        sae_pwe = 2;
        disable_EAPOL_retries = FALSE;
    } else if (security->mode == wifi_security_mode_enhanced_open) {
        strcpy(wpa_mode, "OWE");
        sae_MFP = TRUE;
        sae_pwe = 2;
        disable_EAPOL_retries = FALSE;
    }

    band = wifi_index_to_band(ap_index);
    if (band == band_6 && strstr(wpa_mode, "WPA3") == NULL) {
        fprintf(stderr, "%s: 6G band must set with wpa3.\n", __func__);
        return RETURN_ERR;
    }

    wifi_setApSecurityModeEnabled(ap_index, wpa_mode);
    wifi_setOpportunisticKeyCaching(ap_index, okc_enable);
    wifi_setSAEMFP(ap_index, sae_MFP);
    wifi_setSAEpwe(ap_index, sae_pwe);
    wifi_setDisable_EAPOL_retries(ap_index, disable_EAPOL_retries);

    if (security->mode != wifi_security_mode_none && security->mode != wifi_security_mode_enhanced_open) {
        if (security->u.key.type == wifi_security_key_type_psk || security->u.key.type == wifi_security_key_type_pass || security->u.key.type == wifi_security_key_type_psk_sae) {
            int key_len = strlen(security->u.key.key);
            // wpa_psk and wpa_passphrase cann;t use at the same time, the command replace one with the other.
            if (key_len == 64) {    // set wpa_psk
                strncpy(password, security->u.key.key, 63);
                password[63] = '\0';
                wifi_setApSecurityPreSharedKey(ap_index, password);
                snprintf(cmd, sizeof(cmd), "sed -i -n -e '/^wpa_passphrase=/!p' %s", config_file);
            } else if (key_len >= 8 && key_len < 64) {  // set wpa_passphrase
                strncpy(password, security->u.key.key, 63);
                password[63] = '\0';
                wifi_setApSecurityKeyPassphrase(ap_index, password);
                snprintf(cmd, sizeof(cmd), "sed -i -n -e '/^wpa_psk=/!p' %s", config_file);
            } else
                return RETURN_ERR;
            _syscmd(cmd, buf, sizeof(buf));
        }
        if (security->u.key.type == wifi_security_key_type_sae || security->u.key.type == wifi_security_key_type_psk_sae) {
            params.name = "sae_password";
            params.value = security->u.key.key;
            wifi_hostapdWrite(config_file, &params, 1);
        } else {    // remove sae_password
            snprintf(cmd, sizeof(cmd), "sed -i -n -e '/^sae_password=/!p' %s", config_file);
            _syscmd(cmd, buf, sizeof(buf));
        }
    }

    if (security->mode != wifi_security_mode_none) {
        memset(&params, 0, sizeof(params));
        params.name = "wpa_pairwise";
        if (security->encr == wifi_encryption_tkip)
            params.value = "TKIP";
        else if (security->encr == wifi_encryption_aes)
            params.value = "CCMP";
        else if (security->encr == wifi_encryption_aes_tkip)
            params.value = "TKIP CCMP";
        wifi_hostapdWrite(config_file, &params, 1);

        /* rsn_pairwise need to be updated too */
        params.name = "rsn_pairwise";
        wifi_hostapdWrite(config_file, &params, 1);
    }

    if (security->mfp == wifi_mfp_cfg_disabled)
        strcpy(mfp, "Disabled");
    else if (security->mfp == wifi_mfp_cfg_optional)
        strcpy(mfp, "Optional");
    else if (security->mfp == wifi_mfp_cfg_required)
        strcpy(mfp, "Required");
    wifi_setApSecurityMFPConfig(ap_index, mfp);

    memset(&params, 0, sizeof(params));
    params.name = "transition_disable";
    if (security->wpa3_transition_disable == TRUE)
        params.value = "0x01";
    else
        params.value = "0x00";
    wifi_hostapdWrite(config_file, &params, 1);

    memset(&params, 0, sizeof(params));
    params.name = "wpa_group_rekey";
    snprintf(buf, sizeof(buf), "%d", security->rekey_interval);
    params.value = buf;
    wifi_hostapdWrite(config_file, &params, 1);

    memset(&params, 0, sizeof(params));
    params.name = "wpa_strict_rekey";
    params.value = security->strict_rekey?"1":"0";
    wifi_hostapdWrite(config_file, &params, 1);

    memset(&params, 0, sizeof(params));
    params.name = "wpa_pairwise_update_count";
    if (security->eapol_key_retries == 0)
        security->eapol_key_retries = 4;    // 0 is invalid, set to default value.
    snprintf(buf, sizeof(buf), "%u", security->eapol_key_retries);
    params.value = buf;
    wifi_hostapdWrite(config_file, &params, 1);

    memset(&params, 0, sizeof(params));
    params.name = "disable_pmksa_caching";
    params.value = security->disable_pmksa_caching?"1":"0";
    wifi_hostapdWrite(config_file, &params, 1);

    if (multiple_set == FALSE) {
        wifi_setApEnable(ap_index, FALSE);
        wifi_setApEnable(ap_index, TRUE);
    }

    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);

    return RETURN_OK;
}

INT wifi_getApSecurity(INT ap_index, wifi_vap_security_t *security)
{
    char buf[256] = {0};
    char config_file[128] = {0};
    int disable = 0;
    bool set_sae = FALSE;
    wifi_encryption_method_t wpa_pairwise = 0, rsn_pairwise = 0;

    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);
    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, ap_index);
    wifi_getApSecurityModeEnabled(ap_index, buf);   // Get wpa config
    security->mode = wifi_security_mode_none;
    if (strlen(buf) != 0) {
        if (!strcmp(buf, "WPA-Personal"))
            security->mode = wifi_security_mode_wpa_personal;
        else if (!strcmp(buf, "WPA2-Personal"))
            security->mode = wifi_security_mode_wpa2_personal;
        else if (!strcmp(buf, "WPA-WPA2-Personal"))
            security->mode = wifi_security_mode_wpa_wpa2_personal;
        else if (!strcmp(buf, "WPA-Enterprise"))
            security->mode = wifi_security_mode_wpa_enterprise;
        else if (!strcmp(buf, "WPA2-Enterprise"))
            security->mode = wifi_security_mode_wpa2_enterprise;
        else if (!strcmp(buf, "WPA-WPA2-Enterprise"))
            security->mode = wifi_security_mode_wpa_wpa2_enterprise;
        else if (!strcmp(buf, "WPA3-Personal"))
            security->mode = wifi_security_mode_wpa3_personal;
        else if (!strcmp(buf, "WPA3-Personal-Transition"))
            security->mode = wifi_security_mode_wpa3_transition;
        else if (!strcmp(buf, "WPA3-Enterprise"))
            security->mode = wifi_security_mode_wpa3_enterprise;
        else if (!strcmp(buf, "OWE"))
            security->mode = wifi_security_mode_enhanced_open;
    }

    if (security->mode == wifi_security_mode_none)
        security->encr = wifi_encryption_none;
    else {
        wifi_hostapdRead(config_file,"wpa_pairwise",buf,sizeof(buf));
        if (strlen(buf) > 0) {
            if (strcmp(buf, "TKIP") == 0)
                wpa_pairwise = wifi_encryption_tkip;
            else if (strcmp(buf, "CCMP") == 0)
                wpa_pairwise = wifi_encryption_aes;
            else
                wpa_pairwise = wifi_encryption_aes_tkip;
        }

        wifi_hostapdRead(config_file,"rsn_pairwise",buf,sizeof(buf));
        if (strlen(buf) > 0) {
            if (strcmp(buf, "TKIP") == 0)
                rsn_pairwise = wifi_encryption_tkip;
            else if (strcmp(buf, "CCMP") == 0)
                rsn_pairwise = wifi_encryption_aes;
            else
                rsn_pairwise = wifi_encryption_aes_tkip;
        }

        security->encr = wpa_pairwise | rsn_pairwise;
    }

    if (security->mode != wifi_encryption_none) {
        memset(buf, 0, sizeof(buf));
        // wpa3 can use one or both configs as password, so we check sae_password first.
        wifi_hostapdRead(config_file, "sae_password", buf, sizeof(buf));
        if (strlen(buf) != 0) {
            if (security->mode == wifi_security_mode_wpa3_personal || security->mode == wifi_security_mode_wpa3_transition)
                security->u.key.type = wifi_security_key_type_sae;
            set_sae = TRUE;
            strncpy(security->u.key.key, buf, sizeof(buf));
        }
        wifi_hostapdRead(config_file, "wpa_passphrase", buf, sizeof(buf));
        if (strlen(buf) != 0){
            if (set_sae == TRUE)
                security->u.key.type = wifi_security_key_type_psk_sae;
            else if (strlen(buf) == 64)
                security->u.key.type = wifi_security_key_type_psk;
            else
                security->u.key.type = wifi_security_key_type_pass;
            strncpy(security->u.key.key, buf, sizeof(security->u.key.key));
        }
        security->u.key.key[255] = '\0';
    }

    memset(buf, 0, sizeof(buf));
    wifi_getApSecurityMFPConfig(ap_index, buf);
    if (strcmp(buf, "Disabled") == 0)
        security->mfp = wifi_mfp_cfg_disabled;
    else if (strcmp(buf, "Optional") == 0)
        security->mfp = wifi_mfp_cfg_optional;
    else if (strcmp(buf, "Required") == 0)
        security->mfp = wifi_mfp_cfg_required;

    memset(buf, 0, sizeof(buf));
    security->wpa3_transition_disable = FALSE;
    wifi_hostapdRead(config_file, "transition_disable", buf, sizeof(buf));
    disable = strtol(buf, NULL, 16);
    if (disable != 0)
        security->wpa3_transition_disable = TRUE;

    memset(buf, 0, sizeof(buf));
    wifi_hostapdRead(config_file, "wpa_group_rekey", buf, sizeof(buf));
    if (strlen(buf) == 0)
        security->rekey_interval = 86400;
    else
        security->rekey_interval = strtol(buf, NULL, 10);

    memset(buf, 0, sizeof(buf));
    wifi_hostapdRead(config_file, "wpa_strict_rekey", buf, sizeof(buf));
    if (strlen(buf) == 0)
        security->strict_rekey = 0;
    else
        security->strict_rekey = strtol(buf, NULL, 10);

    memset(buf, 0, sizeof(buf));
    wifi_hostapdRead(config_file, "wpa_pairwise_update_count", buf, sizeof(buf));
    if (strlen(buf) == 0)
        security->eapol_key_retries = 4;
    else
        security->eapol_key_retries = strtol(buf, NULL, 10);

    memset(buf, 0, sizeof(buf));
    wifi_hostapdRead(config_file, "disable_pmksa_caching", buf, sizeof(buf));
    if (strlen(buf) == 0)
        security->disable_pmksa_caching = FALSE;
    else
        security->disable_pmksa_caching = strtol(buf, NULL, 10)?TRUE:FALSE;

    /* TODO
    eapol_key_timeout, eap_identity_req_timeout, eap_identity_req_retries, eap_req_timeout, eap_req_retries
    */
    security->eapol_key_timeout = 1000; // Unit is ms. The default value in protocol.
    security->eap_identity_req_timeout = 0;
    security->eap_identity_req_retries = 0;
    security->eap_req_timeout = 0;
    security->eap_req_retries = 0;
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}

#endif /* WIFI_HAL_VERSION_3 */

#ifdef WIFI_HAL_VERSION_3_PHASE2
INT wifi_getApAssociatedDevice(INT ap_index, mac_address_t *output_deviceMacAddressArray, UINT maxNumDevices, UINT *output_numDevices)
{
    char interface_name[16] = {0};
    char cmd[128] = {0};
    char buf[128] = {0};
    char *mac_addr = NULL;
    BOOL status = FALSE;
    size_t len = 0;

    if(ap_index > MAX_APS)
        return RETURN_ERR;

    *output_numDevices = 0;
    wifi_getApEnable(ap_index, &status);
    if (status == FALSE)
        return RETURN_OK;

    if (wifi_GetInterfaceName(ap_index, interface_name) != RETURN_OK)
        return RETURN_ERR;
    sprintf(cmd, "hostapd_cli -i %s list_sta", interface_name);
    _syscmd(cmd, buf, sizeof(buf));

    mac_addr = strtok(buf, "\n");
    for (int i = 0; i < maxNumDevices && mac_addr != NULL; i++) {
        *output_numDevices = i + 1;
        fprintf(stderr, "mac_addr: %s\n", mac_addr);
        addr_ptr = output_deviceMacAddressArray[i];
        mac_addr_aton(addr_ptr, mac_addr);
        mac_addr = strtok(NULL, "\n");
    }

    return RETURN_OK;
}
#else
INT wifi_getApAssociatedDevice(INT ap_index, CHAR *output_buf, INT output_buf_size)
{
    char interface_name[16] = {0};
    char cmd[128];
    BOOL status = false;

    if(ap_index > MAX_APS || output_buf == NULL || output_buf_size <= 0)
        return RETURN_ERR;

    output_buf[0] = '\0';

    wifi_getApEnable(ap_index,&status);
    if (!status)
        return RETURN_OK;

    if (wifi_GetInterfaceName(ap_index, interface_name) != RETURN_OK)
        return RETURN_ERR;
    sprintf(cmd, "hostapd_cli -i %s list_sta | tr '\\n' ',' | sed 's/.$//'", interface_name);
    _syscmd(cmd, output_buf, output_buf_size);
    
    return RETURN_OK;
}
#endif

INT wifi_getProxyArp(INT apIndex, BOOL *enable)
{
    char output[16]={'\0'};
    char config_file[MAX_BUF_SIZE] = {0};

    if (!enable)
        return RETURN_ERR;

    sprintf(config_file, "%s%d.conf", CONFIG_PREFIX, apIndex);
    wifi_hostapdRead(config_file, "proxy_arp", output, sizeof(output));

    if (strlen(output) == 0)
        *enable = FALSE;
    else if (strncmp(output, "1", 1) == 0)
        *enable = TRUE;
    else
        *enable = FALSE;

    wifi_dbg_printf("\n[%s]: proxy_arp is : %s", __func__, output);
    return RETURN_OK;
}

INT wifi_getRadioStatsEnable(INT radioIndex, BOOL *output_enable)
{
    if (NULL == output_enable || radioIndex >=MAX_NUM_RADIOS)
        return RETURN_ERR;
    *output_enable=TRUE;
    return RETURN_OK;
}

INT wifi_getTWTsessions(INT ap_index, UINT maxNumberSessions, wifi_twt_sessions_t *twtSessions, UINT *numSessionReturned)
{
    char cmd[128] = {0};
    char buf[128] = {0};
    char line[128] = {0};
    size_t len = 0;
    FILE *f = NULL;
    int index = 0;
    int exp = 0;
    int mantissa = 0;
    int duration = 0;
    int radio_index = 0;
    int max_radio_num = 0;
    uint twt_wake_interval = 0;
    int phyId = 0;
    WIFI_ENTRY_EXIT_DEBUG("Inside %s:%d\n",__func__, __LINE__);

    wifi_getMaxRadioNumber(&max_radio_num);

    radio_index = ap_index % max_radio_num;

    phyId = radio_index_to_phy(radio_index);
    sprintf(cmd, "cat /sys/kernel/debug/ieee80211/phy%d/mt76/twt_stats | wc -l", phyId);
    _syscmd(cmd, buf, sizeof(buf));
    *numSessionReturned = strtol(buf, NULL, 10) - 1;
    if (*numSessionReturned > maxNumberSessions)
        *numSessionReturned = maxNumberSessions;
    else if (*numSessionReturned < 1) {
        *numSessionReturned = 0;
        return RETURN_OK;
    }

    sprintf(cmd, "cat /sys/kernel/debug/ieee80211/phy%d/mt76/twt_stats | tail -n %d | tr '|' ' ' | tr -s ' '", phyId, *numSessionReturned);
    if ((f = popen(cmd, "r")) == NULL) {
        wifi_dbg_printf("%s: popen %s error\n", __func__, cmd);
        return RETURN_ERR;
    }

    // the format of each line is "[wcid] [id] [flags] [exp] [mantissa] [duration] [tsf]"
    while((fgets(line, sizeof(line), f)) != NULL && index < maxNumberSessions) {
        char *tmp = NULL;
        strncpy(buf, line, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        tmp = strtok(buf, " ");
        if (!tmp) continue;
        twtSessions[index].numDevicesInSession = strtol(tmp, NULL, 10);
        tmp = strtok(NULL, " ");
        if (!tmp) continue;
        twtSessions[index].twtParameters.operation.flowID = strtol(tmp, NULL, 10);
        tmp = strtok(NULL, " ");
        if (!tmp) continue;
        if (strstr(tmp, "t")) {
            twtSessions[index].twtParameters.operation.trigger_enabled = TRUE;
        }
        if (strstr(tmp, "a")) {
            twtSessions[index].twtParameters.operation.announced = TRUE;
        }
        tmp = strtok(NULL, " ");
        if (!tmp) continue;
        exp = strtol(tmp, NULL, 10);
        tmp = strtok(NULL, " ");
        if (!tmp) continue;
        mantissa = strtol(tmp, NULL, 10);
        tmp = strtok(NULL, " ");
        if (!tmp) continue;
        duration = strtol(tmp, NULL, 10);

        // only implicit supported
        twtSessions[index].twtParameters.operation.implicit = TRUE;
        // only individual agreement supported
        twtSessions[index].twtParameters.agreement = wifi_twt_agreement_type_individual;

        // wakeInterval_uSec is a unsigned integer, but the maximum TWT wake interval could be 2^15 (mantissa) * 2^32 = 2^47.
        twt_wake_interval = mantissa * (1 << exp);
        if (mantissa == 0 || twt_wake_interval/mantissa != (1 << exp)) {
            // Overflow handling
            twtSessions[index].twtParameters.params.individual.wakeInterval_uSec = -1;   // max unsigned int
        } else {
            twtSessions[index].twtParameters.params.individual.wakeInterval_uSec = twt_wake_interval;
        }
        twtSessions[index].twtParameters.params.individual.minWakeDuration_uSec = duration * 256;
        index++;
    }

    pclose(f);
    WIFI_ENTRY_EXIT_DEBUG("Exiting %s:%d\n",__func__, __LINE__);
    return RETURN_OK;
}
