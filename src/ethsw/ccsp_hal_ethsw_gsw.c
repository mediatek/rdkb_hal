// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 MediaTek Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/ioctl.h>  /* ioctl()  */
#include <sys/socket.h> /* socket() */
#include <arpa/inet.h>  
#include <linux/if.h>   /* struct ifreq */
#include <stdbool.h>
#include <pthread.h>
#include "ccsp_hal_ethsw.h" 


/**********************************************************************
                    DEFINITIONS
**********************************************************************/

#define  CcspHalEthSwTrace(msg)                     printf("%s - ", __FUNCTION__); printf msg;
#define MAX_BUF_SIZE 1024
#define MACADDRESS_SIZE 6
#define LM_ARP_ENTRY_FORMAT  "%63s %63s %63s %63s %17s %63s"

/* Validate a network interface name: alphanumeric, dot, hyphen, underscore only. */
static int ethsw_is_valid_ifname(const char *s)
{
    size_t i, len;
    if (!s) return 0;
    len = strlen(s);
    if (len == 0 || len >= 16) return 0;
    for (i = 0; i < len; i++) {
        char c = s[i];
        if (!isalnum((unsigned char)c) && c != '.' && c != '-' && c != '_')
            return 0;
    }
    return 1;
}

/* Validate an IP address: digits, dots, colons, brackets only. */
static int ethsw_is_valid_ip(const char *s)
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

/* Validate a MAC address: hex digits and colons only, XX:XX:XX:XX:XX:XX. */
static int ethsw_is_valid_mac(const char *s)
{
    int i;
    if (!s || strlen(s) != 17) return 0;
    for (i = 0; i < 17; i++) {
        if (i % 3 == 2) { if (s[i] != ':') return 0; }
        else             { if (!isxdigit((unsigned char)s[i])) return 0; }
    }
    return 1;
}

#define ETH_WAN_INTERFACE  "erouter0"
#define ETH_WAN_IFNAME   "eth2"
#if defined(FEATURE_RDKB_WAN_MANAGER)
static pthread_t ethsw_tid;
static int hal_init_done = 0;
appCallBack ethWanCallbacks;
#define  ETH_INITIALIZE  "/tmp/ethagent_initialized"
void *ethsw_thread_main(void *context __attribute__((unused)));
#endif

#define  ETHSWITCHTOOL   "switch"
#define  MIITOOL         "mii_mgr_cl45"
#define  WANLINKUP       "0x796D"
#define  MAX_LAN_PORT     6
/**********************************************************************
                            MAIN ROUTINES
**********************************************************************/

CCSP_HAL_ETHSW_ADMIN_STATUS admin_status;

int is_interface_exists(const char *fname)
{
    FILE *file;
    if ((file = fopen(fname, "r")))
    {
        fclose(file);
        return 1;
    }
    return 0;
}

int is_interface_link(const char *fname)
{
    FILE *file;
    if ((file = fopen(fname, "r")))
    {
        char buf[32] = {0};
        fgets(buf,sizeof(buf),file);
        fclose(file);
        if(strtol(buf, NULL, 10))
            return 1;
    }
    return 0;
}
/* CcspHalEthSwInit :  */
/**
* @description Do what needed to intialize the Eth hal.
* @param None
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
INT
CcspHalEthSwInit
    (
        void
    )
{
#if defined(FEATURE_RDKB_WAN_MANAGER)
    int rc;

    if (hal_init_done) {
        return RETURN_OK;
    }

    // Create thread to handle async events and callbacks.
    rc = pthread_create(&ethsw_tid, NULL, ethsw_thread_main, NULL);
    if (rc != 0) {
        return RETURN_ERR;
    }

    hal_init_done = 1;
#endif
    return  RETURN_OK;
}
#ifdef THREE_GMACS_SUPPORT
INT
EthSwGetExtPortStatus
    (
        CCSP_HAL_ETHSW_PORT         PortId,
        PCCSP_HAL_ETHSW_LINK_RATE   pLinkRate,
        PCCSP_HAL_ETHSW_DUPLEX_MODE pDuplexMode,
        PCCSP_HAL_ETHSW_LINK_STATUS pStatus
    )
{
    char path[32] = {0};
    FILE *fp = NULL;
    char cmd[64] = {0};
    char filepath[32] = {0};
    char buf[32] = {0};
    char duplex[6] = {0};
    int link = 0;
    int speed = 0;

    if(PortId == NULL || pLinkRate == NULL || pDuplexMode == NULL || pStatus == NULL)
        return  RETURN_ERR;


    sprintf(path, "/sys/class/net/eth3/carrier");
    link = is_interface_link(path);

    if(link){
        *pStatus  = CCSP_HAL_ETHSW_LINK_Up;
    }else{
        *pStatus   = CCSP_HAL_ETHSW_LINK_Down;
        *pLinkRate      = CCSP_HAL_ETHSW_LINK_NULL;
        *pDuplexMode    = CCSP_HAL_ETHSW_DUPLEX_Auto;
        return  RETURN_OK; 
    }
    fp = popen("ethtool eth3 | grep -i speed", "r");
    if(fp != NULL)
    {
        while (fgets(buf, sizeof(buf), fp) != NULL) {
            if(strstr(buf,"Unknown") == NULL)
                sscanf(buf,"       Speed: %dMb/s", &speed);
        }
        pclose(fp);
    }else{
        *pLinkRate      = CCSP_HAL_ETHSW_LINK_NULL;
        *pDuplexMode    = CCSP_HAL_ETHSW_DUPLEX_Auto;
        return  RETURN_OK;
    }

    if(speed)
    {
        memset(buf, 0, sizeof(buf));
        fp = popen("ethtool eth3 | grep -i duplex", "r");
        if(fp != NULL)
        {
            while (fgets(buf, sizeof(buf), fp) != NULL) {
                if(strstr(buf,"Unknown") == NULL)
                    sscanf(buf,"        Duplex: %5s", duplex);
            }
            pclose(fp);
            if(!strcmp(duplex,"Full"))
                *pDuplexMode    = CCSP_HAL_ETHSW_DUPLEX_Full;
            else
                *pDuplexMode    = CCSP_HAL_ETHSW_DUPLEX_Half;
        }
    }
    switch (speed)
    {
        case 0:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_Auto;
            *pDuplexMode    = CCSP_HAL_ETHSW_DUPLEX_Auto;
            break;
        }

        case 10:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_10Mbps;
            break;
        }

        case 100:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_100Mbps;
            break;
        }

        case 1000:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_1Gbps;
            break;
        }

        case 2500:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_2_5Gbps;
            break;
        }

        case 5000:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_5Gbps;
            break;
        }

        case 10000:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_10Gbps;
            break;
        }

        default:
        {
            CcspHalEthSwTrace(("Unsupported link rate %d port id %d\n",speed, PortId));
            return  RETURN_ERR;
        }
    }

    return  RETURN_OK;
}

INT
EthSwSetExtPortCfg
    (
        CCSP_HAL_ETHSW_PORT         PortId,
        CCSP_HAL_ETHSW_LINK_RATE    LinkRate,
        CCSP_HAL_ETHSW_DUPLEX_MODE  DuplexMode
    )
{
    CcspHalEthSwTrace(("set port %d LinkRate to %d, DuplexMode to %d", PortId, LinkRate, DuplexMode));
    
    if(PortId < 1 || PortId > MAX_LAN_PORT)
        return  RETURN_ERR;

    char cmd[128] = {0};
    char setduplex[6] = {0}; 

    if(DuplexMode == 2 || DuplexMode == 0)
        strcpy(setduplex,"full");
    else if (DuplexMode == 1)
        strcpy(setduplex,"half");
    else
        return  RETURN_ERR;


    switch (LinkRate)
    {
        case CCSP_HAL_ETHSW_LINK_10Mbps:
        {
            sprintf(cmd,"ethtool -s eth3 speed %d duplex %s", 10, setduplex);
            system(cmd);
            break;
        }

        case CCSP_HAL_ETHSW_LINK_100Mbps:
        {
            sprintf(cmd,"ethtool -s eth3 speed %d duplex %s", 100, setduplex);
            system(cmd);
            break;
        }

        case CCSP_HAL_ETHSW_LINK_1Gbps:
        {
            sprintf(cmd,"ethtool -s eth3 speed %d duplex full", 1000);
            system(cmd);
            break;
        }
        case CCSP_HAL_ETHSW_LINK_2_5Gbps:
        case CCSP_HAL_ETHSW_LINK_5Gbps:
        case CCSP_HAL_ETHSW_LINK_10Gbps:
        case CCSP_HAL_ETHSW_LINK_Auto:
        {
            sprintf(cmd,"ethtool -s eth3 autoneg on");
            system(cmd);
            break;
        }
        default:
        {
            CcspHalEthSwTrace(("Unsupported link rate %d port id %d\n",LinkRate, PortId));
            return  RETURN_ERR;
        }
    }

    return  RETURN_OK;
}
#endif
/* CcspHalEthSwGetPortStatus :  */
/**
* @description Retrieve the current port status -- link speed, duplex mode, etc.

* @param PortId      -- Port ID as defined in CCSP_HAL_ETHSW_PORT
* @param pLinkRate   -- Receives the current link rate, as in CCSP_HAL_ETHSW_LINK_RATE
* @param pDuplexMode -- Receives the current duplex mode, as in CCSP_HAL_ETHSW_DUPLEX_MODE
* @param pStatus     -- Receives the current link status, as in CCSP_HAL_ETHSW_LINK_STATUS

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
INT
CcspHalEthSwGetPortStatus
    (
        CCSP_HAL_ETHSW_PORT         PortId,
        PCCSP_HAL_ETHSW_LINK_RATE   pLinkRate,
        PCCSP_HAL_ETHSW_DUPLEX_MODE pDuplexMode,
        PCCSP_HAL_ETHSW_LINK_STATUS pStatus
    )
{
    FILE *fp = NULL;
    char cmd[64] = {0};
    char buf[32] = {0};
    int duplex = 0 ;
    int link = 0;
    int speed = 0;
	int status = 0;

    if(PortId == NULL || pLinkRate == NULL || pDuplexMode == NULL || pStatus == NULL)
        return  RETURN_ERR;

    if(PortId < 1 || PortId > MAX_LAN_PORT)
        return  RETURN_ERR;

#ifdef THREE_GMACS_SUPPORT
    if(PortId == 5){
        return  EthSwGetExtPortStatus(PortId, pLinkRate, pDuplexMode, pStatus);
    }else if (PortId == 6){
        *pStatus   = CCSP_HAL_ETHSW_LINK_Down;
        *pLinkRate      = CCSP_HAL_ETHSW_LINK_NULL;
        *pDuplexMode    = CCSP_HAL_ETHSW_DUPLEX_Auto;
        return  RETURN_OK;          
    }    
#endif

    sprintf(cmd, "%s reg r 3%d08 | awk '/Read/ {print $3}'", ETHSWITCHTOOL, (PortId-1));

	fp = popen(cmd, "r");
    if(fp != NULL)
    {
        fgets(buf,sizeof(buf),fp);
        sscanf(buf,"value=%x", &status);        
        pclose(fp);
    }else{
        *pStatus   = CCSP_HAL_ETHSW_LINK_Down;
        *pLinkRate      = CCSP_HAL_ETHSW_LINK_NULL;
        *pDuplexMode    = CCSP_HAL_ETHSW_DUPLEX_Auto;
        return  RETURN_OK;        
    }

	link = status & 1;
	duplex = (status >> 1) & 1;
	speed = (status >> 2) & 3;
	fprintf(stderr,"===>portid %d status %x , link %d ,duplex %d, speed %d\n", PortId, status, link, duplex, speed);


    if(link)
    {
    	*pStatus  = CCSP_HAL_ETHSW_LINK_Up;
		if(duplex) 
		    *pDuplexMode    = CCSP_HAL_ETHSW_DUPLEX_Full;
		else
		    *pDuplexMode    = CCSP_HAL_ETHSW_DUPLEX_Half;
    }else{
        *pStatus   = CCSP_HAL_ETHSW_LINK_Down;
        *pLinkRate      = CCSP_HAL_ETHSW_LINK_NULL;
        *pDuplexMode    = CCSP_HAL_ETHSW_DUPLEX_Auto;
        return  RETURN_OK; 
    }
	
    switch (speed)
    {
        case 0:
        {
			*pLinkRate		= CCSP_HAL_ETHSW_LINK_10Mbps;
            break;
        }

        case 1:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_100Mbps;
            break;
        }

        case 2:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_1Gbps;
            break;
        }
/* Todo
        case 2500:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_2_5Gbps;
            break;
        }

        case 5000:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_5Gbps;
            break;
        }

        case 10000:
        {
            *pLinkRate      = CCSP_HAL_ETHSW_LINK_10Gbps;
            break;
        }
*/
        default:
        {
            CcspHalEthSwTrace(("Unsupported link rate %d port id %d\n",speed, PortId));
            return  RETURN_ERR;
        }
    }

    return  RETURN_OK;
}


/* CcspHalEthSwGetPortCfg :  */
/**
* @description Retrieve the current port config -- link speed, duplex mode, etc.

* @param PortId      -- Port ID as defined in CCSP_HAL_ETHSW_PORT
* @param pLinkRate   -- Receives the current link rate, as in CCSP_HAL_ETHSW_LINK_RATE
* @param pDuplexMode -- Receives the current duplex mode, as in CCSP_HAL_ETHSW_DUPLEX_MODE

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
INT
CcspHalEthSwGetPortCfg
    (
        CCSP_HAL_ETHSW_PORT         PortId,
        PCCSP_HAL_ETHSW_LINK_RATE   pLinkRate,
        PCCSP_HAL_ETHSW_DUPLEX_MODE pDuplexMode
    )
{
	FILE *fp = NULL;
	char cmd[64] = {0};
	char buf[32] = {0};
	int duplex = 0 ;
	int link = 0;
	int speed = 0;
	int status = 0;
#ifdef THREE_GMACS_SUPPORT
	CCSP_HAL_ETHSW_LINK_STATUS  LinkStatus;
#endif

	if(PortId == NULL || pLinkRate == NULL || pDuplexMode == NULL)
		return	RETURN_ERR;

	if(PortId < 1 || PortId > MAX_LAN_PORT)
		return	RETURN_ERR;

#ifdef THREE_GMACS_SUPPORT
    if(PortId == 5){
        return  EthSwGetExtPortStatus(PortId, pLinkRate, pDuplexMode, &LinkStatus);
    }else if (PortId == 6){
		*pLinkRate		= CCSP_HAL_ETHSW_LINK_NULL;
		*pDuplexMode	= CCSP_HAL_ETHSW_DUPLEX_Auto;
		return	RETURN_OK;    
    }    
#endif

	sprintf(cmd, "%s reg r 3%d08 | awk '/Read/ {print $3}'", ETHSWITCHTOOL, (PortId-1));

	fp = popen(cmd, "r");
	if(fp != NULL)
	{
		fgets(buf,sizeof(buf),fp);
		sscanf(buf,"value=%x", &status);		
		pclose(fp);
	}else{
		*pLinkRate		= CCSP_HAL_ETHSW_LINK_NULL;
		*pDuplexMode	= CCSP_HAL_ETHSW_DUPLEX_Auto;
		return	RETURN_OK;		  
	}

	link = status & 1;
	duplex = (status >> 1) & 1;
	speed = (status >> 2) & 3;

	if(link)
	{
		if(duplex) 
			*pDuplexMode	= CCSP_HAL_ETHSW_DUPLEX_Full;
		else
			*pDuplexMode	= CCSP_HAL_ETHSW_DUPLEX_Half;
		
	}else{
		*pLinkRate		= CCSP_HAL_ETHSW_LINK_Auto;
		*pDuplexMode	= CCSP_HAL_ETHSW_DUPLEX_Auto;
		return	RETURN_OK; 
	}
	
	switch (speed)
	{
		case 0:
		{
			*pLinkRate		= CCSP_HAL_ETHSW_LINK_10Mbps;
			break;
		}

		case 1:
		{
			*pLinkRate		= CCSP_HAL_ETHSW_LINK_100Mbps;
			break;
		}

		case 2:
		{
			*pLinkRate		= CCSP_HAL_ETHSW_LINK_1Gbps;
			break;
		}
/* Todo
		case 2500:
		{
			*pLinkRate		= CCSP_HAL_ETHSW_LINK_2_5Gbps;
			break;
		}

		case 5000:
		{
			*pLinkRate		= CCSP_HAL_ETHSW_LINK_5Gbps;
			break;
		}

		case 10000:
		{
			*pLinkRate		= CCSP_HAL_ETHSW_LINK_10Gbps;
			break;
		}
*/
		default:
		{
			CcspHalEthSwTrace(("Unsupported link rate %d port id %d\n",speed, PortId));
			return	RETURN_ERR;
		}
	}

	return	RETURN_OK;

}


/* CcspHalEthSwSetPortCfg :  */
/**
* @description Set the port configuration -- link speed, duplex mode

* @param PortId      -- Port ID as defined in CCSP_HAL_ETHSW_PORT
* @param LinkRate    -- Set the link rate, as in CCSP_HAL_ETHSW_LINK_RATE
* @param DuplexMode  -- Set the duplex mode, as in CCSP_HAL_ETHSW_DUPLEX_MODE

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
INT
CcspHalEthSwSetPortCfg
    (
        CCSP_HAL_ETHSW_PORT         PortId,
        CCSP_HAL_ETHSW_LINK_RATE    LinkRate,
        CCSP_HAL_ETHSW_DUPLEX_MODE  DuplexMode
    )
{
    CcspHalEthSwTrace(("set port %d LinkRate to %d, DuplexMode to %d", PortId, LinkRate, DuplexMode));

	char cmd[128] = {0};
	
    if(PortId < 1 || PortId > MAX_LAN_PORT)
        return  RETURN_ERR;

    if(DuplexMode < 0 || DuplexMode > 2)
        return  RETURN_ERR;

#ifdef THREE_GMACS_SUPPORT
    if(PortId == 5)
        return  EthSwSetExtPortCfg(PortId, LinkRate, DuplexMode);
    else if (PortId == 6)
        return  RETURN_OK;
#endif

	sprintf(cmd,"%s phy cl22 w %d 0x1f 0x0", ETHSWITCHTOOL, (PortId-1));
	system(cmd);

	memset(cmd,0,sizeof(cmd));
	
    switch (LinkRate)
    {
        case CCSP_HAL_ETHSW_LINK_10Mbps:
        {
			if(DuplexMode ==1)
            	sprintf(cmd,"%s phy cl22 w %d 0x4 0x421", ETHSWITCHTOOL, (PortId-1));
			else
				sprintf(cmd,"%s phy cl22 w %d 0x4 0x441", ETHSWITCHTOOL, (PortId-1));
			
            system(cmd);

			memset(cmd,0,sizeof(cmd));
			sprintf(cmd,"%s phy cl22 w %d 0x9 0x0", ETHSWITCHTOOL, (PortId-1));
			system(cmd);

            break;
        }

        case CCSP_HAL_ETHSW_LINK_100Mbps:
        {
			if(DuplexMode ==1)
            	sprintf(cmd,"%s phy cl22 w %d 0x4 0x481", ETHSWITCHTOOL, (PortId-1));
			else
				sprintf(cmd,"%s phy cl22 w %d 0x4 0x501", ETHSWITCHTOOL, (PortId-1));
			
            system(cmd);

			memset(cmd,0,sizeof(cmd));
			sprintf(cmd,"%s phy cl22 w %d 0x9 0x0", ETHSWITCHTOOL, (PortId-1));
			system(cmd);

            break;
        }

        case CCSP_HAL_ETHSW_LINK_1Gbps:
        case CCSP_HAL_ETHSW_LINK_2_5Gbps:
        case CCSP_HAL_ETHSW_LINK_5Gbps:
        case CCSP_HAL_ETHSW_LINK_10Gbps:
        case CCSP_HAL_ETHSW_LINK_Auto:
        {
            sprintf(cmd,"%s phy cl22 w %d 0x4 0xde1", ETHSWITCHTOOL, (PortId-1));
            system(cmd);

			memset(cmd,0,sizeof(cmd));
			sprintf(cmd,"%s phy cl22 w %d 0x9 0x200", ETHSWITCHTOOL, (PortId-1));
			system(cmd);

            break;
        }
        default:
        {
            CcspHalEthSwTrace(("Unsupported link rate %d port id %d\n",LinkRate, PortId));
            return  RETURN_ERR;
        }
    }
	memset(cmd,0,sizeof(cmd));
	sprintf(cmd,"%s phy cl22 w %d 0x0 0x1240", ETHSWITCHTOOL, (PortId-1));
	system(cmd);

    return  RETURN_OK;
}


/* CcspHalEthSwGetPortAdminStatus :  */
/**
* @description Retrieve the current port admin status.

* @param PortId      -- Port ID as defined in CCSP_HAL_ETHSW_PORT
* @param pAdminStatus -- Receives the current admin status

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
INT
CcspHalEthSwGetPortAdminStatus
    (
        CCSP_HAL_ETHSW_PORT           PortId,
        PCCSP_HAL_ETHSW_ADMIN_STATUS  pAdminStatus
    )
{
    if(PortId == NULL || pAdminStatus == NULL)
        return  RETURN_ERR;
	
    CcspHalEthSwTrace(("port id %d", PortId));
 
    if(PortId < 1 || PortId > MAX_LAN_PORT)
        return  RETURN_ERR;

 	int sockfd;
    struct ifreq ifr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        printf("====> open socket fail \n");
        return RETURN_ERR;
    }

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", "eth1");

    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0)
    {
        printf("====> ioctl open socket fail \n");
        close(sockfd);
        return RETURN_ERR;
    }

    close(sockfd);
    if(ifr.ifr_flags & IFF_UP)
        *pAdminStatus   = CCSP_HAL_ETHSW_AdminUp;
    else
        *pAdminStatus   = CCSP_HAL_ETHSW_AdminDown;
    
    if(admin_status)
        *pAdminStatus   = CCSP_HAL_ETHSW_AdminDown;
	
  return RETURN_OK;
}

/* CcspHalEthSwSetPortAdminStatus :  */
/**
* @description Set the ethernet port admin status

* @param AdminStatus -- set the admin status, as defined in CCSP_HAL_ETHSW_ADMIN_STATUS

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
INT
CcspHalEthSwSetPortAdminStatus
    (
        CCSP_HAL_ETHSW_PORT         PortId,
        CCSP_HAL_ETHSW_ADMIN_STATUS AdminStatus
    )
{
    CcspHalEthSwTrace(("set port %d AdminStatus to %d", PortId, AdminStatus));
    if(AdminStatus < CCSP_HAL_ETHSW_AdminUp || AdminStatus > CCSP_HAL_ETHSW_AdminTest)
        return  RETURN_ERR;
    if(PortId < 1 || PortId > MAX_LAN_PORT)
        return  RETURN_ERR;
    
    char cmd1[32] = {0};
    char cmd2[32] = {0};
    char interface[8] = {0};
    char path[32] = {0};

    strcpy(path,"/sys/class/net/eth1");

    int eth_if=is_interface_exists(path);

    if(eth_if == 0 )
        return  RETURN_ERR;

    strcpy(interface,"eth1");

    sprintf(cmd1,"ip link set %s up",interface);
    sprintf(cmd2,"ip link set %s down",interface);

    switch (PortId)
    {
        case CCSP_HAL_ETHSW_EthPort1:
        case CCSP_HAL_ETHSW_EthPort2:
        case CCSP_HAL_ETHSW_EthPort3:
        case CCSP_HAL_ETHSW_EthPort4:
        {

            {
                 if(AdminStatus==0)
                 {
                    system(cmd1);
                    admin_status=0;
                 }
                 else
                 {
                     //system(cmd2);
                     admin_status=1;
                 }
             }
             break;
        }
        default:
            CcspHalEthSwTrace(("Unsupported port id %d", PortId));
            return  RETURN_ERR;
    }
    return  RETURN_OK;
}


/* CcspHalEthSwSetAgingSpeed :  */
/**
* @description Set the ethernet port configuration -- admin up/down, link speed, duplex mode

* @param PortId      -- Port ID as defined in CCSP_HAL_ETHSW_PORT
* @param AgingSpeed  -- integer value of aging speed
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
INT
CcspHalEthSwSetAgingSpeed
    (
        CCSP_HAL_ETHSW_PORT         PortId,
        INT                         AgingSpeed
    )
{
    CcspHalEthSwTrace(("set port %d aging speed to %d", PortId, AgingSpeed));
    if(AgingSpeed < 0 || AgingSpeed > 300)
        return  RETURN_ERR;
    if(PortId < 1)
        return  RETURN_ERR;
    return  RETURN_OK;
}


/* CcspHalEthSwLocatePortByMacAddress :  */
/**
* @description Retrieve the port number that the specificed MAC address is associated with (seen)

* @param pMacAddr    -- Specifies the MAC address -- 6 bytes
* @param pPortId     -- Receives the found port number that the MAC address is seen on

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
INT
CcspHalEthSwLocatePortByMacAddress
    (
		unsigned char * pMacAddr, 
		INT * pPortId
    )
{
    if (pMacAddr == NULL)
        return RETURN_ERR;

    CcspHalEthSwTrace
        ((
            "%s -- search for MAC address %02x:%02x:%02x:%02x:%02x:%02x",
            __FUNCTION__,
            pMacAddr[0], pMacAddr[1], pMacAddr[2], 
            pMacAddr[3], pMacAddr[4], pMacAddr[5]
        ));

	char cmd[128] = {0};
	char buf[128] = {0};
	char foundmac[18] = {0};
	int port = 0;
	FILE *fp = NULL;

	sprintf(foundmac,"%02x%02x%02x%02x%02x%02x",pMacAddr[0], pMacAddr[1], pMacAddr[2], pMacAddr[3], pMacAddr[4], pMacAddr[5]);

	snprintf(cmd,128, "%s dump | grep %s | awk '/%s/ {print $2}'", ETHSWITCHTOOL, foundmac, foundmac);
	
	fp = popen(cmd, "r");
	if(fp != NULL)
	{
		if(fgets(buf,sizeof(buf),fp) != NULL)
		{
			pclose(fp);

			port = strtol(buf, NULL, 10);
			*pPortId = port+1;
			return RETURN_OK;
		}             
        pclose(fp);
	}
	return  RETURN_ERR;
}

//For Getting Current Interface Name from corresponding hostapd configuration
void GetInterfaceName(char *interface_name, char *conf_file)
{
        FILE *fp = NULL;
        char line[MAX_BUF_SIZE] = {0};
        char *val = NULL;
        size_t val_len;

        if (!interface_name || !conf_file) return;
        interface_name[0] = '\0';

        /* Read config file directly — no shell involved */
        fp = fopen(conf_file, "r");
        if(fp == NULL)
        {
                printf("conf_file %s not exists \n", conf_file);
                return;
        }

        while (fgets(line, sizeof(line), fp)) {
                if (strncmp(line, "interface=", 10) == 0) {
                        val = line + 10;
                        /* strip trailing newline */
                        val_len = strlen(val);
                        if (val_len > 0 && val[val_len-1] == '\n')
                                val[--val_len] = '\0';
                        snprintf(interface_name, 16, "%s", val);
                        break;
                }
        }
        fclose(fp);

        fprintf(stderr, "Interface name %s \n", interface_name);
}
/* CcspHalExtSw_getAssociatedDevice :  */
/**
* @description Collected the active wired clients information

* @param output_array_size    -- Size of the active wired connected clients
* @param output_struct     -- Structure of  wired clients informations

*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
*/

INT CcspHalExtSw_getAssociatedDevice(ULONG *output_array_size, eth_device_t **output_struct)
{
	CHAR buf[MAX_BUF_SIZE] = {0},str[MAX_BUF_SIZE] = {0},interface_name[50] = {0},macAddr[50] = {0};
	FILE *fp = NULL,*fp1 = NULL;
	INT count = 0,str_count = 0;
	ULONG maccount = 0,eth_count = 0;
	INT arr[MACADDRESS_SIZE] = {0};
	UCHAR mac[MACADDRESS_SIZE] = {0};
	CHAR ipAddr[64],stub[64],phyAddr[64],ifName[64],status[64];
	int ret;
	if(output_struct == NULL)
	{
		printf("\nNot enough memory\n");
		return RETURN_ERR;
	}

	system("echo -n  > /tmp/ethernetmac.txt");

	system("cat /nvram/dnsmasq.leases | cut -d ' ' -f2 > /tmp/connected_mac.txt"); //storing the all associated device information in tmp folder
	//storing the private wifi  associated device iformation in tmp folder
	GetInterfaceName(interface_name,"/nvram/hostapd0.conf");
	if (ethsw_is_valid_ifname(interface_name)) {
		snprintf(buf, sizeof(buf), "iw dev %s station dump | grep Station | cut -d ' ' -f2 > /tmp/Associated_Devices.txt", interface_name);
		system(buf);
	}
	GetInterfaceName(interface_name,"/nvram/hostapd1.conf");
	if (ethsw_is_valid_ifname(interface_name)) {
		snprintf(buf, sizeof(buf), "iw dev %s station dump | grep Station | cut -d ' ' -f2 >> /tmp/Associated_Devices.txt", interface_name);
		system(buf);
	}

	system("diff /tmp/Associated_Devices.txt /tmp/connected_mac.txt | grep \"^+\" | cut -c2- | sed -n '1!p' > /tmp/ethernet_connected_clients.txt"); //separating the ethernet associated device information from connected_mac test file
	fp=popen("cat /tmp/ethernet_connected_clients.txt | wc -l","r"); // For getting the  ethernet connected mac count
	if(fp == NULL)
		goto cleanup_tmp;
	else
	{
		fgets(buf,MAX_BUF_SIZE,fp);
		maccount = strtol(buf, NULL, 10);
		fprintf(stderr,"ethernet umac is %d \n",maccount);
	}
	pclose(fp);
	eth_device_t *temp=NULL;
	temp = (eth_device_t*)calloc(1, sizeof(eth_device_t)*maccount);
	if(temp == NULL)
	{
		fprintf(stderr,"Not enough memory \n");
		goto cleanup_tmp;
	}
	fp=fopen("/tmp/ethernet_connected_clients.txt","r"); // reading the ethernet associated device information
	if(fp == NULL)
	{
		*output_struct = NULL;
		*output_array_size = 0;
		free(temp);
		goto cleanup_tmp;
	}
	else
	{
		for(count = 0;count < maccount ; count++)
		{
			if (fgets(str, MAX_BUF_SIZE, fp) == NULL)
				break;
			{
				size_t slen = strcspn(str, "\n");
				if (slen >= sizeof(macAddr)) slen = sizeof(macAddr) - 1;
				memcpy(macAddr, str, slen);
				macAddr[slen] = '\0';
			}
			fp1=popen("ip nei show | grep brlan0","r");
			if(fp1 == NULL){
				fclose(fp);
				free(temp);
				goto cleanup_tmp;
			}
			while(fgets(buf,sizeof(buf),fp1) != NULL)
			{
				if ( strstr(buf, "FAILED") != 0 )
					continue;
				/*
Sample:
10.0.0.208 dev brlan0 lladdr d4:be:d9:99:7f:47 STALE
10.0.0.107 dev brlan0 lladdr 64:a2:f9:d2:f5:67 REACHABLE
				 */
				ret = sscanf(buf, LM_ARP_ENTRY_FORMAT,
						ipAddr,
						stub,
						ifName,
						stub,
						phyAddr,
						status);  
				if(ret != 6)
					continue;
				if(strcmp(phyAddr,macAddr) == 0)
				{
					memset(buf,0,sizeof(buf));
					if(strcmp(status,"REACHABLE") == 0)
					{
						if (ethsw_is_valid_mac(macAddr)) {
							FILE *mfp = fopen("/tmp/ethernetmac.txt", "a");
							if (mfp) { fprintf(mfp, "%s\n", macAddr); fclose(mfp); }
							eth_count++;
						}
						break;
					}
					else if((strcmp(status,"STALE") == 0) || (strcmp(status,"DELAY")))
					{
						if (!ethsw_is_valid_ip(ipAddr) || !ethsw_is_valid_mac(macAddr))
							break;
						snprintf(buf, sizeof(buf), "ping -q -c 1 -W 1 %s > /dev/null 2>&1", ipAddr);
						fprintf(stderr,"buf is %s and MACADRRESS %s\n",buf,macAddr);
						if (WEXITSTATUS(system(buf)) == 0)
						{
							fprintf(stderr,"Inside STALE SUCCESS \n");
							FILE *mfp = fopen("/tmp/ethernetmac.txt", "a");
							if (mfp) { fprintf(mfp, "%s\n", macAddr); fclose(mfp); }
							eth_count++;
							break;
						}
					}
					else
					{
						fprintf(stderr,"Running in different state \n");
						break;
					}
				}
				else
					fprintf(stderr,"MAcAddress is not valid \n");
			}
			pclose(fp1);
		}
	}
	fclose(fp);
	fp=fopen("/tmp/ethernetmac.txt","r");
	if(fp == NULL)
	{
		*output_struct = NULL;
		*output_array_size = 0;
		free(temp);
		return RETURN_OK;
	}
	else
	{
		memset(buf,0,sizeof(buf));
		for(count = 0;count < eth_count ; count++)
		{
			fgets(buf,sizeof(buf),fp);
			if(MACADDRESS_SIZE  == sscanf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",&arr[0],&arr[1],&arr[2],&arr[3],&arr[4],&arr[5]) )
			{
				for( int ethclientindex = 0; ethclientindex < 6; ++ethclientindex )
				{
					mac[ethclientindex] = (unsigned char) arr[ethclientindex];
				}
				memcpy(temp[count].eth_devMacAddress,mac,(sizeof(unsigned char))*6);
				fprintf(stderr,"MAC %d = %X:%X:%X:%X:%X:%X \n", count, temp[count].eth_devMacAddress[0],temp[count].eth_devMacAddress[1], temp[count].eth_devMacAddress[2], temp[count].eth_devMacAddress[3], temp[count].eth_devMacAddress[4], temp[count].eth_devMacAddress[5]);
			}
			temp[count].eth_port= 0;
			CcspHalEthSwLocatePortByMacAddress(temp[count].eth_devMacAddress, &temp[count].eth_port);
			temp[count].eth_vlanid=-1;
			FILE *fp2 = NULL;
			char cmd[64] = {0};
			char buffer[32] = {0};
			int status =0;
			int speed =0 ;

#ifdef THREE_GMACS_SUPPORT
			if(temp[count].eth_port > 4){
				sprintf(cmd, "cat /sys/class/net/eth3/speed");
				temp[count].eth_port = 5;
			}else
#endif
			{	 
				sprintf(cmd, "%s reg r 3%d08 | awk '/Read/ {print $3}'", ETHSWITCHTOOL, (temp[count].eth_port-1));
			}
			fp2 = popen(cmd, "r");
			if(fp2 != NULL)
			{
				fgets(buffer,sizeof(buffer),fp2);
#ifdef THREE_GMACS_SUPPORT
				if(temp[count].eth_port > 4){
					speed = strtol(buffer, NULL, 10);
				}else
#endif				
				{
					sscanf(buffer,"value=%x", &status);
					speed = (status >> 2) & 3;
				}	
				pclose(fp2);
				

				
				if(speed == 0)
					temp[count].eth_devTxRate = 10;
				else if (speed == 1)
					temp[count].eth_devTxRate = 100;
				else if (speed == 2)
					temp[count].eth_devTxRate = 1000;
				else
					temp[count].eth_devTxRate = speed;

				temp[count].eth_Active=1;
			}else{
				temp[count].eth_devTxRate= -1;
				temp[count].eth_Active=0;
			}

			temp[count].eth_devRxRate = temp[count].eth_devTxRate;
		}
	}
	fclose(fp);
	*output_struct = temp;
	*output_array_size = eth_count;
	fprintf(stderr,"Connected Active ethernet clients count is %ld \n",*output_array_size);
cleanup_tmp:
	unlink("/tmp/ethernetmac.txt");
	unlink("/tmp/connected_mac.txt");
	unlink("/tmp/Associated_Devices.txt");
	unlink("/tmp/ethernet_connected_clients.txt");
	return RETURN_OK;
}

/* CcspHalExtSw_getEthWanEnable  */
/**
* @description Return the Ethwan Enbale status

* @param enable    -- Having status of WANMode ( Ethernet,DOCSIS)

*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
*/

INT CcspHalExtSw_getEthWanEnable(BOOLEAN *enable)
{
	int sockfd;
    struct ifreq ifr;

    if (enable == NULL)
        return RETURN_ERR;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        printf("====> open socket fail \n");
        return RETURN_ERR;
    }

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ETH_WAN_INTERFACE);

    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0)
    {
        printf("====> ioctl open socket fail \n");
        close(sockfd);
        return RETURN_ERR;
    }

    close(sockfd);
    *enable = ifr.ifr_flags & IFF_UP;
	return RETURN_OK;
}

/* CcspHalExtSw_getEthWanPort:  */
/**
* @description Return the ethwan port

* @param port    -- having ethwan port

*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
*/

INT CcspHalExtSw_getEthWanPort(UINT *Port)
{
	if(Port == NULL)
		return RETURN_ERR;
	
	*Port = 6;
	return RETURN_OK;
}

/* CcspHalExtSw_setEthWanEnable :  */
/**
* @description setting the ethwan enable status

* @enable    -- Switch from ethernet mode to docsis mode or vice-versa

*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
*/

INT CcspHalExtSw_setEthWanEnable(BOOLEAN enable)
{
    char cmd[32] = {0};

    sprintf(cmd,"ifconfig %s %s",ETH_WAN_INTERFACE, enable ? "up":"down");
    system(cmd);

	return RETURN_OK;
}


/* CcspHalExtSw_setEthWanPort :  */
/**
* @description  Need to set the ethwan port

* @param port    -- Setting the ethwan port

*
* @return The status of the operation.
* @retval RETURN_OK if successful.
* @retval RETURN_ERR if any error is detected
*
*/

INT CcspHalExtSw_setEthWanPort(UINT Port)
{
	if(Port != 6)
		return  RETURN_ERR;
	return RETURN_OK;
}

INT GWP_GetEthWanLinkStatus()
{
    int link = 0;
    char path[32] = {0};

    sprintf(path, "/sys/class/net/erouter0/carrier");
    link = is_interface_link(path);

    if(link){
        return 1;
    }else{
        return 0; 
    }
}

#if defined(FEATURE_RDKB_WAN_MANAGER)
void *ethsw_thread_main(void *context __attribute__((unused)))
{
	int previousLinkDetected = 0;
	int currentLinkDeteced = 0;
	int timeout = 0;
	int file = 0;

	while(timeout != 180)
	{
		if (file == access(ETH_INITIALIZE, R_OK))
		{
			CcspHalEthSwTrace(("Eth agent initialized \n"));
			break;
		}
		else
		{
			timeout = timeout+1;
			sleep(1);
		}
	}

	while(1)
	{
		currentLinkDeteced = GWP_GetEthWanLinkStatus();
		if (currentLinkDeteced != previousLinkDetected)
		{
			if (currentLinkDeteced)
			{
				CcspHalEthSwTrace(("send_link_event: Got Link UP Event\n"));
				if (ethWanCallbacks.pGWP_act_EthWanLinkUP)
					ethWanCallbacks.pGWP_act_EthWanLinkUP();
			}
			else
			{
				CcspHalEthSwTrace(("send_link_event: Got Link DOWN Event\n"));
				if (ethWanCallbacks.pGWP_act_EthWanLinkDown)
					ethWanCallbacks.pGWP_act_EthWanLinkDown();
			}
			previousLinkDetected = currentLinkDeteced;
		}
		sleep(5);
	}

    return NULL;
}
#endif
void GWP_RegisterEthWan_Callback(appCallBack *obj) {
#if defined(FEATURE_RDKB_WAN_MANAGER)
    int rc;

    if (obj == NULL) {
        rc = RETURN_ERR;
    } else {
        ethWanCallbacks.pGWP_act_EthWanLinkUP = obj->pGWP_act_EthWanLinkUP;
        ethWanCallbacks.pGWP_act_EthWanLinkDown = obj->pGWP_act_EthWanLinkDown;
        rc = RETURN_OK;
    }
#endif	
}

INT GWP_GetEthWanInterfaceName
(
 unsigned char * Interface,
 ULONG           maxSize
)
{
    //Maxsize param should be minimum 4charecters(eth0) including NULL charecter
    if( ( Interface == NULL ) || ( maxSize < ( strlen( ETH_WAN_IFNAME ) + 1 ) ) )
    {
        printf("ERROR: Invalid argument. \n");
        return RETURN_ERR;
    }
    snprintf(Interface, maxSize, "%s", ETH_WAN_IFNAME);
    return RETURN_OK;
}
