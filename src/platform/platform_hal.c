// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 MediaTek Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "platform_hal.h" 

#define FACTORY_RESET_COUNT_FILE "/nvram/.factory_reset_count"

/* Note that 0 == RETURN_OK == STATUS_OK    */
/* Note that -1 == RETURN_ERR == STATUS_NOK */


INT platform_hal_PandMDBInit(void) { return RETURN_OK; }
INT platform_hal_DocsisParamsDBInit(void) { return RETURN_OK; }

INT platform_hal_GetDeviceConfigStatus(CHAR *pValue)
{
	if(NULL == pValue )
	{
		return RETURN_ERR;
	}

	strcpy(pValue, "Complete");
	return RETURN_OK;
}

INT platform_hal_GetWebUITimeout(ULONG *pValue)
{
	if(NULL == pValue )
	{
		return RETURN_ERR;
	}

	return RETURN_OK;
}

INT platform_hal_SetWebUITimeout(ULONG value)
{
	return RETURN_OK;
}

INT platform_hal_GetWebAccessLevel(INT userIndex, INT ifIndex, ULONG *pValue)
{
	if(NULL == pValue )
	{
		return RETURN_ERR;
	}

	return RETURN_OK;
}

INT platform_hal_SetWebAccessLevel(INT userIndex, INT ifIndex, ULONG value)
{
	return RETURN_OK;
}

INT platform_hal_GetBootloaderVersion(CHAR* pValue, ULONG maxSize)
{
	if(NULL == pValue )
	{
		return RETURN_ERR;
	}
	strcpy(pValue, "Not Supported");

	return RETURN_OK;
}

INT platform_hal_GetSerialNumber(CHAR* pValue)
{
	if (pValue != NULL)
	{
		INT arr[6] = {0};
		const char *path = "/sys/class/net/eth1/address";
		FILE *fp = fopen(path, "r");
		if (fp != NULL)
		{
			char *end;
			char buf[64] = {0};
			fgets(buf, sizeof(buf), fp);
			fclose(fp);
			if(6  == sscanf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",&arr[0],&arr[1],&arr[2],&arr[3],&arr[4],&arr[5]))
			{
				sprintf(pValue,"%02x%02x%02x%02x%02x%02x",arr[0],arr[1],arr[2],arr[3],arr[4],arr[5]);
				return RETURN_OK;
			}	
		}
	}
	return RETURN_ERR;

}

INT platform_hal_GetHardwareVersion(CHAR* pValue)
{
	if (pValue == NULL)
	{
		return RETURN_ERR;
	}

	strcpy(pValue, "1.0");
	return RETURN_OK;
}

INT platform_hal_GetHardware(CHAR *pValue)
{
	FILE *fp = NULL;
	char buf[64] = {0};
	char cmd[128] = {0};

  
	if (pValue == NULL)
	{
		return RETURN_ERR;
	}
	snprintf(cmd,128, "cat /proc/partitions | grep mtdblock5 | awk '/mtdblock5/ {print $3}'");
	fp = popen(cmd,"r");
	if(fp == NULL)
	{
		return RETURN_ERR;
	}

	if(fgets(buf,sizeof(buf) -1,fp) != NULL)
	{
		sprintf(pValue,"%d",(atoi(buf)/1024));
	}else{
		*pValue = '0';
	}

	pclose(fp);
	
	return RETURN_OK; 

}

INT platform_hal_GetBaseMacAddress(CHAR *pValue)
{
	if (pValue != NULL)
	{
		const char *path = "/sys/class/net/eth1/address";
		FILE *fp = fopen(path, "r");
		if (fp != NULL)
		{
			char *end;
			char buf[64] = {0};
			fgets(buf, sizeof(buf), fp);
			fclose(fp);

			end = strchr(buf, '\n');
			if (end)
			{
				*end = '\0';
			}
			/* MAC address is at most 17 chars + NUL; 18 bytes is sufficient */
			snprintf(pValue, 18, "%s", buf);
			return RETURN_OK;
		}
	}
	return RETURN_ERR;
}

INT platform_hal_GetTelnetEnable(BOOLEAN *pFlag)
{ 
	char cmd[128] = {0};
	char buf[128] = {0};
	FILE *fp = NULL;
	
	if (pFlag == NULL)
	{
		return RETURN_ERR;
	}else{
		*pFlag = FALSE;
		snprintf(cmd,128, "netstat -apn | grep telnetd");
		fp = popen(cmd, "r");
		if(fp != NULL)
		{
			if(fgets(buf,sizeof(buf),fp) != NULL)
			{
				if (strstr(buf, "telnetd") != NULL)
					*pFlag = TRUE;
			}
			pclose(fp);
		}
	}
	
	return RETURN_OK; 
}

INT platform_hal_SetTelnetEnable(BOOLEAN Flag) 
{
	if(Flag)
		system("telnetd &");
	else
		system("killall telnetd");
	
	return RETURN_OK;
}

INT platform_hal_GetSSHEnable(BOOLEAN *pFlag)
{
	char cmd[128] = {0};
	char buf[128] = {0};
	FILE *fp = NULL;
	
	if (pFlag == NULL)
	{
		return RETURN_ERR;
	}else{
		*pFlag = FALSE;
		snprintf(cmd,128, "netstat -apn | grep dropbear");
		fp = popen(cmd, "r");
		if(fp != NULL)
		{
			if(fgets(buf,sizeof(buf),fp) != NULL)
			{
				if (strstr(buf, "dropbear") != NULL)
					*pFlag = TRUE;
			}
			pclose(fp);
		}
	}
	
	return RETURN_OK; 

}

INT platform_hal_SetSSHEnable(BOOLEAN Flag)
{
	if(Flag)
	{
		system("systemctl restart dropbear");
	}else{
		system("systemctl stop dropbear");
		system("killall dropbear");
	}
	return RETURN_OK;
}

INT platform_hal_GetSNMPEnable(CHAR* pValue)
{
	char cmd[128] = {0};
	char buf[128] = {0};
	FILE *fp = NULL;
	
	if (pValue == NULL)
	{
		return RETURN_ERR;
	}else{
		sprintf(pValue,"%s","disable");
		snprintf(cmd,128, "netstat -apn | grep snmpd");
		fp = popen(cmd, "r");
		if(fp != NULL)
		{
			if(fgets(buf,sizeof(buf),fp) != NULL)
			{
				if (strstr(buf, "snmpd") != NULL)
					sprintf(pValue,"%s","enable");
			}
			pclose(fp);
		}
	}
	
	return RETURN_OK; 

}

INT platform_hal_SetSNMPEnable(CHAR* pValue)
{
	if(pValue == NULL)
	{
		return RETURN_ERR;
	}else{
		if(strcmp(pValue,"enable") == 0)
			system("systemctl restart snmpd");
		else if (strcmp(pValue,"disable") == 0)
			system("systemctl stop snmpd");
	}	
	return RETURN_OK;
}

INT platform_hal_GetModelName(CHAR* pValue)
{
	FILE *fp = NULL;
	char buf[64] = {0};
	int count = 0;
  
	if (pValue == NULL)
	{
		return RETURN_ERR;
	}

	fp = popen("cat /proc/device-tree/model","r");
	if(fp == NULL)
	{
		return RETURN_ERR;
	}

	if(fgets(buf, sizeof(buf) - 1, fp) != NULL)
	{
		/* strip trailing newline and copy safely */
		buf[strcspn(buf, "\n")] = '\0';
		snprintf(pValue, sizeof(buf), "%s", buf);
	}

	pclose(fp);
	
	return RETURN_OK; 
}

INT platform_hal_GetSoftwareVersion(CHAR* pValue, ULONG maxSize)
{
	FILE *fp;
	char buff[64]={0};
  
	if (pValue == NULL)
	{
		return RETURN_ERR;
	}

	if((fp = fopen("/version.txt", "r")) == NULL)
	{
		printf(("Error while opening the file version.txt \n"));
		return RETURN_ERR;
	}

	while(fgets(buff, 64, fp) != NULL)
	{
		if(strstr(buff, "VERSION") != NULL && strstr(buff, "YOCTO_VERSION") == NULL)
		{
			int i = 0;
			while((i < (int)(sizeof(buff)-8)) && (i < (int)(maxSize)-1) &&
			      (buff[i+8] != '\n') && (buff[i+8] != '\r') && (buff[i+8] != '\0'))
			{
				pValue[i] = buff[i+8];
				i++;
			}
			pValue[i] = '\0';
			break;
		}
	}

	if(fp)
		fclose(fp);

	return RETURN_OK;
}

INT platform_hal_GetFirmwareName(CHAR* pValue, ULONG maxSize)
{
	FILE *fp;
	char buff[64]={0};
  
	if (pValue == NULL)
	{
		return RETURN_ERR;
	}

	if((fp = fopen("/version.txt", "r")) == NULL)
	{
		printf(("Error while opening the file version.txt \n"));
		return RETURN_ERR;
	}

	while(fgets(buff, 64, fp) != NULL)
	{
		if(strstr(buff, "imagename") != NULL)
		{
			int i = 0;
			while((i < (int)(sizeof(buff)-10)) && (i < (int)(maxSize)-1) &&
			      (buff[i+10] != '\n') && (buff[i+10] != '\r') && (buff[i+10] != '\0'))
			{
				pValue[i] = buff[i+10];
				i++;
			}
			pValue[i] = '\0';
			break;
		}
	}

	if(fp)
		fclose(fp);

	return RETURN_OK;
}
INT platform_hal_GetTotalMemorySize(ULONG *pulSize)
{
    char buf[64] = {0};
    FILE *fp = NULL;

    if (pulSize == NULL)
        return RETURN_ERR;

    fp = popen("awk '/MemTotal/ {print $2}' /proc/meminfo", "r");
    if(fp != NULL)
    {
        if (fgets(buf, sizeof(buf), fp) != NULL)
            *pulSize = strtoul(buf, NULL, 10) / 1024;
        else
            *pulSize = 0;
        pclose(fp);
    }else{
        *pulSize = 0;
    }
    return RETURN_OK;
}

INT platform_hal_GetHardware_MemUsed(CHAR *pValue)
{
    char buf[64] = {0};
    FILE *fp = NULL;

    if (pValue == NULL)
        return RETURN_ERR;

    fp = popen("df | awk '/ubi0/ {print $3}'", "r");
    if(fp != NULL)
    {
        if (fgets(buf, sizeof(buf), fp) != NULL)
            snprintf(pValue, 32, "%ld", strtol(buf, NULL, 10) / 1024);
        else
            snprintf(pValue, 32, "0");
        pclose(fp);
    }else{
        snprintf(pValue, 32, "0");
    }
    return RETURN_OK;
}

INT platform_hal_GetHardware_MemFree(CHAR *pValue)
{
    char buf[64] = {0};
    FILE *fp = NULL;

    if (pValue == NULL)
        return RETURN_ERR;

    fp = popen("df | awk '/ubi0/ {print $4}'", "r");
    if(fp != NULL)
    {
        if (fgets(buf, sizeof(buf), fp) != NULL)
            snprintf(pValue, 32, "%ld", strtol(buf, NULL, 10) / 1024);
        else
            snprintf(pValue, 32, "0");
        pclose(fp);
    }else{
        snprintf(pValue, 32, "0");
    }
    return RETURN_OK;
}

INT platform_hal_GetFreeMemorySize(ULONG *pulSize)
{
    if (pulSize == NULL)
    {
        return RETURN_ERR;
    }
    char buf[64] = {0};
    FILE *fp = NULL;

    fp = popen("awk '/MemFree/ {print $2}' /proc/meminfo", "r");
    if(fp != NULL)
    {
        if (fgets(buf, sizeof(buf), fp) != NULL)
            *pulSize = strtoul(buf, NULL, 10) / 1024;
        else
            *pulSize = 0;
        pclose(fp);
    }else{
        *pulSize = 0;
    }
    return RETURN_OK;
}

INT platform_hal_GetUsedMemorySize(ULONG *pulSize)
{
    if (pulSize == NULL)
    {
        return RETURN_ERR;
    }

    unsigned long total = 0;
    unsigned long free = 0;
    platform_hal_GetTotalMemorySize(&total);
    platform_hal_GetFreeMemorySize(&free);
    *pulSize = (total > free) ? (total - free) : 0;
    return RETURN_OK;
}

INT platform_hal_GetFactoryResetCount(ULONG *pulSize)
{
	FILE *pdbFile = NULL;
	char buf[128]={0};
	if(NULL == pulSize)
	{
		return RETURN_ERR;
	}

	pdbFile = fopen(FACTORY_RESET_COUNT_FILE, "r");
	if(pdbFile != NULL)
	{
		fread(buf,sizeof(buf),1,pdbFile);
		fclose(pdbFile); 
		*pulSize = atoi(buf);
	}
	else
	{
		*pulSize = 0;
	}

	return RETURN_OK;

}

INT platform_hal_ClearResetCount(BOOLEAN bFlag)
{
	char cmd[128] = {0};

	
	if(bFlag){
		snprintf(cmd,128, "rm %s",FACTORY_RESET_COUNT_FILE);
		system(cmd);
	}	
	return RETURN_OK;
}

INT platform_hal_getTimeOffSet(CHAR *pValue)
{
	if (pValue == NULL)
	{
		return RETURN_ERR;
	}
	return RETURN_OK; 
} 

INT platform_hal_SetDeviceCodeImageTimeout(INT seconds)
{ 
	return RETURN_OK; 
} 

INT platform_hal_SetDeviceCodeImageValid(BOOLEAN flag)
{ 
	return RETURN_OK; 
}

INT platform_hal_getFactoryPartnerId(CHAR *pValue)
{
	if (pValue == NULL)
	{
		return RETURN_ERR;
	}
	strcpy(pValue, "Mediatek");
	return RETURN_OK;
}

INT platform_hal_getFactoryCmVariant(CHAR *pValue)
{
	if (pValue == NULL)
	{
		return RETURN_ERR;
	}
	strcpy(pValue, "rdkb-filogic");
	return RETURN_OK;	
}

INT platform_hal_setFactoryCmVariant(CHAR *pValue)
{
	if (pValue == NULL)
	{
		return RETURN_ERR;
	}

	return RETURN_OK;
}

int platform_hal_initLed (char * config_file_name)
{
	char cmd[128] = {0};
	
	if (config_file_name == NULL)
	{
		return RETURN_ERR;
	}

	snprintf(cmd,128, "echo 0 > /sys/class/pwm/pwmchip0/export");
	system(cmd);
		
	return RETURN_OK;

}

INT platform_hal_setLed(PLEDMGMT_PARAMS pValue)
{
	char cmd[128] = {0};

	if (pValue == NULL)
	{
		return RETURN_ERR;
	}

	if(!pValue->State)
	{
		snprintf(cmd,128, "echo 1000000000 > /sys/class/pwm/pwmchip0/pwm0/period");
		system(cmd);
		memset(cmd,0,sizeof(cmd));
		snprintf(cmd,128, "echo 0 > /sys/class/pwm/pwmchip0/pwm0/duty_cycle");
		system(cmd);

	}else{
		if (pValue->Interval == 0)
			return RETURN_ERR;
		snprintf(cmd,128, "echo %d > /sys/class/pwm/pwmchip0/pwm0/period",(1000000000/pValue->Interval));
		system(cmd);
		memset(cmd,0,sizeof(cmd));
		snprintf(cmd,128, "echo %d > /sys/class/pwm/pwmchip0/pwm0/duty_cycle",(1000000000/pValue->Interval)/2 );
		system(cmd);
	}

	memset(cmd,0,sizeof(cmd));
	snprintf(cmd,128, "echo 1 > /sys/class/pwm/pwmchip0/pwm0/enable");
	system(cmd);

	return RETURN_OK;
}

INT platform_hal_getLed(PLEDMGMT_PARAMS pValue)
{
	FILE *fp = NULL;
	char buf[64] = {0};
	int duty_cycle = 0;
	int period = 0;

	if (pValue == NULL)
	{
		return RETURN_ERR;
	}
	pValue->LedColor = 0;

	fp = fopen("/sys/class/pwm/pwmchip0/pwm0/duty_cycle", "r");
	if(fp == NULL)
	{
		return RETURN_ERR;
	}

	if(fgets(buf, sizeof(buf) - 1, fp) != NULL)
	{
		duty_cycle = atoi(buf);
	}else{
		fclose(fp);
		return RETURN_ERR;
	}
	fclose(fp);
	
	if(duty_cycle == 0)
	{
		pValue->State = 0;
		pValue->Interval = 0;
		return RETURN_OK;
	}else{
		pValue->State = 1;
	}
	fp = fopen("/sys/class/pwm/pwmchip0/pwm0/period", "r");
	if(fp == NULL)
	{
		return RETURN_ERR;
	}

	if(fgets(buf, sizeof(buf) - 1, fp) != NULL)
	{
		period = atoi(buf);
	}else{
		fclose(fp);
		return RETURN_ERR;
	}
	fclose(fp);

	if (period == 0)
		return RETURN_ERR;
	pValue->Interval = (1000000000 / period);

	return RETURN_OK;

}

INT platform_hal_getCMTSMac(CHAR *pValue)
{
	return platform_hal_GetBaseMacAddress(pValue);
}

/* platform_hal_SetSNMPOnboardRebootEnable() function */
/**
* @description : Set SNMP Onboard Reboot Enable value
*                to allow or ignore SNMP reboot
* @param IN    : pValue - SNMP Onboard Reboot Enable value
                 ("disable" or "enable")
*
* @return      : The status of the operation
* @retval      : RETURN_OK if successful
* @retval      : RETURN_ERR if any error is detected
*/
INT platform_hal_SetSNMPOnboardRebootEnable(CHAR* pValue)
{
	if(pValue == NULL)
	{
		return RETURN_ERR;
	}else{
		if(strcmp(pValue,"enable") == 0)
			system("systemctl enable snmpd");
		else if (strcmp(pValue,"disable") == 0)
			system("systemctl disable snmpd");
	}	
	return RETURN_OK;

}

UINT platform_hal_getFanSpeed(UINT fanIndex)
{
	unsigned speed = 3600;
	
	return speed;
}

UINT platform_hal_getRPM(UINT fanIndex)
{
	unsigned speed = 3600;
	
	return speed;
}

INT platform_hal_getRotorLock(UINT fanIndex)
{
	/* -1=> Not_Applicable ,0=> false  1 => ture */
	return RETURN_OK;
}

BOOLEAN platform_hal_getFanStatus(UINT fanIndex)
{
	FILE *pdbFile = NULL;
	char buf[128]={0};


	pdbFile = fopen("/sys/class/pwm/pwmchip0/pwm0/enable", "r");
	if(pdbFile != NULL)
	{
		fread(buf,sizeof(buf),1,pdbFile);
		fclose(pdbFile); 
		if(atoi(buf))
			return TRUE;
		else
			return FALSE;
	}
	else
	{
		return FALSE;
	}
}

INT platform_hal_setFanMaxOverride(BOOLEAN bOverrideFlag, UINT fanIndex)
{
	return RETURN_OK;	
}

INT platform_hal_GetRouterRegion(CHAR* pValue)
{
    char buf[128] = {0};
	char cmd[128] = {0}; 
	FILE *fp = NULL;

    if(pValue == NULL)
		return RETURN_ERR;

    sprintf(cmd,"hostapd_cli -i wifi0 status driver | grep country | cut -d '=' -f2");

	fp = popen(cmd, "r");
	if(fp != NULL)
	{
		if(fgets(buf,sizeof(buf),fp) != NULL)
		{
			pclose(fp);
			if (strlen(buf) > 0) {
				/* strip trailing newline before copying */
				buf[strcspn(buf, "\n")] = '\0';
				snprintf(pValue, sizeof(buf), "%s", buf);
			}
		}else{
			pclose(fp);
			return RETURN_ERR;
		}
		
	}else{
		return RETURN_ERR;
	}

    return RETURN_OK;

}

INT platform_hal_GetMACsecEnable(INT ethPort, BOOLEAN *pFlag)
{
	FILE *fp = NULL;
	char buf[64] = {0};
	char cmd[128] = {0};
	
	if (pFlag == NULL)
	{
		return RETURN_ERR;
	}else{
		*pFlag = FALSE;
		snprintf(cmd,128, "systemctl status MACSec | grep Loaded");
		fp = popen(cmd, "r");
		if(fp != NULL)
		{
			if(fgets(buf,sizeof(buf),fp) != NULL)
			{
				if (strstr(buf, "enabled") != NULL)
					*pFlag = TRUE;
			}
			pclose(fp);
		}
	}
	return RETURN_OK;

}


INT platform_hal_SetMACsecEnable(INT ethPort, BOOLEAN Flag)
{
	char cmd[128] = {0}; 

	if(Flag)
	{
		sprintf(cmd, "systemctl enable MACSec");
		system(cmd);
	}else{
		sprintf(cmd, "systemctl disable MACSec");
		system(cmd);
	}
		
	return RETURN_OK;
}

INT platform_hal_GetMACsecOperationalStatus(INT ethPort, BOOLEAN *pFlag)
{
	FILE *fp = NULL;
	char buf[64] = {0};
	char cmd[128] = {0};
	
	if (pFlag == NULL)
	{
		return RETURN_ERR;
	}else{
		*pFlag = FALSE;
		snprintf(cmd,128, "systemctl status MACSec | grep Active");
		fp = popen(cmd, "r");
		if(fp != NULL)
		{
			if(fgets(buf,sizeof(buf),fp) != NULL)
			{
				if (strstr(buf, "active") != NULL)
					*pFlag = TRUE;
			}
			pclose(fp);
		}
	}
	return RETURN_OK;

}

INT platform_hal_StartMACsec(INT ethPort, INT timeoutSec)
{
	char cmd[128] = {0};
	
	sprintf(cmd, "systemctl restart MACSec");
	system(cmd);

	return RETURN_OK;
}

INT platform_hal_StopMACsec(INT ethPort)
{
	char cmd[128] = {0};
	
	sprintf(cmd, "systemctl stop MACSec");
	system(cmd);

	return RETURN_OK;
}

INT platform_hal_GetMemoryPaths(RDK_CPUS index, PPLAT_PROC_MEM_INFO *ppinfo)
{
	if(ppinfo == NULL)
		return RETURN_ERR;	

	return RETURN_OK;
}

INT platform_hal_SetLowPowerModeState(PPSM_STATE pState)
{
	if(pState == NULL)
		return RETURN_ERR;	

	pState = PSM_NOT_SUPPORTED;

	return RETURN_OK;
}

INT platform_hal_setDscp(WAN_INTERFACE interfaceType , TRAFFIC_CNT_COMMAND cmd , char* pDscpVals)
{


	if(pDscpVals == NULL)
		return RETURN_ERR;	

	if(interfaceType == EWAN){
		if(cmd == TRAFFIC_CNT_START){
	
		}else if(cmd == TRAFFIC_CNT_STOP){
	
		}
	}	
	return RETURN_OK;
}

INT platform_hal_resetDscpCounts(WAN_INTERFACE interfaceType)
{
	return RETURN_OK;
}

INT platform_hal_getDscpClientList(WAN_INTERFACE interfaceType , pDSCP_list_t pDSCP_List)
{
	return RETURN_OK;
}

char ifname[32];
char *get_current_wan_ifname()
{
	FILE *fp = NULL;
	char command[128] = {0};
	char ert_ifname[32] = {0};
	snprintf(command, 128, "sysevent get %s", "current_wan_ifname");
	fp = popen(command, "r");
	if (fp == NULL)
	{
		return "0";
	}
	if (fgets(ert_ifname, sizeof(ert_ifname), fp) != NULL)
	{
		if(strlen(ert_ifname) == 0){
			fprintf(stderr, "%s %d syseventError %d\n", __FUNCTION__, __LINE__, RETURN_ERR);
			pclose(fp);
			return "0";
		}
	}	
	pclose(fp);
	{
		size_t len = strlen(ert_ifname);
		/* strip trailing newline if present */
		if (len > 0 && ert_ifname[len - 1] == '\n')
			ert_ifname[--len] = '\0';
		if (len == 0)
			return "0";
		memset(ifname, 0, sizeof(ifname));
		snprintf(ifname, sizeof(ifname), "%s", ert_ifname);
	}

	return ifname;
}



INT platform_hal_GetDhcpv6_Options ( dhcp_opt_list ** req_opt_list, dhcp_opt_list ** send_opt_list)
{
	if ((req_opt_list == NULL) || (send_opt_list == NULL))    
	{
		return RETURN_ERR;
	}

	return RETURN_OK;
}



INT platform_hal_GetDhcpv4_Options ( dhcp_opt_list ** req_opt_list, dhcp_opt_list ** send_opt_list)
{
	if ((req_opt_list == NULL) || (send_opt_list == NULL))    
	{
		return RETURN_ERR;
	}

	return RETURN_OK;
}

INT platform_hal_GetFirmwareBankInfo(FW_BANK bankIndex, PFW_BANK_INFO pFW_Bankinfo)
{
    return RETURN_OK;
}

INT platform_hal_GetInterfaceStats(const char *ifname,PINTF_STATS pIntfStats)
{
    return RETURN_OK;
}