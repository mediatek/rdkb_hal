// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 MediaTek Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>

#include "fwupgrade_hal.h"
#define HTTP_DWNLD_CONFIG_FILE      "/tmp/httpDwnld.conf"
#define HTTP_DWNLD_IF_FILE          "/tmp/httpDwnldIf.conf"

#define REBOOT_REASON_SW_UPGRADE    "Software_upgrade"

static int gDwdInProgressFlag = 0; /* flag to set dload inprogress */

#define HAL_URL_MAXLEN   1024
#define HAL_FNAME_MAXLEN 256

/* Open a file inside /tmp/xconf using O_NOFOLLOW on both the directory and
 * the file, so a symlink at either level cannot redirect the operation. */
static int open_xconf_file(const char *filename, int flags, mode_t mode)
{
	int xfd = open("/tmp/xconf", O_RDONLY | O_NOFOLLOW | O_DIRECTORY);
	if (xfd < 0)
		return -1;
	int ffd = openat(xfd, filename, flags | O_NOFOLLOW, mode);
	close(xfd);
	return ffd;
}

static int is_valid_filename(const char *name)
{
	size_t i, len;
	if (!name) return 0;
	len = strlen(name);
	if (len == 0 || len > 127) return 0;
	if (name[0] == '.') return 0;
	for (i = 0; i < len; i++) {
		char c = name[i];
		if (!isalnum((unsigned char)c) && c != '.' && c != '-' && c != '_')
			return 0;
	}
	return 1;
}

static INT fwupgrade_hal_util_get_syscmd_output( char *pCmd, char *pOutput, int iOutputSize );
static INT fwupgrade_hal_get_download_url_ex(char *pUrl, size_t urlSize, char *pfilename, size_t fnameSize);

/* * fwupgrade_hal_util_get_syscmd_output() */
static INT fwupgrade_hal_util_get_syscmd_output( char *pCmd, char *pOutput, int iOutputSize )
{
	FILE   *FilePtr            = NULL;
	char   bufContent[ 256 ]  = { 0 };

	if ( ( NULL == pCmd ) || ( NULL == pOutput ) || ( 0 == iOutputSize ) )
	{
		return RETURN_ERR;
	}

	FilePtr = popen( pCmd, "r" );

	if ( FilePtr )
	{
		char *pos;

		if ( fgets( bufContent, 256, FilePtr ) == NULL )
		{
			pclose( FilePtr );
			return RETURN_ERR;
		}
		pclose( FilePtr );
		FilePtr = NULL;

		// Remove line \n charecter from string
		if ( ( pos = strchr( bufContent, '\n' ) ) != NULL )
			*pos = '\0';

		snprintf( pOutput, iOutputSize, "%s", bufContent );
		return RETURN_OK;
	}

	return RETURN_ERR;
}


/*
    download the image from httpserver and store in /tmp
 */
static INT download_image_from_server(char *httpUrl, char *fileName)
{
	char destPath[300] = {0};
	pid_t pid;
	int status = -1, curl_ret;
	FILE *fp = NULL;

	if (mkdir("/tmp/xconf", 0700) != 0 && errno != EEXIST)
		return RETURN_ERR;

	/* Verify /tmp/xconf is a real directory, not a symlink */
	{
		struct stat st;
		if (lstat("/tmp/xconf", &st) != 0 || !S_ISDIR(st.st_mode))
		{
			fprintf(stderr, "%s: /tmp/xconf is not a real directory\n", __func__);
			return RETURN_ERR;
		}
	}

	snprintf(destPath, sizeof(destPath), "/tmp/%s", fileName);

	/* O_TRUNC (not O_EXCL) so a second download overwrites the previous
	 * image; O_RDWR so the same fd can be handed to sysupgrade later. */
	int destfd = open(destPath, O_RDWR | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
	if (destfd < 0) {
		fprintf(stderr, "%s: cannot pre-create %s\n", __func__, destPath);
		return RETURN_ERR;
	}
	fprintf(stderr, "%s: downloading %s to %s\n", __func__, httpUrl, destPath);

	pid = fork();
	if (pid < 0) {
		close(destfd);
		return RETURN_ERR;
	}
	if (pid == 0) {
		char fdPath[32] = {0};
		snprintf(fdPath, sizeof(fdPath), "/dev/fd/%d", destfd);
		char *argv[] = { "curl", "--proto", "=https,http",
		                 "--proto-redir", "=https,http",
		                 "-fgLo", fdPath, httpUrl, NULL };
		execv("/usr/bin/curl", argv);
		_exit(127);
	}
	{
		pid_t wret;
		do { wret = waitpid(pid, &status, 0); } while (wret < 0 && errno == EINTR);
		if (wret < 0)
		{
			fprintf(stderr, "%s: waitpid for curl failed\n", __func__);
			close(destfd);
			return RETURN_ERR;
		}
	}

	curl_ret = (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : 1;

	if (curl_ret != 0) {
		unlink(destPath);
		close(destfd);
		printf("download from remote server failed!\n");
		return RETURN_ERR;
	}

	fprintf(stderr, "### Debug ### Image download successful at %s\n", destPath);

	/* Rewind so sysupgrade reads from the beginning of the image. */
	if (lseek(destfd, 0, SEEK_SET) == (off_t)-1)
	{
		fprintf(stderr, "%s: lseek failed\n", __func__);
		close(destfd);
		return RETURN_ERR;
	}

	/* Flash the image via the same fd curl wrote to — the kernel resolves
	 * /dev/fd/N directly to the inode, eliminating the TOCTOU window
	 * between download and sysupgrade open. */
	{
		char fdPath[32] = {0};
		pid_t spid;
		int sstat = 0;
		snprintf(fdPath, sizeof(fdPath), "/dev/fd/%d", destfd);
		spid = fork();
		if (spid < 0) {
			fprintf(stderr, "%s: fork for sysupgrade failed\n", __func__);
			close(destfd);
			return RETURN_ERR;
		}
		if (spid == 0) {
			char *sargv[] = { "sysupgrade", fdPath, NULL };
			execv("/sbin/sysupgrade", sargv);
			_exit(127);
		}
		{
			pid_t wret;
			do { wret = waitpid(spid, &sstat, 0); } while (wret < 0 && errno == EINTR);
			if (wret < 0)
			{
				fprintf(stderr, "%s: waitpid for sysupgrade failed\n", __func__);
				close(destfd);
				return RETURN_ERR;
			}
		}
		int sysupgrade_ok = (WIFEXITED(sstat) && WEXITSTATUS(sstat) == 0) ? 1 : 0;

		/* Write dload_status after sysupgrade completes so get_download_status()
		 * returns 100 (in-progress) during flash, and reflects the real result. */
		{
			int sfd = open_xconf_file("dload_status",
			                          O_WRONLY | O_CREAT | O_TRUNC, 0600);
			if (sfd >= 0) {
				fp = fdopen(sfd, "w");
				if (fp) {
					fprintf(fp, "%d\n", sysupgrade_ok ? 0 : 1);
					fclose(fp);
				} else {
					close(sfd);
				}
			}
		}

		if (!sysupgrade_ok)
		{
			fprintf(stderr, "%s: sysupgrade failed (exit %d)\n",
			        __func__, WIFEXITED(sstat) ? WEXITSTATUS(sstat) : -1);
			close(destfd);
			return RETURN_ERR;
		}
	}
	close(destfd);
	return RETURN_OK;
}

/* FW Download HAL API Prototype */
/* fwupgrade_hal_set_download_url  - 1 */
/* Description: Set Download Settings
Parameters : char* pUrl;
Parameters : char* pfilename;

@return the status of the operation
@retval RETURN_OK if successful.
@retval RETURN_ERR if any Downloading is in process or Url string is invalided.
*/
INT fwupgrade_hal_set_download_url (char* pUrl, char* pfilename)
{
	fprintf(stderr,"Entering %s \n",__FUNCTION__);
	if ((pUrl == NULL) || (pfilename==NULL))
	{
		return RETURN_ERR;
	}

	if (__sync_add_and_fetch(&gDwdInProgressFlag, 0) != 0)
	{
		fprintf(stderr, "%s: download in progress, rejected\n", __func__);
		return RETURN_ERR;
	}
	else
	{
		FILE* fp = NULL;
		char httpUrl[HAL_URL_MAXLEN] = {0};
		char fileName[HAL_FNAME_MAXLEN] = {0};
		int ret_status = 0;

		if (!is_valid_filename(pfilename))
		{
			fprintf(stderr, "%s: invalid filename rejected\n", __func__);
			return RETURN_ERR;
		}

		if (strchr(pUrl, '\n') || strchr(pUrl, '\r'))
		{
			fprintf(stderr, "%s: URL contains newline, rejected\n", __func__);
			return RETURN_ERR;
		}

		if (strlen(pUrl) >= HAL_URL_MAXLEN - 1)
		{
			fprintf(stderr, "%s: URL too long, rejected\n", __func__);
			return RETURN_ERR;
		}

		/* To Get the previous URL if any and compare with new one */
		ret_status = fwupgrade_hal_get_download_url_ex(httpUrl, sizeof(httpUrl), fileName, sizeof(fileName));

		if(ret_status == RETURN_OK)
		{
			if ((strcmp(httpUrl, pUrl) == 0) && (strcmp(fileName, pfilename) == 0))
			{
				fprintf(stderr,"HTTP URL and file name is same as previous! \n");
			}
			else
			{
				fprintf(stderr,"HTTP URL or filename Changed! \n");
				{
					int xfd = open("/tmp/xconf", O_RDONLY | O_NOFOLLOW | O_DIRECTORY);
					if (xfd >= 0) { unlinkat(xfd, "dload_status", 0); close(xfd); }
				}
			}
		}
		else
		{
			int xfd = open("/tmp/xconf", O_RDONLY | O_NOFOLLOW | O_DIRECTORY);
			if (xfd >= 0) { unlinkat(xfd, "dload_status", 0); close(xfd); }
		}
		{
			int fd = open(HTTP_DWNLD_CONFIG_FILE,
			              O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
			if (fd < 0)
			{
				fprintf(stderr, "%s: cannot open config file: %s\n", __func__, HTTP_DWNLD_CONFIG_FILE);
				return RETURN_ERR;
			}
			fp = fdopen(fd, "w");
			if (fp == NULL)
			{
				close(fd);
				return RETURN_ERR;
			}
		}
		fprintf(fp, "%s\n%s\n", pUrl, pfilename);
		fclose(fp);
		fprintf(stderr,"%s Stored HTTP download URL and filename to %s file\n", __func__, HTTP_DWNLD_CONFIG_FILE);

		return RETURN_OK;
	}
}


/* fwupgrade_hal_get_download_Url: */
/* Description: Get FW Download Url
Parameters : char* pUrl
Parameters : char* pfilename;
@return the status of the operation.
@retval RETURN_OK if successful.
@retval RETURN_ERR if http url string is empty.
*/
INT fwupgrade_hal_get_download_url_ex (char *pUrl, size_t urlSize, char *pfilename, size_t fnameSize)
{
	if ((pUrl == NULL) || (pfilename==NULL) || (urlSize == 0) || (fnameSize == 0))
	{
		return RETURN_ERR;
	}
	else
	{
		FILE* fp = NULL;

		fprintf(stderr,"Entering %s\n", __func__);

		{
			int rfd = open(HTTP_DWNLD_CONFIG_FILE, O_RDONLY | O_NOFOLLOW);
			if (rfd < 0) return RETURN_ERR;
			fp = fdopen(rfd, "r");
			if (fp == NULL) { close(rfd); return RETURN_ERR; }
		}
		char linebuf[HAL_URL_MAXLEN] = {0};

		if (fgets(linebuf, sizeof(linebuf), fp) == NULL) { fclose(fp); return RETURN_ERR; }
		linebuf[strcspn(linebuf, "\n")] = '\0';
		snprintf(pUrl, urlSize, "%s", linebuf);

		if (fgets(linebuf, sizeof(linebuf), fp) == NULL) { fclose(fp); return RETURN_ERR; }
		linebuf[strcspn(linebuf, "\n")] = '\0';
		snprintf(pfilename, fnameSize, "%s", linebuf);

		fprintf(stderr,"%s pfilename: %s\n", __func__, pfilename);
		fclose(fp);

		return RETURN_OK;
	}
}

INT fwupgrade_hal_get_download_url (char *pUrl, char* pfilename)
{
	return fwupgrade_hal_get_download_url_ex(pUrl, HAL_URL_MAXLEN, pfilename, HAL_FNAME_MAXLEN);
}

/* interface=0 for wan0, interface=1 for erouter0 */
INT fwupgrade_hal_set_download_interface(unsigned int interface)
{
	fprintf(stderr,"Entering %s\n", __func__);
	FILE *fp = NULL;	
	if( interface > 1 )
	{
		return RETURN_ERR;
	}
	// Save the interface numerical value to the config file
	{
		int ifd = open(HTTP_DWNLD_IF_FILE,
		               O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
		if (ifd < 0)
			return RETURN_ERR;
		fp = fdopen(ifd, "w");
		if (fp == NULL) { close(ifd); return RETURN_ERR; }
	}
	fprintf(fp, "%d\n", interface);
	fclose(fp);
	return RETURN_OK;
}


/* interface=0 for wan0, interface=1 for erouter0 */
INT fwupgrade_hal_get_download_interface(unsigned int* pinterface)
{
	if (pinterface == NULL)
	{
		return RETURN_ERR;
	}
	else
	{
		FILE *fp = NULL;

		{
			int rfd = open(HTTP_DWNLD_IF_FILE, O_RDONLY | O_NOFOLLOW);
			if (rfd < 0) return RETURN_ERR;
			fp = fdopen(rfd, "r");
			if (fp == NULL) { close(rfd); return RETURN_ERR; }
		}
		char ifbuf[4] = {0};
		int ch = fgetc(fp);
		if (ch == EOF) { fclose(fp); return RETURN_ERR; }
		ifbuf[0] = (char)ch;
		{
			char *endptr = NULL;
			long val = strtol(ifbuf, &endptr, 10);
			if (endptr == ifbuf || val < 0 || val > 1)
			{
				fprintf(stderr, "%s: invalid interface value in config\n", __func__);
				fclose(fp);
				return RETURN_ERR;
			}
			*pinterface = (unsigned int)val;
		}
		fprintf(stderr,"%s Download interface numerical value: %d\n", __func__, *pinterface);
		fclose(fp);
		return RETURN_OK;
	}
}


/* fwupgrade_hal_download */
/**
Description: Start FW Download
Parameters: <None>
@return the status of the operation.
@retval RETURN_OK if successful.
@retval RETURN_ERR if any Downloading is in process.

*/
INT fwupgrade_hal_download ()
{
    fprintf(stderr,"Entering %s\n", __func__);
    char dlHttpUrl[HAL_URL_MAXLEN] = {0};
    char dlFilename[HAL_FNAME_MAXLEN] = {0};

    if (__sync_val_compare_and_swap(&gDwdInProgressFlag, 0, 1) != 0)
    {
        fprintf(stderr, "%s: download already in progress, rejected\n", __func__);
        return RETURN_ERR;
    }

    if( fwupgrade_hal_get_download_url_ex(dlHttpUrl, sizeof(dlHttpUrl), dlFilename, sizeof(dlFilename)) != RETURN_OK)
    {
        __sync_lock_release(&gDwdInProgressFlag);
        return RETURN_ERR;
    }

    if (!is_valid_filename(dlFilename))
    {
        fprintf(stderr, "%s: invalid filename from config, rejected\n", __func__);
        __sync_lock_release(&gDwdInProgressFlag);
        return RETURN_ERR;
    }

    if( strncmp(dlHttpUrl, "http://", 7) != 0 && strncmp(dlHttpUrl, "https://", 8) != 0 )
    {
        fprintf(stderr, "%s: URL scheme not http/https, rejected\n", __func__);
        __sync_lock_release(&gDwdInProgressFlag);
        return RETURN_ERR;
    }

    /* Extract hostname for reachability check */
    {
        const char *p = strstr(dlHttpUrl, "://");
        char hostname[256] = {0};
        int j = 0;
        struct addrinfo hints = {0}, *res = NULL;

        p = p ? p + 3 : dlHttpUrl;
        while (*p && *p != '/' && *p != ':' && j < (int)(sizeof(hostname) - 1))
            hostname[j++] = *p++;
        hostname[j] = '\0';

        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(hostname, NULL, &hints, &res) != 0)
        {
            fprintf(stderr, "%s: cannot resolve hostname: %s\n", __func__, hostname);
            __sync_lock_release(&gDwdInProgressFlag);
            return RETURN_ERR;
        }
        fprintf(stderr, "%s: hostname %s resolved OK\n", __func__, hostname);
        freeaddrinfo(res);
    }

    // Download the image and flash (sysupgrade called inside via fd)
    if(RETURN_OK != download_image_from_server(dlHttpUrl, dlFilename))
    {
        fprintf(stderr,"failed download the image to CPE\n");
        __sync_lock_release(&gDwdInProgressFlag);
        return RETURN_ERR;
    }
    __sync_lock_release(&gDwdInProgressFlag);
    return RETURN_OK;
}


/* fwupgrade_hal_get_download_status */
/**
Description: Get the FW Download Status
Parameters : <None>
@return the status of the HTTP Download.
?   0 ? Download is not started.
?   Number between 0 to 100: Values of percent of download.
?   200 ? Download is completed and waiting for reboot.
?   400 -  Invalided Http server Url
?   401 -  Cannot connect to Http server
?   402 -  File is not found on Http server
?   403 -  HW_Type_DL_Protection Failure
?   404 -  HW Mask DL Protection Failure
?   405 -  DL Rev Protection Failure
?   406 -  DL Header Protection Failure
?   407 -  DL CVC Failure
?   500 -  General Download Failure
?   */
INT fwupgrade_hal_get_download_status()
{
	fprintf(stderr,"Entering %s\n", __func__);
	FILE* DL_StatusFile = NULL;
	char str[16] = {0};
	int dl_stat = 0;
	{
		int stfd = open_xconf_file("dload_status", O_RDONLY, 0);
		if (stfd < 0) {
			fprintf(stderr, "%s: dload_status not found\n", __func__);
		} else {
			DL_StatusFile = fdopen(stfd, "r");
			if (DL_StatusFile == NULL) close(stfd);
		}
	}
	if(NULL != DL_StatusFile)
	{
		if (fgets(str, sizeof(str)-1, DL_StatusFile) == NULL)
		{
			fclose(DL_StatusFile);
			fprintf(stderr, "%s: dload_status read failed\n", __func__);
			return 500;
		}
		fclose(DL_StatusFile);
		dl_stat = atoi(str);
		if(0 != dl_stat)
		{
			fprintf(stderr,"download from remote server failed!\n");
			return 500;
		}
		return 200;
	}
	if ( __sync_add_and_fetch(&gDwdInProgressFlag, 0) == 1 )
	{
		return 100;
	}
	return 0;
}

/* fwupgrade_hal_reboot_ready */
/*
Description: Get the Reboot Ready Status
Parameters:
ULONG *pValue- Values of 1 for Ready, 2 for Not Ready
@return the status of the operation.
@retval RETURN_OK if successful.
@retval RETURN_ERR if any error is detected

*/
INT fwupgrade_hal_reboot_ready(ULONG *pValue)
{
    fprintf(stderr,"Entering %s\n", __func__);

    if (pValue == NULL)
    {
        return RETURN_ERR;
    }
    *pValue = (__sync_add_and_fetch(&gDwdInProgressFlag, 0) == 0) ? 1 : 2;
    return RETURN_OK;
}

/* fwupgrade_hal_reboot_now */
/*
Description:  Http Download Reboot Now
Parameters : <None>
@return the status of the reboot operation.
@retval RETURN_OK if successful.
@retval RETURN_ERR if any reboot is in process.
*/
INT fwupgrade_hal_download_reboot_now()
{
	fprintf(stderr,"Entering %s\n", __func__);
	int rebootCount=1,
	    IsNeeds2Configure = 1;
	char cmd[128]={0},
	     acOutput[64] = { 0 };

	if (system("touch /nvram/reboot_due_to_sw_upgrade") != 0)
		fprintf(stderr, "%s: touch /nvram/reboot_due_to_sw_upgrade failed\n", __func__);

	//Check whether already reboot-reason configured or not. since this case will avoid overwrite "Forced_Software_upgrade" reason
	if ( ( RETURN_OK == fwupgrade_hal_util_get_syscmd_output("syscfg get X_RDKCENTRAL-COM_LastRebootCounter", acOutput, sizeof(acOutput)) ) &&
			( 0 == strcmp( acOutput, "1" ) ) )
	{
		//No need to configure this
		IsNeeds2Configure = 0;
	}

	//Configure reboot reason if already not configured
	if( 1 == IsNeeds2Configure )
	{
		snprintf(cmd, sizeof(cmd), "syscfg set X_RDKCENTRAL-COM_LastRebootReason %s ", REBOOT_REASON_SW_UPGRADE);
		if (system(cmd) != 0)
			fprintf(stderr, "%s: syscfg set LastRebootReason failed\n", __func__);
		snprintf(cmd, sizeof(cmd), "syscfg set X_RDKCENTRAL-COM_LastRebootCounter %d ", rebootCount);
		if (system(cmd) != 0)
			fprintf(stderr, "%s: syscfg set LastRebootCounter failed\n", __func__);
		if (system("syscfg commit") != 0)
			fprintf(stderr, "%s: syscfg commit failed\n", __func__);
	}

	fprintf(stderr,"### reboot now ###\n");
	if (system("/rdklogger/backupLogs.sh true") != 0)
		fprintf(stderr, "%s: backupLogs.sh failed\n", __func__);

	// reboot the device
	if (system("/sbin/reboot") != 0)
	{
		fprintf(stderr, "%s: reboot failed\n", __func__);
		return RETURN_ERR;
	}
	return RETURN_OK;
}

/* fwupgrade_hal_update_and_factoryreset */
/*
Description:  Do FW update and Factory reset
Parameters : <None>
@return the status of the operation.
@retval RETURN_OK if successful.
@retval RETURN_ERR if any reboot/Download is in process.
*/
INT fwupgrade_hal_update_and_factoryreset()
{
    fprintf(stderr,"Entering %s\n", __func__);

    /* fwupgrade_hal_download() now downloads and flashes via sysupgrade internally.
     * sysupgrade handles the reboot itself, so no separate reboot call is needed. */
    if(RETURN_OK != fwupgrade_hal_download())
    {
        fprintf(stderr,"failed download the image to CPE\n");
        return RETURN_ERR;
    }

    return RETURN_OK;
}

/*  fwupgrade_hal_download_install: */
/**
* @description: Downloads and upgrades the firmware
* @param None
* @return the status of the Firmware download and upgrade status
* @retval RETURN_OK if successful.
* @retval RETURN_ERR in case of remote server not reachable
*/
INT fwupgrade_hal_download_install(const char *url)
{
    return RETURN_OK;
}
