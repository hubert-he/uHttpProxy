/*
**  Author: hubert_he@realsil.com.cn
**  3rdParty: tinyProxy: https://banu.com/tinyproxy/
**  About FTP proxy: squid http://www.squid-cache.org/
** Http Proxy: asynchronous and non-block socket implementation
** 
*/

#include "proxyFTP.h"

#define MAX_URL  8192

static const char *const crlf = "\r\n";

#define CTRL_BUFLEN 1024
/// \ingroup ServerProtocolFTPInternal
static char cbuf[CTRL_BUFLEN];

/// \ingroup ServerProtocolFTPInternal
typedef enum {
    BEGIN,
    SENT_USER,
    SENT_PASS,
    SENT_TYPE,
    SENT_MDTM,
    SENT_SIZE,
    SENT_EPRT,
    SENT_PORT,
    SENT_EPSV_ALL,
    SENT_EPSV_1,
    SENT_EPSV_2,
    SENT_PASV,
    SENT_CWD,
    SENT_LIST,
    SENT_NLST,
    SENT_REST,
    SENT_RETR,
    SENT_STOR,
    SENT_QUIT,
    READING_DATA,
    WRITING_DATA,
    SENT_MKDIR
} ftp_state_t;

typedef void (FTPSM) (FtpStateData *);


static FTPSM ftpReadWelcome;
static FTPSM ftpSendUser;
static FTPSM ftpReadUser;
static FTPSM ftpSendPass;
static FTPSM ftpReadPass;
static FTPSM ftpSendType;
static FTPSM ftpReadType;
static FTPSM ftpSendMdtm;
static FTPSM ftpReadMdtm;
static FTPSM ftpSendSize;
static FTPSM ftpReadSize;
static FTPSM ftpSendEPRT;
static FTPSM ftpReadEPRT;
static FTPSM ftpSendPORT;
static FTPSM ftpReadPORT;
static FTPSM ftpSendPassive;
static FTPSM ftpReadEPSV;
static FTPSM ftpReadPasv;
static FTPSM ftpTraverseDirectory;
static FTPSM ftpListDir;
static FTPSM ftpGetFile;
static FTPSM ftpSendCwd;
static FTPSM ftpReadCwd;
static FTPSM ftpRestOrList;
static FTPSM ftpSendList;
static FTPSM ftpSendNlst;
static FTPSM ftpReadList;
static FTPSM ftpSendRest;
static FTPSM ftpReadRest;
static FTPSM ftpSendRetr;
static FTPSM ftpReadRetr;
static FTPSM ftpReadTransferDone;
static FTPSM ftpSendStor;
static FTPSM ftpReadStor;
static FTPSM ftpWriteTransferDone;
static FTPSM ftpSendReply;
static FTPSM ftpSendMkdir;
static FTPSM ftpReadMkdir;
static FTPSM ftpFail;
static FTPSM ftpSendQuit;
static FTPSM ftpReadQuit;


FTPSM *FTP_SM_FUNCS[] = {
    ftpReadWelcome,		/* BEGIN */
    ftpReadUser,		/* SENT_USER */
    ftpReadPass,		/* SENT_PASS */
    ftpReadType,		/* SENT_TYPE */
    ftpReadMdtm,		/* SENT_MDTM */
    ftpReadSize,		/* SENT_SIZE */
    ftpReadEPRT,		/* SENT_EPRT */
    ftpReadPORT,		/* SENT_PORT */
    ftpReadEPSV,		/* SENT_EPSV_ALL */
    ftpReadEPSV,		/* SENT_EPSV_1 */
    ftpReadEPSV,		/* SENT_EPSV_2 */
    ftpReadPasv,		/* SENT_PASV */
    ftpReadCwd,		/* SENT_CWD */
    ftpReadList,		/* SENT_LIST */
    ftpReadList,		/* SENT_NLST */
    ftpReadRest,		/* SENT_REST */
    ftpReadRetr,		/* SENT_RETR */
    ftpReadStor,		/* SENT_STOR */
    ftpReadQuit,		/* SENT_QUIT */
    ftpReadTransferDone,	/* READING_DATA (RETR,LIST,NLST) */
    ftpWriteTransferDone,	/* WRITING_DATA (STOR) */
    ftpReadMkdir		/* SENT_MKDIR */
};

/// handler called by Comm when FTP control channel is closed unexpectedly
void
FtpStateData::ctrlClosed(const CommCloseCbParams &io)
{
    debugs(9, 4, HERE);
    ctrl.clear();
    mustStop("FtpStateData::ctrlClosed");
}

static void ftpParseControlReply(char *buf_line, int *codep)
{
	unsigned char line_len = strlen(buf_line);
	char *s = buf_line;
	*codep = -1;
	if(line_len > 3)
		if (*s >= '0' && *s <= '9' && (*(s + 3) == '-' || *(s + 3) == ' '))
			*codep = atoi(s);
}

static int handleControlReply(FtpStateData *ftp_fwd_ops)
{
	ftpParseControlReply(ftp_fwd_ops->ctrl.buf, &(ftp_fwd_ops->ctrl.replycode));
	log_message(LOG_INFO, "state= %d, code= %d", ftp_fwd_ops->state, ftp_fwd_ops->ctrl.replycode);
	if(ftp_fwd_ops->ctrl.replycode > 0)
    {
    	FTP_SM_FUNCS[state] (ftp_fwd_ops);
		return TRUE;
	}
	else
		return -1;
	
}

static int scheduleReadControlReply(int fd, FtpStateData *ftp_fwd_ops)
{
	proxyCCB *proxy_ccb = NULL;
	log_message(LOG_INFO, "FTP: Ctrl schedule: fd = %d", fd);
	if(ftp_fwd_ops->io.io_errno < 0 && ftp_fwd_ops->io.io_write)
	{
		log_message(LOG_INFO, "FTP: Ctrl schedule: fd = %d io_errno=%d\n", fd, ftp_fwd_ops->io.io_errno);
		return -1;
	}
	int len = readline2 (fd, &ftp_fwd_ops->ctrl.buf, 0);
	if(len < 0)
	{
		if(len == -PROXY_WAIT_MSG)
		{
			return -PROXY_WAIT_MSG;
			//httpProxy_event_notify(fd, HTTP_PROXY_REMOTE_DATA, );
		}
		return len;
	}
	else
	{
		return handleControlReply(ftp_fwd_ops);
	}
}

static void ftpStateInit(struct FtpStateData *ftp_stat)
{
	memset(ftp_stat, 0, sizeof(FtpStateData));
}

int ftpStateStart(struct conn_s *connptr)
{
	struct FtpStateData *ftpFwdOps = NULL;
	if(connptr->ftpFwd)
	{
		log_message(LOG_ERR, "connptr->ftpFwd = %x\n", connptr->ftpFwd);
		return -1;
	}
	ftpFwdOps = connptr->ftpFwd = xmalloc(sizeof(struct FtpStateData));
	
	ftpFwdOps->state = BEGIN;
	return scheduleReadControlReply(connptr->server_fd, ftpFwdOps);
}

int handle_ftp_http_tunnel(void *datap)
{
	FtpStateData *ftpFwdOps = (FtpStateData *)datap;
	int len = 0, fd = conns->server_fd;
	struct conn_s *conns =  ftpFwdOps->ctrl.ctrl_conn;
	if(ftpFwdOps->ctrl.buf)
	{
		len = proxy_send (fd, ftpFwdOps->ctrl.buf, ftpFwdOps->ctrl.size, 0);
		ftpFwdOps->io.io_write = 1;
		ftpFwdOps->io.io_errno = 0;

		if(len < 0) // < 0, not 0
		{
			if(ignoreErrno(len))
			{
				httpProxy_event_notify(fd, HTTP_PROXY_REMOTE_DATA, datap);
				return 0;
			}
			else
				ftpFwdOps->io.io_errno = len;
			return len;
		}
		else
		{
			if(ftpFwdOps->ctrl.size == len)
			{
				ftpFwdOps->io.io_write = 0;
				memset(ftpFwdOps->ctrl.buf, 0, 1024)
				// need free???
			}
		}
	}
	// reading
	return scheduleReadControlReply(fd, ftpFwdOps);

}

static void
ftpReadWelcome(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    log_message(LOG_ERR, "start");
/*
    if (ftpState->flags.pasv_only)
        ++ ftpState->login_att;
*/
    if (code == 220) {
		/*
        if (ftpState->ctrl.message) {
            if (strstr(ftpState->ctrl.message->key, "NetWare"))
                ftpState->flags.skip_whitespace = 1;
        }
*/
        ftpSendUser(ftpState);
    } else if (code == 120) {
        if (NULL != ftpState->ctrl.message)
            log_message(LOG_WARNING, "FTP server is busy: %s", ftpState->ctrl.message->key);

        return;
    } else {
        ftpFail(ftpState);
    }
}

static void writeCommand(FtpStateData * ftp_state)
{
	int fd = ftp_state->ctrl.ctrl_conn->client_fd;
	httpProxy_event_notify(fd, HTTP_PROXY_REMOTE_DATA, ftp_state);
}

static void loginFailed(FtpStateData * ftpState)
{
	log_message(LOG_FTP_DEB, "login: Failed");
}

static void
ftpSendUser(FtpStateData * ftpState)
{
    /* check the server control channel is still available */
/*
    if (!ftpState || !ftpState->haveControlChannel("ftpSendUser"))
        return;

    if (ftpState->proxy_host != NULL)
        snprintf(cbuf, CTRL_BUFLEN, "USER %s@%s\r\n",
                 ftpState->user,
                 ftpState->request->GetHost());
    else
*/
        snprintf(ftpState->ctrl.buf, CTRL_BUFLEN, "USER %s\r\n", ftpState->user);

    writeCommand(ftpState);

    ftpState->state = SENT_USER;
}

static void
ftpReadUser(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    log_message(LOG_FTP_DEB, "code = %d\n", code);

    if (code == 230) {
        ftpReadPass(ftpState);
    } else if (code == 331) {
        ftpSendPass(ftpState);
    } else {
        loginFailed(ftpState);
    }
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpSendPass(FtpStateData * ftpState)
{
    /* check the server control channel is still available */
 //   if (!ftpState || !ftpState->haveControlChannel("ftpSendPass"))
 //       return;

    snprintf(ftpState->ctrl.buf, CTRL_BUFLEN, "PASS %s\r\n", ftpState->password);
    writeCommand(ftpState);
    ftpState->state = SENT_PASS;
}

/// \ingroup ServerProtocolFTPInternal
static void
ftpReadPass(FtpStateData * ftpState)
{
    int code = ftpState->ctrl.replycode;
    log_message(LOG_FTP_DEB, "code=", code);

    if (code == 230) {
        //ftpSendType(ftpState);
        ftpSendQuit(ftpState);
    } else {
        loginFailed(ftpState);
    }
}

static void
ftpSendQuit(FtpStateData * ftpState)
{
    /* check the server control channel is still available */
    if (!ftpState || !ftpState->haveControlChannel("ftpSendQuit"))
        return;

    snprintf(ftpState->ctrl.buf, CTRL_BUFLEN, "QUIT\r\n");
    writeCommand(ftpState);
    ftpState->state = SENT_QUIT;
}

static void
ftpReadQuit(FtpStateData * ftpState)
{
    ftpState->serverComplete();
}


