#define EM_MAX_TARGET_IP		8
#define EM_LOGDIR				"@em_log"
#define EM_LOGPREFIX			"em"
#define EM_CONFIG_FN			"@EtherMirror.config"

#define EM_MAX_QUEUE_SIZE		10000


// Types

struct EM_CONFIG
{
	char InputIf[MAX_PATH];
	char OutputIf[MAX_PATH];
	char OutputMac[6];
	UCHAR Padding[2];
	IP OutputArpSrc;
	UINT NumTargetIp;
	IP TargetIpList[EM_MAX_TARGET_IP];
	UINT ArpInterval;
	UINT ArpTimeout;
};

struct EM
{
	LOG *Log;
	EM_CONFIG *Config;
	THREAD *RecvThread;
	THREAD *SendThread;
	bool Halt;
	QUEUE *SendQueue;
	LOCK *Lock;
	CANCEL *SendCancel;
};

// Functions
EM *NewEm();
void FreeEm(EM *m);
void EmLog(EM *m, char *name, ...);
EM_CONFIG *EmLoadConfig(char *fn);
void EmFreeConfig(EM_CONFIG *c);


void EmRecvThread(THREAD *thread, void *param);
void EmSendThread(THREAD *thread, void *param);
PKT *EmParsePacket(EM *m, UCHAR *data, UINT size);






