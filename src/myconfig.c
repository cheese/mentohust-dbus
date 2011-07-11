/* -*- Mode: C; tab-width: 4; -*- */
/*
* Copyright (C) 2009, HustMoon Studio
*
* 文件名称：myconfig.c
* 摘	要：初始化认证参数
* 作	者：HustMoon@BYHH
* 邮	箱：www.ehust@gmail.com
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#else
static const char *VERSION = "0.3.1";
static const char *PACKAGE_BUGREPORT = "http://code.google.com/p/mentohust/issues/list";
#endif

#include "mentohust.h"
#include "myconfig.h"
#include "i18n.h"
#include "myini.h"
#include "myfunc.h"
#include "dlfunc.h"
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>

/*#define ACCOUNT_SIZE		65	[> 用户名密码长度<]*/
#define NIC_SIZE			16	/* 网卡名最大长度 */
#define MAX_PATH			255	/* FILENAME_MAX */
#define D_TIMEOUT			8	/* 默认超时间隔 */
#define D_ECHOINTERVAL		30	/* 默认心跳间隔 */
#define D_RESTARTWAIT		15	/* 默认重连间隔 */
#define D_STARTMODE			0	/* 默认组播模式 */
#define D_DHCPMODE			0	/* 默认DHCP模式 */
#define D_DAEMONMODE		0	/* 默认daemon模式 */
#define D_MAXFAIL			8	/* 默认允许失败次数 */

#ifdef MAC_OS
static const char *D_DHCPSCRIPT = "dhcping -v -t 15";	/* 默认DHCP脚本 */
#else
static const char *D_DHCPSCRIPT = "dhclient";	/* 默认DHCP脚本 */
#endif
static const char *CFG_FILE = "/etc/mentohust.conf";	/* 配置文件 */
static const char *LOG_FILE = "/tmp/mentohust.log";	/* 日志文件 */
static const char *LOCK_FILE = "/var/run/mentohust.pid";	/* 锁文件 */
#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)	/* 创建掩码 */

#ifndef NO_NOTIFY
#define D_SHOWNOTIFY		5	/* 默认Show Notify模式 */
int showNotify = D_SHOWNOTIFY;	/* 显示通知 */
#endif

extern int bufType;	/*0内置xrgsu 1内置Win 2仅文件 3文件+校验*/
extern u_char version[];	/* 版本 */
char userName[ACCOUNT_SIZE] = "";	/* 用户名 */
char password[ACCOUNT_SIZE] = "";	/* 密码 */
#ifdef LOCAL_CONF
char userNameLocal[ACCOUNT_NUM][ACCOUNT_SIZE] = {""};	/* 当前用户所记录的账户的用户名。
																												由于配置文件的错误编写，数组里
																												面可能有空字符串，在添加用户的
																												时候要遍历检查。*/
char passwordLocal[ACCOUNT_NUM][ACCOUNT_SIZE] = {""};	/* 当前用户所记录的账户的的密码 */
int user_count = 0; /* 记录读入的账户数，其实就是read_count */
int locaUserFlag = 0; /* 指定要使用的账户id，0就是默认主配置文件的账户 */
char localUserPath[MAX_PATH] = ""; /* 本地用户配置文件路径 */
#endif
char nic[NIC_SIZE] = "";	/* 网卡名 */
char dataFile[MAX_PATH] = "";	/* 数据文件 */
char dhcpScript[MAX_PATH] = "";	/* DHCP脚本 */
u_int32_t ip = 0;	/* 本机IP */
u_int32_t mask = 0;	/* 子网掩码 */
u_int32_t gateway = 0;	/* 网关 */
u_int32_t dns = 0;	/* DNS */
u_int32_t pingHost = 0;	/* ping */
u_char localMAC[6];	/* 本机MAC */
u_char destMAC[6];	/* 服务器MAC */
unsigned timeout = D_TIMEOUT;	/* 超时间隔 */
unsigned echoInterval = D_ECHOINTERVAL;	/* 心跳间隔 */
unsigned restartWait = D_RESTARTWAIT;	/* 失败等待 */
unsigned startMode = D_STARTMODE;	/* 组播模式 */
unsigned dhcpMode = D_DHCPMODE;	/* DHCP模式 */
unsigned maxFail = D_MAXFAIL;	/* 允许失败次数 */
pcap_t *hPcap = NULL;	/* Pcap句柄 */
int lockfd = -1;	/* 锁文件描述符 */

static int readFile(int *daemonMode);	/* 读取配置文件来初始化 */
#ifdef LOCAL_CONF
static int readLocalFile(const char *filepath);	/* 读取当前用户的配置文件 返回读取的账户数*/
static int saveLocalConfig(const char*);
int addLocalAccount(const char *, const char *, const char *);
static int haveLocalAccount();
static int getFreeUserNum();
inline void showLocalAccounts();
static int setLocalConfigPath(const char *);
inline void setLocalConfigFilePath(const char *);
#endif
static void readArg(char argc, char **argv, int *saveFlag, int *exitFlag, int *daemonMode);	/* 读取命令行参数来初始化 */
static void showHelp(const char *fileName);	/* 显示帮助信息 */
static int getAdapter();	/* 查找网卡名 */
static void printConfig();	/* 显示初始化后的认证参数 */
static int openPcap();	/* 初始化pcap、设置过滤器 */
static void saveConfig(int daemonMode);	/* 保存参数 */
static void checkRunning(int exitFlag, int daemonMode);	/* 检测是否已运行 */

#ifndef NO_ENCODE_PASS
static const unsigned char base64Tab[] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"};
static const char xorRuijie[] = {"~!:?$*<(qw2e5o7i8x12c6m67s98w43d2l45we82q3iuu1z4xle23rt4oxclle34e54u6r8m"};

static int encodePass(char *dst, const char *osrc) {
    unsigned char in[3], buf[70];
	unsigned char *src = buf;
	int sz = strlen(osrc);
    int i, len;
	if (sizeof(xorRuijie) < sz)
		return -1;
	for(i=0; i<sz; i++)
		src[i] = osrc[i] ^ xorRuijie[i];
    while (sz > 0) {
        for (len=0, i=0; i<3; i++, sz--) {
			if (sz > 0) {
				len++;
				in[i] = src[i];
            } else in[i] = 0;
        }
        src += 3;
        if (len) {
			dst[0] = base64Tab[ in[0] >> 2 ];
			dst[1] = base64Tab[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
			dst[2] = len > 1 ? base64Tab[ ((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6) ] : '=';
			dst[3] = len > 2 ? base64Tab[ in[2] & 0x3f ] : '=';
            dst += 4;
        }
    }
    *dst = '\0';
	return 0;
}

static int decodePass(char *dst, const char *src) {
	unsigned esi = 0, idx = 0;
	int i=0, j=0, equal=0;
	for(; src[i]!='\0'; i++) {
		if (src[i] == '=') {
			if (++equal > 2)
				return -1;
		} else {
			for(idx=0; base64Tab[idx]!='\0'; idx++) {
				if(base64Tab[idx] == src[i])
					break;
			}
			if (idx == 64)
				return -1;
			esi += idx;
		}
		if(i%4 == 3) {
			dst[j++] = (char)(esi>>16);
			if(equal < 2)
				dst[j++] = (char)(esi>>8);
			if(equal < 1)
				dst[j++] = (char)esi;
			esi = 0;
			equal = 0;
		}
		esi <<= 6;
	}
	if (i%4!=0 || sizeof(xorRuijie)<j)
		return -1;
	for(i=0; i<j; i++)
		dst[i] ^= xorRuijie[i];
	dst[j] = '\0';
	return 0;
}
#endif

void initConfig(int argc, char **argv)
{
	int saveFlag = 0;	/* 是否需要保存参数 */
	int exitFlag = 0;	/* 0Nothing 1退出 2重启 */
	int daemonMode = D_DAEMONMODE;	/* 是否后台运行 */

	printf(_("\n欢迎使用MentoHUST\t版本: %s\n"
			"Copyright (C) 2009-2010 HustMoon Studio\n"
			"人到华中大，有甜亦有辣。明德厚学地，求是创新家。\n"
			"Bug report to %s\n\n"), VERSION, PACKAGE_BUGREPORT);
	saveFlag = (readFile(&daemonMode)==0 ? 0 : 1);
#ifdef LOCAL_CONF
	if (strncmp(localUserPath, "",2))
		if (readLocalFile(localUserPath) == -1)
			printf(_( "打开本地配置文件失败！\n" ));
#endif
	readArg(argc, argv, &saveFlag, &exitFlag, &daemonMode);
#ifndef NO_DYLOAD
	if (load_libpcap() == -1) {
	#ifndef NO_NOTIFY
		if (showNotify && show_notify(_("MentoHUST - 错误提示"),
			_("载入libpcap失败, 请检查该库文件！"), 1000*showNotify) < 0)
			showNotify = 0;
	#endif
		exit(EXIT_FAILURE);
	}
#endif
	if (nic[0] == '\0')
	{
		saveFlag = 1;
		if (getAdapter() == -1) {	/* 找不到（第一块）网卡？ */
#ifndef NO_NOTIFY
			if (showNotify && show_notify(_("MentoHUST - 错误提示"),
				 _("找不到网卡！"), 1000*showNotify) < 0)
				showNotify = 0;
#endif
			exit(EXIT_FAILURE);
		}
	}
	if (userName[0]=='\0' || password[0]=='\0')	/* 未写用户名密码？ */
	{
#ifdef LOCAL_CONF
		/* 主配置文件默认账户为空且未读入任何本地账户 */
		if (!strncmp(userNameLocal[locaUserFlag], "", 1) || !haveLocalAccount()) {
#endif
			saveFlag = 1;
			printf(_("?? 请输入用户名: "));
			scanf("%s", userName);
			printf(_("?? 请输入密码: "));
			scanf("%s", password);

			printf(_("?? 请选择组播地址(0标准 1锐捷私有 2赛尔): "));
			scanf("%u", &startMode);
			startMode %= 3;
			printf(_("?? 请选择DHCP方式(0不使用 1二次认证 2认证后 3认证前): "));
			scanf("%u", &dhcpMode);
			dhcpMode %= 4;
#ifdef LOCAL_CONF
		}
#endif
	}
	checkRunning(exitFlag, daemonMode);
	if (startMode%3==2 && gateway==0)	/* 赛尔且未填写网关地址 */
	{
		gateway = ip;	/* 据说赛尔的网关是ip前三字节，后一字节是2 */
		((u_char *)&gateway)[3] = 0x02;
	}
	if (dhcpScript[0] == '\0')	/* 未填写DHCP脚本？ */
		strcpy(dhcpScript, D_DHCPSCRIPT);
	newBuffer();
	printConfig();
	if (fillHeader()==-1 || openPcap()==-1) {	/* 获取IP、MAC，打开网卡 */
#ifndef NO_NOTIFY
		if (showNotify && show_notify(_("MentoHUST - 错误提示"),
			_("获取MAC地址或打开网卡失败！"), 1000*showNotify) < 0)
			showNotify = 0;
#endif
		exit(EXIT_FAILURE);
	}

	if (saveFlag)
		saveConfig(daemonMode);
}

static int readFile(int *daemonMode)
{
	char tmp[16], *buf;
	if (loadFile(&buf, CFG_FILE) < 0) /*open CFG_FILE, read the content of configuration file into buf and close it*/
		return -1;
	getString(buf, "MentoHUST", "Username", "", userName, sizeof(userName));
#ifdef NO_ENCODE_PASS
	getString(buf, "MentoHUST", "Password", "", password, sizeof(password));
#else
	char pass[ACCOUNT_SIZE*4/3+1];
	getString(buf, "MentoHUST", "Password", "", pass, sizeof(pass));
	if (pass[0] == ' ') {
		decodePass(password, pass+1);
	} else {
		strncpy(password, pass, sizeof(password)-1);
		encodePass(pass+1, password);
		pass[0] = ' ';
		setString(&buf, "MentoHUST", "Password", pass);
		saveFile(buf, CFG_FILE);
	}
#endif
#ifdef LOCAL_CONF
	strncpy(userNameLocal[0], userName, sizeof(userName));
	strncpy(passwordLocal[0], password, sizeof(password));
	getString(buf, "MentoHUST", "LocalConf", "", localUserPath, sizeof(localUserPath));
#endif
	getString(buf, "MentoHUST", "Nic", "", nic, sizeof(nic));
	getString(buf, "MentoHUST", "Datafile", "", dataFile, sizeof(dataFile));
	getString(buf, "MentoHUST", "DhcpScript", "", dhcpScript, sizeof(dhcpScript));
	getString(buf, "MentoHUST", "Version", "", tmp, sizeof(tmp));
	if (strlen(tmp) >= 3) {
		unsigned ver[2];
		if (sscanf(tmp, "%u.%u", ver, ver+1)!=EOF && ver[0]!=0) {
			version[0] = ver[0];
			version[1] = ver[1];
			bufType = 1;
		}
	}
	getString(buf, "MentoHUST", "IP", "255.255.255.255", tmp, sizeof(tmp));
	ip = inet_addr(tmp);
	getString(buf, "MentoHUST", "Mask", "255.255.255.255", tmp, sizeof(tmp));
	mask = inet_addr(tmp);
	getString(buf, "MentoHUST", "Gateway", "0.0.0.0", tmp, sizeof(tmp));
	gateway = inet_addr(tmp);
	getString(buf, "MentoHUST", "DNS", "0.0.0.0", tmp, sizeof(tmp));
	dns = inet_addr(tmp);
	getString(buf, "MentoHUST", "PingHost", "0.0.0.0", tmp, sizeof(tmp));
	pingHost = inet_addr(tmp);
	timeout = getInt(buf, "MentoHUST", "Timeout", D_TIMEOUT) % 100;
	echoInterval = getInt(buf, "MentoHUST", "EchoInterval", D_ECHOINTERVAL) % 1000;
	restartWait = getInt(buf, "MentoHUST", "RestartWait", D_RESTARTWAIT) % 100;
	startMode = getInt(buf, "MentoHUST", "StartMode", D_STARTMODE) % 3;
	dhcpMode = getInt(buf, "MentoHUST", "DhcpMode", D_DHCPMODE) % 4;
#ifndef NO_NOTIFY
	showNotify = getInt(buf, "MentoHUST", "ShowNotify", D_SHOWNOTIFY) % 21;
#endif
	*daemonMode = getInt(buf, "MentoHUST", "DaemonMode", D_DAEMONMODE) % 4;
	maxFail = getInt(buf, "MentoHUST", "MaxFail", D_MAXFAIL);
	free(buf);
	return 0;
}


static void readArg(char argc, char **argv, int *saveFlag, int *exitFlag, int *daemonMode)
{
	char *str, c;
	int i;
	for (i=1; i<argc; i++)
	{
		str = argv[i];
		if (str[0]!='-' && str[0]!='/')
			continue;
		c = str[1];
		if (c=='h' || c=='?' || strcmp(str, "--help")==0)
			showHelp(argv[0]);
        else if (c == 'q') {
            printSuConfig(str+2);
            exit(EXIT_SUCCESS);
        }
#ifdef LOCAL_CONF
		else if (c == 'C'){
			setLocalConfigPath(str+2);
			readLocalFile(localUserPath);
		}
		else if (c == 'A'){
			printf(_("?? 请输入用户名: "));
			scanf("%s", userName);
			printf(_("?? 请输入密码: "));
			scanf("%s", password);
			addLocalAccount(localUserPath, userName, password);
			exit(EXIT_SUCCESS);
		}
		else if (c == 'D'){
			deleteLocalAccount(localUserPath, str+2);
			exit(EXIT_SUCCESS);
		}
#endif
		else if (c == 'w')
			*saveFlag = 1;
		else if (c == 'k') {
			if (strlen(str) > 2)
				*exitFlag = 2;
			else {
				*exitFlag = 1;
				return;
			}
		} else if (strlen(str) > 2) {
			if (c == 'u')
				strncpy(userName, str+2, sizeof(userName)-1);
			else if (c == 'p')
				strncpy(password, str+2, sizeof(password)-1);
			else if (c == 'n')
				strncpy(nic, str+2, sizeof(nic)-1);
			else if (c == 'f')
				strncpy(dataFile, str+2, sizeof(dataFile)-1);
			else if (c == 'c')
				strncpy(dhcpScript, str+2, sizeof(dhcpScript)-1);
			else if (c=='v' && strlen(str+2)>=3) {
				unsigned ver[2];
				if (sscanf(str+2, "%u.%u", ver, ver+1) != EOF) {
					if (ver[0] == 0)
						bufType = 0;
					else {
						version[0] = ver[0];
						version[1] = ver[1];
						bufType = 1;
					}
				}
			}
			else if (c == 'i')
				ip = inet_addr(str+2);
			else if (c == 'm')
				mask = inet_addr(str+2);
			else if (c == 'g')
				gateway = inet_addr(str+2);
			else if (c == 's')
				dns = inet_addr(str+2);
			else if (c == 'o')
				pingHost = inet_addr(str+2);
			else if (c == 't')
				timeout = atoi(str+2) % 100;
			else if (c == 'e')
				echoInterval = atoi(str+2) % 1000;
			else if (c == 'r')
				restartWait = atoi(str+2) % 100;
			else if (c == 'a')
				startMode = atoi(str+2) % 3;
			else if (c == 'd')
				dhcpMode = atoi(str+2) % 4;
#ifndef NO_NOTIFY
			else if (c == 'y')
				showNotify = atoi(str+2) % 21;
#endif
			else if (c == 'b')
				*daemonMode = atoi(str+2) % 4;
			else if (c == 'l')
				maxFail = atoi(str+2);
		}
	}
}

static void showHelp(const char *fileName)
{
	char *helpString =
		_("用法:\t%s [-选项][参数]\n"
		"选项:\t-h 显示本帮助信息\n"
		"\t-k -k(退出程序) 其他(重启程序)\n"
		"\t-w 保存参数到配置文件\n"
		"\t-u 用户名\n"
		"\t-p 密码\n"
#ifdef LOCAL_CONF
		"\t-A 添加本地账户\n"
		"\t-C 指定本地配置路径，若给定目录则自动搜索默认配置文件“.mentohust.conf”\n"
		"\t   (如-C/home/bob 或-C/home/bob/.mentohust.conf)\n"
#endif
		"\t-n 网卡名\n"
		"\t-i IP[默认本机IP]\n"
		"\t-m 子网掩码[默认本机掩码]\n"
		"\t-g 网关[默认0.0.0.0]\n"
		"\t-s DNS[默认0.0.0.0]\n"
		"\t-o Ping主机[默认0.0.0.0，表示关闭该功能]\n"
		"\t-t 认证超时(秒)[默认8]\n"
		"\t-e 心跳间隔(秒)[默认30]\n"
		"\t-r 失败等待(秒)[默认15]\n"
		"\t-l 允许失败次数[0表示无限制，默认8]\n"
		"\t-a 组播地址: 0(标准) 1(锐捷) 2(赛尔) [默认0]\n"
		"\t-d DHCP方式: 0(不使用) 1(二次认证) 2(认证后) 3(认证前) [默认0]\n"
		"\t-b 是否后台运行: 0(否) 1(是，关闭输出) 2(是，保留输出) 3(是，输出到文件) [默认0]\n"
#ifndef NO_NOTIFY
		"\t-y 是否显示通知: 0(否) 1~20(是) [默认5]\n"
#endif
		"\t-v 客户端版本号[默认0.00表示兼容xrgsu]\n"
		"\t-f 自定义数据文件[默认不使用]\n"
		"\t-c DHCP脚本[默认dhclient]\n"
		"\t-q 显示SuConfig.dat的内容(如-q/path/SuConfig.dat)\n"
		"例如:\t%s -uusername -ppassword -neth0 -i192.168.0.1 -m255.255.255.0 -g0.0.0.0 -s0.0.0.0 -o0.0.0.0 -t8 -e30 -r15 -a0 -d1 -b0 -v4.10 -fdefault.mpf -cdhclient\n"
		"注意：使用时请确保是以root权限运行！\n\n");
	printf(helpString, fileName, fileName);
	exit(EXIT_SUCCESS);
}

static int getAdapter()
{
	pcap_if_t *alldevs, *d;
	int num = 0, avail = 0, i;
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&alldevs, errbuf)==-1 || alldevs==NULL)
	{
		printf(_("!! 查找网卡失败: %s\n"), errbuf);
		return -1;
	}
	for (d=alldevs; d!=NULL; d=d->next)
	{
		num++;
		if (!(d->flags & PCAP_IF_LOOPBACK) && strcmp(d->name, "any")!=0)
		{
			printf(_("** 网卡[%d]:\t%s\n"), num, d->name);
			avail++;
			i = num;
		}
	}
	if (avail == 0)
	{
		pcap_freealldevs(alldevs);
		printf(_("!! 找不到网卡！\n"));
		return -1;
	}
	if (avail > 1)
	{
		printf(_("?? 请选择网卡[1-%d]: "), num);
		scanf("%d", &i);
		if (i < 1)
			i = 1;
		else if (i > num)
			i = num;
	}
	printf(_("** 您选择了第[%d]块网卡。\n"), i);
	for (d=alldevs; i>1; d=d->next, i--);
	strncpy(nic, d->name, sizeof(nic)-1);
	pcap_freealldevs(alldevs);
	return 0;
}

static void printConfig()
{
	char *addr[] = {_("标准"), _("锐捷"), _("赛尔")};
	char *dhcp[] = {_("不使用"), _("二次认证"), _("认证后"), _("认证前")};
#ifdef LOCAL_CONF
	int i = 0;
	printf(_("** 默认账户:\t%s\n"), userNameLocal[locaUserFlag]);
	MENTOHUST_LOG ("主配置文件账户：%s", userNameLocal[0]);
	for (i = 1; i <= user_count; i++)
	{
		MENTOHUST_LOG ("本地账户%d：%s", i, userNameLocal[i]);
	}
#else
	printf(_("** 用户名:\t%s\n"), userName);
#endif
	printf(_("** 网卡: \t%s\n"), nic);
	if (gateway)
		printf(_("** 网关地址:\t%s\n"), formatIP(gateway));
	if (dns)
		printf(_("** DNS地址:\t%s\n"), formatIP(dns));
	if (pingHost)
		printf(_("** 智能重连:\t%s\n"), formatIP(pingHost));
	printf(_("** 认证超时:\t%u秒\n"), timeout);
	printf(_("** 心跳间隔:\t%u秒\n"), echoInterval);
	printf(_("** 失败等待:\t%u秒\n"), restartWait);
	if (maxFail)
		printf(_("** 允许失败:\t%u次\n"), maxFail);
	printf(_("** 组播地址:\t%s\n"), addr[startMode]);
	printf(_("** DHCP方式:\t%s\n"), dhcp[dhcpMode]);
#ifndef NO_NOTIFY
	if (showNotify)
		printf(_("** 通知超时:\t%d秒\n"), showNotify);
#endif
	if (bufType >= 2)
		printf(_("** 数据文件:\t%s\n"), dataFile);
#ifdef LOCAL_CONF
		printf(_("** 用户配置文件:%s\n"), localUserPath);
#endif
	if (dhcpMode != 0)
		printf(_("** DHCP脚本:\t%s\n"), dhcpScript);
}

static int openPcap()
{
	char buf[PCAP_ERRBUF_SIZE], *fmt;
	struct bpf_program fcode;
	if ((hPcap = pcap_open_live(nic, 2048, 1, 1000, buf)) == NULL)
	{
		printf(_("!! 打开网卡%s失败: %s\n"), nic, buf);
		return -1;
	}
	fmt = formatHex(localMAC, 6);
#ifndef NO_ARP
	sprintf(buf, "((ether proto 0x888e and (ether dst %s or ether dst 01:80:c2:00:00:03)) "
			"or ether proto 0x0806) and not ether src %s", fmt, fmt);
#else
	sprintf(buf, "ether proto 0x888e and (ether dst %s or ether dst 01:80:c2:00:00:03) "
			"and not ether src %s", fmt, fmt);
#endif
	if (pcap_compile(hPcap, &fcode, buf, 0, 0xffffffff) == -1
			|| pcap_setfilter(hPcap, &fcode) == -1)
	{
		printf(_("!! 设置pcap过滤器失败: %s\n"), pcap_geterr(hPcap));
		return -1;
	}
	pcap_freecode(&fcode);
	return 0;
}

static void saveConfig(int daemonMode)
{
	char *buf;
	if (loadFile(&buf, CFG_FILE) < 0) {
		buf = (char *)malloc(1);
		buf[0] = '\0';
	}
	setString(&buf, "MentoHUST", "DhcpScript", dhcpScript);
	setString(&buf, "MentoHUST", "DataFile", dataFile);
	if (bufType != 0) {
		char ver[10];
		sprintf(ver, "%u.%u", version[0], version[1]);
		setString(&buf, "MentoHUST", "Version", ver);
	} else
		setString(&buf, "MentoHUST", "Version", "0.00");
#ifndef NO_NOTIFY
	setInt(&buf, "MentoHUST", "ShowNotify", showNotify);
#endif
	setInt(&buf, "MentoHUST", "DaemonMode", daemonMode);
	setInt(&buf, "MentoHUST", "DhcpMode", dhcpMode);
	setInt(&buf, "MentoHUST", "StartMode", startMode);
	setInt(&buf, "MentoHUST", "MaxFail", maxFail);
	setInt(&buf, "MentoHUST", "RestartWait", restartWait);
	setInt(&buf, "MentoHUST", "EchoInterval", echoInterval);
	setInt(&buf, "MentoHUST", "Timeout", timeout);
	setString(&buf, "MentoHUST", "PingHost", formatIP(pingHost));
	setString(&buf, "MentoHUST", "DNS", formatIP(dns));
	setString(&buf, "MentoHUST", "Gateway", formatIP(gateway));
	setString(&buf, "MentoHUST", "Mask", formatIP(mask));
	setString(&buf, "MentoHUST", "IP", formatIP(ip));
	setString(&buf, "MentoHUST", "Nic", nic);
#ifdef NO_ENCODE_PASS
	setString(&buf, "MentoHUST", "Password", password);
#else
	char pass[ACCOUNT_SIZE*4/3+1];
	encodePass(pass+1, password);
	pass[0] = ' ';
	setString(&buf, "MentoHUST", "Password", pass);
#endif
	setString(&buf, "MentoHUST", "Username", userName);
	if (saveFile(buf, CFG_FILE) != 0)
		printf(_("!! 保存认证参数到%s失败！\n"), CFG_FILE);
	else
		printf(_("** 认证参数已成功保存到%s.\n"), CFG_FILE);
	free(buf);
}

static void checkRunning(int exitFlag, int daemonMode)
{
	struct flock fl;
	lockfd = open (LOCK_FILE, O_RDWR|O_CREAT, LOCKMODE);
	if (lockfd < 0) {
		perror(_("!! 打开锁文件失败"));
		goto error_exit;
	}
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0;
	fl.l_type = F_WRLCK;
	if (fcntl(lockfd, F_GETLK, &fl) < 0) {
		perror(_("!! 获取文件锁失败"));
		goto error_exit;
	}
	if (exitFlag) {
		if (fl.l_type != F_UNLCK) {
			printf(_(">> 已发送退出信号给MentoHUST进程(PID=%d).\n"), fl.l_pid);
			if (kill(fl.l_pid, SIGINT) == -1)
				perror(_("!! 结束进程失败"));
		}
		else
			printf(_("!! 没有MentoHUST正在运行！\n"));
		if (exitFlag == 1)
			exit(EXIT_SUCCESS);
	}
	else if (fl.l_type != F_UNLCK) {
		printf(_("!! MentoHUST已经运行(PID=%d)!\n"), fl.l_pid);
		exit(EXIT_FAILURE);
	}
	if (daemonMode) {	/* 貌似我过早进入后台模式了，就给个选项保留输出或者输出到文件吧 */
		printf(_(">> 进入后台运行模式，使用参数-k可退出认证。\n"));
		if (daemon(0, (daemonMode+1)%2))
			perror(_("!! 后台运行失败"));
		else if (daemonMode == 3) {
			freopen(LOG_FILE, "w", stdout);
			setvbuf(stdout, (char *)NULL, _IOLBF, BUFSIZ);
			freopen(LOG_FILE, "a", stderr);
		}
	}
	fl.l_type = F_WRLCK;
	fl.l_pid = getpid();
	if (fcntl(lockfd, F_SETLKW, &fl) < 0) {
		perror(_("!! 加锁失败"));
		goto error_exit;
	}
	return;

error_exit:
#ifndef NO_NOTIFY
	if (showNotify && show_notify(_("MentoHUST - 错误提示"),
		_("操作锁文件失败，请检查是否为root权限！"), 1000*showNotify) < 0)
		showNotify = 0;
#endif
	exit(EXIT_FAILURE);
}

#ifdef LOCAL_CONF
/*若打开文件失败，则返回-1，否则返回读入的账户个数*/
static int readLocalFile(const char *filepath)
{
	char *buf, userid_tail[4], 
			 userid[8] = "user";
	int read_count = 0;

	if(loadFile(&buf, filepath) < 0)
		return -1;

	read_count = getInt(buf, "MentoHUST", "AccountCount", 0);

	user_count = 0;
	/*MENTOHUST_LOG ("用户%d:%s读入", user_count, userNameLocal[user_count]);*/
	/* 下标0存放的是默认账户，在读主配置文件时已存入 */
	do {
		user_count++;
		sprintf(userid_tail, "%d", user_count);
		strncpy(&userid[4], userid_tail, 4);
		if (getString(buf, userid, "Username", "", userNameLocal[user_count], ACCOUNT_SIZE) != -1){
			getString(buf, userid, "Password", "", passwordLocal[user_count], ACCOUNT_SIZE);
			/* 指定第一个本地账户为默认账户 */
			if (locaUserFlag == 0)
				locaUserFlag = user_count;
		/*MENTOHUST_LOG ("用户%d:%s读入", user_count, userNameLocal[user_count]);*/
		} else {
			memcpy(passwordLocal[user_count], "", 1);
		}
	}while(user_count < read_count);
	/*MENTOHUST_LOG ( "读入账户数：%d\n", user_count );*/

	free(buf);
	return user_count;
}

static int saveLocalConfig(const char*filepath)
{
	char *buf,
			 userid[8] = "user",
			 userid_tail[4] = "";
	int i, j = getFreeUserNum() - 1;

	buf = (char *)malloc(1);
	if (!buf)
		return -1;
	buf[0] = '\0';

	setInt(&buf, "MentoHUST", "AccountCount", user_count);

	/* 删除空闲的账户id */
	for (i = 1; i <= user_count; i++)
	{
		if (!strncmp(userNameLocal[i], "", 1)) {
			/* 找一个非空账户id */
			while(i < user_count)
			{
				i++;
				if (strncmp(userNameLocal[i], "", 1))
					break;
			}

			/* 若后面全为空 */
			if (i > user_count)
				break;
			else if (i == user_count && (!strncmp(userNameLocal[i], "", 1)))
				break;

			/* 找到非空的账户id */
			j = getFreeUserNum();
			/* 移动账户id */
			strncpy(userNameLocal[j], userNameLocal[i], ACCOUNT_SIZE);
			strncpy(passwordLocal[j], passwordLocal[i], ACCOUNT_SIZE);
			strncpy(userNameLocal[i], "", 1);
			strncpy(passwordLocal[i], "", 1);
			i--;		/* i加1后指向置空的账户id */
		}
	}

	/* 将内存中更新过的账户信息写入代保存的buf中 */
	for (i = 1; i <= j; i++)
	{
		sprintf(userid_tail, "%d", i);
		strncpy(&userid[4], userid_tail, 4);
		/*@@encodePass here*/
		setString(&buf, userid, "Password", passwordLocal[i]);
		setString(&buf, userid, "Username", userNameLocal[i]);
	}

	/* 删除多余的账户id */
	for (i = j+1; i <= user_count; i++)
	{
		sprintf(userid_tail, "%d", i);
		strncpy(&userid[4], userid_tail, 4);
		setString(&buf, userid, NULL, NULL);
	}

	if (user_count != j) {
		user_count = j;
		setInt(&buf, "MentoHUST", "AccountCount", user_count);
	}

	if (saveFile(buf, filepath) != 0)
		printf(_("!! 保存本地配置文件到%s失败！\n"), filepath);
	else
		printf(_("** 本地配置文件已成功保存到%s.\n"), filepath);

	free(buf);
}

/* 在配置文件filepath中添加新的账户
 * 若账户已存在，则仅对密码进行修改。 */
int addLocalAccount(const char *filepath, 
										const char *userNameToAdd, 
										const char *passToAdd)
{
	char *buf, 
			 newuserid[8] = "user",
			 userid_tail[4] = "";
	int i, empty_acc_nu;   /* 可用的user号 */

	if(access(filepath, 0) == -1)
		return -1;

	if (loadFile(&buf, filepath) < 0) {
		buf = (char *)malloc(1);
		buf[0] = '\0';
	}

	/*若已存在，则只修改密码*/
	for (i = 1; i <= user_count; i++)
	{
		if (!strncmp(userNameLocal[i], userNameToAdd, ACCOUNT_SIZE))
			break;
	}

	if (i > user_count) 
		empty_acc_nu = getFreeUserNum();
	else
		empty_acc_nu = i;

  sprintf(userid_tail, "%d", empty_acc_nu);
	strncpy(&newuserid[4], userid_tail, 4);

  if (user_count < empty_acc_nu)
	  setInt(&buf, "MentoHUST", "AccountCount", user_count+1);
	setString(&buf, newuserid, "Password", passToAdd);
	setString(&buf, newuserid, "Username", userNameToAdd);

	if (saveFile(buf, filepath) != 0)
		printf(_("!! 保存账户到%s失败！\n"), filepath);
	else
		printf(_("** 账户%s已成功保存到%s.\n"), userNameToAdd, filepath);

	free(buf);
}

static int haveLocalAccount()
{
	int i;
	for (i = 1; i <= user_count; i++)
	{
		if (strncmp(userNameLocal[i], "", ACCOUNT_SIZE))
			return 1;
	}
	return 0;
}

/*找一个未被占有的user号，而不是数组下标*/
static int getFreeUserNum()
{
	int empty_acc_nu;   /* 可用的user号 */

	for (empty_acc_nu = 1; empty_acc_nu <= user_count; empty_acc_nu++)
	{
		if (!strncmp(userNameLocal[empty_acc_nu], "", 1))
			break;
	}
	return empty_acc_nu;
}

/* make sure configuration has been loaded 
 * before calling this function*/
inline void showLocalAccounts()
{
	int i;

	for (i = 1; i <= user_count; i++)
		printf ( "user[%d]:%s\n", i, userNameLocal[i] );
}

int setLocalConfigPath(const char *path)
{
	struct stat st;

	if (!path)
		return -1;
	if (stat(path, &st) == -1)
		return -1;

	if (S_ISDIR(st.st_mode)){
		char *filepath = NULL;
		filepath = malloc(strlen(path)+18);
		if (!filepath)
			return -1;
		strncpy(filepath, path, strlen(path)+1);
		strncat(filepath, "/.mentohust.conf", 17);
		setLocalConfigFilePath(filepath);
		free(filepath);
	}
	else
		setLocalConfigFilePath(path);

	return 0;
}

inline void setLocalConfigFilePath(const char *path)
{
	strncpy(localUserPath, path, strlen(path)+1);
}

int deleteLocalAccount(char *filepath, char *userNameToDel)
{
	int i;

	if(access(filepath, 0) == -1)
		return -1;

	if (readLocalFile(filepath) <=0)
		return -1;

	for (i = 1; i <= user_count; i++)
	{
		if (!strncmp(userNameToDel, userNameLocal[i], ACCOUNT_SIZE))
			break;
	}

	/* Not found */
	if (i > user_count)
		return -1;

	strncpy(userNameLocal[i], "", 1);
	strncpy(passwordLocal[i], "", 1);

	saveLocalConfig(filepath);

	return 0;
}
#endif
