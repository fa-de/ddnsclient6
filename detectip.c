#include <stdlib.h>
#include <stdio.h>
#include <string.h>

//For daemon functionality
#include <unistd.h>

#include <time.h>

#include <netdb.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <openssl/ssl.h>

#include <signal.h>
#include <syslog.h>
#include <sys/stat.h>

#include <stdbool.h>
#include <errno.h>


static bool verbose_mode = false;
static FILE *global_output = NULL;

typedef enum
{
	TERM_SIGTERM = 0,
	TERM_ASSERT = 1
} TERM_REASON;

static void terminate(TERM_REASON reason)
{
	fprintf(global_output, "Terminating: %d\n", reason);
	if(global_output != stdout)
		fclose(global_output);

	exit(reason == TERM_SIGTERM ? 0 : 1);
}

#define log(args...) fprintf(global_output, args)
#define verbose_log(args...) do { if(verbose_mode) log(args); } while(0)


#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define assert(b) do {if(!(b)){_assert(#b " ("__FILE__ ":" TOSTRING(__LINE__)")");}} while(0)

static void _assert(const char* text)
{
	log("Assertion failed: %s\n", text);
	terminate(TERM_ASSERT);
}

static void _perror(const char* prefix)
{
	log("%s: %s\n", prefix, strerror(errno));
}


//SSH functionality
static int encode_base64(char *encoded, int outputlen, const char *string, int len)
{
	const char basis_64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t required_space = 4 * ((len + 2) / 3);
	assert(required_space <= outputlen);

	int i;
	char *p;

	p = encoded;
	for (i = 0; i < len - 2; i += 3) {
		*p++ = basis_64[(string[i] >> 2) & 0x3F];
		*p++ = basis_64[((string[i] & 0x3) << 4) | ((int)(string[i + 1] & 0xF0) >> 4)];
		*p++ = basis_64[((string[i + 1] & 0xF) << 2) | ((int)(string[i + 2] & 0xC0) >> 6)];
		*p++ = basis_64[string[i + 2] & 0x3F];
	}
	if (i < len) {
		*p++ = basis_64[(string[i] >> 2) & 0x3F];
		if (i == (len - 1)) {
			*p++ = basis_64[((string[i] & 0x3) << 4)];
			*p++ = '=';
		}
		else {
			*p++ = basis_64[((string[i] & 0x3) << 4) | ((int)(string[i + 1] & 0xF0) >> 4)];
			*p++ = basis_64[((string[i + 1] & 0xF) << 2)];
		}
		*p++ = '=';
	}

	*p++ = '\0';
	assert(p - encoded <= outputlen);
	return p - encoded;
}

static int send_update_request(const char *hostname, const char* myip, const char *username, const char* password)
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	SSL_load_error_strings();
	SSL_library_init();
	ctx = SSL_CTX_new(SSLv23_client_method());

	//TCP socket
	int sd;
	struct hostent *host;
	struct sockaddr_in addr;

	host = gethostbyname(hostname);
	sd = socket(PF_INET, SOCK_STREAM, 0);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(443);
	addr.sin_addr.s_addr = *(long*)(host->h_addr);
	assert(connect(sd, (struct sockaddr*)&addr, sizeof(addr)) == 0);

	//Start SSL session
	SSL *ssl;
	ssl = SSL_new(ctx);    // create new SSL connection state
	SSL_set_fd(ssl, sd);   // attach the socket descriptor
	SSL_connect(ssl);          // perform the connection

	//Create request
	size_t auth_size = (strlen(username) + strlen(password) + 1);
	char auth[auth_size + 1];
	assert(sprintf(auth, "%s:%s", username, password) <= auth_size);

	size_t encoded_size = 4 * ((auth_size + 2) / 3) + 1;
	char encoded_auth[encoded_size];

	encode_base64(encoded_auth, encoded_size, auth, auth_size);

	const char *format = "GET /?myip=%s HTTP/1.0\r\nAuthorization: Basic %s\r\nHost: %s\r\nConnection: Close\r\n\r\n";
	int request_size = snprintf(NULL, 0, format, myip, encoded_auth, hostname);

	char request[request_size + 1];
	snprintf(request, request_size + 1, format, myip, encoded_auth, hostname);

	SSL_write(ssl, request, request_size);

	//Read answer
	int BUFFERLEN = 16384;
	char buffer[BUFFERLEN];
	char *p = buffer;
	int len;

	//TODO: Parse return value and answer
	while ((len = SSL_read(ssl, p, BUFFERLEN - (p - buffer) - 1)) > 0)
	{
		p += len;
		assert(p - buffer < BUFFERLEN - 1); //TODO: Keep receiving and throw away?
	}

	*p = '\0';

	log("RESPONSE:\n%s<END OF RESPONSE>\n", buffer);

	int shutdown_state = SSL_shutdown(ssl);
	if (shutdown_state == 0)
	{
		verbose_log("Shutdown state: 0\n");
		shutdown_state = SSL_shutdown(ssl);
	}
	else if(shutdown_state < 0)
	{
		verbose_log("Shutdown failed: SSL_get_error: %d\n", SSL_get_error(ssl, shutdown_state));
	}

	verbose_log("Shutdown state (get_shutdown()): %d\n", SSL_get_shutdown(ssl));
	//verbose_log("Shutdown state: %d\n", SSL_get_shutdown(ssl));

	//TODO: Parse response

	SSL_free(ssl);              /* release SSL state */
	SSL_CTX_free(ctx);

	close(sd);
}


uint16_t last_address[8] = { 0 };


static void log_time()
{
	time_t t = time(NULL);
	struct tm *local = localtime(&t);
	log("\n%s", asctime(local));
}

static void fprint_ipv6(FILE* o, const void* ipv6addr)
{
	const uint16_t *data = ipv6addr;
	int i = 0;
	fprintf(o, "[");
	for (i = 0; i < 7; i++) fprintf(o, "%x:", ntohs(data[i]));
	fprintf(o, "%x]", ntohs(data[7]));
}

static void sprintf_ipv6(char* dst, const void *ipv6addr)
{
	const uint16_t *data = ipv6addr;
	const char *p = dst;

	int i = 0;
	for (i = 0; i < 7; i++) dst += snprintf(dst, 40 - (p - dst), "%x:", ntohs(data[i]));
	snprintf(dst, 40 - (p - dst), "%x", ntohs(data[7]));
}

static void activate_ip(const void *address)
{
	//Do not update again if address has already been sent.
	if (memcmp(address, last_address, 16) == 0)
	{
		if(verbose_mode)
		{
			fprint_ipv6(global_output, address);
			log(" <<< already active\n");
		}
		return;
	}
	memcpy(last_address, address, 16);

	if(!verbose_mode) log_time();
	fprint_ipv6(global_output, address);
	log(" <<< activating\n");

	char ipstring[40];
	sprintf_ipv6(ipstring, address);

	const char *hostname = "ddns.do.de";
	const char *username = "DDNS-KD3428-F727";
	const char *password = "IMHvqKld26ab";

	send_update_request(hostname, ipstring, username, password);
}

static void process_ip(void *address, int ifa_flags, int ifa_scope, int prefered_time)
{
	const char *bytes = address;

	bool deprecated = ifa_flags & IFA_F_DEPRECATED;
	bool temporary = ifa_flags & IFA_F_TEMPORARY;
	bool global = ifa_scope == RT_SCOPE_UNIVERSE;

	//fprint_time(global_output);
	if (deprecated || temporary || !global) //filter old and temporary IPs
	{
		if(verbose_mode)
		{
			fprint_ipv6(global_output, address);
			log(" rejected for deprecated: %d temporary: %d local: %d\n", deprecated, temporary, !global);
		}
		return;
	}
	else if (prefered_time <= 0)
	{
		if(verbose_mode)
		{
			fprint_ipv6(global_output, address);
			log(" rejected for not prefered (time expired: %d)\n", prefered_time);
		}
		return;
	}
	else //accept and process further
	{	
		if(verbose_mode) log("flags: dep: %d temp: %d global: %d pref: %d\n", deprecated, temporary, global, prefered_time);
		activate_ip(address);
	}
}

static struct
{
	struct nlmsghdr		nlmsg_info;
	struct ifaddrmsg	ifaddrmsg_info;
	//	char			buffer[2048];
} netlink_req;

static void
send_ip_list_request(int sock)
{
	int rtn;

	memset(&netlink_req, 0, sizeof(netlink_req));

	netlink_req.nlmsg_info.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	netlink_req.nlmsg_info.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
	netlink_req.nlmsg_info.nlmsg_type = RTM_GETADDR;
	netlink_req.nlmsg_info.nlmsg_pid = getpid();

	netlink_req.ifaddrmsg_info.ifa_family = AF_INET6;

	rtn = send(sock, &netlink_req, netlink_req.nlmsg_info.nlmsg_len, 0);
	assert(rtn >= 0);
}

#define TESTFLAG(v,f) ((v&f) != 0 ? #f" " : "")

static void fprint_flags(FILE *o, int flags)
{
	fprintf(o, "%s%s", TESTFLAG(flags, IFA_F_TEMPORARY), TESTFLAG(flags, IFA_F_DEPRECATED));
}

static int
main_loop()
{
	struct sockaddr_nl addr;
	int sock, len;
	const int RECV_SIZE = 512;
	char recv_buffer[RECV_SIZE];
	struct nlmsghdr *nlh;

	if ((sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1)
	{
		_perror("couldn't open NETLINK_ROUTE socket");
		_assert(false);
		return 1;
	}


	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = RTMGRP_IPV6_IFADDR;

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		_perror("couldn't bind");
		assert(false);
		return 1;
	}

	send_ip_list_request(sock);

	//nlh = (struct nlmsghdr *)buffer;
	loop:
	while ((len = recv(sock, recv_buffer, RECV_SIZE, 0)) > 0)
	{
		struct nlmsghdr* nlh = (struct nlmsghdr*) recv_buffer;
		while (NLMSG_OK(nlh, len) && (nlh->nlmsg_type != NLMSG_DONE))
		{
			if (nlh->nlmsg_type == RTM_NEWADDR || nlh->nlmsg_type == RTM_GETADDR || nlh->nlmsg_type == RTM_DELADDR)
			{
				struct ifaddrmsg *ifa = (struct ifaddrmsg *) NLMSG_DATA(nlh);

				if(verbose_mode)
				{
					log_time();
					log("Message: [%d] flags: ", nlh->nlmsg_type);
					fprint_flags(global_output, ifa->ifa_flags);
					log(" scope: %d\n", ifa->ifa_scope);
				}

				if (ifa->ifa_family == AF_INET6)
				{
					//Address:
					void *address;
					//Cache info:
					struct ifa_cacheinfo *ci;
					int ci_valid;
					int ci_prefered;

					struct rtattr *rth = IFA_RTA(ifa);
					int rtl = IFA_PAYLOAD(nlh);

					while (rtl && RTA_OK(rth, rtl))
					{
						if (rth->rta_type == IFA_ADDRESS)
						{
							address = RTA_DATA(rth);

							if(verbose_mode)
							{
								log("[IFA_ADDRESS]");
								fprint_ipv6(global_output, address);
								log("\n");
							}
						}
						else if (rth->rta_type == IFA_CACHEINFO)
						{
							ci =  (struct ifa_cacheinfo *) RTA_DATA(rth);
							if(verbose_mode)
							{
								log("[IFA_CACHEINFO] valid: %d prefered: %d\n", ci->ifa_valid, ci->ifa_prefered);
							}
						}
						else
						{
							verbose_log("[?%d?]\n", rth->rta_type);
						}
						rth = RTA_NEXT(rth, rtl);
					}

					process_ip(address, ifa->ifa_flags, ifa->ifa_scope, ci->ifa_prefered);
				}
			}
			else if (nlh->nlmsg_type == NLMSG_ERROR)
			{
				struct nlmsgerr *err = (struct nlmsgerr*) NLMSG_DATA(nlh);
				if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
				{
					log("ERROR truncated\n");
				}
				else
				{
					errno = -err->error;
					_perror("RTNETLINK answers");
				}
				return -1;
			}
			nlh = NLMSG_NEXT(nlh, len);
		}

		fflush(global_output);
	}

	if (errno == EINTR || errno == EAGAIN) goto loop;

	assert(len != 0);
	assert(len > 0);
}

static void on_sigterm(int signo)
{
	terminate(TERM_SIGTERM);
}

static void skeleton_daemon()
{
	pid_t pid;

	/* Fork off the parent process */
	pid = fork();

	/* An error occurred */
	if (pid < 0)
		exit(EXIT_FAILURE);

	/* Success: Let the parent terminate */
	if (pid > 0)
		exit(EXIT_SUCCESS);

	/* On success: The child process becomes session leader */
	if (setsid() < 0)
		exit(EXIT_FAILURE);

	/* Catch, ignore and handle signals */
	//TODO: Implement a working signal handler */
	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGTERM, on_sigterm);

	/* Fork off for the second time*/
	pid = fork();

	/* An error occurred */
	if (pid < 0)
		exit(EXIT_FAILURE);

	/* Success: Let the parent terminate */
	if (pid > 0)
		exit(EXIT_SUCCESS);

	/* Set new file permissions */
	umask(0);

	/* Change the working directory to the root directory */
	/* or another appropriated directory */
	chdir("/");

	/* Close all open file descriptors */
	/*
	int x;
	for (x = sysconf(_SC_OPEN_MAX); x>0; x--)
	{
		close(x);
	}*/

	const char* LOGPATH = "/var/log/ddnsclient";
	global_output = fopen("/var/log/ddnsclient", "a");
	if(!global_output)
	{
		fprintf(stderr, "Unable to open log file %s\n", LOGPATH);
		exit(1);
	}

	close(0); close(1); close(2); //stdin stdout stderr

	log_time();
	log("Started as daemon\n");

	/* Open the log file */
	//openlog("ddnsclient", LOG_PID, LOG_DAEMON);
}

int main(int argc, char **argv)
{
	int i = 0;
	global_output = stdout;
	for(i = 1; i < argc; i++)
	{
		if(!strcmp(argv[i], "-v")) verbose_mode = true;
		if(!strcmp(argv[i], "-d")) skeleton_daemon();
	}
	//syslog(LOG_NOTICE, "IP watcher daemon started.")
	int ignore = main_loop();
	assert(0);
}
