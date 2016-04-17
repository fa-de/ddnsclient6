#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>

#include <netdb.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <signal.h>
#include <errno.h>

#include "ddnsclient.h"

#include "config.h"	//Contains username, hostname and password for now

//Store most recent address to avoid duplicate update requests (Some servers block after too many nochg-Requests)
static uint16_t last_address[8] = { 0 };

//Print ipv6 in human-readable format into dst
static void
sprintf_ipv6(char* dst, const void *ipv6addr)
{
	const uint16_t *data = ipv6addr;
	const char *p = dst;

	int i = 0;
	for (i = 0; i < 7; i++) dst += snprintf(dst, 40 - (p - dst), "%x:", ntohs(data[i]));
	snprintf(dst, 40 - (p - dst), "%x", ntohs(data[7]));
}

//Send request to server to store address
static void
activate_ip(const void *address)
{
	//Do not update again if address has been sent before.
	if (memcmp(address, last_address, 16) == 0)
	{
		if(verbose_mode)
		{
			log_ipv6(address);
			log(" <<< already active\n");
		}
		return;
	}
	memcpy(last_address, address, 16);

	//Log update
	if(!verbose_mode) log_time();
	log_ipv6(address);
	log(" <<< activating\n");

	char ipstring[40];
	sprintf_ipv6(ipstring, address);

	send_update_request(config_hostname, ipstring, config_username, config_password);
}

#define STRBOOL(f) ((f) ? #f" " : "")

static void
filter_ip(void *address, int ifa_flags, int ifa_scope, int preferred_time)
{
	bool deprecated = ifa_flags & IFA_F_DEPRECATED;
	bool temporary = ifa_flags & IFA_F_TEMPORARY;
	bool global = ifa_scope == RT_SCOPE_UNIVERSE;

	if (deprecated || temporary || !global) //filter old and temporary IPs
	{
		if(verbose_mode)
		{
			bool local = !global;
			log_ipv6(address);
			log(" rejected for being %s%s%s\n", STRBOOL(deprecated), STRBOOL(temporary), STRBOOL(local));
		}
		return;
	}
	else if (preferred_time <= 0)
	{
		if(verbose_mode)
		{
			log_ipv6(address);
			log(" rejected for not preferred (time expired: %d)\n", preferred_time);
		}
		return;
	}
	else //accept and process further
	{
		log_ipv6(address);
		if(verbose_mode) log("\n\tflags: dep: %d temp: %d global: %d pref: %d\n", deprecated, temporary, global, preferred_time);
		activate_ip(address);
	}
}

static struct
{
	struct nlmsghdr		nlmsg_info;
	struct ifaddrmsg	ifaddrmsg_info;
	//	char			buffer[2048];
} netlink_req;

//Send request for current IP addresses
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

#define STRFLAGIFSET(v,f) ((v&f) != 0 ? #f" " : "")

static void
fprint_flags(FILE *o, int flags)
{
	fprintf(o, "%s%s", STRFLAGIFSET(flags, IFA_F_TEMPORARY), STRFLAGIFSET(flags, IFA_F_DEPRECATED));
}

static int
listen_for_IP()
{
	struct sockaddr_nl addr;
	int sock, len;
	const int RECV_SIZE = 512;
	char recv_buffer[RECV_SIZE];

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
					void *address = NULL; //The IP Address:
					struct ifa_cacheinfo *ci = NULL; //Cache info for address:

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
								log_ipv6(address);
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

					assert(address != NULL);
					assert(ci != NULL);

					filter_ip(address, ifa->ifa_flags, ifa->ifa_scope, ci->ifa_prefered);
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

	if (errno == EINTR || errno == EAGAIN) goto loop;	//Would a do..while be cleaner?

	assert(len != 0);
	assert(len > 0);
	return 0;
}

static void
on_sigterm(int signo)
{
	log("Terminating: SIGTERM\n");
	close_log();
	exit(0);
}

int
main(int argc, char **argv)
{
	global_output = stdout;

	bool daemon_mode = false;

	int c;
	while ((c = getopt (argc, argv, "dv")) != -1)
	switch (c)
	{
		case 'v':
			verbose_mode = true;
			break;
		case 'd':
			daemon_mode = true;
			break;
		//case '?':
		default:
			abort();
	}

	//Activate daemon-mode
    if(daemon_mode)
	{
		signal(SIGTERM, on_sigterm);

		skeleton_daemon();

		const char* LOGPATH = "/var/log/ddnsclient";
		global_output = fopen(LOGPATH, "a");
		if(!global_output)
		{
			fprintf(stderr, "Unable to open log file %s\n", LOGPATH);
			exit(1);
		}

		log_time();
		log("Started as daemon\n");
	}

	assert(listen_for_IP());
	assert(0);
	return 1;
}
