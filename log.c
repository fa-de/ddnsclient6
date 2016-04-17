#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <netinet/in.h>	//for ntohs

#include "ddnsclient.h"

FILE *global_output = NULL;
bool verbose_mode = false;

void
_assert(const char* text)
{
	log("Assertion failed: %s\nTerminating.", text);
	close_log();
}

void
_perror(const char* prefix)
{
	log("%s: %s\n", prefix, strerror(errno));
}

void
log_time()
{
	time_t t = time(NULL);
	struct tm *local = localtime(&t);
	log("\n%s", asctime(local));
}

static void
fprint_ipv6(FILE* o, const void* ipv6addr)
{
	const uint16_t *data = ipv6addr;
	int i = 0;
	fprintf(o, "[");
	for (i = 0; i < 7; i++) fprintf(o, "%x:", ntohs(data[i]));
	fprintf(o, "%x]", ntohs(data[7]));
}

void
log_ipv6(const void *ipv6addr)
{
	fprint_ipv6(global_output, ipv6addr);
}

void
close_log()
{
	if(global_output != stdout)
		fclose(global_output);
}
