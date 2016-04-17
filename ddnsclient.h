#include <stdbool.h>

void _assert(const char* text);

#define log(args...) fprintf(global_output, args)
#define verbose_log(args...) do { if(verbose_mode) log(args); } while(0)

void log_time();
void log_ipv6(const void* ipv6addr);
void close_log();
void _perror(const char* prefix);

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define assert(b) do {if(!(b)){_assert(#b " ("__FILE__ ":" TOSTRING(__LINE__)")");}} while(0)

extern bool verbose_mode;
extern FILE *global_output;

void skeleton_daemon();

void send_update_request(const char *hostname, const char* myip, const char *username, const char* password);
