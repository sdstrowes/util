#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define nelem(x) (int)(sizeof(x)/sizeof(x[0]))

typedef struct {
	char * ip;
	int netmask;
	struct in_addr* addr;
} prefix;

/* These are known Spotify prefixes. Netmasks are in network byte
   order. The NULL field is filled later by inet_pton. */

/* These prefixes were visible throughout the November/December 2010
   traces:
   193.182.3.0/24
   193.182.8.0/21
   194.71.232.0/22
   78.31.10.0/24
   78.31.12.0/22
   78.31.8.0/22
   78.31.8.0/24
   78.31.9.0/24
*/

prefix s_pfx[] = {
	{"78.31.8.0",    0xfffffc00, NULL}, /* /22 */
	{"78.31.9.0",    0xffffff00, NULL}, /* /24 */
	{"78.31.10.0",   0xffffff00, NULL}, /* /24 */
	{"78.31.12.0",   0xfffffc00, NULL}, /* /22 */
	{"193.182.3.0",  0xffffff00, NULL}, /* /24 */
	{"193.182.8.0",  0xfffff800, NULL}, /* /21 */
	{"194.71.232.0", 0xfffffc00, NULL}  /* /22 */
};

prefix g_pfx[] = {
	{"130.209.0.0", 0xffff0000, NULL}   /* /16 */
};

prefix h_pfx[] = {
	{"192.168.0.0", 0xffff0000, NULL}   /* /16 */
};

/* This chops off the port number from the tcpdump input. There must
 * be a better way of doing this. */
void ipify(char* ip)
{
	int max = strlen(ip);
	int i;
	for (i = max - 1; i >= 0 ; i--) {
		if (ip[i] == '.') {
			ip[i] = '\0';
			return;
		}
	}
}

/* This determines the 'type' of an IP, based on whether it matches
 * any of the spotify numbers above. If it does, it returns a 'S'erver
 * type, else a 'P'eer type. */
char type_of(char* ip)
{
	int i, rt;
	char type;
	struct in_addr addr;

	rt = inet_pton(AF_INET, ip, &addr);
	if (rt <= 0) {
		printf("FAIL: %s\n", ip);
		perror("inet_pton");
	}

	/* If input IP & netmask == prefix, then output = "S" */
	type = 'P';
	for (i = 0; i < nelem(s_pfx); i++) {
		if (s_pfx[i].addr->s_addr == (addr.s_addr & htonl(s_pfx[i].netmask))) {
			type = 'S';
			break;
		}
	}
/* no longer want to check for Glasgow prefixes!
	for (i = 0; i < nelem(g_pfx); i++) {
		if (g_pfx[i].addr->s_addr == (addr.s_addr & htonl(g_pfx[i].netmask))) {
			type = 'G';
			break;
		}
	}
*/
	for (i = 0; i < nelem(h_pfx); i++) {
		if (h_pfx[i].addr->s_addr == (addr.s_addr & htonl(h_pfx[i].netmask))) {
			type = 'H';
			break;
		}
	}
	return type;
}

/* Read all lines from stdin
 * Parse out IP addresses
 * Determine, for each one, whether it's a spotify or non-spotify 
 *   address
 * Output line with additional flags.
 */
int main(int argc, char* argv[])
{
	char ip1[23];
	char ip2[23];
	int rt;
	int i;

	/* Generate the binary representations of the known IP
	   addresses */
	for (i = 0; i < nelem(s_pfx); i++) {
		s_pfx[i].addr = (struct in_addr*)malloc(sizeof(struct in_addr));
		rt = inet_pton(AF_INET, s_pfx[i].ip, s_pfx[i].addr);	
	}
/* no longer want to check for Glasgow prefixes!
	for (i = 0; i < nelem(g_pfx); i++) {
		g_pfx[i].addr = (struct in_addr*)malloc(sizeof(struct in_addr));
		rt = inet_pton(AF_INET, g_pfx[i].ip, g_pfx[i].addr);	
	}
*/
	for (i = 0; i < nelem(h_pfx); i++) {
		h_pfx[i].addr = (struct in_addr*)malloc(sizeof(struct in_addr));
		rt = inet_pton(AF_INET, h_pfx[i].ip, h_pfx[i].addr);	
	}

	FILE* in = fopen("/dev/stdin", "r");

	memset(ip1, '\0', 23);
	memset(ip2, '\0', 23);


	while (1) {
		char line[1024];
		char* rtp;
		char flag1, flag2;

		memset(line, '\0', 1024);
		rtp = fgets(line, 1024, in);
		if (rtp == NULL) {
			exit(1);
		}

		rt = sscanf(line, "%*s IP %s > %s Flags ", ip1, ip2);
		if (rt < 2) {
			continue;
		}

		ipify(ip1);
		ipify(ip2);

		flag1 = type_of(ip1);
		flag2 = type_of(ip2);

		printf("%c%c %s", flag1, flag2, line);
	}
}
