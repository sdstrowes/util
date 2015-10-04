/**
 * For licensing, see ./LICENSE
 * 
 * Currently, this code allows insertions and lookups, but not
 * deletions. The data structure is a simple trie, which provides an
 * O(log n) bound on insertions and lookups. Deletions wouldn't be
 * tricky to add.
 * 
 * When performing a lookup, bit comparisons decide left/right
 * traversal from the head of the tree, and the prefix length defines
 * a maximum depth when inserting. The lookup function will traverse
 * the tree until it determines that no more specific match than the
 * best already found is possible. The code will replace all valid IP
 * addresses (according to inet_pton()) with the matching prefix, or
 * "NF" if there was no match. It will not attempt to match tokens
 * that are not prefixes, but will print them out in the output.
 * 
 * The code reads the lines to convert from standard input; it reads a
 * list of prefixes from a file, specified by the "-f" parameter. The
 * prefix file should contain one prefix per line, with the prefix and
 * the netmask separated by a space. All output is sent to standard
 * output.
 */

#include "tree.h"

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include <math.h>
#include <string.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>

int debug = 0;

/*#define DEBUG(fmt, ...) do { if (debug) fprintf(stderr, fmt, __VA_ARGS__); } while (0)*/
#define DEBUG(...) do { if (debug) fprintf(stdout, __VA_ARGS__); } while (0)

char *print_binary(uint8_t *data, int data_byte_len, char *out, int out_byte_len)
{
	char *ptr = out + out_byte_len - 2;
	uint8_t one  = 1;

	while (data_byte_len != 0) {
		data_byte_len--;
		uint8_t current_byte = data[data_byte_len];
		int i;
		for (i = 7; i >= 0; i--) {
			*ptr = (current_byte & one) ? '1' : '0';
			ptr--;
			current_byte = current_byte >> 1;
		}
	}

	return out;
}

/*
 * This creates an data (value-holding) node which points nowhere.
 */
struct data_node* create_data_node(struct sockaddr_storage *prefix, uint8_t netmask)
{
	struct data_node* node = (struct data_node*)malloc(sizeof(struct data_node));
	node->type  = DAT_NODE;
	node->prefix = prefix;
	node->netmask  = netmask;
	node->l = NULL;
	node->r = NULL;

	char prefix_str[INET6_ADDRSTRLEN];
	switch (prefix->ss_family) {
	case AF_INET6: {
		inet_ntop(AF_INET6, &((struct sockaddr_in6 *)prefix)->sin6_addr, prefix_str, INET6_ADDRSTRLEN);
		break;
	}
	case AF_INET: {
		inet_ntop(AF_INET, &((struct sockaddr_in *)prefix)->sin_addr, prefix_str, INET_ADDRSTRLEN);
		break;
	}
	}
	DEBUG("## Created data node %p for %s\n", (void*)node, prefix_str);

	return node;
}

/*
 * This creates an internal node that points nowhere.
 */
struct internal_node* create_internal_node()
{
	struct internal_node* tmp = (struct internal_node*)malloc(sizeof(struct internal_node));
	DEBUG("## Created internal node %p\n", (void*)tmp);
	tmp->type = INT_NODE;
	tmp->l = NULL;
	tmp->r = NULL;

	return tmp;
}

bool test_v_bit(struct sockaddr_storage *addr, uint8_t bit)
{
	if (addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;

		uint8_t byte_idx    = bit / 8;
		uint8_t subbyte_idx = bit % 8;

		uint8_t subbyte = addr6->sin6_addr.s6_addr[byte_idx];
		uint8_t v_bit = subbyte & ((uint8_t)pow(2, subbyte_idx));

		return v_bit;
	}
	else if (addr->ss_family == AF_INET) {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
		uint32_t v_bit = addr4->sin_addr.s_addr & ((uint32_t)pow(2, bit));

		return v_bit;
	}

	return 0;
}

/*
 * This function used internally; see lpm_insert().
 */
void insert(struct sockaddr_storage *prefix, uint32_t nm, struct internal_node* n)
{
	uint8_t b = 0;
	uint8_t depth = 0;
	struct internal_node* parent;
	struct internal_node* next = n;

	if (prefix->ss_family == AF_INET6) {
		b = MAX_BITS6;
	}
	else if (prefix->ss_family == AF_INET) {
		b = MAX_BITS4;
	}


	/* First, find the correct location for the prefix. Burrow down to
	   the correct depth, potentially creating internal nodes as I
	   go. */
	do {
		n = next;
		b--;
		depth++;

		parent = (struct internal_node*)n;
		bool v_bit = test_v_bit(prefix, b);

		/* Determine which direction to descend. */
		if (v_bit) {
			if (n->r == NULL) {
				n->r = create_internal_node();
			}
			next = n->r;
		}
		else {
			if (n->l == NULL) {
				n->l = create_internal_node();
			}
			next = n->l;
		}
	} while (depth < nm);

	if (next == NULL) {
		/* The easy case. */
		struct data_node* node = create_data_node(prefix, nm);
		bool v_bit = test_v_bit(prefix, b);
		if (v_bit) {
			parent->r = (struct internal_node*)node;
		}
		else {
			parent->l = (struct internal_node*)node;
		}
	}
	else if (next->type == INT_NODE) {
		/* In this case, we've descended as far as we can. Attach the
		   prefix here. */
		bool v_bit = test_v_bit(prefix, b);
		struct data_node* newnode = create_data_node(prefix, nm);
		newnode->l = next->l;
		newnode->r = next->r;

		if (v_bit) {
			n->r = (struct internal_node*)newnode;
		}
		else {
			n->l = (struct internal_node*)newnode;
		}

		DEBUG("## Freeing %p\n", (void*)next);
		free(next);
	}
}

/* destroy:
 * Recursively destroys nodes.
 */
void destroy(struct internal_node* node)
{
	if (node == NULL) return;

	if (node->l != NULL) {
		destroy(node->l);
	}
	if (node->r != NULL) {
		destroy(node->r);
	}

	free(node);
}


/* lpm_destroy:
 * Frees the entire tree structure.
 */
void lpm_destroy(struct lpm_tree* tree)
{
	if (tree == NULL) return;
	destroy(tree->head);
	free(tree);
}


/* lpm_init:
 * Constructs a fresh tree ready for use by the other functions.
 */
struct lpm_tree* lpm_init()
{
	/* Build empty internal node, and attach it to new tree. */
	struct internal_node* node = create_internal_node();

	struct lpm_tree* tree = (struct lpm_tree*)malloc(sizeof(struct lpm_tree));
	DEBUG("## Created tree %p\n", (void*)tree);
	tree->head = node;

	return tree;
}


/* lpm_insert:
 * Insert a new prefix ('ip_string' and 'netmask') into the tree. If
 * 'ip_string' does not contain a valid IPv4 address, or the netmask
 * is clearly invalid, the tree is not modified and the function
 * returns 0. Successful insertion returns 1.
 */
int lpm_insert(struct lpm_tree* tree, char* ip_string, uint32_t netmask)
{
	struct sockaddr_storage *prefix = (struct sockaddr_storage *)malloc(sizeof(struct sockaddr_storage));

	struct sockaddr_in6 *prefix6 = (struct sockaddr_in6 *)prefix;
	struct sockaddr_in  *prefix4 = (struct sockaddr_in *) prefix;

	if (inet_pton(AF_INET6, ip_string, &prefix6->sin6_addr) == 1 && netmask <= MAX_BITS6) {
		prefix->ss_family = AF_INET6;

		char buffer[129];
		memset(buffer, '\0', 129);
		printf("%s\n", print_binary((uint8_t *)&prefix6->sin6_addr, sizeof(prefix6->sin6_addr), buffer, 129));

		DEBUG(">> Inserting %s/%d ========\n", ip_string, netmask);
		insert(prefix, netmask, tree->head);
		DEBUG(">> Done inserting %s/%d ===\n", ip_string, netmask);

		return 1;
	}
	else if (inet_pton(AF_INET, ip_string, &prefix4->sin_addr) == 1 && netmask <= MAX_BITS4) {
		prefix4->sin_family = AF_INET;
		prefix4->sin_addr.s_addr = htonl(prefix4->sin_addr.s_addr);

		char buffer[33];
		memset(buffer, '\0', 33);
		printf("%s\n", print_binary((uint8_t *)&prefix4->sin_addr, sizeof(prefix4->sin_addr), buffer, 32));

		DEBUG(">> Inserting %s/%d ========\n", ip_string, netmask);
		insert(prefix, netmask, tree->head);
		DEBUG(">> Done inserting %s/%d ===\n", ip_string, netmask);
		return 1;
	}

	return 0;
}

/*
 * Internal function; called by lpm_lookup()
 */
void lookup(struct sockaddr_storage *addr, char* output, struct internal_node* n)
{
	uint32_t b = 0;
	struct internal_node* next = n;

	struct  sockaddr_storage *best_prefix = NULL;
	uint8_t best_netmask = 0;

	if (addr->ss_family == AF_INET6) {
		b = MAX_BITS6;
	}
	else if (addr->ss_family == AF_INET) {
		b = MAX_BITS4;
	}

	do {
		n = next;
		b--;

		bool v_bit = test_v_bit(addr, b);

		/* If we've found an internal node, determine which
		   direction to descend. */
		if (v_bit) {
			next = n->r;
		}
		else {
			next = n->l;
		}

		if (n->type == DAT_NODE) {
			struct data_node* node = (struct data_node*)n;

			char prefix[INET6_ADDRSTRLEN];
			switch (node->prefix->ss_family) {
			case AF_INET6: {
				struct sockaddr_in6 *match_addr = (struct sockaddr_in6 *)addr;
				inet_ntop(AF_INET6, &match_addr->sin6_addr, prefix, INET6_ADDRSTRLEN);

				printf("WARNING: IPv6 unhandled!\n");

				break;
			}
			case AF_INET: {
				struct sockaddr_in *match_addr = (struct sockaddr_in *)addr;
				struct sockaddr_in *node_addr  = (struct sockaddr_in *)node->prefix;
				inet_ntop(AF_INET, &match_addr->sin_addr, prefix, INET6_ADDRSTRLEN);

				uint32_t mask = 0xFFFFFFFF;
				mask = mask - ((uint32_t)pow(2, 32 - node->netmask) - 1);

				if ((match_addr->sin_addr.s_addr & mask) == node_addr->sin_addr.s_addr) {
					best_prefix = node->prefix;
					best_netmask = node->netmask;
				}
				else {
					break;
				}

				break;
			}
			}
		}
	} while (next != NULL);

	if (best_prefix == NULL) {
		sprintf(output, "NF");
	}
	else {
		char prefix[INET6_ADDRSTRLEN];
		switch (best_prefix->ss_family) {
		case AF_INET6: {
			inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&best_prefix)->sin6_addr, prefix, INET6_ADDRSTRLEN);
			break;
		}
		case AF_INET: {
			struct sockaddr_in *addr4 = (struct sockaddr_in *)best_prefix;
			struct in_addr addr_bytes;
			addr_bytes.s_addr = htonl(addr4->sin_addr.s_addr);
			inet_ntop(AF_INET, &addr_bytes, prefix, INET_ADDRSTRLEN);
			break;
		}
		}


		sprintf(output, "%s/%d", prefix, best_netmask);
	}
}

/* lpm_lookup:
 * Perform a lookup. Given a string 'ip_string' convert to the
 * best-matching prefix if the string is a valid IPv4 address
 * (according to inet_pton), and store it in 'output' and return 1. If
 * no match is found, store the string "NF" in 'output' and return
 * 1. If 'ip_string' is not a valid IPv4 address, return 0, and
 * 'output' is not modified.
 */
int lpm_lookup(struct lpm_tree* tree, char* ip_string, char* output)
{
	struct sockaddr_storage addr;

	if (inet_pton(AF_INET6, ip_string, &((struct sockaddr_in6 *)&addr)->sin6_addr)) {
		lookup(&addr, output, tree->head);
	}
	else if (inet_pton(AF_INET, ip_string, &((struct sockaddr_in *)&addr)->sin_addr)) {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;
		addr4->sin_family = AF_INET;
		addr4->sin_addr.s_addr = htonl(addr4->sin_addr.s_addr);
		lookup(&addr, output, tree->head);
	}
	return 1;
}




/* debug_print:
 * Prints out the current node's parent, the current node's value (if
 * it has one), and recurses down to the left then right children. The
 * 'left' parameter should indicate the direction of the hop to the
 * current node (1 if the left child was used, 0 if the right child
 * was used; -1 is used to indicate the root of the tree.)
 */
void debug_print(struct internal_node* parent, int left, int depth, struct internal_node* n)
{
	printf("parent:%p", (void*)parent);
	if (left == 1) {
		printf("->L");
	}
	else if (left == 0) {
		printf("->R");
	}
	else {
		printf("---");
	}

	if (n == NULL) {
		printf(" Reached a null bottom %p\n", (void*)n);
		return;
	}
	else if (n->type == INT_NODE) {
		printf(" Internal node %p.\n", (void*)n);
	}
	else {
		struct data_node* node = (struct data_node*)n;

		char output[INET6_ADDRSTRLEN];
		memset(output, 0, INET6_ADDRSTRLEN);
		struct sockaddr_storage *addr = node->prefix;
		switch (addr->ss_family) {
		case AF_INET6: {
			struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
			inet_ntop(AF_INET6, &addr6->sin6_addr, output, INET6_ADDRSTRLEN);
			break;
		}
		case AF_INET: {
			struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
			inet_ntop(AF_INET, &addr4->sin_addr, output, INET6_ADDRSTRLEN);
			char buffer[33];
			memset(buffer, '\0', 33);
			printf("%s\n", print_binary((uint8_t *)&addr4->sin_addr, sizeof(addr4->sin_addr), buffer, 33));
			break;
		}
		}

		printf(" External node: %p, %s/%d\n", (void*)n, output, node->netmask);
	}

	debug_print(n, 1, depth+1, n->l);
	debug_print(n, 0, depth+1, n->r);
}

/* lpm_debug_print:
 * Traverses the tree and prints out node status, starting from the root.
 */
void lpm_debug_print(struct lpm_tree* tree)
{
	if (debug) {
		debug_print((struct internal_node*)tree, -1, 0, tree->head);
	}
}

/*
 * Educate the user via standard error.
 */
void print_usage(char* name)
{
	fprintf(stderr, "%s will replace any IPv4 address on standard input with the\n", name);
	fprintf(stderr, "\tmatching prefix in prefix_file, or 'NF'.\n");
	fprintf(stderr, "Usage: %s -f prefix_file [-d]\n\n", name);
}


int main(int argc, char* argv[])
{
	char* input;
	int opt;
	struct lpm_tree* tree;
	FILE* in;
	char* ifile = "/dev/stdin";

	/* Check inputs; print usage and exit if something is clearly
	   wrong. */
	if (argc < 3) {
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	/* Parse options */
	while ((opt = getopt(argc, argv, "df:")) != -1) {
		switch (opt) {
		case 'd':
			debug = 1;
			break;
		case 'f':
			input = optarg;
			break;
		default: /* '?' */
			print_usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	/* Create a fresh tree. */
	tree = lpm_init();

	/* Read in all prefixes. */
	in = fopen(input, "r");
	while (1) {
		char *line = NULL;
		size_t linecap = 0;
		ssize_t linelen;
		char ip_string[INET6_ADDRSTRLEN];
		int mask;
		uint8_t rt;

		linelen = getline(&line, &linecap, in);
		if (linelen < 0) {
			break;
		}
		rt = sscanf(line, "%39s %d%*[^\n]", ip_string, &mask);
		if (rt < 2) {
			continue;
		}

		lpm_insert(tree, ip_string, mask);
	}
	fclose(in);

	lpm_debug_print(tree);

	/* Begin reading from standard input the lines of text to
	   convert. */
	in = fopen(ifile, "r");
	while (1) {
		char *line = NULL;
		size_t linecap = 0;
		ssize_t linelen;
		char address_string[16];
		char output[16];
		char* pointer;
		char* strstart;
		char* strend;
		int rt;

		/* Read line. */
		linelen = getline(&line, &linecap, in);
		if (linelen < 0) {
			break;
		}

		line[strlen(line)-1] = '\0';

		pointer = line;
		strstart = pointer;
		strend = strstr(strstart, " ");

		while (strend != NULL) {
			memset(address_string, '\0', 16);
			memcpy(address_string, strstart, strend - strstart);

			memset(output,         '\0', 16);
			rt = lpm_lookup(tree, address_string, output);

			if (rt) {
				printf("%s ", output);
			}
			else {
				printf("%s ", address_string);
			}

			strstart = strend + 1;
			strend = strstr(strstart, " ");
		}

		memset(output, '\0', 16);
		rt = lpm_lookup(tree, strstart, output);
		if (rt) {
			printf("%s\n", output);
		}
		else {
			printf("%s\n", strstart);
		}

		free(line);
	}

	lpm_destroy(tree);

	fclose(in);
	return 1;
}
