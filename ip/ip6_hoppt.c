/*
 * ip6_hoppt.c "ip pt"
 *
 *	  This program is free software; you can redistribute it and/or
 *	  modify it under the terms of the GNU General Public License
 *	  version 2 as published by the Free Software Foundation;
 *
 * Authors: Andrea Mayer <andrea.mayer@uniroma2.it>
 *          Paolo Lungaroni <paolo.lungaroni@uniroma2.it>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>

#include <linux/genetlink.h>
#include <linux/ip6_hoppt_genl.h>
//#include <linux/ip6_hoppt.h>

#include "utils.h"
#include "ip_common.h"
#include "libgenl.h"
#include "json_print.h"

static void usage(void)
{
	fprintf(stderr,
		"Usage: ip pt add dev DEVICE id ID tts TMPL\n"
		"\n"
		"       ip pt del dev DEVICE [ id ID tts TMPL ]\n"
		"\n"
		"       ip pt show [ dev DEVICE ]\n"
		"\n"
		"ip pt source { add | del } dev DEVICE\n"
		"\n"
		"ip pt source show\n"
		"\n"
		"Where: DEVICE    := Interface\n"
		"       ID        := 0..4095\n"
		"       TMPL      := template1..template4\n");
	exit(-1);
}

static struct rtnl_handle grth = { .fd = -1 };
static int genl_family = -1;

#define IPV6_HOPPT_REQUEST(_req, _bufsiz, _cmd, _flags)		\
	GENL_REQUEST(_req, _bufsiz, genl_family, 0,		\
		     IPV6_HOPPT_GENL_VERSION, _cmd, _flags)

static struct {
	unsigned int cmd;
	__u32 id;
	__u32 ifindex;
	__u32 ttstmpl;
} opts;

static const char *pt_tts_names[IPV6_HOPPT_TTS_TMPL_MAX + 1] = {
	[IPV6_HOPPT_TTS_TMPL_1]		= "template1",
	[IPV6_HOPPT_TTS_TMPL_2]		= "template2",
	[IPV6_HOPPT_TTS_TMPL_3]		= "template3",
	[IPV6_HOPPT_TTS_TMPL_4]		= "template4",
};

static const char *pt_tts_short_names[IPV6_HOPPT_TTS_TMPL_MAX + 1] = {
	[IPV6_HOPPT_TTS_TMPL_1]		= "tmpl1",
	[IPV6_HOPPT_TTS_TMPL_2]		= "tmpl2",
	[IPV6_HOPPT_TTS_TMPL_3]		= "tmpl3",
	[IPV6_HOPPT_TTS_TMPL_4]		= "tmpl4",
};

static const char *format_tts_tmpl(int tmplid)
{
	if (tmplid < 0 || tmplid > IPV6_HOPPT_TTS_TMPL_MAX)
		return "<invalid>";

	return pt_tts_names[tmplid] ?: "<unknown>";
}

static int read_tts_tmpl(const char *name)
{
	int i;

	for (i = 0; i < IPV6_HOPPT_TTS_TMPL_MAX + 1; i++) {
		if (!pt_tts_names[i])
			continue;

		if (strcmp(pt_tts_names[i], name) == 0)
			return i;

		if (strcmp(pt_tts_short_names[i], name) == 0)
			return i;
	}

	return IPV6_HOPPT_TTS_TMPL_UNSPEC;
}

static void print_id(struct rtattr *attrs[])
{
	unsigned int id = rta_getattr_u32(attrs[IPV6_HOPPT_ATTR_ID]);
	int ifindex = rta_getattr_s32(attrs[IPV6_HOPPT_ATTR_IFINDEX]);
	unsigned int tts = rta_getattr_u32(attrs[IPV6_HOPPT_ATTR_TTSTMPL]);

	print_string(PRINT_ANY, "dev", "dev %s ", ll_index_to_name(ifindex));
	print_uint(PRINT_ANY, "id", "id %u (0x%x) ", id);
	print_string(PRINT_ANY, "tts", "tts %s\n", format_tts_tmpl(tts));
}

static void print_list_id(struct rtattr *attrs[])
{
	print_id(attrs);
}

static void print_iface(struct rtattr *attrs[])
{
	int ifindex = rta_getattr_s32(attrs[IPV6_HOPPT_ATTR_IFINDEX]);

	print_string(PRINT_ANY, "incoming dev", "incoming dev %s\n",
		     ll_index_to_name(ifindex));
}

static int process_msg(struct nlmsghdr *n, void *arg)
{
	struct rtattr *attrs[IPV6_HOPPT_ATTR_MAX + 1];
	struct genlmsghdr *ghdr;
	int len = n->nlmsg_len;

	if (n->nlmsg_type != genl_family)
		return -1;

	len -= NLMSG_LENGTH(GENL_HDRLEN);
	if (len < 0)
		return -1;

	ghdr = NLMSG_DATA(n);

	parse_rtattr(attrs, IPV6_HOPPT_ATTR_MAX, (void *)ghdr + GENL_HDRLEN,
		     len);

	open_json_object(NULL);
	switch (ghdr->cmd) {
	case IPV6_HOPPT_CMD_SHOW_ID:
		print_id(attrs);
		break;
	case IPV6_HOPPT_CMD_DUMP_ID:
		print_list_id(attrs);
		break;
	case IPV6_HOPPT_CMD_TGRCV_DUMP_ID:
		print_iface(attrs);
		break;
	}
	close_json_object();

	return 0;
}

static int ipv6_hoppt_do_cmd(void)
{
	IPV6_HOPPT_REQUEST(req, 1024, opts.cmd, NLM_F_REQUEST);
	struct nlmsghdr *answer;
	int repl = 0, dump = 0;

	if (genl_family < 0) {
		if (rtnl_open_byproto(&grth, 0, NETLINK_GENERIC) < 0) {
			fprintf(stderr, "Cannot open generic netlink socket\n");
			exit(1);
		}
		genl_family = genl_resolve_family(&grth, IPV6_HOPPT_GENL_NAME);
		if (genl_family < 0)
			exit(1);
		req.n.nlmsg_type = genl_family;
	}

	switch (opts.cmd) {
	case IPV6_HOPPT_CMD_ADD_ID:
		addattr32(&req.n, sizeof(req), IPV6_HOPPT_ATTR_ID,
			  opts.id);
		addattr32(&req.n, sizeof(req), IPV6_HOPPT_ATTR_IFINDEX,
			  opts.ifindex);
		addattr32(&req.n, sizeof(req), IPV6_HOPPT_ATTR_TTSTMPL,
			  opts.ttstmpl);
		break;
	case IPV6_HOPPT_CMD_DEL_ID:
		addattr32(&req.n, sizeof(req), IPV6_HOPPT_ATTR_IFINDEX,
			  opts.ifindex);
		break;
	case IPV6_HOPPT_CMD_SHOW_ID:
		addattr32(&req.n, sizeof(req), IPV6_HOPPT_ATTR_IFINDEX,
			  opts.ifindex);
		repl = 1;
		break;
	case IPV6_HOPPT_CMD_DUMP_ID:
		dump = 1;
		break;
	case IPV6_HOPPT_CMD_TGRCV_ADD_ID:
		addattr32(&req.n, sizeof(req), IPV6_HOPPT_ATTR_IFINDEX,
			  opts.ifindex);
		break;
	case IPV6_HOPPT_CMD_TGRCV_DEL_ID:
		addattr32(&req.n, sizeof(req), IPV6_HOPPT_ATTR_IFINDEX,
			  opts.ifindex);
		break;
	case IPV6_HOPPT_CMD_TGRCV_DUMP_ID:
		repl = 1;
		break;
	}

	if (!repl && !dump) {
		if (rtnl_talk(&grth, &req.n, NULL) < 0)
			return -1;
	} else if (repl) {
		if (rtnl_talk(&grth, &req.n, &answer) < 0)
			return -2;
		new_json_obj(json);
		if (process_msg(answer, stdout) < 0) {
			fprintf(stderr, "Error parsing reply\n");
			exit(1);
		}
		delete_json_obj();
		free(answer);
	} else {
		req.n.nlmsg_flags |= NLM_F_DUMP;
		req.n.nlmsg_seq = grth.dump = ++grth.seq;
		if (rtnl_send(&grth, &req, req.n.nlmsg_len) < 0) {
			perror("Failed to send dump request");
			exit(1);
		}

		new_json_obj(json);
		if (rtnl_dump_filter(&grth, process_msg, stdout) < 0) {
			fprintf(stderr, "Dump terminated\n");
			exit(1);
		}
		delete_json_obj();
		fflush(stdout);
	}

	return 0;
}

/* FIXME: check for duplicate keywords ? */
int do_ipv6_hoppt(int argc, char **argv)
{
	memset(&opts, 0, sizeof(opts));

	if (argc < 1) {
		opts.cmd = IPV6_HOPPT_CMD_DUMP_ID;
		return ipv6_hoppt_do_cmd();
	}

	if (matches(*argv, "help") == 0) {
		usage();
	} else if (matches(*argv, "source") == 0 ||
		   matches(*argv, "src") == 0) {
		NEXT_ARG();
		if (matches(*argv, "show") == 0 ||
		    matches(*argv, "list") == 0 || matches(*argv, "lst") == 0) {
			opts.cmd = IPV6_HOPPT_CMD_TGRCV_DUMP_ID;
		} else if (matches(*argv, "add") == 0) {
			NEXT_ARG();
			if (matches(*argv, "dev") != 0)
				invarg("missing \"dev\" attribute", *argv);

			NEXT_ARG();
			opts.ifindex = ll_name_to_index(*argv);
			if (!opts.ifindex)
				exit(nodev(*argv));

			opts.cmd = IPV6_HOPPT_CMD_TGRCV_ADD_ID;
		} else if (matches(*argv, "del") == 0) {
			NEXT_ARG();
			if (matches(*argv, "dev") != 0)
				invarg("missing \"dev\" attribute", *argv);

			NEXT_ARG();
			opts.ifindex = ll_name_to_index(*argv);
			if (!opts.ifindex)
				exit(nodev(*argv));

			opts.cmd = IPV6_HOPPT_CMD_TGRCV_DEL_ID;
		} else {
			fprintf(stderr, "Command \"%s\" is unknown, try \"ip pt help\".\n", *argv);
			exit(-1);
		}
	} else if (matches(*argv, "show") == 0 || matches(*argv, "list") == 0 ||
		   matches(*argv, "lst") == 0) {
		if (argc == 1){
			opts.cmd = IPV6_HOPPT_CMD_DUMP_ID;
		} else if (argc > 1) {
			NEXT_ARG();
			if (matches(*argv, "dev") != 0)
				invarg("missing \"dev\" attribute", *argv);

			NEXT_ARG();
			opts.ifindex = ll_name_to_index(*argv);
			if (!opts.ifindex)
				exit(nodev(*argv));

			opts.cmd = IPV6_HOPPT_CMD_SHOW_ID;
		}
	} else if (matches(*argv, "add") == 0) {
		NEXT_ARG();
		if (matches(*argv, "dev") != 0)
			invarg("missing \"dev\" attribute", *argv);

		NEXT_ARG();
		opts.ifindex = ll_name_to_index(*argv);
		if (!opts.ifindex)
			exit(nodev(*argv));

		NEXT_ARG();
		if (matches(*argv, "id") != 0)
			invarg("missing \"id\" attribute", *argv);

		NEXT_ARG();
		get_u32(&opts.id, *argv, 0);

		NEXT_ARG();
		if (matches(*argv, "tts") != 0)
			invarg("missing \"tts template\" attribute", *argv);

		NEXT_ARG();
		if (get_u32(&opts.ttstmpl, *argv, 0))
			opts.ttstmpl = read_tts_tmpl(*argv);

		opts.cmd = IPV6_HOPPT_CMD_ADD_ID;
	} else if (matches(*argv, "del") == 0) {
		NEXT_ARG();
		if (matches(*argv, "dev") != 0)
			invarg("missing \"dev\" attribute", *argv);

		NEXT_ARG();
		opts.ifindex = ll_name_to_index(*argv);
		if (!opts.ifindex)
			exit(nodev(*argv));

		opts.cmd = IPV6_HOPPT_CMD_DEL_ID;
	} else {
		fprintf(stderr, "Command \"%s\" is unknown, try \"ip pt help\".\n", *argv);
		exit(-1);
	}

	return ipv6_hoppt_do_cmd();
}
