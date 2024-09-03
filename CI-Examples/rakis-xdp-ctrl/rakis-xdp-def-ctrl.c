/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mansour Alharthi <mansour.alharthi@intel.com>
 */
#include <err.h>
#include <getopt.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#define MAX_NUM_OF_CLIENTS 10
#define RAKIS_XDP_PROG_NAME "rakis-xdp-prog"

static const char* opt_if = NULL;
static const char* opt_ctrl_sock_path = NULL;
static int opt_serve_one = 0;
static int opt_unload = 0;

static struct option long_options[] = {
    {"interface", required_argument, 0, 'i'},
    {"ctrl-sock-path", required_argument, 0, 'p'},
    {"serve-one", optional_argument, 0, 'o'},
    {"unload", optional_argument, 0, 'u'},
    {0, 0, 0, 0}
};

static void usage(void) {/*{{{*/
    const char* str =
        "  Usage: perf-xdp-loader [OPTIONS]\n"
        "  Options:\n"
        "  -i, --interface=n         Run on interface n\n"
        "  -p, --ctrl-sock-path=n    Unix socket path n\n"
        "  -o, --serve-one           Serve only one connecting process then die [Default: false].\n"
        "  -u, --unload              If this argument is given, then the operation becomes unloading XDP program and deleting unix socket.\n"
        "\n";
    printf("%s\n", str);
    exit(0);
}/*}}}*/

static void parse_command_line(int argc, char** argv) {/*{{{*/
    int option_index, c;
    opterr = 0;

    for (;;) {
        c = getopt_long(argc, argv, "i:p:ou", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'i':
                opt_if = optarg;
                break;
            case 'p':
                opt_ctrl_sock_path = optarg;
                break;
            case 'o':
                opt_serve_one = 1;
                break;
            case 'u':
                opt_unload = 1;
                break;
            default:
                usage();
        }
    }
    if(!opt_if)
        errx(EXIT_FAILURE, "Interface argument is required");
    if(!opt_ctrl_sock_path)
        errx(EXIT_FAILURE, "Control unix socket path argument is required");
}/*}}}*/

static int send_xsks_map_fd(int sock, int fd) {/*{{{*/
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    struct msghdr msg;
    struct iovec iov;
    int value = 0;

    iov.iov_base = &value;
    iov.iov_len  = sizeof(int);

    msg.msg_name       = NULL;
    msg.msg_namelen    = 0;
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_flags      = 0;
    msg.msg_control    = cmsgbuf;
    msg.msg_controllen = CMSG_LEN(sizeof(int));

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);

    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));

    *(int*)CMSG_DATA(cmsg) = fd;
    int ret                = sendmsg(sock, &msg, 0);

    if (ret == -1)
        warn("Sendmsg failed");

    return ret;
} /*}}}*/

static int lookup_bpf_map(int prog_fd)
{
	__u32 i, *map_ids, num_maps, prog_len = sizeof(struct bpf_prog_info);
	__u32 map_len = sizeof(struct bpf_map_info);
	struct bpf_prog_info prog_info = {};
	int fd, err, xsks_map_fd = -1;
	struct bpf_map_info map_info;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (err)
		return err;

	num_maps = prog_info.nr_map_ids;

	map_ids = calloc(prog_info.nr_map_ids, sizeof(*map_ids));
	if (!map_ids)
		return -1;

	memset(&prog_info, 0, prog_len);
	prog_info.nr_map_ids = num_maps;
	prog_info.map_ids = (__u64)(unsigned long)map_ids;

	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
	if (err) {
		free(map_ids);
		return err;
	}

	for (i = 0; i < prog_info.nr_map_ids; i++) {
		fd = bpf_map_get_fd_by_id(map_ids[i]);
		if (fd < 0)
			continue;

		memset(&map_info, 0, map_len);
		err = bpf_obj_get_info_by_fd(fd, &map_info, &map_len);
		if (err) {
			close(fd);
			continue;
		}

		if (!strncmp(map_info.name, "xsks_map", sizeof(map_info.name)) &&
		    map_info.key_size == 4 && map_info.value_size == 4) {
			xsks_map_fd = fd;
			break;
		}

		close(fd);
	}

	free(map_ids);
	return xsks_map_fd;
}

static int load_custom_xdp_program(int ifindex, int* xsks_map_fd){
  struct xdp_program * xdp_prog = xdp_program__open_file(RAKIS_XDP_PROG_NAME, NULL, NULL);
  int errn;
  char errmsg[1024];
  errn = libxdp_get_error(xdp_prog);
  if (errn) {
    libxdp_strerror(errn, errmsg, sizeof(errmsg));
    fprintf(stderr, "ERROR: program loading failed: %s\n", errmsg);
    exit(EXIT_FAILURE);
  }

	errn = xdp_program__attach(xdp_prog, ifindex, XDP_MODE_NATIVE, 0);
	if (errn) {
		libxdp_strerror(errn, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERROR: attaching program failed: %s\n", errmsg);
		exit(EXIT_FAILURE);
	}

  errn = lookup_bpf_map(xdp_program__fd(xdp_prog));
  if (errn < 0) {
    libxdp_strerror(errn, errmsg, sizeof(errmsg));
    fprintf(stderr, "ERROR: xdp bpf lookup failed: %s\n", errmsg);
    exit(EXIT_FAILURE);
  }

  *xsks_map_fd = errn;

  return 0;
}

int main(int argc, char** argv) {/*{{{*/
    struct sockaddr_un server;
    int msgsock;
    int ifindex = 0;
    int ret;
    int sock;
    int xsks_map_fd;

    parse_command_line(argc, argv);

    ifindex = if_nametoindex(opt_if);
    if (ifindex == 0)
        err(EXIT_FAILURE, "Unable to get ifindex for Interface %s.", opt_if);

    if (opt_unload) {
        unlink(opt_ctrl_sock_path);

        LIBBPF_OPTS(bpf_xdp_attach_opts, detach_opts);
        int ret = bpf_xdp_detach(ifindex, 0, &detach_opts);
        if (ret)
            err(EXIT_FAILURE, "Failed to unload xdp program from interface %s", opt_if);

        printf("[*] Successfully unloaded xdp program at %s and removed unix socket at %s\n", opt_if, opt_ctrl_sock_path);
        return EXIT_SUCCESS;
    }

    // better security practics should be used here. However, since this program
    // will mostly run as root, and Gramine would not, we need to make sure
    // this EXAMPLE loader is accessable to Gramine.
    umask(0);

    ret = load_custom_xdp_program(ifindex, &xsks_map_fd);
    if (ret){
        unlink(opt_ctrl_sock_path);
        err(EXIT_FAILURE, "Failed setting up the XDP program at %s", opt_if);
    }

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0)
        err(EXIT_FAILURE, "Opening unix socket stream failed.");

    server.sun_family = AF_UNIX;
    int unix_server_path_len = strnlen(opt_ctrl_sock_path, sizeof(server.sun_path));
    if (unix_server_path_len == sizeof(server.sun_path))
        errx(EXIT_FAILURE, "The provided unix server path is too long!");
    strncpy(server.sun_path, opt_ctrl_sock_path, unix_server_path_len);

    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));

    if (bind(sock, (struct sockaddr*)&server, sizeof(struct sockaddr_un)))
        err(EXIT_FAILURE, "Binding to unix socket stream failed.");

    listen(sock, MAX_NUM_OF_CLIENTS);
    do{
        msgsock = accept(sock, 0, 0);
        if (msgsock == -1)
            warn("Could not accept connection.");

        ret = send_xsks_map_fd(msgsock, xsks_map_fd);
        if(ret <= 0)
            warn("Could not send xsks map fd to client.");

        printf("[*] Successfully sent the xsks map fd to one client.\n");
    }while(!opt_serve_one);

    close(msgsock);
    close(sock);
    unlink(opt_ctrl_sock_path);
    // but we dont unload the xdp program!
    return 0;
}/*}}}*/
