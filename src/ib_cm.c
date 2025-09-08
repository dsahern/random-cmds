#include <arpa/inet.h>
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include <stdbool.h>
#include <unistd.h>

#include "logging.h"
#include "str_utils.h"

/* used for CQ and WQs */
#define QUEUE_DEPTH		128
#define CM_OP_TIMEOUT_MS	1000

struct ctx {
	struct rdma_event_channel *channel;
	struct rdma_cm_id *cm_id;

	struct sockaddr_in6 local_addr;
	struct sockaddr_in6 rem_addr;
	struct sockaddr *laddr;
	struct sockaddr *raddr;

	struct ibv_device_attr dev_attr;

	struct ibv_context *context;
	struct ibv_pd *pd;
	struct ibv_cq *cq; /* one cq for send and recv; this is a stupid app */
	struct ibv_qp *qp;
};

static int find_ib_context(struct ctx *ctx, const char *dev)
{
	struct ibv_context **ctx_list;
	int num_devices, i;

	ctx_list = rdma_get_devices(&num_devices);
	if (!ctx_list) {
		log_error("No RDMA devices available");
		return -1;
	}

	for (i = 0; i < num_devices; ++i) {
		if (!strcmp(ibv_get_device_name(ctx_list[i]->device), dev)) {
			ctx->context = ctx_list[i];
			break;
		}
	}

	rdma_free_devices(ctx_list);

	if (!ctx->context) {
		log_error("IB device %s not available", dev);
		return -1;
	}

	return 0;
}

static int ctx_init(struct ctx *ctx, const char *dev)
{
	int rc = -1;

	if (find_ib_context(ctx, dev))
		return -1;

	if (ibv_query_device(ctx->context, &ctx->dev_attr)) {
		log_err_errno("ibv_query_device failed for dev %s", dev);
		return -1;
	}

	log_msg("IB device %s node GUID %llx\n", dev, ctx->dev_attr.node_guid);

	ctx->cq = ibv_create_cq(ctx->context, QUEUE_DEPTH, NULL, NULL, 0);
	if (ctx->cq == NULL) {
		log_err_errno("ibv_create_cq failed");
		goto err_create_cq;
	}

	ctx->channel = rdma_create_event_channel();
	if (!ctx->channel) {
		log_err_errno("rdma_create_event_channel failed");
		goto err_event_channel;
	}

	/* RDMA_PS_TCP - Provides reliable, connection-oriented QP
	 * communication.
	 */
	rc = rdma_create_id(ctx->channel, &ctx->cm_id, NULL, RDMA_PS_TCP);
	if (rc) {
		log_err_errno("rdma_create_id failed");
		goto err_create_id;
	}

	return 0;

err_create_id:
	rdma_destroy_event_channel(ctx->channel);
err_event_channel:
	ibv_destroy_cq(ctx->cq);
err_create_cq:
	return rc;
}

static void ctx_cleanup(struct ctx *ctx)
{
	rdma_destroy_id(ctx->cm_id);
	rdma_destroy_event_channel(ctx->channel);
}

static int qp_init(struct ctx *ctx)
{
	struct ibv_qp_init_attr qp_init_attr = {
		.cap.max_recv_sge = 1,
		.cap.max_recv_wr = QUEUE_DEPTH,
		.cap.max_send_sge = 1,
		.cap.max_send_wr = QUEUE_DEPTH,
		.qp_type = IBV_QPT_RC,
		.recv_cq = ctx->cq,
		.send_cq = ctx->cq,
	};

	ctx->pd = ibv_alloc_pd(ctx->context);
	if (ctx->pd == NULL) {
		log_err_errno("ibv_alloc_pd failed");
		goto err_out;
	}

	if (rdma_create_qp(ctx->cm_id, ctx->pd, &qp_init_attr)) {
		log_err_errno("rdma_create_qp failed");
		goto err_create_qp;
	}

	ctx->qp = ctx->cm_id->qp;

	return 0;

err_create_qp:
	ibv_dealloc_pd(ctx->pd);
err_out:
	return -1;
}

static void qp_cleanup(struct ctx *ctx)
{
	if (ibv_destroy_qp(ctx->qp))
		log_err_errno("ibv_destroy_qp failed");
}

static int get_ack_cm_op(struct ctx *ctx, enum rdma_cm_event_type exp_evt)
{
	struct rdma_cm_event *event;

	if (rdma_get_cm_event(ctx->channel, &event)) {
		log_err_errno("rdma_get_cm_event failed");
		return -1;
	}

	if (event->event != exp_evt) {
		log_error("rdma_get_cm_event returned event %s expected %s\n",
			  rdma_event_str(event->event), rdma_event_str(exp_evt));
	}

	/* frees event */
	if (rdma_ack_cm_event(event)) {
		log_err_errno("rdma_ack_cm_event failed for event %s",
			      rdma_event_str(event->event));
		return -1;
	}

	return 0;
}

static int resolve_route(struct ctx *ctx)

{
	if (rdma_resolve_route(ctx->cm_id, CM_OP_TIMEOUT_MS)) {
		log_err_errno("rdma_resolve_route call failed");
		return -1;
	}

	if (get_ack_cm_op(ctx, RDMA_CM_EVENT_ROUTE_RESOLVED)) {
		log_error("Failed to resolve route to peer\n");
		return -1;
	}

	return 0;
}

static int resolve_addr(struct ctx *ctx, struct sockaddr *addr, const char *desc)

{
	if (rdma_resolve_addr(ctx->cm_id, NULL, addr, CM_OP_TIMEOUT_MS)) {
		log_err_errno("rdma_resolve_addr call failed");
		return -1;
	}

	if (get_ack_cm_op(ctx, RDMA_CM_EVENT_ADDR_RESOLVED)) {
		log_error("Failed to resolve %s address\n", desc);
		return -1;
	}

	return 0;
}

static int bind_addr(struct ctx *ctx, struct sockaddr *addr)
{
	if (rdma_bind_addr(ctx->cm_id, addr)) {
		log_err_errno("rdma_bind_addr failed");
		return -1;
	}

	return 0;
}

static int do_accept(struct ctx *ctx)
{
	struct rdma_conn_param params = {};
	struct rdma_cm_event *event;
	int rc = 0;

	if (rdma_listen(ctx->cm_id, 1)) {
		log_err_errno("rdma_listen call failed");
		return -1;
	}


	if (rdma_get_cm_event(ctx->channel, &event)) {
		log_err_errno("rdma_get_cm_event failed");
		return -1;
	}

	if (event->event != RDMA_CM_EVENT_CONNECT_REQUEST) {
		log_error("rdma_get_cm_event returned event %s expected %s\n",
			  rdma_event_str(event->event),
			  rdma_event_str(RDMA_CM_EVENT_CONNECT_REQUEST));
		rc = -1;
		goto free_event;
	}

	rc = rdma_accept(event->id, &params);
	if (rc) {
		log_err_errno("rdma_accept call failed");
		/* cannot return until rdma_ack_cm_event call */
	} else {
		ctx->cm_id = event->id;
	}

free_event:
	/* frees event */
	if (rdma_ack_cm_event(event)) {
		log_err_errno("rdma_ack_cm_event failed for event %s",
			      rdma_event_str(event->event));
	}

	if (rc)
		return rc;

	if (get_ack_cm_op(ctx, RDMA_CM_EVENT_ESTABLISHED)) {
		log_error("Failed to accept connection with peer\n");
		return -1;
	}

	return 0;
}

static int do_connect(struct ctx *ctx)
{
	struct rdma_conn_param params = {
		//.retry_count = 7,
		//.rnr_retry_count = 7,
	};

	if (rdma_connect(ctx->cm_id, &params)) {
		log_err_errno("rdma_connect failed");
		return -1;
	}

	if (get_ack_cm_op(ctx, RDMA_CM_EVENT_ESTABLISHED)) {
		log_error("Failed to establish connection to peer\n");
		return -1;
	}

	return 0;
}

static int disconnect(struct ctx *ctx)

{
	if (rdma_disconnect(ctx->cm_id)) {
		log_err_errno("rdma_disconnect call failed");
		return -1;
	}

	if (get_ack_cm_op(ctx, RDMA_CM_EVENT_DISCONNECTED)) {
		log_error("Disconnect failed");
		return -1;
	}

	return 0;
}

static int server_init(struct ctx *ctx)
{
	if (bind_addr(ctx, ctx->laddr) ||
	    do_accept(ctx))
		return -1;

	return 0;
}

static int client_init(struct ctx *ctx, bool have_laddr)
{
	if (have_laddr) {
		if (resolve_addr(ctx, ctx->laddr, "local") ||
		    bind_addr(ctx, ctx->laddr))
			return -1;
	}

	if (resolve_addr(ctx, ctx->raddr, "remote") ||
	    resolve_route(ctx) ||
	    do_connect(ctx))
		return -1;

	return 0;
}

/* to get just a port:
 *     uint16_t rdma_get_src_port(struct rdma_cm_id *id);
 */
static void show_addr(struct ctx *ctx)
{
	/* no memory is allocated */
	struct sockaddr *sa_local = rdma_get_local_addr(ctx->cm_id);
	struct sockaddr *sa_rem = rdma_get_peer_addr(ctx->cm_id);
	char lstr[64], rstr[64];
	__u16 lport, rport;

	if (sa_local->sa_family == AF_INET) {
		struct sockaddr_in *sl = (struct sockaddr_in *)sa_local;
		struct sockaddr_in *sr = (struct sockaddr_in *)sa_rem;

		inet_ntop(AF_INET, &sl->sin_addr, lstr, sizeof(lstr)),
		lport = ntohs(sl->sin_port);

		inet_ntop(AF_INET, &sr->sin_addr, rstr, sizeof(rstr)),
		rport = ntohs(sr->sin_port);

	} else if (sa_local->sa_family == AF_INET6) {
		struct sockaddr_in6 *sl = (struct sockaddr_in6 *)sa_local;
		struct sockaddr_in6 *sr = (struct sockaddr_in6 *)sa_rem;

		inet_ntop(AF_INET6, &sl->sin6_addr, lstr, sizeof(lstr)),
		lport = ntohs(sl->sin6_port);

		inet_ntop(AF_INET6, &sr->sin6_addr, rstr, sizeof(rstr)),
		rport = ntohs(sr->sin6_port);
	} else {
		return;
	}

	log_msg("%s/%d -> %s/%d\n", lstr, lport, rstr, rport);
}

static void usage(void)
{
	log_msg("options:\n");
	log_msg("	-d name	  name of IB device\n");
	log_msg("	-l addr	  local address (required for server mode; optional for client)\n");
	log_msg("	-L port	  listen port (for server mode)\n");
	log_msg("	-r addr	  remote address (required for client mode)\n");
	log_msg("	-R port	  remote port (for client mode)\n");
	log_msg("	-s	  server mode\n");
	log_msg("\n");
}

#define GETOPT_STR "d:l:L:r:R:s"

int main(int argc, char *argv[])
{
	bool have_laddr = 0, have_raddr = 0;
	unsigned short lport = 0, rport = 0;
	const char *devname = "enf_ib_0";
	bool server_mode = 0;
	struct ctx ctx = {};
	int rc;

	extern char *optarg;

	ctx.local_addr.sin6_family = AF_INET6;
	ctx.rem_addr.sin6_family = AF_INET6;
	ctx.laddr = (struct sockaddr *)&ctx.local_addr;
	ctx.raddr = (struct sockaddr *)&ctx.rem_addr;

	while ((rc = getopt(argc, argv, GETOPT_STR)) != -1) {
		switch (rc) {
		case 'd':
			devname = optarg;
			break;
		case 'l':
			have_laddr = 1;
			rc = str_to_addr(optarg, ctx.laddr,
					 sizeof(ctx.local_addr));
			if (rc) {
				log_error("Invalid local address\n");
				goto out;
			}
			break;
		case 'L':
			rc = str_to_ushort(optarg, &lport);
			if (rc) {
				log_error("Invalid local port\n");
				goto out;
			}
			break;
		case 'r':
			have_raddr = 1;
			rc = str_to_addr(optarg, ctx.raddr,
					 sizeof(ctx.rem_addr));
			if (rc) {
				log_error("Invalid remote address\n");
				goto out;
			}
			break;
		case 'R':
			rc = str_to_ushort(optarg, &rport);
			if (rc) {
				log_error("Invalid remote port\n");
				goto out;
			}
			break;
		case 's':
			server_mode = 1;
			break;
		default:
			usage();
			return 1;
		}
	}

	rc = ctx_init(&ctx, devname);
	if (rc)
		goto out;

	rc = qp_init(&ctx);
	if (rc)
		goto err_qp_init;

	/* plays on fact that family and port are in the same
	 * location for both sockaddr_in and sockaddr_in6
	 */
	ctx.local_addr.sin6_port = htons(lport);
	ctx.rem_addr.sin6_port = htons(rport);

	rc = -1;
	if (server_mode) {
		rc = server_init(&ctx);
	} else {
		if (!have_raddr) {
			usage();
			goto out_cleanup;
		}

		rc = client_init(&ctx, have_laddr);
	}

	if (rc)
		goto out_cleanup;

	show_addr(&ctx);

	log_msg("Sleeping 5\n");
	sleep(5);

	rc = disconnect(&ctx);

out_cleanup:
	qp_cleanup(&ctx);
err_qp_init:
	ctx_cleanup(&ctx);
out:
	return rc < 0 ? 1 : 0;
}

/* other rdma calls:
 *
 * int rdma_set_option (struct rdma_cm_id *id, int level, int optname, void *optval, size_t optlen);
 *
 */
