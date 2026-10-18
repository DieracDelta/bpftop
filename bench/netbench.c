/* Loopback send/recv microbenchmark for measuring per-call overhead of
 * bpftop's network probes. Each op is one send + one recv of 64 bytes.
 * Usage: netbench <ops>  -> prints udp_ns_per_op and tcp_ns_per_op */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static double now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e9 + ts.tv_nsec;
}

static void die(const char *what)
{
	perror(what);
	exit(1);
}

static double run(int tx, int rx, long ops)
{
	char buf[64] = {0};
	double start = now_ns();
	for (long i = 0; i < ops; i++) {
		if (send(tx, buf, sizeof(buf), 0) != sizeof(buf))
			die("send");
		if (recv(rx, buf, sizeof(buf), MSG_WAITALL) != sizeof(buf))
			die("recv");
	}
	return (now_ns() - start) / ops;
}

int main(int argc, char **argv)
{
	long ops = argc > 1 ? atol(argv[1]) : 1000000;
	struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	socklen_t alen = sizeof(addr);
	int one = 1;

	int urx = socket(AF_INET, SOCK_DGRAM, 0), utx = socket(AF_INET, SOCK_DGRAM, 0);
	if (bind(urx, (void *)&addr, sizeof(addr)) || getsockname(urx, (void *)&addr, &alen) ||
	    connect(utx, (void *)&addr, sizeof(addr)))
		die("udp setup");
	printf("udp_ns_per_op=%.1f\n", run(utx, urx, ops));

	addr.sin_port = 0;
	alen = sizeof(addr);
	int lst = socket(AF_INET, SOCK_STREAM, 0), ttx = socket(AF_INET, SOCK_STREAM, 0);
	if (bind(lst, (void *)&addr, sizeof(addr)) || listen(lst, 1) ||
	    getsockname(lst, (void *)&addr, &alen) || connect(ttx, (void *)&addr, sizeof(addr)))
		die("tcp setup");
	int trx = accept(lst, NULL, NULL);
	if (trx < 0)
		die("accept");
	setsockopt(ttx, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	printf("tcp_ns_per_op=%.1f\n", run(ttx, trx, ops));
	return 0;
}
