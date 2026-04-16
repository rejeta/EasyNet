#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net_common.h"
#include "threading.h"

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
    #include <time.h>
#endif

static volatile int g_running = 1;

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s -c <config.toml>\n", prog);
}

/* Phase 1 smoke test: create UDP + TCP listen, poll loop with worker thread */
static void *worker_thread(void *arg)
{
    task_queue_t *q = (task_queue_t *)arg;
    task_t task;

    printf("[worker] started\n");
    fflush(stdout);
    while (1) {
        int rc = task_queue_pop(q, &task, 100);
        if (rc == 0) {
            printf("[worker] got task type=%d session=%u len=%zu\n",
                   (int)task.type, task.session_id, task.len);
            fflush(stdout);
        }
    }
    printf("[worker] exiting\n");
    return NULL;
}

int main(int argc, char *argv[])
{
    const char *config_file = "easynet.toml";
    int i;

    /* Disable buffering so we see output even if the process crashes early */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
            if (i + 1 >= argc) {
                print_usage(argv[0]);
                return 1;
            }
            config_file = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    printf("[main] config: %s\n", config_file);

    if (net_init() != 0) {
        fprintf(stderr, "[main] net_init failed\n");
        return 1;
    }

    /* Smoke test sockets */
    socket_t udp_fd = net_udp_socket("0.0.0.0", 17000);
    if (udp_fd == NET_INVALID_SOCKET) {
        fprintf(stderr, "[main] failed to create UDP socket\n");
        net_cleanup();
        return 1;
    }

    socket_t tcp_fd = net_tcp_listen("0.0.0.0", 18080);
    if (tcp_fd == NET_INVALID_SOCKET) {
        fprintf(stderr, "[main] failed to create TCP listen socket\n");
        closesocket(udp_fd);
        net_cleanup();
        return 1;
    }

    if (net_set_nonblocking(udp_fd) != 0 || net_set_nonblocking(tcp_fd) != 0) {
        fprintf(stderr, "[main] failed to set nonblocking\n");
        closesocket(tcp_fd);
        closesocket(udp_fd);
        net_cleanup();
        return 1;
    }

    task_queue_t *q = task_queue_create();
    if (!q) {
        fprintf(stderr, "[main] failed to create task queue\n");
        closesocket(tcp_fd);
        closesocket(udp_fd);
        net_cleanup();
        return 1;
    }

    if (thread_create(worker_thread, q) != 0) {
        fprintf(stderr, "[main] failed to create worker thread\n");
        task_queue_destroy(q);
        closesocket(tcp_fd);
        closesocket(udp_fd);
        net_cleanup();
        return 1;
    }

    struct pollfd fds[2];
    fds[0].fd = udp_fd;
    fds[0].events = POLLIN;
    fds[1].fd = tcp_fd;
    fds[1].events = POLLIN;

    printf("[main] entering poll loop (Ctrl+C to exit)...\n");

    int loop_count = 0;
    while (g_running && loop_count < 100) {
        int rc = net_poll(fds, 2, 100);
        if (rc < 0) {
            fprintf(stderr, "[main] poll error\n");
            break;
        }

        /* UDP readable */
        if (fds[0].revents & POLLIN) {
            char buf[4096];
            net_addr_t from;
            int ret = recvfrom(udp_fd, buf, sizeof(buf), 0,
                               (struct sockaddr *)&from.ss, &from.len);
            if (ret > 0) {
                char addrbuf[64];
                printf("[main] UDP recv %d bytes from %s\n",
                       ret, net_addr_str(&from, addrbuf, sizeof(addrbuf)));
                task_t task;
                memset(&task, 0, sizeof(task));
                task.type = TASK_ENCRYPT_AND_SEND;
                task.session_id = 0;
                task.len = (size_t)ret;
                if (task.len > sizeof(task.data)) task.len = sizeof(task.data);
                memcpy(task.data, buf, task.len);
                task.udp_dest = from;
                task_queue_push(q, &task);
            }
        }

        /* TCP accept */
        if (fds[1].revents & POLLIN) {
            net_addr_t client_addr;
            socket_t client_fd = accept(tcp_fd, (struct sockaddr *)&client_addr.ss, &client_addr.len);
            if (client_fd != NET_INVALID_SOCKET) {
                char addrbuf[64];
                printf("[main] TCP accepted from %s\n",
                       net_addr_str(&client_addr, addrbuf, sizeof(addrbuf)));
                closesocket(client_fd);
            }
        }

        loop_count++;
    }

    printf("[main] exiting poll loop\n");

    task_queue_set_exit(q);
    /* Give worker a moment to see exit flag. In real code we'd join the thread. */
#ifdef _WIN32
    Sleep(200);
#else
    struct timespec ts = {0, 200000000L};
    nanosleep(&ts, NULL);
#endif

    task_queue_destroy(q);
    closesocket(tcp_fd);
    closesocket(udp_fd);
    net_cleanup();
    return 0;
}
