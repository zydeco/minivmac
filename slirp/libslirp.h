#ifndef _LIBSLIRP_H
#define _LIBSLIRP_H

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
int inet_aton(const char *cp, struct in_addr *ia);

typedef HANDLE pthread_mutex_t;
typedef HANDLE pthread_t;

#define mutex_init(m) m = CreateMutex(NULL, FALSE, NULL)
#define mutex_lock(m) WaitForSingleObject(m, INFINITE)
#define mutex_unlock(m) ReleaseMutex(m)
#define mutex_destroy(m) CloseHandle(m)

#define thread_init(t, func, arg) t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)func, arg, 0, NULL)
#define thread_join(t) WaitForSingleObject(t, INFINITE)
#define thread_cancel(t) TerminateThread(t, 0)
#define thread_testcancel(t)

#else
#include <sys/select.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <assert.h>

#define mutex_init(m) pthread_mutex_init(&(m), NULL)
#define mutex_lock(m) assert(pthread_mutex_lock(&(m)) == 0)
#define mutex_unlock(m) pthread_mutex_unlock(&(m))
#define mutex_destroy(m) pthread_mutex_destroy(&(m))

#define thread_init(t, func, arg) pthread_create(&t, NULL, func, arg)
#define thread_join(t) pthread_join(t, NULL)
#define thread_cancel(t) pthread_cancel(t)
#define thread_testcancel(t) pthread_testcancel(t)

#endif

#ifdef __cplusplus
extern "C" {
#endif

int slirp_init(void);

int slirp_select_fill(int *pnfds, 
					  fd_set *readfds, fd_set *writefds, fd_set *xfds);

void slirp_select_poll(fd_set *readfds, fd_set *writefds, fd_set *xfds);

void slirp_input(const uint8 *pkt, int pkt_len);

/* you must provide the following functions: */
int slirp_can_output(void);
void slirp_output(const uint8 *pkt, int pkt_len);

int slirp_redir(int is_udp, int host_port, 
                struct in_addr guest_addr, int guest_port);
int slirp_add_exec(int do_pty, const char *args, int addr_low_byte, 
                   int guest_port);

extern const char *tftp_prefix;
extern char slirp_hostname[33];

#ifdef __cplusplus
}
#endif

#endif
