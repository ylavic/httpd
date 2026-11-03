/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * This MPM tries to fix the 'keep alive problem' in HTTP.
 *
 * After a client completes the first request, the client can keep the
 * connection open to send more requests with the same socket.  This can save
 * significant overhead in creating TCP connections.  However, the major
 * disadvantage is that Apache traditionally keeps an entire child
 * process/thread waiting for data from the client.  To solve this problem,
 * this MPM has a dedicated thread for handling both the Listening sockets,
 * and all sockets that are in a Keep Alive status.
 *
 * The MPM assumes the underlying apr_pollset implementation is somewhat
 * threadsafe.  This currently is only compatible with KQueue and EPoll.  This
 * enables the MPM to avoid extra high level locking or having to wake up the
 * listener thread when a keep-alive socket needs to be sent to it.
 *
 * This MPM does not perform well on older platforms that do not have very good
 * threading, like Linux with a 2.4 kernel, but this does not matter, since we
 * require EPoll or KQueue.
 *
 * For FreeBSD, use 5.3.  It is possible to run this MPM on FreeBSD 5.2.1, if
 * you use libkse (see `man libmap.conf`).
 *
 * For NetBSD, use at least 2.0.
 *
 * For Linux, you should use a 2.6 kernel, and make sure your glibc has epoll
 * support compiled in.
 *
 */

#include "apr.h"
#include "apr_portable.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_thread_proc.h"
#include "apr_signal.h"
#include "apr_thread_mutex.h"
#include "apr_poll.h"
#include "apr_ring.h"
#include "apr_queue.h"
#include "apr_atomic.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_version.h"

#include <stdlib.h>

#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif
#if APR_HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if APR_HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef HAVE_SYS_PROCESSOR_H
#include <sys/processor.h>      /* for bindprocessor() */
#endif
#ifdef HAVE_TIME_H
#include <time.h>               /* for clock_gettime() */
#endif

#if !APR_HAS_THREADS
#error The Event MPM requires APR threads, but they are unavailable.
#endif

#include "ap_config.h"
#include "httpd.h"
#include "http_main.h"
#include "http_log.h"
#include "http_config.h"        /* for read_config */
#include "http_core.h"          /* for get_remote_host */
#include "http_connection.h"
#include "http_protocol.h"
#include "ap_mpm.h"
#include "mpm_common.h"
#include "ap_listen.h"
#include "scoreboard.h"
#include "mpm_fdqueue.h"
#include "mpm_default.h"
#include "http_vhost.h"
#include "unixd.h"
#include "apr_skiplist.h"
#include "util_time.h"

#include <signal.h>
#include <limits.h>             /* for INT_MAX */
#ifdef HAVE_SCHED_GETAFFINITY
#include <sched.h>              /* for sched_getaffinity() */
#endif
#if defined(HAVE_GETRUSAGE) && defined(HAVE_SYS_RESOURCE_H)
#include <sys/time.h>
#include <sys/resource.h>       /* for getrusage() */
#define EVENT_ELASTIC_THREADS 1
/* Where getrusage() fills the context switches too (POSIX only has the times) */
#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) \
    || defined(__OpenBSD__) || defined(__DragonFly__) || defined(__sun)
#define EVENT_RUSAGE_CSW 1
#endif
#endif


#if HAVE_SERF
#include "mod_serf.h"
#include "serf.h"
#endif

/* Limit on the total --- clients will be locked out if more servers than
 * this are needed.  It is intended solely to keep the server from crashing
 * when things get out of hand.
 *
 * We keep a hard maximum number of servers, for two reasons --- first off,
 * in case something goes seriously wrong, we want to stop the fork bomb
 * short of actually crashing the machine we're running on by filling some
 * kernel table.  Secondly, it keeps the size of the scoreboard file small
 * enough that we can read the whole thing without worrying too much about
 * the overhead.
 */
#ifndef DEFAULT_SERVER_LIMIT
#define DEFAULT_SERVER_LIMIT 16
#endif

/* Admin can't tune ServerLimit beyond MAX_SERVER_LIMIT.  We want
 * some sort of compile-time limit to help catch typos.
 */
#ifndef MAX_SERVER_LIMIT
#define MAX_SERVER_LIMIT 20000
#endif

/* Limit on the threads per process.  Clients will be locked out if more than
 * this are needed.
 *
 * We keep this for one reason it keeps the size of the scoreboard file small
 * enough that we can read the whole thing without worrying too much about
 * the overhead.
 */
#ifndef DEFAULT_THREAD_LIMIT
#define DEFAULT_THREAD_LIMIT 64
#endif

/* Admin can't tune ThreadLimit beyond MAX_THREAD_LIMIT.  We want
 * some sort of compile-time limit to help catch typos.
 */
#ifndef MAX_THREAD_LIMIT
#define MAX_THREAD_LIMIT 100000
#endif

/* The admission's backstop (AsyncAdmissionBacklogPerThread): how many new
 * connections can wait for a worker, per worker thread. From 16 the waiting
 * time decides when to stop accepting, even under a flood of new connections
 * (for requests of about a millisecond or more; below, the backstop does first
 * and only toggles the accepting more often), while what a child holds for
 * them stays cheap: a pool and a socket each (e.g. 400 for 25 threads).
 */
#ifndef DEFAULT_ADMISSION_BACKLOG
#define DEFAULT_ADMISSION_BACKLOG 16.0
#endif

/* MaxRequestWorkers auto: the threads per child (one on a single CPU), and the
 * client connections a child can hold from its descriptors limit: what's left
 * after AUTO_FDS_RESERVE (logs, modules' files...) and the listeners, at
 * AUTO_FDS_PER_CLIENT descriptors per client (a proxied client holds its
 * backend connection too).
 */
#ifndef AUTO_THREADS_PER_CHILD
#define AUTO_THREADS_PER_CHILD 2
#endif
#ifndef AUTO_FDS_RESERVE
#define AUTO_FDS_RESERVE 64
#endif
#ifndef AUTO_FDS_PER_CLIENT
#define AUTO_FDS_PER_CLIENT 2
#endif
/* An unlimited (or huge) descriptors limit counts as this many */
#ifndef AUTO_FDS_MAX
#define AUTO_FDS_MAX (1 << 24)
#endif
/* The derived ThreadLimit (auto) at most */
#ifndef AUTO_THREAD_LIMIT_MAX
#define AUTO_THREAD_LIMIT_MAX 1024
#endif
/* An extra worker (auto) idle for this long exits, checking every
 * WORKER_IDLE_TIMEOUT
 */
#ifndef AUTO_WORKER_RETIRE_TIMEOUT
#define AUTO_WORKER_RETIRE_TIMEOUT apr_time_from_sec(10)
#endif
#define WORKER_IDLE_TIMEOUT apr_time_from_sec(1)

#ifndef SCOREBOARD_DAEMONS_FACTOR
#define SCOREBOARD_DAEMONS_FACTOR 4
#endif

#define MPM_CHILD_PID(i) (ap_scoreboard_image->parent[i].pid)

#if !APR_VERSION_AT_LEAST(1,4,0)
#define apr_time_from_msec(x) ((x) * 1000)
#endif

/* Lingering close: wait for the client to close for LINGER_READ_TIMEOUT at
 * most between two reads, and MAX_SECS_TO_LINGER at most in total, or
 * SECONDS_TO_LINGER with the "short-lingering-close" note (e.g. a timed out
 * connection) or when the child is dying (see linger_expired()). Read at
 * most LINGER_READS_PER_PASS times LINGERING_BUF_SIZE bytes per pass, then
 * requeue, so that a client sending as fast as a worker reads doesn't hold
 * it.
 */
#ifndef MAX_SECS_TO_LINGER
#define MAX_SECS_TO_LINGER 30
#endif
#define SECONDS_TO_LINGER  2
#define LINGER_READ_TIMEOUT     apr_time_from_sec(SECONDS_TO_LINGER)
#define LINGER_READS_PER_PASS   4

/* Shrink linger_q at this period (min) while the connections are full */
#define QUEUES_SHRINK_TIMEOUT   apr_time_from_msec(500)

/* Update scoreboard stats at this period */
#define STATS_UPDATE_TIMEOUT    apr_time_from_msec(1000)

/* While not accepting for the limits, re-check them at this period: a
 * backstop against a lost wake only, the workers and the closes waking up
 * the listener when it should accept again.
 */
#define ACCEPT_RECHECK_TIMEOUT  apr_time_from_sec(1)

/* Prevent extra poll/wakeup calls for timeouts close in the future (queues
 * have the granularity of a second anyway).
 * XXX: Wouldn't 0.5s (instead of 0.1s) be "enough"?
 */
#define QUEUES_FUDGE_TIMEOUT    apr_time_from_msec(100)

/* Same goal as for QUEUES_FUDGE_TIMEOUT, but applied to timers.
 * XXX: Since their timeouts are custom (user defined), we can't be too
 * approximative here (using 5ms).
 */
#define TIMERS_FUDGE_TIMEOUT    apr_time_from_msec(5)

/*
 * Actual definitions of config globals
 */

static int threads_per_child = 0;           /* ThreadsPerChild */
static int ap_daemons_to_start = 0;         /* StartServers */
static int min_spare_threads = 0;           /* MinSpareThreads */
static int max_spare_threads = 0;           /* MaxSpareThreads */
static int active_daemons_limit = 0;        /* MaxRequestWorkers / ThreadsPerChild */
static int max_workers = 0;                 /* MaxRequestWorkers */
static int server_limit = 0;                /* ServerLimit */
static int thread_limit = 0;                /* ThreadLimit */
static int conns_this_child = 0;            /* MaxConnectionsPerChild, only accessed
                                               in listener thread */
static double admission_backlog = DEFAULT_ADMISSION_BACKLOG; /* AsyncAdmissionBacklogPerThread */
#ifndef AP_EVENT_WORKER_POLLERS
#define AP_EVENT_WORKER_POLLERS 0           /* auto */
#endif
static int worker_pollers = AP_EVENT_WORKER_POLLERS; /* AsyncWorkerPollers,
                                                       0 for auto */

/* Idle workers poll the connections themselves (worker_poll_next()): needs
 * one-shot pfds and APR to poll a pollset from several threads. Building with
 * AP_EVENT_NO_WORKER_POLL defined disables it: the listener then polls
 * everything, in a single pollset.
 */
#if !defined(AP_EVENT_NO_WORKER_POLL) \
    && defined(HAVE_APR_POLLSET_POLL_INTO) \
    && defined(APR_POLLONESHOT)
#define EVENT_WORKER_POLL 1
#endif
static int worker_poll; /* set before the threads start, then constant */

static int auto_settings = 0;               /* MaxRequestWorkers auto: settings
                                               derived from max_client_conns and
                                               num_cpus */
static int max_client_conns = 0;            /* The client connections to hold
                                               (auto), derived if 0 */
static int clients_per_child = 0;           /* The client connections a
                                               child's descriptors can hold
                                               (auto) */
static apr_uint32_t clients_share = 0;      /* The client connections a
                                               child accepts at most (auto),
                                               0 for no limit */
/* The settings set explicitly, that auto doesn't derive */
#define AUTO_SET_SERVER_LIMIT   (1u << 0)
#define AUTO_SET_THREAD_LIMIT   (1u << 1)
static unsigned int auto_set_flags = 0;

static int num_cpus = 0;                    /* Number of CPUs usable (the
                                               affinity where known, else
                                               the online ones) */

static int workers_backlog_limit = 0;       /* Max number of events in the workers' backlog
                                               (above which not accepting new connections) */

/* Elastic worker threads (auto, needs getrusage()): a child starts its base
 * workers (threads_per_child) and grows extra ones while they're all blocked,
 * up to threads_max (ThreadLimit), an extra one exiting once idle for
 * AUTO_WORKER_RETIRE_TIMEOUT (workers_grow_check(), worker_thread()).
 * Without, threads_max is threads_per_child.
 */
static int elastic_threads = 0;
static int threads_max = 0;
static /*atomic*/ apr_uint32_t workers_live;    /* running worker threads */
static /*atomic*/ apr_uint32_t workers_retired; /* extra ones that exited (stats) */
static /*atomic*/ apr_uint32_t workers_unjoined; /* retired, not joined yet */

/* When the listener last saw no idle worker (written by the listener only),
 * and the second the last extra worker retired since (see worker_unneeded())
 */
static volatile apr_time_t workers_last_short;
static /*atomic*/ apr_uint32_t workers_retire_sec;

static apr_thread_t **worker_threads;           /* [threads_max] */
static apr_pool_t **worker_thread_pools;        /* [threads_max], the extra ones' */
static apr_threadattr_t *worker_thread_attr;

static /*atomic*/ apr_uint32_t dying = 0;
static /*atomic*/ apr_uint32_t workers_may_exit = 0;
static /*atomic*/ apr_uint32_t start_thread_may_exit = 0;
static /*atomic*/ apr_uint32_t listener_may_exit = 0;

/* The size of a cache line, to keep what a thread writes often away from what
 * the others read (false sharing).
 */
#define CACHE_LINE_SIZE 64

/* On the first member of a struct, aligns it on a cache line and rounds its
 * size up to whole lines, so that nothing else shares them. Without compiler
 * support the struct is laid out as usual (only the isolation is lost).
 */
#if defined(__GNUC__) || defined(__clang__) || defined(__IBMC__) \
    || defined(__xlc__) || defined(__SUNPRO_C)
#define CACHE_LINE_ALIGNED __attribute__((aligned(CACHE_LINE_SIZE)))
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define CACHE_LINE_ALIGNED _Alignas(CACHE_LINE_SIZE)
#else
#define CACHE_LINE_ALIGNED
#endif

/* Counters written by any thread at every connection, timer and suspend, in a
 * cache line of their own: not with the flags and settings above, read by all
 * the threads.
 */
static struct {
    CACHE_LINE_ALIGNED
    /*atomic*/ apr_uint32_t connection_count; /* Number of open connections */
    /*atomic*/ apr_uint32_t timers_count;     /* Number of queued timers */
    /*atomic*/ apr_uint32_t suspended_count;  /* Number of suspended connections */
} event_counts;

static /*atomic*/ apr_uint32_t threads_shutdown = 0; /* Number of threads that have shutdown
                                                        early during graceful termination */

static int had_healthy_child = 0;
static int resource_shortage = 0;

static fd_queue_t *worker_queue;
static fd_queue_info_t *worker_queue_info;

static int num_listensocks = 0;
static apr_pollfd_t *listener_pollfd;

module AP_MODULE_DECLARE_DATA mpm_event_module;

/* Rate limiting of the log lines that can fire per event (see the sites
 * using it): at most one line per second per call site and child at the
 * site's level, the next one preceded by how many were suppressed since;
 * every line at trace7. The state of a site is written by the listener only
 * (shared 0, plain variables) or by any thread (atomics).
 */
typedef struct {
    apr_uint32_t sec;        /* the second of the last line logged (+1) */
    apr_uint32_t suppressed; /* lines not logged since */
} log_ratelimit_t;

static int log_ratelimit(log_ratelimit_t *rl, int level, int shared,
                         const server_rec *s, const conn_rec *c,
                         const char *file, int line, int module_index)
{
    apr_uint32_t sec, last, suppressed;

    if (c ? !APLOG_C_IS_LEVEL(c, level) : !APLOG_IS_LEVEL(s, level)) {
        return 0;
    }
    if (c ? APLOG_C_IS_LEVEL(c, APLOG_TRACE7) : APLOG_IS_LEVEL(s, APLOG_TRACE7)) {
        return 1;
    }
    sec = (apr_uint32_t)apr_time_sec(apr_time_now()) + 1;
    if (!shared) {
        last = rl->sec;
        if (last == sec) {
            rl->suppressed++;
            return 0;
        }
        rl->sec = sec;
        suppressed = rl->suppressed;
        rl->suppressed = 0;
    }
    else {
        last = apr_atomic_read32(&rl->sec);
        if (last == sec || apr_atomic_cas32(&rl->sec, sec, last) != last) {
            apr_atomic_inc32(&rl->suppressed);
            return 0;
        }
        suppressed = apr_atomic_xchg32(&rl->suppressed, 0);
    }
    if (suppressed) {
        if (c) {
            ap_log_cerror_(file, line, module_index, level, 0, c,
                           "%u lines like the next one suppressed in %us",
                           suppressed, sec - last);
        }
        else {
            ap_log_error_(file, line, module_index, level, 0, s,
                          "%u lines like the next one suppressed in %us",
                          suppressed, sec - last);
        }
    }
    return 1;
}
#define LOG_RATELIMIT(rl, level, shared, s, c) \
    log_ratelimit(rl, level, shared, s, c, APLOG_MARK)

/* forward declare */
struct event_srv_cfg_s;
typedef struct event_srv_cfg_s event_srv_cfg;

struct timeout_queue;

/* An entry of a timeout queue (TO_QUEUE_APPEND()), in what it times out */
struct timeout_entry {
    APR_RING_ENTRY(timeout_entry) link;
    struct timeout_queue *q; /* its queue, while in there */
    apr_time_t queued;       /* when it was appended */
    void *owner;             /* what it times out (TO_ENTRY_*()), set once */
};

struct user_wait;

/*
 * The pollset for sockets that are in any of the timeout queues. Currently
 * we use conn_queues.mutex to make sure that connections are added/removed
 * atomically to/from both event_pollset and a timeout queue. Otherwise
 * some confusion can happen under high load if timeout queues and pollset
 * get out of sync.
 * XXX: It should be possible to make the lock unnecessary in many or even all
 * XXX: cases.
 */
static apr_pollset_t *event_pollset;

/* The pollset of the connections and the waits' pfds: event_pollset itself
 * when the listener polls everything, or a pollset of its own with worker_poll,
 * polled by the idle workers (one blocked there is woken up by ring_doorbell()
 * when something is queued for it).
 */
static apr_pollset_t *conn_pollset;
#ifdef EVENT_WORKER_POLL
static void ring_doorbell(void);
static APR_INLINE int workers_parked(void);
#else
#define ring_doorbell() ((void)0)
#define workers_parked() 0
#endif
#define POLLSET_RESERVE_SIZE 10000

/* The pollset methods event uses: they hold any number of descriptors and
 * support APR_POLLSET_THREADSAFE (event is built only where one exists).
 */
static const apr_pollset_method_e good_methods[] = { APR_POLLSET_PORT,
                                                     APR_POLLSET_KQUEUE,
                                                     APR_POLLSET_EPOLL };
#define NUM_GOOD_METHODS (sizeof(good_methods) / sizeof(good_methods[0]))

/* Create a pollset with the first good method that works (flags should
 * include APR_POLLSET_NODEFAULT), the last error if none does.
 */
static apr_status_t pollset_create_good(apr_pollset_t **ps, apr_uint32_t size,
                                        apr_pool_t *p, apr_uint32_t flags)
{
    apr_status_t rv = APR_ENOTIMPL;
    int i;

    for (i = 0; i < NUM_GOOD_METHODS; i++) {
        rv = apr_pollset_create_ex(ps, size, p, flags, good_methods[i]);
        if (rv == APR_SUCCESS) {
            break;
        }
    }
    return rv;
}

struct backlog_timer_event {
    timer_event_t te;
    ap_queue_event_t qe;
};
#define te_qe(te) (&((struct backlog_timer_event *)(te))->qe)
#define te_in_backlog(te) (te_qe(te)->cb != NULL)

/* A module's continuation (ap_mpm_register_wait()) and its arguments:
 * fn and baton as registered (user_wait->continuation), pfds and why once its
 * wait fired (cs->continuation, see run_user_continuation()).
 */
struct user_continuation {
    ap_mpm_continuation_fn_t *fn;
    void *baton;
    apr_array_header_t *pfds;
    ap_mpm_wait_result_e why;
};

/* The kept pfds of a connection (a tunnel keeps 2) */
#define EVENT_KEPT_MAX 4
struct kept_pfd;

typedef struct event_conn_state_t event_conn_state_t;
struct event_conn_state_t {
    /** the entry in its timeout queue (to.q), if any */
    struct timeout_entry to;
    /** public parts of the connection state */
    conn_state_t pub;
    /** memory pool allocated on and to allocate from (ptrans) */
    apr_pool_t *p;
    /** connection record this struct refers to */
    conn_rec *c;
    /** request record (if any) this struct refers to */
    request_rec *r;
    /** server config this struct refers to */
    event_srv_cfg *sc;
    /** server config this struct refers to during keepalive */
    event_srv_cfg *ka_sc;
    /** scoreboard handle for the conn_rec */
    ap_sb_handle_t *sbh;
    /** bucket allocator */
    apr_bucket_alloc_t *bucket_alloc;

    /*
     * when queued to the listener
     */
    /** poll file descriptor information */
    apr_pollfd_t pfd;
    /** the timer event for this entry */
    timer_event_t *te;
    /** user pollfds (for suspended connection) */
    struct user_wait *user_wait;
    /** a wait (ap_mpm_register_wait()) to arm once no thread runs the
     *  connection anymore */
    struct user_wait *pending_wait;
    /** the connection's wait (cs->p), reused by all its waits so that a
     *  fired event's pfd/pt/wait stay valid as long as the connection;
     *  user_wait/pending_wait point to it */
    struct user_wait *wait;
    /** the continuation to run (continuation.fn set), once its wait fired */
    struct user_continuation continuation;
    /** the pfds kept registered across the waits (AP_MPM_WAIT_KEEP_PFDS),
     *  in cs->p, until released */
    struct kept_pfd *kept[EVENT_KEPT_MAX];
    int nkept;
    /** the released ones, to reuse once their drain epoch passed (FIFO) */
    APR_RING_HEAD(kept_pfd_ring, kept_pfd) kept_free;

    /*
     * when queued to workers
     */
    /** the backlog event for this entry */
    struct backlog_socket_event {
        sock_event_t se;
        ap_queue_event_t qe;
        struct timeout_queue *q;
    } bse;
    /** the next one in the listener's timed out connections (backlog,
     *  shutdown or linger queue) */
    event_conn_state_t *bl_timed_out_next;

    /*
     * bools as bits
     */
    unsigned int
        /** Is the current conn_rec suspended?  (disassociated with
         *  a particular MPM thread; for suspend_/resume_connection
         *  hooks)
         */
        suspended       :1,
        /** Is a continuation (continuation.fn) running? */
        in_continuation :1,
        /** Did the running continuation give the conn back? */
        continuation_pending :1,
        /** Has ap_start_lingering_close() been called? */
        linger_started  :1,
        /** Is lingering connection flushed and shutdown? */
        linger_shutdown :1,
        /** Shorter lingering close ("short-lingering-close")? */
        linger_short    :1,
        /** Counted out already (connection_count_out())? */
        counted_out     :1;
    /** Since when lingering (the shutdown, or the timeout that started it) */
    apr_time_t linger_since;
};
#define cs_se(cs) (&(cs)->bse.se)
#define cs_qe(cs) (&(cs)->bse.qe)
#define cs_in_backlog(cs) (cs_qe(cs)->cb != NULL)
/* The connection of a timeout queue's entry */
#define TO_ENTRY_CS(e) ((event_conn_state_t *)(e)->owner)

static APR_INLINE apr_socket_t *cs_sd(event_conn_state_t *cs)
{
    ap_assert(cs != NULL);
    return cs->pfd.desc.s;
}
static APR_INLINE int cs_fd(event_conn_state_t *cs)
{
    apr_os_sock_t fd = -1;
    apr_os_sock_get(&fd, cs_sd(cs));
    return fd;
}
static APR_INLINE apr_sockaddr_t *cs_raddr(event_conn_state_t *cs)
{
    apr_sockaddr_t *addr = NULL;
    apr_socket_addr_get(&addr, APR_REMOTE, cs_sd(cs));
    return addr;
}
static APR_INLINE const char *cs_state_str(event_conn_state_t *cs)
{
    switch (cs->pub.state) {
    case CONN_STATE_PROCESSING:
        return "STATE_PROCESSING";
    case CONN_STATE_HANDLER:
        return "STATE_HANDLER";
    case CONN_STATE_ASYNC_WAITIO:
        return "STATE_ASYNC_WAITIO";
    case CONN_STATE_WRITE_COMPLETION:
        return "STATE_WRITE_COMPLETION";
    case CONN_STATE_KEEPALIVE:
        return "STATE_KEEPALIVE";
    case CONN_STATE_LINGER:
    case CONN_STATE_LINGER_NORMAL:
    case CONN_STATE_LINGER_SHORT:
        return "STATE_LINGER";
    case CONN_STATE_SUSPENDED:
        return "STATE_SUSPENDED";
    default:
        return "STATE_UNKNOWN";
    }
}
#define CS_FMT          "pp:%s:%i"
#define CS_ARG(cs)      (cs), cs_state_str(cs), cs_fd(cs)
#define CS_FMT_TO       CS_FMT " to [%pI]"
#define CS_ARG_TO(cs)   CS_ARG(cs), cs_raddr(cs)

/* A monotonic timestamp: CLOCK_MONOTONIC (POSIX, also macOS >= 10.12) is the
 * clock the kernel times the poll timeouts with, NTP never makes it jump (it
 * only slews its rate), and it's fast (vDSO) where it matters.
 */
static apr_time_t event_time_now(void)
{
#if HAVE_CLOCK_GETTIME && defined(CLOCK_MONOTONIC)
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return apr_time_from_sec(ts.tv_sec) + ts.tv_nsec / 1000;
#else
    /* XXX: not monotonic, still some platform to care about? */
    return apr_time_now();
#endif
}

APR_RING_HEAD(timeout_head_t, timeout_entry);

/* Timeout queues sharing a mutex (for their entries and counts) and a next
 * expiry (the earliest of their first entries' expiries, for the listener's
 * poll()ing timeout), which an append lowers only past the fudge so as not to
 * wake up the listener for close timeouts. The backlog queues are protected
 * by the worker_queue's lock instead (and the mutex too for their
 * expiry, see listener_thread()).
 */
struct timeout_queues {
    apr_thread_mutex_t *mutex;
    volatile apr_time_t next_expiry;
    apr_interval_time_t fudge;
};

struct timeout_queue {
    struct timeout_head_t head;
    apr_interval_time_t timeout;
    apr_uint32_t count;         /* for this queue */
    apr_uint32_t *total;        /* for all chained/related queues */
    const char *name;           /* for logging */
    struct timeout_queue *next; /* chaining */
    struct timeout_queues *qs;  /* its mutex and next expiry */
};

/*
 * Several timeout queues that use different timeouts, so that we always can
 * simply append to the end.
 *   waitio_q           uses vhost's TimeOut
 *   write_completion_q uses vhost's TimeOut
 *   keepalive_q        uses vhost's KeepAliveTimeOut
 *   shutdown_q         uses vhost's TimeOut
 *   linger_q           uses LINGER_READ_TIMEOUT
 *   backlog_q          no timeout (backlog_conn_q, the admission bounds how
 *                      many wait and how long), LINGER_READ_TIMEOUT for the
 *                      lingering connections (backlog_linger_q, chained)
 * A queue whose timeout is negative has none: its entries never expire, it's
 * only walked to shrink it.
 */
static struct timeout_queue *waitio_q,           /* wait for I/O to happen */
                            *write_completion_q, /* completion or user async poll */
                            *keepalive_q,        /* in between requests */
                            *shutdown_q,         /* shutting down (write) before close */
                            *linger_q,           /* lingering (read) before close */
                            *backlog_q,          /* waiting for a worker */
                            *backlog_conn_q,     /* not lingering (no timeout) */
                            *backlog_linger_q;   /* lingering, waiting for a worker */
/* The connections' queues, their mutex and next expiry */
static struct timeout_queues conn_queues = { NULL, 0, QUEUES_FUDGE_TIMEOUT };

/*
 * Macros for accessing struct timeout_queue.
 * For TO_QUEUE_APPEND and TO_QUEUE_REMOVE, q->qs->mutex must be held.
 * TO_QUEUE_APPEND returns whether the listener has to be woken up to update
 * its poll()ing timeout, for the caller to do it once the mutex released
 * (wakeup_listener()).
 */
#define TO_QUEUE_EXPIRY(q, e) ((e)->queued + (q)->timeout)
#define TO_QUEUE_EXPIRES(q) ((q)->timeout >= 0)

/* Lower the next expiry of q's queues to an entry's expiry if it's earlier,
 * past the fudge, returning whether it was lowered.
 */
static APR_INLINE int TO_QUEUE_NEXT_EXPIRY(struct timeout_queue *q,
                                           apr_time_t elem_expiry)
{
    apr_time_t next_expiry = q->qs->next_expiry;
    if (!next_expiry || next_expiry > elem_expiry + q->qs->fudge) {
        q->qs->next_expiry = elem_expiry;
        return 1;
    }
    return 0;
}

static int TO_QUEUE_APPEND(struct timeout_queue *q, struct timeout_entry *e)
{
    /* It greatly simplifies the logic to use a single timeout value per q
     * because the new element can just be added to the end of the list and
     * it will stay sorted in expiration time sequence.  If brand new
     * sockets are sent to the event thread for a readability check, this
     * will be a slight behavior change - they use the non-keepalive
     * timeout today.  With a normal client, the socket will be readable in
     * a few milliseconds anyway.
     */

    ap_assert(q && !e->q);

    e->q = q;
    e->queued = event_time_now();
    APR_RING_INSERT_TAIL(&q->head, e, timeout_entry, link);
    ++q->count;

    /* Use atomic_set to be ordered/consistent with potential atomic reads
     * outside the critical section, but writes are protected so a more
     * expensive atomic_inc is not needed.
     */
    apr_atomic_set32(q->total, *q->total + 1);

    /* Cheaply update the next expiry of the queues with the one of the
     * first entry of this queue (oldest) if it expires before.
     */
    if (!TO_QUEUE_EXPIRES(q)) {
        return 0;
    }
    e = APR_RING_FIRST(&q->head);
    return TO_QUEUE_NEXT_EXPIRY(q, TO_QUEUE_EXPIRY(q, e));
}

static void TO_QUEUE_REMOVE(struct timeout_queue *q, struct timeout_entry *e)
{
    ap_assert(q && e->q == q);
    e->q = NULL;

    APR_RING_REMOVE(e, link);
    APR_RING_ELEM_INIT(e, link);
    --q->count;

    /* Use atomic_set to be ordered/consistent with potential atomic reads
     * outside the critical section, but writes are protected so a more
     * expensive atomic_dec is not needed.
     */
    apr_atomic_set32(q->total, *q->total - 1);
}

static struct timeout_queue *TO_QUEUE_MAKE(apr_pool_t *p,
                                           struct timeout_queues *qs,
                                           const char *name,
                                           apr_interval_time_t t,
                                           struct timeout_queue *ref)
{
    struct timeout_queue *q;

    q = apr_pcalloc(p, sizeof *q);
    APR_RING_INIT(&q->head, timeout_entry, link);
    q->total = (ref) ? ref->total : apr_pcalloc(p, sizeof *q->total);
    q->timeout = t;
    q->name = name;
    q->qs = qs;

    return q;
}

static struct timeout_queue *TO_QUEUE_CHAIN(apr_pool_t *p,
                                            struct timeout_queues *qs,
                                            const char *name,
                                            apr_interval_time_t t,
                                            struct timeout_queue **ref,
                                            apr_hash_t *ht, apr_pool_t *hp)
{
    struct timeout_queue *q = apr_hash_get(ht, &t, sizeof t);

    if (!q) {
        q = TO_QUEUE_MAKE(p, qs, name, t, *ref);
        q->next = *ref;
        *ref = q;

        apr_hash_set(ht, apr_pmemdup(hp, &t, sizeof t), sizeof t, q);
    }

    return q;
}

#if HAVE_SERF
typedef struct {
    apr_pollset_t *pollset;
    apr_pool_t *pool;
} s_baton_t;

static serf_context_t *g_serf;
#endif

/* The structure used to pass unique initialization info to each thread */
typedef struct
{
    int pslot;  /* process slot */
    int tslot;  /* worker slot of the thread */
} proc_info;

/* Structure used to pass information to the thread responsible for
 * creating the rest of the threads.
 */
typedef struct
{
    apr_thread_t **threads;
    apr_thread_t *listener;
    int child_num_arg;
    apr_threadattr_t *threadattr;
} thread_starter;

typedef enum
{
    PT_CSD,
    PT_ACCEPT,
#if HAVE_SERF
    PT_SERF,
#endif
    PT_USER,
    PT_QUEUE,  /* the doorbell (worker_poll) */
    PT_KEPT    /* a kept pfd (AP_MPM_WAIT_KEEP_PFDS) */
} poll_type_e;

typedef struct
{
    poll_type_e type;
    void *baton;
} listener_poll_type;

/* A wait: registered by a module (ap_mpm_register_wait()) for a SUSPENDED
 * connection, on pfds, a timeout and a notifier, the first to fire completes
 * it (claim_user_wait()), then a worker runs the module's continuation
 * (struct user_continuation). Modules only see the registration and the
 * continuation; the wait's states and the kept pfds are the MPM's.
 */

/* The claim state of a wait (user_wait->claim): an armed wait is completed
 * by the first thread to CAS it to WAIT_CLAIMED (claim_user_wait()),
 * whatever completes it (a fired pfd, its timer, its notifier).
 */
#define WAIT_IDLE    0u
#define WAIT_ARMED   1u
#define WAIT_CLAIMED 2u

struct user_wait {
    apr_pool_t *pool; /* the registrant's (cleanup registered there) */
    event_conn_state_t *cs;
    apr_array_header_t *pfds; /* pfds_buf[pfds_cur] */
    apr_array_header_t *pfds_buf[2]; /* alternated by the waits (cs->p) */
    unsigned int pfds_cur;
    listener_poll_type pt_buf[2]; /* pfds_buf[i]'s client_data, so that an
                                   * event fired for the previous wait is
                                   * told apart (stale_user_wait()) */
    /*atomic*/ apr_uint32_t claim; /* WAIT_* */
    apr_thread_mutex_t *mutex; /* pfds added/removed atomically */
    timer_event_t *timer; /* the timer of its timeout if any, unless queued
                           * (to), also cs->te */
    struct timeout_entry to; /* in its timeout queue (to.q) while there,
                              * under wait_queues.mutex */
    struct timeout_queue *tq; /* the timeout queue it's armed in rather than
                               * a timer, written only by the arming thread
                               * before its pfds and notifier are armed (no
                               * other claimer then) and by the claim's
                               * winner */
    struct user_wait *expired_next; /* in the listener's expired waits */
    struct user_wait *next; /* chaining */
    int chained; /* in the listener's user_chain (next may be NULL there) */
    apr_interval_time_t timeout; /* the timeout to arm with */
    struct user_continuation continuation; /* fn and baton (ap_mpm_register_wait()), if any */
    ap_mpm_notifier_t *notifier; /* the wait's notifier, if any */
    int wait_notified; /* completes with AP_MPM_WAIT_NOTIFIED (listener only) */
    int keep; /* keep its pfds registered (AP_MPM_WAIT_KEEP_PFDS) */
    int drained; /* its user drained the pfds (AP_MPM_WAIT_DRAINED) */
};
/* The wait of a timeout queue's entry */
#define TO_ENTRY_WAIT(e) ((struct user_wait *)(e)->owner)

/* A pfd kept registered in conn_pollset across the waits of a connection
 * (AP_MPM_WAIT_KEEP_PFDS), until released (ap_mpm_release_pfd(), or the
 * connection resumed or closed): one-shot, so only the one that fired needs to
 * be re-armed for the next wait, and a readiness while no wait is on it
 * is remembered rather than lost. Its state is
 * changed by CAS between the events (any thread) and the waits of its
 * connection (one thread at a time), but for the re-arm (a plain set: it is
 * disarmed or not registered then, or an event racing the set fires again
 * after the re-arm):
 *   KEPT_IDLE   -> KEPT_WAITED: a wait is on it, still armed (no syscall)
 *   KEPT_WAITED -> KEPT_FIRED:  an event for the wait, disarmed (one-shot)
 *   KEPT_WAITED -> KEPT_IDLE:   the wait completed otherwise, still armed
 *   KEPT_IDLE   -> KEPT_READY:  an event while no wait is on it, disarmed
 *   KEPT_FIRED  -> KEPT_READY:  an event for a wait completed otherwise
 *   KEPT_READY, KEPT_FIRED, KEPT_NEW -> KEPT_WAITED: re-armed (or added) for
 *                               the next wait, firing again right away if it
 *                               is still ready (level-triggered)
 * The record is in cs->p, so an event polled for it before its release can't
 * read freed memory (see the drain epochs).
 */
#define KEPT_NEW     0u
#define KEPT_IDLE    1u
#define KEPT_WAITED  2u
#define KEPT_FIRED   3u
#define KEPT_READY   4u

struct kept_pfd {
    APR_RING_ENTRY(kept_pfd) free_link; /* in cs->kept_free once released */
    apr_pollfd_t pfd;         /* registered (NOCOPY), client_data = &pt */
    listener_poll_type pt;    /* PT_KEPT, baton = this */
    /*atomic*/ apr_uint32_t state; /* KEPT_* */
    struct user_wait *wait;   /* the wait on it (KEPT_WAITED) */
    apr_int16_t latched;      /* the rtnevents of KEPT_READY */
    int delivered;            /* fired for its last wait, which was given
                               * its rtnevents (not completed otherwise) */
    event_conn_state_t *cs;   /* its connection */
    struct kept_anchor *anchor; /* its descriptor's, if any */
    apr_uint32_t free_epoch;  /* the drain epoch of its release */
};

/* A descriptor's link to its kept pfd, attached once to the socket or file
 * (allocated in its pool, apr_socket_data_set() adds a node each time): for
 * ap_mpm_release_pfd() to find it from the descriptor only, and to release
 * it if the descriptor's pool is cleaned up while it's still kept (closed
 * without being released first, a bug of its user). Linked both ways while
 * kept, unlinked by any release or a cleanup of the connection's pool.
 */
struct kept_anchor {
    struct kept_pfd *kept;    /* NULL when not kept */
};
#define KEPT_ANCHOR_KEY "mpm_event:kept_anchor"

/* A notifier (ap_mpm_notifier_create()) fires the wait it's given to (see
 * event_notify()), from any thread; it's created before it's given to
 * ap_mpm_register_wait() so that it can be notified before. Once that wait
 * is done, a re-arm (event_notifier_rearm()) makes it new again for the next
 * wait. Protected by notifiers_mutex.
 */
struct ap_mpm_notifier_t {
    APR_RING_ENTRY(ap_mpm_notifier_t) link;  /* in notified_user_waits */
    struct user_wait *wait;                  /* its wait (once used) */
    unsigned int used     :1, /* given to ap_mpm_register_wait() */
                 done     :1, /* its wait completed, or dropped unarmed */
                 notified :1, /* ap_mpm_notify() was called */
                 armed    :1, /* its wait armed (pollset or timer) */
                 queued   :1; /* in notified_user_waits */
};

/* The notifiers notified while their wait is armed, for the listener to
 * complete the waits (under notifiers_mutex).
 */
static apr_thread_mutex_t *notifiers_mutex;
/* Allocated (pruntime): a static head makes APR_RING_SENTINEL() point before
 * a static object, which compilers flag (-Warray-bounds)
 */
static APR_RING_HEAD(notified_user_waits_t, ap_mpm_notifier_t) *notified_user_waits;

typedef struct event_child_bucket {
    ap_pod_t *pod;
    ap_listen_rec *listeners;
} event_child_bucket;
static event_child_bucket *my_bucket;  /* Current child bucket */
static int my_bucket_num;              /* Its index */

/* data retained by event across load/unload of the module
 * allocated on first call to pre-config hook; located on
 * subsequent calls to pre-config hook
 */
typedef struct event_retained_data {
    ap_unixd_mpm_retained_data *mpm;

    apr_pool_t *gen_pool; /* generation pool (children start->stop lifetime) */
    event_child_bucket *buckets; /* children buckets (reset per generation) */

    ap_listen_rec **listen_buckets;
    int num_listen_buckets;
    int listen_buckets_ratio; /* the ListenCoresBucketsRatio of the count */

    int first_server_limit;
    int first_thread_limit;
    int first_thread_limit_derived; /* by MaxRequestWorkers auto */
    int first_server_sb_limit;
    int gen_daemons_limit; /* the children limit of the PODs' generation */
    int sick_child_detected;
    int maxclients_reported;
    int near_maxclients_reported;

    /*
     * The max child slot ever assigned, preserved across restarts.  Necessary
     * to deal with MaxRequestWorkers changes across AP_SIG_GRACEFUL restarts.
     * We use this value to optimize routines that have to scan the entire
     * scoreboard.
     */
    int max_daemon_used;

    /*
     * All running workers, active and shutting down, including those that
     * may be left from before a graceful restart.
     * Not kept up-to-date when shutdown is pending.
     */
    int total_daemons;
    /*
     * Workers that still active, i.e. are not shutting down gracefully.
     */
    int active_daemons;

    /*
     * idle_spawn_rate is the number of children that will be spawned on the
     * next maintenance cycle if there aren't enough idle servers.  It is
     * doubled up to MAX_SPAWN_RATE, and reset only when a cycle goes by
     * without the need to spawn.
     */
    int idle_spawn_rate;
    int max_spawn_rate, *free_slots;
    int hold_off_on_exponential_spawning;

    /* MaxRequestWorkers auto: the active children per bucket (reset per
     * generation), and whether the scoreboard couldn't hold them all.
     */
    int *bucket_children;
    int target_full_reported;
    /* When each scoreboard slot's child was last started, and the last one
     * (see replace_at_once())
     */
    apr_time_t *slot_started;
    apr_time_t last_started;
} event_retained_data;
static event_retained_data *retained;

#ifndef MAX_SPAWN_RATE
#define MAX_SPAWN_RATE 32
#endif

struct event_srv_cfg_s {
    /* Per server timeout queues */
    struct timeout_queue *io_q,
                         *wc_q,
                         *ka_q,
                         *sh_q;
    server_rec *s; /* backref */
};

#define ID_FROM_CHILD_THREAD(c, t)    ((c * thread_limit) + t)

/* The event MPM respects a couple of runtime flags that can aid
 * in debugging. Setting the -DNO_DETACH flag will prevent the root process
 * from detaching from its controlling terminal. Additionally, setting
 * the -DONE_PROCESS flag (which implies -DNO_DETACH) will get you the
 * child_main loop running in the process which originally started up.
 * This gives you a pretty nice debugging environment.  (You'll get a SIGHUP
 * early in standalone_main; just continue through.  This is the server
 * trying to kill off any child processes which it might have lying
 * around --- Apache doesn't keep track of their pids, it just sends
 * SIGHUP to the process group, ignoring it in the root process.
 * Continue through and you'll be fine.).
 */

static int one_process = 0;

#ifdef DEBUG_SIGSTOP
int raise_sigstop_flags;
#endif

static apr_pool_t *pconf;       /* Pool for config stuff */
static apr_pool_t *pchild;      /* Pool for httpd child stuff */
static apr_pool_t *pruntime;    /* Pool for MPM threads stuff */

static pid_t ap_my_pid;         /* Linux getpid() doesn't work except in main
                                   thread. Use this instead */
static pid_t parent_pid;

static int ap_child_slot;       /* Current child process slot in scoreboard */

/* Count a worker thread in or out of workers_live, and of the process score's
 * (mod_status)
 */
static APR_INLINE void workers_live_inc(void)
{
    apr_atomic_inc32(&workers_live);
    apr_atomic_inc32(&ap_scoreboard_image->parent[ap_child_slot].workers_live);
}
static APR_INLINE void workers_live_dec(void)
{
    apr_atomic_dec32(&workers_live);
    apr_atomic_dec32(&ap_scoreboard_image->parent[ap_child_slot].workers_live);
}

/* What each worker publishes for the other threads, written by the worker
 * only, in a cache line of its own (worker_slots[threads_max], aligned on a
 * cache line): the socket it processes, closed by a non-graceful (forced)
 * shutdown of the server (close_worker_sockets()), its drain epoch
 * (drain_epoch_enter()), and for an extra worker that it retired (exited, to
 * be joined by the listener, reset then).
 */
struct worker_slot {
    CACHE_LINE_ALIGNED
    apr_socket_t *csd;
    apr_uint32_t drain_epoch;
    apr_uint32_t retired;
};
static struct worker_slot *worker_slots;
#ifdef AP_THREAD_LOCAL
/* The slot of the worker running this thread, if any */
static AP_THREAD_LOCAL struct worker_slot *worker_current_slot;
#endif

/* Disabling / enabling listening sockets can only happen in the listener
 * thread, which is the only one to set 'dying' to 1 too, so it's all thread
 * safe. 'listensocks_off' is changed atomically still because it's read
 * concurrently in listensocks_disabled(). It holds the reasons for not
 * accepting, the listening sockets being polled only when there is none.
 */
#define ACCEPT_OFF_LIMIT (1u << 0) /* connections_above_limit(), or dying */
#define ACCEPT_OFF_SHARE (1u << 1) /* above the fair share (fair_share_above()) */
static /*atomic*/ apr_uint32_t listensocks_off = 0;

/* Instrumentation of the workers' backlog: how long the entries wait there
 * for a worker (their sojourn), by class, and how often (and how long) the
 * listener stops accepting. Reported and reset with the periodic stats, at
 * trace2 (backlog_stats_report()).
 */
typedef enum {
    BACKLOG_TIMER = 0,  /* timer callbacks */
    BACKLOG_CONTINUATION, /* the continuations of completed waits */
    BACKLOG_WRITE,      /* write completion */
    BACKLOG_LINGER,     /* lingering close */
    BACKLOG_WAITIO,     /* back from CONN_STATE_ASYNC_WAITIO */
    BACKLOG_KEEPALIVE,  /* back from keepalive (the next request) */
    BACKLOG_NEW,        /* newly accepted connections */
    BACKLOG_CLASSES
} backlog_class_e;

static const char *const backlog_class_names[BACKLOG_CLASSES] = {
    "timer",
    "continuation",
    "write",
    "linger",
    "waitio",
    "keepalive",
    "new"
};

/* Slot k of the histogram counts the sojourns of less than 2^k us (and at
 * least 2^(k-1) us), the last one everything above.
 */
#define BACKLOG_HIST_SLOTS 25

/* The sum of the sojourns (backlog_stats_t.sum_us): 64-bit atomics need
 * APR 1.7, before a 32-bit sum saturating at APR_UINT32_MAX (~71min per
 * period) does.
 */
#if APR_VERSION_AT_LEAST(1,7,0)
typedef apr_uint64_t backlog_sum_t;
#define backlog_sum_add(sum, us) apr_atomic_add64((sum), (us))
#define backlog_sum_take(sum)    apr_atomic_xchg64((sum), 0)
#else
typedef apr_uint32_t backlog_sum_t;
static APR_INLINE void backlog_sum_add(volatile apr_uint32_t *sum,
                                       apr_uint32_t us)
{
    apr_uint32_t old, val;
    do {
        old = apr_atomic_read32(sum);
        val = (us > APR_UINT32_MAX - old) ? APR_UINT32_MAX : old + us;
    } while (apr_atomic_cas32(sum, val, old) != old);
}
#define backlog_sum_take(sum)    apr_atomic_xchg32((sum), 0)
#endif

typedef struct {
    /*atomic*/ apr_uint32_t count;
    /*atomic*/ apr_uint32_t max_us;
    /*atomic*/ backlog_sum_t sum_us;
    /*atomic*/ apr_uint32_t hist[BACKLOG_HIST_SLOTS];
} backlog_stats_t;

static backlog_stats_t backlog_stats[BACKLOG_CLASSES];

/* Whether the stats are recorded, only when they are reported (trace2):
 * the workers would otherwise all write the same cache lines for nothing.
 * Set by the child at startup.
 */
static int backlog_stats_on;

/* The classes are also the lanes of the workers' queue, popped by weighted
 * round-robin with these weights, in this order: work in progress first,
 * then the connections that were waiting for the client, then the new ones,
 * every class keeping a share (no starvation). Only the ratios matter; not
 * tuned yet.
 */
#define BACKLOG_WEIGHT_PROGRESS 4
#define BACKLOG_WEIGHT_WAITING  2
#define BACKLOG_WEIGHT_NEW      1
static const unsigned int backlog_class_weights[BACKLOG_CLASSES] = {
    BACKLOG_WEIGHT_PROGRESS, /* timer */
    BACKLOG_WEIGHT_PROGRESS, /* continuation */
    BACKLOG_WEIGHT_PROGRESS, /* write */
    BACKLOG_WEIGHT_PROGRESS, /* linger */
    BACKLOG_WEIGHT_WAITING,  /* waitio */
    BACKLOG_WEIGHT_WAITING,  /* keepalive */
    BACKLOG_WEIGHT_NEW       /* new */
};

/* The sojourn admission (CoDel-like): stop accepting when the waits of the
 * new connections for a worker have stayed above the target for the
 * interval; any wait at or below the target, or no new connection waiting,
 * resets it. The waits are those of the new connections taken by a worker,
 * and that of the oldest one still waiting (so blocked workers count too).
 * The target and interval are AsyncAdmissionTarget and AsyncAdmissionInterval
 * (ms), whose defaults can be changed at build time.
 */
#ifndef AP_EVENT_ADMISSION_TARGET
#define AP_EVENT_ADMISSION_TARGET 5
#endif
#ifndef AP_EVENT_ADMISSION_INTERVAL
#define AP_EVENT_ADMISSION_INTERVAL 100
#endif
static apr_time_t admission_target =
    apr_time_from_msec(AP_EVENT_ADMISSION_TARGET);
static apr_time_t admission_interval =
    apr_time_from_msec(AP_EVENT_ADMISSION_INTERVAL);

/* Since when the new connections' waits are above the target, 0 when below:
 * written without a lock by the workers (admission_sample(), for each new
 * connection they take), read by any thread (admission_above_target()). A
 * lost update only shifts the start of the interval by a sample (it's a
 * heuristic); the store of a 64-bit apr_time_t is single on 64-bit
 * platforms, but can tear on 32-bit ones (one bogus refusal or delay at
 * worst).
 */
static volatile apr_time_t admission_above_since;

/* The refusals by the backstop rather than the sojourn (for the stats),
 * counted by the listener (disable_listensocks())
 */
static apr_uint32_t admission_backstops;

/* Called by the workers for each new connection they take: write only on
 * changes, the line is read by all of them. The last new connection taken
 * resets it too (none waiting).
 */
static void admission_sample(apr_time_t wait, apr_time_t now)
{
    if (wait <= admission_target
        || !ap_queue_lane_nelts(worker_queue, BACKLOG_NEW)) {
        if (admission_above_since) {
            admission_above_since = 0;
        }
    }
    else if (!admission_above_since) {
        admission_above_since = now;
    }
}

/* What admission_above_target() finds */
#define ADMISSION_UNDER    0
#define ADMISSION_SOJOURN  1 /* waits above the target for the interval */
#define ADMISSION_BACKSTOP 2 /* more waiting than the workers' backlog limit */

/* Whether the new connections waiting for a worker are above the admission's
 * limits (ADMISSION_*), for any thread: it only reads the state, which
 * changes where it's measured (admission_sample(), the worker queue's lane)
 * or decided (listensocks_off).
 *
 * The waits are above the target since the workers' samples say, or since
 * the oldest one still waiting (the lane's head) has waited longer than the
 * target at least, which counts the blocked workers too.
 *
 * Hysteresis: once refusing for the limits (ACCEPT_OFF_LIMIT), accept again
 * only when the new connections are clearly back under (no wait above half
 * the target nor count above half the backstop, or none waiting), so that
 * floods don't toggle the listening sockets at the rate of the workers. A
 * minimum time off as well would cost throughput (workers idle while
 * connections wait in the kernel) for fewer toggles than this already
 * avoids.
 */
static int admission_above_target(apr_time_t now)
{
    apr_time_t head = ap_queue_lane_head_time(worker_queue, BACKLOG_NEW);
    apr_uint32_t count;
    apr_time_t since;

    if (!head) {
        return ADMISSION_UNDER; /* no new connection waiting */
    }
    count = ap_queue_lane_nelts(worker_queue, BACKLOG_NEW);
    if (apr_atomic_read32(&listensocks_off) & ACCEPT_OFF_LIMIT) {
        if (now - head > admission_target / 2) {
            return ADMISSION_SOJOURN;
        }
        if (count > (apr_uint32_t)workers_backlog_limit / 2) {
            return ADMISSION_BACKSTOP;
        }
        return ADMISSION_UNDER;
    }
    if (now - head > admission_target) {
        since = admission_above_since;
        if (!since || since > head + admission_target) {
            since = head + admission_target;
        }
        if (now - since >= admission_interval) {
            return ADMISSION_SOJOURN;
        }
    }
    if (count > (apr_uint32_t)workers_backlog_limit) {
        return ADMISSION_BACKSTOP;
    }
    return ADMISSION_UNDER;
}

/* Changed by the listener only (see above), for any reason and for the fair
 * share alone
 */
static apr_uint32_t listensocks_toggles, share_toggles;
static apr_time_t listensocks_off_since, listensocks_off_time;
static apr_time_t share_off_since, share_off_time;
static apr_time_t fair_share_stopped; /* when it last stopped for the share */

/* The backlog's connections shut down for their timeout, the lingering ones
 * closed by shrink_timeout_queue() (listener only)
 */
static apr_uint32_t backlog_dropped, linger_shrunk;

static apr_time_t listensocks_suspended_at; /* the last stop, for its trace */

/* The durations of the accept-offs that ended in the period, by slot like
 * the sojourns (listener only)
 */
static apr_uint32_t accept_off_hist[BACKLOG_HIST_SLOTS], accept_off_ended,
                    accept_off_max;

/* What made the listener accept again (with the backlog stats): the wakes
 * asking for it (wakeup_listener_by() the ACCEPT_WAKE_* flags of who woke
 * it up, accumulated until the listener takes them), else the timeout of its
 * backstop re-check (RECHECK_BACKSTOP), else that of the fair share's
 * re-check (RECHECK_SHARE), else anything else that woke it up. Counted
 * by the listener only.
 */
#define ACCEPT_WAKE_WORKER (1u << 0) /* a worker took new ones or idled */
#define ACCEPT_WAKE_CLOSE  (1u << 1) /* a connection was closed */
static /*atomic*/ apr_uint32_t accept_wakes;
static apr_uint32_t resumes_woken, resumes_recheck, resumes_share,
                    resumes_other;

/* The re-check whose timeout the listener's poll used, if any */
#define RECHECK_BACKSTOP 1u /* ACCEPT_RECHECK_TIMEOUT, see listener_thread() */
#define RECHECK_SHARE    2u /* the fair share's (fair_share_stopped) */

/* Account for an entry popped from the backlog (any thread) */
static void backlog_stats_record(int qclass, apr_time_t sojourn)
{
    backlog_stats_t *st = &backlog_stats[qclass];
    apr_uint32_t us, max;
    int slot = 0;

    if (sojourn <= 0) {
        us = 0;
    }
    else if (sojourn >= APR_UINT32_MAX) {
        us = APR_UINT32_MAX;
    }
    else {
        us = (apr_uint32_t)sojourn;
    }
    while (slot < BACKLOG_HIST_SLOTS - 1 && (us >> slot)) {
        slot++;
    }

    apr_atomic_inc32(&st->count);
    backlog_sum_add(&st->sum_us, us);
    apr_atomic_inc32(&st->hist[slot]);
    for (;;) {
        max = apr_atomic_read32(&st->max_us);
        if (us <= max || apr_atomic_cas32(&st->max_us, us, max) == max) {
            break;
        }
    }
}

/* The bound (in us) of the histogram slot reaching the given percentile */
static apr_uint32_t backlog_hist_bound(const apr_uint32_t *hist,
                                       apr_uint32_t count, int pct)
{
    apr_uint64_t want = ((apr_uint64_t)count * pct + 99) / 100, cum = 0;
    int slot;

    for (slot = 0; slot < BACKLOG_HIST_SLOTS - 1; slot++) {
        cum += hist[slot];
        if (cum >= want) {
            break;
        }
    }
    return (apr_uint32_t)1 << slot;
}

/* Account for an accept-off that ended (listener) */
static void accept_off_record(apr_time_t duration)
{
    apr_uint32_t us;
    int slot = 0;

    us = (duration <= 0) ? 0
       : (duration >= APR_UINT32_MAX) ? APR_UINT32_MAX
       : (apr_uint32_t)duration;
    while (slot < BACKLOG_HIST_SLOTS - 1 && (us >> slot)) {
        slot++;
    }
    accept_off_hist[slot]++;
    accept_off_ended++;
    if (us > accept_off_max) {
        accept_off_max = us;
    }
}

/* The workers polling conn_pollset (worker_poll_one()): their polls, the
 * connections and waits they claimed, and the events they dropped (expired,
 * completed or claimed otherwise meanwhile, or stale), and the polls missed
 * for lack of a slot and the worker_poll_baton's queuings
 * (AsyncWorkerPollers). Counted only with the backlog stats
 * (backlog_stats_on).
 */
static /*atomic*/ apr_uint32_t drain_polls, drain_csd, drain_user, drain_dropped;
static /*atomic*/ apr_uint32_t poll_misses, poll_promotions;

/* The waits' timeouts armed in a timeout queue, or in the timers' skiplist
 * (not declared, see wait_tq_arm()), with the backlog stats too
 */
static /*atomic*/ apr_uint32_t wait_tq_arms, wait_tq_fallbacks;

#define DRAIN_STAT_INC(counter) do { \
    if (backlog_stats_on) { \
        apr_atomic_inc32(&(counter)); \
    } \
} while (0)

/* Log the backlog stats of the last period and reset them (listener) */
static void backlog_stats_report(apr_time_t now)
{
    char buf[1024];
    apr_size_t len = 0;
    apr_time_t off, share_off;
    apr_uint32_t toggles, share_n;
    int i, j;

    for (i = 0; i < BACKLOG_CLASSES; i++) {
        backlog_stats_t *st = &backlog_stats[i];
        apr_uint32_t hist[BACKLOG_HIST_SLOTS], count, max;
        apr_uint64_t sum;

        count = apr_atomic_xchg32(&st->count, 0);
        max = apr_atomic_xchg32(&st->max_us, 0);
        sum = backlog_sum_take(&st->sum_us);
        for (j = 0; j < BACKLOG_HIST_SLOTS; j++) {
            hist[j] = apr_atomic_xchg32(&st->hist[j], 0);
        }
        if (count && len < sizeof(buf)) {
            len += apr_snprintf(buf + len, sizeof(buf) - len,
                                " %s:n=%u,avg=%" APR_UINT64_T_FMT "us,"
                                "p50<%uus,p99<%uus,max=%uus",
                                backlog_class_names[i], count, sum / count,
                                backlog_hist_bound(hist, count, 50),
                                backlog_hist_bound(hist, count, 99), max);
        }
    }

    off = listensocks_off_time;
    if (listensocks_off_since) {
        off += now - listensocks_off_since;
        listensocks_off_since = now;
    }
    listensocks_off_time = 0;
    toggles = listensocks_toggles;
    listensocks_toggles = 0;
    share_off = share_off_time;
    if (share_off_since) {
        share_off += now - share_off_since;
        share_off_since = now;
    }
    share_off_time = 0;
    share_n = share_toggles;
    share_toggles = 0;

    ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, ap_server_conf,
                 "backlog sojourn:%s; dropped %u; linger shrunk %u;"
                 " accept off %u times, %"
                 APR_TIME_T_FMT "ms, backstop %u,"
                 " share %u times %" APR_TIME_T_FMT "ms,"
                 " resumed woken %u recheck %u share %u other %u;"
                 " drain polls=%u csd=%u user=%u dropped=%u"
                 " misses=%u promotions=%u; wait timeouts queued=%u"
                 " skiplist=%u; accept offs ended %u: p50<%uus,max=%uus",
                 len ? buf : " none", backlog_dropped, linger_shrunk,
                 toggles, apr_time_as_msec(off),
                 apr_atomic_xchg32(&admission_backstops, 0),
                 share_n, apr_time_as_msec(share_off),
                 resumes_woken, resumes_recheck, resumes_share, resumes_other,
                 apr_atomic_xchg32(&drain_polls, 0),
                 apr_atomic_xchg32(&drain_csd, 0),
                 apr_atomic_xchg32(&drain_user, 0),
                 apr_atomic_xchg32(&drain_dropped, 0),
                 apr_atomic_xchg32(&poll_misses, 0),
                 apr_atomic_xchg32(&poll_promotions, 0),
                 apr_atomic_xchg32(&wait_tq_arms, 0),
                 apr_atomic_xchg32(&wait_tq_fallbacks, 0),
                 accept_off_ended,
                 (accept_off_ended
                  ? backlog_hist_bound(accept_off_hist, accept_off_ended, 50)
                  : 0),
                 accept_off_max);
    resumes_woken = resumes_recheck = resumes_share = resumes_other = 0;
    backlog_dropped = linger_shrunk = 0;
    memset(accept_off_hist, 0, sizeof(accept_off_hist));
    accept_off_ended = accept_off_max = 0;
}

static APR_INLINE int connections_full(void);

/* Stop accepting for a reason (ACCEPT_OFF_*), returns whether accepting
 * stopped (not if it was stopped already, for another reason)
 */
static int disable_listensocks(apr_time_t now, unsigned int reason)
{
    volatile process_score *ps;
    apr_uint32_t off = apr_atomic_read32(&listensocks_off);
    int i;

    if (off & reason) {
        return 0;
    }
    if ((reason & ACCEPT_OFF_LIMIT)
        && !apr_atomic_read32(&dying)
        && !connections_full()
        && admission_above_target(now) == ADMISSION_BACKSTOP) {
        admission_backstops++;
    }
    apr_atomic_set32(&listensocks_off, off | reason);
    if (reason & ACCEPT_OFF_SHARE) {
        share_toggles++;
        share_off_since = fair_share_stopped = now;
    }
    if (off) {
        return 0;
    }
    listensocks_toggles++;
    listensocks_off_since = listensocks_suspended_at = now;

    {
        static log_ratelimit_t rl;
        if (LOG_RATELIMIT(&rl, APLOG_DEBUG, 0, ap_server_conf, NULL)) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(10381)
                         "Suspend listening sockets: idlers:%i conns:%u backlog:%u "
                         "waitio:%u write:%u keepalive:%u shutdown:%u "
                         "linger:%u timers:%u suspended:%u",
                         ap_queue_info_idlers_count(worker_queue_info),
                         apr_atomic_read32(&event_counts.connection_count),
                         apr_atomic_read32(backlog_q->total),
                         apr_atomic_read32(waitio_q->total),
                         apr_atomic_read32(write_completion_q->total),
                         apr_atomic_read32(keepalive_q->total),
                         apr_atomic_read32(shutdown_q->total),
                         apr_atomic_read32(linger_q->total),
                         apr_atomic_read32(&event_counts.timers_count),
                         apr_atomic_read32(&event_counts.suspended_count));
        }
    }

    ps = &ap_scoreboard_image->parent[ap_child_slot];
    ps->not_accepting = 1;

    for (i = 0; i < num_listensocks; i++) {
        apr_pollset_remove(event_pollset, &listener_pollfd[i]);
    }
    return 1;
}

/* Accept again, all the reasons cleared (should_enable_listensocks()), "by"
 * what made the listener find it out (traced)
 */
static int enable_listensocks(apr_time_t now, const char *by)
{
    volatile process_score *ps;
    apr_uint32_t off = apr_atomic_read32(&listensocks_off);
    int i;

    if (!off || apr_atomic_read32(&dying)) {
        return 0;
    }
    apr_atomic_set32(&listensocks_off, 0);
    if (share_off_since) {
        share_off_time += now - share_off_since;
        share_off_since = 0;
    }
    if (listensocks_off_since) {
        listensocks_off_time += now - listensocks_off_since;
        listensocks_off_since = 0;
    }
    accept_off_record(now - listensocks_suspended_at);

    {
        static log_ratelimit_t rl;
        if (LOG_RATELIMIT(&rl, APLOG_DEBUG, 0, ap_server_conf, NULL)) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(00457)
                         "Resume listening sockets: by:%s off:%" APR_TIME_T_FMT "us "
                         "idlers:%i conns:%u backlog:%u "
                         "waitio:%u write:%u keepalive:%u shutdown:%u "
                         "linger:%u timers:%u suspended:%u",
                         by, now - listensocks_suspended_at,
                         ap_queue_info_idlers_count(worker_queue_info),
                         apr_atomic_read32(&event_counts.connection_count),
                         apr_atomic_read32(backlog_q->total),
                         apr_atomic_read32(waitio_q->total),
                         apr_atomic_read32(write_completion_q->total),
                         apr_atomic_read32(keepalive_q->total),
                         apr_atomic_read32(shutdown_q->total),
                         apr_atomic_read32(linger_q->total),
                         apr_atomic_read32(&event_counts.timers_count),
                         apr_atomic_read32(&event_counts.suspended_count));
        }
    }

    /*
     * XXX: This is not yet optimal. If many workers suddenly become available,
     * XXX: the parent may kill some processes off too soon.
     */
    ps = &ap_scoreboard_image->parent[ap_child_slot];
    ps->not_accepting = 0;

    for (i = 0; i < num_listensocks; i++) {
        apr_pollset_add(event_pollset, &listener_pollfd[i]);
    }
    return 1;
}

static APR_INLINE int listensocks_disabled(void)
{
    return apr_atomic_read32(&listensocks_off) != 0;
}

/* Whether not accepting for this reason (among others possibly) */
static APR_INLINE int listensocks_disabled_for(unsigned int reason)
{
    return (apr_atomic_read32(&listensocks_off) & reason) != 0;
}

/* The fair share of the connections, in auto mode (MaxRequestWorkers auto):
 * while it has no idle worker, a child stops accepting (ACCEPT_OFF_SHARE)
 * when its connections exceed the average of the accepting children of its
 * bucket plus a slack, provided another of them accepts, and accepts again
 * once back at or below that average, or with an idle worker. So a busy child
 * doesn't keep accepting a whole burst while its siblings sleep, and the
 * connections (staying where they were accepted for their keep-alive life)
 * spread over the children once requests would queue; a child with idle
 * workers takes more connections at no harm, gathering them batches the work
 * (fewer children woken for the same requests). The counts are the
 * scoreboard's (ps->connections, published by each child at its stats tick
 * and on each accept). The listener computes the average at the stats tick,
 * before stopping and while stopped; the workers read the last one
 * (fair_share_above()).
 */
static int fair_share_on;
static apr_uint32_t fair_share_slack;
static /*atomic*/ apr_uint32_t fair_share_avg, fair_share_others;

/* The slack (a count margin above the average, for hysteresis): a quarter
 * of the threads per child, at least 2, so that a child doesn't stop and
 * start accepting at each connection around the average, and stops only for
 * an excess worth a part of what it serves at once.
 */
#define FAIR_SHARE_SLACK(threads) (((threads) / 4 > 2) ? (threads) / 4 : 2)

/* Compute the average connections of the accepting children of this bucket
 * (this one included while it accepts), and how many others accept (listener)
 */
static void fair_share_update(void)
{
    const int n = retained->mpm->num_buckets;
    apr_uint32_t sum = 0, count = 0, others = 0;
    int i;

    if (!fair_share_on) {
        return;
    }
    for (i = my_bucket_num; i < server_limit; i += n) {
        volatile process_score *ps = &ap_scoreboard_image->parent[i];

        if (i == ap_child_slot) {
            if (!listensocks_disabled()) {
                sum += apr_atomic_read32(&event_counts.connection_count);
                count++;
            }
        }
        else if (ps->pid != 0
                 && ps->generation == retained->mpm->my_generation
                 && !ps->quiescing
                 && !ps->not_accepting) {
            sum += apr_atomic_read32(&ps->connections);
            count++;
            others++;
        }
    }
    apr_atomic_set32(&fair_share_avg, (count) ? sum / count : 0);
    apr_atomic_set32(&fair_share_others, others);
}

/* Whether this child's connections are above its fair share: above the
 * average plus the slack to stop accepting, above the average to stay
 * stopped (stopped != 0); never when no other child of the bucket accepts,
 * nor while it has an idle worker.
 */
static int fair_share_above(int stopped)
{
    apr_uint32_t conns, avg;

    if (!fair_share_on || !apr_atomic_read32(&fair_share_others)) {
        return 0;
    }
    if (ap_queue_info_idlers_count(worker_queue_info) > 0) {
        return 0;
    }
    conns = apr_atomic_read32(&event_counts.connection_count);
    avg = apr_atomic_read32(&fair_share_avg);
    return conns > ((stopped) ? avg : avg + fair_share_slack);
}

/* The connections a child holds at most: its share of MaxClientConnections
 * (auto), 0 for no limit.
 */
static apr_uint32_t connections_limit;

/* Hysteresis of the connections limit: once not accepting for it, accept
 * again only below the limit minus 1/LIMIT_HYSTERESIS of it (90%), so that
 * the closes at the limit don't toggle the listening sockets each time.
 * Below 10 connections that's the limit itself (no hysteresis), harmless
 * at that size.
 */
#define LIMIT_HYSTERESIS 10

/* Not more connections than connections_limit, if any, see LIMIT_HYSTERESIS */
static APR_INLINE int connections_full(void)
{
    apr_uint32_t conns;

    if (!connections_limit) {
        return 0;
    }
    conns = apr_atomic_read32(&event_counts.connection_count);
    if (listensocks_disabled_for(ACCEPT_OFF_LIMIT)) {
        return conns >= connections_limit - connections_limit / LIMIT_HYSTERESIS;
    }
    return conns >= connections_limit;
}

/* Whether to stop accepting for the limits, or not to accept again yet once
 * stopped, for any thread (read-only). now: the caller's current time if at
 * hand, otherwise 0 (fetched if needed)
 */
static APR_INLINE int connections_above_limit(apr_time_t now)
{
    if (connections_full()) {
        return 1;
    }

    /* Stop accepting when the new connections have been waiting too long
     * for a worker, whatever the reason (busy or blocked workers).
     */
    if (!now) {
        now = event_time_now();
    }
    return admission_above_target(now) != ADMISSION_UNDER;
}

/* Whether every reason for not accepting is gone, for any thread (see
 * connections_above_limit())
 */
static APR_INLINE int should_enable_listensocks(apr_time_t now)
{
    apr_uint32_t off = apr_atomic_read32(&listensocks_off);

    return (off
            && !apr_atomic_read32(&dying)
            && (!(off & ACCEPT_OFF_LIMIT) || !connections_above_limit(now))
            && (!(off & ACCEPT_OFF_SHARE) || !fair_share_above(1)));
}

static void close_socket_at(apr_socket_t *csd,
                            const char *at, int line)
{
    apr_os_sock_t fd = -1;
    apr_status_t rv = apr_os_sock_get(&fd, csd);

    /* close_worker_sockets() may have closed it already */
    if (rv == APR_SUCCESS && fd == -1) {
        ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, ap_server_conf,
                     "dead socket %pp at %s:%i", csd, at, line);
        return;
    }

    ap_log_error(APLOG_MARK, APLOG_TRACE8, rv, ap_server_conf,
                "closing socket %pp:%i at %s:%i", csd, (int)fd, at, line);

    apr_socket_opt_set(csd, APR_SO_NONBLOCK, 1);
    rv = apr_socket_close(csd);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf, APLOGNO(00468)
                     "error closing socket");
        AP_DEBUG_ASSERT(0);
    }
}
#define close_socket(csd) \
    close_socket_at(csd, __FUNCTION__, __LINE__)

static void close_worker_sockets(void)
{
    int i;
    for (i = 0; i < threads_max; i++) {
        /* Taken from the worker, which leaves the socket and its pool
         * alone from then on (take_back_worker_socket())
         */
        apr_socket_t *csd = apr_atomic_xchgptr((void *volatile *)
                                               &worker_slots[i].csd, NULL);
        if (csd) {
            close_socket(csd);
        }
    }
}

/* Wake up the listener if it's poll()ing, for it to see what changed (its
 * timeout, the listening sockets to poll again, a notified wait, exiting...)
 */
static APR_INLINE void wakeup_listener(void)
{
    if (event_pollset) {
        apr_pollset_wakeup(event_pollset);
    }
}

/* Wake up the listener for it to accept again, by who (ACCEPT_WAKE_*, noted
 * for the backlog stats), the caller having found that it may
 * (should_enable_listensocks()).
 */
static APR_INLINE void wakeup_listener_by(unsigned int who)
{
    if (backlog_stats_on) {
        apr_uint32_t wakes = apr_atomic_read32(&accept_wakes), old;
        while ((wakes & who) != who) {
            old = apr_atomic_cas32(&accept_wakes, wakes | who, wakes);
            if (old == wakes) {
                break;
            }
            wakes = old;
        }
    }
    wakeup_listener();
}

static void shutdown_listener(void)
{
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                 "shutting down listener%s",
                 apr_atomic_read32(&listener_may_exit) ? " again" : "");

    apr_atomic_set32(&listener_may_exit, 1);

    /* Unblock the listener if it's poll()ing */
    wakeup_listener();

    /* unblock the listener if it's waiting for a worker */
    if (worker_queue_info) {
        ap_queue_info_term(worker_queue_info);
    }
}

#define ST_INIT              0
#define ST_GRACEFUL          1
#define ST_UNGRACEFUL        2

static int terminate_mode = ST_INIT;

static void signal_threads(int mode)
{
    if (terminate_mode >= mode) {
        return;
    }
    terminate_mode = mode;
    retained->mpm->mpm_state = AP_MPMQ_STOPPING;

    /* in case we weren't called from the listener thread, wake up the
     * listener thread
     */
    shutdown_listener();

    /* for ungraceful termination, let the workers exit now;
     * for graceful termination, the listener thread will notify the
     * workers to exit once it has stopped accepting new connections
     */
    if (mode == ST_UNGRACEFUL) {
        apr_atomic_set32(&workers_may_exit, 1);
        ap_queue_interrupt_all(worker_queue);
        ring_doorbell(); /* blocked pollers (worker_poll) */
        close_worker_sockets(); /* forcefully kill all current connections */
    }

    ap_run_child_stopping(pchild, mode == ST_GRACEFUL);
}

static int event_query(int query_code, int *result, apr_status_t *rv)
{
    *rv = APR_SUCCESS;
    switch (query_code) {
    case AP_MPMQ_MAX_DAEMON_USED:
        *result = retained->max_daemon_used;
        break;
    case AP_MPMQ_IS_THREADED:
        *result = AP_MPMQ_STATIC;
        break;
    case AP_MPMQ_IS_FORKED:
        *result = AP_MPMQ_DYNAMIC;
        break;
    case AP_MPMQ_IS_ASYNC:
        *result = 1;
        break;
    case AP_MPMQ_HAS_SERF:
        *result = 1;
        break;
    case AP_MPMQ_HARD_LIMIT_DAEMONS:
        *result = server_limit;
        break;
    case AP_MPMQ_HARD_LIMIT_THREADS:
        *result = thread_limit;
        break;
    case AP_MPMQ_MAX_THREADS:
        /* The base threads, but more than one when they can grow (for the
         * modules that don't lock when single-threaded)
         */
        *result = (elastic_threads && threads_per_child < 2) ? 2
                                                              : threads_per_child;
        break;
    case AP_MPMQ_MIN_SPARE_DAEMONS:
        *result = 0;
        break;
    case AP_MPMQ_MIN_SPARE_THREADS:
        *result = min_spare_threads;
        break;
    case AP_MPMQ_MAX_SPARE_DAEMONS:
        *result = 0;
        break;
    case AP_MPMQ_MAX_SPARE_THREADS:
        *result = max_spare_threads;
        break;
    case AP_MPMQ_MAX_REQUESTS_DAEMON:
        *result = ap_max_requests_per_child;
        break;
    case AP_MPMQ_MAX_DAEMONS:
        *result = active_daemons_limit;
        break;
    case AP_MPMQ_MPM_STATE:
        *result = retained->mpm->mpm_state;
        break;
    case AP_MPMQ_GENERATION:
        *result = retained->mpm->my_generation;
        break;
    case AP_MPMQ_CAN_SUSPEND:
        *result = 1;
        break;
    case AP_MPMQ_CAN_WAITIO:
        *result = 1;
        break;
    case AP_MPMQ_CAN_REGISTER_WAIT:
        *result = 1;
        break;
    case AP_MPMQ_MAX_CONNECTIONS:
        /* Not a hard limit (connections_above_limit() doesn't bound the
         * suspended ones), but what a child processes or queues for its
         * workers at once: its threads (up to threads_max when they grow,
         * e.g. for mod_proxy to size its pools for them) plus the workers'
         * backlog limit.
         */
        *result = threads_max + workers_backlog_limit;
        break;
    default:
        *rv = APR_ENOTIMPL;
        break;
    }
    return OK;
}

static void event_note_child_stopped(int slot, pid_t pid, ap_generation_t gen)
{
    if (slot != -1) { /* child had a scoreboard slot? */
        volatile process_score *ps = &ap_scoreboard_image->parent[slot];
        int i;

        pid = ps->pid;
        gen = ps->generation;
        /* Up to the scoreboard's limit: the extra workers of a child of a
         * previous generation may be beyond the current threads_max.
         */
        for (i = 0; i < thread_limit; i++) {
            ap_update_child_status_from_indexes(slot, i, SERVER_DEAD, NULL);
        }
        ap_run_child_status(ap_server_conf, pid, gen, slot, MPM_CHILD_EXITED);
        if (ps->quiescing != 2) { /* vs perform_idle_server_maintenance() */
            retained->active_daemons--;
        }
        retained->total_daemons--;
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                     "Child %d stopped: pid %d, gen %d, "
                     "active %d/%d, total %d/%d/%d, quiescing %d",
                     slot, (int)pid, (int)gen,
                     retained->active_daemons, active_daemons_limit,
                     retained->total_daemons, retained->max_daemon_used,
                     server_limit, ps->quiescing);
        ps->not_accepting = 0;
        ps->quiescing = 0;
        /* No stale counts for the next child of this slot (update_stats()) */
        apr_atomic_set32(&ps->connections, 0);
        apr_atomic_set32(&ps->backlog, 0);
        apr_atomic_set32(&ps->wait_io, 0);
        apr_atomic_set32(&ps->write_completion, 0);
        apr_atomic_set32(&ps->keep_alive, 0);
        apr_atomic_set32(&ps->shutdown, 0);
        apr_atomic_set32(&ps->lingering_close, 0);
        apr_atomic_set32(&ps->suspended, 0);
        apr_atomic_set32(&ps->workers_live, 0);
        ps->pid = 0;
    }
    else {
        ap_run_child_status(ap_server_conf, pid, gen, -1, MPM_CHILD_EXITED);
    }
}

static void event_note_child_started(int slot, pid_t pid)
{
    ap_generation_t gen = retained->mpm->my_generation;

    retained->total_daemons++;
    retained->active_daemons++;
    ap_scoreboard_image->parent[slot].pid = pid;
    ap_scoreboard_image->parent[slot].generation = gen;
    ap_run_child_status(ap_server_conf, pid, gen, slot, MPM_CHILD_STARTED);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                 "Child %d started: pid %d, gen %d, "
                 "active %d/%d, total %d/%d/%d",
                 slot, (int)pid, (int)gen,
                 retained->active_daemons, active_daemons_limit,
                 retained->total_daemons, retained->max_daemon_used,
                 server_limit);
}

static const char *event_get_name(void)
{
    return "event";
}

/* a clean exit from a child with proper cleanup */
static void clean_child_exit(int code) __attribute__ ((noreturn));
static void clean_child_exit(int code)
{
    retained->mpm->mpm_state = AP_MPMQ_STOPPING;
    if (terminate_mode == ST_INIT) {
        ap_run_child_stopping(pchild, 0);
    }

    if (pchild) {
        ap_run_child_stopped(pchild, terminate_mode == ST_GRACEFUL);
        apr_pool_destroy(pchild);
    }

    if (one_process) {
        event_note_child_stopped(/* slot */ 0, 0, 0);
    }

    exit(code);
}

static void just_die(int sig)
{
    clean_child_exit(0);
}

/*****************************************************************
 * Connection structures and accounting...
 */

static int child_fatal;

/* Count a connection out (once), at the final close of its socket
 * (close_connection_at()), or else at its pool's cleanup (e.g. a connection
 * whose pool is cleared before it's closed): a closed connection's pool can
 * wait in the limbo (worker_poll, recycle_connection_pool()) well after the
 * close, the count and the limits shouldn't. Lock-free (the listener may
 * close under conn_queues.mutex), any thread, cs->c possibly NULL.
 */
static void connection_count_out(event_conn_state_t *cs)
{
    int is_last_connection, is_dying;

    AP_DEBUG_ASSERT(!cs->counted_out);
    cs->counted_out = 1;

    /* Unblock the listener if it's waiting for connection_count = 0,
     * or if the listening sockets were disabled due to limits and can
     * now accept new connections.
     */
    is_last_connection = !apr_atomic_dec32(&event_counts.connection_count);
    is_dying = apr_atomic_read32(&dying);
    if (is_last_connection && is_dying) {
        wakeup_listener();
    }
    else if (should_enable_listensocks(0)) {
        wakeup_listener_by(ACCEPT_WAKE_CLOSE);
    }
    if (is_dying) {
        /* Help worker_thread_should_exit_early() */
        ap_queue_interrupt_one(worker_queue);
        ring_doorbell();
    }
}

static apr_status_t decrement_connection_count(void *cs_)
{
    event_conn_state_t *cs = cs_;

    ap_log_error(APLOG_MARK, APLOG_TRACE6, 0, ap_server_conf,
                 "connection %" CS_FMT_TO " cleaned up",
                 CS_ARG_TO(cs));

    /* With the suspended state (ptrans_pre_cleanup() resumes one left
     * suspended), not with the socket
     */
    if (cs->suspended) {
        apr_atomic_dec32(&event_counts.suspended_count);
    }
    if (!cs->counted_out) {
        connection_count_out(cs);
    }
    return APR_SUCCESS;
}

static void arm_pending_wait(event_conn_state_t *cs);
static void notifier_wait_done(ap_mpm_notifier_t *notifier);
static int run_user_continuation(event_conn_state_t *cs, int in_place);

static void enter_suspended(event_conn_state_t *cs)
{
    AP_DEBUG_ASSERT(!cs->suspended);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE7, 0, cs->c,
                  "Suspend connection %" CS_FMT, CS_ARG(cs));
    apr_atomic_inc32(&event_counts.suspended_count);
    cs->suspended = 1;

    cs->c->sbh = NULL;
    cs->c->suspended_baton = cs;
    ap_run_suspend_connection(cs->c, cs->r);

    /* A wait registered by the handler (ap_mpm_register_wait()) is armed
     * now that the MPM has the connection.
     */
    if (cs->pending_wait) {
        arm_pending_wait(cs);
    }
}

static void take_suspended(event_conn_state_t *cs)
{
    AP_DEBUG_ASSERT(cs->suspended);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE7, 0, cs->c,
                  "Resume connection %" CS_FMT, CS_ARG(cs));

    cs->c->sbh = cs->sbh;
    ap_run_resume_connection(cs->c, cs->r);
}

/* worker_poll: idle workers block polling conn_pollset (the connections and
 * the waits) themselves, the listener keeping event_pollset (the listening
 * sockets, its wakeup) with the timers, expiries, notifications and
 * admission. What the listener queues for the workers rings the doorbell, a
 * one-shot pipe in conn_pollset (PT_QUEUE), waking one blocked worker.
 */
#ifdef EVENT_WORKER_POLL
static apr_file_t *doorbell_in, *doorbell_out;
static apr_pollfd_t doorbell_pfd;

/* Written at every ring and pop, in a cache line of its own */
static struct {
    CACHE_LINE_ALIGNED
    /*atomic*/ apr_uint32_t rung;
} doorbell_state;

/* worker_poll: at most worker_poll_slots_max workers poll conn_pollset at once
 * (AsyncWorkerPollers, by default num_cpus: those this process can run on),
 * since every poll returning takes the pollset's lock in the kernel, contended
 * by the other pollers. A worker that would block without a slot parks on the
 * worker_queue instead (woken up by what's queued), and a poller leaving
 * conn_pollset with nobody blocked there anymore while workers are parked
 * queues the worker_poll_baton for one of them to come and poll.
 */
static apr_uint32_t worker_poll_slots_max;

/* Written by the polling and parking workers at each poll and park, read
 * by them and the listener: in a cache line of its own (false sharing).
 */
static struct {
    CACHE_LINE_ALIGNED
    /*atomic*/ apr_uint32_t slots;   /* workers polling conn_pollset */
    /*atomic*/ apr_uint32_t blocked; /* those blocking there */
    /*atomic*/ apr_uint32_t parked;  /* workers parked on the worker_queue */
    /*atomic*/ apr_uint32_t baton;   /* worker_poll_baton queued */
} worker_poll_stats;

/* Queued for a parked worker to come and poll (worker_poll_promote()). A
 * single static baton is safe: it's queued at most once at a time
 * (worker_poll_stats.baton, set from 0 to 1 by worker_poll_promote()'s CAS),
 * so it has one owner at a time; its fields are set here, or written by the
 * queue under its lock (elem, queued_at), and the popper only compares the
 * pointer and releases it (worker_poll_stats.baton = 0). Not const, the
 * queue writes it.
 */
static ap_queue_event_t worker_poll_baton = {
    AP_QUEUE_EVENT_BATON, { NULL }, NULL, NULL, NULL, 0, BACKLOG_TIMER
};

/* Whether workers are parked on the worker_queue, counted until they return
 * from it (with an event or not).
 */
static APR_INLINE int workers_parked(void)
{
    return apr_atomic_read32(&worker_poll_stats.parked) != 0;
}

/* worker_poll: a worker notifying a wait (ap_mpm_notify(), e.g. releasing a
 * backend connection to a pool waiter) completes it itself rather than
 * through the listener (its wakeup, then the doorbell): it queues the
 * continuation without ringing the doorbell and pops it when back to
 * worker_poll_next(), right after its current work, before polling
 * anything (event_notify()).
 */
#ifdef AP_THREAD_LOCAL
#define EVENT_WORKER_NOTIFY 1
static AP_THREAD_LOCAL int worker_thread_polls;   /* a polling worker */
static AP_THREAD_LOCAL int worker_wake_queued;  /* to pop, not rung */
#endif
#endif

static void recycle_connection_pool(apr_pool_t *p);
static void flush_limbo(void);

/* Close the connection and release its resources (ptrans), either because an
 * unrecoverable error occurred (queues or pollset add/remove) or more usually
 * if lingering close timed out.
 * Pre-condition: nonblocking, can be called from anywhere provided cs is not
 *                in any timeout queue or in the pollset.
 */
/* Take a connection's socket back from the slot where the worker processing
 * it published it, before the socket is closed and its pool (holding it)
 * recycled: zero if close_worker_sockets() took it, on an ungraceful stop,
 * the socket and its pool then to be left alone (the child is exiting, pchild
 * frees the pool). A socket not published (e.g. a connection closed by the
 * listener) is taken back unless the child stops ungracefully.
 */
static int take_back_worker_socket(apr_socket_t *csd)
{
    struct worker_slot *slot = NULL;
#ifdef AP_THREAD_LOCAL
    slot = worker_current_slot;
#else
    int i;
    for (i = 0; i < threads_max; i++) {
        if (apr_atomic_casptr((void *volatile *)&worker_slots[i].csd,
                              csd, csd) == csd) {
            slot = &worker_slots[i];
            break;
        }
    }
#endif
    if (slot && apr_atomic_casptr((void *volatile *)&slot->csd,
                                  NULL, csd) == csd) {
        return 1;
    }
    /* signal_threads() sets workers_may_exit before close_worker_sockets() */
    return !apr_atomic_read32(&workers_may_exit);
}

static void release_kept_pfds(event_conn_state_t *cs);
static void close_connection_at(event_conn_state_t *cs,
                                const char *at, int line)
{
    release_kept_pfds(cs);
    if (cs->c) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, cs->c,
                      "closing connection %" CS_FMT " at %s:%i",
                      CS_ARG(cs), at, line);
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_TRACE6, 0, ap_server_conf,
                      "closing connection %" CS_FMT_TO " at %s:%i",
                      CS_ARG_TO(cs), at, line);
    }

    if (!take_back_worker_socket(cs_sd(cs))) {
        /* close_worker_sockets() closes it */
        return;
    }
    close_socket_at(cs_sd(cs), at, line);
    if (!cs->counted_out) {
        connection_count_out(cs);
    }
    recycle_connection_pool(cs->p);
}
#define close_connection(cs) \
    close_connection_at((cs), __FUNCTION__, __LINE__)

static void kill_connection_at(event_conn_state_t *cs, apr_status_t status,
                               const char *at, int line)
{
    if (cs->c) {
        ap_log_cerror(APLOG_MARK, APLOG_INFO, status, cs->c, APLOGNO(10382)
                      "killing connection in %s at %s:%i",
                      cs_state_str(cs), at, line);
    }
    else {
        {
            static log_ratelimit_t rl;
            if (LOG_RATELIMIT(&rl, APLOG_INFO, 0, ap_server_conf, NULL)) {
                ap_log_error(APLOG_MARK, APLOG_INFO, status, ap_server_conf, APLOGNO(10383)
                             "killing unprocessed connection from %pI in %s at %s:%i",
                             cs_raddr(cs), cs_state_str(cs), at, line);
            }
        }
    }

    close_connection_at(cs, at, line);
}
#define kill_connection(cs, status) \
    kill_connection_at((cs), (status), __FUNCTION__, __LINE__)

/* forward declare */
static void set_conn_state_sense(event_conn_state_t *cs, int sense);
static int push2worker(event_conn_state_t *cs, timer_event_t *te,
                       backlog_class_e qclass, apr_time_t now,
                       int *above_limit, int by_worker);
static void cancel_timer_event(timer_event_t *te);

/* Shutdown the connection in case of timeout, error or resources shortage.
 * This starts lingering close if not already there, or directly closes
 * the connection otherwise.
 * Pre-condition: nonblocking, can be called from anywhere provided cs is not
 *                in the pollset nor any non-backlog timeout queue.
 */
static void shutdown_connection(event_conn_state_t *cs, apr_time_t now,
                                int in_backlog)
{
    ap_assert(!cs->to.q && !cs->te);

    if (in_backlog) {
        backlog_dropped++;
    }

    if (!in_backlog && cs->c && cs->pub.state == CONN_STATE_ASYNC_WAITIO && !cs->pub.timed_out) {
        /* The wait for I/O timed out: give the process_connection hooks one
         * last pass to answer the timeout (e.g. a 408), without waiting again.
         */
        {
            static log_ratelimit_t rl;
            if (LOG_RATELIMIT(&rl, APLOG_TRACE4, 0, NULL, cs->c)) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, cs->c,
                              "timed out connection in %s: last processing",
                              cs_state_str(cs));
            }
        }
        cs->pub.timed_out = 1;
        cs->pub.state = CONN_STATE_PROCESSING;
        push2worker(cs, NULL, BACKLOG_WAITIO, now, NULL, 0);
        return;
    }

    if (cs->c) {
        int expiry = 0;
        switch (cs->pub.state) {
        case CONN_STATE_LINGER:
        case CONN_STATE_KEEPALIVE:
            expiry = 1;
        default:
            break;
        }
        if (in_backlog) {
            static log_ratelimit_t rl;
            if (LOG_RATELIMIT(&rl, APLOG_INFO, 0, NULL, cs->c)) {
                ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, cs->c, APLOGNO()
                              "shutting down backlog connection in %s",
                              cs_state_str(cs));
            }
        }
        else if (expiry) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, cs->c,
                          "shutting down expired connection in %s",
                          cs_state_str(cs));
        }
        else {
            static log_ratelimit_t rl;
            if (LOG_RATELIMIT(&rl, APLOG_TRACE4, 0, NULL, cs->c)) {
                ap_log_cerror(APLOG_MARK, APLOG_TRACE4, 0, cs->c, APLOGNO(10380)
                              "shutting down timed out connection in %s",
                              cs_state_str(cs));
            }
        }

        /* Don't re-schedule connections in lingering close, they had
         * their chance already so just close them now (by a worker if their
         * output timed out, below). The others linger shortly, a processed
         * backlog connection whose wait for a worker expired too (for the
         * pre_close hooks), its wait for another worker counted
         * (backlog_linger_q).
         */
        if (cs->pub.state != CONN_STATE_LINGER) {
            apr_table_setn(cs->c->notes, "short-lingering-close", "1");
            if (in_backlog) {
                cs->linger_since = now;
            }
            cs->pub.state = CONN_STATE_LINGER;
            push2worker(cs, NULL, BACKLOG_LINGER, now, NULL, 0);
        }
        else if (!in_backlog && !cs->linger_shutdown) {
            /* Its output timed out (shutdown_q): abort it and let a worker
             * close it, so that the pool cleanups of a request still in
             * flight (its access log, its worker's scoreboard) run there
             * rather than in the listener, its wait for a worker counted
             * (backlog_linger_q).
             */
            cs->c->aborted = 1;
            cs->linger_since = now;
            push2worker(cs, NULL, BACKLOG_LINGER, now, NULL, 0);
        }
        else {
            /* Closed by the listener: no worker's scoreboard slot */
            cs->c->sbh = NULL;
            close_connection(cs);
        }
    }
    else {
        /* Never been scheduled/processed, kill it. */
        ap_assert(in_backlog);
        kill_connection(cs, APR_EBUSY);
    }
}

/*
 * This runs before any non-MPM cleanup code on the connection;
 * if the connection is currently suspended as far as modules
 * know, provide notification of resumption.
 */
static apr_status_t ptrans_pre_cleanup(void *arg)
{
    event_conn_state_t *cs = arg;
    if (cs->suspended) {
        cs->sbh = NULL;
        cs->pub.state = CONN_STATE_LINGER;
        take_suspended(cs);
    }
    return APR_SUCCESS;
}

/*
 * event_pre_read_request() and event_request_cleanup() track the
 * current r for a given connection.
 */
static apr_status_t event_request_cleanup(void *dummy)
{
    conn_rec *c = dummy;
    event_conn_state_t *cs = ap_get_module_config(c->conn_config,
                                                  &mpm_event_module);

    if (!cs) {
        return APR_SUCCESS;
    }

    cs->r = NULL;
    return APR_SUCCESS;
}

static void event_pre_read_request(request_rec *r, conn_rec *c)
{
    event_conn_state_t *cs = ap_get_module_config(c->conn_config,
                                                  &mpm_event_module);

    if (!cs) {
        return;
    }

    cs->r = r;
    cs->sc = ap_get_module_config(ap_server_conf->module_config,
                                  &mpm_event_module);
    apr_pool_cleanup_register(r->pool, c, event_request_cleanup,
                              apr_pool_cleanup_null);
}

/*
 * event_post_read_request() tracks the current server config for a
 * given request.
 */
static int event_post_read_request(request_rec *r)
{
    conn_rec *c = r->connection;
    event_conn_state_t *cs = ap_get_module_config(c->conn_config,
                                                  &mpm_event_module);

    if (!cs) {
        return DECLINED;
    }

    /* Use Timeout from the request's server. */
    cs->sc = ap_get_module_config(r->server->module_config,
                                  &mpm_event_module);

    /* To preserve legacy behaviour (consistent with other MPMs), use
     * KeepaliveTimeout from the base server (first on this IP:port)
     * when none is explicitly configured on this server. Otherwise
     * use the one from the request's server.
     */
    if (!r->server->keep_alive_timeout_set) {
        cs->ka_sc = ap_get_module_config(c->base_server->module_config,
                                         &mpm_event_module);
    }
    else {
        cs->ka_sc = cs->sc;
    }

    return OK;
}

static void insert_timer_event(timer_event_t *te);

static int pollset_add_at(event_conn_state_t *cs, int sense,
                          struct timeout_queue *q, timer_event_t *te,
                          const char *at, int line)
{
    apr_status_t rv;
    int wakeup = 0;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE7, 0, cs->c,
                  "pollset: add %s=%" APR_TIME_T_FMT " events=%x"
                  " for connection %" CS_FMT " at %s:%i",
                  (q) ? "q" : "t",
                  (q) ? q->timeout : (te) ? te->timeout : -1,
                  (int)cs->pfd.reqevents,
                  CS_ARG(cs), at, line);

    ap_assert((q != NULL) ^ (te != NULL));
    ap_assert(cs->to.q == NULL && cs->te == NULL);

    set_conn_state_sense(cs, sense);
#ifdef APR_POLLONESHOT
    /* One-shot: kept registered once added (disarmed when it fires or is
     * removed), so the next add is a re-arm (one epoll_ctl() instead of an
     * add per arming and a remove per completion), see pollset_del_at().
     */
    cs->pfd.reqevents |= APR_POLLONESHOT;
#endif

    if (q) {
        apr_thread_mutex_lock(conn_queues.mutex);
        wakeup = TO_QUEUE_APPEND(q, &cs->to);
    }
    else {
        /* Recorded before it's inserted, see insert_timer_event() */
        cs->te = te;
        insert_timer_event(te);
    }

    rv = apr_pollset_add(conn_pollset, &cs->pfd);
    if (rv != APR_SUCCESS) {
        if (q) {
            TO_QUEUE_REMOVE(q, &cs->to);
            apr_thread_mutex_unlock(conn_queues.mutex);
        }
        else {
            cancel_timer_event(te);
            cs->te = NULL;
        }

        /* close_worker_sockets() may have closed it already */
        if (apr_atomic_read32(&workers_may_exit)) {
            if (!APR_STATUS_IS_EBADF(rv)) {
                ap_log_cerror(APLOG_MARK, APLOG_DEBUG, rv, cs->c, APLOGNO()
                              "pollset add failed for connection %" CS_FMT
                              " at %s:%i while stopping", CS_ARG(cs), at,
                              line);
            }
            AP_DEBUG_ASSERT(APR_STATUS_IS_EBADF(rv));
        }
        else {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, cs->c, APLOGNO(03093)
                          "pollset add failed for connection %" CS_FMT " at %s:%i",
                          CS_ARG(cs), at, line);
            AP_DEBUG_ASSERT(0);
            signal_threads(ST_GRACEFUL);
        }
        return 0;
    }
    if (q) {
        apr_thread_mutex_unlock(conn_queues.mutex);
        if (wakeup) {
            wakeup_listener();
        }
    }
    return 1;
}
#define pollset_add(cs, sense, q, te) \
    pollset_add_at((cs), (sense), (q), (te), __FUNCTION__, __LINE__)

static int pollset_del_at(event_conn_state_t *cs, int locked, int fired,
                          const char *at, int line)
{
    apr_status_t rv;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE7, 0, cs->c,
                  "pollset: del %s=%" APR_TIME_T_FMT " events=%x"
                  " for connection %" CS_FMT " at %s:%i",
                  (cs->to.q) ? "q" : "t",
                  (cs->to.q) ? cs->to.q->timeout : (cs->te ? cs->te->timeout : -1),
                  (int)cs->pfd.reqevents,
                  CS_ARG(cs), at, line);

    if (cs->to.q) {
        if (!locked) {
            apr_thread_mutex_lock(conn_queues.mutex);
        }
        TO_QUEUE_REMOVE(cs->to.q, &cs->to);
        if (!locked) {
            apr_thread_mutex_unlock(conn_queues.mutex);
        }
    }
    else if (cs->te) {
        cancel_timer_event(cs->te);
        cs->te = NULL;
    }

    /*
     * Some of the pollset backends, like KQueue or Epoll
     * automagically remove the FD if the socket is closed,
     * therefore, we can accept _SUCCESS or _NOTFOUND,
     * and we still want to keep going
     */
#ifdef APR_POLLONESHOT
    if (fired && (cs->pfd.reqevents & APR_POLLONESHOT)) {
        return 1; /* disarmed by the kernel already, nothing to remove */
    }
#endif
    rv = apr_pollset_remove(conn_pollset, &cs->pfd);
    if (rv != APR_SUCCESS && !APR_STATUS_IS_NOTFOUND(rv)) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, rv, cs->c, APLOGNO(03094)
                      "pollset remove failed for connection %" CS_FMT " at %s:%i",
                      CS_ARG(cs), at, line);
        AP_DEBUG_ASSERT(0);
        signal_threads(ST_GRACEFUL);
        return 0;
    }

    return 1;
}
#define pollset_del(cs, locked) \
    pollset_del_at((cs), (locked), 0, __FUNCTION__, __LINE__)
/* After the connection's pfd fired (the listener) */
#define pollset_del_fired(cs) \
    pollset_del_at((cs), 0, 1, __FUNCTION__, __LINE__)

/* Forward declare */
static timer_event_t *get_timer_event(apr_time_t timeout,
                                      ap_mpm_callback_fn_t *cbfn, void *baton,
                                      int insert);
static void process_lingering_close(event_conn_state_t *cs);

/* The callback of a wait's timer (arm_user_wait()), whose baton is the
 * struct user_wait: never called, it marks the timer for the listener, which
 * claims the wait (claim_user_wait()) when it expires.
 */
static void wait_timer_cb(void *baton)
{
    ap_assert(0);
}

static event_conn_state_t *make_conn_state(apr_pool_t *p, apr_socket_t *csd)
{
    event_conn_state_t *cs = apr_pcalloc(p, sizeof(*cs));
    listener_poll_type *pt;

    APR_RING_INIT(&cs->kept_free, kept_pfd, free_link);
    cs->pfd.desc_type = APR_POLL_SOCKET;
    cs->pfd.desc.s = cs_se(cs)->sd = csd;
    cs->pfd.client_data = pt = apr_pcalloc(p, sizeof(*pt));
    cs_qe(cs)->cb_baton = cs_se(cs)->baton = cs;
    cs_qe(cs)->type = AP_QUEUE_EVENT_SOCK;
    cs_qe(cs)->data.se = cs_se(cs);
    cs->p = cs_se(cs)->p = p;
    pt->type = PT_CSD;
    pt->baton = cs;

    APR_RING_ELEM_INIT(&cs->to, link);
    cs->to.owner = cs;

    cs->sc = cs->ka_sc = ap_get_module_config(ap_server_conf->module_config,
                                              &mpm_event_module);

    /**
     * XXX If the platform does not have a usable way of bundling
     * accept() with a socket readability check, like Win32,
     * and there are measurable delays before the
     * socket is readable due to the first data packet arriving,
     * it might be better to create the cs on the listener thread
     * with the state set to CONN_STATE_KEEPALIVE
     *
     * FreeBSD users will want to enable the HTTP accept filter
     * module in their kernel for the highest performance
     * When the accept filter is active, sockets are kept in the
     * kernel until a HTTP request is received.
     */
    cs->pub.state = CONN_STATE_PROCESSING;
    cs->pub.sense = CONN_SENSE_DEFAULT;

    apr_atomic_inc32(&event_counts.connection_count);
    apr_pool_cleanup_register(p, cs, decrement_connection_count,
                              apr_pool_cleanup_null);
    return cs;
}

static void set_conn_state_sense(event_conn_state_t *cs, int default_sense)
{
    int sense = default_sense;

    if (cs->pub.sense != CONN_SENSE_DEFAULT) {
        sense = cs->pub.sense;

        /* Reset to default for the next round */
        cs->pub.sense = CONN_SENSE_DEFAULT;
    }

    if (sense == CONN_SENSE_WANT_READ) {
        cs->pfd.reqevents = APR_POLLIN | APR_POLLHUP;
    }
    else {
        cs->pfd.reqevents = APR_POLLOUT;
    }
    /* POLLERR is usually returned event only, but some pollset
     * backends may require it in reqevents to do the right thing,
     * so it shouldn't hurt (ignored otherwise).
     */
    cs->pfd.reqevents |= APR_POLLERR;
}

/*
 * process one connection in the worker
 */
static void process_socket(apr_thread_t *thd, apr_pool_t *p,
                           apr_socket_t *sock, event_conn_state_t *cs,
                           int my_child_num, int my_thread_num)
{
    conn_rec *c = cs->c;
    long conn_id = ID_FROM_CHILD_THREAD(my_child_num, my_thread_num);
    int rc = OK, processed = 0;

    if (!c) { /* This is a new connection */
        cs->bucket_alloc = apr_bucket_alloc_create(p);
        ap_create_sb_handle(&cs->sbh, p, my_child_num, my_thread_num);
        cs->c = c = ap_run_create_connection(p, ap_server_conf, sock, conn_id,
                                             cs->sbh, cs->bucket_alloc);
        if (!c) {
            ap_queue_info_push_pool(worker_queue_info, p);
            return;
        }
        apr_pool_pre_cleanup_register(p, cs, ptrans_pre_cleanup);
        ap_set_module_config(c->conn_config, &mpm_event_module, cs);
        c->current_thread = thd;
        c->cs = &cs->pub;

        ap_update_vhost_given_ip(c);
        rc = ap_pre_connection(c, sock);
        if (rc != OK && rc != DONE) {
            {
                static log_ratelimit_t rl;
                if (LOG_RATELIMIT(&rl, APLOG_DEBUG, 1, NULL, c)) {
                    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(00469)
                                  "process_socket: connection aborted (%d)", rc);
                }
            }
            close_connection(cs);
            return;
        }
    }
    else { /* The connection is scheduled back */
        c = cs->c;
        c->current_thread = thd;
        c->id = conn_id; /* thread number is part of ID */
        ap_update_sb_handle(cs->sbh, my_child_num, my_thread_num);
    }

    /* Suspended connections hooks run here and don't fall through */
    if (cs->suspended) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE7, 0, cs->c,
                      "resuming connection %" CS_FMT, CS_ARG(cs));
        take_suspended(cs);
        if (cs->continuation.fn) {
            /* The continuation of an ap_mpm_register_wait(), which may give
             * the connection back to this thread, this worker busy meanwhile
             * (SERVER_BUSY_WRITE, the handler's status).
             */
            ap_update_child_status(cs->sbh, SERVER_BUSY_WRITE, cs->r);
            if (run_user_continuation(cs, 1)) {
                goto resumed;
            }
        }
        return;
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE7, 0, cs->c,
                  "processing connection %" CS_FMT " (aborted %d, clogging %d)",
                  CS_ARG(cs), c->aborted, c->clogging_input_filters);

    if (cs->pub.state == CONN_STATE_LINGER || c->aborted) {
        cs->pub.state = CONN_STATE_LINGER;
        goto lingering_close;
    }

    if (cs->pub.state == CONN_STATE_PROCESSING
        /* If we have an input filter which 'clogs' the input stream,
         * like mod_ssl used to, lets just do the normal read from input
         * filters, like the Worker MPM does. Filters that need to write
         * where they would otherwise read, or read where they would
         * otherwise write, should set the sense appropriately.
         */
         || c->clogging_input_filters) {
 process_connection:
        processed = 1;
        cs->pub.state = CONN_STATE_PROCESSING;
        rc = ap_run_process_connection(c);
        if (cs->pending_wait && cs->pub.state != CONN_STATE_SUSPENDED) {
            /* The handler registered a wait but didn't suspend in the end */
            {
                static log_ratelimit_t rl;
                if (LOG_RATELIMIT(&rl, APLOG_DEBUG, 1, NULL, c)) {
                    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO()
                                  "ignoring the wait registered by a connection not "
                                  "suspended");
                }
            }
            if (cs->pending_wait->notifier) {
                /* Its notifier can be re-armed */
                notifier_wait_done(cs->pending_wait->notifier);
                cs->pending_wait->notifier = NULL;
            }
            cs->pending_wait = NULL;
        }
        /*
         * The process_connection hooks should set the appropriate connection
         * state upon return, for event MPM to either:
         * - CONN_STATE_LINGER: do lingering close;
         * - CONN_STATE_WRITE_COMPLETION: flush pending outputs using Timeout
         *   and wait for next incoming data using KeepAliveTimeout, then come
         *   back to process_connection() hooks;
         * - CONN_STATE_SUSPENDED: suspend the connection such that it now
         *   interacts with the MPM through suspend/resume_connection() hooks,
         *   and/or registered poll callbacks (PT_USER), and/or registered
         *   timed callbacks triggered by timer events;
         * - CONN_STATE_ASYNC_WAITIO: wait for read/write-ability of the underlying
         *   socket using Timeout and come back to process_connection() hooks when
         *   ready;
         * - CONN_STATE_KEEPALIVE: now handled by CONN_STATE_WRITE_COMPLETION
         *   to flush before waiting for next data (that might depend on it).
         * If a process_connection hook returns an error or no hook sets the state
         * to one of the above expected value, forcibly close the connection w/
         * CONN_STATE_LINGER.  This covers the cases where no process_connection
         * hook executes (DECLINED), or one returns OK w/o touching the state (i.e.
         * CONN_STATE_PROCESSING remains after the call) which can happen with
         * third-party modules not updated to work specifically with event MPM
         * while this was expected to do lingering close unconditionally with
         * worker or prefork MPMs for instance.
         */
        switch (rc) {
        case OK:
        case DONE: /* same as OK, fall through */
            if (cs->pub.state == CONN_STATE_PROCESSING) {
                cs->pub.state = CONN_STATE_LINGER;
            }
            else if (cs->pub.state == CONN_STATE_KEEPALIVE) {
                cs->pub.state = CONN_STATE_WRITE_COMPLETION;
            }
            rc = OK;
        }
        if (rc != OK || (cs->pub.state != CONN_STATE_LINGER
                         && cs->pub.state != CONN_STATE_ASYNC_WAITIO
                         && cs->pub.state != CONN_STATE_WRITE_COMPLETION
                         && cs->pub.state != CONN_STATE_SUSPENDED)) {
            {
                static log_ratelimit_t rl;
                if (LOG_RATELIMIT(&rl, APLOG_DEBUG, 1, NULL, c)) {
                    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(10111)
                                  "process_socket: connection processing returned %i "
                                  "(%sstate %i): closing",
                                  rc, rc ? "" : "unexpected ", (int)cs->pub.state);
                }
            }
            cs->pub.state = CONN_STATE_LINGER;
        }
        else if (c->aborted) {
            cs->pub.state = CONN_STATE_LINGER;
        }
        if (cs->pub.timed_out) {
            /* The last pass after a timed out wait: no waiting again */
            if (cs->pub.state == CONN_STATE_ASYNC_WAITIO) {
                cs->pub.state = CONN_STATE_LINGER;
            }
            cs->pub.timed_out = 0;
        }
        if (cs->pub.state == CONN_STATE_LINGER) {
            goto lingering_close;
        }
    }

    if (cs->pub.state == CONN_STATE_ASYNC_WAITIO) {
        apr_interval_time_t timeout;
        struct timeout_queue *q = NULL;
        timer_event_t *te = NULL;

        /* Set a read/write timeout for this connection, and let the
         * event thread poll for read/writeability.
         */
        ap_update_child_status(cs->sbh, SERVER_BUSY_READ, NULL);

        /* If the connection timeout is actually different than the waitio_q's,
         * use a timer event to honor it (e.g. mod_reqtimeout may enforce its
         * own timeouts per request stage).
         */
        timeout = ap_get_connection_timeout(c, cs->sc->s);
        if (timeout >= 0 && timeout != cs->sc->io_q->timeout) {
            /* Prevent the timer from firing before the pollset is updated */
            if (timeout < TIMERS_FUDGE_TIMEOUT) {
                timeout = TIMERS_FUDGE_TIMEOUT;
            }
            /* Inserted once recorded (cs->te), see pollset_add_at() */
            te = get_timer_event(timeout, NULL, cs, 0);
        }
        else {
            q = cs->sc->io_q;
        }
        if (!pollset_add(cs, CONN_SENSE_WANT_READ, q, te)) {
            cs->pub.state = CONN_STATE_LINGER;
            goto lingering_close;
        }

        return; /* queued */
    }

 resumed:
    if (cs->pub.state == CONN_STATE_WRITE_COMPLETION) {
        int pending = OK;

        /* Flush all pending outputs before going to CONN_STATE_KEEPALIVE or
         * straight to CONN_STATE_PROCESSING if inputs are pending already.
         */
        ap_update_child_status(cs->sbh, SERVER_BUSY_WRITE, NULL);

        if (!processed) {
            pending = ap_check_output_pending(c);
        }
        else if (ap_filter_should_yield(c->output_filters)) {
            pending = AGAIN;
        }
        if (pending == AGAIN) {
            /* Let the event thread poll for write */
            cs->pub.sense = CONN_SENSE_DEFAULT;
            if (pollset_add(cs, CONN_SENSE_WANT_WRITE, cs->sc->wc_q, NULL)) {
                return; /* queued */
            }
            /* Fall through lingering close */
        }
        else if (pending == OK) {
            /* Some data to process immediately? */
            pending = (c->keepalive == AP_CONN_KEEPALIVE
                       ? ap_check_input_pending(c)
                       : DONE);
            if (pending == AGAIN) {
                goto process_connection;
            }
        }
        if (pending != OK) {
            cs->pub.state = CONN_STATE_LINGER;
            goto lingering_close;
        }

        /* Fall through */
        cs->pub.state = CONN_STATE_KEEPALIVE;
    }

    if (cs->pub.state == CONN_STATE_KEEPALIVE) {
        ap_update_child_status(cs->sbh, SERVER_BUSY_KEEPALIVE, NULL);

        cs->pub.sense = CONN_SENSE_DEFAULT;
        if (!pollset_add(cs, CONN_SENSE_WANT_READ, cs->ka_sc->ka_q, NULL)) {
            cs->pub.state = CONN_STATE_LINGER;
            goto lingering_close;
        }

        return; /* queued */
    }

    if (cs->pub.state == CONN_STATE_SUSPENDED) {
        enter_suspended(cs);
        return; /* suspended */
    }

 lingering_close:
    process_lingering_close(cs);
}

static struct user_wait *make_user_wait(event_conn_state_t *cs,
                                        apr_pool_t *p,
                                        const apr_array_header_t *user_pfds,
                                        apr_interval_time_t timeout,
                                        ap_mpm_notifier_t *notifier);
static apr_status_t arm_user_wait(event_conn_state_t *cs,
                                  struct user_wait *user_wait);
static void arm_pending_wait(event_conn_state_t *cs);
static int run_user_continuation(event_conn_state_t *cs, int in_place);
static int claim_user_wait(struct user_wait *user_wait);
static void claimed_user_wait_timer(struct user_wait *user_wait);
static int wait_tq_arm(struct user_wait *user_wait,
                       apr_interval_time_t timeout);

/* The continuation to run since the wait fired (claimed), for why */
static APR_INLINE void set_user_continuation(event_conn_state_t *cs,
                                             struct user_wait *user_wait,
                                             ap_mpm_wait_result_e why)
{
    cs->continuation = user_wait->continuation;
    cs->continuation.pfds = user_wait->pfds;
    cs->continuation.why = why;
}

/* Whether pfds can be kept (AP_MPM_WAIT_KEEP_PFDS): with one-shot pfds, so
 * that a kept pfd outside of a wait fires once only (worker_poll implies
 * them).
 */
/* Whether the kept pfds are edge-triggered (APR_POLLET, epoll and kqueue,
 * with EVENT_WORKER_NOTIFY), else one-shot: an edge-triggered one is never
 * re-armed, but one that fired since its last wait is checked (poll()) when
 * a wait arms it, since its user may have stopped reading or writing before
 * EAGAIN, and no edge would come for what's pending (arm_kept_pfd()), unless
 * the user drained it (AP_MPM_WAIT_DRAINED).
 */
static int kept_pfds_et;

/* Whether a one-shot pfd that fired is disarmed as a whole (epoll), so that
 * nothing remains to remove from conn_pollset: not with kqueue, a filter per
 * event (EVFILT_READ, EVFILT_WRITE), the one that didn't fire stays armed.
 */
static int oneshot_disarms_fd = 1;

static APR_INLINE int kept_pfds_enabled(void)
{
#ifdef APR_POLLONESHOT
    return worker_poll;
#else
    return 0;
#endif
}

/* The index of the connection's kept pfd for the descriptor of pfd, or -1 */
static int kept_pfd_index(event_conn_state_t *cs, const apr_pollfd_t *pfd)
{
    int i;
    for (i = 0; i < cs->nkept; i++) {
        struct kept_pfd *kept = cs->kept[i];
        if (kept->pfd.desc_type == pfd->desc_type
            && (pfd->desc_type == APR_POLL_SOCKET
                ? kept->pfd.desc.s == pfd->desc.s
                : kept->pfd.desc.f == pfd->desc.f)) {
            return i;
        }
    }
    return -1;
}

static APR_INLINE struct kept_pfd *find_kept_pfd(event_conn_state_t *cs,
                                                 const apr_pollfd_t *pfd)
{
    int i = kept_pfd_index(cs, pfd);
    return (i < 0) ? NULL : cs->kept[i];
}

/* A new kept pfd for the descriptor of pfd, or NULL if the table is full
 * (the pfd is then registered for the wait only)
 */
static apr_status_t kept_anchor_cleanup(void *data);
static apr_status_t kept_pfd_cleanup(void *data);

/* The anchor of pfd's descriptor, or NULL if none and !create */
static struct kept_anchor *kept_anchor_of(const apr_pollfd_t *pfd, int create)
{
    struct kept_anchor *anchor = NULL;
    apr_pool_t *p;

    if (pfd->desc_type == APR_POLL_SOCKET) {
        (void)apr_socket_data_get((void **)&anchor, KEPT_ANCHOR_KEY,
                                  pfd->desc.s);
        if (anchor || !create) {
            return anchor;
        }
        p = apr_socket_pool_get(pfd->desc.s);
        anchor = apr_pcalloc(p, sizeof(*anchor));
        (void)apr_socket_data_set(pfd->desc.s, anchor, KEPT_ANCHOR_KEY, NULL);
    }
    else if (pfd->desc_type == APR_POLL_FILE) {
        /* The userdata of the file's pool, so keyed by the file too (e.g.
         * the pipes of a process share a pool)
         */
        char key[64];
        apr_snprintf(key, sizeof(key), KEPT_ANCHOR_KEY ":%pp",
                     (void *)pfd->desc.f);
        (void)apr_file_data_get((void **)&anchor, key, pfd->desc.f);
        if (anchor || !create) {
            return anchor;
        }
        p = apr_file_pool_get(pfd->desc.f);
        anchor = apr_pcalloc(p, sizeof(*anchor));
        (void)apr_file_data_set(pfd->desc.f, anchor, key, NULL);
    }
    else {
        return NULL;
    }
    /* No child cleanup (as apr_socket_data_set() and apr_file_data_set()
     * would register): a forked child must not unregister the descriptor
     * from the pollset it shares.
     */
    apr_pool_cleanup_register(p, anchor, kept_anchor_cleanup,
                              apr_pool_cleanup_null);
    return anchor;
}

static /*atomic*/ apr_uint32_t drain_epoch;
static int drain_epoch_passed(apr_uint32_t epoch);
static struct kept_pfd *make_kept_pfd(event_conn_state_t *cs,
                                      const apr_pollfd_t *pfd)
{
    struct kept_anchor *anchor;
    struct kept_pfd *kept;

    if (cs->nkept >= EVENT_KEPT_MAX) {
        return NULL;
    }
    anchor = kept_anchor_of(pfd, 0);
    if (anchor && anchor->kept) {
        /* Still kept for another connection, not released by its user (see
         * AP_MPM_WAIT_KEEP_PFDS): registered for the wait only.
         */
        {
            static log_ratelimit_t rl;
            if (LOG_RATELIMIT(&rl, APLOG_ERR, 1, ap_server_conf, NULL)) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, APLOGNO()
                             "pollfd kept by connection %" CS_FMT_TO " not released "
                             "by its user (ap_mpm_release_pfd())",
                             CS_ARG_TO(anchor->kept->cs));
            }
        }
        AP_DEBUG_ASSERT(0);
        return NULL;
    }
    /* Reuse a released one when no poller can hold an event for it anymore
     * (the drain epochs), so that the connection's pool doesn't grow with
     * its requests keeping pfds.
     */
    kept = NULL;
    if (!APR_RING_EMPTY(&cs->kept_free, kept_pfd, free_link)) {
        kept = APR_RING_FIRST(&cs->kept_free);
        if (drain_epoch_passed(kept->free_epoch)) {
            APR_RING_REMOVE(kept, free_link);
            memset(kept, 0, sizeof(*kept));
        }
        else {
            kept = NULL;
        }
    }
    if (!kept) {
        kept = apr_pcalloc(cs->p, sizeof(*kept));
    }
    kept->pfd = *pfd;
    kept->pfd.p = cs->p;
    kept->pt.type = PT_KEPT;
    kept->pt.baton = kept;
    kept->pfd.client_data = &kept->pt;
    kept->state = KEPT_NEW;
    kept->cs = cs;
    if (!anchor) {
        anchor = kept_anchor_of(pfd, 1);
    }
    if (anchor) {
        anchor->kept = kept;
        kept->anchor = anchor;
        apr_pool_cleanup_register(cs->p, kept, kept_pfd_cleanup,
                                  apr_pool_cleanup_null);
    }
    cs->kept[cs->nkept++] = kept;
    return kept;
}

/* Have the wait be on a kept pfd, for reqevents: without a syscall if it's
 * still armed for them, else (re-)armed or added (firing right away if it is
 * still ready). The wait is set before the state, read by the events after.
 * With rtnevents, a readiness remembered for reqevents is taken instead
 * (*rtnevents set, the pfd left disarmed): the caller completes the wait.
 */
static apr_status_t arm_kept_pfd(struct kept_pfd *kept,
                                 struct user_wait *user_wait,
                                 apr_int16_t reqevents,
                                 apr_int16_t *rtnevents)
{
#ifdef APR_POLLET
    int delivered = kept->delivered;
    kept->delivered = 0;
#endif
    kept->wait = user_wait;
#ifdef APR_POLLET
    if (kept_pfds_et && rtnevents && kept->pfd.reqevents == reqevents) {
        /* Edge-triggered, still registered for these events: no re-arm */
        for (;;) {
            apr_uint32_t state = apr_atomic_read32(&kept->state);
            if (state == KEPT_IDLE) {
                /* Nothing since its last wait (an edge would be latched) */
                if (apr_atomic_cas32(&kept->state, KEPT_WAITED,
                                     KEPT_IDLE) == KEPT_IDLE) {
                    return APR_SUCCESS;
                }
            }
            else if (state == KEPT_READY && (kept->latched & reqevents)) {
                if (apr_atomic_cas32(&kept->state, KEPT_FIRED,
                                     KEPT_READY) == KEPT_READY) {
                    *rtnevents = kept->latched & reqevents;
                    kept->delivered = 1;
                    return APR_SUCCESS;
                }
            }
            else if (state == KEPT_FIRED && delivered
                     && user_wait->drained) {
                /* Fired for the last wait only, which got its events, and
                 * its user drained it since: an edge from then on would be
                 * latched (KEPT_READY). Not if the last wait completed
                 * otherwise (the event may be latched after this arm).
                 */
                if (apr_atomic_cas32(&kept->state, KEPT_WAITED,
                                     KEPT_FIRED) == KEPT_FIRED) {
                    return APR_SUCCESS;
                }
            }
            else if (state == KEPT_READY || state == KEPT_FIRED) {
                /* Fired since its last wait (or ready for other events):
                 * marked waited first, so that an edge from now on fires
                 * it, then checked below.
                 */
                if (apr_atomic_cas32(&kept->state, KEPT_WAITED,
                                     state) == state) {
                    break;
                }
            }
            else {
                break; /* can't be (KEPT_NEW or KEPT_WAITED) */
            }
        }
        {
            apr_pollfd_t pfd = kept->pfd;
            apr_int32_t n = 0;
            pfd.reqevents = reqevents & ~APR_POLLET;
            pfd.rtnevents = 0;
            if (apr_poll(&pfd, 1, &n, 0) == APR_SUCCESS && n && pfd.rtnevents
                && apr_atomic_cas32(&kept->state, KEPT_FIRED,
                                    KEPT_WAITED) == KEPT_WAITED) {
                /* Ready already: the caller completes the wait (unless an
                 * edge claimed it meanwhile, then the event does)
                 */
                *rtnevents = pfd.rtnevents;
                kept->delivered = 1;
            }
        }
        return APR_SUCCESS;
    }
#endif
    if (kept->pfd.reqevents == reqevents
        && apr_atomic_cas32(&kept->state, KEPT_WAITED,
                            KEPT_IDLE) == KEPT_IDLE) {
        return APR_SUCCESS;
    }
    if (rtnevents && (kept->latched & reqevents)
        && apr_atomic_cas32(&kept->state, KEPT_FIRED,
                            KEPT_READY) == KEPT_READY) {
        *rtnevents = kept->latched & reqevents;
        return APR_SUCCESS;
    }
    /* New, fired, ready (an event raced the CAS above) or other events: an
     * event armed for the previous events may still fire for this wait
     * before the re-arm, with rtnevents it didn't ask for (spurious).
     */
    kept->pfd.reqevents = reqevents;
    apr_atomic_set32(&kept->state, KEPT_WAITED);
    return apr_pollset_add(conn_pollset, &kept->pfd);
}

/* An event on a kept pfd: the wait on it, to claim, or NULL if none
 * (the readiness is then remembered for the next wait, its rtnevents set
 * before the state, read by the arm after)
 */
static struct user_wait *kept_pfd_fired(struct kept_pfd *kept,
                                        apr_int16_t rtnevents)
{
    /* A wait may arm it (KEPT_IDLE -> KEPT_WAITED) or complete otherwise
     * (KEPT_WAITED -> KEPT_IDLE) meanwhile: retry on what the CAS found, the
     * pfd is disarmed so this event must not be lost.
     */
    for (;;) {
        apr_uint32_t state = apr_atomic_read32(&kept->state);
        if (state == KEPT_WAITED) {
            if (apr_atomic_cas32(&kept->state, KEPT_FIRED,
                                 KEPT_WAITED) == KEPT_WAITED) {
                return kept->wait;
            }
        }
        else if (state == KEPT_IDLE) {
            kept->latched = rtnevents;
            if (apr_atomic_cas32(&kept->state, KEPT_READY,
                                 KEPT_IDLE) == KEPT_IDLE) {
                return NULL;
            }
        }
        else if (kept_pfds_et && state == KEPT_FIRED) {
            /* Edge-triggered, a new edge while its wait is completed:
             * remembered for the next wait.
             */
            kept->latched = rtnevents;
            if (apr_atomic_cas32(&kept->state, KEPT_READY,
                                 KEPT_FIRED) == KEPT_FIRED) {
                return NULL;
            }
        }
        else if (kept_pfds_et && state == KEPT_READY) {
            kept->latched |= rtnevents; /* remembered already */
            return NULL;
        }
        else {
            /* Not armed (stale event after a release or a re-arm) */
            return NULL;
        }
    }
}

/* The wait of a fired kept pfd was completed otherwise (claimed by another
 * thread): remember the readiness, unless the next wait re-armed it already.
 */
static APR_INLINE void kept_pfd_unclaimed(struct kept_pfd *kept,
                                          apr_int16_t rtnevents)
{
    kept->latched = rtnevents;
    (void)apr_atomic_cas32(&kept->state, KEPT_READY, KEPT_FIRED);
}

/* The wait completes: its kept pfds that didn't fire stay armed, idle */
static void idle_kept_pfds(event_conn_state_t *cs,
                           struct user_wait *user_wait)
{
    int i;
    for (i = 0; i < cs->nkept; i++) {
        struct kept_pfd *kept = cs->kept[i];
        if (kept->wait == user_wait) {
            (void)apr_atomic_cas32(&kept->state, KEPT_IDLE, KEPT_WAITED);
        }
    }
}

/* Unregister the i-th kept pfd of the connection (no wait is on it) */
static apr_status_t release_kept_pfd(event_conn_state_t *cs, int i)
{
    struct kept_pfd *kept = cs->kept[i];
    apr_status_t rc = APR_SUCCESS;

    if (apr_atomic_read32(&kept->state) != KEPT_NEW) {
        rc = apr_pollset_remove(conn_pollset, &kept->pfd);
        if (APR_STATUS_IS_NOTFOUND(rc)) {
            rc = APR_SUCCESS;
        }
    }
    kept->wait = NULL;
    if (kept->anchor) {
        kept->anchor->kept = NULL;
        kept->anchor = NULL;
        apr_pool_cleanup_kill(cs->p, kept, kept_pfd_cleanup);
    }
    cs->kept[i] = cs->kept[--cs->nkept];

    /* Reusable once the pollers moved past this epoch (make_kept_pfd()) */
    kept->free_epoch = apr_atomic_inc32(&drain_epoch);
    APR_RING_INSERT_TAIL(&cs->kept_free, kept, kept_pfd, free_link);
    return rc;
}

static int kept_index(event_conn_state_t *cs, const struct kept_pfd *kept)
{
    int i;
    for (i = 0; i < cs->nkept; i++) {
        if (cs->kept[i] == kept) {
            return i;
        }
    }
    return -1;
}

/* The safety net: the pool of a descriptor still kept is cleaned up (it's
 * about to be closed), release it first.
 */
static apr_status_t kept_anchor_cleanup(void *data)
{
    struct kept_anchor *anchor = data;
    struct kept_pfd *kept = anchor->kept;

    if (kept) {
        int i = kept_index(kept->cs, kept);
        if (i >= 0) {
            (void)release_kept_pfd(kept->cs, i);
        }
        else {
            anchor->kept = NULL;
            kept->anchor = NULL;
        }
    }
    return APR_SUCCESS;
}

/* The pool of the connection keeping a descriptor is cleaned up first (it's
 * released already, or the child is exiting): unlink the descriptor's anchor.
 */
static apr_status_t kept_pfd_cleanup(void *data)
{
    struct kept_pfd *kept = data;

    if (kept->anchor) {
        kept->anchor->kept = NULL;
        kept->anchor = NULL;
    }
    return APR_SUCCESS;
}

/* Unregister the kept pfds still there when the connection is resumed (the
 * request is done, its users release only the sockets they give up before,
 * see AP_MPM_WAIT_KEEP_PFDS) or closed (possibly while suspended, e.g.
 * killed): an event on them would be for this connection (its cs->p)
 * otherwise, and the connection's socket is polled by the MPM from now on.
 */
static void release_kept_pfds(event_conn_state_t *cs)
{
    while (cs->nkept > 0) {
        (void)release_kept_pfd(cs, cs->nkept - 1);
    }
}

/* The wait of a notifier is over, completed or dropped before being armed:
 * notifying it does nothing from now on, until it's re-armed for the next
 * wait (event_notifier_rearm()).
 */
static void notifier_wait_done(ap_mpm_notifier_t *notifier)
{
    apr_thread_mutex_lock(notifiers_mutex);
    if (notifier->queued) {
        APR_RING_REMOVE(notifier, link);
        notifier->queued = 0;
    }
    notifier->armed = 0;
    notifier->done = 1;
    apr_thread_mutex_unlock(notifiers_mutex);
}

static apr_status_t user_wait_cleanup(void *data)
{
    struct user_wait *user_wait = data;
    apr_array_header_t *pfds = user_wait->pfds;
    apr_status_t rc, final_rc = APR_SUCCESS;
    int i;

    /* Run by the claim's winner when the wait completes, or by the
     * destruction of its registrant's pool while it's armed (e.g. a killed
     * connection): claim it then, only the winner releases its timeout (its
     * entry in a timeout queue would be left linked otherwise).
     */
    if (apr_atomic_cas32(&user_wait->claim, WAIT_CLAIMED,
                         WAIT_ARMED) == WAIT_ARMED) {
        claimed_user_wait_timer(user_wait);
    }
    AP_DEBUG_ASSERT(apr_atomic_read32(&user_wait->claim) == WAIT_CLAIMED);

    /* All the pollfds should be added/removed atomically, so synchronize
     * with arm_user_wait().
     */
    apr_thread_mutex_lock(user_wait->mutex);
    idle_kept_pfds(user_wait->cs, user_wait);
    for (i = 0; i < pfds->nelts; i++) {
        apr_pollfd_t *pfd = &APR_ARRAY_IDX(pfds, i, apr_pollfd_t);
        if (pfd->client_data) {
#ifdef APR_POLLONESHOT
            if (pfd->rtnevents && (pfd->reqevents & APR_POLLONESHOT)
                && (oneshot_disarms_fd
                    || !(pfd->reqevents & APR_POLLIN)
                    || !(pfd->reqevents & APR_POLLOUT))) {
                /* It fired: disarmed by the kernel already (else its other
                 * event may fire later, for this wait's pfd copy reused by
                 * a next one: remove it)
                 */
                pfd->client_data = NULL;
                continue;
            }
#endif
            rc = apr_pollset_remove(conn_pollset, pfd);
            if (rc != APR_SUCCESS && !APR_STATUS_IS_NOTFOUND(rc)) {
                final_rc = rc;
            }
            pfd->client_data = NULL;
        }
    }
    apr_thread_mutex_unlock(user_wait->mutex);

    /* The wait completes: notifying it does nothing from now on */
    if (user_wait->notifier) {
        notifier_wait_done(user_wait->notifier);
        user_wait->notifier = NULL;
    }

    /* Claimable again by the next wait only (an event of this one fired
     * before its pfds were removed is dropped, see stale_user_wait())
     */
    apr_atomic_set32(&user_wait->claim, WAIT_IDLE);

    if (final_rc) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, final_rc, user_wait->cs->c,
                      APLOGNO() "can't remove a wait's pollfd from the "
                      "pollset: stopping the child gracefully");
        AP_DEBUG_ASSERT(0);
        signal_threads(ST_GRACEFUL);
    }
    return final_rc;
}

/* A wait of a SUSPENDED connection, to be armed by arm_user_wait(), in the
 * connection's wait: its memory (pt, pfds) lives in cs->p so that an event
 * fired for it stays readable as long as the connection, whichever thread
 * got it. The pfds are copied into the other array than the previous
 * wait's, which may be the one given to the continuation running this.
 */
static struct user_wait *make_user_wait(event_conn_state_t *cs,
                                        apr_pool_t *p,
                                        const apr_array_header_t *user_pfds,
                                        apr_interval_time_t timeout,
                                        ap_mpm_notifier_t *notifier)
{
    struct user_wait *user_wait = cs->wait;
    apr_array_header_t *pfds;
    int i;

    if (!user_wait) {
        user_wait = apr_pcalloc(cs->p, sizeof(*user_wait));
        apr_thread_mutex_create(&user_wait->mutex, APR_THREAD_MUTEX_DEFAULT,
                                cs->p);
        user_wait->pfds_buf[0] = apr_array_make(cs->p, 2, sizeof(apr_pollfd_t));
        user_wait->pfds_buf[1] = apr_array_make(cs->p, 2, sizeof(apr_pollfd_t));
        user_wait->pt_buf[0].type = user_wait->pt_buf[1].type = PT_USER;
        user_wait->pt_buf[0].baton = user_wait->pt_buf[1].baton = user_wait;
        user_wait->cs = cs;
        APR_RING_ELEM_INIT(&user_wait->to, link);
        user_wait->to.owner = user_wait;
        cs->wait = user_wait;
    }
    AP_DEBUG_ASSERT(apr_atomic_read32(&user_wait->claim) == WAIT_IDLE);
    AP_DEBUG_ASSERT(!user_wait->tq && !user_wait->to.q);

    user_wait->pfds_cur ^= 1;
    pfds = user_wait->pfds_buf[user_wait->pfds_cur];
    apr_array_clear(pfds);
    for (i = 0; user_pfds && i < user_pfds->nelts; i++) {
        APR_ARRAY_PUSH(pfds, apr_pollfd_t) =
            APR_ARRAY_IDX(user_pfds, i, apr_pollfd_t);
    }
    user_wait->pfds = pfds;
    user_wait->pool = p;
    user_wait->timeout = timeout;
    user_wait->timer = NULL;
    user_wait->next = NULL;
    user_wait->chained = 0;
    memset(&user_wait->continuation, 0, sizeof(user_wait->continuation));
    user_wait->wait_notified = 0;
    user_wait->notifier = notifier;
    return user_wait;
}

/* Put the user pollfds of a wait into the listener pollset, with its timer */
static apr_status_t arm_user_wait(event_conn_state_t *cs,
                                  struct user_wait *user_wait)
{
    apr_pool_t *p = user_wait->pool;
    apr_array_header_t *pfds = user_wait->pfds;
    apr_interval_time_t timeout = user_wait->timeout;
    apr_status_t rc, final_rc = APR_SUCCESS;
    listener_poll_type *pt = &user_wait->pt_buf[user_wait->pfds_cur];
    int i;
#ifdef EVENT_WORKER_NOTIFY
    int ready = 0;
#endif

    cs->pub.state = CONN_STATE_SUSPENDED;
    cs->user_wait = user_wait;

    apr_pool_pre_cleanup_register(p, user_wait, user_wait_cleanup);
    cs->te = NULL;

    /* All the pollfds should be added/removed atomically, so synchronize
     * with user_wait_cleanup(): from the claim armed on, a claimer runs the
     * cleanup only once the wait is armed entirely (timer, pfds, notifier),
     * also if its timer expires before (this thread preempted).
     */
    apr_thread_mutex_lock(user_wait->mutex);

    /* Claimable from now on (its timer or pfds may fire below) */
    apr_atomic_set32(&user_wait->claim, WAIT_ARMED);

    if (timeout >= 0) {
        /* Prevent the timer from firing before the pollset is updated */
        if (timeout < TIMERS_FUDGE_TIMEOUT) {
            timeout = TIMERS_FUDGE_TIMEOUT;
        }
        /* The timeout queue of its value if declared, else a timer: recorded
         * before it's inserted, since the listener may pop it and claim the
         * wait as soon as it is (this thread preempted for longer than the
         * timeout): it then finds it this wait's (timer and cs->te),
         * frees it and clears them.
         */
        if (!wait_tq_arm(user_wait, timeout)) {
            timer_event_t *te = get_timer_event(timeout, wait_timer_cb,
                                                user_wait, 0);
            user_wait->timer = cs->te = te;
            insert_timer_event(te);
        }
    }

    for (i = 0; i < pfds->nelts; i++) {
        apr_pollfd_t *pfd = &APR_ARRAY_IDX(pfds, i, apr_pollfd_t);
        pfd->rtnevents = 0;
        if (pfd->reqevents) {
            struct kept_pfd *kept = NULL;

            if (pfd->reqevents & APR_POLLIN) {
                pfd->reqevents |= APR_POLLHUP;
            }
            pfd->reqevents |= APR_POLLERR;
#ifdef APR_POLLONESHOT
            pfd->reqevents |= APR_POLLONESHOT; /* see pollset_add_at() */
#endif

            /* A kept pfd is registered by its record, this copy only gets
             * the rtnevents (and user_wait_cleanup() skips it)
             */
            if (cs->nkept) {
                kept = find_kept_pfd(cs, pfd);
            }
            if (!kept && user_wait->keep) {
                kept = make_kept_pfd(cs, pfd);
            }
            if (kept) {
                apr_int16_t events = pfd->reqevents, *rtnevents = NULL;
#ifdef APR_POLLET
                if (kept_pfds_et) {
                    events = (events & ~APR_POLLONESHOT) | APR_POLLET;
                }
#endif
#ifdef EVENT_WORKER_NOTIFY
                /* A readiness remembered for it completes the wait right
                 * away (below), by this polling worker.
                 */
                if (worker_thread_polls) {
                    rtnevents = &pfd->rtnevents;
                }
#endif
                pfd->client_data = NULL;
                rc = arm_kept_pfd(kept, user_wait, events, rtnevents);
                if (rc != APR_SUCCESS) {
                    final_rc = rc;
                }
#ifdef EVENT_WORKER_NOTIFY
                else if (pfd->rtnevents) {
                    ready = 1;
                }
#endif
                continue;
            }

            pfd->client_data = pt;
            rc = apr_pollset_add(conn_pollset, pfd);
            if (rc != APR_SUCCESS) {
                final_rc = rc;
            }
        }
        else {
            pfd->client_data = NULL;
        }
    }

    /* Notifiable from now on, or completed right away if it was notified
     * already (before the wait was armed). This is done before releasing
     * user_wait->mutex, which the listener's user_wait_cleanup() takes
     * first, so the wait can't complete (and its pool go away) meanwhile.
     */
    if (final_rc == APR_SUCCESS && user_wait->notifier) {
        ap_mpm_notifier_t *notifier = user_wait->notifier;
        int wake = 0;
        apr_thread_mutex_lock(notifiers_mutex);
        notifier->armed = 1;
        if (notifier->notified) {
            APR_RING_INSERT_TAIL(notified_user_waits, notifier,
                                 ap_mpm_notifier_t, link);
            notifier->queued = 1;
            wake = 1;
        }
        apr_thread_mutex_unlock(notifiers_mutex);
        if (wake) {
            wakeup_listener();
        }
    }
    apr_thread_mutex_unlock(user_wait->mutex);

    if (final_rc) {
        AP_DEBUG_ASSERT(0);
        signal_threads(ST_GRACEFUL);
    }
#ifdef EVENT_WORKER_NOTIFY
    else if (ready && claim_user_wait(user_wait)) {
        /* Some kept pfd was ready already (its rtnevents set): complete the
         * wait now, queued for this worker which pops it next (the caller
         * doesn't touch the connection once armed), rather than re-arming
         * it to have it fire again. Unless completed otherwise meanwhile,
         * which then reports these rtnevents too.
         */
        if (user_wait->continuation.fn) {
            set_user_continuation(cs, user_wait, AP_MPM_WAIT_READY);
        }
        apr_pool_cleanup_run(user_wait->pool, user_wait, user_wait_cleanup);
        cs->user_wait = NULL;
        if (push2worker(cs, NULL, BACKLOG_CONTINUATION, event_time_now(),
                        NULL, 1)) {
            worker_wake_queued = 1;
        }
    }
#endif
    return final_rc;
}

/* Create a notifier for a wait (ap_mpm_notifier_create()) */
static apr_status_t event_notifier_create(ap_mpm_notifier_t **notifier,
                                          conn_rec *c, apr_pool_t *p)
{
    if (c->master || !ap_get_module_config(c->conn_config, &mpm_event_module)) {
        return APR_ENOTIMPL; /* not a connection of this MPM */
    }
    *notifier = apr_pcalloc(p, sizeof(**notifier));
    return APR_SUCCESS;
}

/* Re-arm a notifier for another wait (ap_mpm_notifier_rearm()), once its
 * previous wait is done (or none was registered): new again, a notification
 * made until now dropped. Refused while its wait is registered or armed.
 */
static apr_status_t event_notifier_rearm(ap_mpm_notifier_t *notifier)
{
    apr_status_t rv = APR_SUCCESS;

    apr_thread_mutex_lock(notifiers_mutex);
    if (notifier->used && !notifier->done) {
        rv = APR_EBUSY; /* its wait is in flight */
    }
    else {
        AP_DEBUG_ASSERT(!notifier->armed && !notifier->queued);
        notifier->used = 0;
        notifier->done = 0;
        notifier->notified = 0;
        notifier->wait = NULL;
    }
    apr_thread_mutex_unlock(notifiers_mutex);
    return rv;
}

/* Notify a wait (ap_mpm_notify()), from any thread: an armed wait is queued
 * to the listener (notified_user_waits), which completes it after its next
 * poll; a wait not armed yet completes once armed (arm_user_wait()). Once
 * the wait has completed, user_wait_cleanup() has disarmed it so nothing is
 * done, but for the notification recorded, which a re-arm drops
 * (event_notifier_rearm()).
 *
 * A polling worker completes an armed wait itself (EVENT_WORKER_NOTIFY): it
 * claims it under notifiers_mutex, so that it can't complete otherwise
 * meanwhile (user_wait_cleanup() disarms it there), but frees its timer
 * after (claimed_user_wait_timer()), then completes it like the listener
 * does and queues the continuation for itself (worker_wake_queued).
 */
static int event_notify(ap_mpm_notifier_t *notifier)
{
    int wake = 0;
#ifdef EVENT_WORKER_NOTIFY
    struct user_wait *user_wait = NULL;
#endif

    apr_thread_mutex_lock(notifiers_mutex);
    notifier->notified = 1;
    if (notifier->armed && !notifier->queued) {
#ifdef EVENT_WORKER_NOTIFY
        if (worker_thread_polls) {
            if (apr_atomic_cas32(&notifier->wait->claim, WAIT_CLAIMED,
                                 WAIT_ARMED) == WAIT_ARMED) {
                user_wait = notifier->wait;
            }
            /* else completed otherwise already, nothing to do */
        }
        else
#endif
        {
            APR_RING_INSERT_TAIL(notified_user_waits, notifier, ap_mpm_notifier_t,
                                 link);
            notifier->queued = 1;
            wake = 1;
        }
    }
    apr_thread_mutex_unlock(notifiers_mutex);

#ifdef EVENT_WORKER_NOTIFY
    if (user_wait) {
        event_conn_state_t *cs = user_wait->cs;

        AP_DEBUG_ASSERT(cs->user_wait == user_wait);
        AP_DEBUG_ASSERT(cs->pub.state == CONN_STATE_SUSPENDED);
        claimed_user_wait_timer(user_wait);
        if (user_wait->continuation.fn) {
            set_user_continuation(cs, user_wait, AP_MPM_WAIT_NOTIFIED);
        }
        apr_pool_cleanup_run(user_wait->pool, user_wait,
                             user_wait_cleanup);
        cs->user_wait = NULL;
        if (push2worker(cs, NULL, BACKLOG_CONTINUATION, event_time_now(),
                        NULL, 1)) {
            worker_wake_queued = 1;
        }
        return OK;
    }
#endif

    if (wake) {
        wakeup_listener();
    }
    return OK;
}

/* Suspend a request until some pfds are ready, its notifier is notified or a
 * timeout (ap_mpm_register_wait()). The wait is armed once no thread runs
 * the connection anymore, i.e. when the handler has returned SUSPENDED
 * (enter_suspended()) or when the continuation of a previous wait has
 * returned (process_socket()).
 */
static apr_status_t event_register_wait(conn_rec *c, apr_pool_t *p,
                                        const apr_array_header_t *pfds,
                                        apr_interval_time_t timeout,
                                        ap_mpm_notifier_t *notifier,
                                        unsigned int flags,
                                        ap_mpm_continuation_fn_t *fn, void *baton)
{
    event_conn_state_t *cs;
    struct user_wait *user_wait;

    if (c->master) {
        return APR_ENOTIMPL; /* secondary connections not handled (yet) */
    }
    cs = ap_get_module_config(c->conn_config, &mpm_event_module);
    if (!cs) {
        return APR_ENOTIMPL; /* not a connection of this MPM */
    }
    if (!fn || ((!pfds || pfds->nelts <= 0) && !notifier && timeout < 0)) {
        return APR_EINVAL; /* nothing would fire the wait */
    }
    if (cs->pending_wait || (cs->suspended && !cs->in_continuation)) {
        /* One wait at a time, and not from another thread */
        return APR_EBUSY;
    }

    if (notifier) {
        int used;
        apr_thread_mutex_lock(notifiers_mutex);
        used = notifier->used;
        notifier->used = 1;
        apr_thread_mutex_unlock(notifiers_mutex);
        if (used) {
            return APR_EBUSY; /* a single wait until re-armed */
        }
    }

    user_wait = make_user_wait(cs, p, pfds, timeout, notifier);
    if (notifier) {
        /* Read by event_notify() once armed (under notifiers_mutex) */
        notifier->wait = user_wait;
    }
    user_wait->continuation.fn = fn;
    user_wait->continuation.baton = baton;
    user_wait->keep = ((flags & AP_MPM_WAIT_KEEP_PFDS)
                       && kept_pfds_enabled());
    user_wait->drained = !!(flags & AP_MPM_WAIT_DRAINED);
    cs->pending_wait = user_wait;
    return APR_SUCCESS;
}

/* Release a descriptor kept for whichever connection
 * (ap_mpm_release_pfd(), ap_mpm_release_pfds()), from the thread running
 * it, no wait pending nor armed.
 */
static apr_status_t event_release_pfd(const apr_pollfd_t *pfd)
{
    struct kept_anchor *anchor = kept_anchor_of(pfd, 0);
    struct kept_pfd *kept = (anchor) ? anchor->kept : NULL;
    event_conn_state_t *cs;
    int i;

    if (!kept) {
        return APR_SUCCESS; /* not kept */
    }
    cs = kept->cs;
    if (cs->pending_wait || cs->user_wait) {
        return APR_EBUSY;
    }
    i = kept_index(cs, kept);
    AP_DEBUG_ASSERT(i >= 0);
    return (i >= 0) ? release_kept_pfd(cs, i) : APR_SUCCESS;
}

/* Arm the pending wait of a connection, or run its continuation with
 * AP_MPM_WAIT_ERROR if that fails.
 */
static void arm_pending_wait(event_conn_state_t *cs)
{
    struct user_wait *user_wait = cs->pending_wait;
    apr_status_t rc;

    cs->pending_wait = NULL;
    rc = arm_user_wait(cs, user_wait);
    if (rc == APR_SUCCESS) {
        return;
    }
    {
        static log_ratelimit_t rl;
        if (LOG_RATELIMIT(&rl, APLOG_ERR, 1, NULL, cs->c)) {
            ap_log_cerror(APLOG_MARK, APLOG_ERR, rc, cs->c, APLOGNO()
                          "suspended connection: can't wait for its pollfds");
        }
    }
    if (!claim_user_wait(user_wait)) {
        return; /* completed by another thread already (some pfds armed) */
    }
    apr_pool_cleanup_run(user_wait->pool, user_wait, user_wait_cleanup);
    cs->user_wait = NULL;
    set_user_continuation(cs, user_wait, AP_MPM_WAIT_ERROR);
    (void)run_user_continuation(cs, 0);
}

/* Mark a SUSPENDED connection as resumed, for write completion (or lingering
 * close).
 */
static void leave_suspended_state(event_conn_state_t *cs)
{
    release_kept_pfds(cs);
    apr_atomic_dec32(&event_counts.suspended_count);
    cs->c->suspended_baton = NULL;
    cs->c->sbh = cs->sbh;
    cs->suspended = 0;

    cs->pub.sense = CONN_SENSE_DEFAULT;
    if (cs->pub.state != CONN_STATE_LINGER) {
        cs->pub.state = CONN_STATE_WRITE_COMPLETION;
    }
}

/* Put a SUSPENDED connection back into a queue. */
static void leave_suspended(event_conn_state_t *cs)
{
    leave_suspended_state(cs);
    if (cs->pub.state != CONN_STATE_LINGER) {
        if (pollset_add(cs, CONN_SENSE_WANT_WRITE, cs->sc->wc_q, NULL)) {
            return; /* queued */
        }
        /* fall through lingering close on error */
        cs->pub.state = CONN_STATE_LINGER;
    }
    process_lingering_close(cs);
}

static apr_status_t event_resume_suspended(conn_rec *c)
{
    event_conn_state_t *cs = c->suspended_baton;

    AP_DEBUG_ASSERT(cs != NULL);
    AP_DEBUG_ASSERT(cs->suspended);
    if (cs == NULL) {
        ap_log_cerror (APLOG_MARK, LOG_WARNING, 0, c, APLOGNO(02615)
                "event_resume_suspended: suspended_baton is NULL");
        return APR_EINVAL;
    }
    if (!cs->suspended) {
        ap_log_cerror (APLOG_MARK, LOG_WARNING, 0, c, APLOGNO(02616)
                "event_resume_suspended: thread isn't suspended");
        return APR_EINVAL;
    }
    if (cs->in_continuation) {
        /* Called from a continuation: resume the connection when the
         * continuation returns (process_socket()), since the connection must
         * not be queued while this thread still runs it.
         */
        cs->continuation_pending = 1;
        return APR_SUCCESS;
    }
    leave_suspended(cs);
    return APR_SUCCESS;
}

/* Run the continuation of a fired wait (on a worker thread), then arm the
 * next wait or resume the connection, as the continuation asked. With
 * in_place (from process_socket()), a resumed connection is given back to the
 * caller to go on with its write completion in this thread (returns 1),
 * rather than queued to the listener for writing: it would be dispatched
 * right back to a worker, being writable most of the time, for a round trip
 * through the listener and an idle worker's wakeup per request.
 */
static int run_user_continuation(event_conn_state_t *cs, int in_place)
{
    struct user_continuation continuation = cs->continuation;

    memset(&cs->continuation, 0, sizeof(cs->continuation));
    cs->continuation_pending = 0;

    cs->in_continuation = 1;
    continuation.fn(cs->c, cs->r, continuation.why, continuation.pfds, continuation.baton);
    cs->in_continuation = 0;

    if (cs->pending_wait) {
        cs->continuation_pending = 0;
        arm_pending_wait(cs);
    }
    else {
        if (!cs->continuation_pending) {
            /* The continuation neither registers a wait again nor gives
             * the connection back: close it.
             */
            {
                static log_ratelimit_t rl;
                if (LOG_RATELIMIT(&rl, APLOG_ERR, 1, NULL, cs->c)) {
                    ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, cs->c, APLOGNO()
                                  "suspended connection abandoned by its "
                                  "continuation");
                }
            }
            cs->pub.state = CONN_STATE_LINGER;
        }
        cs->continuation_pending = 0;
        if (in_place) {
            leave_suspended_state(cs);
            return 1;
        }
        leave_suspended(cs);
    }
    return 0;
}

/* conns_this_child has gone to zero or below.  See if the admin coded
   "MaxConnectionsPerChild 0", and keep going in that case.  Doing it this way
   simplifies the hot path in worker_thread */
static void check_infinite_requests(void)
{
    if (ap_max_requests_per_child) {
        ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ap_server_conf,
                     "Stopping process due to MaxConnectionsPerChild");
        signal_threads(ST_GRACEFUL);
    }
    /* keep going */
    conns_this_child = APR_INT32_MAX;
}

static void set_child_dying(void)
{
    volatile process_score *ps;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, "quiescing");
    ps = &ap_scoreboard_image->parent[ap_child_slot];
    ps->quiescing = 1;

    apr_atomic_set32(&dying, 1);
    /* definitively with dying = 1 */
    disable_listensocks(event_time_now(), ACCEPT_OFF_LIMIT);
    ap_close_listeners_ex(my_bucket->listeners);

#if 0
    {
        int i;
        for (i = 0; i < threads_per_child; ++i) {
            ap_update_child_status_from_indexes(ap_child_slot, i,
                                                SERVER_GRACEFUL, NULL);
        }
    }
#endif

    /* wake up idle worker threads */
    ap_queue_interrupt_all(worker_queue);
    ring_doorbell();
    /* wake up the main thread */
    kill(ap_my_pid, SIGTERM);

    /* No new connections will use the idle pools */
    ap_queue_info_free_idle_pools(worker_queue_info);
}

static void unblock_signal(int sig)
{
    sigset_t sig_mask;

    sigemptyset(&sig_mask);
    sigaddset(&sig_mask, sig);
#if defined(SIGPROCMASK_SETS_THREAD_MASK)
    sigprocmask(SIG_UNBLOCK, &sig_mask, NULL);
#else
    pthread_sigmask(SIG_UNBLOCK, &sig_mask, NULL);
#endif
}

static void dummy_signal_handler(int sig)
{
    /* XXX If specifying SIG_IGN is guaranteed to unblock a syscall,
     *     then we don't need this goofy function.
     */
}


#if HAVE_SERF
static apr_status_t s_socket_add(void *user_wait,
                                 apr_pollfd_t *pfd,
                                 void *serf_baton)
{
    s_baton_t *s = (s_baton_t*)user_wait;
    /* XXXXX: recycle listener_poll_types */
    listener_poll_type *pt = ap_malloc(sizeof(*pt));
    pt->type = PT_SERF;
    pt->baton = serf_baton;
    pfd->client_data = pt;
    return apr_pollset_add(s->pollset, pfd);
}

static apr_status_t s_socket_remove(void *user_wait,
                                    apr_pollfd_t *pfd,
                                    void *serf_baton)
{
    s_baton_t *s = (s_baton_t*)user_wait;
    listener_poll_type *pt = pfd->client_data;
    free(pt);
    return apr_pollset_remove(s->pollset, pfd);
}
#endif

#if HAVE_SERF
static void init_serf(apr_pool_t *p)
{
    s_baton_t *baton = NULL;

    baton = apr_pcalloc(p, sizeof(*baton));
    baton->pollset = event_pollset;
    /* TODO: subpools, threads, reuse, etc.  -- currently use malloc() inside :( */
    baton->pool = p;

    g_serf = serf_context_create_ex(baton,
                                    s_socket_add,
                                    s_socket_remove, p);

    ap_register_provider(p, "mpm_serf",
                         "instance", "0", g_serf);
}
#endif

/* A backlog connection is both in the worker_queue (for a worker to pull
 * it ASAP) and in the backlog_q (counted, the lingering ones for the listener
 * to enforce their timeout).
 * The worker_queue can do the queuing on both queues for us, that is
 * consistently and safely push/pop to/from both queues under its lock,
 * thanks to a callback called when an event is pushed and popped.
 */
static void conn_state_backlog_cb(void *baton, int pushed)
{
    event_conn_state_t *cs = baton;

    if (pushed) {
        /* Under the worker_queue's lock, but the pusher can't do it after:
         * the connection may be popped and run by then. A lingering one
         * waits LINGER_READ_TIMEOUT at most.
         */
        struct timeout_queue *q = backlog_conn_q;
        if (cs->pub.state == CONN_STATE_LINGER && cs->linger_since) {
            q = backlog_linger_q;
        }
        if (TO_QUEUE_APPEND(q, &cs->to)) {
            wakeup_listener();
        }
    }
    else { /* popped */
        TO_QUEUE_REMOVE(cs->to.q, &cs->to);

        /* not in backlog anymore */
        cs_qe(cs)->cb = NULL;
    }
}

static void timer_event_backlog_cb(void *baton, int pushed)
{
    timer_event_t *te = baton;
    ap_assert(te && te_qe(te));

    if (pushed) {
        apr_atomic_inc32(&event_counts.timers_count);
    }
    else { /* popped */
        apr_atomic_dec32(&event_counts.timers_count);

        /* not in backlog anymore */
        te_qe(te)->cb = NULL;
    }
}

/*
 * Pre-condition: cs is neither in event_pollset nor a queue
 * this function may only be called by the listener, or by a worker for a
 * wait it notified (event_notify(), by_worker), which neither rings the
 * doorbell nor stops accepting (the listener's): returns whether the event
 * was queued.
 */
static int push2worker(event_conn_state_t *cs, timer_event_t *te,
                       backlog_class_e qclass, apr_time_t now,
                       int *above_limit, int by_worker)
{
    ap_queue_event_t *qe;
    apr_status_t rc;
    int busy;

    ap_assert((cs != NULL) ^ (te != NULL));

    busy = (ap_queue_info_idlers_dec(worker_queue_info) < 0);
    /* Might need to kindle the fire by not accepting new connections until
     * the situation settles down. The listener and new idling workers will
     * test for should_enable_listensocks() to recover (when suitable). The
     * waits build up only when the workers are busy, but the connections can
     * reach their limit anyway (connections_full(), e.g. with idle keepalive
     * connections).
     */
    if (!by_worker && (busy ? connections_above_limit(now) : connections_full())) {
        disable_listensocks(now, ACCEPT_OFF_LIMIT);
        if (above_limit) {
            *above_limit = 1;
        }
    }

    if (te) {
        ap_assert(!te_in_backlog(te));

        qe = te_qe(te);
        qe->cb = timer_event_backlog_cb;
    }
    else {
        ap_assert(!cs_in_backlog(cs));
        ap_assert(!cs->to.q);

        if (busy && cs->pub.state == CONN_STATE_LINGER && cs->linger_shutdown) {
            /* Not worth lingering more on this connection if we are short of
             * workers and everything is flushed+shutdown already, back out
             * and close.
             */
            ap_queue_info_idlers_inc(worker_queue_info);
            close_connection(cs);
            return 0;
        }

        if (cs->c) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE7, 0, cs->c,
                          "pushing connection %" CS_FMT,
                          CS_ARG(cs));
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_TRACE7, 0, ap_server_conf,
                          "pushing connection %" CS_FMT_TO,
                          CS_ARG_TO(cs));
        }

        qe = cs_qe(cs);
        qe->cb = conn_state_backlog_cb;
    }
    qe->qclass = (te) ? BACKLOG_TIMER : qclass;
    qe->queued_at = now; /* the listener's, when the event was polled */

    /* A worker queuing for itself pops it next (worker_wake_queued), don't
     * wake up a parked one for nothing. Otherwise a parked worker is woken up
     * by the queue's signal, and the doorbell rings for a worker blocked
     * polling (worker_poll) when no parked one is left for the event: the
     * queue counts those woken up but not running yet, as workers_parked()
     * does until they return from the queue, but not the ones having popped
     * their event already.
     */
    rc = ap_queue_push_event(worker_queue, qe,
                             (by_worker) ? AP_QUEUE_PUSH_NO_SIGNAL
                                         : AP_QUEUE_PUSH_CHECK_WAITERS);
    if (rc == APR_INCOMPLETE) {
        ring_doorbell();
        rc = APR_SUCCESS;
    }
    if (rc == APR_SUCCESS) {
        return 1;
    }
    else {
        int mode = ST_GRACEFUL;

        ap_queue_info_idlers_inc(worker_queue_info);

        ap_log_error(APLOG_MARK, APLOG_CRIT, rc, ap_server_conf, APLOGNO(00471)
                     "push2worker: queuing %s failed", cs ? "socket" : "timer");

        if (cs) {
            /* Can't go anywhere, kill (and log). */
            kill_connection(cs, rc);
        }
        else {
            /* Can't call te->cbfunc() and potentially block there, someone is
             * going to miss this event thus never release their connection(s),
             * graceful stop could never complete.
             */
            mode = ST_UNGRACEFUL;
        }

        AP_DEBUG_ASSERT(0);
        signal_threads(mode);
        return 0;
    }
}

/* Structures to reuse */
static timer_event_t timer_free_ring;

static apr_skiplist *timer_skiplist;
static volatile apr_time_t timers_next_expiry;

/* The timer_comp() function is used by apr_skiplist_insert() to keep the
 * elements/timers sorted, but it should never return 0 because inserting
 * duplicates is not possible (apr_skiplist_add() would allow this but it's
 * not available before APR 1.6). Thus duplicates are sorted by order of
 * insertion and timers are never equal for the skiplist (not an issue
 * because MPM event does not use apr_skiplist_{find,remove}() but
 * apr_skiplist_pop() and apr_skiplist_remove_node(), which don't compare).
 */
static int timer_comp(void *a, void *b)
{
    const timer_event_t *ta = a, *tb = b;
    return (ta->when < tb->when) ? -1 : 1;
}

static apr_thread_mutex_t *g_timer_skiplist_mtx;

/* Insert a timer in the skiplist (g_timer_skiplist_mtx held), returning
 * whether the listener has to be woken up to update its poll()ing timeout,
 * out of the mutex (wakeup_listener()).
 */
static int timer_insert_locked(timer_event_t *te)
{
    apr_time_t next_expiry;

    /* Okay, add sorted by when.. */
    te->node = apr_skiplist_insert(timer_skiplist, te);

    /* Cheaply update the global timers_next_expiry with this event's
     * if it expires before.
     */
    next_expiry = timers_next_expiry;
    if (!next_expiry || next_expiry > te->when + TIMERS_FUDGE_TIMEOUT) {
        timers_next_expiry = te->when;
        return 1;
    }
    return 0;
}

/* Insert a timer created without inserting it (get_timer_event(..., 0)), once
 * its owner has recorded it: from then on the listener may pop it and claim
 * what it times out at any time (the owner preempted for longer than the
 * timeout, say), and finds it recorded (cs->te, user_wait->timer).
 */
static void insert_timer_event(timer_event_t *te)
{
    int wakeup;

    apr_thread_mutex_lock(g_timer_skiplist_mtx);
    wakeup = timer_insert_locked(te);
    apr_thread_mutex_unlock(g_timer_skiplist_mtx);

    /* Out of the mutex (a syscall) */
    if (wakeup) {
        wakeup_listener();
    }
}

static timer_event_t *get_timer_event(apr_time_t timeout,
                                      ap_mpm_callback_fn_t *cbfn, void *baton,
                                      int insert)
{
    timer_event_t *te;
    apr_time_t now = (timeout < 0) ? 0 : event_time_now();
    int wakeup = 0;

    /* oh yeah, and make locking smarter/fine grained. */

    apr_thread_mutex_lock(g_timer_skiplist_mtx);

    if (!APR_RING_EMPTY(&timer_free_ring.link, timer_event_t, link)) {
        te = APR_RING_FIRST(&timer_free_ring.link);
        APR_RING_REMOVE(te, link);
    }
    else {
        struct backlog_timer_event *bte;
        /* invariant: (te == &bte->te) => (te_qe(te) == &bte->qe) */
        bte = apr_skiplist_alloc(timer_skiplist, sizeof(*bte));
        memset(bte, 0, sizeof(*bte));
        bte->qe.type = AP_QUEUE_EVENT_TIMER;
        bte->qe.data.te = bte->qe.cb_baton = &bte->te;
        te = &bte->te;
    }

    APR_RING_ELEM_INIT(te, link);
    te->cbfunc = cbfn;
    te->baton = baton;
    te->when = now + timeout;
    te->timeout = timeout;

    if (insert) {
        wakeup = timer_insert_locked(te);
    }

    apr_thread_mutex_unlock(g_timer_skiplist_mtx);

    /* Wake up the listener to eventually update its poll()ing timeout, out
     * of the mutex (a syscall).
     */
    if (wakeup) {
        wakeup_listener();
    }

    return te;
}

static void put_timer_event(timer_event_t *te, int locked)
{
    if (!locked) {
        apr_thread_mutex_lock(g_timer_skiplist_mtx);
    }

    memset(te, 0, sizeof(*te));
    APR_RING_INSERT_TAIL(&timer_free_ring.link, te, timer_event_t, link);

    if (!locked) {
        apr_thread_mutex_unlock(g_timer_skiplist_mtx);
    }
}

/* Cancel a timer event that won't be needed anymore (e.g. the wait it times
 * out completed first): remove it from the skiplist and recycle it now,
 * rather than keeping it until it expires, which would hold it allocated for
 * its whole timeout (the free ring then empty and each new timer allocated,
 * scanning apr_skiplist_alloc()'s growing memlist). If it's not in the
 * skiplist anymore, the listener has popped and handled it already (under
 * the same mutex), so there's nothing left to do.
 */
static void cancel_timer_event(timer_event_t *te)
{
    apr_thread_mutex_lock(g_timer_skiplist_mtx);
    if (te->node) {
        apr_skiplist_remove_node(timer_skiplist, te->node, NULL);
        te->node = NULL;
        put_timer_event(te, 1);
    }
    apr_thread_mutex_unlock(g_timer_skiplist_mtx);
}

/* The waits' timeouts: most waits use a few fixed timeouts (the proxy's, the
 * connect's, the pool acquire's...), declared by the modules at post-config
 * (ap_mpm_register_timeouts()). Rather than a timer each in the skiplist
 * (O(log n) to insert and remove, under g_timer_skiplist_mtx with all the
 * timers), a wait with a declared timeout is appended to the timeout queue of
 * its value (O(1), its own entry user_wait->to), under wait_queues.mutex;
 * other timeouts (e.g. the variable ones of mod_reqtimeout) use a timer.
 * The queues are a fixed array sorted by timeout (wait_tqs), created at the
 * child's startup, whose first entries the listener expires (the scan is
 * O(declared values) per expiry, a min-heap of the first entries would do if
 * configurations ever declare hundreds of values).
 * The claim of a wait is the CAS on its claim word, whose winner releases its
 * entry (wait_tq_release()), unless the listener unlinked it already
 * (expired, then claimed by the listener or not): the mutex only guards the
 * queues' rings, user_wait->tq is the winner's (or the arming thread's before
 * the wait's pfds and notifier are armed, the other claimers).
 */
static apr_array_header_t *declared_wait_timeouts; /* pconf */
static struct timeout_queues wait_queues = { NULL, 0, TIMERS_FUDGE_TIMEOUT };
static struct timeout_queue **wait_tqs; /* pskip */
static int wait_tqs_num;

/* The first fallbacks to a timer, logged once per timeout value (at debug
 * level, wait_queues.mutex)
 */
#define WAIT_TQ_LOGGED_MAX 16
static apr_interval_time_t wait_tq_logged[WAIT_TQ_LOGGED_MAX];
static int wait_tq_logged_num;

/* Declare the timeouts of the waits (ap_mpm_register_timeouts()) */
static apr_status_t event_register_timeouts(const apr_array_header_t *timeouts)
{
    int i;

    if (!declared_wait_timeouts || wait_queues.mutex) {
        return APR_EINVAL; /* not at post-config */
    }
    for (i = 0; timeouts && i < timeouts->nelts; i++) {
        apr_interval_time_t t = APR_ARRAY_IDX(timeouts, i,
                                              apr_interval_time_t);
        if (t >= 0) {
            APR_ARRAY_PUSH(declared_wait_timeouts, apr_interval_time_t) = t;
        }
    }
    return APR_SUCCESS;
}

static int wait_timeout_cmp(const void *a, const void *b)
{
    apr_interval_time_t ta = *(const apr_interval_time_t *)a,
                        tb = *(const apr_interval_time_t *)b;
    return (ta < tb) ? -1 : (ta > tb);
}

/* Create the timeout queues of the declared values and their mutex, in p
 * (pskip, see setup_threads_runtime())
 */
static void make_wait_queues(apr_pool_t *p)
{
    apr_interval_time_t *t = NULL;
    int i, n = 0;

    apr_thread_mutex_create(&wait_queues.mutex, APR_THREAD_MUTEX_DEFAULT, p);
    if (declared_wait_timeouts && declared_wait_timeouts->nelts) {
        /* Sorted and unique, as armed (at least TIMERS_FUDGE_TIMEOUT) */
        n = declared_wait_timeouts->nelts;
        t = apr_pmemdup(p, declared_wait_timeouts->elts, n * sizeof(*t));
        for (i = 0; i < n; i++) {
            if (t[i] < TIMERS_FUDGE_TIMEOUT) {
                t[i] = TIMERS_FUDGE_TIMEOUT;
            }
        }
        qsort(t, n, sizeof(*t), wait_timeout_cmp);
        for (i = 1, n = 1; i < declared_wait_timeouts->nelts; i++) {
            if (t[i] != t[n - 1]) {
                t[n++] = t[i];
            }
        }
    }
    wait_tqs = apr_pcalloc(p, (n + 1) * sizeof(*wait_tqs));
    for (i = 0; i < n; i++) {
        wait_tqs[i] = TO_QUEUE_MAKE(p, &wait_queues, "wait", t[i],
                                    i ? wait_tqs[0] : NULL);
        ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ap_server_conf,
                     "waits' timeout queue %i: %" APR_TIME_T_FMT "us",
                     i, t[i]);
    }
    wait_tqs_num = n;
    wait_tq_logged_num = 0;
}

/* The timeout queue of a value, NULL if not declared */
static struct timeout_queue *wait_tq_lookup(apr_interval_time_t timeout)
{
    int lo = 0, hi = wait_tqs_num;

    while (lo < hi) {
        int mid = (lo + hi) / 2;
        apr_interval_time_t t = wait_tqs[mid]->timeout;
        if (t == timeout) {
            return wait_tqs[mid];
        }
        if (t < timeout) {
            lo = mid + 1;
        }
        else {
            hi = mid;
        }
    }
    return NULL;
}

/* Whether a timeout value falls back to a timer for the first time, among
 * the first WAIT_TQ_LOGGED_MAX ones (wait_queues.mutex)
 */
static int wait_tq_fallback_new(apr_interval_time_t timeout)
{
    int i;

    for (i = 0; i < wait_tq_logged_num; i++) {
        if (wait_tq_logged[i] == timeout) {
            return 0;
        }
    }
    if (wait_tq_logged_num < WAIT_TQ_LOGGED_MAX) {
        wait_tq_logged[wait_tq_logged_num++] = timeout;
        return 1;
    }
    return 0;
}

/* Arm the timeout of a wait in the queue of its value, if declared (else 0
 * for a timer), before the wait can be claimed (its pfds and notifier armed
 * after): the time is taken under the mutex to keep the queue sorted.
 */
static int wait_tq_arm(struct user_wait *user_wait,
                       apr_interval_time_t timeout)
{
    struct timeout_queue *q = wait_tq_lookup(timeout);
    int wakeup;

    if (!q) {
        DRAIN_STAT_INC(wait_tq_fallbacks);
        if (APLOGdebug(ap_server_conf)) {
            int log_it;
            apr_thread_mutex_lock(wait_queues.mutex);
            log_it = wait_tq_fallback_new(timeout);
            apr_thread_mutex_unlock(wait_queues.mutex);
            if (log_it) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                             "wait timeout %" APR_TIME_T_FMT "us not "
                             "declared: a timer (logged once per value)",
                             timeout);
            }
        }
        return 0;
    }

    DRAIN_STAT_INC(wait_tq_arms);
    AP_DEBUG_ASSERT(!user_wait->tq && !user_wait->to.q);
    user_wait->tq = q;
    apr_thread_mutex_lock(wait_queues.mutex);
    wakeup = TO_QUEUE_APPEND(q, &user_wait->to);
    apr_thread_mutex_unlock(wait_queues.mutex);

    /* Out of the mutex (a syscall), see get_timer_event() */
    if (wakeup) {
        wakeup_listener();
    }
    return 1;
}

/* Release the timeout queue's entry of a wait just claimed by the caller:
 * unlink it, unless the listener did already (expired, then not claimed).
 */
static void wait_tq_release(struct user_wait *user_wait)
{
    apr_thread_mutex_lock(wait_queues.mutex);
    if (user_wait->to.q) {
        TO_QUEUE_REMOVE(user_wait->to.q, &user_wait->to);
    }
    apr_thread_mutex_unlock(wait_queues.mutex);
    user_wait->tq = NULL;
}

/* Whether a fired event (its pt) is for a previous wait than the current one
 * (pfds_cur), completed otherwise while the event was being handled: it must
 * not claim the current wait (a spurious completion). Only an event held
 * across two whole waits could be mistaken (the arrays alternate).
 */
static APR_INLINE int stale_user_wait(listener_poll_type *pt)
{
    struct user_wait *user_wait = pt->baton;
    return pt != &user_wait->pt_buf[user_wait->pfds_cur];
}

/* Claim an armed wait (WAIT_ARMED -> WAIT_CLAIMED), from any thread: the
 * winner completes it. The winner also frees the wait's timer, either still
 * in the skiplist or popped by the listener meanwhile: the listener's timer
 * path claims under g_timer_skiplist_mtx and frees the timer it popped only
 * if it wins, so the timer is freed once whoever wins. Likewise the winner
 * releases the wait's entry in its timeout queue (wait_tq_release()).
 */
static int claim_user_wait(struct user_wait *user_wait)
{
    if (apr_atomic_cas32(&user_wait->claim, WAIT_CLAIMED,
                         WAIT_ARMED) != WAIT_ARMED) {
        return 0;
    }
    claimed_user_wait_timer(user_wait);
    return 1;
}

/* Free the timer of a wait just claimed, or release its timeout queue's
 * entry, see claim_user_wait(): separately for a claim made under
 * notifiers_mutex (event_notify()), since the listener takes
 * g_timer_skiplist_mtx first.
 */
static void claimed_user_wait_timer(struct user_wait *user_wait)
{
    timer_event_t *te = user_wait->timer;

    if (user_wait->tq) {
        wait_tq_release(user_wait);
    }
    else if (te) {
        apr_thread_mutex_lock(g_timer_skiplist_mtx);
        if (te->node) {
            apr_skiplist_remove_node(timer_skiplist, te->node, NULL);
            te->node = NULL;
        }
        put_timer_event(te, 1);
        /* Under the mutex, for the listener's timer path */
        user_wait->timer = NULL;
        user_wait->cs->te = NULL;
        apr_thread_mutex_unlock(g_timer_skiplist_mtx);
    }
}

/* A wait timed out (its timer te, or its timeout queue with te NULL), just
 * claimed by the listener: the suspended connection is run by a worker for
 * the responsible module to know, through its continuation (or with
 * CONN_STATE_LINGER for a wait without one, which ap_mpm_register_wait()
 * doesn't register). Returns the connection to push to a worker.
 */
static event_conn_state_t *user_wait_timed_out(struct user_wait *user_wait,
                                               timer_event_t *te)
{
    event_conn_state_t *cs = user_wait->cs;

    AP_DEBUG_ASSERT(cs->user_wait == user_wait);
    AP_DEBUG_ASSERT(cs->te == te);
    if (te) {
        put_timer_event(te, 1);
    }
    user_wait->timer = cs->te = NULL;
    user_wait->tq = NULL;

    /* The continuation to run, if any (ap_mpm_register_wait()), which
     * decides what to do with the connection.
     */
    if (user_wait->continuation.fn) {
        set_user_continuation(cs, user_wait, AP_MPM_WAIT_TIMEOUT);
    }

    /* Remove all user pollfds from the pollset */
    apr_pool_cleanup_run(user_wait->pool, user_wait, user_wait_cleanup);
    cs->user_wait = NULL;

    AP_DEBUG_ASSERT(cs->suspended);
    if (!cs->continuation.fn) {
        cs->pub.state = CONN_STATE_LINGER;
    }
    return cs;
}

/* Time out the expired waits of the timeout queues (listener): unlinked and
 * claimed under the mutex (the losers' claimers find them unlinked), into a
 * local list, then timed out and pushed to a worker after unlocking (their
 * cleanups take other locks). Returns the next expiry of the queues.
 */
static apr_time_t expire_wait_queues(apr_time_t now, int *above_limit)
{
    struct user_wait *expired = NULL, **last = &expired;
    apr_time_t next_expiry;
    int i;

    apr_thread_mutex_lock(wait_queues.mutex);
    wait_queues.next_expiry = 0;
    for (i = 0; i < wait_tqs_num; i++) {
        struct timeout_queue *q = wait_tqs[i];

        while (!APR_RING_EMPTY(&q->head, timeout_entry, link)) {
            struct timeout_entry *e = APR_RING_FIRST(&q->head);
            apr_time_t elem_expiry = TO_QUEUE_EXPIRY(q, e);
            struct user_wait *user_wait;

            if (elem_expiry > now) {
                (void)TO_QUEUE_NEXT_EXPIRY(q, elem_expiry);
                break;
            }
            TO_QUEUE_REMOVE(q, e);

            /* Claimed by another thread already, which then finds it
             * unlinked (wait_tq_release())
             */
            user_wait = TO_ENTRY_WAIT(e);
            if (apr_atomic_cas32(&user_wait->claim, WAIT_CLAIMED,
                                 WAIT_ARMED) != WAIT_ARMED) {
                continue;
            }
            user_wait->expired_next = NULL;
            *last = user_wait;
            last = &user_wait->expired_next;
        }
    }
    next_expiry = wait_queues.next_expiry;
    apr_thread_mutex_unlock(wait_queues.mutex);

    while (expired) {
        struct user_wait *user_wait = expired;
        event_conn_state_t *cs;

        expired = user_wait->expired_next;
        user_wait->expired_next = NULL;
        cs = user_wait_timed_out(user_wait, NULL);
        push2worker(cs, NULL, BACKLOG_CONTINUATION, now, above_limit, 0);
    }
    return next_expiry;
}

#ifdef APR_POLLONESHOT
/* Claim a connection whose (one-shot) pfd fired, from any thread, against
 * its expiry by the listener: it's ours if it's still in its timeout queue
 * (conn_queues.mutex) or its timer is still in the skiplist (cs->te is read
 * under g_timer_skiplist_mtx since the listener recycles it there when it
 * expires).
 */
static int claim_connection(event_conn_state_t *cs)
{
    timer_event_t *te;
    int claimed = 0;

    apr_thread_mutex_lock(conn_queues.mutex);
    if (cs->to.q) {
        TO_QUEUE_REMOVE(cs->to.q, &cs->to);
        claimed = 1;
    }
    apr_thread_mutex_unlock(conn_queues.mutex);
    if (claimed) {
        return 1;
    }

    apr_thread_mutex_lock(g_timer_skiplist_mtx);
    te = cs->te;
    if (te && te->node) {
        apr_skiplist_remove_node(timer_skiplist, te->node, NULL);
        te->node = NULL;
        put_timer_event(te, 1);
        cs->te = NULL;
        claimed = 1;
    }
    apr_thread_mutex_unlock(g_timer_skiplist_mtx);
    return claimed;
}
#endif

static apr_status_t event_register_timed_callback(apr_time_t timeout,
                                                  ap_mpm_callback_fn_t *cbfn,
                                                  void *baton)
{
    if (!cbfn) {
        return APR_EINVAL;
    }
    get_timer_event(timeout, cbfn, baton, 1);
    return APR_SUCCESS;
}

/* Whether a lingering close lasted long enough (see SECONDS_TO_LINGER) */
static APR_INLINE int linger_expired(event_conn_state_t *cs, apr_time_t now)
{
    apr_interval_time_t max = apr_time_from_sec(MAX_SECS_TO_LINGER);

    if (cs->linger_short || apr_atomic_read32(&dying)) {
        max = apr_time_from_sec(SECONDS_TO_LINGER);
    }
    return now - cs->linger_since >= max;
}

/*
 * Flush data and close our side of the connection, then drain incoming data.
 * If the latter would block put the connection in the linger timeout queue
 * to be called back when ready, and repeat until it's closed by peer or it
 * lingered long enough (linger_expired()).
 * Only to be called in the worker thread, and since it's in immediate call
 * stack, we can afford a comfortable buffer size to consume data quickly.
 * Pre-condition: cs is not in any timeout queue and not in the pollset,
 *                conn_queues.mutex is not locked
 */
#define LINGERING_BUF_SIZE (32 * 1024)
static void process_lingering_close(event_conn_state_t *cs)
{
    char dummybuf[LINGERING_BUF_SIZE];
    int i;
    apr_socket_t *csd = cs_sd(cs);
    apr_status_t rv;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, cs->c,
                  "lingering close for connection %" CS_FMT,
                  CS_ARG(cs));
    AP_DEBUG_ASSERT(cs->pub.state == CONN_STATE_LINGER);

    /* Flush and shutdown first */
    if (!cs->linger_shutdown) {
        conn_rec *c = cs->c;
        int rc = OK;

        if (!cs->linger_started) {
            cs->linger_started = 1; /* once! */
            cs->pub.state = CONN_STATE_LINGER;

            /* Shutdown the connection, i.e. pre_connection_close hooks,
             * SSL/TLS close notify, WC bucket, etc..
             */
            rc = ap_prep_lingering_close(c);
            if (rc == OK) {
                rc = ap_shutdown_conn(c, AP_SHUTDOWN_CONN_WC);
                if (rc == OK) {
                    if (c->aborted) {
                        rc = DONE;
                    }
                    else if (ap_filter_should_yield(c->output_filters)) {
                        rc = AGAIN;
                    }
                }
            }
        }
        else if (c->aborted) {
            rc = DONE; /* e.g. timed out in shutdown_q */
        }
        else {
            rc = ap_check_output_pending(c);
        }

        cs->pub.state = CONN_STATE_LINGER;
        cs->pub.sense = CONN_SENSE_DEFAULT;
        if (rc == AGAIN) {
            ap_log_cerror(APLOG_MARK, APLOG_TRACE6, 0, cs->c,
                          "queuing lingering close for connection %" CS_FMT,
                          CS_ARG(cs));
            if (pollset_add(cs, CONN_SENSE_WANT_WRITE, cs->sc->sh_q, NULL)) {
                return; /* queued */
            }
        }
        if (rc != OK || apr_socket_shutdown(csd, APR_SHUTDOWN_WRITE)) {
            close_connection(cs);
            return;
        }
        
        cs->linger_shutdown = 1; /* once! */
        if (!cs->linger_since) {
            cs->linger_since = event_time_now();
        }
        if (apr_table_get(c->notes, "short-lingering-close")) {
            cs->linger_short = 1;
        }

        /* All nonblocking from now, no need for APR_INCOMPLETE_READ either */
        apr_socket_timeout_set(csd, 0);
        apr_socket_opt_set(csd, APR_INCOMPLETE_READ, 0);
    }

    /* Drain until EAGAIN or EOF/error, LINGER_READS_PER_PASS reads at most,
     * then requeue and come back when readable again unless the connection
     * is over (EOF/error, or lingered long enough).
     */
    for (i = 0; i < LINGER_READS_PER_PASS; i++) {
        apr_size_t nbytes = sizeof(dummybuf);
        rv = apr_socket_recv(csd, dummybuf, &nbytes);
        if (rv != APR_SUCCESS) {
            break;
        }
    }
    if ((rv != APR_SUCCESS && !APR_STATUS_IS_EAGAIN(rv))
        || linger_expired(cs, event_time_now())
        || connections_full() /* short of connections */
        || !pollset_add(cs, CONN_SENSE_WANT_READ, linger_q, NULL)) {
        close_connection(cs);
    }
}

/* Call shutdown_connection() for the elements of 'q' that timed out, or
 * for all if 'shrink' is set. The backlog connections are only removed from
 * the worker_queue and chained to *timed_out, for the caller to shut them
 * down once it released the worker_queue's lock. Likewise for the others when
 * timed_out is not NULL, only removed from the pollset, for the caller to
 * shut them down once it released conn_queues.mutex (closing a connection
 * runs its pool cleanups).
 * Pre-condition: conn_queues.mutex must already be locked
 */
static unsigned int process_timeout_queue_ex(struct timeout_queue *queue,
                                             apr_time_t now, int shrink,
                                             event_conn_state_t **timed_out)
{
    unsigned int count = 0;
    struct timeout_queue *q;

    if (!*queue->total) {
        return 0;
    }

    for (q = queue; q; q = q->next) {
        if (!shrink && !TO_QUEUE_EXPIRES(q)) {
            continue;
        }
        while (!APR_RING_EMPTY(&q->head, timeout_entry, link)) {
            event_conn_state_t *cs = TO_ENTRY_CS(APR_RING_FIRST(&q->head));

            ap_assert(cs->to.q == q);

            if (!shrink) {
                /* Stop if this entry did not expire, no following one will
                 * thanks to the single timeout per queue (latest entries are
                 * added to the tail).
                 */
                apr_time_t elem_expiry = TO_QUEUE_EXPIRY(q, &cs->to);
                if (elem_expiry > now) {
                    /* This is the next expiring entry of this queue, update
                     * the next expiry of the queues if it expires after this
                     * one.
                     */
                    (void)TO_QUEUE_NEXT_EXPIRY(q, elem_expiry);
                    break;
                }
            }

            if (cs_in_backlog(cs)) {
                /* Remove the backlog connection from worker_queue (note that
                 * the lock is held by the listener already when maintaining
                 * the backlog_q), and unreserve/set a worker/idler since
                 * none could handle the event. Ours from now, shut down by
                 * the caller after unlocking.
                 */
                ap_assert(cs->to.q == backlog_conn_q || cs->to.q == backlog_linger_q);
                ap_assert(cs_qe(cs)->cb_baton == cs);
                ap_assert(timed_out != NULL);
                ap_queue_info_idlers_inc(worker_queue_info);
                ap_queue_kill_event_locked(worker_queue, cs_qe(cs));
                cs->bl_timed_out_next = *timed_out;
                *timed_out = cs;
            }
            else if (pollset_del(cs, 1)) {
                /* Removed from the pollset and timeout queue. */
                if (timed_out) {
                    cs->bl_timed_out_next = *timed_out;
                    *timed_out = cs;
                }
                else {
                    shutdown_connection(cs, now, 0);
                }
            }
            else {
                /* Can't go anywhere, kill (and log). */
                kill_connection(cs, APR_EGENERAL);
            }

            count++;
        }
    }

    return count;
}

static APR_INLINE void process_timeout_queue(struct timeout_queue *queue,
                                             apr_time_t now)
{
    (void)process_timeout_queue_ex(queue, now, 0, NULL);
}

/* When the connections are full, kill'em all \m/ (chained to *timed_out
 * for the caller to shut them down, see process_timeout_queue_ex())
 */
static APR_INLINE void shrink_timeout_queue(struct timeout_queue *queue,
                                            apr_time_t now,
                                            event_conn_state_t **timed_out)
{
    unsigned int count = process_timeout_queue_ex(queue, now, 1, timed_out);
    linger_shrunk += count;
    if (count) {
        ap_log_error(APLOG_MARK, APLOG_TRACE5, 0, ap_server_conf,
                     "Connections full, %s queue shrunk (%u done, %u left)",
                     queue->name, count, apr_atomic_read32(queue->total));
    }
}

/* Shut down the connections chained by process_timeout_queue_ex() */
static void shutdown_timed_out(event_conn_state_t *timed_out, apr_time_t now,
                               int in_backlog)
{
    while (timed_out) {
        event_conn_state_t *cs = timed_out;
        timed_out = cs->bl_timed_out_next;
        cs->bl_timed_out_next = NULL;
        shutdown_connection(cs, now, in_backlog);
    }
}

static void *APR_THREAD_FUNC worker_thread(apr_thread_t *thd, void *dummy);

/* elastic_threads: join the extra worker of slot i, which retired */
static void reap_extra_worker(int i)
{
    apr_status_t rv, thread_rv;

    rv = apr_thread_join(&thread_rv, worker_threads[i]);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf, APLOGNO()
                     "apr_thread_join: unable to join worker thread %d", i);
    }
    worker_threads[i] = NULL;
    apr_pool_clear(worker_thread_pools[i]);
    apr_atomic_set32(&worker_slots[i].retired, 0);
    apr_atomic_dec32(&workers_unjoined);
}

/* elastic_threads: join the extra workers that retired (listener thread),
 * not once the child stops (join_workers() joins them)
 */
static void reap_retired_workers(void)
{
    int i;

    if (apr_atomic_read32(&listener_may_exit)) {
        return;
    }
    for (i = threads_per_child; i < threads_max; i++) {
        if (worker_threads[i]
            && apr_atomic_read32(&worker_slots[i].retired)) {
            reap_extra_worker(i);
        }
    }
}

#ifdef EVENT_ELASTIC_THREADS
/* elastic_threads: start an extra worker in the first free slot above the
 * base ones (listener thread, the only one starting them while running),
 * with a pool of its own for its creation (cleared once joined).
 */
static int start_extra_worker(void)
{
    int i;

    for (i = threads_per_child; i < threads_max; i++) {
        proc_info *info;
        apr_status_t rv;

        if (worker_threads[i]) {
            if (!apr_atomic_read32(&worker_slots[i].retired)
                || apr_atomic_read32(&listener_may_exit)) {
                continue;
            }
            reap_extra_worker(i);
        }
        if (ap_scoreboard_image->servers[ap_child_slot][i].status
            != SERVER_DEAD) {
            continue;
        }
        if (!worker_thread_pools[i]) {
            apr_pool_create(&worker_thread_pools[i], pruntime);
            apr_pool_tag(worker_thread_pools[i], "mpm_extra_worker");
        }

        /* Not anymore once the child stops, the extra workers are joined
         * by join_workers() then (maybe without the listener's join)
         */
        if (apr_atomic_read32(&listener_may_exit)
            || apr_atomic_read32(&dying)) {
            return 0;
        }

        info = ap_malloc(sizeof(*info));
        info->pslot = ap_child_slot;
        info->tslot = i;
        ap_update_child_status_from_indexes(ap_child_slot, i,
                                            SERVER_STARTING, NULL);
        workers_live_inc();
        rv = ap_thread_create(&worker_threads[i], worker_thread_attr,
                              worker_thread, info, worker_thread_pools[i]);
        if (rv != APR_SUCCESS) {
            workers_live_dec();
            worker_threads[i] = NULL;
            free(info);
            ap_update_child_status_from_indexes(ap_child_slot, i,
                                                SERVER_DEAD, NULL);
            {
                static log_ratelimit_t rl;
                if (LOG_RATELIMIT(&rl, APLOG_ERR, 0, ap_server_conf, NULL)) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf, APLOGNO()
                                 "ap_thread_create: unable to create an extra worker "
                                 "thread");
                }
            }
            return 0;
        }
        return 1;
    }
    return 0;
}

/* What the process used so far (all its threads): CPU time, and context
 * switches where known (0 otherwise)
 */
struct process_usage {
    apr_time_t cpu;
    apr_int64_t vcsw, ivcsw;    /* voluntary, involuntary */
};

/* The listener's state for growing the workers (workers_grow_check()): the
 * usage sampled at each check of a wait, the last GROW_SAMPLES of them, to
 * compare over admission_interval at least (a shorter time is within the
 * scheduler's slices: a child short of CPU may not run at all then).
 */
#define GROW_SAMPLES 32
static struct {
    apr_time_t next_check;  /* not before, a new worker per target at most */
    apr_time_t busy_since;  /* since when no worker is idle, 0 if one is */
    apr_time_t sample_time[GROW_SAMPLES];
    struct process_usage sample[GROW_SAMPLES];
    unsigned int first, count; /* the oldest sample, how many */
    int limit_reported;
    int backoff;            /* next_check delayed after a CPU refusal */
    apr_uint32_t grown;     /* stats */
} workers_growth;

static int process_usage(struct process_usage *u)
{
    struct rusage ru;

    if (getrusage(RUSAGE_SELF, &ru) != 0) {
        return 0;
    }
    u->cpu = (apr_time_make(ru.ru_utime.tv_sec, ru.ru_utime.tv_usec) +
              apr_time_make(ru.ru_stime.tv_sec, ru.ru_stime.tv_usec));
#ifdef EVENT_RUSAGE_CSW
    u->vcsw = ru.ru_nvcsw;
    u->ivcsw = ru.ru_nivcsw;
#else
    u->vcsw = u->ivcsw = 0;
#endif
    return 1;
}

/* When the oldest event waiting for a worker was queued, 0 if none */
static apr_time_t backlog_head_time(void)
{
    apr_time_t oldest = 0;
    int i;

    for (i = 0; i < BACKLOG_CLASSES; i++) {
        if (ap_queue_lane_nelts(worker_queue, i)) {
            apr_time_t t = ap_queue_lane_head_time(worker_queue, i);
            if (t && (!oldest || t < oldest)) {
                oldest = t;
            }
        }
    }
    return oldest;
}

/* elastic_threads: start an extra worker when the workers are blocked rather
 * than busy on the CPU: none is idle, something has been waiting for one
 * longer than the admission target (the oldest event queued, or with
 * worker_poll the connections nobody polls while none is idle), and over the
 * last admission_interval (at least) the CPU time of the process is below
 * half of what its
 * (busy) workers could use, that is their time but not more than this child's
 * share of the CPUs (num_cpus / the children: those that get less are short
 * of CPU, not blocked), and where known its involuntary context switches stay
 * below half of the voluntary ones (blocking shows as voluntary switches,
 * waiting for a CPU as involuntary ones). Another thread couldn't run
 * otherwise. At most one per admission target, up to threads_max. After a
 * check refused because of the CPU (busy or short of it), the next one
 * waits for the admission interval, or for a worker to have idled meanwhile
 * (backoff). Listener thread, at every loop, woken up in time by its
 * deadline (workers_grow_deadline()).
 */
static void workers_grow_check(apr_time_t now)
{
    struct process_usage u;
    apr_time_t head, elapsed, used;
    apr_int64_t vcsw, ivcsw;
    apr_uint32_t live, cpu_share;
    unsigned int i, n;

    if (ap_queue_info_idlers_count(worker_queue_info) > 0
        || apr_atomic_read32(&dying)) {
        workers_growth.busy_since = 0;
        workers_growth.count = 0;
        if (workers_growth.backoff) {
            workers_growth.next_check = 0;
            workers_growth.backoff = 0;
        }
        return;
    }
    workers_last_short = now;
    if (!workers_growth.busy_since) {
        workers_growth.busy_since = now;
    }
    if (now < workers_growth.next_check) {
        return;
    }
    head = backlog_head_time();
    if (!(head && now - head > admission_target)
        && !(worker_poll && now - workers_growth.busy_since > admission_target)) {
        workers_growth.count = 0;
        workers_growth.backoff = 0;
        return;
    }
    workers_growth.next_check = now + admission_target;

    if (!process_usage(&u)) {
        return;
    }
    /* A new wait if the previous sample is not the previous check's (the
     * backoff spaces them on purpose)
     */
    if (workers_growth.count && !workers_growth.backoff
        && now - workers_growth.sample_time[(workers_growth.first
                                             + workers_growth.count - 1)
                                            % GROW_SAMPLES]
           > 4 * admission_target) {
        workers_growth.count = 0;
    }
    if (workers_growth.count == GROW_SAMPLES) {
        workers_growth.first = (workers_growth.first + 1) % GROW_SAMPLES;
        workers_growth.count--;
    }
    if (!workers_growth.count) {
        workers_growth.first = 0;
    }
    i = (workers_growth.first + workers_growth.count++) % GROW_SAMPLES;
    workers_growth.sample_time[i] = now;
    workers_growth.sample[i] = u;

    /* Compare with the latest sample at least admission_interval old, the
     * oldest one if none is (all of the ring when full)
     */
    for (n = 0, i = workers_growth.first; n + 1 < workers_growth.count;
         n++, i = (i + 1) % GROW_SAMPLES) {
        unsigned int next = (i + 1) % GROW_SAMPLES;
        if (now - workers_growth.sample_time[next] < admission_interval) {
            break;
        }
    }
    elapsed = now - workers_growth.sample_time[i];
    if (elapsed < admission_interval
        && workers_growth.count < GROW_SAMPLES) {
        return; /* not enough time to tell yet */
    }
    used = u.cpu - workers_growth.sample[i].cpu;
    vcsw = u.vcsw - workers_growth.sample[i].vcsw;
    ivcsw = u.ivcsw - workers_growth.sample[i].ivcsw;

    /* The CPUs this child can get, in thousandths (a tenth at least) */
    cpu_share = (apr_uint32_t)num_cpus * 1000 / (apr_uint32_t)active_daemons_limit;
    if (cpu_share < 100) {
        cpu_share = 100;
    }
    live = apr_atomic_read32(&workers_live);
    if (cpu_share > live * 1000) {
        cpu_share = live * 1000;
    }
    if (used * 2 * 1000 >= (apr_time_t)cpu_share * elapsed
        || ivcsw * 2 > vcsw) {
        /* Busy on the CPU, or short of CPU: back off */
        workers_growth.next_check = now + admission_interval;
        workers_growth.backoff = 1;
        return;
    }
    workers_growth.backoff = 0;
    if (live >= (apr_uint32_t)threads_max) {
        if (!workers_growth.limit_reported) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO()
                         "all the %d worker threads of this child (ThreadLimit) "
                         "are blocked: consider raising ThreadLimit, or "
                         "running the blocking work out of process (e.g. "
                         "PHP-FPM with mod_proxy_fcgi)", threads_max);
            workers_growth.limit_reported = 1;
        }
        return;
    }
    if (start_extra_worker()) {
        workers_growth.grown++;
        ap_log_error(APLOG_MARK, APLOG_TRACE5, 0, ap_server_conf,
                     "workers blocked (cpu %" APR_TIME_T_FMT "us in %"
                     APR_TIME_T_FMT "us for %u, share %u/1000, csw %"
                     APR_INT64_T_FMT "/%" APR_INT64_T_FMT "), one more "
                     "worker", used, elapsed, live, cpu_share, vcsw, ivcsw);
    }
}

/* When the listener should check next whether the workers are blocked
 * (workers_grow_check()), 0 for no need: while no worker is idle and more can
 * start, once the oldest event queued would have waited for the admission
 * target (or with worker_poll, once none has been idle for the target), not
 * before the next check is due. A worker popping the head or idling moves or
 * drops it, seen when the listener wakes up then (at the deadline at worst).
 */
static apr_time_t workers_grow_deadline(apr_time_t now)
{
    apr_time_t head, when = 0;

    if (apr_atomic_read32(&dying)
        || ap_queue_info_idlers_count(worker_queue_info) > 0
        || apr_atomic_read32(&workers_live) >= (apr_uint32_t)threads_max) {
        return 0;
    }
    head = backlog_head_time();
    if (head) {
        when = head + admission_target;
    }
    if (worker_poll) {
        apr_time_t since = (workers_growth.busy_since) ? workers_growth.busy_since
                                                       : now;
        if (!when || since + admission_target < when) {
            when = since + admission_target;
        }
    }
    if (when && when < workers_growth.next_check) {
        when = workers_growth.next_check;
    }
    return when;
}
#endif /* EVENT_ELASTIC_THREADS */

static void update_stats(process_score *ps, apr_time_t now,
                         apr_time_t *when, int force)
{
    int expired = (*when <= now);

    if (expired || force) {
        apr_atomic_set32(&ps->wait_io, apr_atomic_read32(waitio_q->total));
        apr_atomic_set32(&ps->write_completion, apr_atomic_read32(write_completion_q->total));
        apr_atomic_set32(&ps->keep_alive, apr_atomic_read32(keepalive_q->total));
        apr_atomic_set32(&ps->shutdown, apr_atomic_read32(shutdown_q->total));
        apr_atomic_set32(&ps->lingering_close, apr_atomic_read32(linger_q->total));
        apr_atomic_set32(&ps->backlog, apr_atomic_read32(backlog_q->total));
        apr_atomic_set32(&ps->suspended, apr_atomic_read32(&event_counts.suspended_count));
        apr_atomic_set32(&ps->connections, apr_atomic_read32(&event_counts.connection_count));
    }

    if (expired) {
        /* Reset at each period, whether logged or not */
        apr_uint32_t retired = apr_atomic_xchg32(&workers_retired, 0);

        fair_share_update();

        ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, ap_server_conf,
                     "child: idlers:%i conns:%u backlog:%u "
                     "waitio:%u write:%u keepalive:%u shutdown:%u linger:%u "
                     "timers:%u suspended:%u (%u/%u workers shutdown) "
                     "workers:%u/%d grown:%u retired:%u",
                     ap_queue_info_idlers_count(worker_queue_info),
                     apr_atomic_read32(&event_counts.connection_count),
                     apr_atomic_read32(backlog_q->total),
                     apr_atomic_read32(waitio_q->total),
                     apr_atomic_read32(write_completion_q->total),
                     apr_atomic_read32(keepalive_q->total),
                     apr_atomic_read32(shutdown_q->total),
                     apr_atomic_read32(linger_q->total),
                     apr_atomic_read32(&event_counts.timers_count),
                     apr_atomic_read32(&event_counts.suspended_count),
                     apr_atomic_read32(&threads_shutdown),
                     threads_per_child,
                     apr_atomic_read32(&workers_live), threads_max,
#ifdef EVENT_ELASTIC_THREADS
                     workers_growth.grown,
#else
                     0u,
#endif
                     retired);
#ifdef EVENT_ELASTIC_THREADS
        workers_growth.grown = 0;
#endif
        if (elastic_threads) {
            reap_retired_workers();
        }
        if (backlog_stats_on) {
            backlog_stats_report(now);
        }

        *when = now + STATS_UPDATE_TIMEOUT;
    }
}

static void * APR_THREAD_FUNC listener_thread(apr_thread_t * thd, void *dummy)
{
    apr_status_t rc;
    proc_info *ti = dummy;
    int process_slot = ti->pslot;
    process_score *ps = ap_get_scoreboard_process(process_slot);
    apr_time_t next_stats_time = 0, next_shrink_time = 0;
    unsigned int recheck_timedout = 0; /* RECHECK_* that timed out last */

    free(ti);

#if HAVE_SERF
    init_serf(apr_thread_pool_get(thd));
#endif

    for (;;) {
        apr_int32_t num = 0;
        apr_time_t next_expiry = -1;
        apr_interval_time_t timeout = -1;
        int above_limit = 0, force_stats = 0;
        unsigned int recheck; /* RECHECK_* used by the poll's timeout */
        event_conn_state_t *expired = NULL;
        struct user_wait *user_chain;
        const apr_pollfd_t *out_pfd;
        apr_time_t now, poll_time;
        event_conn_state_t *cs;
        timer_event_t *te;

        if (conns_this_child <= 0) {
            /* Gracefuly stop (eventually) and keep going */
            check_infinite_requests();
        }

        now = poll_time = event_time_now();

        if (apr_atomic_read32(&listener_may_exit)) {
            int once = !apr_atomic_read32(&dying);
            if (once) {
                set_child_dying();
            }

            if (terminate_mode == ST_UNGRACEFUL
                || (apr_atomic_read32(&event_counts.connection_count) == 0
                    && apr_atomic_read32(&event_counts.timers_count) == 0))
                break;

            if (once) {
                /* Don't wait in poll() the first time (i.e. dying now), we
                 * want to maintain the queues ASAP to shutdown the workers
                 * and exit the child faster.
                 */
                goto do_maintenance; /* with next_expiry == -1 */
            }
        }

#if HAVE_SERF
        rc = serf_context_prerun(g_serf);
        if (rc != APR_SUCCESS) {
            /* TODO: what should we do here? ugh. */
        }
#endif

        /* Start with an infinite poll() timeout and update it according to
         * the next expiring timer or queue entry. If there are none, the
         * listener can poll() indefinitely until a wake up occurs.
         */
        timeout = -1;

        /* Push expired timers to a worker, the first remaining one (if any)
         * determines the maximum time to poll() below.
         */
        next_expiry = timers_next_expiry;
        if (next_expiry && next_expiry <= now) {
            /* The waits timed out, claimed under the mutex and handled after
             * (their cleanups take user_wait->mutex, which arm_user_wait()
             * holds while it inserts their timer)
             */
            struct user_wait *timed_out = NULL;

            apr_thread_mutex_lock(g_timer_skiplist_mtx);
            while ((te = apr_skiplist_peek(timer_skiplist))) {
                if (te->when > now) {
                    break;
                }
                apr_skiplist_pop(timer_skiplist, NULL);
                te->node = NULL;

                /* A timer without a callback is a cancel event for a cs in
                 * either:
                 *  1. CONN_STATE_ASYNC_WAITIO: the timer enforces a timeout
                 *     different from the cs->sc->io_q's, te->baton is the
                 *     (timed out) cs;
                 *  2. CONN_STATE_SUSPENDED: the timer (wait_timer_cb) enforces
                 *     the timeout of a wait (user pollfds bound to the cs),
                 *     te->baton is the wait, to be claimed first.
                 * For 1. we can shutdow the connection now, but for 2. we
                 * need to resume the suspended connection in a worker thread
                 * for the responsible module to know (user_wait_timed_out()).
                 */
                if (te->cbfunc == wait_timer_cb) {
                    struct user_wait *user_wait = te->baton;

                    /* Only the wait's current timer claims it: recorded
                     * before inserted, and cleared under this mutex by
                     * whoever claims the wait otherwise (then freeing it).
                     * Not it: a timer left over (can't be), dropped.
                     */
                    if (user_wait->timer != te) {
                        AP_DEBUG_ASSERT(user_wait->timer == te);
                        put_timer_event(te, 1);
                        continue;
                    }
                    /* The wait may have been claimed by another thread
                     * already, which then frees te (claim_user_wait()).
                     */
                    if (apr_atomic_cas32(&user_wait->claim, WAIT_CLAIMED,
                                         WAIT_ARMED) != WAIT_ARMED) {
                        continue;
                    }
                    put_timer_event(te, 1);
                    user_wait->timer = user_wait->cs->te = NULL;
                    user_wait->expired_next = timed_out;
                    timed_out = user_wait;
                    continue;
                }
                else if (!te->cbfunc) {
                    cs = te->baton;
                    AP_DEBUG_ASSERT(cs != NULL);
                    AP_DEBUG_ASSERT(cs->te == te);
                    AP_DEBUG_ASSERT(!cs->user_wait);
                    put_timer_event(te, 1);
                    cs->te = te = NULL;

                    ap_log_cerror(APLOG_MARK, APLOG_TRACE7, 0, cs->c,
                                  "timed out connection %" CS_FMT,
                                  CS_ARG(cs));
                    (void)pollset_del(cs, 0);
                    shutdown_connection(cs, now, 0);
                    continue;
                }
                else {
                    cs = NULL;
                }

                /* A timed out wait completes, else a timer */
                push2worker(cs, te, BACKLOG_CONTINUATION, now, &above_limit, 0);
            }
            if (te) {
                next_expiry = te->when;
            }
            else {
                next_expiry = 0;
            }
            timers_next_expiry = next_expiry;
            apr_thread_mutex_unlock(g_timer_skiplist_mtx);

            while (timed_out) {
                struct user_wait *user_wait = timed_out;

                timed_out = user_wait->expired_next;
                user_wait->expired_next = NULL;
                cs = user_wait_timed_out(user_wait, NULL);
                push2worker(cs, NULL, BACKLOG_CONTINUATION, now, &above_limit, 0);
            }
        }
        if (next_expiry) {
            timeout = next_expiry > now ? next_expiry - now : 0;
        }

        /* Likewise for the waits' timeout queues */
        next_expiry = wait_queues.next_expiry;
        if (next_expiry && next_expiry <= now) {
            next_expiry = expire_wait_queues(now, &above_limit);
        }
        if (next_expiry && (timeout < 0 || next_expiry - now < timeout)) {
            timeout = next_expiry > now ? next_expiry - now : 0;
        }

        /* Same for queues, use their next expiry, if any. */
        next_expiry = conn_queues.next_expiry;
        if (next_expiry && (timeout < 0 || next_expiry - now < timeout)) {
            timeout = next_expiry > now ? next_expiry - now : 0;
        }

        /* So long as there are connections, wake up at most every
         * STATS_UPDATE_TIMEOUT to refresh the scoreboard stats.
         */
        if (timeout < 0 || timeout > STATS_UPDATE_TIMEOUT) {
            if (timeout > 0
                || apr_atomic_read32(&event_counts.connection_count)
                /* extra workers to retire or join (elastic_threads) */
                || (elastic_threads
                    && (apr_atomic_read32(&workers_live) > (apr_uint32_t)threads_per_child
                        || apr_atomic_read32(&workers_unjoined)))) {
                timeout = next_stats_time - now;
                if (timeout <= 0 || timeout > STATS_UPDATE_TIMEOUT) {
                    timeout = STATS_UPDATE_TIMEOUT;
                }
            }
            else {
                /* No connections and entering infinite poll(),
                 * clear the stats first.
                 */
                force_stats = 1;
            }
        }
        update_stats(ps, now, &next_stats_time, force_stats);

        /* While not accepting for the limits (connections_above_limit()),
         * re-evaluate them in time. They clear only when a connection is
         * closed or a worker takes new connections or idles, which wake up
         * the listener when it should accept again (see
         * wakeup_listener_by()), so this is a backstop against a lost
         * wake only, not expected to decide (ACCEPT_RECHECK_TIMEOUT). After
         * stopping for the fair share though, re-evaluate within the
         * admission's target during the admission's interval, when a burst
         * is spreading over the children (other children's connections, no
         * local event to wake up the listener), then at the stats tick. A
         * resume counts as a re-check's (backlog stats) only when that
         * re-check's own timeout ended the poll.
         */
        recheck = 0;
        if (!apr_atomic_read32(&dying)) {
            if (listensocks_disabled_for(ACCEPT_OFF_SHARE)
                && now - fair_share_stopped < admission_interval) {
                if (timeout < 0 || timeout > admission_target) {
                    timeout = admission_target;
                    recheck = RECHECK_SHARE;
                }
            }
            else if (listensocks_disabled_for(ACCEPT_OFF_LIMIT)
                     && (timeout < 0 || timeout > ACCEPT_RECHECK_TIMEOUT)) {
                timeout = ACCEPT_RECHECK_TIMEOUT;
                recheck = RECHECK_BACKSTOP;
            }
        }
#ifdef EVENT_ELASTIC_THREADS
        /* Likewise for the next check of whether the workers are blocked
         * (workers_grow_deadline())
         */
        if (elastic_threads) {
            apr_time_t when = workers_grow_deadline(now);
            if (when && (timeout < 0 || timeout > when - now)) {
                /* due already: in 1ms rather than spinning */
                timeout = (when > now) ? when - now : apr_time_from_msec(1);
                recheck = 0;
            }
        }
#endif

        /* apr_pollset_poll() might round down the timeout to
         * milliseconds, let's forcibly round up here to never
         * return before the timeout.
         */
        if (timeout > 0) {
            timeout = apr_time_from_msec(
                apr_time_as_msec(timeout + apr_time_from_msec(1) - 1)
            );
        }

        /* Unpause listening sockets before poll()ing if possible (with the
         * current fair share if stopped for it).
         */
        if (listensocks_disabled_for(ACCEPT_OFF_SHARE)) {
            fair_share_update();
        }
        if (listensocks_disabled()) {
            /* The wakes asking to accept, up to now (any later one will
             * make the poll below return).
             */
            apr_uint32_t wakes = 0;
            if (backlog_stats_on) {
                wakes = apr_atomic_xchg32(&accept_wakes, 0);
            }
            if (should_enable_listensocks(now)) {
                const char *by;
                if (wakes) {
                    resumes_woken++;
                    by = (wakes == ACCEPT_WAKE_WORKER) ? "worker"
                       : (wakes == ACCEPT_WAKE_CLOSE) ? "close"
                       : "worker+close";
                }
                else if (recheck_timedout == RECHECK_BACKSTOP) {
                    resumes_recheck++;
                    by = "recheck";
                }
                else if (recheck_timedout == RECHECK_SHARE) {
                    resumes_share++;
                    by = "share";
                }
                else {
                    resumes_other++;
                    by = "other";
                }
                enable_listensocks(now, by);
            }
        }

        ap_log_error(APLOG_MARK, APLOG_TRACE7, 0, ap_server_conf,
                     "pollset: wait timeout=%" APR_TIME_T_FMT
                     " queues_timeout=%" APR_TIME_T_FMT
                     " timers_timeout=%" APR_TIME_T_FMT
                     " listen=%s conns=%d exit=%d/%d",
                     timeout,
                     conn_queues.next_expiry ? conn_queues.next_expiry - now : 0,
                     timers_next_expiry ? timers_next_expiry - now : 0,
                     listensocks_disabled() ? "no" : "yes",
                     apr_atomic_read32(&event_counts.connection_count),
                     apr_atomic_read32(&listener_may_exit),
                     apr_atomic_read32(&dying));

        rc = apr_pollset_poll(event_pollset, timeout, &num, &out_pfd);
        recheck_timedout = (APR_STATUS_IS_TIMEUP(rc)) ? recheck : 0;
        if (rc != APR_SUCCESS) {
            if (!APR_STATUS_IS_EINTR(rc) && !APR_STATUS_IS_TIMEUP(rc)) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rc, ap_server_conf,
                             APLOGNO(03267)
                             "apr_pollset_poll failed.  Attempting to "
                             "shutdown process gracefully");
                AP_DEBUG_ASSERT(0);
                signal_threads(ST_GRACEFUL);
            }
            num = 0;
        }

        /* Update "now" after polling and use it for everything below (all
         * non-(indefinitely-)blocking code). "now - poll_time" is then the
         * time passed in poll().
         *
         * XXX possible optimization: stash this time for use as
         * r->request_time for new requests.
         */
        now = event_time_now();

        ap_log_error(APLOG_MARK, APLOG_TRACE7, rc, ap_server_conf,
                     "pollset: have num=%i"
                     " elapsed=%" APR_TIME_T_FMT "/%" APR_TIME_T_FMT
                     " queues_timeout=%" APR_TIME_T_FMT
                     " timers_timeout=%" APR_TIME_T_FMT
                     " listen=%s conns=%d exit=%d/%d",
                     (int)num, now - poll_time, timeout,
                     conn_queues.next_expiry ? conn_queues.next_expiry - now : 0,
                     timers_next_expiry ? timers_next_expiry - now : 0,
                     listensocks_disabled() ? "no" : "yes",
                     apr_atomic_read32(&event_counts.connection_count),
                     apr_atomic_read32(&listener_may_exit),
                     apr_atomic_read32(&dying));

        for (user_chain = NULL; num > 0; --num, ++out_pfd) {
            listener_poll_type *pt = out_pfd->client_data;
            struct user_wait *user_wait;
            backlog_class_e qclass = BACKLOG_NEW;

            if (!pt) {
                /* A wait's pfd copy whose wait completed meanwhile (its
                 * client_data reset by user_wait_cleanup()): stale
                 */
                continue;
            }
            switch (pt->type) {
            case PT_CSD:
                /* one of the sockets is ready */
                cs = (event_conn_state_t *)pt->baton;
#ifdef APR_POLLONESHOT
                /* Ours unless expired meanwhile (or taken by another thread
                 * polling); nothing to remove from the pollset once fired.
                 */
                if (!claim_connection(cs)) {
                    break;
                }
#endif
                ap_log_cerror(APLOG_MARK, APLOG_TRACE7, 0, cs->c,
                              "polled connection %" CS_FMT,
                              CS_ARG(cs));

                switch (cs->pub.state) {
                case CONN_STATE_KEEPALIVE:
                    qclass = BACKLOG_KEEPALIVE;
                    cs->pub.state = CONN_STATE_PROCESSING;
                    break;
                case CONN_STATE_ASYNC_WAITIO:
                    qclass = BACKLOG_WAITIO;
                    cs->pub.state = CONN_STATE_PROCESSING;
                    break;
                case CONN_STATE_WRITE_COMPLETION:
                    qclass = BACKLOG_WRITE;
                    break;
                case CONN_STATE_LINGER:
                    qclass = BACKLOG_LINGER;
                    break;

                default:
                    ap_log_error(APLOG_MARK, APLOG_CRIT, rc,
                                 ap_server_conf, APLOGNO(03096)
                                 "event_loop: unexpected state %d",
                                 cs->pub.state);
                    ap_assert(0);
                }

#ifdef APR_POLLONESHOT
                push2worker(cs, NULL, qclass, now, &above_limit, 0);
#else
                if (pollset_del_fired(cs)) {
                    push2worker(cs, NULL, qclass, now, &above_limit, 0);
                }
                else {
                    /* Can't go anywhere, kill (and log) and next. */
                    kill_connection(cs, APR_EGENERAL);
                }
#endif
                break;

            case PT_ACCEPT:
                /* A Listener Socket is ready for an accept() */
                if (above_limit || listensocks_disabled_for(ACCEPT_OFF_SHARE)) {
                    /* Listeners disabled for now, keep the new connection in
                     * the socket backlog until listening again (or for
                     * another child, above the fair share).
                     */
                    continue;
                }
                if (!apr_atomic_read32(&dying)) {
                    void *csd = NULL;
                    ap_listen_rec *lr = (ap_listen_rec *) pt->baton;
                    apr_pool_t *ptrans;         /* Pool for per-transaction stuff */

                    ptrans = ap_queue_info_pop_pool(worker_queue_info);
                    if (ptrans == NULL) {
                        /* create a new transaction pool for each accepted socket */
                        apr_allocator_t *allocator = NULL;

                        rc = apr_allocator_create(&allocator);
                        if (rc == APR_SUCCESS) {
                            apr_allocator_max_free_set(allocator,
                                                       ap_max_mem_free);
                            rc = apr_pool_create_ex(&ptrans, pconf, NULL,
                                                    allocator);
                            if (rc == APR_SUCCESS) {
                                apr_pool_tag(ptrans, "transaction");
                                apr_allocator_owner_set(allocator, ptrans);
                            }
                        }
                        if (rc != APR_SUCCESS) {
                            ap_log_error(APLOG_MARK, APLOG_CRIT, rc,
                                         ap_server_conf, APLOGNO(03097)
                                         "Failed to create transaction pool");
                            if (allocator) {
                                apr_allocator_destroy(allocator);
                            }
                            resource_shortage = 1;
                            signal_threads(ST_GRACEFUL);
                            continue;
                        }
                    }

                    rc = lr->accept_func(&csd, lr, ptrans);
                    if (rc == APR_SUCCESS) {
                        conns_this_child--;

                        /* Create and account for the connection from here, or
                         * a graceful shutdown happening before it's processed
                         * would consider it does not exist and could exit the
                         * child too early.
                         */
                        ap_assert(csd != NULL);
                        cs = make_conn_state(ptrans, csd);
                        push2worker(cs, NULL, BACKLOG_NEW, now,
                                    &above_limit, 0);

                        /* Stop accepting above the fair share, with the
                         * average recomputed (fresh counts) before
                         */
                        if (fair_share_on) {
                            apr_uint32_t conns = apr_atomic_read32(&event_counts.connection_count);
                            apr_atomic_set32(&ps->connections, conns);
                            /* Rescan whatever the last scan found of the
                             * others (none before the first stats tick)
                             */
                            if (!above_limit
                                && conns > apr_atomic_read32(&fair_share_avg) + fair_share_slack) {
                                fair_share_update();
                                if (fair_share_above(0)) {
                                    disable_listensocks(now, ACCEPT_OFF_SHARE);
                                }
                            }
                        }
                    }
                    else {
                        if (rc == APR_EGENERAL) {
                            /* E[NM]FILE, ENOMEM, etc */
                            resource_shortage = 1;
                            signal_threads(ST_GRACEFUL);
                        }
                        else if (ap_accept_error_is_nonfatal(rc)) {
                            {
                                static log_ratelimit_t rl;
                                if (LOG_RATELIMIT(&rl, APLOG_DEBUG, 0, ap_server_conf, NULL)) {
                                    ap_log_error(APLOG_MARK, APLOG_DEBUG, rc, ap_server_conf,
                                                 "accept() on client socket failed");
                                }
                            }
                        }
                        ap_queue_info_push_pool(worker_queue_info, ptrans);
                    }
                }
                break;

#if HAVE_SERF
            case PT_SERF:
                /* send socket to serf. */
                /* XXXX: this doesn't require a worker thread */
                serf_event_trigger(g_serf, pt->baton, out_pfd);
                break;
#endif

            case PT_KEPT:
            case PT_USER: {
                /* A kept pfd's event is for the wait on it, if any
                 * (else remembered for the next one), never stale.
                 */
                struct kept_pfd *kept = NULL;
                int stale = 0;

                /* Multiple pfds of the same baton might trigger in this pass
                 * so chain once here and run the cleanup only after this loop
                 * to avoid lifetime issues (i.e. user_wait->pool cleared while
                 * some of its pfd->client_data are still to be dereferenced here).
                 */
                if (pt->type == PT_KEPT) {
                    kept = pt->baton;
                    user_wait = kept_pfd_fired(kept, out_pfd->rtnevents);
                    if (!user_wait) {
                        break;
                    }
                }
                else {
                    user_wait = pt->baton;
                    stale = stale_user_wait(pt);
                }
                if (!user_wait->chained) {
                    /* Ours unless completed meanwhile (timer, notifier, other
                     * thread), else this is a stale event.
                     */
                    if (stale || !claim_user_wait(user_wait)) {
                        if (kept) {
                            kept_pfd_unclaimed(kept, out_pfd->rtnevents);
                        }
                        break;
                    }
                    user_wait->chained = 1;
                    user_wait->next = user_chain;
                    user_chain = user_wait;
                }
                else if (stale) {
                    break;
                }
                if (kept) {
                    kept->delivered = 1; /* before the continuation is queued */
                }
                if (user_wait->continuation.fn) {
                    /* Tell the continuation which pfds are ready */
                    apr_array_header_t *pfds = user_wait->pfds;
                    int i;
                    for (i = 0; i < pfds->nelts; i++) {
                        apr_pollfd_t *pfd = &APR_ARRAY_IDX(pfds, i, apr_pollfd_t);
                        if (pfd->desc_type == out_pfd->desc_type
                            && (pfd->desc_type == APR_POLL_SOCKET
                                ? pfd->desc.s == out_pfd->desc.s
                                : pfd->desc.f == out_pfd->desc.f)) {
                            pfd->rtnevents |= out_pfd->rtnevents;
                        }
                    }
                }
                break;
            }

            case PT_QUEUE:
                /* The doorbell is in conn_pollset only (worker_poll) */
                break;
            }
        } /* for processing poll */

        /* Chain the notified waits too (event_notify()), if not completed
         * otherwise meanwhile. The wait is the connection's, so it can't go
         * away while its notifier is queued.
         */
        apr_thread_mutex_lock(notifiers_mutex);
        while (!APR_RING_EMPTY(notified_user_waits, ap_mpm_notifier_t, link)) {
            ap_mpm_notifier_t *notifier;
            struct user_wait *user_wait;
            notifier = APR_RING_FIRST(notified_user_waits);
            APR_RING_REMOVE(notifier, link);
            notifier->queued = 0;
            user_wait = notifier->wait;
            if (!user_wait->chained) {
                if (!claim_user_wait(user_wait)) {
                    continue;
                }
                user_wait->chained = 1;
                user_wait->next = user_chain;
                user_chain = user_wait;
            }
            user_wait->wait_notified = 1;
        }
        apr_thread_mutex_unlock(notifiers_mutex);

        /* Time to queue user callbacks chained above */
        while (user_chain) {
            struct user_wait *user_wait = user_chain;
            user_chain = user_wait->next;
            user_wait->next = NULL;
            user_wait->chained = 0;

            cs = user_wait->cs;
            AP_DEBUG_ASSERT(cs != NULL);
            AP_DEBUG_ASSERT(cs->user_wait == user_wait);
            AP_DEBUG_ASSERT(!cs->te); /* freed by claim_user_wait() */
            AP_DEBUG_ASSERT(cs->pub.state == CONN_STATE_SUSPENDED);
            AP_DEBUG_ASSERT(cs->suspended);

            /* The continuation to run, if any (ap_mpm_register_wait()) */
            if (user_wait->continuation.fn) {
                set_user_continuation(cs, user_wait, user_wait->wait_notified
                                                        ? AP_MPM_WAIT_NOTIFIED
                                                        : AP_MPM_WAIT_READY);
            }

            /* Remove all user pollfds from the pollset */
            apr_pool_cleanup_run(user_wait->pool, user_wait,
                                 user_wait_cleanup);
            cs->user_wait = NULL;

            /* Schedule ap_run_resume_connection() */
            push2worker(cs, NULL, BACKLOG_CONTINUATION, now, &above_limit, 0);
        }

        if (worker_poll) {
            flush_limbo();
        }

#ifdef EVENT_ELASTIC_THREADS
        if (elastic_threads) {
            workers_grow_check(now);
        }
#endif

        /* We process the timeout queues here only when the global
         * conn_queues.next_expiry has passed. This happens accurately since
         * adding to the queues (in workers) can only decrease this expiry,
         * while latest ones are only taken into account here (in listener)
         * during queues' processing, with the lock held. This works both
         * with and without wake-ability.
         * Even if "now" drifted a bit since it was fetched and the real
         * "now" went below "expiry" in the meantime, the next poll() will
         * return immediately so the maintenance will happen then.
         */
        next_expiry = conn_queues.next_expiry;
        if (next_expiry && next_expiry <= now) {
do_maintenance:
            ap_log_error(APLOG_MARK, APLOG_TRACE7, 0, ap_server_conf,
                         "queues maintenance: expired=%" APR_TIME_T_FMT,
                         next_expiry > 0 ? now - next_expiry : -1);

            apr_thread_mutex_lock(conn_queues.mutex);

            /* Recompute this by walking the timeout queues (under the lock) */
            conn_queues.next_expiry = 0;

            /* Process shutdown_q first because the expired entries from the
             * other queues will go there and don't need to be checked twice
             * (nor do we want to potentially kill them before the shutdown).
             * The expired shutting down and lingering connections are closed
             * after releasing conn_queues.mutex (their pool cleanups must not
             * run under it).
             */
            (void)process_timeout_queue_ex(shutdown_q, now, 0, &expired);

            /* No specific requirement/order for those */
            process_timeout_queue(waitio_q, now);
            process_timeout_queue(write_completion_q, now);
            process_timeout_queue(keepalive_q, now);

            /* The linger queue is shrunk while the connections are full,
             * at most every QUEUES_SHRINK_TIMEOUT.
             */
            if (next_shrink_time <= now && connections_full()) {
                shrink_timeout_queue(linger_q, now, &expired);
                next_shrink_time = now + QUEUES_SHRINK_TIMEOUT;
            }
            else {
                (void)process_timeout_queue_ex(linger_q, now, 0, &expired);
            }

            /* Connections in backlog race with the workers (dequeuing) under
             * the worker_queue mutex. Shut the timed out ones down after
             * releasing it: that pushes them to a worker, which takes the
             * mutex, or clears their pool, whose cleanups must not run under
             * it (e.g. decrement_connection_count() evaluates the admission).
             */
            if (apr_atomic_read32(backlog_q->total)) {
                event_conn_state_t *bl_timed_out = NULL;

                ap_queue_lock(worker_queue);
                (void)process_timeout_queue_ex(backlog_q, now, 0, &bl_timed_out);
                ap_queue_unlock(worker_queue);

                shutdown_timed_out(bl_timed_out, now, 1);
            }

            next_expiry = conn_queues.next_expiry;
            apr_thread_mutex_unlock(conn_queues.mutex);

            shutdown_timed_out(expired, now, 0);

            ap_log_error(APLOG_MARK, APLOG_TRACE7, 0, ap_server_conf,
                         "queues maintained: next timeout=%" APR_TIME_T_FMT,
                         next_expiry ? next_expiry - now : -1);
        }
        else if (next_shrink_time <= now
                 && apr_atomic_read32(linger_q->total)
                 && connections_full()) {
            apr_thread_mutex_lock(conn_queues.mutex);
            shrink_timeout_queue(linger_q, now, &expired);
            apr_thread_mutex_unlock(conn_queues.mutex);
            next_shrink_time = now + QUEUES_SHRINK_TIMEOUT;

            shutdown_timed_out(expired, now, 0);
        }
    } /* listener main loop */

    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ap_server_conf,
                 "listener thread exiting");

    ap_queue_term(worker_queue);
    ring_doorbell();

    apr_thread_exit(thd, APR_SUCCESS);
    return NULL;
}

/*
 * During graceful shutdown, if there are more running worker threads than
 * open connections, exit one worker thread.
 *
 * return 1 if thread should exit, 0 if it should continue running.
 */
static int worker_thread_should_exit_early(int slot)
{
    for (;;) {
        apr_uint32_t conns = apr_atomic_read32(&event_counts.connection_count);
        apr_uint32_t live = apr_atomic_read32(&workers_live);

        AP_DEBUG_ASSERT(live > 0);
        if (conns >= live)
            return 0;

        /* Counted out of the live workers by this exit (worker_thread()) */
        if (apr_atomic_cas32(&workers_live, live - 1, live) == live) {
            /*
             * No other thread has exited in the mean time, safe to exit
             * this one.
             */
            apr_uint32_t deads = apr_atomic_inc32(&threads_shutdown) + 1;

            apr_atomic_dec32(&ap_scoreboard_image->parent[ap_child_slot]
                             .workers_live);
            ap_log_error(APLOG_MARK, APLOG_TRACE5, 0, ap_server_conf,
                         "worker thread %i/%i-%i should exit (%i conns)",
                         slot, threads_per_child, deads, conns);
            return 1;
        }
    }
}

/* Drain epochs: a worker polling conn_pollset (worker_poll_one()) publishes
 * the current epoch in its slot until it's done with what it polled (claimed
 * or dropped). A closed connection's pool is recycled only once no slot holds
 * an epoch older than its close (its fd closed before, so no event for it can
 * be returned to a later poll); otherwise it waits in the limbo, flushed when
 * the slots move on (the connection is counted out at its close already,
 * connection_count_out()). Only needed when the workers poll (worker_poll).
 */
static /*atomic*/ apr_uint32_t drain_epoch = 1;
struct limbo_pool {
    apr_pool_t *p;
    apr_uint32_t epoch;
    struct limbo_pool *next;
};
static struct limbo_pool *limbo_head, *limbo_tail;
static apr_thread_mutex_t *limbo_mutex;

#ifdef EVENT_WORKER_POLL
static void drain_epoch_enter(int slot)
{
    apr_atomic_set32(&worker_slots[slot].drain_epoch,
                     apr_atomic_read32(&drain_epoch));
}

static void drain_epoch_leave(int slot)
{
    apr_atomic_set32(&worker_slots[slot].drain_epoch, 0);

    /* Leaving may let the pools in the limbo be recycled, so flush it now
     * rather than at the listener's next loop. The check is racy: a pool added
     * meanwhile and missed here is flushed by the next leave, or by the
     * listener's loop which flushes too.
     */
    if (limbo_head) {
        flush_limbo();
    }
}
#endif

/* Whether the pools closed at epoch can be recycled (wrap-safe) */
static int drain_epoch_passed(apr_uint32_t epoch)
{
    int i;
    for (i = 0; i < threads_max; i++) {
        apr_uint32_t held = apr_atomic_read32(&worker_slots[i].drain_epoch);
        if (held && (apr_int32_t)(held - epoch) <= 0) {
            return 0;
        }
    }
    return 1;
}

static void flush_limbo(void)
{
    struct limbo_pool *lp;

    if (!limbo_head) { /* racy but rechecked under the lock */
        return;
    }
    apr_thread_mutex_lock(limbo_mutex);
    while ((lp = limbo_head) && drain_epoch_passed(lp->epoch)) {
        limbo_head = lp->next;
        if (!limbo_head) {
            limbo_tail = NULL;
        }
        ap_queue_info_push_pool(worker_queue_info, lp->p);
    }
    apr_thread_mutex_unlock(limbo_mutex);
}

static int worker_queue_empty(void)
{
    int i;
    for (i = 0; i < BACKLOG_CLASSES; i++) {
        if (ap_queue_lane_nelts(worker_queue, i)) {
            return 0;
        }
    }
    return 1;
}

/* Recycle the pool of a closed connection (its socket closed already) */
static void recycle_connection_pool(apr_pool_t *p)
{
    struct limbo_pool *lp;
    apr_uint32_t epoch;

    if (!worker_poll) {
        ap_queue_info_push_pool(worker_queue_info, p);
        return;
    }

    epoch = apr_atomic_inc32(&drain_epoch);
    if (drain_epoch_passed(epoch)) {
        ap_queue_info_push_pool(worker_queue_info, p);
        flush_limbo();
        return;
    }

    lp = apr_palloc(p, sizeof(*lp));
    lp->p = p;
    lp->epoch = epoch;
    lp->next = NULL;
    apr_thread_mutex_lock(limbo_mutex);
    if (limbo_tail) {
        limbo_tail->next = lp;
    }
    else {
        limbo_head = lp;
    }
    limbo_tail = lp;
    apr_thread_mutex_unlock(limbo_mutex);
}

#ifdef EVENT_WORKER_POLL
/* worker_poll: a worker polls conn_pollset itself (one event, without waiting
 * or blocking up to timeout when idle) and runs what it gets, without the
 * listener -> worker hand-off (queue + futex wake/wait). One-shot pfds make a
 * fired fd a single thread's, and the worker claims what the event is for
 * (claim_connection(), claim_user_wait()), dropping it if another thread
 * completed it already; what it holds stays valid until then (the
 * connection's wait, drain epochs). Returns the connection to run, if any,
 * *doorbell set if the doorbell is what it got.
 */
static event_conn_state_t *worker_poll_one(int slot,
                                           apr_interval_time_t timeout,
                                           int *doorbell)
{
    apr_pollfd_t out;
    apr_int32_t num = 0;
    listener_poll_type *pt;
    event_conn_state_t *cs = NULL;

    DRAIN_STAT_INC(drain_polls);
    drain_epoch_enter(slot);
    if (apr_pollset_poll_into(conn_pollset, timeout, 1, &out,
                              &num) != APR_SUCCESS
        || num != 1) {
        drain_epoch_leave(slot);
        return NULL;
    }
    pt = out.client_data;
    if (!pt) {
        /* a stale wait's pfd copy (its wait completed meanwhile) */
        drain_epoch_leave(slot);
        return NULL;
    }

    switch (pt->type) {
    case PT_QUEUE:
        *doorbell = 1;
        break;

    case PT_CSD:
        cs = pt->baton;
        if (!claim_connection(cs)) {
            DRAIN_STAT_INC(drain_dropped);
            cs = NULL;
            break;
        }
        switch (cs->pub.state) {
        case CONN_STATE_KEEPALIVE:
        case CONN_STATE_ASYNC_WAITIO:
            cs->pub.state = CONN_STATE_PROCESSING;
            break;
        case CONN_STATE_WRITE_COMPLETION:
        case CONN_STATE_LINGER:
            break;
        default:
            ap_assert(0);
        }
        DRAIN_STAT_INC(drain_csd);
        break;

    case PT_KEPT:
    case PT_USER: {
        struct user_wait *user_wait;
        struct kept_pfd *kept = NULL;
        apr_array_header_t *pfds;
        int i;

        if (pt->type == PT_KEPT) {
            /* For the wait on it, else remembered for the next */
            kept = pt->baton;
            user_wait = kept_pfd_fired(kept, out.rtnevents);
            if (!user_wait) {
                DRAIN_STAT_INC(drain_dropped);
                break;
            }
            if (!claim_user_wait(user_wait)) {
                kept_pfd_unclaimed(kept, out.rtnevents);
                DRAIN_STAT_INC(drain_dropped);
                break;
            }
            kept->delivered = 1; /* before the continuation runs */
        }
        else {
            user_wait = pt->baton;
            if (stale_user_wait(pt) || !claim_user_wait(user_wait)) {
                DRAIN_STAT_INC(drain_dropped);
                break;
            }
        }
        cs = user_wait->cs;
        AP_DEBUG_ASSERT(cs->user_wait == user_wait);

        /* Tell the continuation which pfd is ready */
        pfds = user_wait->pfds;
        for (i = 0; i < pfds->nelts; i++) {
            apr_pollfd_t *pfd = &APR_ARRAY_IDX(pfds, i, apr_pollfd_t);
            if (pfd->desc_type == out.desc_type
                && (pfd->desc_type == APR_POLL_SOCKET
                    ? pfd->desc.s == out.desc.s
                    : pfd->desc.f == out.desc.f)) {
                pfd->rtnevents |= out.rtnevents;
            }
        }
        if (user_wait->continuation.fn) {
            set_user_continuation(cs, user_wait, AP_MPM_WAIT_READY);
        }
        apr_pool_cleanup_run(user_wait->pool, user_wait, user_wait_cleanup);
        cs->user_wait = NULL;
        DRAIN_STAT_INC(drain_user);
        break;
    }

    default:
        break; /* listening sockets (level-triggered, the listener's) */
    }

    /* A claimed connection is ours (can't be closed by others), done with
     * the event otherwise
     */
    drain_epoch_leave(slot);
    return cs;
}

/* A poller leaving conn_pollset with nobody blocked there anymore while
 * workers are parked: queue the worker_poll_baton for one of them to come and
 * poll (once, until popped). Both the pollers here and the parking workers
 * update their counter before reading the other's, with atomic
 * read-modify-writes, so either a parking worker sees a free slot or the
 * pollers see it parked. Hence apr_atomic_add32(x, 0) for these reads:
 * apr_atomic_read32() isn't ordered after a previous update everywhere (e.g.
 * the mutex based or ppc implementations, a plain load there).
 */
static void worker_poll_promote(void)
{
    if (!apr_atomic_add32(&worker_poll_stats.blocked, 0)
        && apr_atomic_add32(&worker_poll_stats.parked, 0)
        && !apr_atomic_cas32(&worker_poll_stats.baton, 1, 0)) {
        if (ap_queue_push_event(worker_queue, &worker_poll_baton, 0) != APR_SUCCESS) {
            apr_atomic_set32(&worker_poll_stats.baton, 0);
            return;
        }
        DRAIN_STAT_INC(poll_promotions);
    }
}

/* worker_poll_one() with a poll slot (AsyncWorkerPollers), *polled zero if
 * there's none.
 */
static event_conn_state_t *worker_poll_slot(int slot,
                                            apr_interval_time_t timeout,
                                            int *doorbell, int *polled)
{
    event_conn_state_t *cs;

    if (apr_atomic_inc32(&worker_poll_stats.slots) >= worker_poll_slots_max) {
        apr_atomic_dec32(&worker_poll_stats.slots);
        DRAIN_STAT_INC(poll_misses);
        *polled = 0;
        return NULL;
    }
    *polled = 1;

    if (timeout) {
        apr_atomic_inc32(&worker_poll_stats.blocked);
    }
    cs = worker_poll_one(slot, timeout, doorbell);
    if (timeout) {
        apr_atomic_dec32(&worker_poll_stats.blocked);
    }
    apr_atomic_dec32(&worker_poll_stats.slots);

    /* Leaving to run a connection (otherwise this worker polls again) */
    if (cs) {
        worker_poll_promote();
    }
    return cs;
}

/* Wait on the worker_queue for an event (or the worker_poll_baton) rather than
 * in conn_pollset, no poll slot being available. APR_EAGAIN if one is now,
 * APR_TIMEUP after timeout if positive.
 */
static apr_status_t worker_park(ap_queue_event_t **pqe,
                                apr_interval_time_t timeout)
{
    apr_status_t rv;

    apr_atomic_inc32(&worker_poll_stats.parked);
    if (apr_atomic_add32(&worker_poll_stats.slots, 0) < worker_poll_slots_max) {
        /* A slot freed meanwhile, the pollers may not have seen us */
        apr_atomic_dec32(&worker_poll_stats.parked);
        return APR_EAGAIN;
    }
    rv = (timeout > 0) ? ap_queue_pop_event_timeout(worker_queue, pqe, timeout)
                       : ap_queue_pop_event(worker_queue, pqe);
    apr_atomic_dec32(&worker_poll_stats.parked);
    return rv;
}

/* worker_poll: wake up one worker blocked polling conn_pollset, unless a
 * ring is pending already (the woken worker rings again if more is queued).
 */
static void ring_doorbell(void)
{
    char c = 0;
    apr_size_t n = 1;

    if (worker_poll && apr_atomic_cas32(&doorbell_state.rung, 1, 0) == 0) {
        (void)apr_file_write(doorbell_out, &c, &n);
    }
}

/* A worker woken up by the doorbell: empty and re-arm it (one-shot) */
static void answer_doorbell(void)
{
    char buf[64];
    apr_size_t n;

    do {
        n = sizeof(buf);
    } while (apr_file_read(doorbell_in, buf, &n) == APR_SUCCESS
             && n == sizeof(buf));
    apr_atomic_set32(&doorbell_state.rung, 0);
    (void)apr_pollset_add(conn_pollset, &doorbell_pfd);
}

/* worker_poll: a worker shares its time between the connections it polls and
 * the queued events (mostly new connections), BACKLOG_WEIGHT_WAITING to
 * BACKLOG_WEIGHT_NEW, like the queue's lanes weigh them (the polled ones are
 * mostly keepalive and waitio connections), so that the new connections are
 * the ones waiting under load (what the admission measures); either source
 * when the other is empty. By time rather than by count: polled events much
 * longer than the queued ones (e.g. workers blocking) would otherwise keep the
 * queue's share below its arrivals, which refusing new connections doesn't
 * change. The time due to either source is capped to admission_interval, so
 * that a long event doesn't make the other source wait for long after it.
 */
struct worker_poll_round {
    apr_time_t polled, queued; /* weighted time spent on each source */
    apr_time_t since;          /* when the current event was taken, if any */
    int from_poll;             /* whether it was polled */
};

static void worker_poll_round_charge(struct worker_poll_round *round,
                                     apr_time_t now)
{
    if (round->since) {
        apr_time_t spent = (now > round->since) ? now - round->since : 0;
        if (round->from_poll) {
            round->polled += spent * BACKLOG_WEIGHT_NEW;
        }
        else {
            round->queued += spent * BACKLOG_WEIGHT_WAITING;
        }
        round->since = 0;
    }
    if (round->polled > round->queued + admission_interval) {
        round->polled = round->queued + admission_interval;
    }
    else if (round->queued > round->polled + admission_interval) {
        round->queued = round->polled + admission_interval;
    }
}

/* worker_poll: a worker blocked in conn_pollset holds the epoch it entered
 * before polling (see worker_poll_one()), so the pools recycled meanwhile
 * wait in the limbo until its poll returns. Nothing can make a given blocked
 * worker return early (the doorbell or a pollset wakeup wake the threads
 * blocked on an epoll in LIFO order, so never the ones blocked for long), so
 * the timeout bounds that wait: 1s keeps the idle wakeups low (once per
 * second per idle worker) and the limbo to the pools of the last second.
 */
#define WORKER_POLL_TIMEOUT apr_time_from_sec(1)

/* worker_poll: the next queued event (*pqe), or a connection polled by
 * this (idle) worker to run (*pcs), blocking in conn_pollset while there's
 * none, in this worker's *round. APR_TIMEUP after WORKER_POLL_TIMEOUT
 * without anything, for the caller to check the exit conditions (the exits
 * ring the doorbell anyway) and this thread's drain epoch to move on, or
 * after park_timeout if positive when parked on the worker_queue.
 */
static apr_status_t worker_poll_next(int slot,
                                     struct worker_poll_round *round,
                                     ap_queue_event_t **pqe,
                                     event_conn_state_t **pcs,
                                     apr_interval_time_t park_timeout)
{
    apr_time_t now = event_time_now();
    int answered = 0;

    worker_poll_round_charge(round, now);
    for (;;) {
        event_conn_state_t *cs;
        int doorbell = 0, pop_first, polled;
        apr_status_t rv;

        /* Woken up by the doorbell: something is queued for this worker,
         * which the doorbell rang once for, so pop it before polling (an
         * event polled instead would leave it queued with nobody woken up
         * for it, until the next ring)
         */
        pop_first = answered;
#ifdef EVENT_WORKER_NOTIFY
        /* Its own continuation queued without ringing (event_notify()) */
        pop_first |= worker_wake_queued;
        worker_wake_queued = 0;
#endif
        if (!pop_first && round->polled <= round->queued) {
            cs = worker_poll_slot(slot, 0, &doorbell, &polled);
            if (cs) {
                round->since = now;
                round->from_poll = 1;
                *pcs = cs;
                return APR_SUCCESS;
            }
            if (doorbell) {
                answer_doorbell(); /* something queued */
                answered = 1;
            }
        }

        rv = ap_queue_trypop_event(worker_queue, pqe);
        if (rv == APR_SUCCESS && *pqe == &worker_poll_baton) {
            apr_atomic_set32(&worker_poll_stats.baton, 0);
            continue; /* this worker polls anyway, after what's rung for */
        }
        answered = 0;
        if (rv == APR_SUCCESS) {
            round->since = now;
            round->from_poll = 0;
            if (!worker_queue_empty()) {
                ring_doorbell(); /* more for another worker */
            }
            return APR_SUCCESS;
        }
        /* Nothing queued, the time due starts again */
        round->polled = round->queued = 0;
        if (!APR_STATUS_IS_EAGAIN(rv)) {
            /* APR_EOF, APR_EINTR: pass the doorbell on, the other blocked
             * workers have to see it too (they'd wait for their timeout)
             */
            ring_doorbell();
            return rv;
        }
        if (apr_atomic_read32(&workers_may_exit)) {
            ring_doorbell(); /* the next blocked worker exits too */
            return APR_EINTR;
        }

        /* Nothing either way, wait for something: in conn_pollset with a
         * slot, else parked on the worker_queue
         */
        cs = worker_poll_slot(slot, WORKER_POLL_TIMEOUT, &doorbell, &polled);
        if (!polled) {
            rv = worker_park(pqe, park_timeout);
            now = event_time_now();
            if (rv == APR_SUCCESS && *pqe == &worker_poll_baton) {
                apr_atomic_set32(&worker_poll_stats.baton, 0);
                continue; /* promoted, come and poll */
            }
            if (rv == APR_SUCCESS) {
                round->since = now;
                round->from_poll = 0;
                return APR_SUCCESS;
            }
            if (APR_STATUS_IS_EAGAIN(rv)) {
                continue; /* a slot freed meanwhile */
            }
            return rv;
        }
        now = event_time_now();
        if (cs) {
            round->since = now;
            round->from_poll = 1;
            *pcs = cs;
            return APR_SUCCESS;
        }
        if (!doorbell) {
            return APR_TIMEUP;
        }
        answer_doorbell();
        answered = 1;
    }
}
#endif /* EVENT_WORKER_POLL */

/* An extra worker (elastic_threads) idle since idle_since retires, unless
 * something is queued meanwhile: it'd be the one waiting for it maybe. It
 * leaves the idlers then, unless none is left: the listener counted on it
 * for an event it's queuing, it stays to take it.
 */
static int worker_should_retire(apr_time_t idle_since)
{
    return (!apr_atomic_read32(&dying)
            && event_time_now() - idle_since >= AUTO_WORKER_RETIRE_TIMEOUT
            && worker_queue_empty()
            && ap_queue_info_try_get_idler(worker_queue_info) == APR_SUCCESS);
}

/* XXX For ungraceful termination/restart, we definitely don't want to
 *     wait for active connections to finish but we may want to wait
 *     for idle workers to get out of the queue code and release mutexes,
 *     since those mutexes are cleaned up pretty soon and some systems
 *     may not react favorably (i.e., segfault) if operations are attempted
 *     on cleaned-up mutexes.
 */
/* An extra worker (elastic_threads) done with some work retires when the child
 * hasn't been short of workers (none idle) for AUTO_WORKER_RETIRE_TIMEOUT,
 * one per second at most: with the idle workers sharing the work (polling the
 * connections) none may stay idle that long while the extra ones aren't
 * needed anymore.
 */
static int worker_unneeded(void)
{
    apr_time_t now = event_time_now();
    apr_uint32_t sec = (apr_uint32_t)apr_time_sec(now), last;

    if (apr_atomic_read32(&dying)
        || now - workers_last_short < AUTO_WORKER_RETIRE_TIMEOUT) {
        return 0;
    }
    last = apr_atomic_read32(&workers_retire_sec);
    return (last != sec
            && apr_atomic_cas32(&workers_retire_sec, sec, last) == last);
}

static void *APR_THREAD_FUNC worker_thread(apr_thread_t * thd, void *dummy)
{
    proc_info *ti = dummy;
    int process_slot = ti->pslot;
    int thread_slot = ti->tslot;
    worker_score *ws = &ap_scoreboard_image->servers[process_slot][thread_slot];
    int is_idler = 0;
    /* An extra worker waits for work for this long before checking whether
     * it should retire, idle since idle_since.
     */
    const apr_interval_time_t idle_timeout =
        (thread_slot >= threads_per_child) ? WORKER_IDLE_TIMEOUT : -1;
    apr_time_t idle_since = 0;
    int retire = 0, counted_out = 0;
#ifdef EVENT_WORKER_POLL
    struct worker_poll_round round = {0, 0, 0, 0}; /* worker_poll_next()'s */
#endif
    apr_status_t rv;

    free(ti);

    ws->pid = ap_my_pid;
    ws->tid = apr_os_thread_current();
    ws->generation = retained->mpm->my_generation;
    ap_update_child_status_from_indexes(process_slot, thread_slot,
                                        SERVER_STARTING, NULL);
#ifdef EVENT_WORKER_NOTIFY
    worker_thread_polls = worker_poll;
#endif
#ifdef AP_THREAD_LOCAL
    worker_current_slot = &worker_slots[thread_slot];
#endif

    for (;;) {
        ap_queue_event_t *qe;

        if (!is_idler) {
            int idlers;

            if (idle_timeout > 0 && idle_since && worker_unneeded()) {
                retire = 1;
                break;
            }
            idlers = ap_queue_info_idlers_inc(worker_queue_info);
            ap_log_error(APLOG_MARK, APLOG_TRACE7, 0, ap_server_conf,
                         "worker thread %i/%i idle (idlers %i)",
                         thread_slot, threads_per_child, idlers);
            is_idler = 1;
            if (idle_timeout > 0) {
                idle_since = event_time_now();
            }

            /* If the listening sockets are paused and this new idler switches
             * connections_above_limit() back, let the listener know and poll
             * them again.
             */
            if (should_enable_listensocks(0)) {
                wakeup_listener_by(ACCEPT_WAKE_WORKER);
            }
        }

        ap_update_child_status_from_indexes(process_slot, thread_slot,
                                            (apr_atomic_read32(&dying)
                                             ? SERVER_GRACEFUL : SERVER_READY),
                                            NULL);

        if (apr_atomic_read32(&workers_may_exit)) {
            ap_log_error(APLOG_MARK, APLOG_TRACE5, 0, ap_server_conf,
                         "worker thread %i/%i may exit",
                         thread_slot, threads_per_child);
            break;
        }
        if (apr_atomic_read32(&dying)
            && worker_thread_should_exit_early(thread_slot)) {
            counted_out = 1;
            break;
        }

#ifdef EVENT_WORKER_POLL
        if (worker_poll) {
            event_conn_state_t *cs = NULL;
            rv = worker_poll_next(thread_slot, &round, &qe, &cs, idle_timeout);
            if (APR_STATUS_IS_TIMEUP(rv)) {
                if (idle_timeout > 0 && worker_should_retire(idle_since)) {
                    is_idler = 0; /* left by worker_should_retire() */
                    retire = 1;
                    break;
                }
                continue; /* still idle */
            }
            if (rv == APR_SUCCESS && cs) {
                /* Polled here, no push2worker() accounted for it */
                apr_socket_t *csd = cs_se(cs)->sd;
                ap_queue_info_idlers_dec(worker_queue_info);
                is_idler = 0;
                (void)apr_atomic_xchgptr((void *volatile *)
                                         &worker_slots[thread_slot].csd, csd);
                process_socket(thd, cs->p, csd, cs, process_slot, thread_slot);
                (void)apr_atomic_xchgptr((void *volatile *)
                                         &worker_slots[thread_slot].csd, NULL);
                continue;
            }
        }
        else
#endif
        rv = (idle_timeout > 0) ? ap_queue_pop_event_timeout(worker_queue, &qe,
                                                             idle_timeout)
                                : ap_queue_pop_event(worker_queue, &qe);
        if (APR_STATUS_IS_TIMEUP(rv)) {
            if (worker_should_retire(idle_since)) {
                is_idler = 0; /* left by worker_should_retire() */
                retire = 1;
                break;
            }
            continue; /* still idle */
        }
        if (rv != APR_SUCCESS) {
            /* We get APR_EOF during a graceful shutdown once all the
             * connections accepted by this server process have been handled.
             */
            if (APR_STATUS_IS_EOF(rv)) {
                ap_log_error(APLOG_MARK, APLOG_TRACE5, 0, ap_server_conf,
                             "worker thread %i/%i queue terminated",
                             thread_slot, threads_per_child);
                break;
            }

            /* We get APR_EINTR whenever ap_queue_pop_event() has been
             * interrupted from an explicit call to ap_queue_interrupt_*().
             * This allows us to unblock threads stuck in ap_queue_pop_event()
             * when a shutdown is pending.
             *
             * If workers_may_exit is set and this is ungraceful stop or
             * restart, we are bound to get an error on some systems (e.g.,
             * AIX, which sanity-checks mutex operations) since the queue
             * may have already been cleaned up.  Don't log the "error" if
             * workers_may_exit is set.
             */
            if (!APR_STATUS_IS_EINTR(rv) && !apr_atomic_read32(&workers_may_exit)) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf,
                             APLOGNO(03099) "ap_queue_pop_event failed");
                AP_DEBUG_ASSERT(0);
                signal_threads(ST_GRACEFUL);
            }
            continue;
        }

        is_idler = 0; /* event consumed */
        if (backlog_stats_on || qe->qclass == BACKLOG_NEW) {
            apr_time_t now = event_time_now();
            if (backlog_stats_on) {
                backlog_stats_record(qe->qclass, now - qe->queued_at);
            }
            if (qe->qclass == BACKLOG_NEW) {
                admission_sample(now - qe->queued_at, now);

                /* Taking the new connections is what clears the admission
                 * (the oldest one waiting, see admission_above_target()): if
                 * the listener can accept again, let it know now rather than
                 * when this worker idles.
                 */
                if (listensocks_disabled_for(ACCEPT_OFF_LIMIT)
                    && should_enable_listensocks(now)) {
                    wakeup_listener_by(ACCEPT_WAKE_WORKER);
                }
            }
        }
        ap_log_error(APLOG_MARK, APLOG_TRACE7, 0, ap_server_conf,
                     "worker thread %i/%i busy (idlers %i)",
                     thread_slot, threads_per_child,
                     ap_queue_info_idlers_count(worker_queue_info));

        if (qe->type == AP_QUEUE_EVENT_SOCK) {
            apr_pool_t *p;
            apr_socket_t *csd;
            event_conn_state_t *cs;

            ap_assert(qe->data.se);
            p = qe->data.se->p;
            csd = qe->data.se->sd;
            cs = qe->data.se->baton;
            ap_assert(p && csd && cs && qe == cs_qe(cs));

            (void)apr_atomic_xchgptr((void *volatile *)
                                     &worker_slots[thread_slot].csd, csd);
            process_socket(thd, p, csd, cs, process_slot, thread_slot);
            (void)apr_atomic_xchgptr((void *volatile *)
                                     &worker_slots[thread_slot].csd, NULL);
        }
        else if (qe->type == AP_QUEUE_EVENT_TIMER) {
            timer_event_t *te;
            ap_mpm_callback_fn_t *cbfunc;
            void *baton;

            te = qe->data.te;
            ap_assert(te && qe == te_qe(te));

            cbfunc = te->cbfunc;
            baton = te->baton;

            /* first recycle the timer event */
            put_timer_event(te, 0);

            ap_update_child_status_from_indexes(process_slot, thread_slot,
                                                SERVER_BUSY_WRITE, NULL);
            ap_assert(cbfunc != NULL);
            cbfunc(baton);
        }
        else {
            ap_assert(0);
        }
    }
    if (is_idler) {
        /* Not idling anymore */
        ap_queue_info_idlers_dec(worker_queue_info);
    }
#ifdef EVENT_WORKER_POLL
    if (retire && worker_poll) {
        /* Maybe the last one blocked in conn_pollset, while others park */
        worker_poll_promote();
    }
#endif
#ifdef EVENT_WORKER_NOTIFY
    worker_thread_polls = 0;
    if (worker_wake_queued) {
        /* Exiting before popping it, another worker will: a polling one
         * (the doorbell) or a parked one, woken up by the interrupt and
         * popping what's queued first (the interrupt itself goes to whichever
         * pop finds the queue empty later, see ap_queue_interrupt_one())
         */
        worker_wake_queued = 0;
        ring_doorbell();
        if (workers_parked()) {
            ap_queue_interrupt_one(worker_queue);
        }
    }
#endif

    ap_update_child_status_from_indexes(process_slot, thread_slot,
                                        (retire || apr_atomic_read32(&dying)
                                         ? SERVER_DEAD : SERVER_GRACEFUL),
                                        NULL);
    if (!counted_out) {
        workers_live_dec();
    }
    if (retire) {
        ap_log_error(APLOG_MARK, APLOG_TRACE5, 0, ap_server_conf,
                     "worker thread %i/%i retired (idle)",
                     thread_slot, threads_per_child);
        apr_atomic_inc32(&workers_retired);
        apr_atomic_inc32(&workers_unjoined);
        /* Last, the listener may join this thread and reuse its slot then */
        apr_atomic_set32(&worker_slots[thread_slot].retired, 1);
    }

    apr_thread_exit(thd, APR_SUCCESS);
    return NULL;
}

static int check_signal(int signum)
{
    switch (signum) {
    case SIGTERM:
    case SIGINT:
        return 1;
    }
    return 0;
}

static void create_listener_thread(thread_starter * ts)
{
    int my_child_num = ts->child_num_arg;
    apr_threadattr_t *thread_attr = ts->threadattr;
    proc_info *my_info;
    apr_status_t rv;

    my_info = (proc_info *) ap_malloc(sizeof(proc_info));
    my_info->pslot = my_child_num;
    my_info->tslot = -1;      /* listener thread doesn't have a thread slot */
    rv = ap_thread_create(&ts->listener, thread_attr, listener_thread,
                          my_info, pruntime);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, rv, ap_server_conf, APLOGNO(00474)
                     "ap_thread_create: unable to create listener thread");
        /* let the parent decide how bad this really is */
        clean_child_exit(APEXIT_CHILDSICK);
    }
}

static void setup_threads_runtime(void)
{
    apr_status_t rv;
    ap_listen_rec *lr;
    apr_pool_t *pskip = NULL;
    int max_recycled_pools = -1, i;
    /* The size is the events returned by a poll (the connections the good
     * methods hold are unbounded).
     */
    const apr_size_t pollset_size = ((apr_size_t)threads_per_child * 2 +
                                     (apr_size_t)num_listensocks +
                                     POLLSET_RESERVE_SIZE);
    int pollset_flags;

    backlog_stats_on = APLOGtrace2(ap_server_conf);

    /* Event's skiplist operations will happen concurrently with other modules'
     * runtime so they need their own pool for allocations, and its lifetime
     * should be at least the one of the connections (ptrans). Thus pskip is
     * created as a subpool of pconf like/before ptrans (before so that it's
     * destroyed after). In forked mode pconf is never destroyed so we are good
     * anyway, but in ONE_PROCESS mode this ensures that the skiplist works
     * from connection/ptrans cleanups (even after pchild is destroyed).
     */
    apr_pool_create(&pskip, pconf);
    apr_pool_tag(pskip, "mpm_skiplist");
    apr_thread_mutex_create(&g_timer_skiplist_mtx, APR_THREAD_MUTEX_DEFAULT, pskip);
    APR_RING_INIT(&timer_free_ring.link, timer_event_t, link);
    apr_skiplist_init(&timer_skiplist, pskip);
    apr_skiplist_set_compare(timer_skiplist, timer_comp, timer_comp);
    make_wait_queues(pskip);

    /* All threads (listener, workers) and synchronization objects (queues,
     * pollset, mutexes...) created here should have at least the lifetime of
     * the connections they handle (i.e. ptrans). We can't use this thread's
     * self pool because all these objects survive it, nor use pchild or pconf
     * directly because this starter thread races with other modules' runtime,
     * nor finally pchild (or subpool thereof) because it is killed explicitly
     * before pconf (thus connections/ptrans can live longer, which matters in
     * ONE_PROCESS mode). So this leaves us with a subpool of pconf, created
     * before any ptrans hence destroyed after.
     */
    apr_pool_create(&pruntime, pconf);
    apr_pool_tag(pruntime, "mpm_runtime");

    /* We must create the fd queues before we start up the listener
     * and worker threads, it's bounded by connections_above_limit(). */
    rv = ap_queue_create(&worker_queue, -1, pruntime);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, rv, ap_server_conf, APLOGNO(03100)
                     "ap_queue_create() failed");
        clean_child_exit(APEXIT_CHILDFATAL);
    }
    /* The lanes (the backlog classes), the new connections' one needed by
     * the admission.
     */
    rv = ap_queue_set_lanes(worker_queue, BACKLOG_CLASSES,
                            backlog_class_weights);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, rv, ap_server_conf, APLOGNO()
                     "ap_queue_set_lanes() failed");
        clean_child_exit(APEXIT_CHILDFATAL);
    }
    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ap_server_conf,
                 "admission: target %" APR_TIME_T_FMT "ms, interval %"
                 APR_TIME_T_FMT "ms", apr_time_as_msec(admission_target),
                 apr_time_as_msec(admission_interval));

    if (ap_max_mem_free != APR_ALLOCATOR_MAX_FREE_UNLIMITED) {
        /* If we want to conserve memory, let's not keep an unlimited number of
         * pools & allocators.
         * XXX: This should probably be a separate config directive
         */
        max_recycled_pools = threads_per_child * 3 / 4 ;
    }
    rv = ap_queue_info_create(&worker_queue_info, pruntime, max_recycled_pools);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, rv, ap_server_conf, APLOGNO(03101)
                     "ap_queue_info_create() failed");
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    /* Create the timeout mutex and main pollset before the listener
     * thread starts.
     */
    rv = apr_thread_mutex_create(&conn_queues.mutex, APR_THREAD_MUTEX_DEFAULT,
                                 pruntime);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf, APLOGNO(03102)
                     "creation of the timeout mutex failed.");
        clean_child_exit(APEXIT_CHILDFATAL);
    }
    rv = apr_thread_mutex_create(&notifiers_mutex, APR_THREAD_MUTEX_DEFAULT,
                                 pruntime);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf, APLOGNO()
                     "creation of the notifiers mutex failed.");
        clean_child_exit(APEXIT_CHILDFATAL);
    }
    notified_user_waits = apr_palloc(pruntime, sizeof(*notified_user_waits));
    APR_RING_INIT(notified_user_waits, ap_mpm_notifier_t, link);

    /* Create the main pollset with a good method. APR_POLLSET_WAKEABLE is
     * required (any method implements it with APR >= 1.4), we account for
     * the wakeup pipe explicitely with pollset_size+1 because some pollset
     * implementations don't do it implicitely in APR.
     * APR_POLLSET_THREADSAFE since several threads add/remove concurrently.
     */
    pollset_flags = APR_POLLSET_THREADSAFE | APR_POLLSET_NOCOPY |
                    APR_POLLSET_WAKEABLE | APR_POLLSET_NODEFAULT;
    rv = pollset_create_good(&event_pollset, pollset_size + 1, pruntime,
                             pollset_flags);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf, APLOGNO(03103)
                     "apr_pollset_create with Thread Safety failed.");
        clean_child_exit(APEXIT_CHILDFATAL);
    }
    connections_limit = clients_share;
    if (connections_limit) {
        ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ap_server_conf,
                     "up to %u connections in this child",
                     (unsigned int)connections_limit);
    }

    /* The connections' pollset, the workers' own with its doorbell
     * (worker_poll), or the main one if they can't poll (not built in). The
     * workers poll it while others add/remove (APR_POLLSET_THREADSAFE), and
     * APR_POLLSET_NOCOPY is mandatory for apr_pollset_poll_into().
     */
    conn_pollset = event_pollset;
#ifdef EVENT_WORKER_POLL
    {
        static listener_poll_type doorbell_pt = { PT_QUEUE, NULL };
        apr_pollset_t *ps = NULL;

        rv = pollset_create_good(&ps, pollset_size + 1, pruntime,
                                 APR_POLLSET_THREADSAFE |
                                 APR_POLLSET_NOCOPY |
                                 APR_POLLSET_NODEFAULT);
        if (rv == APR_SUCCESS) {
            rv = apr_file_pipe_create_ex(&doorbell_in, &doorbell_out,
                                         APR_FULL_NONBLOCK, pruntime);
        }
        if (rv == APR_SUCCESS) {
            doorbell_pfd.desc_type = APR_POLL_FILE;
            doorbell_pfd.reqevents = APR_POLLIN | APR_POLLONESHOT;
            doorbell_pfd.desc.f = doorbell_in;
            doorbell_pfd.client_data = &doorbell_pt;
            rv = apr_pollset_add(ps, &doorbell_pfd);
        }
        if (rv == APR_SUCCESS) {
            conn_pollset = ps;
            worker_poll = 1;
            worker_poll_slots_max = (worker_pollers > 0) ? worker_pollers
                                                         : num_cpus;
            if (worker_poll_slots_max > (apr_uint32_t)threads_per_child) {
                worker_poll_slots_max = threads_per_child;
            }
            ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ap_server_conf,
                         "workers polling at most %u at once%s",
                         worker_poll_slots_max, (worker_pollers > 0) ? "" : " (auto)");
#if defined(APR_POLLET) && defined(EVENT_WORKER_NOTIFY)
            /* Edge-triggered kept pfds where APR supports them */
            kept_pfds_et = (strcmp(apr_pollset_method_name(ps), "epoll") == 0
                            || strcmp(apr_pollset_method_name(ps), "kqueue") == 0);
#endif
        }
        else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf,
                         APLOGNO() "can't create the workers' pollset, the "
                         "listener polls the connections");
        }
    }
#endif
    oneshot_disarms_fd = (strcmp(apr_pollset_method_name(conn_pollset),
                                 "kqueue") != 0);

    /* Add listeners to the main pollset */
    listener_pollfd = apr_pcalloc(pruntime,
                                  num_listensocks * sizeof(apr_pollfd_t));
    for (i = 0, lr = my_bucket->listeners; lr; lr = lr->next, i++) {
        apr_pollfd_t *pfd;
        listener_poll_type *pt;

        ap_assert(i < num_listensocks);
        pfd = &listener_pollfd[i];

        pfd->reqevents = APR_POLLIN | APR_POLLHUP | APR_POLLERR;
#ifdef APR_POLLEXCL
        /* If APR_POLLEXCL is available, use it to prevent the thundering
         * herd issue. The listening sockets are potentially polled by all
         * the children at the same time, when new connections arrive this
         * avoids all of them to be woken up while most would get EAGAIN
         * on accept().
         */
        pfd->reqevents |= APR_POLLEXCL;
#endif
        pfd->desc_type = APR_POLL_SOCKET;
        pfd->desc.s = lr->sd;

        pt = apr_pcalloc(pruntime, sizeof(*pt));
        pfd->client_data = pt;
        pt->type = PT_ACCEPT;
        pt->baton = lr;

        apr_socket_opt_set(pfd->desc.s, APR_SO_NONBLOCK, 1);
        rv = apr_pollset_add(event_pollset, pfd);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, ap_server_conf, APLOGNO(10473)
                         "apr_pollset_add for listener failed.");
            clean_child_exit(APEXIT_CHILDFATAL);
        }

        lr->accept_func = ap_unixd_accept;
    }

    /* The fair share of the connections in auto mode (see fair_share_update()) */
    fair_share_on = auto_settings;
    fair_share_slack = FAIR_SHARE_SLACK(threads_per_child);
    if (fair_share_on) {
        ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ap_server_conf,
                     "fair share of the connections: on, slack %u",
                     fair_share_slack);
    }

    /* Aligned on a cache line (APR allocates on 8 bytes), so that a slot's
     * data never straddles into the next slot's line (one more slot for it).
     */
    {
        char *slots = apr_pcalloc(pruntime, ((apr_size_t)threads_max + 1) *
                                            sizeof(struct worker_slot));
        worker_slots = (struct worker_slot *)APR_ALIGN((apr_uintptr_t)slots,
                                                       CACHE_LINE_SIZE);
    }
    apr_thread_mutex_create(&limbo_mutex, APR_THREAD_MUTEX_DEFAULT, pruntime);
}

/* XXX under some circumstances not understood, children can get stuck
 *     in start_threads forever trying to take over slots which will
 *     never be cleaned up; for now there is an APLOG_DEBUG message issued
 *     every so often when this condition occurs
 */
static void *APR_THREAD_FUNC start_threads(apr_thread_t * thd, void *dummy)
{
    thread_starter *ts = dummy;
    apr_thread_t **threads = ts->threads;
    apr_threadattr_t *thread_attr = ts->threadattr;
    int my_child_num = ts->child_num_arg;
    proc_info *my_info;
    apr_status_t rv;
    int threads_created = 0;
    int listener_started = 0;
    int prev_threads_created;
    int loops, i;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(02471)
                 "start_threads: Using %s",
                 apr_pollset_method_name(event_pollset));

    loops = prev_threads_created = 0;
    while (1) {
        /* threads_per_child does not include the listener thread */
        for (i = 0; i < threads_per_child; i++) {
            int status =
                ap_scoreboard_image->servers[my_child_num][i].status;

            if (status != SERVER_DEAD) {
                continue;
            }

            my_info = (proc_info *) ap_malloc(sizeof(proc_info));
            my_info->pslot = my_child_num;
            my_info->tslot = i;

            /* We are creating threads right now */
            ap_update_child_status_from_indexes(my_child_num, i,
                                                SERVER_STARTING, NULL);
            /* We let each thread update its own scoreboard entry.  This is
             * done because it lets us deal with tid better.
             */
            workers_live_inc();
            rv = ap_thread_create(&threads[i], thread_attr,
                                  worker_thread, my_info, pruntime);
            if (rv != APR_SUCCESS) {
                workers_live_dec();
                threads[i] = NULL;
                ap_update_child_status_from_indexes(my_child_num, i, SERVER_DEAD, NULL);
                ap_log_error(APLOG_MARK, APLOG_ALERT, rv, ap_server_conf,
                             APLOGNO(03104)
                             "ap_thread_create: unable to create worker thread");
                /* Let the parent decide how bad this really is by returning
                 * APEXIT_CHILDSICK. If threads were created already let them
                 * stop cleanly first to avoid deadlocks in clean_child_exit(),
                 * just stop creating new ones here (but set resource_shortage
                 * to return APEXIT_CHILDSICK still when the child exists).
                 */
                if (threads_created) {
                    resource_shortage = 1;
                    signal_threads(ST_GRACEFUL);
                    if (!listener_started) {
                        workers_may_exit = 1;
                        ap_queue_term(worker_queue);
                        /* wake up main POD thread too */
                        kill(ap_my_pid, SIGTERM);
                    }
                    apr_thread_exit(thd, APR_SUCCESS);
                    return NULL;
                }
                clean_child_exit(APEXIT_CHILDSICK);
            }
            threads_created++;
        }

        /* Start the listener only when there are workers available */
        if (!listener_started && threads_created) {
            create_listener_thread(ts);
            listener_started = 1;
        }


        if (apr_atomic_read32(&start_thread_may_exit)
            || threads_created == threads_per_child) {
            break;
        }
        /* wait for previous generation to clean up an entry */
        apr_sleep(apr_time_from_sec(1));
        ++loops;
        if (loops % 120 == 0) { /* every couple of minutes */
            if (prev_threads_created == threads_created) {
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                             APLOGNO(03271)
                             "child %" APR_PID_T_FMT " isn't taking over "
                             "slots very quickly (%d of %d)",
                             ap_my_pid, threads_created,
                             threads_per_child);
            }
            prev_threads_created = threads_created;
        }
    }

    /* What state should this child_main process be listed as in the
     * scoreboard...?
     *  ap_update_child_status_from_indexes(my_child_num, i, SERVER_STARTING,
     *                                      (request_rec *) NULL);
     *
     *  This state should be listed separately in the scoreboard, in some kind
     *  of process_status, not mixed in with the worker threads' status.
     *  "life_status" is almost right, but it's in the worker's structure, and
     *  the name could be clearer.   gla
     */
    apr_thread_exit(thd, APR_SUCCESS);
    return NULL;
}

static void join_workers(apr_thread_t * listener, apr_thread_t ** threads)
{
    int i, joined_all = 1;
    apr_status_t rv, thread_rv;

    if (listener) {
        int iter;

        /* deal with a rare timing window which affects waking up the
         * listener thread...  if the signal sent to the listener thread
         * is delivered between the time it verifies that the
         * listener_may_exit flag is clear and the time it enters a
         * blocking syscall, the signal didn't do any good...  work around
         * that by sleeping briefly and sending it again
         */

        iter = 0;
        while (!apr_atomic_read32(&dying)) {
            apr_sleep(apr_time_from_msec(500));
            if (apr_atomic_read32(&dying) || ++iter > 10) {
                break;
            }
            /* listener has not stopped accepting yet */
            ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ap_server_conf,
                         "listener has not stopped accepting yet (%d iter)", iter);
            shutdown_listener();
        }
        if (iter > 10) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf, APLOGNO(00475)
                         "the listener thread didn't stop accepting");
            joined_all = 0;
        }
        else {
            rv = apr_thread_join(&thread_rv, listener);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf, APLOGNO(00476)
                             "apr_thread_join: unable to join listener thread");
                joined_all = 0;
            }
        }
    }

    /* The extra workers too (elastic_threads), the listener which starts
     * them is gone
     */
    for (i = 0; i < threads_max; i++) {
        ap_log_error(APLOG_MARK, APLOG_TRACE5, 0, ap_server_conf,
                     "apr_thread_join: joining thread %pp (%i/%i)",
                     threads[i], i, threads_max);
        if (threads[i]) {       /* if we ever created this thread */
            rv = apr_thread_join(&thread_rv, threads[i]);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf, APLOGNO(00477)
                             "apr_thread_join: unable to join worker "
                             "thread %d", i);
                joined_all = 0;
            }
        }
    }

    /* No worker holds a drain epoch anymore: recycle the pools still in the
     * limbo (worker_poll), their connections counted out at their close
     * already, before the child exits
     */
    if (joined_all && worker_slots) {
        for (i = 0; i < threads_max; i++) {
            apr_atomic_set32(&worker_slots[i].drain_epoch, 0);
        }
        flush_limbo();
    }
}

static void join_start_thread(apr_thread_t * start_thread_id)
{
    apr_status_t rv, thread_rv;

    /* tell it to give up in case it is still trying to take over slots
     * from a previous generation
     */
    apr_atomic_set32(&start_thread_may_exit, 1);

    rv = apr_thread_join(&thread_rv, start_thread_id);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf, APLOGNO(00478)
                     "apr_thread_join: unable to join the start " "thread");
    }
}

static void child_main(int child_num_arg, int child_bucket)
{
    apr_thread_t **threads;
    apr_status_t rv;
    thread_starter *ts;
    apr_threadattr_t *thread_attr;
    apr_thread_t *start_thread_id;
    int i;

    /* for benefit of any hooks that run as this child initializes */
    retained->mpm->mpm_state = AP_MPMQ_STARTING;

    ap_my_pid = getpid();
    ap_child_slot = child_num_arg;
    ap_fatal_signal_child_setup(ap_server_conf);

    /* Get a sub context for global allocations in this child, so that
     * we can have cleanups occur when the child exits.
     */
    apr_pool_create(&pchild, pconf);
    apr_pool_tag(pchild, "pchild");

#if AP_HAS_THREAD_LOCAL
    if (!one_process) {
        apr_thread_t *thd = NULL;
        if ((rv = ap_thread_main_create(&thd, pchild))) {
            ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf, APLOGNO(10377)
                         "Couldn't initialize child main thread");
            clean_child_exit(APEXIT_CHILDFATAL);
        }
    }
#endif

    /* close unused listeners and pods */
    my_bucket_num = child_bucket;
    for (i = 0; i < retained->mpm->num_buckets; i++) {
        if (i != child_bucket) {
            ap_close_listeners_ex(retained->buckets[i].listeners);
            ap_mpm_podx_close(retained->buckets[i].pod);
        }
    }

    /*stuff to do before we switch id's, so we have permissions. */
    ap_reopen_scoreboard(pchild, NULL, 0);

    /* done with init critical section */
    if (ap_run_drop_privileges(pchild, ap_server_conf)) {
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    /* Just use the standard apr_setup_signal_thread to block all signals
     * from being received.  The child processes no longer use signals for
     * any communication with the parent process. Let's also do this before
     * child_init() hooks are called and possibly create threads that
     * otherwise could "steal" (implicitly) MPM's signals.
     */
    rv = apr_setup_signal_thread();
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, rv, ap_server_conf, APLOGNO(00479)
                     "Couldn't initialize signal thread");
        clean_child_exit(APEXIT_CHILDFATAL);
    }

    /* For rand() users (e.g. skiplist). */
    srand((unsigned int)event_time_now());

    ap_run_child_init(pchild, ap_server_conf);

    if (ap_max_requests_per_child) {
        conns_this_child = ap_max_requests_per_child;
    }
    else {
        /* coding a value of zero means infinity */
        conns_this_child = APR_INT32_MAX;
    }

    /* Setup threads */

    /* Globals used by signal_threads() so to be initialized before */
    setup_threads_runtime();

    /* clear the storage; we may not create all our threads immediately,
     * and we want a 0 entry to indicate a thread which was not created
     */
    threads = ap_calloc(threads_max, sizeof(apr_thread_t *));
    ts = apr_palloc(pchild, sizeof(*ts));
    worker_threads = threads;
    worker_thread_pools = apr_pcalloc(pchild, threads_max * sizeof(apr_pool_t *));

    apr_threadattr_create(&thread_attr, pchild);
    /* 0 means PTHREAD_CREATE_JOINABLE */
    apr_threadattr_detach_set(thread_attr, 0);

    if (ap_thread_stacksize != 0) {
        rv = apr_threadattr_stacksize_set(thread_attr, ap_thread_stacksize);
        if (rv != APR_SUCCESS && rv != APR_ENOTIMPL) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, rv, ap_server_conf, APLOGNO(02436)
                         "WARNING: ThreadStackSize of %" APR_SIZE_T_FMT " is "
                         "inappropriate, using default",
                         ap_thread_stacksize);
        }
    }

    ts->threads = threads;
    ts->listener = NULL;
    ts->child_num_arg = child_num_arg;
    ts->threadattr = thread_attr;
    worker_thread_attr = thread_attr;

    rv = ap_thread_create(&start_thread_id, thread_attr, start_threads,
                          ts, pchild);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ALERT, rv, ap_server_conf, APLOGNO(00480)
                     "ap_thread_create: unable to create worker thread");
        /* let the parent decide how bad this really is */
        clean_child_exit(APEXIT_CHILDSICK);
    }

    retained->mpm->mpm_state = AP_MPMQ_RUNNING;

    /* If we are only running in one_process mode, we will want to
     * still handle signals. */
    if (one_process) {
        /* Block until we get a terminating signal. */
        apr_signal_thread(check_signal);
        /* make sure the start thread has finished; signal_threads()
         * and join_workers() depend on that
         */
        /* XXX join_start_thread() won't be awakened if one of our
         *     threads encounters a critical error and attempts to
         *     shutdown this child
         */
        join_start_thread(start_thread_id);

        /* helps us terminate a little more quickly than the dispatch of the
         * signal thread; beats the Pipe of Death and the browsers
         */
        signal_threads(ST_UNGRACEFUL);

        /* A terminating signal was received. Now join each of the
         * workers to clean them up.
         *   If the worker already exited, then the join frees
         *   their resources and returns.
         *   If the worker hasn't exited, then this blocks until
         *   they have (then cleans up).
         */
        join_workers(ts->listener, threads);
    }
    else {                      /* !one_process */
        /* remove SIGTERM from the set of blocked signals...  if one of
         * the other threads in the process needs to take us down
         * (e.g., for MaxConnectionsPerChild) it will send us SIGTERM
         */
        apr_signal(SIGTERM, dummy_signal_handler);
        unblock_signal(SIGTERM);
        /* Watch for any messages from the parent over the POD */
        while (1) {
            rv = ap_mpm_podx_check(my_bucket->pod);
            if (rv == AP_MPM_PODX_NORESTART) {
                /* see if termination was triggered while we slept */
                switch (terminate_mode) {
                case ST_GRACEFUL:
                    rv = AP_MPM_PODX_GRACEFUL;
                    break;
                case ST_UNGRACEFUL:
                    rv = AP_MPM_PODX_RESTART;
                    break;
                }
            }
            if (rv == AP_MPM_PODX_GRACEFUL || rv == AP_MPM_PODX_RESTART) {
                /* make sure the start thread has finished;
                 * signal_threads() and join_workers depend on that
                 */
                join_start_thread(start_thread_id);
                signal_threads(rv ==
                               AP_MPM_PODX_GRACEFUL ? ST_GRACEFUL : ST_UNGRACEFUL);
                break;
            }
        }

        /* A terminating signal was received. Now join each of the
         * workers to clean them up.
         *   If the worker already exited, then the join frees
         *   their resources and returns.
         *   If the worker hasn't exited, then this blocks until
         *   they have (then cleans up).
         */
        ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ap_server_conf,
                     "%s termination received, joining workers",
                     rv == AP_MPM_PODX_GRACEFUL ? "graceful" : "ungraceful");
        join_workers(ts->listener, threads);
        ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ap_server_conf,
                     "%s termination, workers joined, exiting",
                     rv == AP_MPM_PODX_GRACEFUL ? "graceful" : "ungraceful");
    }

    if (terminate_mode == ST_GRACEFUL) {
        ap_mpm_wait_for_extra_connections();
    }

    free(threads);

    clean_child_exit(resource_shortage ? APEXIT_CHILDSICK : 0);
}

static int make_child(server_rec *s, int slot)
{
    int pid, bucket = slot % retained->mpm->num_buckets;

    if (slot + 1 > retained->max_daemon_used) {
        retained->max_daemon_used = slot + 1;
    }
    if (retained->slot_started) {
        retained->slot_started[slot] = retained->last_started = apr_time_now();
    }

    if (ap_scoreboard_image->parent[slot].pid != 0) {
        /* XXX replace with assert or remove ? */
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, APLOGNO(03455)
                 "BUG: Scoreboard slot %d should be empty but is "
                 "in use by pid %" APR_PID_T_FMT,
                 slot, ap_scoreboard_image->parent[slot].pid);
        return -1;
    }

    if (one_process) {
        my_bucket = &retained->buckets[0];

        event_note_child_started(slot, getpid());
        child_main(slot, 0);
        /* NOTREACHED */
        ap_assert(0);
        return -1;
    }

    if ((pid = fork()) == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, errno, s, APLOGNO(00481)
                     "fork: Unable to fork new process");

        /* fork didn't succeed.  There's no need to touch the scoreboard;
         * if we were trying to replace a failed child process, then
         * server_main_loop() marked its workers SERVER_DEAD, and if
         * we were trying to replace a child process that exited normally,
         * its worker_thread()s left SERVER_DEAD or SERVER_GRACEFUL behind.
         */

        /* In case system resources are maxxed out, we don't want
           Apache running away with the CPU trying to fork over and
           over and over again. */
        apr_sleep(apr_time_from_sec(10));

        return -1;
    }

    if (!pid) {
#if AP_HAS_THREAD_LOCAL
        ap_thread_current_after_fork();
#endif

        my_bucket = &retained->buckets[bucket];

#ifdef HAVE_BINDPROCESSOR
        /* By default, AIX binds to a single processor.  This bit unbinds
         * children which will then bind to another CPU.
         */
        int status = bindprocessor(BINDPROCESS, (int) getpid(),
                                   PROCESSOR_CLASS_ANY);
        if (status != OK)
            ap_log_error(APLOG_MARK, APLOG_DEBUG, errno,
                         ap_server_conf, APLOGNO(00482)
                         "processor unbind failed");
#endif
        RAISE_SIGSTOP(MAKE_CHILD);

        apr_signal(SIGTERM, just_die);
        child_main(slot, bucket);
        /* NOTREACHED */
        ap_assert(0);
        return -1;
    }

    event_note_child_started(slot, pid);
    return 0;
}

/* start up a bunch of children */
static void startup_children(int number_to_start)
{
    int i;

    for (i = 0; number_to_start && i < server_limit; ++i) {
        if (ap_scoreboard_image->parent[i].pid != 0) {
            continue;
        }
        if (make_child(ap_server_conf, i) < 0) {
            break;
        }
        --number_to_start;
    }
}

static void perform_idle_server_maintenance(void)
{
    volatile process_score *ps;
    const int num_buckets = retained->mpm->num_buckets;
    int last_non_dead = -1;
    int free_length = 0, free_bucket = 0;
    int max_daemon_used = 0;
    int idle_thread_count = 0;
    int active_thread_count = 0;
    int backlog_count = 0;
    int i, j;

    for (i = 0; i < server_limit; ++i) {
        if (i >= retained->max_daemon_used &&
            free_length == retained->idle_spawn_rate) {
            /* short cut if all active processes have been examined and
             * enough empty scoreboard slots have been found
             */
            break;
        }

        ps = &ap_scoreboard_image->parent[i];
        if (ps->pid != 0) {
            int child_threads_active = 0;
            if (ps->quiescing == 1) {
                ps->quiescing = 2;
                retained->active_daemons--;
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                             "Child %d quiescing: pid %d, gen %d, "
                             "active %d/%d, total %d/%d/%d",
                             i, (int)ps->pid, (int)ps->generation,
                             retained->active_daemons, active_daemons_limit,
                             retained->total_daemons, retained->max_daemon_used,
                             server_limit);
            }
            for (j = 0; j < threads_per_child; j++) {
                int status = ap_scoreboard_image->servers[i][j].status;

                /* We consider a starting server as idle because we started it
                 * at least a cycle ago, and if it still hasn't finished starting
                 * then we're just going to swamp things worse by forking more.
                 * So we hopefully won't need to fork more if we count it.
                 * This depends on the ordering of SERVER_READY and SERVER_STARTING.
                 */
                if (status <= SERVER_READY && !ps->quiescing && !ps->not_accepting
                    && ps->generation == retained->mpm->my_generation) {
                    ++idle_thread_count;
                }
                if (status >= SERVER_READY && status < SERVER_GRACEFUL) {
                    ++child_threads_active;
                }
            }
            active_thread_count += child_threads_active;
            backlog_count += apr_atomic_read32(&ps->backlog);
            if (child_threads_active == threads_per_child) {
                had_healthy_child = 1;
            }
            last_non_dead = i;
        }
        else if (free_length < retained->idle_spawn_rate
                 && (i % num_buckets) == free_bucket) {
            retained->free_slots[free_length++] = i;
            if (++free_bucket == num_buckets) {
                free_bucket = 0;
            }
        }
    }
    if (max_daemon_used < last_non_dead + 1) {
        max_daemon_used = last_non_dead + 1;
    }

    if (retained->sick_child_detected) {
        if (had_healthy_child) {
            /* Assume this is a transient error, even though it may not be.  Leave
             * the server up in case it is able to serve some requests or the
             * problem will be resolved.
             */
            retained->sick_child_detected = 0;
        }
        else {
            /* looks like a basket case, as no child ever fully initialized; give up.
             */
            retained->mpm->shutdown_pending = 1;
            child_fatal = 1;
            ap_log_error(APLOG_MARK, APLOG_ALERT, 0,
                         ap_server_conf, APLOGNO(02324)
                         "A resource shortage or other unrecoverable failure "
                         "was encountered before any child process initialized "
                         "successfully... httpd is exiting!");
            /* the child already logged the failure details */
            return;
        }
    }

    AP_DEBUG_ASSERT(retained->active_daemons <= retained->total_daemons
                    && retained->total_daemons <= retained->max_daemon_used
                    && retained->max_daemon_used <= server_limit);

    if (idle_thread_count > max_spare_threads) {
        /*
         * Child processes that we ask to shut down won't die immediately
         * but may stay around for a long time when they finish their
         * requests. If the server load changes many times, many such
         * gracefully finishing processes may accumulate, filling up the
         * scoreboard. To avoid running out of scoreboard entries, we
         * don't shut down more processes if there are stopping ones
         * already (i.e. active_daemons != total_daemons) and not enough
         * slack space in the scoreboard for a graceful restart.
         *
         * XXX It would be nice if we could
         * XXX - kill processes without keepalive connections first
         * XXX - tell children to stop accepting new connections, and
         * XXX   depending on server load, later be able to resurrect them
         *       or kill them
         */
        int do_kill = (retained->active_daemons == retained->total_daemons
                       || (server_limit - retained->total_daemons >
                           active_daemons_limit));
        ap_log_error(APLOG_MARK, APLOG_TRACE5, 0, ap_server_conf,
                     "%shutting down one child: "
                     "active %d/%d, total %d/%d/%d, "
                     "idle threads %d, max workers %d",
                     (do_kill) ? "S" : "Not s",
                     retained->active_daemons, active_daemons_limit,
                     retained->total_daemons, retained->max_daemon_used,
                     server_limit, idle_thread_count, max_workers);
        if (do_kill) {
            for (i = 0; i < num_buckets; ++i) {
                ap_mpm_podx_signal(retained->buckets[i].pod,
                                   AP_MPM_PODX_GRACEFUL);
            }
        }
        else {
            /* Wait for dying daemon(s) to exit */
        }
        retained->idle_spawn_rate = num_buckets;
    }
    else if (idle_thread_count < min_spare_threads) {
        if (active_thread_count >= max_workers) {
            if (0 == idle_thread_count) {
                if (!retained->maxclients_reported) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, APLOGNO(00484)
                                 "server reached MaxRequestWorkers setting, "
                                 "consider raising the MaxRequestWorkers "
                                 "setting");
                    retained->maxclients_reported = 1;
                }
             }
             else {
                if (!retained->near_maxclients_reported) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, APLOGNO(10159)
                            "server is within MinSpareThreads of "
                            "MaxRequestWorkers, consider raising the "
                            "MaxRequestWorkers setting");
                    retained->near_maxclients_reported = 1;
                }
            }
            retained->idle_spawn_rate = num_buckets;
        }
        else if (free_length == 0) { /* scoreboard is full, can't fork */
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, APLOGNO(03490)
                         "scoreboard is full, not at MaxRequestWorkers."
                         "Increase ServerLimit.");
            retained->idle_spawn_rate = num_buckets;
        }
        else {
            if (free_length + retained->active_daemons > active_daemons_limit) {
                if (retained->active_daemons < active_daemons_limit) {
                    free_length = active_daemons_limit - retained->active_daemons;
                }
                else {
                    ap_log_error(APLOG_MARK, APLOG_TRACE1, 0, ap_server_conf,
                                 "server is at active daemons limit, spawning "
                                 "of %d children cancelled: active %d/%d, "
                                 "total %d/%d/%d, rate %d", free_length,
                                 retained->active_daemons, active_daemons_limit,
                                 retained->total_daemons, retained->max_daemon_used,
                                 server_limit, retained->idle_spawn_rate);
                    /* reset the spawning rate and prevent its growth below */
                    retained->idle_spawn_rate = num_buckets;
                    free_length = 0;
                }
            }
            if (retained->idle_spawn_rate >= retained->max_spawn_rate / 4) {
                ap_log_error(APLOG_MARK, APLOG_INFO, 0, ap_server_conf, APLOGNO(00486)
                             "server seems busy, (you may need "
                             "to increase StartServers, ThreadsPerChild "
                             "or Min/MaxSpareThreads), "
                             "spawning %d children, there are around %d idle "
                             "threads, %d active children, and %d children "
                             "that are shutting down", free_length,
                             idle_thread_count, retained->active_daemons,
                             retained->total_daemons);
            }
            free_length = (free_length / num_buckets) * num_buckets;
            for (i = 0; i < free_length; ++i) {
                int slot = retained->free_slots[i];
                if (make_child(ap_server_conf, slot) < 0) {
                    continue;
                }
                if (max_daemon_used < slot + 1) {
                    max_daemon_used = slot + 1;
                }
            }
            /* the next time around we want to spawn twice as many if this
             * wasn't good enough, but not if we've just done a graceful
             */
            if (retained->hold_off_on_exponential_spawning) {
                --retained->hold_off_on_exponential_spawning;
            }
            else if (free_length && retained->idle_spawn_rate < retained->max_spawn_rate) {
                int new_rate = retained->idle_spawn_rate * 2;
                new_rate = ((new_rate + num_buckets - 1) / num_buckets) * num_buckets;
                if (new_rate > retained->max_spawn_rate) {
                    new_rate = retained->max_spawn_rate;
                }
                retained->idle_spawn_rate = new_rate;
            }
        }
    }
    else {
        retained->idle_spawn_rate = num_buckets;
    }

    retained->max_daemon_used = max_daemon_used;
    if (APLOGdebug(ap_server_conf)) {
        ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, ap_server_conf,
                     "score: idlers:%d backlog:%d, "
                     "threads active:%d/%d max:%d, "
                     "daemons active:%d/%d max:%d used:%d/%d/%d",
                     idle_thread_count, backlog_count,
                     active_thread_count, retained->active_daemons * threads_per_child,
                     max_workers, retained->active_daemons, retained->total_daemons,
                     active_daemons_limit, max_daemon_used, retained->max_daemon_used,
                     server_limit);
    }
}

/* MaxRequestWorkers auto: keep the target of children running (all of them,
 * active_daemons_limit), the same number per bucket, replacing those that
 * exited or stopped accepting for good (quiescing, e.g. MaxConnectionsPerChild
 * or a descriptors shortage) at once, in the free scoreboard slots of their
 * bucket. Never stop a child for its idle threads, they may hold many
 * connections, nor start more than the target because threads are blocked
 * (connections can't move to another child, its own workers grow instead).
 */
static void perform_children_target_maintenance(void)
{
    const int num_buckets = retained->mpm->num_buckets;
    const int per_bucket = active_daemons_limit / num_buckets;
    int *children = retained->bucket_children;
    int max_daemon_used = 0, active = 0, missing = 0;
    int i, j, b;

    for (b = 0; b < num_buckets; b++) {
        children[b] = 0;
    }
    for (i = 0; i < server_limit; ++i) {
        volatile process_score *ps = &ap_scoreboard_image->parent[i];

        if (ps->pid == 0) {
            continue;
        }
        if (ps->quiescing == 1) {
            ps->quiescing = 2;
            retained->active_daemons--;
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ap_server_conf,
                         "Child %d quiescing: pid %d, gen %d, "
                         "active %d/%d, total %d/%d/%d",
                         i, (int)ps->pid, (int)ps->generation,
                         retained->active_daemons, active_daemons_limit,
                         retained->total_daemons, retained->max_daemon_used,
                         server_limit);
        }
        if (!ps->quiescing
            && ps->generation == retained->mpm->my_generation) {
            int threads_active = 0;
            for (j = 0; j < threads_per_child; j++) {
                int status = ap_scoreboard_image->servers[i][j].status;
                if (status >= SERVER_READY && status < SERVER_GRACEFUL) {
                    ++threads_active;
                }
            }
            if (threads_active == threads_per_child) {
                had_healthy_child = 1;
            }
            children[i % num_buckets]++;
            active++;
        }
        max_daemon_used = i + 1;
    }

    if (retained->sick_child_detected) {
        if (had_healthy_child) {
            /* Assume this is a transient error (see
             * perform_idle_server_maintenance())
             */
            retained->sick_child_detected = 0;
        }
        else {
            retained->mpm->shutdown_pending = 1;
            child_fatal = 1;
            ap_log_error(APLOG_MARK, APLOG_ALERT, 0,
                         ap_server_conf, APLOGNO()
                         "A resource shortage or other unrecoverable failure "
                         "was encountered before any child process initialized "
                         "successfully... httpd is exiting!");
            return;
        }
    }

    for (b = 0; b < num_buckets; b++) {
        for (i = b; children[b] < per_bucket && i < server_limit;
             i += num_buckets) {
            if (ap_scoreboard_image->parent[i].pid != 0) {
                continue;
            }
            if (make_child(ap_server_conf, i) < 0) {
                break;
            }
            children[b]++;
            active++;
            if (max_daemon_used < i + 1) {
                max_daemon_used = i + 1;
            }
        }
        if (children[b] < per_bucket) {
            missing += per_bucket - children[b];
        }
    }
    if (missing) {
        if (!retained->target_full_reported) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, ap_server_conf, APLOGNO()
                         "scoreboard is full, %d of the %d children are "
                         "missing (MaxRequestWorkers auto): increase "
                         "ServerLimit", missing, active_daemons_limit);
            retained->target_full_reported = 1;
        }
    }
    else {
        retained->target_full_reported = 0;
    }

    if (retained->max_daemon_used < max_daemon_used) {
        retained->max_daemon_used = max_daemon_used;
    }
    if (APLOGdebug(ap_server_conf)) {
        ap_log_error(APLOG_MARK, APLOG_TRACE2, 0, ap_server_conf,
                     "score: children target %d, active:%d/%d total:%d "
                     "used:%d/%d/%d",
                     active_daemons_limit, active, retained->active_daemons,
                     retained->total_daemons, max_daemon_used,
                     retained->max_daemon_used, server_limit);
    }
}

/* MaxRequestWorkers auto: whether a child that exited from slot can be
 * replaced at once, else on the next timeout (like the idle maintenance):
 * not when the previous child of that slot or the last one started less than
 * REPLACE_AT_ONCE_INTERVAL ago (children exiting right after their start,
 * e.g. a module failing at child_init, would be forked again and again), nor
 * after a sick child (perform_children_target_maintenance() decides then).
 * The interval is above ap_wait_or_timeout()'s 1s, after which such a child
 * is reaped.
 */
#define REPLACE_AT_ONCE_INTERVAL apr_time_from_sec(2)
static int replace_at_once(int slot)
{
    apr_time_t now = apr_time_now();

    return (!retained->sick_child_detected
            && now - retained->slot_started[slot] >= REPLACE_AT_ONCE_INTERVAL
            && now - retained->last_started >= REPLACE_AT_ONCE_INTERVAL);
}

static void server_main_loop(int remaining_children_to_start)
{
    int successive_kills = 0;
    int child_slot;
    apr_exit_why_e exitwhy;
    int status, processed_status;
    apr_proc_t pid;

    while (!retained->mpm->restart_pending && !retained->mpm->shutdown_pending) {
        ap_wait_or_timeout(&exitwhy, &status, &pid, pconf, ap_server_conf);

        if (pid.pid != -1) {
            processed_status = ap_process_child_status(&pid, exitwhy, status);
            child_slot = ap_find_child_by_pid(&pid);
            if (processed_status == APEXIT_CHILDFATAL) {
                /* fix race condition found in PR 39311
                 * A child created at the same time as a graceful happens
                 * can find the lock missing and create a fatal error.
                 * It is not fatal for the last generation to be in this state.
                 */
                if (child_slot < 0
                    || ap_get_scoreboard_process(child_slot)->generation
                       == retained->mpm->my_generation) {
                    retained->mpm->shutdown_pending = 1;
                    child_fatal = 1;
                    /*
                     * total_daemons counting will be off now, but as we
                     * are shutting down, that is not an issue anymore.
                     */
                    return;
                }
                else {
                    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, ap_server_conf, APLOGNO(00487)
                                 "Ignoring fatal error in child of previous "
                                 "generation (pid %ld).",
                                 (long)pid.pid);
                    retained->sick_child_detected = 1;
                }
            }
            else if (processed_status == APEXIT_CHILDSICK) {
                /* tell perform_idle_server_maintenance to check into this
                 * on the next timer pop
                 */
                retained->sick_child_detected = 1;
            }
            /* non-fatal death... note that it's gone in the scoreboard. */
            if (child_slot >= 0) {
                event_note_child_stopped(child_slot, 0, 0);

                if (processed_status == APEXIT_CHILDSICK) {
                    /* resource shortage, minimize the fork rate */
                    retained->idle_spawn_rate = retained->mpm->num_buckets;
                }
                else if (remaining_children_to_start) {
                    /* we're still doing a 1-for-1 replacement of dead
                     * children with new children
                     */
                    make_child(ap_server_conf, child_slot);
                    --remaining_children_to_start;
                }
            }
#if APR_HAS_OTHER_CHILD
            else if (apr_proc_other_child_alert(&pid, APR_OC_REASON_DEATH,
                                                status) == 0) {
                /* handled */
            }
#endif
            else if (retained->mpm->was_graceful) {
                /* Great, we've probably just lost a slot in the
                 * scoreboard.  Somehow we don't know about this child.
                 */
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0,
                             ap_server_conf, APLOGNO(00488)
                             "long lost child came home! (pid %ld)",
                             (long) pid.pid);
            }
            /* Don't perform idle maintenance when a child dies,
             * only do it when there's a timeout.  Remember only a
             * finite number of children can die, and it's pretty
             * pathological for a lot to die suddenly.  If a child is
             * killed by a signal (faulting) we want to restart it ASAP
             * though, up to 3 successive faults or we stop this until
             * a timeout happens again (to avoid the flood of fork()ed
             * processes that keep being killed early).
             */
            if (child_slot < 0 || !APR_PROC_CHECK_SIGNALED(exitwhy)) {
                /* MaxRequestWorkers auto: replace it at once, unless sick
                 * or too soon (on the next timeout then)
                 */
                if (auto_settings && child_slot >= 0
                    && processed_status != APEXIT_CHILDSICK
                    && !remaining_children_to_start
                    && replace_at_once(child_slot)) {
                    perform_children_target_maintenance();
                }
                continue;
            }
            if (++successive_kills >= 3) {
                if (successive_kills % 10 == 3) {
                    ap_log_error(APLOG_MARK, APLOG_WARNING, 0,
                                 ap_server_conf, APLOGNO(10392)
                                 "children are killed successively!");
                }
                continue;
            }
            if (auto_settings && !remaining_children_to_start) {
                if (replace_at_once(child_slot)) {
                    perform_children_target_maintenance();
                }
                continue;
            }
            ++remaining_children_to_start;
        }
        else {
            successive_kills = 0;
        }

        if (remaining_children_to_start) {
            /* we hit a 1 second timeout in which none of the previous
             * generation of children needed to be reaped... so assume
             * they're all done, and pick up the slack if any is left.
             */
            startup_children(remaining_children_to_start);
            remaining_children_to_start = 0;
            /* In any event we really shouldn't do the code below because
             * few of the servers we just started are in the IDLE state
             * yet, so we'd mistakenly create an extra server.
             */
            continue;
        }

        if (auto_settings) {
            perform_children_target_maintenance();
        }
        else {
            perform_idle_server_maintenance();
        }
    }
}

static int event_run(apr_pool_t * _pconf, apr_pool_t * plog, server_rec * s)
{
    int remaining_children_to_start;
    int num_buckets, i;
    apr_status_t rv;

    ap_log_pid(pconf, ap_pid_fname);

    /* Preserve the scoreboard on graceful restart, reset when ungraceful */
    if (!retained->mpm->was_graceful
        && ap_run_pre_mpm(s->process->pool, SB_SHARED)) {
        retained->mpm->mpm_state = AP_MPMQ_STOPPING;
        return !OK;
    }

    /* Now on for the new generation. */
    ap_scoreboard_image->global->running_generation = retained->mpm->my_generation;
    ap_unixd_mpm_set_signals(pconf, one_process);

    /* Set the buckets listeners from the listen_buckets initialized
     * in event_open_logs().
     */
    num_buckets = retained->num_listen_buckets;
    retained->buckets = apr_pcalloc(retained->gen_pool,
                                    num_buckets * sizeof(event_child_bucket));
    for (i = 0; i < num_buckets; i++) {
        if (!one_process /* no POD in one_process mode */
                && (rv = ap_mpm_podx_open(retained->gen_pool,
                                          &retained->buckets[i].pod))) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv,
                         ap_server_conf, APLOGNO(03274)
                         "could not open pipe-of-death");
            return !OK;
        }
        retained->buckets[i].listeners = retained->listen_buckets[i];
    }
    /* Reset for the next generation/restart */
    retained->listen_buckets = NULL;
    retained->num_listen_buckets = 0;
    retained->bucket_children = apr_pcalloc(retained->gen_pool,
                                            num_buckets * sizeof(int));
    /* server_limit (the scoreboard's) doesn't change across restarts */
    if (!retained->slot_started) {
        retained->slot_started = apr_pcalloc(ap_pglobal, server_limit *
                                                         sizeof(apr_time_t));
    }

    /* If num_buckets changed, adjust max_spawn_rate and the free_slots buffer */
    if (retained->mpm->num_buckets != num_buckets) {
        if (retained->mpm->max_buckets < num_buckets) {
            int new_max, new_slots;
            new_max = retained->mpm->max_buckets * 2;
            if (new_max < num_buckets) {
                new_max = num_buckets;
            }
            else {
                new_max = ((new_max + num_buckets - 1) / num_buckets) * num_buckets;
            }
            new_slots = ((MAX_SPAWN_RATE + new_max - 1) / new_max) * new_max;
            retained->free_slots = apr_palloc(ap_pglobal, new_slots * sizeof(int));
            retained->mpm->max_buckets = new_max;
        }
        /* We always spawn/kill children in a multiple of num_buckets (as needed),
         * so align (round up) max_spawn_rate and idle_spawn_rate to num_buckets.
         */
        retained->max_spawn_rate = (((MAX_SPAWN_RATE + num_buckets - 1)
                                     / num_buckets) * num_buckets);
        retained->idle_spawn_rate = (((retained->idle_spawn_rate + num_buckets - 1)
                                      / num_buckets) * num_buckets);
        if (retained->idle_spawn_rate < num_buckets) {
            retained->idle_spawn_rate = num_buckets;
        }
        else if (retained->idle_spawn_rate > retained->max_spawn_rate) {
            retained->idle_spawn_rate = retained->max_spawn_rate;
        }
        retained->mpm->num_buckets = num_buckets;
    }

    ap_log_error(APLOG_MARK, APLOG_INFO, 0, ap_server_conf, APLOGNO(10464)
                 "MPM event settings%s: MaxRequestWorkers=%d AsyncAdmissionBacklogPerThread=%.1lf "
                 "AsyncAdmissionTarget=%" APR_TIME_T_FMT "ms AsyncAdmissionInterval=%"
                 APR_TIME_T_FMT "ms "
                 "ThreadsPerChild=%d ThreadLimit=%d MinSpareThreads=%d MaxSpareThreads=%d "
                 "ServerLimit=%d/%d StartServers=%d Buckets=%d CPUs=%d "
                 "MaxClientConnections=%d (%d/%u per child) ElasticThreads=%s "
                 "WorkerPoll=%s",
                 auto_settings ? " (auto)" : "", max_workers, admission_backlog,
                 apr_time_as_msec(admission_target), apr_time_as_msec(admission_interval),
                 threads_per_child, thread_limit, min_spare_threads, max_spare_threads,
                 active_daemons_limit, server_limit, ap_daemons_to_start,
                 num_buckets, num_cpus, max_client_conns, clients_per_child,
                 (unsigned int)clients_share, elastic_threads ? "on" : "off",
#ifdef EVENT_WORKER_POLL
                 "on"   /* unless the workers' pollset can't be created */
#else
                 "off"
#endif
                 );

    /* If we're doing a graceful_restart then we're going to see a lot
     * of children exiting immediately when we get into the main loop
     * below (because we just sent them AP_SIG_GRACEFUL).  This happens pretty
     * rapidly... and for each one that exits we may start a new one, until
     * there are at least min_spare_threads idle threads, counting across
     * all children.  But we may be permitted to start more children than
     * that, so we'll just keep track of how many we're
     * supposed to start up without the 1 second penalty between each fork.
     */
    remaining_children_to_start = ap_daemons_to_start;
    if (remaining_children_to_start > active_daemons_limit) {
        remaining_children_to_start = active_daemons_limit;
    }
    if (!retained->mpm->was_graceful) {
        startup_children(remaining_children_to_start);
        remaining_children_to_start = 0;
    }
    else if (auto_settings) {
        /* The whole target at once, in the slots the previous generation's
         * children don't hold (the scoreboard has room for both)
         */
        perform_children_target_maintenance();
        remaining_children_to_start = 0;
    }
    else {
        /* give the system some time to recover before kicking into
         * exponential mode */
        retained->hold_off_on_exponential_spawning = 10;
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO(00489)
                 "%s configured -- resuming normal operations",
                 ap_get_server_description());
    ap_log_error(APLOG_MARK, APLOG_INFO, 0, ap_server_conf, APLOGNO(00490)
                 "Server built: %s", ap_get_server_built());
    ap_log_command_line(plog, s);
    ap_log_mpm_common(s);

    retained->mpm->mpm_state = AP_MPMQ_RUNNING;

    server_main_loop(remaining_children_to_start);
    retained->mpm->mpm_state = AP_MPMQ_STOPPING;

    if (retained->mpm->shutdown_pending && retained->mpm->is_ungraceful) {
        /* Time to shut down:
         * Kill child processes, tell them to call child_exit, etc...
         */
        for (i = 0; i < num_buckets; i++) {
            ap_mpm_podx_killpg(retained->buckets[i].pod,
                               active_daemons_limit, AP_MPM_PODX_RESTART);
        }
        ap_reclaim_child_processes(1, /* Start with SIGTERM */
                                   event_note_child_stopped);

        if (!child_fatal) {
            /* cleanup pid file on normal shutdown */
            ap_remove_pid(pconf, ap_pid_fname);
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0,
                         ap_server_conf, APLOGNO(00491) "caught SIGTERM, shutting down");
        }

        return DONE;
    }

    if (retained->mpm->shutdown_pending) {
        /* Time to gracefully shut down:
         * Kill child processes, tell them to call child_exit, etc...
         */
        int active_children;
        int index;
        apr_time_t cutoff = 0;

        /* Close our listeners, and then ask our children to do same */
        ap_close_listeners();
        for (i = 0; i < num_buckets; i++) {
            ap_mpm_podx_killpg(retained->buckets[i].pod,
                               active_daemons_limit, AP_MPM_PODX_GRACEFUL);
        }
        ap_relieve_child_processes(event_note_child_stopped);

        if (!child_fatal) {
            /* cleanup pid file on normal shutdown */
            ap_remove_pid(pconf, ap_pid_fname);
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO(00492)
                         "caught " AP_SIG_GRACEFUL_STOP_STRING
                         ", shutting down gracefully");
        }

        if (ap_graceful_shutdown_timeout) {
            cutoff = event_time_now() +
                     apr_time_from_sec(ap_graceful_shutdown_timeout);
        }

        /* Don't really exit until each child has finished */
        retained->mpm->shutdown_pending = 0;
        do {
            /* Pause for a second */
            apr_sleep(apr_time_from_sec(1));

            /* Relieve any children which have now exited */
            ap_relieve_child_processes(event_note_child_stopped);

            active_children = 0;
            for (index = 0; index < retained->max_daemon_used; ++index) {
                if (ap_mpm_safe_kill(MPM_CHILD_PID(index), 0) == APR_SUCCESS) {
                    active_children = 1;
                    /* Having just one child is enough to stay around */
                    break;
                }
            }
        } while (!retained->mpm->shutdown_pending && active_children &&
                 (!ap_graceful_shutdown_timeout || event_time_now() < cutoff));

        /* We might be here because we received SIGTERM, either
         * way, try and make sure that all of our processes are
         * really dead.
         */
        for (i = 0; i < num_buckets; i++) {
            ap_mpm_podx_killpg(retained->buckets[i].pod,
                               active_daemons_limit, AP_MPM_PODX_RESTART);
        }
        ap_reclaim_child_processes(1, event_note_child_stopped);

        return DONE;
    }

    /* we've been told to restart */
    if (one_process) {
        /* not worth thinking about */
        return DONE;
    }

    if (!retained->mpm->is_ungraceful) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO(00493)
                     "%s received.  Doing graceful restart",
                     AP_SIG_GRACEFUL_STRING);
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, APLOGNO(00494)
                     "SIGHUP received.  Attempting to restart");
    }
    return OK;
}

static void setup_slave_conn(conn_rec *c, void *csd)
{
    event_conn_state_t *mcs;
    event_conn_state_t *cs;

    mcs = ap_get_module_config(c->master->conn_config, &mpm_event_module);
    if (!mcs) {
        /* Master connection is not managed by this MPM; nothing to inherit. */
        return;
    }

    cs = make_conn_state(c->pool, csd);
    cs->c = c;
    cs->sc = mcs->sc;
    cs->bucket_alloc = c->bucket_alloc;
    cs->pfd = mcs->pfd;
    cs->pub = mcs->pub;
    cs->pub.state = CONN_STATE_PROCESSING;
    cs->pub.sense = CONN_SENSE_DEFAULT;

    c->cs = &(cs->pub);
    ap_set_module_config(c->conn_config, &mpm_event_module, cs);
}

static int event_pre_connection(conn_rec *c, void *csd)
{
    if (c->master && (!c->cs || c->cs == c->master->cs)) {
        setup_slave_conn(c, csd);
    }
    return OK;
}

static int event_protocol_switch(conn_rec *c, request_rec *r, server_rec *s,
                                 const char *protocol)
{
    if (!r && s) {
        /* connection based switching of protocol, set the correct server
         * configuration, so that timeouts, keepalives and such are used
         * for the server that the connection was switched on.
         * Normally, we set this on post_read_request, but on a protocol
         * other than http/1.1, this might never happen.
         */
        event_conn_state_t *cs;

        cs = ap_get_module_config(c->conn_config, &mpm_event_module);
        if (cs) {
            cs->sc = ap_get_module_config(s->module_config, &mpm_event_module);
        }
    }
    return DECLINED;
}

/* The number of listeners buckets for active_daemons_limit children: the
 * largest divisor of the children count not above num_cpus (those this
 * process can run on) / ListenCoresBucketsRatio, so that every bucket has the
 * same number of children and MaxRequestWorkers is not changed.  A graceful
 * restart keeps the previous count (prev > 0) when it still fits and the
 * ratio is unchanged, the configuration deciding otherwise.  Zero lets
 * ap_duplicate_listeners() warn and use one bucket without SO_REUSEPORT.
 */
static int event_listen_buckets(server_rec *s, int prev)
{
    int ratio = ap_get_listen_buckets_ratio();
    int max, n;

    if (ratio != retained->listen_buckets_ratio) {
        retained->listen_buckets_ratio = ratio;
        prev = 0;
    }
    if (one_process || ratio <= 0) {
        return 1;
    }
    if (!ap_have_so_reuseport) {
        return 0;
    }
    max = num_cpus / ratio;
    if (max < 1) {
        max = 1;
    }
    if (prev > 0 && prev <= max && active_daemons_limit % prev == 0) {
        return prev;
    }
    for (n = max; n > 1 && active_daemons_limit % n; n--) {
        continue;
    }
    if (n < max) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO()
                     "Using %d listeners bucket(s) instead of %d (%d CPUs, "
                     "ListenCoresBucketsRatio %d): the largest divisor of "
                     "the %d children (MaxRequestWorkers / ThreadsPerChild)",
                     n, max, num_cpus, ratio, active_daemons_limit);
    }
    else {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO()
                     "Using %d listeners bucket(s) based on %d CPUs and "
                     "ListenCoresBucketsRatio %d", n, num_cpus, ratio);
    }
    return n;
}

/* MaxRequestWorkers auto: derive the settings not set explicitly from the
 * client connections to hold (max_client_conns, or what the descriptors limit
 * allows) and the CPUs: ThreadsPerChild (AUTO_THREADS_PER_CHILD), the
 * children needed to hold the clients with the connections a child can hold
 * (clients_per_child), at least enough for their threads to cover the CPUs,
 * MaxRequestWorkers (all their threads) and StartServers (all of them).
 * Called with the listeners set up (num_listensocks), before the buckets are
 * fit to the children.
 */
static void auto_settings_derive(server_rec *s, int startup)
{
    const int level_flags = (startup) ? APLOG_STARTUP : 0;
    server_rec *ls = (startup) ? NULL : s;
    int ratio = ap_get_listen_buckets_ratio();
    int tpc, children, min_children, cpu_buckets = 1;
    apr_int64_t fds = AUTO_FDS_MAX, hard = AUTO_FDS_MAX, reserve, per_child, n;
    int clients_set = (max_client_conns > 0);

    tpc = threads_per_child;
    if (tpc <= 0) {
        tpc = (num_cpus > 1) ? AUTO_THREADS_PER_CHILD : 1;
    }
    else if (tpc > MAX_THREAD_LIMIT) {
        ap_log_error(APLOG_MARK, APLOG_WARNING | level_flags, 0, ls, APLOGNO()
                     "ThreadsPerChild of %d exceeds the compile-time limit "
                     "of %d threads, decreasing to match", tpc,
                     MAX_THREAD_LIMIT);
        tpc = MAX_THREAD_LIMIT;
    }
    if (tpc > thread_limit && (auto_set_flags & AUTO_SET_THREAD_LIMIT)) {
        ap_log_error(APLOG_MARK, APLOG_WARNING | level_flags, 0, ls, APLOGNO()
                     "ThreadsPerChild of %d exceeds ThreadLimit of %d, "
                     "decreasing to match", tpc, thread_limit);
        tpc = thread_limit;
    }

    /* The buckets the CPUs would have (ListenCoresBucketsRatio) */
    if (!one_process && ratio > 0 && ap_have_so_reuseport) {
        cpu_buckets = num_cpus / ratio;
        if (cpu_buckets < 1) {
            cpu_buckets = 1;
        }
    }

#if APR_HAVE_STRUCT_RLIMIT && defined(RLIMIT_NOFILE)
    {
        struct rlimit rl;
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
            if (rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur < AUTO_FDS_MAX) {
                fds = (apr_int64_t)rl.rlim_cur;
            }
            if (rl.rlim_max != RLIM_INFINITY && rl.rlim_max < AUTO_FDS_MAX) {
                hard = (apr_int64_t)rl.rlim_max;
            }
        }
    }
#endif
    reserve = AUTO_FDS_RESERVE + (apr_int64_t)num_listensocks;
    per_child = (fds - reserve) / AUTO_FDS_PER_CLIENT;
    if (per_child < 1) {
        per_child = 1;
    }

    /* The fewest children: enough for their threads to cover the CPUs */
    min_children = (num_cpus + tpc - 1) / tpc;

    if (clients_set) {
        n = max_client_conns;
    }
    else {
        /* What the descriptors limit allows anyway: the fewest children (or
         * a child per bucket if more) at their capacity.
         */
        n = per_child * ((min_children > cpu_buckets) ? min_children
                                                      : cpu_buckets);
        if (n > INT_MAX / 2) {
            n = INT_MAX / 2;
        }
        if (hard >= fds * 2) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE | level_flags, 0, ls, APLOGNO()
                         "MaxRequestWorkers auto: %" APR_INT64_T_FMT " client "
                         "connections at most, from the soft descriptors limit "
                         "(%" APR_INT64_T_FMT "), the hard limit allows %s%"
                         APR_INT64_T_FMT ": raise the soft limit (e.g. "
                         "ulimit -n) to hold more", n, fds,
                         (hard == AUTO_FDS_MAX) ? "at least " : "", hard);
        }
    }

    children = (int)((n + per_child - 1) / per_child);
    if (children < min_children) {
        children = min_children;
    }
    /* A multiple of the buckets when more, so that event_listen_buckets()
     * can use all of them
     */
    if (children > cpu_buckets) {
        children = ((children + cpu_buckets - 1) / cpu_buckets) * cpu_buckets;
    }
    if (children > server_limit && (auto_set_flags & AUTO_SET_SERVER_LIMIT)) {
        ap_log_error(APLOG_MARK, APLOG_WARNING | level_flags, 0, ls, APLOGNO()
                     "MaxRequestWorkers auto: %" APR_INT64_T_FMT " client "
                     "connections would need %d children of up to %"
                     APR_INT64_T_FMT " connections, above ServerLimit %d: "
                     "up to %" APR_INT64_T_FMT " connections only",
                     n, children, per_child, server_limit,
                     per_child * server_limit);
        children = server_limit;
    }
    else if (children > MAX_SERVER_LIMIT) {
        ap_log_error(APLOG_MARK, APLOG_WARNING | level_flags, 0, ls, APLOGNO()
                     "MaxRequestWorkers auto: %" APR_INT64_T_FMT " client "
                     "connections would need %d children of up to %"
                     APR_INT64_T_FMT " connections, above the compile-time "
                     "limit of %d: up to %" APR_INT64_T_FMT " connections only",
                     n, children, per_child, MAX_SERVER_LIMIT,
                     per_child * MAX_SERVER_LIMIT);
        children = MAX_SERVER_LIMIT;
    }

    /* ThreadLimit: what a fully blocking load needs (a worker per client)
     * but AUTO_THREAD_LIMIT_MAX at most, the workers growing up to it while
     * blocked (elastic_threads); the base threads without getrusage(). The
     * scoreboard's on restart.
     */
    if (!(auto_set_flags & AUTO_SET_THREAD_LIMIT)) {
        if (retained->first_thread_limit) {
            thread_limit = retained->first_thread_limit;
        }
        else {
#ifdef EVENT_ELASTIC_THREADS
            apr_int64_t tl = (n + children - 1) / children;
            if (tl > AUTO_THREAD_LIMIT_MAX) {
                tl = AUTO_THREAD_LIMIT_MAX;
            }
            thread_limit = (tl > tpc) ? (int)tl : tpc;
#else
            thread_limit = tpc;
#endif
        }
    }

    threads_per_child = tpc;
    max_workers = children * tpc;
    if (ap_daemons_to_start <= 0 || ap_daemons_to_start > children) {
        ap_daemons_to_start = children;
    }
    max_client_conns = (int)n;
    clients_per_child = (int)per_child;
}

/* This really should be a post_config hook, but the error log is already
 * redirected by that point, so we need to do this in the open_logs phase.
 * We compute num_buckets here too, thus the definitive AP_MPMQ_* settings
 * which need it and which may be needed by the post_config hooks of other
 * modules.
 */
static int event_open_logs(apr_pool_t * p, apr_pool_t * plog,
                           apr_pool_t * ptemp, server_rec * s)
{
    int startup = 0;
    int level_flags = 0;
    int num_buckets = 0, i;
    int min_threads;
    apr_status_t rv;

    pconf = p;

    /* the reverse of pre_config, we want this only the first time around */
    if (retained->mpm->module_loads == 1) {
        startup = 1;
        level_flags |= APLOG_STARTUP;
    }

    /* This sets up new listeners or reuses existing ones, as well as cleaning
     * up unused ones from the previous generation.
     */
    num_listensocks = ap_setup_listeners(ap_server_conf);
    if (num_listensocks < 1) {
        ap_log_error(APLOG_MARK, APLOG_ALERT | level_flags, 0,
                     (startup ? NULL : s), APLOGNO(03272)
                     "no listening sockets available, shutting down");
        return !OK;
    }

    /* On first startup create gen_pool to satisfy the lifetime of the
     * parent's PODs (the listeners live in the process pool, reused across
     * generations); on restart stop the children from the previous
     * generation and clear gen_pool for the next one.
     */
    if (!retained->gen_pool) {
        apr_pool_create(&retained->gen_pool, ap_pglobal);
    }
    else {
        /* As many PODs as children in the previous generation (the module's
         * statics were reloaded, active_daemons_limit is the new generation's
         * here if derived already, not with MaxRequestWorkers auto)
         */
        int limit = (retained->gen_daemons_limit > active_daemons_limit)
                    ? retained->gen_daemons_limit
                    : active_daemons_limit;
        num_buckets = retained->mpm->num_buckets;
        if (retained->mpm->was_graceful) {
            /* wake up the children...time to die.  But we'll have more soon */
            for (i = 0; i < num_buckets; i++) {
                ap_mpm_podx_killpg(retained->buckets[i].pod,
                                   limit, AP_MPM_PODX_GRACEFUL);
            }
        }
        else {
            /* Kill 'em all.  Since the child acts the same on the parents SIGTERM
             * and a SIGHUP, we may as well use the same signal, because some user
             * pthreads are stealing signals from us left and right.
             */
            for (i = 0; i < num_buckets; i++) {
                ap_mpm_podx_killpg(retained->buckets[i].pod,
                                   limit, AP_MPM_PODX_RESTART);
            }
            ap_reclaim_child_processes(1,  /* Start with SIGTERM */
                                       event_note_child_stopped);
        }
        apr_pool_clear(retained->gen_pool);
        retained->buckets = NULL;

        /* advance to the next generation */
        /* XXX: we really need to make sure this new generation number isn't in
         * use by any of the previous children.
         */
        ++retained->mpm->my_generation;
    }

    /* The previous generation's buckets count, kept on graceful restart if it
     * still fits and the ratio is unchanged (see event_listen_buckets()).
     */
    if (!retained->mpm->was_graceful) {
        num_buckets = 0;
        retained->mpm->num_buckets = 0; /* old gen's until event_run() */
    }

    if (auto_settings) {
        auto_settings_derive(s, startup);
    }

    if (retained->first_thread_limit) {
        if (threads_per_child > retained->first_thread_limit) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(10465)
                         "ThreadsPerChild (%d) exceeds initial ThreadLimit, "
                         "forcing ThreadsPerChild to %d",
                         threads_per_child, retained->first_thread_limit);
            threads_per_child = retained->first_thread_limit;
        }
    }
    else {
        if (thread_limit < threads_per_child) {
            thread_limit = threads_per_child;
        }
        retained->first_thread_limit = thread_limit;
        retained->first_thread_limit_derived =
            (auto_settings && !(auto_set_flags & AUTO_SET_THREAD_LIMIT));
    }

    /* The worker threads grow up to ThreadLimit in auto mode */
#ifdef EVENT_ELASTIC_THREADS
    elastic_threads = (auto_settings && thread_limit > threads_per_child);
#else
    elastic_threads = 0;
#endif
    threads_max = (elastic_threads) ? thread_limit : threads_per_child;

    /* MaxRequestWorkers is a multiple of ThreadsPerChild (already the case
     * without the auto settings), limited on restart by the scoreboard.
     */
    if (max_workers < threads_per_child) {
        max_workers = threads_per_child;
    }
    else {
        max_workers = (max_workers / threads_per_child) * threads_per_child;
    }
    active_daemons_limit = max_workers / threads_per_child;
    if (auto_settings && retained->first_server_limit) {
        /* The children target is started whole on graceful restart while the
         * previous generation drains (perform_children_target_maintenance()),
         * so it takes half of the initial scoreboard at most.
         */
        int limit = retained->first_server_sb_limit / 2;
        if (limit < 1) {
            limit = 1;
        }
        if (active_daemons_limit > limit) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO()
                         "MaxClientConnections (%d) would need %d children, "
                         "above half of the initial scoreboard limit (%d) "
                         "kept for a graceful restart: %d children, up to %"
                         APR_INT64_T_FMT " connections", max_client_conns,
                         active_daemons_limit, retained->first_server_sb_limit,
                         limit, (apr_int64_t)limit * clients_per_child);
            max_workers = limit * threads_per_child;
            active_daemons_limit = limit;
        }
    }
    else if (retained->first_server_limit
             && active_daemons_limit > retained->first_server_sb_limit) {
        int new_max_workers = retained->first_server_sb_limit * threads_per_child;
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(10466)
                     "MaxRequestWorkers (%d) / ThreadsPerChild (%d) would "
                     "exceed initial scoreboard limit (%d), forcing "
                     "MaxRequestWorkers to %d",
                     max_workers, threads_per_child,
                     retained->first_server_sb_limit,
                     new_max_workers);
        max_workers = new_max_workers;
        active_daemons_limit = retained->first_server_sb_limit;
    }

    /* A child's share of MaxClientConnections, with a 10% slack since the
     * kernel spreads the new connections only roughly evenly (when a child
     * stops accepting, the others take them).
     */
    clients_share = 0;
    if (auto_settings && max_client_conns > 0) {
        clients_share = ((apr_uint32_t)max_client_conns + active_daemons_limit - 1)
                        / active_daemons_limit;
        clients_share += (clients_share + 9) / 10;
    }

    /* The buckets divide the children, so MaxRequestWorkers is not changed */
    num_buckets = event_listen_buckets(s, num_buckets);
    if ((rv = ap_duplicate_listeners(retained->gen_pool, ap_server_conf,
                                     &retained->listen_buckets,
                                     &num_buckets))) {
        ap_log_error(APLOG_MARK, APLOG_ALERT | level_flags, rv,
                     (startup ? NULL : s), APLOGNO(03273)
                     "could not duplicate listeners, shutting down");
        return !OK;
    }
    retained->num_listen_buckets = num_buckets;
    min_threads = threads_per_child * num_buckets;

    if (retained->first_server_limit) {
        server_limit = retained->first_server_sb_limit;
    }
    else {
        /* Save the initial ServerLimit which cannot be changed on restart, but
         * leave some spare room in the actual server_[sb_]limit (used to size
         * the scoreboard) to allow for children restarting while the old gen
         * is gracefully exiting.
         */
        retained->first_server_limit = server_limit;
        if (server_limit < active_daemons_limit * SCOREBOARD_DAEMONS_FACTOR) {
            server_limit = active_daemons_limit * SCOREBOARD_DAEMONS_FACTOR;
        }
        retained->first_server_sb_limit = server_limit;
    }
    /* Start the same number of children per bucket */
    if (ap_daemons_to_start < num_buckets) {
        ap_daemons_to_start = num_buckets;
    }
    else if (ap_daemons_to_start < active_daemons_limit) {
        ap_daemons_to_start = ((ap_daemons_to_start + num_buckets - 1)
                               / num_buckets) * num_buckets;
    }
    else {
        ap_daemons_to_start = active_daemons_limit;
    }
    if (auto_settings) {
        /* Not used (perform_children_target_maintenance()) */
        min_spare_threads = max_spare_threads = 0;
    }
    else {
        if (min_spare_threads < ap_daemons_to_start * threads_per_child) {
            min_spare_threads = ap_daemons_to_start * threads_per_child;
        }
        else if (min_spare_threads < max_workers) {
            min_spare_threads = (min_spare_threads / min_threads) * min_threads;
        }
        else {
            min_spare_threads = max_workers;
        }
        if (max_spare_threads < min_spare_threads + min_threads) {
            max_spare_threads = min_spare_threads + min_threads;
        }
        else if (max_spare_threads < max_workers) {
            max_spare_threads = (max_spare_threads / min_threads) * min_threads;
        }
        else {
            max_spare_threads = max_workers;
        }
    }

    workers_backlog_limit = threads_per_child * admission_backlog;

    /* For the PODs of the next restart (see above) */
    retained->gen_daemons_limit = active_daemons_limit;

    return OK;
}

static int event_pre_config(apr_pool_t * pconf, apr_pool_t * plog,
                            apr_pool_t * ptemp)
{
    int no_detach, debug, foreground;
    apr_status_t rv;
    const char *userdata_key = "mpm_event_module";
    int test_atomics = 0;

    ap_mpm_register_extra_connection_fns();

    debug = ap_exists_config_define("DEBUG");

    if (debug) {
        foreground = one_process = 1;
        no_detach = 0;
    }
    else {
        one_process = ap_exists_config_define("ONE_PROCESS");
        no_detach = ap_exists_config_define("NO_DETACH");
        foreground = ap_exists_config_define("FOREGROUND");
    }

    retained = ap_retained_data_get(userdata_key);
    if (!retained) {
        retained = ap_retained_data_create(userdata_key, sizeof(*retained));
        retained->mpm = ap_unixd_mpm_get_retained_data();
        retained->mpm->baton = retained;
        if (retained->mpm->module_loads) {
            test_atomics = 1;
        }
    }
    else if (retained->mpm->baton != retained) {
        /* If the MPM changes on restart, be ungraceful */
        retained->mpm->baton = retained;
        retained->mpm->was_graceful = 0;
    }
    retained->mpm->mpm_state = AP_MPMQ_STARTING;
    ++retained->mpm->module_loads;

    /* test once for correct operation of fdqueue */
    if (test_atomics || retained->mpm->module_loads == 2) {
        static apr_uint32_t foo1, foo2;

        apr_atomic_set32(&foo1, 100);
        foo2 = apr_atomic_add32(&foo1, -10);
        if (foo2 != 100 || foo1 != 90) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, NULL, APLOGNO(02405)
                         "atomics not working as expected - add32 of negative number");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* sigh, want this only the second time around */
    if (retained->mpm->module_loads == 2) {
        /* The pollset the children need (see start_threads()) */
        apr_pollset_t *tmp = NULL;
        rv = pollset_create_good(&tmp, 1, plog,
                                 APR_POLLSET_THREADSAFE | APR_POLLSET_NOCOPY |
                                 APR_POLLSET_WAKEABLE | APR_POLLSET_NODEFAULT);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL, APLOGNO(00495)
                         "Couldn't create a thread safe and wakeable pollset "
                         "with port, kqueue or epoll. "
                         "Also check system or user limits!");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        apr_pollset_destroy(tmp);

        if (!one_process && !foreground) {
            /* before we detach, setup crash handlers to log to errorlog */
            ap_fatal_signal_setup(ap_server_conf, pconf);
            rv = apr_proc_detach(no_detach ? APR_PROC_DETACH_FOREGROUND
                                 : APR_PROC_DETACH_DAEMONIZE);
            if (rv != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_CRIT, rv, NULL, APLOGNO(00496)
                             "apr_proc_detach failed");
                return HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    parent_pid = ap_my_pid = getpid();

    ap_listen_pre_config();
    had_healthy_child = 0;
    ap_extended_status = 0;

    max_workers = -1;
    threads_per_child = -1;
    min_spare_threads = max_spare_threads = -1;
    server_limit = thread_limit = -1;
    ap_daemons_to_start = -1;
    auto_settings = 0;
    max_client_conns = 0;
    clients_per_child = 0;

#ifndef _SC_NPROCESSORS_ONLN
    num_cpus = 1;
#else
    num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cpus < 1) {
        num_cpus = 1;
    }
#endif
#ifdef HAVE_SCHED_GETAFFINITY
    {
        /* Those this process can run on (taskset, cpusets, isolcpus...) */
        cpu_set_t set;
        if (sched_getaffinity(0, sizeof(set), &set) == 0) {
            int n = CPU_COUNT(&set);
            if (n > 0 && n < num_cpus) {
                num_cpus = n;
            }
        }
    }
#endif
    admission_backlog = DEFAULT_ADMISSION_BACKLOG;
    admission_target = apr_time_from_msec(AP_EVENT_ADMISSION_TARGET);
    admission_interval = apr_time_from_msec(AP_EVENT_ADMISSION_INTERVAL);
    worker_pollers = AP_EVENT_WORKER_POLLERS;

    /* The waits' timeouts declared for this configuration (post-config) */
    declared_wait_timeouts = apr_array_make(pconf, 8,
                                            sizeof(apr_interval_time_t));
    wait_queues.mutex = NULL;
    wait_queues.next_expiry = 0;
    wait_tqs = NULL;
    wait_tqs_num = 0;

    return OK;
}

static int event_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s)
{
    apr_hash_t *io_h, *wc_h, *ka_h, *sh_h;

    /* Not needed in pre_config stage */
    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG) {
        return OK;
    }

    io_h = apr_hash_make(ptemp);
    wc_h = apr_hash_make(ptemp);
    ka_h = apr_hash_make(ptemp);
    sh_h = apr_hash_make(ptemp);

    linger_q = TO_QUEUE_MAKE(pconf, &conn_queues, "linger",
                             LINGER_READ_TIMEOUT, NULL);

    for (; s; s = s->next) {
        event_srv_cfg *sc = apr_pcalloc(pconf, sizeof *sc);
        ap_set_module_config(s->module_config, &mpm_event_module, sc);
        sc->s = s; /* backref */

        sc->io_q = TO_QUEUE_CHAIN(pconf, &conn_queues, "waitio",
                                  s->timeout, &waitio_q, io_h, ptemp);

        sc->wc_q = TO_QUEUE_CHAIN(pconf, &conn_queues, "write_completion",
                                  s->timeout, &write_completion_q, wc_h,
                                  ptemp);

        sc->ka_q = TO_QUEUE_CHAIN(pconf, &conn_queues, "keepalive",
                                  s->keep_alive_timeout, &keepalive_q, ka_h,
                                  ptemp);

        sc->sh_q = TO_QUEUE_CHAIN(pconf, &conn_queues, "shutdown",
                                  s->timeout, &shutdown_q, sh_h, ptemp);
    }

    /* The connections waiting for a worker have no timeout (the admission
     * bounds how many wait and how long: accepted, they're served late rather
     * than dropped), the lingering ones LINGER_READ_TIMEOUT (chained first).
     */
    backlog_conn_q = TO_QUEUE_MAKE(pconf, &conn_queues, "backlog", -1, NULL);
    backlog_linger_q = TO_QUEUE_MAKE(pconf, &conn_queues, "backlog_linger",
                                     LINGER_READ_TIMEOUT, backlog_conn_q);
    backlog_linger_q->next = backlog_conn_q;
    backlog_q = backlog_linger_q;

    return OK;
}

static int event_check_config(apr_pool_t *p, apr_pool_t *plog,
                              apr_pool_t *ptemp, server_rec *s)
{
    int startup = 0;

    /* the reverse of pre_config, we want this only the first time around */
    if (retained->mpm->module_loads == 1) {
        startup = 1;
    }

    auto_set_flags = 0;
    if (server_limit >= 0) {
        auto_set_flags |= AUTO_SET_SERVER_LIMIT;
    }
    if (thread_limit >= 0) {
        auto_set_flags |= AUTO_SET_THREAD_LIMIT;
    }

    if (server_limit < 0) {
        server_limit = DEFAULT_SERVER_LIMIT;
    }
    else if (server_limit > MAX_SERVER_LIMIT) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00497)
                         "WARNING: ServerLimit of %d exceeds compile-time "
                         "limit of %d servers, decreasing to %d.",
                         server_limit, MAX_SERVER_LIMIT, MAX_SERVER_LIMIT);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00498)
                         "ServerLimit of %d exceeds compile-time limit "
                         "of %d, decreasing to match",
                         server_limit, MAX_SERVER_LIMIT);
        }
        server_limit = MAX_SERVER_LIMIT;
    }
    else if (server_limit == 0) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00499)
                         "WARNING: ServerLimit of %d not allowed, "
                         "increasing to 1.", server_limit);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00500)
                         "ServerLimit of %d not allowed, increasing to 1",
                         server_limit);
        }
        server_limit = 1;
    }
    /* you cannot change ServerLimit across a restart; ignore
     * any such attempts
     */
    if (retained->first_server_limit && server_limit != retained->first_server_limit) {
        /* don't need a startup console version here */
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00501)
                     "changing ServerLimit to %d from original value of %d "
                     "not allowed during restart",
                     server_limit, retained->first_server_limit);
        server_limit = retained->first_server_limit;
    }

    if (thread_limit < 0) {
        /* Derived in auto mode (auto_settings_derive()) */
        if (!auto_settings) {
            thread_limit = DEFAULT_THREAD_LIMIT;
        }
    }
    else if (thread_limit > MAX_THREAD_LIMIT) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00502)
                         "WARNING: ThreadLimit of %d exceeds compile-time "
                         "limit of %d threads, decreasing to %d.",
                         thread_limit, MAX_THREAD_LIMIT, MAX_THREAD_LIMIT);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00503)
                         "ThreadLimit of %d exceeds compile-time limit "
                         "of %d, decreasing to match",
                         thread_limit, MAX_THREAD_LIMIT);
        }
        thread_limit = MAX_THREAD_LIMIT;
    }
    else if (thread_limit == 0) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00504)
                         "WARNING: ThreadLimit of %d not allowed, "
                         "increasing to 1.", thread_limit);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00505)
                         "ThreadLimit of %d not allowed, increasing to 1",
                         thread_limit);
        }
        thread_limit = 1;
    }
    /* you cannot change ThreadLimit across a restart; ignore
     * any such attempts (silently when it's not set and the original value
     * was derived, by MaxRequestWorkers auto)
     */
    if (retained->first_thread_limit && thread_limit >= 0
        && thread_limit != retained->first_thread_limit) {
        if ((auto_set_flags & AUTO_SET_THREAD_LIMIT)
            || !retained->first_thread_limit_derived) {
            /* don't need a startup console version here */
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00506)
                         "changing ThreadLimit to %d from original value of %d "
                         "not allowed during restart",
                         thread_limit, retained->first_thread_limit);
        }
        thread_limit = retained->first_thread_limit;
    }

    /* The auto settings depend on the listeners (the descriptors they take),
     * set up in event_open_logs() only, so they're derived there
     * (auto_settings_derive()).
     */
    if (auto_settings) {
        /* The children target is kept running whatever their idle threads
         * (perform_children_target_maintenance())
         */
        if (min_spare_threads >= 0 || max_spare_threads >= 0) {
            if (startup) {
                ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO()
                             "WARNING: MinSpareThreads and MaxSpareThreads have "
                             "no effect with MaxRequestWorkers auto, ignored.");
            } else {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO()
                             "MinSpareThreads and MaxSpareThreads have no "
                             "effect with MaxRequestWorkers auto, ignored");
            }
        }
        return OK; /* => event_open_logs() */
    }

    if (max_client_conns > 0) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO()
                         "WARNING: MaxClientConnections has no effect without "
                         "MaxRequestWorkers auto, ignored.");
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO()
                         "MaxClientConnections has no effect without "
                         "MaxRequestWorkers auto, ignored");
        }
        max_client_conns = 0;
    }

    /* No auto settings; use the default for anything not set (or set to
     * some negative value), warn about nonsense values and adjust otherwise.
     */

    if (threads_per_child < 0) {
        threads_per_child = DEFAULT_THREADS_PER_CHILD;
    }
    else if (threads_per_child > thread_limit) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00507)
                         "WARNING: ThreadsPerChild of %d exceeds ThreadLimit "
                         "of %d threads, decreasing to %d. "
                         "To increase, please see the ThreadLimit directive.",
                         threads_per_child, thread_limit, thread_limit);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00508)
                         "ThreadsPerChild of %d exceeds ThreadLimit "
                         "of %d, decreasing to match",
                         threads_per_child, thread_limit);
        }
        threads_per_child = thread_limit;
    }
    else if (threads_per_child == 0) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00509)
                         "WARNING: ThreadsPerChild of %d not allowed, "
                         "increasing to 1.", threads_per_child);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00510)
                         "ThreadsPerChild of %d not allowed, increasing to 1",
                         threads_per_child);
        }
        threads_per_child = 1;
    }

    if (max_workers < 0) {
        max_workers = DEFAULT_SERVER_LIMIT * DEFAULT_THREADS_PER_CHILD;
    }
    else if (max_workers < threads_per_child) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00511)
                         "WARNING: MaxRequestWorkers of %d is less than "
                         "ThreadsPerChild of %d, increasing to %d. "
                         "MaxRequestWorkers must be at least as large "
                         "as the number of threads in a single server.",
                         max_workers, threads_per_child, threads_per_child);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00512)
                         "MaxRequestWorkers of %d is less than ThreadsPerChild "
                         "of %d, increasing to match",
                         max_workers, threads_per_child);
        }
        max_workers = threads_per_child;
    }

    active_daemons_limit = max_workers / threads_per_child;
    if (active_daemons_limit > server_limit) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00515)
                         "WARNING: MaxRequestWorkers of %d would require %d servers "
                         "and would exceed ServerLimit of %d, decreasing to %d. "
                         "To increase, please see the ServerLimit directive.",
                         max_workers, active_daemons_limit, server_limit,
                         server_limit * threads_per_child);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00516)
                         "MaxRequestWorkers of %d would require %d servers and "
                         "exceed ServerLimit of %d, decreasing to %d",
                         max_workers, active_daemons_limit, server_limit,
                         server_limit * threads_per_child);
        }
        active_daemons_limit = server_limit;
        max_workers = active_daemons_limit * threads_per_child;
    }
    else if (max_workers % threads_per_child) {
        int new_max_workers = active_daemons_limit * threads_per_child;
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00513)
                         "WARNING: MaxRequestWorkers of %d is not an integer "
                         "multiple of ThreadsPerChild of %d, decreasing to nearest "
                         "multiple %d, for a maximum of %d servers.",
                         max_workers, threads_per_child, new_max_workers,
                         active_daemons_limit);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00514)
                         "MaxRequestWorkers of %d is not an integer multiple "
                         "of ThreadsPerChild of %d, decreasing to nearest "
                         "multiple %d", max_workers, threads_per_child,
                         new_max_workers);
        }
        max_workers = new_max_workers;
    }

    if (ap_daemons_to_start < 0) {
        ap_daemons_to_start = DEFAULT_START_DAEMON;
    }
    else if (ap_daemons_to_start > active_daemons_limit) {
        ap_daemons_to_start = active_daemons_limit;
    }
    else if (ap_daemons_to_start == 0) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00517)
                         "WARNING: StartServers of %d not allowed, "
                         "increasing to 1.", ap_daemons_to_start);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00518)
                         "StartServers of %d not allowed, increasing to 1",
                         ap_daemons_to_start);
        }
        ap_daemons_to_start = 1;
    }

    if (min_spare_threads < 0) {
        min_spare_threads = DEFAULT_MIN_FREE_DAEMON * DEFAULT_THREADS_PER_CHILD;
    }
    else if (min_spare_threads == 0) {
        if (startup) {
            ap_log_error(APLOG_MARK, APLOG_WARNING | APLOG_STARTUP, 0, NULL, APLOGNO(00519)
                         "WARNING: MinSpareThreads of %d not allowed, "
                         "increasing to 1 to avoid almost certain server "
                         "failure. Please read the documentation.",
                         min_spare_threads);
        } else {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, APLOGNO(00520)
                         "MinSpareThreads of %d not allowed, increasing to 1",
                         min_spare_threads);
        }
        min_spare_threads = threads_per_child;
    }

    if (max_spare_threads < 0) {
        max_spare_threads = DEFAULT_MAX_FREE_DAEMON * DEFAULT_THREADS_PER_CHILD;
    }
    else {
        /* max_spare_threads value has never been checked, it's silently
         * adjusted in event_open_logs() such that max_spare_threads >=
         * min_spare_threads + threads_per_child.
         */
    }

    return OK;
}

static void event_hooks(apr_pool_t * p)
{
    /* Our open_logs hook function must run before the core's, or stderr
     * will be redirected to a file, and the messages won't print to the
     * console.
     */
    static const char *const aszSucc[] = { "core.c", NULL };
    one_process = 0;
    ap_force_set_tz(p);

    ap_hook_open_logs(event_open_logs, NULL, aszSucc, APR_HOOK_REALLY_FIRST);
    /* we need to set the MPM state before other pre-config hooks use MPM query
     * to retrieve it, so register as REALLY_FIRST
     */
    ap_hook_pre_config(event_pre_config, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_post_config(event_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_config(event_check_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm(event_run, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_query(event_query, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_register_timed_callback(event_register_timed_callback, NULL, NULL,
                                        APR_HOOK_MIDDLE);
    ap_hook_pre_read_request(event_pre_read_request, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(event_post_read_request, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_get_name(event_get_name, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_resume_suspended(event_resume_suspended, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_register_wait(event_register_wait, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_register_timeouts(event_register_timeouts, NULL, NULL,
                                  APR_HOOK_MIDDLE);
    ap_hook_mpm_release_pfd(event_release_pfd, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_notifier_create(event_notifier_create, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_notify(event_notify, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_mpm_notifier_rearm(event_notifier_rearm, NULL, NULL,
                               APR_HOOK_MIDDLE);

    ap_hook_pre_connection(event_pre_connection, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_protocol_switch(event_protocol_switch, NULL, NULL, APR_HOOK_REALLY_FIRST);
}

static const char *set_daemons_to_start(cmd_parms *cmd, void *dummy,
                                        const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_daemons_to_start = atoi(arg);
    return NULL;
}

static const char *set_min_spare_threads(cmd_parms * cmd, void *dummy,
                                         const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    min_spare_threads = atoi(arg);
    return NULL;
}

static const char *set_max_spare_threads(cmd_parms * cmd, void *dummy,
                                         const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    max_spare_threads = atoi(arg);
    return NULL;
}

static const char *set_max_workers(cmd_parms * cmd, void *dummy,
                                   const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }
    if (!strcasecmp(cmd->cmd->name, "MaxClients")) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, NULL, APLOGNO(00521)
                     "MaxClients is deprecated, use MaxRequestWorkers "
                     "instead.");
    }

    if (strcasecmp(arg, "auto") == 0) {
        auto_settings = 1;
        max_workers = -1;
    }
    else {
        auto_settings = 0;
        max_workers = atoi(arg);
    }
    return NULL;
}

static const char *set_max_client_conns(cmd_parms *cmd, void *dummy,
                                        const char *arg)
{
    char *endptr;
    long n;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    n = strtol(arg, &endptr, 10);
    if (*endptr || n < 1 || n > INT_MAX / 2) {
        return "MaxClientConnections must be a positive number";
    }
    max_client_conns = (int)n;
    return NULL;
}

static const char *set_threads_per_child(cmd_parms * cmd, void *dummy,
                                         const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    threads_per_child = atoi(arg);
    return NULL;
}
static const char *set_server_limit(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    server_limit = atoi(arg);
    return NULL;
}

static const char *set_thread_limit(cmd_parms * cmd, void *dummy,
                                    const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    thread_limit = atoi(arg);
    return NULL;
}

static const char *set_worker_factor(cmd_parms * cmd, void *dummy,
                                     const char *arg)
{
    static int warnonce = 0;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    /* Its meaning (a limit of the connections per process) is gone, a value
     * tuned for it would mean something else for the admission.
     */
    if (++warnonce == 1) {
        ap_log_error(APLOG_MARK, APLOG_WARNING|APLOG_STARTUP, 0, NULL, APLOGNO()
                     "AsyncRequestWorkerFactor has no effect since 2.5.1, "
                     "see AsyncAdmissionBacklogPerThread %s:%d",
                     cmd->directive->filename, cmd->directive->line_num);
    }
    return NULL;
}

static const char *set_admission_backlog(cmd_parms *cmd, void *dummy,
                                         const char *arg)
{
    char *endptr;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    admission_backlog = strtod(arg, &endptr);
    if (*endptr || admission_backlog < 1.0) {
        return "AsyncAdmissionBacklogPerThread must be a rational number greater or equal to 1";
    }
    return NULL;
}

static const char *set_worker_pollers(cmd_parms *cmd, void *dummy,
                                      const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (strcasecmp(arg, "auto") == 0) {
        worker_pollers = 0;
    }
    else {
        char *endptr;
        long n = strtol(arg, &endptr, 10);
        if (*endptr || n < 1 || n > INT_MAX) {
            return "AsyncWorkerPollers must be a positive number or auto";
        }
        worker_pollers = (int)n;
    }
    return NULL;
}

static const char *set_admission_time(cmd_parms *cmd, void *dummy,
                                      const char *arg)
{
    apr_interval_time_t *t = cmd->info;
    apr_interval_time_t val;
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    if (ap_timeout_parameter_parse(arg, &val, "ms") != APR_SUCCESS
        || val <= 0) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name,
                           " must be a positive time (ms by default)", NULL);
    }
    *t = val;
    return NULL;
}


static const command_rec event_cmds[] = {
    LISTEN_COMMANDS,
    AP_INIT_TAKE1("StartServers", set_daemons_to_start, NULL, RSRC_CONF,
                  "Number of child processes launched at server startup"),
    AP_INIT_TAKE1("ServerLimit", set_server_limit, NULL, RSRC_CONF,
                  "Maximum number of child processes for this run of Apache"),
    AP_INIT_TAKE1("MinSpareThreads", set_min_spare_threads, NULL, RSRC_CONF,
                  "Minimum number of idle threads, to handle request spikes"),
    AP_INIT_TAKE1("MaxSpareThreads", set_max_spare_threads, NULL, RSRC_CONF,
                  "Maximum number of idle threads"),
    AP_INIT_TAKE1("MaxClients", set_max_workers, NULL, RSRC_CONF,
                  "Deprecated name of MaxRequestWorkers"),
    AP_INIT_TAKE1("MaxRequestWorkers", set_max_workers, NULL, RSRC_CONF,
                  "Maximum number of threads alive at the same time, or auto "
                  "(derived from the clients and the CPUs)"),
    AP_INIT_TAKE1("MaxClientConnections", set_max_client_conns, NULL, RSRC_CONF,
                  "Maximum number of simultaneous client connections, with "
                  "MaxRequestWorkers auto"),
    AP_INIT_TAKE1("ThreadsPerChild", set_threads_per_child, NULL, RSRC_CONF,
                  "Number of threads each child creates"),
    AP_INIT_TAKE1("ThreadLimit", set_thread_limit, NULL, RSRC_CONF,
                  "Maximum number of worker threads per child process for this "
                  "run of Apache - Upper limit for ThreadsPerChild"),
    AP_INIT_TAKE1("AsyncRequestWorkerFactor", set_worker_factor, NULL, RSRC_CONF,
                  "No effect since 2.5.1, see AsyncAdmissionBacklogPerThread"),
    AP_INIT_TAKE1("AsyncAdmissionBacklogPerThread", set_admission_backlog, NULL,
                  RSRC_CONF,
                  "How many new connections can wait for a worker, per "
                  "worker thread, before accepting stops"),
    AP_INIT_TAKE1("AsyncAdmissionTarget", set_admission_time, &admission_target,
                  RSRC_CONF,
                  "How long new connections can wait for a worker (ms by "
                  "default) before the admission counts them as late"),
    AP_INIT_TAKE1("AsyncAdmissionInterval", set_admission_time, &admission_interval,
                  RSRC_CONF,
                  "How long the new connections must be late (ms by default) "
                  "before accepting stops"),
    AP_INIT_TAKE1("AsyncWorkerPollers", set_worker_pollers, NULL, RSRC_CONF,
                  "How many idle workers can poll the connections at once, "
                  "or auto (the CPUs available)"),
    AP_GRACEFUL_SHUTDOWN_TIMEOUT_COMMAND,
    {NULL}
};

AP_DECLARE_MODULE(mpm_event) = {
    MPM20_MODULE_STUFF,
    NULL,                       /* hook to run before apache parses args */
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    event_cmds,                 /* command apr_table_t */
    event_hooks                 /* register_hooks */
};
