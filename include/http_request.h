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
 * @file http_request.h
 * @brief Apache Request library
 *
 * @defgroup APACHE_CORE_REQ Apache Request Processing
 * @ingroup  APACHE_CORE
 * @{
 */

/*
 * request.c is the code which handles the main line of request
 * processing, once a request has been read in (finding the right per-
 * directory configuration, building it if necessary, and calling all
 * the module dispatch functions in the right order).
 *
 * The pieces here which are public to the modules, allow them to learn
 * how the server would handle some other file or URI, or perhaps even
 * direct the server to serve that other file instead of the one the
 * client requested directly.
 *
 * There are two ways to do that.  The first is the sub_request mechanism,
 * which handles looking up files and URIs as adjuncts to some other
 * request (e.g., directory entries for multiviews and directory listings);
 * the lookup functions stop short of actually running the request, but
 * (e.g., for includes), a module may call for the request to be run
 * by calling run_sub_req.  The space allocated to create sub_reqs can be
 * reclaimed by calling destroy_sub_req --- be sure to copy anything you care
 * about which was allocated in its apr_pool_t elsewhere before doing this.
 */

#ifndef APACHE_HTTP_REQUEST_H
#define APACHE_HTTP_REQUEST_H

#include "apr_optional.h"
#include "apr_poll.h"
#include "util_filter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AP_SUBREQ_NO_ARGS 0
#define AP_SUBREQ_MERGE_ARGS 1

/**
 * An internal handler used by the ap_process_request, all subrequest mechanisms
 * and the redirect mechanism.
 * @param r The request, subrequest or internal redirect to pre-process
 * @return The return code for the request
 */
AP_DECLARE(int) ap_process_request_internal(request_rec *r);

/**
 * Create a subrequest from the given URI.  This subrequest can be
 * inspected to find information about the requested URI
 * @param new_uri The URI to lookup
 * @param r The current request
 * @param next_filter The first filter the sub_request should use.  If this is
 *                    NULL, it defaults to the first filter for the main request
 * @return The new request record
 */
AP_DECLARE(request_rec *) ap_sub_req_lookup_uri(const char *new_uri,
                                                const request_rec *r,
                                                ap_filter_t *next_filter);

/**
 * Create a subrequest for the given file.  This subrequest can be
 * inspected to find information about the requested file
 * @param new_file The file to lookup
 * @param r The current request
 * @param next_filter The first filter the sub_request should use.  If this is
 *                    NULL, it defaults to the first filter for the main request
 * @return The new request record
 */
AP_DECLARE(request_rec *) ap_sub_req_lookup_file(const char *new_file,
                                              const request_rec *r,
                                              ap_filter_t *next_filter);
/**
 * Create a subrequest for the given apr_dir_read result.  This subrequest
 * can be inspected to find information about the requested file
 * @param finfo The apr_dir_read result to lookup
 * @param r The current request
 * @param subtype What type of subrequest to perform, one of;
 * <PRE>
 *      AP_SUBREQ_NO_ARGS     ignore r->args and r->path_info
 *      AP_SUBREQ_MERGE_ARGS  merge r->args and r->path_info
 * </PRE>
 * @param next_filter The first filter the sub_request should use.  If this is
 *                    NULL, it defaults to the first filter for the main request
 * @return The new request record
 * @note The apr_dir_read flags value APR_FINFO_MIN|APR_FINFO_NAME flag is the
 * minimum recommended query if the results will be passed to apr_dir_read.
 * The file info passed must include the name, and must have the same relative
 * directory as the current request.
 */
AP_DECLARE(request_rec *) ap_sub_req_lookup_dirent(const apr_finfo_t *finfo,
                                                   const request_rec *r,
                                                   int subtype,
                                                   ap_filter_t *next_filter);
/**
 * Create a subrequest for the given URI using a specific method.  This
 * subrequest can be inspected to find information about the requested URI
 * @param method The method to use in the new subrequest
 * @param new_uri The URI to lookup
 * @param r The current request
 * @param next_filter The first filter the sub_request should use.  If this is
 *                    NULL, it defaults to the first filter for the main request
 * @return The new request record
 */
AP_DECLARE(request_rec *) ap_sub_req_method_uri(const char *method,
                                                const char *new_uri,
                                                const request_rec *r,
                                                ap_filter_t *next_filter);
/**
 * An output filter to strip EOS buckets from sub-requests.  This always
 * has to be inserted at the end of a sub-requests filter stack.
 * @param f The current filter
 * @param bb The brigade to filter
 * @return status code
 */
AP_CORE_DECLARE_NONSTD(apr_status_t) ap_sub_req_output_filter(ap_filter_t *f,
                                                        apr_bucket_brigade *bb);

/**
 * Run the handler for the subrequest
 * @param r The subrequest to run
 * @return The return code for the subrequest
 */
AP_DECLARE(int) ap_run_sub_req(request_rec *r);

/**
 * Free the memory associated with a subrequest
 * @param r The subrequest to finish
 */
AP_DECLARE(void) ap_destroy_sub_req(request_rec *r);

/*
 * Then there's the case that you want some other request to be served
 * as the top-level request INSTEAD of what the client requested directly.
 * If so, call this from a handler, and then immediately return OK.
 */

/**
 * Redirect the current request to some other uri
 * @param new_uri The URI to replace the current request with
 * @param r The current request
 */
AP_DECLARE(void) ap_internal_redirect(const char *new_uri, request_rec *r);

/**
 * This function is designed for things like actions or CGI scripts, when
 * using AddHandler, and you want to preserve the content type across
 * an internal redirect.
 * @param new_uri The URI to replace the current request with.
 * @param r The current request
 */
AP_DECLARE(void) ap_internal_redirect_handler(const char *new_uri, request_rec *r);

/**
 * Redirect the current request to a sub_req, merging the pools
 * @param sub_req A subrequest created from this request
 * @param r The current request
 * @note the sub_req's pool will be merged into r's pool, be very careful
 * not to destroy this subrequest, it will be destroyed with the main request!
 */
AP_DECLARE(void) ap_internal_fast_redirect(request_rec *sub_req, request_rec *r);

/**
 * Can be used within any handler to determine if any authentication
 * is required for the current request
 * @param r The current request
 * @return 1 if authentication is required, 0 otherwise
 * @bug Behavior changed in 2.4.x refactoring, API no longer usable
 * @deprecated @see ap_some_authn_required()
 */
AP_DECLARE(int) ap_some_auth_required(request_rec *r);

/**
 * @defgroup APACHE_CORE_REQ_AUTH Access Control for Sub-Requests and
 *                                Internal Redirects
 * @ingroup  APACHE_CORE_REQ
 * @{
 */

#define AP_AUTH_INTERNAL_PER_URI  0  /**< Run access control hooks on all
                                          internal requests with URIs
                                          distinct from that of initial
                                          request */
#define AP_AUTH_INTERNAL_PER_CONF 1  /**< Run access control hooks only on
                                          internal requests with
                                          configurations distinct from
                                          that of initial request */
#define AP_AUTH_INTERNAL_MASK     0x000F  /**< mask to extract internal request
                                               processing mode */

/**
 * Clear flag which determines when access control hooks will be run for
 * internal requests.
 */
AP_DECLARE(void) ap_clear_auth_internal(void);

/**
 * Determine whether access control hooks will be run for all internal
 * requests with URIs distinct from that of the initial request, or only
 * those for which different configurations apply than those which applied
 * to the initial request.  To accommodate legacy external modules which
 * may expect access control hooks to be run for all internal requests
 * with distinct URIs, this is the default behaviour unless all access
 * control hooks and authentication and authorization providers are
 * registered with AP_AUTH_INTERNAL_PER_CONF.
 * @param ptemp Pool used for temporary allocations
 */
AP_DECLARE(void) ap_setup_auth_internal(apr_pool_t *ptemp);

/**
 * Register an authentication or authorization provider with the global
 * provider pool.
 * @param pool The pool to create any storage from
 * @param provider_group The group to store the provider in
 * @param provider_name The name for this provider
 * @param provider_version The version for this provider
 * @param provider Opaque structure for this provider
 * @param type Internal request processing mode, either
 *             AP_AUTH_INTERNAL_PER_URI or AP_AUTH_INTERNAL_PER_CONF
 * @return APR_SUCCESS if all went well
 */
AP_DECLARE(apr_status_t) ap_register_auth_provider(apr_pool_t *pool,
                                                   const char *provider_group,
                                                   const char *provider_name,
                                                   const char *provider_version,
                                                   const void *provider,
                                                   int type);

/** @} */

/* Optional functions coming from mod_authn_core and mod_authz_core
 * that list all registered authn/z providers.
 */
APR_DECLARE_OPTIONAL_FN(apr_array_header_t *, authn_ap_list_provider_names,
                        (apr_pool_t *ptemp));
APR_DECLARE_OPTIONAL_FN(apr_array_header_t *, authz_ap_list_provider_names,
                        (apr_pool_t *ptemp));

/**
 * Determine if the current request is the main request or a subrequest
 * @param r The current request
 * @return 1 if this is the main request, 0 otherwise
 */
AP_DECLARE(int) ap_is_initial_req(request_rec *r);

/**
 * Function to set the r->mtime field to the specified value if it's later
 * than what's already there.
 * @param r The current request
 * @param dependency_mtime Time to set the mtime to
 */
AP_DECLARE(void) ap_update_mtime(request_rec *r, apr_time_t dependency_mtime);

/**
 * Add one or more methods to the list permitted to access the resource.
 * Usually executed by the content handler before the response header is
 * sent, but sometimes invoked at an earlier phase if a module knows it
 * can set the list authoritatively.  Note that the methods are ADDED
 * to any already permitted unless the reset flag is non-zero.  The
 * list is used to generate the Allow response header field when it
 * is needed.
 * @param   r     The pointer to the request identifying the resource.
 * @param   reset Boolean flag indicating whether this list should
 *                completely replace any current settings.
 * @param   ...   A NULL-terminated list of strings, each identifying a
 *                method name to add.
 * @return  None.
 */
AP_DECLARE(void) ap_allow_methods(request_rec *r, int reset, ...)
                 AP_FN_ATTR_SENTINEL;

/**
 * Add one or more methods to the list permitted to access the resource.
 * Usually executed by the content handler before the response header is
 * sent, but sometimes invoked at an earlier phase if a module knows it
 * can set the list authoritatively.  Note that the methods are ADDED
 * to any already permitted unless the reset flag is non-zero.  The
 * list is used to generate the Allow response header field when it
 * is needed.
 * @param   r     The pointer to the request identifying the resource.
 * @param   reset Boolean flag indicating whether this list should
 *                completely replace any current settings.
 * @param   ...   A list of method identifiers, from the "M_" series
 *                defined in httpd.h, terminated with a value of -1
 *                (e.g., "M_GET, M_POST, M_OPTIONS, -1")
 * @return  None.
 */
AP_DECLARE(void) ap_allow_standard_methods(request_rec *r, int reset, ...);

#define MERGE_ALLOW 0
#define REPLACE_ALLOW 1

/**
 * Process a top-level request from a client, and synchronously write
 * the response to the client
 * @param r The current request
 */
AP_DECLARE(void) ap_process_request(request_rec *r);

/* For post-processing after a handler has finished with a request.
 * (Commonly used after it was suspended)
 */
AP_DECLARE(void) ap_process_request_after_handler(request_rec *r);

/**
 * Process a top-level request from a client, allowing some or all of
 * the response to remain buffered in the core output filter for later,
 * asynchronous write completion
 * @param r The current request
 */
void ap_process_async_request(request_rec *r);

/**
 * Finish a request whose handler returned SUSPENDED, once the module that
 * suspended it is done with it (e.g. from the continuation of its last
 * wait, ap_mpm_register_wait()): as ap_process_async_request() would have
 * continued if the handler had returned status (ap_die() and
 * ap_process_request_after_handler()), then give the connection back to the
 * MPM (ap_mpm_resume_suspended()).
 * @param r The suspended request
 * @param status The handler's final status (OK, DONE or an HTTP error)
 * @remark Don't dereference r afterwards.
 */
AP_DECLARE(void) ap_request_finish_suspended(request_rec *r, int status);

/**
 * Whether the request can be suspended now, i.e. a module can wait
 * asynchronously and return SUSPENDED from the current hook: the MPM can
 * wait (AP_MPMQ_CAN_REGISTER_WAIT), the request is a top-level one processed
 * by ap_process_async_request(), neither a subrequest nor (for now)
 * internally redirected or on a secondary connection (HTTP/2 stream), it
 * is in a phase that can suspend (the handlers for now), and AsyncRequests
 * isn't off for it.
 * @param r The request
 * @return non-zero if it can
 */
AP_DECLARE(int) ap_request_can_suspend(request_rec *r);

/** The directions of a request's wait (ap_request_wait()), as bits */
typedef enum {
    AP_WAIT_IN  = (1u << 0), /**< readable (input) */
    AP_WAIT_OUT = (1u << 1)  /**< writable (room for the pending output) */
} ap_wait_direction_e;

/**
 * Flag for ap_request_wait() and ap_request_wait_any(): the caller drained
 * what it waits for, i.e. the read or write it waits for failed with EAGAIN
 * since its last wait, so a target that the MPM keeps registered across the
 * waits needs no check for a readiness the caller would have consumed
 * (AP_MPM_WAIT_DRAINED). Without it the MPM checks such targets, which is
 * always correct.
 */
#define AP_REQUEST_WAIT_DRAINED (1u << 0)

/**
 * The timeout of a wait context (ap_request_waitctx_t) that core resolves
 * at each wait: for the client connection, the time left to read
 * (ap_get_connection_timeout(): Timeout, or less with mod_reqtimeout) when
 * waiting for input, the server's Timeout when waiting for output only; for
 * other connections and descriptors, the server's Timeout. Not a timeout
 * given to the MPM (where any negative value means none).
 */
#define AP_REQUEST_WAITCTX_TIMEOUT_DEFAULT ((apr_interval_time_t)-2)

/**
 * @brief A request's wait context: what a module waits for (the client
 * connection, a timer, ...), created by core for a request
 * (ap_request_waitctx_*()) from the pool given to its constructor, but the
 * client's (in the request's pool, for the whole request). The module sets
 * the fields below as needed before waiting (ap_request_wait()); core's own
 * part follows them in the allocation.
 * @remark The pool must outlive every wait on the context, and not outlive
 *         the request: the request's pool or one destroyed before it (e.g.
 *         a subpool, for a context made per target). Cleaning it up
 *         releases the context (ap_request_waitctx_release()); destroying
 *         it while a wait on the context is in flight is a bug of the
 *         caller (logged as an error, the context detached from the wait,
 *         debug builds asserting).
 */
typedef struct {
    /** The request that waits (set by core) */
    request_rec *r;
    /** The module whose log level the waits' log lines follow: the module
     *  calling the ap_request_waitctx_*() macros (APLOG_MODULE_INDEX, which
     *  is APLOG_NO_MODULE outside a module, as for logging), or the index
     *  given to their ap_request_waitctx_*_() functions by code acting for
     *  another module */
    int module_index;
    /** The timeout of the waits: AP_REQUEST_WAITCTX_TIMEOUT_DEFAULT (initially,
     *  but for timers and notifiers), a negative value for none (initially
     *  for a notifier), or the delay of a timer (initially negative: to be
     *  set) */
    apr_interval_time_t timeout;
    /** How long to poll the target synchronously before suspending, for a
     *  readiness expected soon: none if zero (initially) or negative */
    apr_interval_time_t delay;
} ap_request_waitctx_t;

/**
 * The continuation of a request's wait (ap_request_wait()), called by a
 * thread processing the request once the wait completes.
 * @param r The request that waited (the context's)
 * @param status APR_SUCCESS when ready (or a timer's delay elapsed, a
 *        notifier notified), APR_TIMEUP when the wait timed out, or
 *        APR_EGENERAL when the MPM failed to wait (e.g. a pollset error)
 * @param baton The baton given to the wait
 * @remark The continuation either waits again (and returns), or continues
 *         the request until it ends it (ap_request_finish_suspended()),
 *         then doesn't touch r.
 */
typedef void ap_request_continuation_fn(request_rec *r, apr_status_t status,
                                        void *baton);

/**
 * The context of the request's waits for its client connection, the same
 * for the whole request (shared by the modules waiting for the client: set
 * its fields before each wait).
 * @param r The request
 * @param module_index The module whose log level the waits' log lines
 *        follow, set at each call
 * @return The context
 * @remark The client's socket is kept registered in the MPM from the second
 *         wait in a direction (AP_MPM_WAIT_KEEP_PFDS) until the request is
 *         done, or the context is released (ap_request_waitctx_release()).
 */
AP_DECLARE(ap_request_waitctx_t *) ap_request_waitctx_client_(request_rec *r,
                                                              int module_index);

/** ap_request_waitctx_client_() for the calling module (APLOG_MODULE_INDEX) */
#define ap_request_waitctx_client(r) \
    ap_request_waitctx_client_(r, APLOG_MODULE_INDEX)

/**
 * A context for the request to wait for another connection than the
 * client's (e.g. a backend's), whose filters are checked like the client's
 * (input pending, no output pending) before waiting for its socket.
 * @param r The request
 * @param p The pool to allocate the context from (see ap_request_waitctx_t)
 * @param c The connection
 * @param module_index The module whose log level the waits' log lines
 *        follow
 * @return The context, in p
 * @remark The connection's socket is kept registered in the MPM from the
 *         second wait in a direction (AP_MPM_WAIT_KEEP_PFDS): release the
 *         context (ap_request_waitctx_release()) before closing it or
 *         letting another request use it.
 */
AP_DECLARE(ap_request_waitctx_t *) ap_request_waitctx_conn_(request_rec *r,
                                                            apr_pool_t *p,
                                                            conn_rec *c,
                                                            int module_index);

/** ap_request_waitctx_conn_() for the calling module (APLOG_MODULE_INDEX) */
#define ap_request_waitctx_conn(r, p, c) \
    ap_request_waitctx_conn_(r, p, c, APLOG_MODULE_INDEX)

/**
 * A context for the request to wait for a descriptor (socket or pipe) read
 * or written directly, not through a connection's filters: nothing is
 * checked before waiting for it.
 * @param r The request
 * @param p The pool to allocate the context from (see ap_request_waitctx_t)
 * @param pfd The descriptor (desc_type and desc only, copied)
 * @param module_index The module whose log level the waits' log lines
 *        follow
 * @return The context, in p
 * @remark The descriptor is kept registered in the MPM from the second
 *         wait in a direction (AP_MPM_WAIT_KEEP_PFDS): release the context
 *         (ap_request_waitctx_release()) before closing it or letting
 *         another request use it.
 */
AP_DECLARE(ap_request_waitctx_t *) ap_request_waitctx_pfd_(request_rec *r,
                                                           apr_pool_t *p,
                                                           const apr_pollfd_t *pfd,
                                                           int module_index);

/** ap_request_waitctx_pfd_() for the calling module (APLOG_MODULE_INDEX) */
#define ap_request_waitctx_pfd(r, p, pfd) \
    ap_request_waitctx_pfd_(r, p, pfd, APLOG_MODULE_INDEX)

/**
 * A context for the request to wait for a delay (its timeout, to set),
 * whatever the direction given to ap_request_wait(): a timer completes its
 * wait with APR_SUCCESS.
 * @param r The request
 * @param p The pool to allocate the context from (see ap_request_waitctx_t)
 * @param module_index The module whose log level the waits' log lines
 *        follow
 * @return The context, in p
 */
AP_DECLARE(ap_request_waitctx_t *) ap_request_waitctx_timer_(request_rec *r,
                                                             apr_pool_t *p,
                                                             int module_index);

/** ap_request_waitctx_timer_() for the calling module (APLOG_MODULE_INDEX) */
#define ap_request_waitctx_timer(r, p) \
    ap_request_waitctx_timer_(r, p, APLOG_MODULE_INDEX)

/* ap_mpm.h's ap_mpm_notifier_t, not included here to keep this header from
 * pulling ap_mpm.h and scoreboard.h into every module (and C89 forbids
 * repeating its typedef)
 */
struct ap_mpm_notifier_t;

/**
 * A context for the request to wait for a notifier, notified from any thread
 * (ap_mpm_notify()), whatever the direction given to ap_request_wait(): a
 * notifier completes its wait with APR_SUCCESS. No timeout by default.
 * @param r The request
 * @param p The pool to allocate the context from (see ap_request_waitctx_t),
 *        e.g. the notifier's
 * @param notifier The notifier (ap_mpm_notifier_create()), whose pool must
 *        outlive the waits
 * @param module_index The module whose log level the waits' log lines
 *        follow
 * @return The context, in p
 * @remark A notifier serves a single wait, so does its context, unless the
 *         notifier is re-armed (ap_mpm_notifier_rearm()) once that wait
 *         has completed (its continuation called): the context then waits
 *         again, its fields set before each wait, a notification made
 *         before the re-arm dropped. Otherwise the next wait needs a new
 *         notifier and context (the old one released,
 *         ap_request_waitctx_release()): a wait on a context whose
 *         notifier served a wait and wasn't re-armed is logged as an error
 *         and answered DECLINED, the notifier never re-armed implicitly.
 */
AP_DECLARE(ap_request_waitctx_t *) ap_request_waitctx_notifier_(request_rec *r,
                                                                apr_pool_t *p,
                                                                struct ap_mpm_notifier_t *notifier,
                                                                int module_index);

/** ap_request_waitctx_notifier_() for the calling module
 *  (APLOG_MODULE_INDEX) */
#define ap_request_waitctx_notifier(r, p, notifier) \
    ap_request_waitctx_notifier_(r, p, notifier, APLOG_MODULE_INDEX)

/**
 * Release a wait context once its target is given up: the MPM stops keeping
 * its descriptor registered (ap_mpm_release_pfd()), when the wait in
 * flight completes if any, and the context can't wait anymore (a new one
 * is needed, e.g. the next ap_request_waitctx_client()).
 * @param ctx The context
 * @remark It must be called before the target's descriptor is closed or
 *         used by another connection, from the thread processing the
 *         request (the handler, or a continuation).
 */
AP_DECLARE(void) ap_request_waitctx_release(ap_request_waitctx_t *ctx);

/**
 * Wait for a target without holding the thread when possible. Unless it's
 * ready already (for a connection: input pending in its filters,
 * ap_check_input_pending(); no output pending, ap_check_output_pending()),
 * or within the context's delay (polled), the MPM waits for it.
 * @param ctx The context of the target
 * @param direction AP_WAIT_IN or AP_WAIT_OUT for a connection or a
 *        descriptor, ignored by a timer or a notifier
 * @param flags AP_REQUEST_WAIT_DRAINED or 0
 * @param fn Called once the asynchronous wait completes
 * @param baton For fn
 * @return SUSPENDED if waiting asynchronously (return SUSPENDED up, fn is
 *         called later, never inline), OK if ready now or with an error the
 *         next I/O will report (go on), or DECLINED if the request can't
 *         wait asynchronously (ap_request_can_suspend(), or the MPM
 *         refusing the wait, e.g. a notifier not re-armed after its
 *         previous wait): go on blocking (or sleep for a timer).
 * @remark From the second wait in a direction, the MPM keeps the target's
 *         descriptor registered (AP_MPM_WAIT_KEEP_PFDS).
 * @remark Input that the filters keep after the caller's last read returned
 *         EAGAIN (e.g. mod_ssl's part of a line) is pending but not readable:
 *         such a wait answers OK once, then waits.
 * @remark ap_request_waitctx_ready() tells which directions are ready.
 */
AP_DECLARE(int) ap_request_wait(ap_request_waitctx_t *ctx,
                                ap_wait_direction_e direction,
                                unsigned int flags,
                                ap_request_continuation_fn *fn, void *baton);

/**
 * Wait for several targets of a request at once, the first ready completing
 * the wait, as ap_request_wait() does for one: OK when some are ready
 * already, else SUSPENDED or DECLINED. The timeout is the smallest of the
 * contexts', the delay the smallest of those waiting for a descriptor (no
 * poll if any of them has none).
 * @param ctxs The contexts, all of the same request, at most one notifier
 * @param nctxs The number of contexts
 * @param directions For each context, AP_WAIT_IN and/or AP_WAIT_OUT (both
 *        for the same descriptor in one wait), ignored by a timer or a
 *        notifier
 * @param flags AP_REQUEST_WAIT_DRAINED or 0
 * @param fn Called once the asynchronous wait completes
 * @param baton For fn
 * @return As ap_request_wait()
 * @remark The MPM keeps the targets' descriptors registered from the first
 *         wait (AP_MPM_WAIT_KEEP_PFDS), such waits being repeated.
 * @remark ap_request_waitctx_ready() tells which targets and directions are
 *         ready, for each context.
 */
AP_DECLARE(int) ap_request_wait_any(ap_request_waitctx_t *const *ctxs,
                                    int nctxs,
                                    const unsigned int *directions,
                                    unsigned int flags,
                                    ap_request_continuation_fn *fn,
                                    void *baton);

/**
 * The directions found ready by the last wait of a context: when it
 * answered OK, or for its continuation.
 * @param ctx The context
 * @return AP_WAIT_IN and/or AP_WAIT_OUT, or 0 (e.g. after a timeout, or
 *         another target of ap_request_wait_any() ready); both for a timer
 *         whose delay elapsed or a notifier notified
 */
AP_DECLARE(unsigned int) ap_request_waitctx_ready(const ap_request_waitctx_t *ctx);

/**
 * Kill the current request
 * @param type Why the request is dying
 * @param r The current request
 */
AP_DECLARE(void) ap_die(int type, request_rec *r);

/**
 * Check whether a connection is still established and has data available,
 * optionally consuming blank lines ([CR]LF).
 * @param c The current connection
 * @param bb The brigade to filter
 * @param max_blank_lines Max number of blank lines to consume, or zero
 *                        to consider them as data (single read).
 * @return APR_SUCCESS: connection established with data available,
 *         APR_EAGAIN: connection established and empty,
 *         APR_NOTFOUND: too much blank lines,
 *         APR_E*: connection/general error.
 */
AP_DECLARE(apr_status_t) ap_check_pipeline(conn_rec *c, apr_bucket_brigade *bb,
                                           unsigned int max_blank_lines);

/* Hooks */

/**
 * Gives modules a chance to create their request_config entry when the
 * request is created.
 * @param r The current request
 * @ingroup hooks
 */
AP_DECLARE_HOOK(int,create_request,(request_rec *r))

/**
 * This hook allow modules an opportunity to translate the URI into an
 * actual filename, before URL decoding happens.
 * @param r The current request
 * @return DECLINED to let other modules handle the pre-translation,
 *         OK if it was handled and no other module should process it,
 *         DONE if no further transformation should happen on the URI,
 *         HTTP_... in case of error.
 * @ingroup hooks
 */
AP_DECLARE_HOOK(int,pre_translate_name,(request_rec *r))

/**
 * This hook allow modules an opportunity to translate the URI into an
 * actual filename.  If no modules do anything special, the server's default
 * rules will be followed.
 * @param r The current request
 * @return OK, DECLINED, or HTTP_...
 * @ingroup hooks
 */
AP_DECLARE_HOOK(int,translate_name,(request_rec *r))

/**
 * This hook allow modules to set the per_dir_config based on their own
 * context (such as "<Proxy>" sections) and responds to contextless requests
 * such as TRACE that need no security or filesystem mapping.
 * based on the filesystem.
 * @param r The current request
 * @return DONE (or HTTP_) if this contextless request was just fulfilled
 * (such as TRACE), OK if this is not a file, and DECLINED if this is a file.
 * The core map_to_storage (HOOK_RUN_REALLY_LAST) will directory_walk
 * and file_walk the r->filename.
 *
 * @ingroup hooks
 */
AP_DECLARE_HOOK(int,map_to_storage,(request_rec *r))

/**
 * This hook is used to analyze the request headers, authenticate the user,
 * and set the user information in the request record (r->user and
 * r->ap_auth_type). This hook is only run when Apache determines that
 * authentication/authorization is required for this resource (as determined
 * by the 'Require' directive). It runs after the access_checker hook, and
 * before the auth_checker hook. This hook should be registered with
 * ap_hook_check_authn().
 * If "Satisfy any" is in effect, this hook may be skipped.
 *
 * @param r The current request
 * @return OK, DECLINED, or HTTP_...
 * @ingroup hooks
 * @see ap_hook_check_authn
 */
AP_DECLARE_HOOK(int,check_user_id,(request_rec *r))

/**
 * Allows modules to perform module-specific fixing of header fields.  This
 * is invoked just before any content-handler
 * @param r The current request
 * @return OK, DECLINED, or HTTP_...
 * @ingroup hooks
 */
AP_DECLARE_HOOK(int,fixups,(request_rec *r))

/**
 * This routine is called to determine and/or set the various document type
 * information bits, like Content-type (via r->content_type), language, et
 * cetera.
 * @param r the current request
 * @return OK, DECLINED, or HTTP_...
 * @ingroup hooks
 */
AP_DECLARE_HOOK(int,type_checker,(request_rec *r))

/**
 * This hook is used to apply additional access control to this resource.
 * It runs *before* a user is authenticated, so this hook is really to
 * apply additional restrictions independent of a user. It also runs
 * independent of 'Require' directive usage. This hook should be registered
 * with ap_hook_check_access().
 *
 * @param r the current request
 * @return OK, DECLINED, or HTTP_...
 * @ingroup hooks
 * @see ap_hook_check_access
 */
AP_DECLARE_HOOK(int,access_checker,(request_rec *r))

/**
 * This hook is used to apply additional access control and/or bypass
 * authentication for this resource. It runs *before* a user is authenticated,
 * but after the access_checker hook.
 * This hook should be registered with ap_hook_check_access_ex().
 * If "Satisfy any" is in effect, this hook may be skipped.
 *
 * @param r the current request
 * @return OK (allow access), DECLINED (let later modules decide),
 *         or HTTP_... (deny access)
 * @ingroup hooks
 * @see ap_hook_check_access_ex
 */
AP_DECLARE_HOOK(int,access_checker_ex,(request_rec *r))

/**
 * This hook is used to check to see if the resource being requested
 * is available for the authenticated user (r->user and r->ap_auth_type).
 * It runs after the access_checker and check_user_id hooks. Note that
 * it will *only* be called if Apache determines that access control has
 * been applied to this resource (through a 'Require' directive). This
 * hook should be registered with ap_hook_check_authz().
 * If "Satisfy any" is in effect, this hook may be skipped.
 *
 * @param r the current request
 * @return OK, DECLINED, or HTTP_...
 * @ingroup hooks
 * @see ap_hook_check_authz
 */
AP_DECLARE_HOOK(int,auth_checker,(request_rec *r))

/**
 * This hook is used to parse any tokens in the request that might key
 * or contain metadata such as users or IP addresses that may be
 * relevant to the request. It runs before the access checker. This
 * hook should be registered with ap_hook_check_autht().
 *
 * @param r the current request
 * @return OK, DECLINED, or HTTP_...
 * @ingroup hooks
 * @see ap_hook_check_authz
 */
AP_DECLARE_HOOK(int,token_checker,(request_rec *r))

/**
 * Register a hook function that will apply additional access control to
 * the current request.
 * @param pf An access_checker hook function
 * @param aszPre A NULL-terminated array of strings that name modules whose
 *               hooks should precede this one
 * @param aszSucc A NULL-terminated array of strings that name modules whose
 *                hooks should succeed this one
 * @param nOrder An integer determining order before honouring aszPre and
 *               aszSucc (for example, HOOK_MIDDLE)
 * @param type Internal request processing mode, either
 *             AP_AUTH_INTERNAL_PER_URI or AP_AUTH_INTERNAL_PER_CONF
 */
AP_DECLARE(void) ap_hook_check_access(ap_HOOK_access_checker_t *pf,
                                      const char * const *aszPre,
                                      const char * const *aszSucc,
                                      int nOrder, int type);

/**
 * Register a hook function that will apply additional access control
 * and/or bypass authentication for the current request.
 * @param pf An access_checker_ex hook function
 * @param aszPre A NULL-terminated array of strings that name modules whose
 *               hooks should precede this one
 * @param aszSucc A NULL-terminated array of strings that name modules whose
 *                hooks should succeed this one
 * @param nOrder An integer determining order before honouring aszPre and
 *               aszSucc (for example, HOOK_MIDDLE)
 * @param type Internal request processing mode, either
 *             AP_AUTH_INTERNAL_PER_URI or AP_AUTH_INTERNAL_PER_CONF
 */
AP_DECLARE(void) ap_hook_check_access_ex(ap_HOOK_access_checker_ex_t *pf,
                                         const char * const *aszPre,
                                         const char * const *aszSucc,
                                         int nOrder, int type);

/**
 * Register a hook function that will analyze the request headers, extract
 * any tokens, and apply and metadata contained in the tokens or keyed against
 * the tokens to the request record.
 * @param pf A token_checker hook function
 * @param aszPre A NULL-terminated array of strings that name modules whose
 *               hooks should precede this one
 * @param aszSucc A NULL-terminated array of strings that name modules whose
 *                hooks should succeed this one
 * @param nOrder An integer determining order before honouring aszPre and
 *               aszSucc (for example, HOOK_MIDDLE)
 * @param type Internal request processing mode, either
 *             AP_AUTH_INTERNAL_PER_URI or AP_AUTH_INTERNAL_PER_CONF
 */
AP_DECLARE(void) ap_hook_check_autht(ap_HOOK_token_checker_t *pf,
                                     const char * const *aszPre,
                                     const char * const *aszSucc,
                                     int nOrder, int type);

/**
 * Register a hook function that will analyze the request headers,
 * authenticate the user, and set the user information in the request record.
 * @param pf A check_user_id hook function
 * @param aszPre A NULL-terminated array of strings that name modules whose
 *               hooks should precede this one
 * @param aszSucc A NULL-terminated array of strings that name modules whose
 *                hooks should succeed this one
 * @param nOrder An integer determining order before honouring aszPre and
 *               aszSucc (for example, HOOK_MIDDLE)
 * @param type Internal request processing mode, either
 *             AP_AUTH_INTERNAL_PER_URI or AP_AUTH_INTERNAL_PER_CONF
 */
AP_DECLARE(void) ap_hook_check_authn(ap_HOOK_check_user_id_t *pf,
                                     const char * const *aszPre,
                                     const char * const *aszSucc,
                                     int nOrder, int type);

/**
 * Register a hook function that determine if the resource being requested
 * is available for the currently authenticated user.
 * @param pf An auth_checker hook function
 * @param aszPre A NULL-terminated array of strings that name modules whose
 *               hooks should precede this one
 * @param aszSucc A NULL-terminated array of strings that name modules whose
 *                hooks should succeed this one
 * @param nOrder An integer determining order before honouring aszPre and
 *               aszSucc (for example, HOOK_MIDDLE)
 * @param type Internal request processing mode, either
 *             AP_AUTH_INTERNAL_PER_URI or AP_AUTH_INTERNAL_PER_CONF
 */
AP_DECLARE(void) ap_hook_check_authz(ap_HOOK_auth_checker_t *pf,
                                     const char * const *aszPre,
                                     const char * const *aszSucc,
                                     int nOrder, int type);

/**
 * This hook allows modules to insert filters for the current request
 * @param r the current request
 * @ingroup hooks
 */
AP_DECLARE_HOOK(void,insert_filter,(request_rec *r))

/**
 * This hook allows modules to affect the request immediately after the
 * per-directory configuration for the request has been generated.
 * @param r The current request
 * @return OK (allow access), DECLINED (let later modules decide),
 *         or HTTP_... (deny access)
 * @ingroup hooks
 */
AP_DECLARE_HOOK(int,post_perdir_config,(request_rec *r))

/**
 * This hook allows a module to force authn to be required when
 * processing a request.
 * This hook should be registered with ap_hook_force_authn().
 * @param r The current request
 * @return OK (force authn), DECLINED (let later modules decide)
 * @ingroup hooks
 */
AP_DECLARE_HOOK(int,force_authn,(request_rec *r))

/**
 * This hook allows modules to handle/emulate the apr_stat() calls
 * needed for directory walk.
 * @param finfo where to put the stat data
 * @param r The current request
 * @param wanted APR_FINFO_* flags to pass to apr_stat()
 * @return apr_status_t or AP_DECLINED (let later modules decide)
 * @ingroup hooks
 */
AP_DECLARE_HOOK(apr_status_t,dirwalk_stat,(apr_finfo_t *finfo, request_rec *r, apr_int32_t wanted))

AP_DECLARE(int) ap_location_walk(request_rec *r);
AP_DECLARE(int) ap_directory_walk(request_rec *r);
AP_DECLARE(int) ap_file_walk(request_rec *r);
AP_DECLARE(int) ap_if_walk(request_rec *r);

/** End Of REQUEST (EOR) bucket */
AP_DECLARE_DATA extern const apr_bucket_type_t ap_bucket_type_eor;

/**
 * Determine if a bucket is an End Of REQUEST (EOR) bucket
 * @param e The bucket to inspect
 * @return true or false
 */
#define AP_BUCKET_IS_EOR(e)         ((e)->type == &ap_bucket_type_eor)

/**
 * Make the bucket passed in an End Of REQUEST (EOR) bucket
 * @param b The bucket to make into an EOR bucket
 * @param r The request to destroy when this bucket is destroyed
 * @return The new bucket, or NULL if allocation failed
 */
AP_DECLARE(apr_bucket *) ap_bucket_eor_make(apr_bucket *b, request_rec *r);

/**
 * Create a bucket referring to an End Of REQUEST (EOR). This bucket
 * holds a pointer to the request_rec, so that the request can be
 * destroyed right after all of the output has been sent to the client.
 *
 * @param list The freelist from which this bucket should be allocated
 * @param r The request to destroy when this bucket is destroyed
 * @return The new bucket, or NULL if allocation failed
 */
AP_DECLARE(apr_bucket *) ap_bucket_eor_create(apr_bucket_alloc_t *list,
                                              request_rec *r);

/**
 * Get the request bound to an End Of Request (EOR) bucket.
 * @param b The EOR bucket
 * @return Its associated request
 */
AP_DECLARE(request_rec *) ap_bucket_eor_request(apr_bucket *b);

/**
 * Can be used within any handler to determine if any authentication
 * is required for the current request.  Note that if used with an
 * access_checker hook, an access_checker_ex hook or an authz provider; the
 * caller should take steps to avoid a loop since this function is
 * implemented by calling these hooks.
 * @param r The current request
 * @return TRUE if authentication is required, FALSE otherwise
 */
AP_DECLARE(int) ap_some_authn_required(request_rec *r);

#ifdef __cplusplus
}
#endif

#endif  /* !APACHE_HTTP_REQUEST_H */
/** @} */
