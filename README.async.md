# Asynchronous requests: concepts and APIs

This document is for module and MPM developers. It explains how a request can wait without holding a
thread, which APIs do it, and how to use them. It covers concepts and usage. The headers' doxygen
documents each function precisely, and [the appendix](#appendix-the-functions-by-purpose) lists the
functions by purpose.

## 1. Introduction

A request (or a connection) is asynchronous when it waits without holding a worker thread. "Waiting"
here means waiting for a backend to answer, for the client to send more of its body or to make room
for the response, for a timer, or for another thread to say that something is done. Meanwhile the
request is suspended: the hook that waits returned `SUSPENDED`, and the MPM keeps the connection,
not a thread. When what it waits for is ready, a worker thread calls the module's continuation,
which goes on with the request. For now only handlers, the quick_handler and output filters (through
holds) can suspend; resumable request phases are planned ([8.1](#81-resumable-request-phases)).

Only mpm_event can wait like this. With the other MPMs (worker, prefork, winnt), on HTTP/2 streams,
and wherever `AsyncRequests Off` applies, the same calls tell the module that it can't wait
asynchronously. The module then does the same work blocking, as it always did. A module written for
this API works with every MPM; it only holds fewer threads with event.

What a module does to benefit:

- use nonblocking I/O on what it waits for, and on `EAGAIN` wait through the API instead of polling
  or sleeping;
- keep its per-request state in a structure that survives the return to the MPM (in `r->pool`), so
  that a continuation can pick up where the hook stopped;
- return `SUSPENDED` up the call stack when a wait suspends, and end or resume the request from the
  continuation of its last wait;
- keep a blocking path for when the wait is refused.

There are two layers:

- **The MPM API** (see `ap_mpm.h`) has one MPM wait per connection, on descriptors, a notifier and a
  timeout, with a continuation. It is low level: the module drives the connection's end itself.
- **The core request API** (see `http_request.h`) has wait contexts for the client, other
  connections, descriptors, timers and notifiers; several pending waits per request; body reads;
  asynchronous subrequests; and filters holding output. The core handles the request's end. Request
  modules should use this layer: it checks the filters before waiting, picks the timeouts, keeps
  descriptors registered across waits, and orders the end of the request.

mod_proxy has helpers of its own on top of the core's ([section 5](#5-mod_proxys-helpers)).

## Terms

Request processing:

- **phase**: a step of a request's processing that runs the hooks registered for it, e.g.
  translate_name (mapping the URL), check_user_id and auth_checker (authentication and
  authorization), fixups, and the handlers (the response).
- **hook**: a function that a module registers for a phase (`ap_hook_handler()`,
  `ap_hook_check_user_id()`, ...) and that the core calls with the request, returning `OK`,
  `DECLINED`, an error status, or `SUSPENDED` where the phase can suspend
  ([4.1](#41-can-the-request-suspend)). For now the handlers and the quick_handler can suspend (a
  quick_handler's continuation can only finish its request); the hooks before the handler are
  planned to ([8.1](#81-resumable-request-phases)).
- **handler**: a hook of the handler phase, which makes the response.

What a request waits on, in the MPM:

- **pollset**: the MPM's set of descriptors that it watches for readiness, through APR's poll API
  (epoll, kqueue, event ports, poll, ...). A suspended connection's descriptors sit there, instead
  of a thread blocking on them; a few threads watch the whole set.
- **descriptor**: a socket or a pipe given to the pollset, with the events wanted: readable,
  writable, or the peer closing.
- **timer**: a deadline that the MPM keeps in its timeout queues. It holds no thread and no OS
  timer: when the deadline passes, the wait it belongs to completes (as a timeout, or as the timer's
  own readiness when a delay is what is waited for).
- **notifier**: an object that another thread signals to complete a wait, e.g. the thread that frees
  a backend connection. It lives in the process, can serve a new wait once re-armed, and can be
  attached to a **parent** notifier, so that one wait can stand for many notifiers
  ([2.4](#24-notifiers)).
- **kept descriptor**: a descriptor left in the pollset across the waits of a connection, to save
  the system calls of adding and removing it each time; **drained**: the caller's hint that its last
  read or write on a descriptor got `EAGAIN` ([2.5](#25-kept-descriptors)).

The waits, at two levels:

- **MPM wait**: what a connection registers with the MPM (`ap_mpm_register_wait()`): some
  descriptors, a timeout and at most one notifier, with one continuation. A connection has one MPM
  wait at a time, armed once no thread processes the connection anymore.
- **request wait**: what a module starts with `ap_request_wait()` (or `_any()`): a wait for one or
  more wait contexts, with its own continuation.
- **continuation**: the function called on a worker thread when a wait (either kind) completes, with
  why it completed (ready, timed out, notified, or failed). It goes on with the connection or the
  request, and may wait again.
- **wait context (waitctx)**: a reusable object that names one thing a request can wait on: the
  client, another connection, a descriptor, a timer or a notifier. Made from a pool that the module
  chooses, it carries the target's timeout and, after a wait, which directions were ready
  ([4.2](#42-wait-contexts)).
- **wait set (waitset)**: all the pending waits of a request and of its asynchronous subrequests. At
  the end of each run the core registers the whole wait set as the connection's single MPM wait, and
  when that completes it calls the continuations of the request waits that completed
  ([2.1](#21-suspending), [2.3](#23-completion-and-resumption)).
- **pending wait**: a request wait that hasn't completed yet, one of the wait set. A request can
  have several pending waits at once (a tunnel's two directions and a notifier, say).
- **suspended / run**: a request is suspended while it has pending waits and no thread; a run is the
  time a worker thread spends on it, from the start of its processing or from a continuation
  ([2.1](#21-suspending)).
- **hold, pace, delegate**: what an output filter can do with its output: hold it until a wait
  completes, pace it until a given time, or delegate its hold to a subrequest that it runs
  asynchronously. The request's end waits for every hold
  ([2.7](#27-holds-of-output-and-the-requests-end)).

Below, "MPM wait" and "request wait" say which level is meant; a bare "wait" is used where both
behave the same.

## 2. How it works

### 2.1 Suspending

A hook that has to wait (a handler, for now) asks the core to wait for a target (the client, a
backend, a timer, ...; [4.3](#43-waiting)). If the target is ready already, the call says so and the
hook goes on. Otherwise the core records a pending wait for the request and answers `SUSPENDED`. The
hook returns `SUSPENDED`, and so does every caller up to the core, which remembers where the handler
chain stopped ([4.4](#44-ending-or-resuming-a-suspended-request)).

The request's processing is cut into runs. A run is the time a thread spends on the request: the
first run lasts until the hook returns, and every continuation is another run. At the end of a run,
the core gives all the pending waits of the request (and of its subrequests) to the MPM as **one MPM
wait** for the connection: the union of their descriptors, the smallest of their timeouts, and one
notifier standing for all their notifiers ([2.4](#24-notifiers)). The MPM arms it only once no
thread processes the connection anymore. So a continuation never runs while the code that made its
request wait is still on the stack.

### 2.2 Who holds what while a request waits

- **The MPM** holds the suspended connection and its armed MPM wait: descriptors in its pollset, a
  timer, a notifier. It may also keep some descriptors registered across waits
  ([2.5](#25-kept-descriptors)).
- **The request** holds its wait set: its wait contexts and the list of its pending waits, in the
  order they were made, each with its targets, timeout and continuation. All of it lives in the
  request's pool and is reused, so nothing is allocated per wait.
- **The module** holds its own state and whatever it waits on: a backend connection, a pipe, a
  thread that will notify.
- **The worker running the request** (an MPM worker; for an HTTP/2 stream, one of mod_http2's) runs
  it alone: consecutive runs through the core's waits never overlap, since the MPM arms a wait only
  once the run has ended, and debug builds assert it. Code outside a run, such as a module's own
  thread, doesn't touch the request; it only notifies.

### 2.3 Completion and resumption

When the MPM wait completes (a descriptor ready, a timeout, a notification, or a failure), a worker
starts a new run of the request and looks at each pending wait. A request wait completes when one of
its own targets is ready, or when its own timeout is reached. The continuations of the completed
request waits are called one at a time, in the order they were made. The others stay pending, and
their timeouts keep counting from when they were first armed.

A continuation does one of three things:

- it **waits again** and returns, and the request stays suspended;
- it **continues the request** until the request ends: it resumes the handler chain as if the
  suspended handler had returned some status, and with `DECLINED` the next handlers run and may
  suspend in turn; or it finishes the request with a status at once
  ([4.4](#44-ending-or-resuming-a-suspended-request));
- for an asynchronous subrequest, it **ends the subrequest**, and the caller's completion function
  then goes on with the main request ([4.6](#46-asynchronous-subrequests)).

Ending a request drops its remaining pending waits, and their continuations aren't called. A run
that leaves no pending wait and doesn't end the request abandons it, and the MPM closes the
connection. Whatever is still pending at the end of a run goes back to the MPM as one MPM wait.

When the handlers are done, the core ends the request in order. It waits for the filters that hold
output ([2.7](#27-holds-of-output-and-the-requests-end)), answers an error status if any, waits for
holds of that response too, then gives the connection back to the MPM for write completion or
lingering close.

### 2.4 Notifiers

A notifier lets another thread complete a wait. The waiting side creates the notifier and waits on
it, either directly in an MPM wait or through a notifier wait context ([4.2](#42-wait-contexts)) in
a request wait. The other thread keeps a pointer to it and calls `ap_mpm_notify()` when its work is
done. For example, mod_proxy: a request that finds a backend's connection pool exhausted waits on a
notifier, and the thread that later returns a connection to the pool notifies it.

Timing doesn't matter. If the notification comes before the MPM has armed the wait, for instance
while the request's thread is still returning `SUSPENDED`, it is remembered, and the wait completes
as soon as it's armed. Nothing is lost in between.

A notifier completes one wait. To wait on it again, the waiting side re-arms it
(`ap_mpm_notifier_rearm()`) after that wait has completed. Re-arming also discards any notification
that arrived after the previous wait completed, so a stale notification can't complete the next wait
by mistake.

The MPM takes one notifier per MPM wait. To wait on several notifiers at once, a notifier can be
attached to a parent: notifying it notifies the parent, and the wait is given the parent. The core
does this for the request's notifier wait contexts, so a request can wait on any number of them.

### 2.5 Kept descriptors

Adding a descriptor to the pollset for each wait and removing it afterwards costs system calls on
every wait. A descriptor can instead be **kept** registered across the MPM waits of a connection. A
readiness that comes while no wait is on it is remembered. The owner must release a kept descriptor
before closing it or handing it to another connection.

The caller can also say that it **drained** the descriptor: its last read or write got `EAGAIN`.
Then the MPM doesn't need to check for a readiness that the caller would already have consumed. The
core's wait contexts ([4.2](#42-wait-contexts)) keep descriptors that are waited on repeatedly, and
release them with the wait context.

### 2.6 Timeouts

Every request wait has a timeout, or none. By default, the core uses the time left to read for the
client's input (`Timeout`, or less with mod_reqtimeout), and the server's `Timeout` for the client's
output and for other targets. A timer waits for its delay. A notifier has no timeout by default, but
holds of output are always bounded. An asynchronous subrequest can have a deadline that caps all its
waits ([4.6](#46-asynchronous-subrequests)).

Modules can declare the fixed timeouts they use, at configuration time. event then keeps one queue
per value instead of a timer per wait. Declaring is never required.

### 2.7 Holds of output and the request's end

A request output filter can **hold** its output until a wait completes: a service to consult, a
notification from another thread, or room downstream. The filter returns as if it had passed its
data. The producer upstream sees pending output and backs off, and the core calls the filter again
when the wait is over. A filter can also **pace** its output until a time, or **delegate** its hold
to a subrequest that it runs asynchronously ([4.7](#47-filters-holding-pacing-delegating)).

Holds are allowed while the handlers run and at the request's end: before the error response, if
any, and after it. The end of the request never overtakes held output, so the request's pool, where
the held data and the filter's state live, stays until that output is passed. Every hold is bounded,
by its wait's timeout or else by `Timeout`.

### 2.8 mpm_event's threads, as far as a module sees them

- **Idle workers** poll the connections and the waits themselves (`AsyncWorkerPollers`). A
  continuation runs on whichever worker takes the event, so the runs of one request may be on
  different threads.
- **With `MaxRequestWorkers auto`**, the workers grow from `ThreadsPerChild` up to `ThreadLimit`
  when they all look busy or blocked and connections wait, and the extra workers retire slowly once
  idle. A suspended request holds no worker and never counts as demand. A module that blocks holds a
  worker, and the MPM can only infer that from CPU usage (see [8.2](#82-blocking-sections)).
- **At a graceful stop**, suspended requests finish normally, bounded by their timeouts. An
  immediate stop doesn't call their continuations or destroy their pools in a forked child: the
  child is exiting, and the pools go with the process.

## 3. The MPM API

Use this layer for connection-level code, or when the core's request layer doesn't fit. See
`ap_mpm.h`.

- **What the MPM can do:** `ap_mpm_query()` with `AP_MPMQ_CAN_REGISTER_WAIT` (waits and notifiers
  available) and `AP_MPMQ_MAX_CONNECTIONS` (how many connections a child serves at once, suspended
  ones included: a sizing hint, e.g. for a connection pool). `ap_request_can_suspend()` already
  includes these checks for request modules ([4.1](#41-can-the-request-suspend)).
- **Waiting:** `ap_mpm_register_wait()` suspends the connection until one of some descriptors is
  ready, a notifier is notified, or a timeout expires, whichever comes first. Each descriptor can be
  flagged `AP_MPM_WAIT_KEEP_PFDS` or `AP_MPM_WAIT_DRAINED` ([2.5](#25-kept-descriptors)). Call it
  from a handler, which then returns `SUSPENDED`, or from the previous wait's continuation. A
  connection has one MPM wait at a time.
- **The continuation** (`ap_mpm_continuation_fn_t`) learns why the wait completed
  (`ap_mpm_wait_result_e`: ready, timeout, notified, or the MPM failed). It then either registers
  another wait, or gives the connection back with `ap_mpm_resume_suspended()`. After either, it
  doesn't touch the connection or the request. For a request processed by the core,
  `ap_request_finish_suspended()` or `ap_request_resume_suspended()` take care of the giving back
  ([4.4](#44-ending-or-resuming-a-suspended-request)).
- **Releasing kept descriptors:** `ap_mpm_release_pfd()` / `ap_mpm_release_pfds()`, before closing
  the descriptor or letting another connection use it.
- **Notifiers:** `ap_mpm_notifier_create()`, `ap_mpm_notify()` (from any thread),
  `ap_mpm_notifier_rearm()`, `ap_mpm_notifier_attach()` / `ap_mpm_notifier_detach()` (parents), and
  `ap_mpm_notifier_notified()` to see which attached ones fired.
- **Timeouts:** `ap_mpm_register_timeouts()` at post-config, with the configured values only.
- **A delay alone:** the MPM has no timed callbacks. A request waits on a timer wait context
  ([4.2](#42-wait-contexts)), connection-level code registers a wait with only a timeout.

Rules:

- The continuation runs on a worker thread, never inline and never at the same time as the code that
  registered the wait. Only `ap_mpm_notify()` may be called from other threads.
- The pools given for a wait or a notifier must outlive it.
- A thread that may notify after the request is gone needs a guard: notify and withdraw the reason
  to notify under the same lock, with a pool cleanup on the request's side.
- A continuation holds a worker, so it shouldn't block for long.
- Keep nothing outside the connection's or the request's pools that only a continuation would free.
  Use pool cleanups instead: continuations aren't called when a connection is killed.

## 4. The core request API

### 4.1 Can the request suspend?

`ap_request_can_suspend(r)` is true when all of these hold:

- the MPM can wait;
- the request is a top-level one, or a subrequest run by `ap_run_sub_req_async()`;
- the request isn't internally redirected and isn't an HTTP/2 stream;
- it is in a phase that can suspend (for now, the handlers and the quick_handler;
  [8.1](#81-resumable-request-phases));
- `AsyncRequests` isn't `Off` for it.

The waiting calls check this themselves and refuse when it's false, so a module needs it only to
choose its path up front.

### 4.2 Wait contexts

A wait context (`ap_request_waitctx_t`) names what the request waits for. There is one constructor
per kind of target:

- `ap_request_waitctx_client()`: the client connection. There is one per request, shared by all
  modules, so set its fields before each wait;
- `ap_request_waitctx_conn()`: another connection, e.g. a backend, whose filters are checked like
  the client's;
- `ap_request_waitctx_pfd()`: a socket or pipe that the module reads or writes directly;
- `ap_request_waitctx_timer()`: a delay;
- `ap_request_waitctx_notifier()`: a notifier.

The module sets the wait context's `timeout` (the default is resolved per wait, [2.6](#26-timeouts))
and optionally a `delay`: a short synchronous poll before suspending, for a readiness expected soon.
`ap_request_waitctx_ready()` tells, after a wait, which directions were found ready.
`ap_request_waitctx_release()` gives the target up. Release before closing the descriptor or lending
the connection to another request.

A wait context is allocated from a pool that the module chooses. That pool must outlive the waits
and must not outlive the request: use `r->pool`, or a subpool with the target's life (e.g. one per
backend connection). A notifier's wait context serves one wait unless the module re-arms the
notifier ([2.4](#24-notifiers)); the core never re-arms on its own.

### 4.3 Waiting

`ap_request_wait()` waits for one wait context in a direction (`AP_WAIT_IN`, `AP_WAIT_OUT`).
`ap_request_wait_any()` waits for several, and the first that is ready completes the wait. Pass
`AP_REQUEST_WAIT_DRAINED` when the read or write got `EAGAIN` since the last wait
([2.5](#25-kept-descriptors)). The answer tells the module what to do:

- `SUSPENDED`: return `SUSPENDED` up. The continuation (`ap_request_continuation_fn`) will be called
  later ([2.3](#23-completion-and-resumption)), with `APR_SUCCESS`, `APR_TIMEUP` or a failure;
- `OK`: the target is ready now, so go on;
- `DECLINED`: the request can't wait asynchronously, so go on blocking.

For a connection, "ready" accounts for its filters: input already pending counts as readable, and
output still pending means not writable. A request may have several waits pending at once, e.g. both
directions of a tunnel and a notifier. Each one completes on its own. A wait context is in one
pending wait at a time. `ap_request_wait_cancel()` withdraws a pending wait, e.g. to wait for the
same target differently.

### 4.4 Ending or resuming a suspended request

From the continuation of its last wait, a module does one of these:

- `ap_request_resume_suspended(r, status)`: continue as if the suspended handler had returned
  `status`. With `DECLINED`, the next handlers run;
- `ap_request_finish_suspended(r, status)`: end the request with `status` now.

Call one of them **once per suspension**, and **never on the path that returns to the handler** (a
premature resume is refused and logged). Don't touch `r` afterwards.

### 4.5 The request body

- `ap_request_read_body()` reads without blocking when the request can suspend, and answers `AGAIN`
  when there is nothing to read yet. It also answers a pending `100-continue` without blocking.
- `ap_request_wait_body()` waits for more of the body. Its continuation simply reads again: that
  read reports a timeout or a failure as an HTTP error.
- `ap_request_body_run()` is that loop, feeding each read to a sink.
- `ap_request_discard_body()` drops the rest of the body without blocking, or tells the caller that
  closing the connection is better.
- A caller that can't return `SUSPENDED`, such as a filter, passes `AP_REQUEST_BODY_BLOCK` to read
  blocking.

### 4.6 Asynchronous subrequests

`ap_run_sub_req_async()` runs a subrequest that may suspend, e.g. a proxied URL. If it answers
`SUSPENDED`, the caller returns `SUSPENDED` up, and the completion function (`ap_sub_req_done_fn`)
runs when the subrequest is done. That function reads the subrequest's outcome, destroys it, and
goes on with the main request. Otherwise the subrequest completed at once, with its status.

- It never refuses: when the subrequest can't run asynchronously, it runs blocking.
- A timeout bounds the subrequest's waits ([2.6](#26-timeouts)).
- Call it from a handler or a continuation of the main request, or from a filter that delegated its
  hold to the subrequest ([4.7](#47-filters-holding-pacing-delegating)). Several subrequests may run
  at once. Keeping their output in order is the caller's job, e.g. by capturing it.

### 4.7 Filters: holding, pacing, delegating

- `ap_filter_pending_wait()` lets a request output filter hold its output
  ([2.7](#27-holds-of-output-and-the-requests-end)) until a wait context's wait completes, or until
  there is room downstream. The core calls the filter again afterwards, and the filter passes its
  data or holds again. `ap_filter_pending_notify()` is the same with a notifier
  ([2.4](#24-notifiers)). When a hold is refused, the filter does its work blocking.
- A request input filter can hold its input the same way, while the handlers read without blocking.
  Their waits for the client wait for the hold too.
- `ap_filter_pending_until()` paces output until a time, so a rate limit doesn't sleep between
  chunks (mod_ratelimit uses it).
- With `AP_FILTER_HOLD_DELEGATED`, the filter holds while a subrequest that it starts **next, in the
  same call** runs (`ap_run_sub_req_async()`). The subrequest's completion function only records the
  outcome, and then the core calls the filter again. mod_include's `include virtual` works this way.
- A `FLUSH` bucket keeps its meaning: the filter does its work and passes on, blocking.
- Code that holds something other than filter output (e.g. a tunnel's direction) delegates with
  `ap_request_hold_delegate()` and an `ap_request_holder_t`, and can withdraw with
  `ap_request_hold_withdraw()`.

### 4.8 Other pieces

- `ap_check_input_pending()` and `ap_check_output_pending()` tell whether data is pending in a
  connection's filters. Their `AGAIN` means opposite things: input can be read now, while output
  must be waited for.
- `ap_filter_pending_more()` lets an input filter say that what it keeps needs more input before it
  can be read (e.g. a partial TLS record).
- `ap_send_interim_response_ex()` with `AP_SEND_INTERIM_NONBLOCK` sends a 1xx response without
  blocking. Get it written before waiting for the client, which may be waiting for it.
- Request heads are read without blocking: `ap_read_request_ex()` keeps a partial head in the
  connection state (`partial_request`) across `EAGAIN`, and the connection waits without a thread.
  After that wait times out (`timed_out`), the process_connection hooks get one last pass to answer
  it. The HTTP/1 head parser (`ap_h1_head_parse()`) is available to modules for clients and
  backends.
- Configuration: `AsyncRequests On|Off` (on by default) turns suspension on or off per directory,
  which is handy to compare behaviours. `AsyncFilter` must stay at `request` (the default) for
  request filters to hold.

## 5. mod_proxy's helpers

See `mod_proxy.h`.

- `ap_proxy_wait()` waits for the client or a backend in a direction, with a short synchronous poll
  first (`ProxyAsyncDelay`; `-1` keeps mod_proxy synchronous). `ap_proxy_request_can_suspend()`
  tells whether that is possible.
- `ap_proxy_handler_done()` ends a scheme handler that suspended. mod_proxy continues as if the
  handler had returned the given status, with balancer failover, then the request ends or the next
  handlers run.
- `ap_proxy_acquire_connection_async()` waits for a connection of an exhausted pool on a notifier
  ([2.4](#24-notifiers)), then runs the scheme handler again.
- `ap_proxy_connect_backend_ex()` and `ap_proxy_spool_input_ex()` connect and spool the request body
  without blocking.
- `ap_proxy_tunnel_run_ex()` runs a tunnel asynchronously. A `tunnel_forward` hook can hold one
  direction with `ap_proxy_tunnel_hold()` ([4.7](#47-filters-holding-pacing-delegating)), e.g. to
  have each message checked.
- `ProxyAsyncIdleTimeout` sets the idle timeout of the asynchronous waits.

## 6. Usage rules

**Return codes.**
- Propagate `SUSPENDED` unchanged up to the hook's return. It isn't an error. Don't return it from a
  hook that can't suspend ([4.1](#41-can-the-request-suspend); for now, anything but a handler or
  the quick_handler).
- Continuations are never called inline, and only after `SUSPENDED` was returned.
- Each continuation run ([2.3](#23-completion-and-resumption)) does exactly one of these: resume,
  finish, or wait again. After that, it doesn't touch `r`.

**Pools.**
- Keep per-request state in `r->pool`, made once (e.g. hung on the module's request config or a
  filter's context), never on the handler's stack.
- Allocations made per iteration of a loop that waits (per chunk, per message, per wait) go in a
  subpool cleared at the end of each iteration, so a long request or tunnel doesn't grow without
  bound. Wait contexts take a pool for the same reason.
- Wait contexts and notifiers outlive their waits and don't outlive the request.

**Threads.**
- Continuations and completion functions run on worker threads, possibly a different one each time,
  one at a time per request. Thread-local state doesn't carry over.
- Only `ap_mpm_notify()` may be called from outside the request's runs. A module thread that may
  notify after the request is gone must be stopped or unregistered by a cleanup of the request's
  pool.
- A continuation holds a worker, so it shouldn't block for long. Blocking is fine on the fallback
  path, where the API declined.

**Portability.**
- Use APR only (polling, sockets, pipes, threads): no platform-specific calls in modules.
- Always keep the blocking fallback. The module must also work with prefork and worker, on HTTP/2
  streams, and with `AsyncRequests Off`.

**Descriptors.**
- Release a wait context before closing its descriptor or lending its connection to another request.
- Read or write until `EAGAIN` before waiting, and say so with the drained flag.

**Never.**
- Never resume or finish a request on the path that returns to the handler.
- Never keep `r`, or anything in its pool, after the request's end.
- Never rely on a continuation or completion function to free memory outside the request's pools.
- Never run an asynchronous subrequest from a filter without a delegated hold.

**Logging.** Use the macros, not the `_`-suffixed functions, so that the waits' log lines follow the
module's log level. Log routine waits at trace levels. A refused wait is a normal fallback, so it's
a debug line at most.

## 7. Examples

These are trimmed to the API calls, error handling left out. They come from the tree's own users:
mod_aptest (the test module), mod_proxy_http, mod_include and mod_ratelimit.

### 7.1 A handler waiting on a timer

See [4.2](#42-wait-contexts), [4.3](#43-waiting), [4.4](#44-ending-or-resuming-a-suspended-request).

This is the basic shape: wait, return `SUSPENDED`, and finish from the continuation, with a blocking
fallback.

```c
static void timer_done(request_rec *r, apr_status_t status, void *baton)
{
    ap_request_finish_suspended(r, respond(r));
}

static int my_handler(request_rec *r)
{
    ap_request_waitctx_t *ctx = ap_request_waitctx_timer(r, r->pool);
    int rc;

    ctx->timeout = apr_time_from_msec(100);
    rc = ap_request_wait(ctx, AP_WAIT_IN, 0, timer_done, NULL);
    if (rc == SUSPENDED) {
        return SUSPENDED;
    }
    if (rc == DECLINED) {
        apr_sleep(ctx->timeout);        /* can't suspend: block */
    }
    return respond(r);
}
```

### 7.2 Reading the body

See [4.5](#45-the-request-body).

This shows one loop serving both the handler and the continuation.

```c
static int pull(my_ctx_t *m)            /* OK, SUSPENDED or an HTTP error */
{
    for (;;) {
        int rc = ap_request_read_body(m->r, m->bb, AP_IOBUFSIZE, 0);
        if (rc == AGAIN) {
            if (ap_request_wait_body(m->r, pull_done, m) == SUSPENDED) {
                return SUSPENDED;
            }
            continue;                   /* ready, or must block: read again */
        }
        if (rc != OK || consume(m)) {   /* an error, or the end of the body */
            return rc;
        }
    }
}

static void pull_done(request_rec *r, apr_status_t status, void *baton)
{
    int rc = pull(baton);               /* this read reports a timeout */
    if (rc != SUSPENDED) {
        ap_request_finish_suspended(r, respond(baton, rc));
    }
}
```

### 7.3 Waiting for a backend (mod_proxy_http)

See [5](#5-mod_proxys-helpers), [2.5](#25-kept-descriptors).

The scheme handler reads the backend's response and forwards it without blocking, and waits whenever
it can't go on: for the backend to send more, or for the client to take what's pending.

```c
/* OK at the end of the response, SUSPENDED, or an HTTP error */
static int forward_response(proxy_http_req_t *req)
{
    for (;;) {
        /* Nonblocking: OK at the end, AGAIN when it can't go on (setting
         * req->want), or an error
         */
        int rc = read_and_forward(req);
        if (rc != AGAIN) {
            return rc;
        }
        rc = ap_proxy_wait(req->r, req->backend, req->want,  /* AP_PROXY_BACKEND_IN
                                                              * or _CLIENT_OUT */
                           AP_PROXY_WAIT_DRAINED, req->idle_timeout,
                           response_ready, req);
        if (rc == SUSPENDED) {
            return SUSPENDED;               /* the handler returns it up */
        }
        req->blocking = (rc == DECLINED);   /* can't suspend: block from now on */
    }
}

static void response_ready(request_rec *r, apr_status_t status, void *baton)
{
    proxy_http_req_t *req = baton;
    int rc = (status == APR_SUCCESS) ? forward_response(req) : HTTP_GATEWAY_TIME_OUT;

    if (rc != SUSPENDED) {
        release_backend(req);
        ap_proxy_handler_done(r, rc);       /* as if the handler had returned rc */
    }
}
```

`read_and_forward()` asks for `AP_PROXY_CLIENT_OUT` when `ap_check_output_pending()` answers `AGAIN`
(the client is slow), and for `AP_PROXY_BACKEND_IN` when the backend has nothing more to read yet.

### 7.4 Notifying from another thread

See [2.4](#24-notifiers).

A request waiting for a pooled backend connection waits on a notifier, and the thread that releases
a connection hands it over and notifies. The lock the releaser takes is also taken by the request's
pool cleanup, so a request that goes away while queued can't be notified after its pool is gone. A
module's own client of another service, running on its own thread, works the same way.

```c
struct waiter {
    APR_RING_ENTRY(waiter) link;
    conn_pool_t *pool;                      /* its waiters and their lock */
    ap_mpm_notifier_t *notifier;            /* made once, re-armed for each wait */
    ap_request_waitctx_t *ctx;
    backend_conn_t *conn;                   /* handed over by the releaser */
};

/* In the request: no connection free, wait for one (SUSPENDED, or DECLINED to
 * wait blocking)
 */
static int wait_for_conn(request_rec *r, struct waiter *w)
{
    if (!w->notifier) {
        ap_mpm_notifier_create(&w->notifier, r->connection, r->pool);
        w->ctx = ap_request_waitctx_notifier(r, r->pool, w->notifier);
        apr_pool_cleanup_register(r->pool, w, waiter_cleanup, apr_pool_cleanup_null);
    }
    else {
        ap_mpm_notifier_rearm(w->notifier); /* a previous wait done */
    }
    w->ctx->timeout = acquire_timeout;

    apr_thread_mutex_lock(w->pool->lock);
    APR_RING_INSERT_TAIL(&w->pool->waiters, w, waiter, link);
    apr_thread_mutex_unlock(w->pool->lock);

    return ap_request_wait(w->ctx, AP_WAIT_IN, 0, conn_acquired, w);
}

static void conn_acquired(request_rec *r, apr_status_t status, void *baton)
{
    struct waiter *w = baton;

    withdraw(w);                            /* unqueue under the lock, if still queued */
    if (!w->conn) {                         /* APR_TIMEUP: none freed in time */
        ap_request_finish_suspended(r, HTTP_SERVICE_UNAVAILABLE);
        return;
    }
    ap_request_finish_suspended(r, use_conn(r, w->conn));   /* or wait again */
}

/* The request's pool goes while it's queued: withdraw before anyone notifies */
static apr_status_t waiter_cleanup(void *baton)
{
    withdraw(baton);
    return APR_SUCCESS;
}

/* In another thread, releasing a connection */
static void release_conn(conn_pool_t *pool, backend_conn_t *conn)
{
    apr_thread_mutex_lock(pool->lock);
    if (!APR_RING_EMPTY(&pool->waiters, waiter, link)) {
        struct waiter *w = APR_RING_FIRST(&pool->waiters);
        APR_RING_REMOVE(w, link);
        w->conn = conn;                     /* handed over */
        ap_mpm_notify(w->notifier);         /* under the lock withdraw() takes */
        conn = NULL;
    }
    apr_thread_mutex_unlock(pool->lock);
    if (conn) {
        put_back_idle(pool, conn);
    }
}
```

### 7.5 A filter holding output on a notifier

See [4.7](#47-filters-holding-pacing-delegating), [2.4](#24-notifiers).

A request output filter keeps the response until another thread has checked it (a service to
consult, say), without holding the request's thread meanwhile. The core calls the filter again, with
an empty brigade, once the notifier is notified.

```c
typedef struct {
    apr_bucket_brigade *kept;               /* what it holds */
    ap_mpm_notifier_t *notifier;            /* made once, re-armed for each hold */
    int holding;
} hold_t;

static apr_status_t hold_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    hold_t *h = get_hold(f);                /* f->ctx, made once in r->pool */
    apr_status_t rv;

    if (h->holding) {
        if (!APR_BRIGADE_EMPTY(bb)) {       /* more while held: keep it behind */
            return ap_save_brigade(f, &h->kept, &bb, f->r->pool);
        }
        h->holding = 0;                     /* called again by the core: pass it on */
        APR_BRIGADE_CONCAT(bb, h->kept);
        return ap_pass_brigade(f->next, bb);
    }
    if (!needs_check(bb)) {
        return ap_pass_brigade(f->next, bb);
    }

    ap_save_brigade(f, &h->kept, &bb, f->r->pool);
    rv = h->notifier ? ap_mpm_notifier_rearm(h->notifier)
                     : ap_mpm_notifier_create(&h->notifier, f->c, f->r->pool);
    if (rv == APR_SUCCESS
        && ap_filter_pending_notify(f, NULL, h->notifier) == APR_SUCCESS) {
        start_check(h);     /* another thread, ending with ap_mpm_notify(h->notifier);
                             * r->pool's pre-cleanup joins it */
        h->holding = 1;
        return APR_SUCCESS; /* held: the producer sees pending output and backs off */
    }
    check_blocking(h);      /* refused: check here, then pass */
    APR_BRIGADE_CONCAT(bb, h->kept);
    return ap_pass_brigade(f->next, bb);
}
```

### 7.6 A filter running a subrequest (mod_include)

See [4.6](#46-asynchronous-subrequests), [4.7](#47-filters-holding-pacing-delegating).

For an `include virtual`, the filter delegates its hold to the subrequest and keeps the rest of the
page meanwhile. The subrequest's completion function only records its status: the core then calls
the filter again, which picks the result up and goes on with the page.

```c
static apr_status_t include_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    include_ctx_t *ctx = f->ctx;

    if (ctx->state == INCLUDE_DONE) {       /* called again: the subrequest is done */
        ctx->state = INCLUDE_NONE;
        ap_destroy_sub_req(ctx->rr);
        directive_done(ctx, ctx->include_status);
    }
    /* ... parse the page, and at an include virtual: */
    {
        request_rec *rr = ap_sub_req_lookup_uri(url, f->r, f->next);
        int status;

        if (ap_filter_pending_wait(f, NULL, NULL, 0,
                                   AP_FILTER_HOLD_DELEGATED) != APR_SUCCESS) {
            status = ap_run_sub_req(rr);    /* refused: blocking */
        }
        else if ((status = ap_run_sub_req_async(rr, 0, include_done, ctx)) == SUSPENDED) {
            ctx->state = INCLUDE_RUNNING;
            ctx->rr = rr;
            return keep_rest(ctx, bb);      /* the core calls the filter again */
        }
        ap_destroy_sub_req(rr);             /* completed at once */
        directive_done(ctx, status);
    }
    /* ... */
}

static void include_done(request_rec *rr, int status, void *baton)
{
    include_ctx_t *ctx = baton;

    ctx->include_status = status;           /* only record it */
    ctx->state = INCLUDE_DONE;
}
```

### 7.7 Pacing (mod_ratelimit)

See [4.7](#47-filters-holding-pacing-delegating).

```c
rv = ap_filter_pending_until(f, apr_time_now() + interval);
if (rv == APR_SUCCESS) {
    return ap_save_brigade(f, &ctx->holdingbb, &bb, f->r->pool);   /* called again then */
}
/* refused: sleep between chunks, as before */
```

### 7.8 Resuming the handler chain

See [4.4](#44-ending-or-resuming-a-suspended-request), [2.3](#23-completion-and-resumption).

A handler running before the others checks something without holding the thread, then lets the next
handlers run (mod_aptest's suspending handlers do this):

```c
static int check_handler(request_rec *r)
{
    struct check *c;
    ap_request_waitctx_t *ctx;
    int rc;

    if (!wants_check(r)) {
        return DECLINED;
    }
    c = start_check(r);                     /* a request sent to a service, nonblocking */
    ctx = ap_request_waitctx_pfd(r, r->pool, &c->pfd);
    ctx->timeout = check_timeout;
    rc = ap_request_wait(ctx, AP_WAIT_IN, 0, check_done, c);
    if (rc == SUSPENDED) {
        return SUSPENDED;
    }
    /* OK: answered already; DECLINED: can't suspend, wait for it blocking */
    return check_result(c, rc == DECLINED) ? DECLINED : HTTP_SERVICE_UNAVAILABLE;
}

static void check_done(request_rec *r, apr_status_t status, void *baton)
{
    int ok = (status == APR_SUCCESS) && check_result(baton, 0);

    /* DECLINED: the next handlers run, as if check_handler() had returned it */
    ap_request_resume_suspended(r, ok ? DECLINED : HTTP_SERVICE_UNAVAILABLE);
}
```

### 7.9 Seeing them run

The functional checks under `test/async-bench/` run each case twice: blocking (`AsyncRequests Off`,
or `ProxyAsyncDelay -1`) and asynchronously. Both modes must give the same responses, and in the
asynchronous mode no worker may be held.

## 8. Planned (not implemented)

This section describes planned work, **not in the code**. All names in it are proposed.

### 8.1 Resumable request phases

The plan is to let the hooks before the handler (translate_name, token_checker, access_checker,
access_checker_ex, check_user_id, auth_checker, fixups) suspend the way handlers do. A hook makes a
wait and returns `SUSPENDED`, and its continuation resumes with the hook's result
(`ap_request_resume_suspended()`). The core resumes the phases from where they stopped, with the
same order and the same `Satisfy` logic, without re-running the walks. `SUSPENDED` from a phase that
can't suspend would be refused (a 500). Subrequest lookups and internal redirects stay synchronous.
The users would be mod_ssl's renegotiation, mod_authnz_fcgi's authorizer and mod_auth_form's body
read.

### 8.2 Blocking sections

Some calls can't easily become nonblocking: LDAP, database drivers, name lookups. Instead, the plan
is to mark them, so that the MPM knows when a worker is blocked:

```c
/* proposed */
ap_mpm_blocking_section_t *ap_mpm_blocking_section(apr_pool_t *p,
                                                   const char *name); /* "ldap" */
apr_status_t ap_mpm_blocking_enter(ap_mpm_blocking_section_t *section,
                                   unsigned int flags, request_rec *r,
                                   ap_request_waitctx_t **waitctx);
void ap_mpm_blocking_leave(ap_mpm_blocking_section_t *section);
```

- **What the MPM does with the marks.** event counts the marked workers. It starts a worker as soon
  as none is idle, connections wait, and too few unmarked workers are left, without waiting to infer
  blocking from CPU usage. Other MPMs ignore the marks.
- **Growth stays smooth.** Marks never start or stop a thread themselves: they only update a count.
  Growth stays demand-driven (at most one new worker per admission target), and retirement stays
  slow, so a worker started for one blocking call also serves the next ones. Still to decide: a
  grace period before a mark counts, a moving average of the count, and a cap on growth below
  `ThreadLimit`.
- **First marked calls:** `ap_get_remote_host()`'s lookups and util_ldap, and possibly mod_dbd.
- **A per-name limit with a queue (optional).** A module gets a handle once at startup
  (`ap_mpm_blocking_section()`, proposed) for a name, e.g. its provider's. A configured limit bounds
  the calls in progress for that name. At the limit, a caller passing `AP_MPM_BLOCKING_CAN_WAIT`
  gets a wait context and waits the usual way, holding no thread. When a call leaves, its slot goes
  to the next waiter in order. A request dropped while queued gives its place up through a pool
  cleanup. Limits are per child.
- **Growth with the queue.** Workers grown for marked calls are then bounded by the sum of the
  limits, and queued requests don't count as demand. For example, 1000 requests queued behind a
  limit of 16 need about 16 extra workers, with no thread started or retired per request. The first
  user would be mod_auth_basic around its provider call.

Running blocking calls on a separate thread pool, with another thread owning the request meanwhile,
is not planned. Blocking sections give the same thread counts without that.

## Appendix: the functions by purpose

The headers' doxygen is the authority for parameters and return values.

| Purpose | Functions (header) |
|---|---|
| MPM capabilities | `ap_mpm_query()` with `AP_MPMQ_CAN_REGISTER_WAIT`, `AP_MPMQ_MAX_CONNECTIONS` (ap_mpm.h) |
| MPM waits | `ap_mpm_register_wait()`, `ap_mpm_continuation_fn_t`, `ap_mpm_wait_result_e`, `AP_MPM_WAIT_KEEP_PFDS`, `AP_MPM_WAIT_DRAINED`, `ap_mpm_release_pfd()`, `ap_mpm_release_pfds()`, `ap_mpm_resume_suspended()`, `ap_mpm_register_timeouts()` (ap_mpm.h) |
| Notifiers | `ap_mpm_notifier_create()`, `ap_mpm_notify()`, `ap_mpm_notifier_rearm()`, `ap_mpm_notifier_attach()`, `ap_mpm_notifier_detach()`, `ap_mpm_notifier_notified()` (ap_mpm.h) |
| Suspension | `ap_request_can_suspend()`, `ap_request_resume_suspended()`, `ap_request_finish_suspended()` (http_request.h) |
| Wait contexts | `ap_request_waitctx_client()`, `_conn()`, `_pfd()`, `_timer()`, `_notifier()`, `ap_request_waitctx_release()`, `ap_request_waitctx_ready()`, `AP_REQUEST_WAITCTX_TIMEOUT_DEFAULT` (http_request.h) |
| Request waits | `ap_request_wait()`, `ap_request_wait_any()`, `ap_request_wait_cancel()`, `ap_request_continuation_fn`, `AP_WAIT_IN`, `AP_WAIT_OUT`, `AP_REQUEST_WAIT_DRAINED` (http_request.h) |
| Body | `ap_request_read_body()`, `ap_request_wait_body()`, `ap_request_body_run()`, `ap_request_discard_body()`, `AP_REQUEST_BODY_SETASIDE`, `AP_REQUEST_BODY_BLOCK` (http_request.h) |
| Subrequests | `ap_run_sub_req_async()`, `ap_sub_req_done_fn` (http_request.h) |
| Holds | `ap_filter_pending_wait()`, `ap_filter_pending_notify()`, `ap_filter_pending_until()`, `AP_FILTER_HOLD_DELEGATED`, `ap_request_hold_delegate()`, `ap_request_hold_withdraw()`, `ap_request_holder_t` (http_request.h) |
| Pending data | `ap_check_input_pending()`, `ap_check_output_pending()`, `ap_filter_pending_more()`, `ap_filter_should_yield()` (util_filter.h) |
| Protocol | `ap_read_request_ex()`, `ap_send_interim_response_ex()`, `AP_SEND_INTERIM_NONBLOCK`, `ap_h1_head_parser_create()`, `ap_h1_head_parse()` (http_protocol.h); `conn_state_t`'s `partial_request` and `timed_out` (httpd.h) |
| mod_proxy | `ap_proxy_request_can_suspend()`, `ap_proxy_wait()`, `AP_PROXY_WAIT_DRAINED`, `ap_proxy_handler_done()`, `ap_proxy_acquire_connection_async()`, `ap_proxy_connect_backend_ex()`, `ap_proxy_spool_input_ex()`, `ap_proxy_tunnel_run_ex()`, `ap_proxy_tunnel_hold()` (mod_proxy.h) |
| Directives | `AsyncRequests`, `AsyncFilter` (core); `AsyncWorkerPollers`, `MaxRequestWorkers auto`, `ThreadsPerChild`, `ThreadLimit` (event); `ProxyAsyncDelay`, `ProxyAsyncIdleTimeout` (mod_proxy) |
