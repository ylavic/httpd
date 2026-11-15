# mpm_event: how it works

This document is for people working on the event MPM, and for reviewers of its changes. It describes
the design as it is now: the concepts, the threads and how the parts fit together. It is not a
reference of every function: the comments in the code are, and this document gives the names that
help to find them. For the side that modules see (waits, continuations, notifiers, the core's
request API), see [README.async.md](../../../README.async.md) at the top of the tree.

## 1. Purpose and scope

The worker and prefork MPMs give each connection a thread (or a process) for its whole life,
including while it only waits: for the client's next request, for the client to read the response,
for a backend, for a timer. event keeps the connections that wait **without a thread**. A thread
runs a connection only while there is work to do, then gives it back to the MPM, which watches its
socket and its timeout until the next piece of work. A request can also be **suspended**: its
handler returns `SUSPENDED` after registering a wait, and a thread comes back to it only when the
wait completes.

So a child holds many more connections than it has threads. What bounds the connections is memory
and file descriptors, not threads, and what bounds the work in progress is the threads.

The process model, in a few lines:

- The **parent** process forks the children and keeps their number right ([section
  8](#8-stops-and-maintenance)). It never serves connections.
- Each **child** has a fixed set of listening sockets (its bucket's, [section
  8](#8-stops-and-maintenance)), one **listener** thread, and **worker** threads: `ThreadsPerChild`
  of them, more with `MaxRequestWorkers auto` ([section 7](#7-threads)). A start thread creates
  them, and the child's main thread waits for the parent's orders on the pipe of death.
- The listener accepts new connections, keeps the timers and the timeouts, completes the waits that
  time out or are notified, and decides whether the child accepts more ([section
  6](#6-admission-and-the-backlog)).
- The workers run the connections. By default the idle workers also poll the connections and the
  waits themselves ([section 4](#4-polling)).

## 2. Terms

Threads and their roles:

- **listener**: the child's thread that polls the listening sockets and the wakeups of its pollset
  (`event_pollset`), and runs the timers and timeout queues. Without worker polling it polls the
  connections too.
- **worker**: a thread that runs connections and continuations. A worker is either
  busy or **idle** (waiting for work); the count of idle workers is the **idlers**.
- **poller**: an idle worker that polls the connections' pollset (`conn_pollset`) itself. At most
  `AsyncWorkerPollers` of them poll at once; the other idle workers <a id="park"></a>**park** on the
  workers' queue.
- **doorbell**: a pipe in the connections' pollset that wakes one blocked poller when something is
  queued for the workers.
- **worker slot**: what each worker publishes for the other threads (`struct worker_slot`): the
  socket it runs, its drain epoch, and whether it retired.
- **base and extra workers**: the `ThreadsPerChild` workers that live as long as the child, and the
  workers grown above them up to `ThreadLimit` with `MaxRequestWorkers auto` (**elastic workers**),
  which retire when idle.

Queues:

- **timeout queue**: a list of connections (or waits) that share one timeout value, appended at the
  tail, so it stays sorted by expiry and only its head needs looking at. The connections' queues are
  per state: I/O wait, write completion, keep-alive, shutdown, lingering close, and the backlog.
- **timer**: an entry of the timers' skiplist, sorted by expiry, for timeouts that no queue holds (a
  value that varies per connection, a wait's undeclared timeout).
- **workers' queue** (`worker_queue`): what waits for a worker: connections and timers, in **lanes**
  by class (new connections, keep-alive, I/O wait, write completion, lingering close, continuations,
  timers), popped by weighted round-robin.
- **backlog**: everything in the workers' queue. Its connections are also in a timeout queue of
  their own (`backlog_q`), so that they are counted and the lingering ones time out.

Accepting:

- **admission**: the rule that decides when the child stops accepting new connections: when they
  wait for a worker longer than a target for too long, or when too many wait.
- **sojourn**: how long an entry of the workers' queue waited there for a worker.
- **fair share**: in auto mode, the share of the connections above which a busy child leaves new
  connections to the other children of its bucket.
- **listener bucket**: a set of children that share duplicated listening sockets (`SO_REUSEPORT`)
  and a pipe of death.

Waits (see [README.async.md](../../../README.async.md) for the module's view):

- **wait**: what a suspended connection waits for: some descriptors, at most one notifier and a
  timeout, the first to fire completing it. The MPM keeps one wait per connection (`struct
  user_wait`), reused by all its waits.
- **pending wait**: a wait registered but not armed yet, because a thread still runs the connection.
- **armed / claimed**: an armed wait can complete; the first thread to claim it (a compare and swap
  on its claim word) completes it, whatever fired.
- **continuation**: the module's function that a worker runs once the wait completed, told why.
- **kept descriptor** (kept pfd): a descriptor left registered in the pollset across the waits of a
  connection, with a small state machine of its own; <a id="drained"></a>**drained**: the caller's
  hint that its last read or write got `EAGAIN`.
- **notifier**: an object that any thread notifies to complete a wait; it can be attached to a
  **parent** notifier, which then stands for all the notifiers attached to it.
- **drain epoch**: a counter that pollers publish while they hold an event, so that the memory an
  event refers to isn't recycled under them.
- **limbo**: the closed connections' pools waiting for the pollers to move past their epoch.

## 3. A connection's life

### 3.1 The states

The connection's state (`conn_state_t`, `c->cs`) says what the MPM does with it when a thread gives
it back. The process_connection hooks set it before they return; the MPM sets it in its own
transitions.

```
            accept
              |
              v
        +------------+   ready    +------------------+
        | PROCESSING | <--------- | ASYNC_WAITIO     |  waits for read/write
        | (a worker) | ---------> | (no thread)      |  (Timeout, or a timer)
        +------------+            +------------------+
          |   |   |  \
          |   |   |   \------------------> SUSPENDED (no thread, a wait, section 5)
          |   |   v                          | resumed (ap_mpm_resume_suspended())
          |   |  WRITE_COMPLETION <----------+
          |   |   | flushes; waits for writable (Timeout)
          |   |   v
          |   |  KEEPALIVE  waits for the next request (KeepAliveTimeout)
          |   |   | readable: back to PROCESSING
          |   v
          |  LINGER: flush, shut down, read until the client closes, close
          v
        error, unexpected state: LINGER
```

- **PROCESSING**: a worker runs the process_connection hooks (`ap_run_process_connection()`):
  reading a request, running it, writing the response. A new connection starts there, and so does a
  connection whose wait for the client is over.
- **ASYNC_WAITIO**: the hooks need the socket readable (or writable, through the connection's sense)
  before they can go on, e.g. a partial request head. The connection waits without a thread for
  `Timeout`, or for the connection's own timeout when it differs (mod_reqtimeout): then a timer
  holds it rather than the I/O wait queue. When it times out, the MPM gives the hooks one last pass
  with `timed_out` set, to answer it (a 408, say), and closes it after.
- **WRITE_COMPLETION**: the response is done but some output is still pending in the filters. The
  MPM flushes it, waiting for the socket to be writable without a thread. Once flushed, a kept-alive
  connection with input pending already goes straight back to PROCESSING, the others go to
  KEEPALIVE, or to LINGER if they aren't kept alive.
- **KEEPALIVE**: waiting for the next request, for `KeepAliveTimeout` (the request's virtual host's
  if it sets one, else the base server's). The hooks may return it; the MPM goes through write
  completion first anyway.
- **SUSPENDED**: a handler (or a filter, through the core's request API) registered a wait and
  returned `SUSPENDED`; the core gives the connection to the MPM in this state ([section
  5](#5-waits)).
- **LINGER**: the connection ends ([section 3.3](#33-the-end-lingering-close)).
- **HANDLER**: set by the protocol modules while the handlers run; the MPM never gets a connection
  back in it.

A connection's sense (`CONN_SENSE_WANT_READ` or `_WRITE`) overrides what the MPM polls for in the
next wait, e.g. TLS that must read to be able to write. It is reset after each use.

The hooks that return `OK` with the state left at PROCESSING (third-party modules not written for
event) get a lingering close, like with worker or prefork. Any other unexpected state or error
closes the connection too.

### 3.2 Who owns the connection when

At any time a connection is in exactly one of these places, and whoever has it is the only one to
touch it:

- **a worker** running it (process_socket()): the hooks, write completion, lingering close or a
  continuation. The worker publishes the socket in its slot meanwhile ([section
  8.2](#82-immediate-stop));
- **the workers' queue**, waiting for a worker (and counted in the backlog queue);
- **the pollset and a timeout queue (or a timer)**, waiting for its socket or its timeout;
- **its wait**, while suspended: the wait's descriptors in the pollset, its timeout and notifier,
  and no thread.

The handovers between the last two and a thread are races by nature: the socket's event and the
timeout's expiry can come at once, on different threads. They are decided by a **claim**:

- a connection waiting for its socket is claimed by removing it from its timeout queue (under the
  queues' mutex) or its timer from the skiplist (under the skiplist's mutex). Whoever removes it
  owns it; the loser drops its event, or skips the entry (`claim_connection()`);
- a wait is claimed by the compare and swap of its claim word from armed to claimed
  (`claim_user_wait()`). The winner completes it, the others drop what they had.

The sockets are registered one-shot ([section 4.4](#44-one-shot-registrations)): once fired, the
kernel won't report it to another thread, so an event and its claim are a single thread's.

### 3.3 The end: lingering close

A connection doesn't just close: the client may still be sending (an early error response while it
uploads), and a reset would lose the response. Lingering close, run by a worker
(process_lingering_close()):

1. runs the pre-close hooks and the connection's shutdown (TLS close notify) once, then flushes
   what's pending, waiting in the shutdown queue for writability (`Timeout`) if needed;
2. shuts the socket down for writing;
3. reads and discards what the client sends, a few reads per pass so that a fast client doesn't hold
   the worker, then waits in the linger queue for the socket to be readable again;
4. closes when the client closes, on an error, after 2 seconds without data, or after 30 seconds in
   all. A connection that timed out, one marked with the "short-lingering-close" note, and every
   connection of a stopping child linger 2 seconds in all.

When the child is out of connections (its limit reached in auto mode, [section
6.2](#62-the-admission)), the lingering connections are closed rather than requeued, and the
listener closes those waiting in the linger queue, at most every half second.

The final close (close_connection()) releases the connection's kept descriptors, takes the socket
back from the worker's slot, closes it, counts the connection out, and recycles its pool (through
the limbo with worker polling, [section 4.5](#45-stale-events-and-the-drain-epochs)). A connection
counts out at its close, not when its pool is recycled, so the limits and the stops see it gone at
once.

### 3.4 Timeouts

The listener expires the timeout queues at their next expiry ([section
4.6](#46-timeout-queues-and-timers)). What an expired connection becomes (shutdown_connection()):

- one in I/O wait: the last pass described above, on a worker;
- one in keep-alive or write completion: a short lingering close, pushed to a worker (the pre-close
  hooks run there);
- one whose flush in the shutdown queue timed out: aborted and pushed to a worker to close, so that
  the cleanups of a request still in flight run on a worker, not on the listener;
- one in the linger queue: closed by the listener.

A new connection waiting in the backlog has no timeout: the admission bounds how many wait, hence
for how long ([section 6](#6-admission-and-the-backlog)). A lingering connection waiting there for a
worker does time out (2 seconds), and the listener closes it.

## 4. Polling

### 4.1 The pollsets

event uses the pollset methods that hold any number of descriptors and can be used by several
threads at once: event ports, kqueue or epoll, the first that works. There are two pollsets:

- `event_pollset`, the listener's: the listening sockets (with `APR_POLLEXCL` where available, so
  that a new connection wakes up one child, not all), and the pollset's wakeup;
- `conn_pollset`, the connections': the connections' sockets, the waits' descriptors, the kept
  descriptors, and the doorbell. The idle workers poll it.

Without worker polling (event built with `AP_EVENT_NO_WORKER_POLL`, an APR without
`apr_pollset_poll_into()` or one-shot support, or the second pollset failing to start), there is one
pollset: `conn_pollset` is `event_pollset`, and the listener polls everything and queues the work
for the workers.

### 4.2 The listener's loop

Each turn, the listener:

1. pops the expired timers and the expired waits of the waits' timeout queues;
2. computes its poll timeout: the earliest of the timers', the waits' queues' and the connections'
   queues' next expiry; at most a second while there are connections (for the stats tick); shorter
   while it doesn't accept ([section 6](#6-admission-and-the-backlog)) or while workers may have to
   grow ([section 7](#7-threads));
3. accepts again if every reason not to is gone;
4. polls, then handles what fired: new connections, and without worker polling the connections and
   the waits;
5. completes the waits that were notified meanwhile, and queues their continuations;
6. checks whether the workers should grow, and recycles the pools whose epoch passed;
7. expires the connections' timeout queues, if their next expiry passed.

Other threads wake the listener up (`wakeup_listener()`) when it must see something before its
timeout: a timer or queue entry that expires before its next expiry (beyond a fudge of 100 ms for
the connections' queues, 5 ms for the timers and waits, so that close timeouts don't cost a wakeup
each), a notified wait, a reason to accept again, a stop.

### 4.3 Workers that poll

With worker polling, the listener only accepts and keeps time; the idle workers poll `conn_pollset`
themselves and run what they get. A connection that becomes readable is run by the worker that
polled it, without the hand-off from the listener through the queue (a futex wake and a context
switch per event).

A poller takes one event per poll (`apr_pollset_poll_into()`), so that what it gets is what it runs.
At most `AsyncWorkerPollers` workers poll at once (by default the CPUs the child can run on, at most
`ThreadsPerChild`), since every poll returning takes the pollset's lock in the kernel. The other
idle workers park on the workers' queue.

An idle worker looks for work in this order (worker_poll_next()):

1. a nonblocking poll of `conn_pollset`, if it has a poll slot;
2. a nonblocking pop of the workers' queue;
3. a blocking poll, for a second at most, if it has a slot; otherwise it parks on the queue.

The worker shares its time between what it polls (mostly keep-alive and I/O wait connections) and
what is queued (mostly new connections) in the same ratio as the queue's lanes weigh them, by time
spent rather than by count, so that the new connections are the ones that wait under load: the
admission measures them.

Two mechanisms keep the polling and the parked workers in step:

- the **doorbell**: the listener queuing work for the workers wakes a parked worker if there is one,
  else rings the doorbell, a one-shot pipe in `conn_pollset` that wakes one blocked poller. The
  woken poller pops the queue first, and rings again if more is queued. A ring pending isn't
  repeated;
- the **promotion**: a poller leaving to run a connection while nobody is blocked in `conn_pollset`
  and workers are parked queues a token (`worker_poll_baton`) for one of them to come and poll. Both
  sides update their counter before they read the other's, so either the parking worker sees a free
  slot or the pollers see it parked.

A blocked poller can't be woken up individually (epoll wakes the threads blocked on it in LIFO
order), so the one second bound on its poll is also what bounds how long it may hold its drain
epoch.

### 4.4 One-shot registrations

The connections' sockets and the waits' descriptors are registered one-shot (`APR_POLLONESHOT`):
once it fires, the kernel disarms the descriptor until it is re-armed. This gives:

- **a single owner per event**: a fired descriptor is reported to one poller only, which then claims
  what it is for ([section 3.2](#32-who-owns-the-connection-when));
- **fewer system calls**: a socket stays registered from its first wait to its close; the next wait
  re-arms it with a single call, and nothing is removed after it fired.

epoll disarms a fired descriptor as a whole. kqueue has a filter per direction, so the other
direction of a descriptor waited on for both stays armed and is removed when the wait completes.

### 4.5 Stale events and the drain epochs

A poller may hold an event for something that another thread completes meanwhile: the wait it is for
timed out, or the connection was closed. Three rules keep that safe:

- **the memory an event points to stays valid**: the client data of every registration (the
  connection's state, its wait, its kept descriptors) lives in the connection's pool, not in the
  pools of the requests or of the modules;
- **events of a previous wait are told apart**: the wait's descriptors are copied into one of two
  arrays, alternated by the waits, with a client data of their own; an event whose client data isn't
  the current wait's is stale and dropped, and a completed wait's copies have their client data
  cleared;
- **a connection's pool isn't recycled while a poller may hold an event for it**: a poller publishes
  the current drain epoch in its slot from its poll until it is done with the event (claimed or
  dropped). A closed connection's pool gets the next epoch, and goes back to the pools' cache only
  once no slot holds an epoch at or before it; meanwhile it waits in the limbo, which the pollers
  and the listener flush. The released kept descriptor records are reused under the same rule.

Without worker polling, only the listener polls, and the pools are recycled at once.

### 4.6 Timeout queues and timers

Each queue has a single timeout value, so appending keeps it sorted and the listener only looks at
the heads. The values that differ per virtual host get one queue each, chained together and counted
together (`TO_QUEUE_CHAIN()`). The queues share a mutex and a next expiry, which an append only
lowers.

A timeout that no queue holds uses a timer in the skiplist instead: a connection whose `Timeout` was
changed for this connection (mod_reqtimeout), a wait whose timeout wasn't declared ([section
5.4](#54-timeouts-of-the-waits)). A timer is recorded by its owner before it's inserted, since the
listener may pop it at once if the owner is preempted. A timer that isn't needed anymore is removed
and recycled at once.

## 5. Waits

This section is the MPM's side of `ap_mpm_register_wait()` and the notifiers. How modules use them,
directly or through the core's request API, is in [README.async.md](../../../README.async.md).

### 5.1 Registration and arming

A wait is registered from a handler (or a filter) of a running request, or from the continuation of
the previous wait (event_register_wait()). Registering only records it as the connection's **pending
wait**: a thread still runs the connection, and the wait must not complete under it. A connection
has one wait at a time; a second registration, or one from another thread while the connection is
suspended, is refused, and so is a wait that nothing could complete.

The wait is **armed** once no thread runs the connection anymore: when the handler has returned
`SUSPENDED` and the connection reaches the MPM in the SUSPENDED state (enter_suspended(), after the
suspend_connection hooks), or when the continuation that registered it returns. Arming
(arm_user_wait()), under the wait's mutex:

1. sets the claim word to armed: from now on anything may complete the wait;
2. arms its timeout, in the timeout queue of its value if it was declared, else as a timer;
3. adds its descriptors to `conn_pollset` (one-shot), or arms the kept ones ([section
   5.5](#55-kept-descriptors));
4. arms its notifier: if it was notified already, the wait is queued for completion at once.

If arming fails, the continuation runs with `AP_MPM_WAIT_ERROR`. A registered wait that the handler
didn't follow with `SUSPENDED` is dropped (logged at debug), and its notifier can be re-armed.

The wait itself (`struct user_wait`) is the connection's, allocated once in its pool and reused by
all its waits, so that an event fired for it stays readable as long as the connection lives,
whatever thread holds it.

### 5.2 Completion

Whatever fires first completes the wait: a descriptor's event (on a poller, or the listener), the
timeout's expiry (the listener), or a notification (the listener, or a polling worker, [section
5.6](#56-notifiers)). Each of them first claims the wait; the winner then:

1. frees its timer or unlinks it from its timeout queue;
2. runs the wait's cleanup (user_wait_cleanup()): it removes the descriptors that didn't fire,
   leaves the kept ones armed and idle, marks the notifier's wait done, and makes the claim word
   idle again for the next wait;
3. records the continuation to run, with why (`AP_MPM_WAIT_READY`, `_TIMEOUT`, `_NOTIFIED`) and the
   events of the descriptors that fired;
4. queues the connection for a worker, in the continuations' lane; a poller that claimed it runs it
   itself.

The cleanup is also registered on the pool given with the wait (normally the request's), so a
connection killed while it waits (its pools destroyed) disarms the wait first.

### 5.3 Continuations

A worker gets the suspended connection like any other (process_socket()): it runs the
resume_connection hooks, then the continuation (run_user_continuation()). The scoreboard shows the
worker busy writing meanwhile. When the continuation returns:

- it registered another wait: the wait is armed now, and the connection stays suspended;
- it gave the connection back (`ap_mpm_resume_suspended()`, which from a continuation only takes
  effect when it returns): the connection leaves the SUSPENDED state and goes on with write
  completion **on the same worker**, rather than being queued for writing, which would bring it
  straight back to a worker since a socket is writable most of the time;
- it did neither: the connection is abandoned, logged as an error, and closed.

`ap_mpm_resume_suspended()` called outside a continuation queues the connection for write
completion at once.

Leaving the SUSPENDED state releases the connection's kept descriptors: the request is done, and the
connection's own socket is the MPM's again.

### 5.4 Timeouts of the waits

Most waits use a few fixed timeouts (the proxy's, the connect's, a pool acquire's). A module can
declare them at post-config (`ap_mpm_register_timeouts()`). The child then creates one timeout queue
per declared value (`wait_tqs`, sorted by value), and a wait with a declared timeout is appended to
its value's queue, in constant time. The other values use a timer in the skiplist, in logarithmic
time and under the timers' mutex; the first time a value falls back to a timer, it is logged at
debug (once per value). The periodic stats count both ([section 7.5](#75-the-periodic-stats)).

The listener expires the waits' queues like the connections' (expire_wait_queues()): it unlinks and
claims the expired entries under the queues' mutex, then completes them with `AP_MPM_WAIT_TIMEOUT`
after releasing it, since the waits' cleanups take other locks. A wait's timeout is never shorter
than 5 ms, so that it can't fire before its descriptors are in the pollset.

### 5.5 Kept descriptors

Adding a descriptor to the pollset for each wait and removing it after costs system calls per wait.
With `AP_MPM_WAIT_KEEP_PFDS`, a descriptor stays registered across the connection's waits, until its
owner releases it (`ap_mpm_release_pfd()`), or the connection is resumed or closed. This needs
worker polling (one-shot registrations). A connection keeps at most 4 descriptors
(`EVENT_KEPT_MAX`); more are waited for as if not kept.

A kept descriptor has a record of its own (`struct kept_pfd`), in the connection's pool, whose state
changes by compare and swap between the events (any thread) and the connection's waits:

- `KEPT_IDLE`: armed, no wait on it;
- `KEPT_WAITED`: a wait is on it, still armed: arming a wait on an idle kept descriptor costs no
  system call;
- `KEPT_FIRED`: it fired for its wait, and the kernel disarmed it;
- `KEPT_READY`: it fired while no wait was on it (or for a wait completed otherwise): the readiness
  is remembered, and the next wait on it completes at once, without polling;
- `KEPT_NEW`: not registered yet.

Where the pollset supports edge-triggered registrations (epoll, kqueue) and the compiler has
thread-local storage, the kept descriptors are edge-triggered: never re-armed at all. Since an edge
only comes for new data, a wait arming a descriptor that fired since its last wait checks it with a
nonblocking poll, unless the caller said it **drained** it (`AP_MPM_WAIT_DRAINED`) after the last
event was delivered. For input, the registration also asks for the peer's half-close where the
pollset reports it, so that the end of file can't sit unseen behind data that a short read left.

The record is found from the descriptor alone through an anchor attached to the socket or the file,
so that `ap_mpm_release_pfd()` needs no connection. If the descriptor's pool is cleaned up while it
is still kept (closed without being released, a bug of its user), the anchor's cleanup releases it,
and a descriptor still kept by another connection is logged as an error and waited for without
keeping. A released record is reused after its drain epoch passed ([section
4.5](#45-stale-events-and-the-drain-epochs)).

### 5.6 Notifiers

A notifier (`ap_mpm_notifier_t`) is created before the wait it is given to, so that it can be
notified before the wait is armed. `ap_mpm_notify()` may be called from any thread (event_notify()),
under the notifiers' mutex:

- before its wait is armed, it only records the notification; arming the wait then completes it at
  once;
- while its wait is armed, it queues the notifier for the listener, which completes the wait after
  its next poll, and wakes the listener up; but a **polling worker** that notifies (e.g. releasing a
  backend connection to a request waiting for one) claims and completes the wait itself, and queues
  the continuation for itself without ringing the doorbell: it pops it right after its current work;
- after its wait completed, it does nothing but record the notification.

A notifier serves one wait. `ap_mpm_notifier_rearm()` makes it new again for the next one, and drops
a late notification; it is refused while the wait is registered or armed.

A notifier can be **attached** to a parent (`ap_mpm_notifier_attach()`), one level deep: notifying
it notifies the parent, and the parent is what is given to the wait. A notification made before the
attachment passes on to the parent. This lets one wait stand for any number of notifiers (the core
does it for a request's notifier wait contexts). `ap_mpm_notifier_detach()` ends it, and
`ap_mpm_notifier_notified()` tells which attached notifiers fired.

### 5.7 Races, and how they are avoided

- **A continuation never runs while the registering code is on the stack**: the wait is armed only
  once no thread runs the connection (pending, then armed).
- **Arming against completing**: the claim word is set to armed first, under the wait's mutex, and
  the wait's cleanup takes the same mutex, so a wait completed while its arming is still going on
  (its timer expiring, the thread preempted) is disarmed only once it is armed entirely.
- **The timer against the claim**: a wait's timer is recorded before it is inserted. The listener
  pops expired timers and claims their waits under the timers' mutex, and frees the timer only if it
  won; a winner on another thread frees the timer under the same mutex. So a timer is freed once,
  whoever wins.
- **A notification against the other completions**: a polling worker claims the wait under the
  notifiers' mutex, where the wait's cleanup marks the notifier done, and frees the wait's timer
  only after (the listener takes the timers' mutex first).
- **Stale events**: a wait's descriptors alternate between two copies, and a kept descriptor's state
  machine takes the events that come between waits (sections
  [4.5](#45-stale-events-and-the-drain-epochs) and [5.5](#55-kept-descriptors)).
- **Memory**: the wait, its copies and the kept records live in the connection's pool, which isn't
  recycled while a poller may hold an event for it (the drain epochs).

## 6. Admission and the backlog

### 6.1 What is limited, and what isn't

The connections that wait without a thread (keep-alive, write completion, lingering close, suspended
requests) cost a pool, a socket and a descriptor each. They are not limited by the threads, only by
the descriptors (and in auto mode by `MaxClientConnections`). What the admission limits is the work
waiting for a thread: the **new connections** waiting in the workers' queue.

A new connection accepted is never dropped for waiting: it waits without a timeout until a worker
takes it. Instead, the child stops accepting when the new connections wait too long, and the next
ones stay in the kernel's listen backlog, or go to the other children of the bucket.

### 6.2 The admission

The child stops accepting (`ACCEPT_OFF_LIMIT`) when:

- **the sojourn** of the new connections stays above `AsyncAdmissionTarget` (5 ms by default) for
  `AsyncAdmissionInterval` (100 ms) in a row, like CoDel. The waits are measured by the workers for
  each new connection they take, and by the age of the oldest new connection still waiting, so that
  workers blocked in long requests count too;
- **the backstop**: more than `ThreadsPerChild` times `AsyncAdmissionBacklogPerThread` (16) new
  connections wait, whatever their waits. It acts first only for very short requests;
- **the connections limit** is reached (auto mode, [section 7.3](#73-auto-settings)).

The listener checks the limits when it queues an event and no worker is idle (only the connections
limit while one is). It stops accepting by removing the listening sockets from its pollset, and
marks the child not accepting in the scoreboard.

It accepts again once every reason is gone, with a hysteresis so as not to toggle at the pace of the
workers: no new connection waiting longer than half the target, fewer than half the backstop
waiting, and the connections below 90% of their limit. The workers taking new connections or going
idle, and the connections closing, wake the listener up when it may accept again; a re-check every
second is only a backstop against a lost wakeup.

### 6.3 The workers' queue

The workers' queue has a lane per class of work, popped by weighted round-robin: the work in
progress first (timers, continuations, write completion, lingering close: weight 4), then the
connections that were waiting for the client (I/O wait, keep-alive: 2), then the new connections
(1). Every lane keeps a share, so nothing starves, and under load the new connections are the ones
that wait, which is what the admission measures.

The queue also keeps the idlers count. The listener reserves an idle worker for each event it queues
(the count may go negative: all busy), and a worker counts itself idle again when it goes back to
wait.

### 6.4 The fair share (auto mode)

The kernel spreads the new connections only roughly evenly over the children of a bucket, and a
connection stays in its child for its whole keep-alive life. In auto mode, a child with no idle
worker stops accepting (`ACCEPT_OFF_SHARE`) when its connections exceed the average of the accepting
children of its bucket plus a slack (a quarter of `ThreadsPerChild`, at least 2), provided another
child of the bucket accepts. It accepts again once back at or below the average, or when a worker is
idle. The counts are the scoreboard's, which each child publishes at its stats tick and when it
accepts. After stopping for the share, the listener re-checks within the admission target during the
admission interval, then at the stats tick.

A child with idle workers takes more connections at no harm: gathering them batches the work.

### 6.5 Other limits on accepting

- `MaxConnectionsPerChild`: the child stops gracefully once it accepted that many.
- A shortage while accepting (descriptors, memory) stops the child gracefully, and the parent sees
  it as a sick child.

## 7. Threads

### 7.1 Worker slots and the scoreboard

Each worker has a scoreboard entry (its status, the request it runs) and a worker slot, in a cache
line of its own since it's written often: the socket it runs (for an immediate stop, [section
8.2](#82-immediate-stop)), its drain epoch, and whether it retired. A child has `ThreadLimit` of
each; the workers use the first `ThreadsPerChild`, and the extra workers the others.

The child's scoreboard entry (`process_score`) shows its connections by state (I/O wait, write
completion, keep-alive, shutdown, lingering close, backlog, suspended, all), its live workers, and
whether it accepts and whether it is stopping. The listener updates them every second, and the
connections count at each accept in auto mode. mod_status shows them.

### 7.2 Elastic workers

With `MaxRequestWorkers auto` (and `getrusage()`), a child's workers grow from `ThreadsPerChild` up
to `ThreadLimit` while they are blocked rather than busy on the CPU, since then another thread could
run, and the connections can't move to another child. The listener checks it (workers_grow_check())
and starts one more worker when all of these hold:

- no worker is idle;
- something waits for a worker longer than the admission target: the oldest event queued or, with
  worker polling, no worker has been idle for that long (the connections nobody polls);
- over the last admission interval at least, the process's CPU time is below half of what its
  workers could use, that is their count but not more than the child's share of the CPUs (the CPUs
  divided by the children: a child that gets less is short of CPU, not blocked);
- where the system reports them, its involuntary context switches stay below half of the voluntary
  ones (blocking shows as voluntary switches, waiting for a CPU as involuntary ones).

At most one worker starts per admission target. After a check refused because of the CPU, the next
one waits for the admission interval, unless a worker idles meanwhile. At `ThreadLimit`, a notice
says once that all the workers are blocked. The listener wakes up in time for these checks
(workers_grow_deadline()) while no worker is idle and more can start.

The extra workers **retire** slowly: one that has been idle for 10 seconds with nothing queued
exits, checking every second; and one done with some work exits when the child hasn't been short of
workers for 10 seconds, one per second in the child (with the workers polling, an idle worker may
never stay idle that long while the extra ones aren't needed anymore). The listener joins the
retired threads at its stats tick, and their slots can be used again.

A suspended request holds no worker, so it never counts as demand. A module that blocks holds a
worker, and the MPM can only infer it from the CPU usage ([section
10](#10-known-limits-and-planned-work)).

### 7.3 Auto settings

`MaxRequestWorkers auto` derives the settings that aren't set explicitly (auto_settings_derive()):

- `ThreadsPerChild`: 2, or 1 on a single CPU;
- the client connections to hold: `MaxClientConnections` if set, else what the descriptors limit
  allows (the soft limit, less a reserve for logs, modules and listeners, at two descriptors per
  client since a proxied client holds a backend connection too);
- the children: enough to hold those clients, at least enough for their threads to cover the CPUs, a
  multiple of the listener buckets; `MaxRequestWorkers` is all their threads, and `StartServers` all
  of them;
- `ThreadLimit`: a worker per client of a child, at most 1024, for a fully blocking load.

The parent then keeps that number of children running ([section 8.3](#83-children-maintenance)).
With `MaxClientConnections`, each child accepts at most its share of them, plus 10% since the kernel
spreads the connections only roughly evenly. The fair share ([section
6.4](#64-the-fair-share-auto-mode)) is on.

### 7.4 What the MPM tells modules

- `AP_MPMQ_MAX_THREADS`: the base workers (2 when they can grow from 1, for the modules that skip
  locking when single-threaded).
- `AP_MPMQ_MAX_CONNECTIONS`: what a child runs or queues at once: its threads up to `ThreadLimit`,
  plus the backstop of the admission. A sizing hint (e.g. for a connection pool), not a limit: the
  suspended connections aren't bounded by it.
- `AP_MPMQ_CAN_REGISTER_WAIT`, `AP_MPMQ_CAN_SUSPEND`, `AP_MPMQ_CAN_WAITIO`: true.

### 7.5 The periodic stats

At trace2, the listener logs two lines every second while the child has connections:

- the child's line: idlers, connections by state, timers, suspended connections, workers live out of
  the most, grown and retired in the period;
- the backlog's line: for each class of the workers' queue, how many waited and for how long
  (average, p50 and p99 bounds, maximum), the connections dropped from the backlog and closed by the
  linger queue's shrinking, how often and how long the child stopped accepting and why it resumed,
  the polling workers' counters (polls, connections and waits claimed, events dropped, polls missed
  for lack of a slot, promotions), and the waits' timeouts armed in a queue or as a timer.

The backlog's counters are only kept when they are logged: the workers would otherwise write the
same cache lines for nothing.

## 8. Stops and maintenance

### 8.1 Graceful stop

A child stops gracefully when the parent says so on the pipe of death (a graceful restart or stop,
or too many idle threads), after `MaxConnectionsPerChild`, or on a failure it can survive. Then
(signal_threads(), then set_child_dying() on the listener):

- the MPM's state says stopping, so the core ends the connections after their current response
  rather than keeping them alive;
- the listener stops accepting for good, closes its listening sockets, wakes up the idle workers,
  and frees the idle pools;
- the connections go on: suspended requests finish normally, bounded by their timeouts; the idle
  keep-alive connections stay until their `KeepAliveTimeout`, so that their clients don't have to
  reconnect for a request already on its way; lingering closes last 2 seconds at most;
- while there are more live workers than connections, the workers exit one by one;
- the listener exits once there are no connections and no timers left, then the queue is terminated,
  the last workers exit, the main thread joins them and the child exits.

The parent bounds a graceful stop of the server with `GracefulShutdownTimeout`, after which it stops
the children immediately.

### 8.2 Immediate stop

On an immediate stop (a restart or a stop, or a failure that can't wait), the workers are told to
exit at once, the parked ones interrupted and the blocked pollers woken by the doorbell, and the
listener exits at its next turn.

The sockets of the connections that workers are running are closed by the thread that stops the
child, so that a worker blocked on one returns: it takes each socket from its worker's slot (an
atomic exchange) and closes it. A worker done with its connection then finds its slot empty, and
leaves the socket and the connection's pool alone (take_back_worker_socket()); the child exits
anyway. The suspended connections get no continuation, and in a forked child their pool cleanups
don't run either: the process exits.

### 8.3 Children maintenance

The parent counts what the children publish in the scoreboard, once a second (and when a child
exits):

- **fixed settings**: it keeps the idle threads of all the children between `MinSpareThreads` and
  `MaxSpareThreads`, forking children (more each second while it isn't enough, up to 32 at once) or
  asking one per bucket to stop gracefully; it doesn't stop more while children are stopping and the
  scoreboard lacks room for a restart;
- **auto settings**: it keeps the target of children running, the same number per bucket, and
  replaces those that exited or stopped accepting for good at once (unless their slot's child or the
  last one started under 2 seconds ago, so that children failing at startup aren't forked in a
  loop). It never stops a child for its idle threads, since an idle child may hold many connections,
  and never starts more because threads are blocked (the workers grow instead).

The scoreboard has room for more children than `MaxRequestWorkers` allows (four times as many, or
`ServerLimit`), so that the children of a previous generation can finish gracefully while the new
ones run. In auto mode, a graceful restart starts the whole target at once, which is why the target
takes half of the scoreboard at most.

### 8.4 Listener buckets

With `SO_REUSEPORT`, each listening socket is duplicated once per bucket, and the kernel spreads the
new connections over the buckets. A child serves one bucket (its scoreboard slot modulo the number
of buckets) and closes the other buckets' sockets. Each bucket has its own pipe of death, and the
children are started and stopped per bucket. The number of buckets is the largest divisor of the
children's count not above the CPUs divided by `ListenCoresBucketsRatio`, so that every bucket has
the same number of children and `MaxRequestWorkers` isn't changed.

## 9. Logging levels

event logs by the worst-case rate of each line, since many of its lines can fire per connection or
per event:

- **error, warning, notice**: something to fix or a limit reached, once or rarely (e.g. the
  `ThreadLimit` notice, a wait that couldn't be armed or was abandoned by its continuation);
- **debug**: rare and actionable (accepting stopped and resumed, a wait's timeout not declared, a
  registered wait not followed by `SUSPENDED`);
- **trace1**: the settings at startup (admission, pollers, connections limit, the waits' queues);
- **trace2**: the periodic stats lines ([section 7.5](#75-the-periodic-stats)): the level for
  benchmarks;
- **trace4 to trace6**: per connection outcomes (timeouts, closes, worker growth and retirement);
- **trace7**: per event (polls, pushes to workers, suspends and resumes, waits armed), never in
  benchmarks;
- **trace8**: every socket closed.

The lines that can come in bursts but say something useful are rate-limited at their level
(`LOG_RATELIMIT()`): at most one per second per call site and child, the next one preceded by how
many were suppressed; at trace7 all of them are logged.

## 10. Known limits and planned work

- **Blocking is only inferred.** A worker blocked in a module's call (LDAP, a database, a name
  lookup) looks busy, like one on the CPU. The workers grow only with the auto settings and
  `getrusage()`, only once something waited for the admission target, after at least an admission
  interval of CPU samples, and not when other workers keep the process's CPU above the half in a
  mixed load.
- **Blocking sections (planned, not in the code).** Modules would mark their blocking calls
  (proposed: `ap_mpm_blocking_enter()` and `ap_mpm_blocking_leave()`, see
  [README.async.md](../../../README.async.md)). On event's side, the plan is:
  - each worker records its marks (a nesting depth and when it entered) in its slot, and the child
    counts the marked workers; marks never start or stop a thread themselves;
  - the workers grow without waiting for CPU samples while marked workers leave fewer unmarked ones
    than `ThreadsPerChild`, still with no idler, something waiting beyond the admission target, and
    one worker per target at most; the retirement stays as slow as now, so a worker started for one
    blocking call serves the next ones;
  - to decide: a grace before a mark counts (one admission target), a moving average of the marked
    count, and a cap on the workers grown for marked calls below `ThreadLimit`;
  - the stats line and the `ThreadLimit` notice count the marked workers;
  - optionally, a limit per name with a queue: callers beyond it wait without a thread, and queued
    requests don't count as demand, so the workers grown for marked calls are bounded by the limits.
- **Secondary connections** (HTTP/2 streams) can't wait through the MPM: their waits are refused,
  and the modules block instead.
- **Kept descriptors need worker polling**, and one-shot support in the pollset.
- **One wait per connection**: the core's request API multiplexes a request's waits on it.
- **The timers share one skiplist and mutex**; the waits' declared timeouts avoid it, and the
  listener scans the waits' queues in time linear in the number of declared values.
