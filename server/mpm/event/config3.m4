APACHE_MPMPATH_INIT(event)

APACHE_MPM_MODULE(event, $enable_mpm_event, event.lo,[
    AC_CHECK_FUNCS(pthread_kill)
    dnl The CPU time of the process, for the elastic worker threads (auto)
    AC_CHECK_FUNCS(getrusage)
    dnl Workers draining the pollset (EVENT_WORKER_DRAIN) need APR to poll the
    dnl same pollset from several threads; a header check since the bundled
    dnl APR isn't built yet.
    event_old_cppflags=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS $INCLUDES"
    AC_EGREP_HEADER([apr_pollset_poll_into], [apr_poll.h],
                    [AC_DEFINE(HAVE_APR_POLLSET_POLL_INTO, 1,
                               [Define if APR has apr_pollset_poll_into()])])
    CPPFLAGS=$event_old_cppflags
])

APACHE_MPMPATH_FINISH
