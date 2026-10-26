APACHE_MPMPATH_INIT(event)

dnl ## XXX - Need a more thorough check of the proper flags to use

APACHE_CHECK_SERF
if test "$ac_cv_serf" = yes ; then
    APR_ADDTO(MOD_MPM_EVENT_LDADD,[\$(SERF_LIBS)])
fi
APACHE_SUBST(MOD_MPM_EVENT_LDADD)

APACHE_MPM_MODULE(event, $enable_mpm_event, event.lo,[
    AC_CHECK_FUNCS(pthread_kill)
    dnl Workers draining the pollset (EVENT_WORKER_DRAIN) need APR to poll the
    dnl same pollset from several threads; a header check since the bundled
    dnl APR isn't built yet.
    event_old_cppflags=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS $INCLUDES"
    AC_EGREP_HEADER([apr_pollset_poll_into], [apr_poll.h],
                    [AC_DEFINE(HAVE_APR_POLLSET_POLL_INTO, 1,
                               [Define if APR has apr_pollset_poll_into()])])
    CPPFLAGS=$event_old_cppflags
], , [\$(MOD_MPM_EVENT_LDADD)])

APACHE_MPMPATH_FINISH
