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

/*
 * protocol.c --- routines which directly communicate with the client.
 *
 * Code originally by Rob McCool; much redone by Robert S. Thau
 * and the Apache Software Foundation.
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_lib.h"
#include "apr_signal.h"
#include "apr_strmatch.h"
#include "apr_date.h"

#define APR_WANT_STDIO          /* for sscanf */
#define APR_WANT_STRFUNC
#define APR_WANT_MEMFUNC
#include "apr_want.h"

#include "util_filter.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_request.h"
#include "http_vhost.h"
#include "http_log.h"           /* For errors detected in basic auth common
                                 * support code... */
#include "mod_core.h"
#include "util_charset.h"
#include "util_ebcdic.h"
#include "util_time.h"
#include "scoreboard.h"

#if APR_HAVE_STDARG_H
#include <stdarg.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

/* we know core's module_index is 0 */
#undef APLOG_MODULE_INDEX
#define APLOG_MODULE_INDEX AP_CORE_MODULE_INDEX

APR_HOOK_STRUCT(
    APR_HOOK_LINK(pre_read_request)
    APR_HOOK_LINK(post_read_request)
    APR_HOOK_LINK(log_transaction)
    APR_HOOK_LINK(http_scheme)
    APR_HOOK_LINK(default_port)
    APR_HOOK_LINK(note_auth_failure)
    APR_HOOK_LINK(protocol_propose)
    APR_HOOK_LINK(protocol_switch)
    APR_HOOK_LINK(protocol_get)
)

AP_DECLARE_DATA ap_filter_rec_t *ap_old_write_func = NULL;


/* Patterns to match in ap_make_content_type() */
static const char *const needcset[] = {
    "text/plain",
    "text/html",
    NULL
};
static const apr_strmatch_pattern **needcset_patterns;
static const apr_strmatch_pattern *charset_pattern;

AP_DECLARE(void) ap_setup_make_content_type(apr_pool_t *pool)
{
    int i;
    for (i = 0; needcset[i]; i++) {
        continue;
    }
    needcset_patterns = (const apr_strmatch_pattern **)
        apr_palloc(pool, (i + 1) * sizeof(apr_strmatch_pattern *));
    for (i = 0; needcset[i]; i++) {
        needcset_patterns[i] = apr_strmatch_precompile(pool, needcset[i], 0);
    }
    needcset_patterns[i] = NULL;
    charset_pattern = apr_strmatch_precompile(pool, "charset=", 0);
}

/*
 * Builds the content-type that should be sent to the client from the
 * content-type specified.  The following rules are followed:
 *    - if type is NULL or "", return NULL (do not set content-type).
 *    - if charset adding is disabled, stop processing and return type.
 *    - then, if there are no parameters on type, add the default charset
 *    - return type
 */
AP_DECLARE(const char *)ap_make_content_type(request_rec *r, const char *type)
{
    const apr_strmatch_pattern **pcset;
    core_dir_config *conf =
        (core_dir_config *)ap_get_core_module_config(r->per_dir_config);
    core_request_config *request_conf;
    apr_size_t type_len;

    if (!type || *type == '\0') {
        return NULL;
    }

    if (conf->add_default_charset != ADD_DEFAULT_CHARSET_ON) {
        return type;
    }

    request_conf = ap_get_core_module_config(r->request_config);
    if (request_conf->suppress_charset) {
        return type;
    }

    type_len = strlen(type);

    if (apr_strmatch(charset_pattern, type, type_len) != NULL) {
        /* already has parameter, do nothing */
        /* XXX we don't check the validity */
        ;
    }
    else {
        /* see if it makes sense to add the charset. At present,
         * we only add it if the Content-type is one of needcset[]
         */
        for (pcset = needcset_patterns; *pcset ; pcset++) {
            if (apr_strmatch(*pcset, type, type_len) != NULL) {
                struct iovec concat[3];
                concat[0].iov_base = (void *)type;
                concat[0].iov_len = type_len;
                concat[1].iov_base = (void *)"; charset=";
                concat[1].iov_len = sizeof("; charset=") - 1;
                concat[2].iov_base = (void *)(conf->add_default_charset_name);
                concat[2].iov_len = strlen(conf->add_default_charset_name);
                type = apr_pstrcatv(r->pool, concat, 3, NULL);
                break;
            }
        }
    }

    return type;
}

AP_DECLARE(void) ap_set_content_length(request_rec *r, apr_off_t clength)
{
    r->clength = clength;
    apr_table_setn(r->headers_out, "Content-Length",
                   apr_off_t_toa(r->pool, clength));
}

/*
 * Return the latest rational time from a request/mtime (modification time)
 * pair.  We return the mtime unless it's in the future, in which case we
 * return the current time.  We use the request time as a reference in order
 * to limit the number of calls to time().  We don't check for futurosity
 * unless the mtime is at least as new as the reference.
 */
AP_DECLARE(apr_time_t) ap_rationalize_mtime(request_rec *r, apr_time_t mtime)
{
    apr_time_t now;

    /* For all static responses, it's almost certain that the file was
     * last modified before the beginning of the request.  So there's
     * no reason to call time(NULL) again.  But if the response has been
     * created on demand, then it might be newer than the time the request
     * started.  In this event we really have to call time(NULL) again
     * so that we can give the clients the most accurate Last-Modified.  If we
     * were given a time in the future, we return the current time - the
     * Last-Modified can't be in the future.
     */
    now = (mtime < r->request_time) ? r->request_time : apr_time_now();
    return (mtime > now) ? now : mtime;
}

/* Get a line from an input filter, including any continuation lines
 * caused by MIME folding (or broken clients) if fold != 0, and place it
 * in the buffer s, of size n bytes, without the ending newline.
 *
 * If s is NULL, ap_fgetline_core will allocate necessary memory from p.
 *
 * Returns APR_SUCCESS if there are no problems and sets *read to be
 * the full length of s.
 *
 * APR_ENOSPC is returned if there is not enough buffer space.
 * Other errors may be returned on other errors.
 *
 * The [CR]LF are *not* returned in the buffer.  Therefore, a *read of 0
 * indicates that an empty line was read.
 *
 * Notes: Because the buffer uses 1 char for NUL, the most we can return is
 *        (n - 1) actual characters.
 *
 *        If no LF is detected on the last line due to a dropped connection
 *        or a full buffer, that's considered an error.
 */
enum folding_state_e {
    NOT_FOLDING = 0,
    FOLDING_FIND,
    FOLDING_READ,
    FOLDING_DONE,
};
typedef struct {
    char *buf;
    apr_size_t len;
    apr_size_t max_size;
    apr_size_t alloc_size;
    apr_size_t folding_len;
    enum folding_state_e folding_state;
    apr_status_t late_rv;   /* to return once the line is read */
    unsigned int allocate       :1,
                 reusable       :1,
                 seen_nospc     :1;
} getline_state_t;
static apr_status_t ap_fgetline_core(getline_state_t *state,
                                     ap_filter_t *f, int flags,
                                     apr_bucket_brigade *bb,
                                     apr_pool_t *p,
                                     int rec)
{
    apr_status_t rv;
    apr_read_type_e block;
    int fold = flags & AP_GETLINE_FOLD;
    int crlf = flags & AP_GETLINE_CRLF;
    int do_alloc = state->allocate;
    int nospc_eol = flags & AP_GETLINE_NOSPC_EOL;
    int seen_eol = 0;
    apr_bucket *e;

    state->reusable = 0; /* until further notice */

    if (state->max_size == 0) {
        /* Needs room for NUL byte at least */
        return APR_BADARG;
    }

    block = (flags & AP_GETLINE_NONBLOCK) ? APR_NONBLOCK_READ
                                          : APR_BLOCK_READ;

    if (state->folding_state == FOLDING_FIND) {
        /* EAGAIN looking up for folding line, continue there */
        goto find_folding;
    }
    do {
        apr_brigade_cleanup(bb);
        rv = ap_get_brigade(f, bb, AP_MODE_GETLINE, block, 0);
        if (rv != APR_SUCCESS) {
            goto cleanup;
        }
        if (APR_BRIGADE_EMPTY(bb)) {
            if (block == APR_BLOCK_READ) {
                /* Something horribly wrong happened.  Someone didn't block! */
                rv = APR_EGENERAL;
            }
            else {
                /* Non blocking (which would block) gets us here */
                rv = APR_EAGAIN;
            }
            goto cleanup;
        }

        for (e = APR_BRIGADE_FIRST(bb);
             e != APR_BRIGADE_SENTINEL(bb);
             e = APR_BUCKET_NEXT(e))
        {
            const char *str;
            apr_size_t len;

            /* APR_EOF on EOS (CRLF is missing) */
            if (APR_BUCKET_IS_EOS(e)) {
                rv = APR_EOF;
                goto cleanup;
            }

            rv = apr_bucket_read(e, &str, &len, APR_BLOCK_READ);
            if (rv != APR_SUCCESS) {
                goto cleanup;
            }

            /* If folding, trim leading blanks */
            if (state->folding_state == FOLDING_READ && len > 0) {
                size_t i;
                for (i = 0; i < len; ++i) {
                    const char c = str[i];
                    if (c != APR_ASCII_BLANK && c != APR_ASCII_TAB) {
                        break;
                    }
                }
                state->folding_len += i;
                ap_assert(state->folding_len > 0);
                str += i;
                len -= i;

                /* Fail if the line is composed of blanks only */
                if ((len > 0 && str[0] == APR_ASCII_LF)
                     || (len > 1 && str[0] == APR_ASCII_CR
                                 && str[1] == APR_ASCII_LF)) {
                    state->late_rv = APR_EINVAL;
                }
            }
            if (len == 0) {
                /* no use attempting a zero-byte alloc (hurts when
                 * using --with-efence --enable-pool-debug) or
                 * doing any of the other logic either
                 */
                continue;
            }

            /* Would this exceed the limit?  If so, we'll die. */
            if (state->len + state->folding_len + len >= state->max_size) {
                apr_size_t read_len = state->len + state->folding_len;

                /* Before we die, let's fill the buffer up to its limit (i.e.
                 * fall through with the remaining length, if any), setting
                 * seen_eol on LF to stop the outer loop appropriately; we may
                 * come back here once the buffer is filled (no LF seen), and
                 * either be done at that time or continue to wait for LF here
                 * if nospc_eol is set.
                 *
                 * But there is also a corner cases which we want to address,
                 * namely if the buffer is overrun by the final LF only (i.e.
                 * the CR fits in); this is not really an overrun since we'll
                 * strip the CR finally (and use it for NUL byte), but anyway
                 * we have to handle the case so that it's not returned to the
                 * caller as part of the truncated line (it's not!). This is
                 * easier to consider that LF is out of counting and thus fall
                 * through with no error (seen_eol is set to 2 so that we later
                 * ignore LF handling already done here), while folding and
                 * nospc_eol logics continue to work (or fail) appropriately.
                 */
                seen_eol = (str[len - 1] == APR_ASCII_LF);
                if (!seen_eol
                    || state->seen_nospc
                    || read_len + len != state->max_size) {
                    /* Some data lost */
                    state->late_rv = APR_ENOSPC;
                    state->seen_nospc = 1;
                }
                else if ((len == 1
                          && state->len > 0
                          && state->buf[state->len - 1] == APR_ASCII_CR)
                         || (len > 1 && str[len - 2] == APR_ASCII_CR)) {
                    /* CR[LF] is to be stripped */
                    seen_eol = 2;
                }
                else {
                    /* Single LF, not copied (fail if AP_GETLINE_CRLF) */
                    AP_DEBUG_ASSERT(seen_eol == 1);
                    seen_eol = 3;
                }

                if (read_len + 1 >= state->max_size) {
                    /* Full, check loop condition */
                    continue;
                }

                /* Fall through (fill buf up to len) */
                len = state->max_size - read_len - 1;
            }

            /* Do we have to handle the allocation ourselves? */
            if (do_alloc) {
                apr_size_t more_len = len + (state->folding_state == FOLDING_READ);

                /* We'll assume the common case where one bucket is enough. */
                if (state->buf == NULL) {
                    state->alloc_size = more_len + 1;
                    state->buf = apr_palloc(p, state->alloc_size);
                }
                else if (state->len + more_len >= state->alloc_size) {
                    /* Increase the buffer size */
                    apr_size_t new_size;
                    char *new_buffer;

                    if (state->alloc_size >= state->max_size / 2) {
                        new_size = state->max_size;
                    }
                    else {
                        new_size = state->alloc_size * 2;
                        if (state->len + more_len >= new_size) {
                            new_size = state->len + more_len + 1;
                        }
                    }
                    ap_assert(new_size > state->len + more_len);

                    new_buffer = apr_palloc(p, new_size);

                    /* Copy what we already had. */
                    memcpy(new_buffer, state->buf, state->len);
                    state->alloc_size = new_size;
                    state->buf = new_buffer;
                }
            }

            if (state->folding_state == FOLDING_READ) {
                /* Replace all blanks with a single one. */
                state->buf[state->len++] = APR_ASCII_BLANK;
                state->folding_state = FOLDING_DONE;
            }
            /* Just copy new data to the end of the buffer. */
            memcpy(state->buf + state->len, str, len);
            state->len += len;
        }

        /* If we got a full line of input, stop reading */
        if (state->len && state->buf[state->len - 1] == APR_ASCII_LF) {
            seen_eol = 1;
        }
    } while (!seen_eol && (!state->seen_nospc || nospc_eol));

    if (state->late_rv != APR_SUCCESS) {
        rv = state->late_rv;
        goto cleanup;
    }
    if (state->folding_state == FOLDING_READ) {
        /* Folding is blank only */
        rv = APR_EINVAL;
        goto cleanup;
    }

    /* Now terminate the string at the end of the line;
     * if the last-but-one character is a CR, terminate there.
     * LF is handled above (not accounted nor copied) when seen_eol
     * is 2 or 3: the last char is then CR to terminate at still (2),
     * or the line's last one (3, a single LF).
     */
    if (seen_eol != 3) {
        state->len--;
    }
    if (seen_eol != 2) {
        if (state->len && state->buf[state->len - 1] == APR_ASCII_CR) {
            state->len--;
        }
        else if (crlf) {
            rv = APR_EINVAL;
            goto cleanup;
        }
    }

    /* If we have to search for folding, we have more work to do.
     * A continuation line read by the recursion (not folding there)
     * returns to the caller's loop for the next one if any, thus
     * issuing terminal recursions only; one resumed here after EAGAIN
     * (FOLDING_READ or FOLDING_DONE) goes on with the search here.
     *
     * Note that if an empty line or an EOS was seen, we know we can't have
     * another line.
     */
    if (fold && state->len) {
        state->folding_state = FOLDING_FIND;
find_folding:
        flags &= ~AP_GETLINE_FOLD;
        for (;;) {
            const char *str;
            apr_size_t len;
            char c = 0;

            /* We only care about the first byte. */
            apr_brigade_cleanup(bb);
            rv = ap_get_brigade(f, bb, AP_MODE_SPECULATIVE, block, 1);
            if (rv != APR_SUCCESS) {
                goto cleanup;
            }
            if (APR_BRIGADE_EMPTY(bb)) {
                if (block != APR_NONBLOCK_READ) {
                    rv = APR_EGENERAL;
                }
                else {
                    rv = APR_EAGAIN;
                }
                break;
            }
            do {
                e = APR_BRIGADE_FIRST(bb);

                /* APR_EOF on EOS (CRLF is missing) */
                if (APR_BUCKET_IS_EOS(e)) {
                    rv = APR_EOF;
                    goto cleanup;
                }

                rv = apr_bucket_read(e, &str, &len, APR_BLOCK_READ);
                if (rv != APR_SUCCESS) {
                    goto cleanup;
                }
                if (len > 0) {
                    c = *str;
                    break;
                }

                apr_bucket_delete(e);
            } while (!APR_BRIGADE_EMPTY(bb));

            if (APR_BRIGADE_EMPTY(bb)) {
                /* No useful data, continue reading */
                continue;
            }
            if (c != APR_ASCII_BLANK && c != APR_ASCII_TAB) {
                /* Not a continuation line */
                state->folding_state = NOT_FOLDING;
                break;
            }

            /* Before folding, trim trailing blanks */
            while (state->len
                   && (state->buf[state->len - 1] == APR_ASCII_BLANK
                       || state->buf[state->len - 1] == APR_ASCII_TAB)) {
                state->folding_len++;
                state->len--;
            }

            /* Call ourselves again to get the next line. */
            state->folding_state = FOLDING_READ;
            rv = ap_fgetline_core(state, f, flags, bb, p, 1);
            if (rv != APR_SUCCESS) {
                goto cleanup;
            }
            state->folding_state = FOLDING_FIND;
        }
    }

cleanup:
    if (rec) {
        /* On recursion, let the caller do the finalization */
        return rv;
    }
    if (APR_STATUS_IS_EAGAIN(rv) && block == APR_NONBLOCK_READ) {
        state->reusable = 1;
        rv = APR_EAGAIN;
    }
    if (state->buf) {
        apr_size_t len;

        /* ensure the string is NUL terminated */
        state->buf[state->len] = '\0';

        /* PR#43039: We shouldn't accept NULL bytes within the line,
         * checked once it's complete (the next call resumes it after
         * EAGAIN, from the whole buffer)
         */
        len = (state->reusable) ? state->len : strlen(state->buf);
        if (len < state->len) {
            ap_log_data(APLOG_MARK, APLOG_DEBUG, ap_server_conf,
                        "NULL bytes in header", state->buf, state->len, 0);
            if (rv == APR_SUCCESS) {
                rv = APR_EINVAL;
            }
            state->len = len;
        }
    }
    apr_brigade_cleanup(bb);
    return rv;
}

/* Get a line with the state, resumed after APR_EAGAIN if reusable */
static apr_status_t ap_fgetline_ex(char **s, apr_size_t n,
                                   apr_size_t *read, ap_filter_t *f,
                                   int flags, apr_bucket_brigade *bb,
                                   getline_state_t *state,
                                   apr_pool_t *p)
{
    apr_status_t rv;

    if (!state->reusable) {
        /* A new line */
        state->buf = NULL;
        state->len = state->alloc_size = state->folding_len = 0;
        state->folding_state = NOT_FOLDING;
        state->late_rv = APR_SUCCESS;
        state->allocate = state->seen_nospc = 0;
        if (*s) {
            state->buf = *s;
        }
        else {
            state->allocate = 1;
            *s = NULL;
        }
        state->max_size = n;
    }

    rv = ap_fgetline_core(state, f, flags, bb, p, 0);

    *s = state->buf;
    *read = state->len;
#if APR_CHARSET_EBCDIC
    /* On EBCDIC boxes, each complete http protocol input line needs to be
     * translated into the code page used by the compiler.  Since
     * ap_fgetline_core uses recursion, we do the translation in a wrapper
     * function to ensure that each input character gets translated only once.
     * A line to be resumed (APR_EAGAIN) is translated once read to its end
     * only, since ap_fgetline_core() compares its bytes with ASCII ones.
     */
    if (*read && !state->reusable) {
        ap_xlate_proto_from_ascii(*s, *read);
    }
#endif

    return rv;
}

AP_DECLARE(apr_status_t) ap_fgetline(char **s, apr_size_t n,
                                     apr_size_t *read, ap_filter_t *f,
                                     int flags, apr_bucket_brigade *bb,
                                     apr_pool_t *p)
{
    getline_state_t state;
    memset(&state, 0, sizeof(state));

    return ap_fgetline_ex(s, n, read, f, flags, bb, &state, p);
}

/* Same as ap_fgetline(), working on r's pool and protocol input filters.
 * Pulls from r->proto_input_filters instead of r->input_filters for
 * stricter protocol adherence and better input filter behavior during
 * chunked trailer processing (for http).
 */
AP_DECLARE(apr_status_t) ap_rgetline(char **s, apr_size_t n,
                                     apr_size_t *read, request_rec *r,
                                     int flags, apr_bucket_brigade *bb)
{
    return ap_fgetline(s, n, read, r->proto_input_filters,
                       flags, bb, r->pool);
}

AP_DECLARE(int) ap_getline(char *s, int n, request_rec *r, int flags)
{
    apr_status_t rv;
    apr_size_t len;
    apr_bucket_brigade *tmp_bb;

    if (n < 1) {
        /* Can't work since we always NUL terminate */
        return -1;
    }

    tmp_bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    rv = ap_rgetline(&s, n, &len, r, flags, tmp_bb);
    apr_brigade_destroy(tmp_bb);

    /* Map the out-of-space condition to the old API. */
    if (rv == APR_ENOSPC) {
        return n;
    }

    /* Anything else is just bad. */
    if (rv != APR_SUCCESS) {
        return -1;
    }

    return (int)len;
}

/* parse_uri: break apart the uri
 * Side Effects:
 * - sets r->args to rest after '?' (or NULL if no '?')
 * - sets r->uri to request uri (without r->args part)
 * - sets r->hostname (if not set already) from request (scheme://host:port)
 */
AP_CORE_DECLARE(void) ap_parse_uri(request_rec *r, const char *uri)
{
    int status = HTTP_OK;

    r->unparsed_uri = apr_pstrdup(r->pool, uri);

    /* http://issues.apache.org/bugzilla/show_bug.cgi?id=31875
     * http://issues.apache.org/bugzilla/show_bug.cgi?id=28450
     *
     * This is not in fact a URI, it's a path.  That matters in the
     * case of a leading double-slash.  We need to resolve the issue
     * by normalizing that out before treating it as a URI.
     */
    while ((uri[0] == '/') && (uri[1] == '/')) {
        ++uri ;
    }
    if (r->method_number == M_CONNECT) {
        status = apr_uri_parse_hostinfo(r->pool, uri, &r->parsed_uri);
    }
    else {
        status = apr_uri_parse(r->pool, uri, &r->parsed_uri);
    }

    if (status == APR_SUCCESS) {
        /* if it has a scheme we may need to do absoluteURI vhost stuff */
        if (r->parsed_uri.scheme
            && !ap_cstr_casecmp(r->parsed_uri.scheme, ap_http_scheme(r))) {
            r->hostname = r->parsed_uri.hostname;
        }
        else if (r->method_number == M_CONNECT) {
            r->hostname = r->parsed_uri.hostname;
        }

        r->args = r->parsed_uri.query;
        if (r->parsed_uri.path) {
            r->uri = r->parsed_uri.path;
        }
        else if (r->method_number == M_OPTIONS) {
            r->uri = apr_pstrdup(r->pool, "*");
        }
        else {
            r->uri = apr_pstrdup(r->pool, "/");
        }

#if defined(OS2) || defined(WIN32)
        /* Handle path translations for OS/2 and plug security hole.
         * This will prevent "http://www.wherever.com/..\..\/" from
         * returning a directory for the root drive.
         */
        {
            char *x;

            for (x = r->uri; (x = strchr(x, '\\')) != NULL; )
                *x = '/';
        }
#endif /* OS2 || WIN32 */
    }
    else {
        r->args = NULL;
        r->hostname = NULL;
        r->status = HTTP_BAD_REQUEST;             /* set error status */
        r->uri = apr_pstrdup(r->pool, uri);
    }
}

/* get the length of the field name for logging, but no more than 80 bytes */
#define LOG_NAME_MAX_LEN 80
static int field_name_len(const char *field)
{
    const char *end = ap_strchr_c(field, ':');
    if (end == NULL || end - field > LOG_NAME_MAX_LEN)
        return LOG_NAME_MAX_LEN;
    return end - field;
}

AP_DECLARE(int) ap_parse_request_line(request_rec *r)
{
    const char *method, *uri, *protocol;

    return ap_h1_tokenize_request_line(r, r->the_request,
                                       &method, &uri, &protocol)
        && ap_assign_request_line(r, method, uri, protocol);
}

AP_DECLARE(int) ap_check_request_header(request_rec *r)
{
    core_server_config *conf;
    int strict_host_check;
    const char *expect;
    int access_status;

    conf = ap_get_core_module_config(r->server->module_config);

    /* update what we think the virtual host is based on the headers we've
     * now read. may update status.
     */
    strict_host_check = (conf->strict_host_check == AP_CORE_CONFIG_ON);
    access_status = ap_update_vhost_from_headers_ex(r, strict_host_check);
    if (strict_host_check && access_status != HTTP_OK) { 
        if (r->server == ap_server_conf) { 
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(10156)
                          "Requested hostname '%s' did not match any ServerName/ServerAlias "
                          "in the global server configuration ", r->hostname);
        }
        else { 
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(10157)
                          "Requested hostname '%s' did not match any ServerName/ServerAlias "
                          "in the matching virtual host (default vhost for "
                          "current connection is %s:%u)", 
                          r->hostname, r->server->defn_name, r->server->defn_line_number);
        }
        r->status = access_status;
    }
    if (r->status != HTTP_OK) { 
        return 0;
    }

    if ((!r->hostname && (r->proto_num >= HTTP_VERSION(1, 1)))
        || ((r->proto_num == HTTP_VERSION(1, 1))
            && !apr_table_get(r->headers_in, "Host"))) {
        /*
         * Client sent us an HTTP/1.1 or later request without telling us the
         * hostname, either with a full URL or a Host: header. We therefore
         * need to (as per the 1.1 spec) send an error.  As a special case,
         * HTTP/1.1 mentions twice (S9, S14.23) that a request MUST contain
         * a Host: header, and the server MUST respond with 400 if it doesn't.
         */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00569)
                      "client sent HTTP/1.1 request without hostname "
                      "(see RFC2616 section 14.23): %s", r->uri);
        r->status = HTTP_BAD_REQUEST;
        return 0;
    }

    /* we may have switched to another server */
    conf = ap_get_core_module_config(r->server->module_config);

    if (((expect = apr_table_get(r->headers_in, "Expect")) != NULL)
        && (expect[0] != '\0')) {
        /*
         * The Expect header field was added to HTTP/1.1 after RFC 2068
         * as a means to signal when a 100 response is desired and,
         * unfortunately, to signal a poor man's mandatory extension that
         * the server must understand or return 417 Expectation Failed.
         */
        if (ap_cstr_casecmp(expect, "100-continue") == 0) {
            r->expecting_100 = 1;
        }
        else if (conf->http_expect_strict == AP_HTTP_EXPECT_STRICT_DISABLE) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02595)
                          "client sent an unrecognized expectation value "
                          "of Expect (not fatal): %s", expect);
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00570)
                          "client sent an unrecognized expectation value "
                          "of Expect: %s", expect);
            r->status = HTTP_EXPECTATION_FAILED;
            return 0;
        }
    }

    return 1;
}

/* The HTTP/1 head parser (ap_h1_head_parse()) reads the head in blocks: it
 * peeks at what the input filters have (AP_MODE_SPECULATIVE), checks the
 * bytes of the lines there in place, then consumes those it used
 * (AP_MODE_READBYTES), up to the head's end only. The rules are checked as
 * the bytes come, failing at once (the cause in parser->line_error): no NUL
 * byte, no whitespace before the first field line, no blank continuation
 * line, the limits (an obs-fold counting as the SP that replaces it). A
 * complete start line or field is copied once into the parser's pool, where
 * the head keeps it; a line not complete at a block's end (or a field whose
 * continuation is not known yet) is copied there, the next blocks appended.
 */
typedef enum {
    LINE_OK = 0,
    LINE_NOT_CRLF,          /* not ended by CRLF (Strict) */
    LINE_NUL,               /* a NUL byte */
    LINE_BLANK_FOLD,        /* a blank continuation line */
    LINE_LEADING_BLANK,     /* a continuation line with no line before */
} line_error_e;
typedef enum {
    H1_HEAD_START = 0,      /* the start line, after the empty lines skipped */
    H1_HEAD_FIELDS,         /* the header (or trailer) section */
    H1_HEAD_DONE,           /* the head is complete */
    H1_HEAD_FAILED          /* failed or ended (status), final */
} h1_head_phase_e;
typedef enum {
    H1_LINE_START = 0,      /* at the start of a line */
    H1_LINE_IN,             /* in a line */
    H1_LINE_FOLD,           /* in the blanks starting a continuation line */
    H1_LINE_END             /* after a field line: the next line's first byte
                             * tells whether it continues the field */
} h1_line_state_e;
struct ap_h1_head_parser {
    apr_pool_t *pool;
    request_rec *r;
    ap_h1_head_opts_t opts;
    apr_bucket_brigade *bb; /* the blocks read, emptied before returning */
    ap_h1_head_t *head;
    h1_head_phase_e phase;
    int status;             /* once failed: DONE or an HTTP status */
    apr_status_t rv;        /* the apr_status_t behind it */
    int loglevel;           /* of the errors' causes */
    const char *what_start; /* "request line", "status line" */
    const char *what;       /* "request header", "response trailer"... */
    const char *what_line;  /* "request header line"... */
    unsigned int blank_lines;
    unsigned int fields_read;

    /* The line being read, kept across the blocks */
    h1_line_state_e line_state;
    line_error_e line_error;/* the cause of an APR_EINVAL */
    char *line;             /* its bytes copied, the continuation lines of a
                             * field joined (NULL if none) */
    apr_size_t line_len;
    apr_size_t line_size;   /* allocated, room for a NUL byte */
    int fold_sp;            /* an obs-fold's SP to add before the next byte */
};

static int table_do_fn_check_lengths(void *parser_, const char *key,
                                     const char *value)
{
    ap_h1_head_parser_t *parser = parser_;
    request_rec *r = parser->r;
    if (value == NULL || parser->opts.limit_field >= strlen(value) )
        return 1;

    apr_table_setn(r->notes, "error-notes",
                   "Size of a request header field exceeds server limit.");
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00560) "Request "
                  "header exceeds LimitRequestFieldSize after merging: %.*s",
                  field_name_len(key), key);
    return 0;
}

/* Log under the module given in the options */
#define H1_LOG_MARK __FILE__, __LINE__, parser->opts.module_index

/* The error-notes of the client side's error response, from fmt with a %s
 * for what the head is (e.g. "request header")
 */
static void h1_head_notes(ap_h1_head_parser_t *parser, const char *fmt)
{
    if (!(parser->opts.flags & AP_H1_HEAD_OPT_BACKEND)) {
        apr_table_setn(parser->r->notes, "error-notes",
                       apr_psprintf(parser->r->pool, fmt, parser->what));
    }
}

/* Reading a line failed with rv: log the cause, and give the status, or DONE
 * if the input ended or failed (but a timeout) before the start line
 */
static int h1_head_read_error(ap_h1_head_parser_t *parser, apr_status_t rv)
{
    request_rec *r = parser->r;
    const char *what_line = (parser->phase == H1_HEAD_START)
                            ? parser->what_start
                            : parser->what_line;

    if (rv == APR_ENOSPC) {
        if (parser->phase == H1_HEAD_START) {
            ap_log_rerror(H1_LOG_MARK, parser->loglevel, 0, r, APLOGNO()
                          "%s longer than the limit of %" APR_SIZE_T_FMT
                          " bytes", parser->what_start,
                          parser->opts.limit_start_line);
            return (parser->opts.kind == AP_H1_HEAD_REQUEST)
                   ? HTTP_REQUEST_URI_TOO_LARGE
                   : HTTP_BAD_REQUEST;
        }
        h1_head_notes(parser, "Size of a %s field exceeds server limit.");
        ap_log_rerror(H1_LOG_MARK, parser->loglevel, 0, r, APLOGNO()
                      "%s field longer than the limit of %" APR_SIZE_T_FMT
                      " bytes: %.*s", parser->what, parser->opts.limit_field,
                      field_name_len(parser->line), parser->line);
        return HTTP_BAD_REQUEST;
    }
    if (APR_STATUS_IS_EINVAL(rv) && parser->line_error != LINE_OK) {
        switch (parser->line_error) {
        case LINE_NOT_CRLF:
            ap_log_rerror(H1_LOG_MARK, parser->loglevel, 0, r, APLOGNO()
                          "%s not ended by CRLF", what_line);
            break;
        case LINE_NUL:
            ap_log_rerror(H1_LOG_MARK, parser->loglevel, 0, r, APLOGNO()
                          "NUL byte in a %s", what_line);
            break;
        case LINE_BLANK_FOLD:
            ap_log_rerror(H1_LOG_MARK, parser->loglevel, 0, r, APLOGNO()
                          "%s field continued by a blank line: %.*s",
                          parser->what, field_name_len(parser->line),
                          parser->line);
            break;
        case LINE_LEADING_BLANK:
            ap_log_rerror(H1_LOG_MARK, parser->loglevel, 0, r, APLOGNO()
                          "whitespace before the first %s field",
                          parser->what);
            break;
        default:
            break;
        }
        return HTTP_BAD_REQUEST;
    }
    if (APR_STATUS_IS_TIMEUP(rv)) {
        ap_log_rerror(H1_LOG_MARK, parser->loglevel, rv, r, APLOGNO()
                      "timeout reading the %s",
                      (parser->phase == H1_HEAD_START) ? parser->what_start
                                                       : parser->what);
        return HTTP_REQUEST_TIME_OUT;
    }
    if (parser->phase == H1_HEAD_START) {
        /* No head: a closed connection, for the caller to tell */
        ap_log_rerror(H1_LOG_MARK, APLOG_TRACE3, rv, r,
                      "reading the %s failed", parser->what_start);
        return DONE;
    }
    ap_log_rerror(H1_LOG_MARK, parser->loglevel, rv, r, APLOGNO()
                  "%s section %s", parser->what,
                  APR_STATUS_IS_EOF(rv) ? "ended before the empty line"
                                        : "failed to read");
    return HTTP_BAD_REQUEST;
}

/* The number of a request's protocol, as r_assign_protocol() gives
 * r->proto_num: HTTP/x.y (case-insensitive, x not 0), else HTTP/0.9
 */
static int h1_head_proto_num(const char *protocol)
{
    if (ap_cstr_casecmpn(protocol, "HTTP/", 5) == 0
        && apr_isdigit(protocol[5]) && protocol[5] != '0'
        && protocol[6] == '.' && apr_isdigit(protocol[7])
        && !protocol[8]) {
        int major = protocol[5] - '0', minor = protocol[7] - '0';

        /* A 1.x minor above ours is read as the highest we support
         * (RFC 9112 2.3)
         */
        return HTTP_VERSION(major, (major == 1 && minor > 1) ? 1 : minor);
    }
    return HTTP_VERSION(0, 9);
}

/* Parse the start line, of len bytes */
static int h1_head_start_line(ap_h1_head_parser_t *parser, const char *line,
                              apr_size_t len)
{
    ap_h1_head_t *head = parser->head;

    head->start_line = line;

    if (parser->opts.kind == AP_H1_HEAD_REQUEST) {
        const char *method, *uri, *protocol;

        /* The request line, its errors logged */
        if (!ap_h1_tokenize_request_line(parser->r, line,
                                         &method, &uri, &protocol)) {
            return HTTP_BAD_REQUEST;
        }
        head->u.req.method = method;
        head->u.req.uri = uri;
        head->protocol = protocol;
        head->proto_num = h1_head_proto_num(protocol);
        if (HTTP_VERSION_MAJOR(head->proto_num) > 1) {
            /* HTTP/2 and above is not spoken with an HTTP/1 request line
             * (mod_http2 builds its requests without one)
             */
            ap_log_rerror(H1_LOG_MARK, parser->loglevel, 0, parser->r,
                          APLOGNO()
                          "HTTP Request Line; version not supported: '%.*s'",
                          field_name_len(protocol), protocol);
            return HTTP_VERSION_NOT_SUPPORTED;
        }
    }
    else {
        const char *echo = parser->opts.echo_protocol;
        const char *reason = "";
        apr_size_t plen = 0; /* the protocol's length */
        int echoed = 0;
        int status = 0;

        /* RFC 9112 4: HTTP/1.x, SP, 3DIGIT, then SP and the reason phrase
         * if any (tolerated without), with no control characters but HTAB;
         * or opts.echo_protocol (a gateway echoing the request's protocol)
         * if HTTP/2 or later, also as "HTTP/x" for an "HTTP/x.0".
         */
        if (len >= 12 && apr_date_checkmask(line, "HTTP/#.# ###*")) {
            if (line[5] == '1') {
                plen = 8;
            }
            else if (echo && line[5] >= '2' && !strncmp(line, echo, 8)
                     && !echo[8]) {
                plen = 8;
                echoed = 1;
            }
        }
        else if (echo && len >= 10 && line[5] >= '2'
                 && apr_date_checkmask(line, "HTTP/# ###*")
                 && !strncmp(echo, line, 6) && !strcmp(echo + 6, ".0")) {
            plen = 6;
            echoed = 1;
        }
        if (plen && (len == plen + 4 || line[plen + 4] == ' ')) {
            const char *code = line + plen + 1;

            status = (code[0] - '0') * 100 + (code[1] - '0') * 10
                     + (code[2] - '0');
            for (reason = code + 3; *reason; reason++) {
                const unsigned char c = *reason;
                if ((c < 0x20 && c != '\t') || c == 0x7f) {
                    status = 0;
                    break;
                }
            }
            reason = (len > plen + 5) ? line + plen + 5 : "";
        }
        if (status < 100) {
            ap_log_rerror(H1_LOG_MARK, parser->loglevel, 0, parser->r,
                          APLOGNO() "malformed status line: %.*s",
                          (int)((len > 128) ? 128 : len), line);
            return HTTP_BAD_REQUEST;
        }
        if (echoed) {
            /* Read as HTTP/1.1 */
            head->protocol = "HTTP/1.1";
            head->proto_num = HTTP_VERSION(1, 1);
        }
        else {
            head->protocol = apr_pstrmemdup(parser->pool, line, plen);
            head->proto_num = HTTP_VERSION(1, line[7] - '0');
        }
        head->u.rsp.status = status;
        head->u.rsp.reason = reason;
    }
    return OK;
}

AP_DECLARE(ap_h1_head_parser_t *) ap_h1_head_parser_create(apr_pool_t *p,
                                                           request_rec *r,
                                                           const ap_h1_head_opts_t *opts)
{
    ap_h1_head_parser_t *parser = apr_pcalloc(p, sizeof(*parser));

    parser->pool = p;
    parser->r = r;
    parser->opts = *opts;
    parser->loglevel = ((opts->flags & AP_H1_HEAD_OPT_BACKEND) ? APLOG_WARNING
                                                               : APLOG_DEBUG);
    switch (opts->kind) {
    case AP_H1_HEAD_REQUEST:
    case AP_H1_HEAD_HEADERS: /* no start line */
        parser->what_start = "request line";
        parser->what = "request header";
        parser->what_line = "request header line";
        break;
    case AP_H1_HEAD_RESPONSE:
        parser->what_start = "status line";
        parser->what = "response header";
        parser->what_line = "response header line";
        break;
    default:
        parser->what_start = "status line"; /* none */
        if (opts->flags & AP_H1_HEAD_OPT_BACKEND) {
            parser->what = "response trailer";
            parser->what_line = "response trailer line";
        }
        else {
            parser->what = "request trailer";
            parser->what_line = "request trailer line";
        }
        break;
    }
    ap_h1_head_parser_reset(parser);
    return parser;
}

AP_DECLARE(void) ap_h1_head_parser_reset(ap_h1_head_parser_t *parser)
{
    parser->head = apr_pcalloc(parser->pool, sizeof(*parser->head));
    parser->head->headers = apr_table_make(parser->pool, 20);
    parser->head->kind = parser->opts.kind;
    if (parser->opts.kind == AP_H1_HEAD_HEADERS
        || parser->opts.kind == AP_H1_HEAD_TRAILERS) {
        parser->phase = H1_HEAD_FIELDS;
    }
    else {
        parser->phase = H1_HEAD_START;
    }
    parser->status = OK;
    parser->rv = APR_SUCCESS;
    parser->blank_lines = 0;
    parser->fields_read = 0;
    parser->line_state = H1_LINE_START;
    parser->line_error = LINE_OK;
    parser->line = NULL;
    parser->line_len = parser->line_size = 0;
    parser->fold_sp = 0;
}

AP_DECLARE(apr_status_t) ap_h1_head_parser_status(const ap_h1_head_parser_t *parser)
{
    return parser->rv;
}

/* The bytes of the line being read before its LF (a CR included) must be
 * fewer than this, as with ap_fgetline() given the limit + 2 for the line
 * end + 1 for the NUL byte
 */
static APR_INLINE apr_size_t h1_line_limit(const ap_h1_head_parser_t *parser)
{
    return ((parser->phase == H1_HEAD_START) ? parser->opts.limit_start_line
                                             : parser->opts.limit_field) + 3;
}

/* Append len bytes to the line copied, room kept for a NUL byte */
static void h1_line_append(ap_h1_head_parser_t *parser, const char *buf,
                           apr_size_t len)
{
    if (parser->line_len + len >= parser->line_size) {
        apr_size_t size = (parser->line_size) ? parser->line_size * 2 : 64;
        char *line;

        if (size <= parser->line_len + len) {
            size = parser->line_len + len + 1;
        }
        line = apr_palloc(parser->pool, size);
        if (parser->line_len) {
            memcpy(line, parser->line, parser->line_len);
        }
        parser->line = line;
        parser->line_size = size;
    }
    if (len) {
        memcpy(parser->line + parser->line_len, buf, len);
        parser->line_len += len;
    }
}

/* NUL-terminate the line copied for the error logs, translated on EBCDIC
 * hosts as a complete one is
 */
static void h1_line_for_logs(ap_h1_head_parser_t *parser)
{
    h1_line_append(parser, NULL, 0);
    parser->line[parser->line_len] = '\0';
#if APR_CHARSET_EBCDIC
    ap_xlate_proto_from_ascii(parser->line, parser->line_len);
#endif
}

/* Take the complete line, in place in a block (in, in_len) or copied, as a
 * NUL-terminated string of the parser's pool, where the head keeps it; on
 * EBCDIC hosts, translated (once, its bytes having been checked as ASCII
 * ones)
 */
static char *h1_line_take(ap_h1_head_parser_t *parser, const char *in,
                          apr_size_t in_len, apr_size_t *len)
{
    char *line;

    if (in) {
        line = apr_pstrmemdup(parser->pool, in, in_len);
        *len = in_len;
    }
    else {
        line = parser->line;
        *len = parser->line_len;
        line[*len] = '\0';
        parser->line = NULL;
        parser->line_len = parser->line_size = 0;
    }
#if APR_CHARSET_EBCDIC
    ap_xlate_proto_from_ascii(line, *len);
#endif
    return line;
}

/* Check and add a complete field of len bytes, its continuation lines
 * joined; returns OK or the status of the error (logged), with *rv set for a
 * limit
 */
static int h1_head_field(ap_h1_head_parser_t *parser, char *field,
                         apr_size_t len, apr_status_t *rv)
{
    request_rec *r = parser->r;
    char *value;

    /* For all header values, and all obs-fold lines, the presence of
     * additional whitespace is a no-op, so collapse trailing whitespace
     * to save buffer allocation and optimize copy operations.
     * Do not remove the last single whitespace under any condition.
     */
    while (len > 1 && (field[len-1] == '\t' || field[len-1] == ' ')) {
        field[--len] = '\0';
    }

    /* Counted in the parser, which a non-blocking read keeps across the
     * calls (EAGAIN)
     */
    if (parser->opts.limit_fields
            && (++parser->fields_read > parser->opts.limit_fields)) {
        h1_head_notes(parser, "The number of %s fields exceeds this "
                              "server's limit.");
        ap_log_rerror(H1_LOG_MARK, parser->loglevel, 0, r, APLOGNO()
                      "number of %ss exceeds the limit of %u",
                      parser->what, parser->opts.limit_fields);
        *rv = APR_ENOSPC;
        return HTTP_BAD_REQUEST;
    }

    if (!(parser->opts.flags & AP_H1_HEAD_OPT_STRICT)) {
        /* Not Strict ('Unsafe' mode), using the legacy parser */

        if (!(value = strchr(field, ':'))) { /* Find ':' or */
            ap_log_rerror(H1_LOG_MARK, parser->loglevel, 0, r,
                          APLOGNO() "%s field is missing ':' "
                          "separator: %.*s", parser->what,
                          (int)LOG_NAME_MAX_LEN, field);
            return HTTP_BAD_REQUEST;        /* abort bad request */
        }

        if (value == field) {
            ap_log_rerror(H1_LOG_MARK, parser->loglevel, 0, r,
                          APLOGNO() "%s field name is empty",
                          parser->what);
            return HTTP_BAD_REQUEST;
        }

        *value++ = '\0'; /* NUL-terminate at colon */

        if (strpbrk(field, "\t\n\v\f\r ")) {
            ap_log_rerror(H1_LOG_MARK, parser->loglevel, 0, r,
                          APLOGNO() "%s field name has whitespace: "
                          "%.*s", parser->what,
                          field_name_len(field), field);
            return HTTP_BAD_REQUEST;
        }

        while (*value == ' ' || *value == '\t') {
             ++value;            /* Skip to start of value   */
        }

        if (strpbrk(value, "\n\v\f\r")) {
            ap_log_rerror(H1_LOG_MARK, parser->loglevel, 0, r,
                          APLOGNO() "%s field value has bad "
                          "whitespace: %.*s", parser->what,
                          field_name_len(field), field);
            return HTTP_BAD_REQUEST;
        }
    }
    else {
        /* Using strict RFC7230 parsing */

        /* Ensure valid token chars before ':' per RFC 7230 3.2.4 */
        value = (char *)ap_scan_http_token(field);
        if ((value == field) || *value != ':') {
            ap_log_rerror(H1_LOG_MARK, parser->loglevel, 0, r,
                          APLOGNO() "%s field name is malformed: "
                          "%.*s", parser->what,
                          field_name_len(field), field);
            return HTTP_BAD_REQUEST;
        }

        *value++ = '\0'; /* NUL-terminate field name at ':' */

        while (*value == ' ' || *value == '\t') {
            ++value;     /* Skip LWS of value */
        }

        /* Reject value for all garbage input (CTRLs excluding HT)
         * e.g. only VCHAR / SP / HT / obs-text are allowed per
         * RFC7230 3.2.6 - leave all more explicit rule enforcement
         * for specific header handler logic later in the cycle
         */
        if (*ap_scan_http_field_content(value) != '\0') {
            ap_log_rerror(H1_LOG_MARK, parser->loglevel, 0, r,
                          APLOGNO() "%s field value is malformed: "
                          "%.*s", parser->what,
                          field_name_len(field), field);
            return HTTP_BAD_REQUEST;
        }
    }

    apr_table_addn(parser->head->headers, field, value);
    return OK;
}

/* Feed the parser with a block of len bytes: check the bytes of the lines
 * there and process each complete start line and field, the line not
 * complete at the block's end being copied. *used is set to the bytes used,
 * up to the head's end (phase H1_HEAD_DONE) or an error. Returns APR_SUCCESS
 * with *status set to OK or to the status of a start line, empty lines or a
 * field in error (logged), or else the line's error: APR_ENOSPC, or
 * APR_EINVAL with its cause in parser->line_error.
 */
static apr_status_t h1_head_feed(ap_h1_head_parser_t *parser,
                                 const char *buf, apr_size_t len,
                                 apr_size_t *used, int *status)
{
    const char *p = buf, *end = buf + len;
    const char *in = NULL;  /* the line's bytes in place, unless copied */
    apr_size_t in_len = 0;
    apr_status_t rv = APR_SUCCESS;

    *status = OK;
    while (p < end) {
        const char *lf = memchr(p, APR_ASCII_LF, end - p);
        const char *eol = (lf) ? lf : end; /* this line's bytes here end */
        apr_size_t limit, n;
        char *line;

        if (parser->line_state == H1_LINE_END) {
            /* After a field line, an obs-fold if this line starts with a
             * blank, otherwise the field is complete
             */
            if (*p == APR_ASCII_BLANK || *p == APR_ASCII_TAB) {
                if (in) {
                    h1_line_append(parser, in, in_len);
                    in = NULL;
                }
                /* Before folding, trim trailing blanks */
                while (parser->line_len) {
                    const char c = parser->line[parser->line_len - 1];
                    if (c != APR_ASCII_BLANK && c != APR_ASCII_TAB) {
                        break;
                    }
                    parser->line_len--;
                }
                parser->fold_sp = 1;
                parser->line_state = H1_LINE_FOLD;
            }
            else {
                line = h1_line_take(parser, in, in_len, &n);
                in = NULL;
                *status = h1_head_field(parser, line, n, &rv);
                if (*status != OK) {
                    break;
                }
                parser->line_state = H1_LINE_START;
            }
        }

        /* PR#43039: no NUL byte */
        if (memchr(p, '\0', eol - p)) {
            parser->line_error = LINE_NUL;
            rv = APR_EINVAL;
            break;
        }
        if (parser->line_state == H1_LINE_START) {
            /* RFC 9112 2.2: nothing to continue on a first field line */
            if (parser->phase == H1_HEAD_FIELDS
                && (*p == APR_ASCII_BLANK || *p == APR_ASCII_TAB)) {
                parser->line_error = LINE_LEADING_BLANK;
                rv = APR_EINVAL;
                break;
            }
            parser->line_state = H1_LINE_IN;
        }
        else if (parser->line_state == H1_LINE_FOLD) {
            /* Trim the continuation line's leading blanks */
            while (p < eol && (*p == APR_ASCII_BLANK || *p == APR_ASCII_TAB)) {
                p++;
            }
            if (p == end) {
                break;
            }
            /* Fail if the line is composed of blanks only */
            if (*p == APR_ASCII_CR || *p == APR_ASCII_LF) {
                h1_line_for_logs(parser);
                parser->line_error = LINE_BLANK_FOLD;
                rv = APR_EINVAL;
                break;
            }
            parser->line_state = H1_LINE_IN;
        }

        /* Would this exceed the limit? If so, we'll die. */
        limit = h1_line_limit(parser);
        n = ((in) ? in_len : parser->line_len) + parser->fold_sp;
        if (n + (eol - p) >= limit) {
            if (parser->phase == H1_HEAD_FIELDS) {
                /* The field filled up to the limit for the logs */
                if (in) {
                    h1_line_append(parser, in, in_len);
                    in = NULL;
                }
                if (parser->fold_sp && parser->line_len + 1 < limit) {
                    h1_line_append(parser, " ", 1);
                }
                if (parser->line_len + 1 < limit) {
                    n = limit - 1 - parser->line_len;
                    h1_line_append(parser, p, (n < (apr_size_t)(eol - p))
                                              ? n : (apr_size_t)(eol - p));
                }
                h1_line_for_logs(parser);
            }
            rv = APR_ENOSPC;
            break;
        }
        if (eol > p) {
            if (parser->fold_sp) {
                h1_line_append(parser, " ", 1);
                parser->fold_sp = 0;
            }
            if (!parser->line_len) {
                in = p;
                in_len = eol - p;
            }
            else {
                h1_line_append(parser, p, eol - p);
            }
        }
        if (!lf) {
            p = end;
            break;
        }
        p = lf + 1;

        /* The line is complete: strip its CR, required with Strict */
        n = (in) ? in_len : parser->line_len;
        if (n && ((in) ? in : parser->line)[n - 1] == APR_ASCII_CR) {
            if (in) {
                in_len = --n;
            }
            else {
                parser->line_len = --n;
            }
        }
        else if (parser->opts.flags & AP_H1_HEAD_OPT_STRICT) {
            parser->line_error = LINE_NOT_CRLF;
            rv = APR_EINVAL;
            break;
        }

        if (parser->phase == H1_HEAD_START) {
            parser->line_state = H1_LINE_START;
            if (!n) {
                /* Skip the empty lines before the start line, up to the
                 * limit
                 */
                in = NULL;
                if (++parser->blank_lines > parser->opts.max_blank_lines) {
                    ap_log_rerror(H1_LOG_MARK, parser->loglevel, 0, parser->r,
                                  APLOGNO() "too many empty lines before the "
                                  "%s", parser->what_start);
                    *status = HTTP_BAD_REQUEST;
                    break;
                }
                continue;
            }
            line = h1_line_take(parser, in, in_len, &n);
            in = NULL;
            *status = h1_head_start_line(parser, line, n);
            if (*status != OK) {
                break;
            }
            if (parser->opts.kind == AP_H1_HEAD_REQUEST
                && !*parser->head->protocol) {
                /* HTTP/0.9: no header section */
                parser->phase = H1_HEAD_DONE;
                break;
            }
            parser->phase = H1_HEAD_FIELDS;
        }
        else if (!n) {
            /* The empty line ending the head */
            in = NULL;
            parser->line_state = H1_LINE_START;
            parser->phase = H1_HEAD_DONE;
            break;
        }
        else {
            parser->line_state = H1_LINE_END;
        }
    }
    if (in && rv == APR_SUCCESS && *status == OK) {
        /* The line goes on in the next blocks */
        h1_line_append(parser, in, in_len);
    }
    *used = p - buf;
    return rv;
}

/* The bytes peeked at once */
#define H1_HEAD_READ_SIZE AP_IOBUFSIZE

AP_DECLARE(int) ap_h1_head_parse(ap_h1_head_parser_t *parser,
                                 ap_filter_t *f,
                                 apr_read_type_e block,
                                 ap_h1_head_t **head)
{
    request_rec *r = parser->r;
    apr_status_t rv = APR_SUCCESS;
    int status = OK;

    *head = NULL;
    if (parser->phase == H1_HEAD_DONE) {
        *head = parser->head;
        return OK;
    }
    if (parser->phase == H1_HEAD_FAILED) {
        goto failed;
    }
    if (!parser->bb) {
        parser->bb = apr_brigade_create(parser->pool, f->c->bucket_alloc);
    }

    /* Read the head in blocks until its empty line (past the empty lines
     * before the start line, which browsers tack on to the end of POSTs to
     * support old CERN webservers), a read error, the connection closes
     * (EOF), we timeout, or the rules or limits fail.
     */
    while (parser->phase != H1_HEAD_DONE) {
        apr_size_t used = 0;
        apr_bucket *e;

        /* Peek at what's there, so that nothing after the head is read */
        rv = ap_get_brigade(f, parser->bb, AP_MODE_SPECULATIVE, block,
                            H1_HEAD_READ_SIZE);
        if (rv == APR_SUCCESS && APR_BRIGADE_EMPTY(parser->bb)) {
            /* Non blocking (which would block) gets us here, otherwise
             * someone didn't block
             */
            rv = (block == APR_NONBLOCK_READ) ? APR_EAGAIN : APR_EGENERAL;
        }
        for (e = APR_BRIGADE_FIRST(parser->bb);
             e != APR_BRIGADE_SENTINEL(parser->bb)
             && rv == APR_SUCCESS && status == OK
             && parser->phase != H1_HEAD_DONE;
             e = APR_BUCKET_NEXT(e)) {
            const char *str;
            apr_size_t len, n;

            /* APR_EOF on EOS (the head is not complete) */
            if (APR_BUCKET_IS_EOS(e)) {
                rv = APR_EOF;
                break;
            }
            rv = apr_bucket_read(e, &str, &len, APR_BLOCK_READ);
            if (rv == APR_SUCCESS && len) {
                rv = h1_head_feed(parser, str, len, &n, &status);
                used += n;
            }
        }
        apr_brigade_cleanup(parser->bb);

        /* Consume the bytes used */
        if (used) {
            apr_status_t urv;
            apr_off_t got = 0;

            parser->head->length += used;
            urv = ap_get_brigade(f, parser->bb, AP_MODE_READBYTES, block,
                                 used);
            if (urv == APR_SUCCESS) {
                apr_brigade_length(parser->bb, 1, &got);
                if (got != (apr_off_t)used) {
                    ap_log_rerror(H1_LOG_MARK, APLOG_ERR, 0, r, APLOGNO()
                                  "reading the %s: %" APR_OFF_T_FMT " bytes "
                                  "consumed of the %" APR_SIZE_T_FMT " peeked",
                                  parser->what, got, used);
                    urv = APR_EGENERAL;
                }
            }
            apr_brigade_cleanup(parser->bb);
            if (urv != APR_SUCCESS && rv == APR_SUCCESS && status == OK) {
                rv = urv;
            }
        }
        if (status != OK) {
            goto cleanup;
        }
        if (rv != APR_SUCCESS) {
            goto read_error;
        }
    }

    if (parser->opts.flags & AP_H1_HEAD_OPT_MERGE) {
        /* Combine multiple message-header fields with the same
         * field-name, following RFC 2616, 4.2.
         */
        apr_table_compress(parser->head->headers, APR_OVERLAP_TABLES_MERGE);

        /* enforce LimitRequestFieldSize for merged headers */
        if (!apr_table_do(table_do_fn_check_lengths, parser,
                          parser->head->headers, NULL)) {
            status = HTTP_BAD_REQUEST;
            rv = APR_ENOSPC;
            goto cleanup;
        }
    }
    parser->phase = H1_HEAD_DONE;
    *head = parser->head;
    return OK;

read_error:
    if (APR_STATUS_IS_EAGAIN(rv) && block == APR_NONBLOCK_READ) {
        return AGAIN;
    }
    status = h1_head_read_error(parser, rv);

cleanup:
    /* Failed or ended, final */
    apr_brigade_cleanup(parser->bb);
    if ((parser->opts.flags & AP_H1_HEAD_OPT_BACKEND) && status != DONE) {
        status = ((status == HTTP_REQUEST_TIME_OUT) ? HTTP_GATEWAY_TIME_OUT
                                                    : HTTP_BAD_GATEWAY);
    }
    parser->phase = H1_HEAD_FAILED;
    parser->status = status;
    parser->rv = (rv != APR_SUCCESS) ? rv : APR_EINVAL;

failed:
    if (parser->head->start_line) {
        *head = parser->head;
    }
    return parser->status;
}

AP_DECLARE(void) ap_get_mime_headers_core(request_rec *r, apr_bucket_brigade *bb)
{
    ap_h1_head_opts_t opts;
    ap_h1_head_parser_t *parser;
    ap_h1_head_t *head;
    int rc;

    /* A header section with the client side's rules, merged */
    ap_h1_head_opts_init(&opts, r, AP_H1_HEAD_HEADERS, 0);
    parser = ap_h1_head_parser_create(r->pool, r, &opts);
    rc = ap_h1_head_parse(parser, r->proto_input_filters, APR_BLOCK_READ,
                          &head);
    if (rc != OK) {
        r->status = (rc == DONE) ? HTTP_BAD_REQUEST : rc;
        return;
    }
    /* Copied into the caller's r->headers_in, the table itself since
     * callers may hold it, merged: apr_table_overlap() adds the headers then
     * compresses the whole table with APR_OVERLAP_TABLES_MERGE, as reading
     * the headers into it does
     */
    apr_table_overlap(r->headers_in, head->headers, APR_OVERLAP_TABLES_MERGE);
}

AP_DECLARE(void) ap_get_mime_headers(request_rec *r)
{
    conn_rec *c = r->connection;
    apr_bucket_brigade *tmp_bb = ap_acquire_brigade(c);
    ap_get_mime_headers_core(r, tmp_bb);
    ap_release_brigade(c, tmp_bb);
}

AP_DECLARE(request_rec *) ap_create_request(conn_rec *conn)
{
    request_rec *r;
    apr_pool_t *p;

    apr_pool_create(&p, conn->pool);
    apr_pool_tag(p, "request");
    r = apr_pcalloc(p, sizeof(request_rec));
    AP_READ_REQUEST_ENTRY((intptr_t)r, (uintptr_t)conn);
    r->pool            = p;
    r->connection      = conn;
    r->server          = conn->base_server;

    r->user            = NULL;
    r->ap_auth_type    = NULL;

    r->allowed_methods = ap_make_method_list(p, 2);

    r->headers_in      = apr_table_make(r->pool, 25);
    r->trailers_in     = apr_table_make(r->pool, 5);
    r->subprocess_env  = apr_table_make(r->pool, 25);
    r->headers_out     = apr_table_make(r->pool, 12);
    r->err_headers_out = apr_table_make(r->pool, 5);
    r->trailers_out    = apr_table_make(r->pool, 5);
    r->notes           = apr_table_make(r->pool, 5);

    r->request_config  = ap_create_request_config(r->pool);
    /* Must be set before we run create request hook */

    r->proto_output_filters = conn->output_filters;
    r->output_filters  = r->proto_output_filters;
    r->proto_input_filters = conn->input_filters;
    r->input_filters   = r->proto_input_filters;
    ap_run_create_request(r);
    r->per_dir_config  = r->server->lookup_defaults;

    r->sent_bodyct     = 0;                      /* bytect isn't for body */

    r->read_length     = 0;
    r->read_body       = REQUEST_NO_BODY;

    r->status          = HTTP_OK;  /* Until further notice */
    r->header_only     = 0;
    r->the_request     = NULL;

    /* Begin by presuming any module can make its own path_info assumptions,
     * until some module interjects and changes the value.
     */
    r->used_path_info = AP_REQ_DEFAULT_PATH_INFO;

    r->useragent_addr = conn->client_addr;
    r->useragent_ip = conn->client_ip;

    return r;
}

/* Apply the server's timeout/config to the connection/request. */
static void apply_server_config(request_rec *r)
{
    apr_socket_t *csd;

    csd = ap_get_conn_socket(r->connection);
    apr_socket_timeout_set(csd, r->server->timeout);

    r->per_dir_config = r->server->lookup_defaults;
}

typedef enum {
    http_error_none,
    http_error_badprotocol,
    http_error_reject09,
    http_error_badmethod09,
} http_error;

static http_error r_assign_protocol(request_rec *r,
                                    const char *protocol,
                                    int strict)
{
    int proto_num;
    http_error error = http_error_none;

    if (protocol[0] == 'H' && protocol[1] == 'T'
            && protocol[2] == 'T' && protocol[3] == 'P'
            && protocol[4] == '/' && apr_isdigit(protocol[5])
            && protocol[6] == '.' && apr_isdigit(protocol[7])
            && !protocol[8] && protocol[5] != '0') {
        r->assbackwards = 0;
        proto_num = HTTP_VERSION(protocol[5] - '0', protocol[7] - '0');
        if (proto_num > HTTP_VERSION(1, 1) && proto_num < HTTP_VERSION(2, 0)) {
            /* A 1.x minor above ours is treated as the highest we support
             * (RFC 9112 2.3), r->protocol keeping what was received.
             */
            proto_num = HTTP_VERSION(1, 1);
        }
    }
    else if ((protocol[0] == 'H' || protocol[0] == 'h')
                 && (protocol[1] == 'T' || protocol[1] == 't')
                 && (protocol[2] == 'T' || protocol[2] == 't')
                 && (protocol[3] == 'P' || protocol[3] == 'p')
                 && protocol[4] == '/' && apr_isdigit(protocol[5])
                 && protocol[6] == '.' && apr_isdigit(protocol[7])
                 && !protocol[8] && protocol[5] != '0') {
        r->assbackwards = 0;
        proto_num = HTTP_VERSION(protocol[5] - '0', protocol[7] - '0');
        if (proto_num > HTTP_VERSION(1, 1) && proto_num < HTTP_VERSION(2, 0)) {
            proto_num = HTTP_VERSION(1, 1);
        }
        if (strict && error == http_error_none)
            error = http_error_badprotocol;
        else
            protocol = apr_psprintf(r->pool, "HTTP/%d.%d", HTTP_VERSION_MAJOR(proto_num),
                                    HTTP_VERSION_MINOR(proto_num));
    }
    else if (protocol[0]) {
        proto_num = HTTP_VERSION(0, 9);
        if (error == http_error_none)
            error = http_error_badprotocol;
    }
    else {
        r->assbackwards = 1;
        protocol = "HTTP/0.9";
        proto_num = HTTP_VERSION(0, 9);
    }
    r->protocol = protocol;
    r->proto_num = proto_num;
    return error;
}

AP_DECLARE(int) ap_assign_request_line(request_rec *r,
                                       const char *method, const char *uri,
                                       const char *protocol)
{
    core_server_config *conf = ap_get_core_module_config(r->server->module_config);
    int strict = (conf->http_conformance != AP_HTTP_CONFORMANCE_UNSAFE);
    http_error error = r_assign_protocol(r, protocol, strict);

    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                  "assigned protocol: %s, error=%d", r->protocol, error);

    /* Determine the method_number and parse the uri prior to invoking error
     * handling, such that these fields are available for substitution
     */
    r->method = method;
    r->method_number = ap_method_number_of(r->method);
    if (r->method_number == M_GET && r->method[0] == 'H')
        r->header_only = 1;

    /* For internal integrity and palloc efficiency, reconstruct the_request
     * in one palloc, using only single SP characters, per spec.
     */
    r->the_request = apr_pstrcat(r->pool, r->method, *uri ? " " : NULL, uri,
                                 *r->protocol ? " " : NULL, r->protocol, NULL);
    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                  "assigned request_line: %s, error=%d", r->the_request, error);

    ap_parse_uri(r, uri);
    if (r->status == HTTP_OK
            && (r->parsed_uri.path != NULL)
            && (r->parsed_uri.path[0] != '/')
            && (r->method_number != M_OPTIONS
                || strcmp(r->parsed_uri.path, "*") != 0)) {
        /* Invalid request-target per RFC 7230 section 5.3 */
        r->status = HTTP_BAD_REQUEST;
    }

    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                  "parsed uri: r->status=%d, error=%d", r->status, error);
    /* With the request understood, we can consider HTTP/0.9 specific errors */
    if (r->proto_num == HTTP_VERSION(0, 9) && error == http_error_none) {
        if (conf->http09_enable == AP_HTTP09_DISABLE)
            error = http_error_reject09;
        else if (strict && (r->method_number != M_GET || r->header_only))
            error = http_error_badmethod09;
    }

    /* Now that the method, uri and protocol are all processed,
     * we can safely resume any deferred error reporting
     */
    if (error != http_error_none) {
        switch (error) {
        case http_error_badprotocol:
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(10388)
                          "HTTP Request: Unrecognized protocol '%.*s' "
                          "(perhaps whitespace was injected?)",
                          field_name_len(r->protocol), r->protocol);
            break;
        case http_error_reject09:
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02401)
                          "HTTP Request: Rejected HTTP/0.9 request");
            break;
        case http_error_badmethod09:
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03444)
                          "HTTP Request: Invalid method token: '%.*s'"
                          " (only GET is allowed for HTTP/0.9 requests)",
                          field_name_len(r->method), r->method);
            break;
        default:
            break;
        }
        r->status = HTTP_BAD_REQUEST;
        goto failed;
    }

    if (conf->http_methods == AP_HTTP_METHODS_REGISTERED
            && r->method_number == M_INVALID) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02423)
                      "HTTP Request Line; Unrecognized HTTP method: '%.*s' "
                      "(disallowed by RegisteredMethods)",
                      field_name_len(r->method), r->method);
        r->status = HTTP_NOT_IMPLEMENTED;
        /* This can't happen in an HTTP/0.9 request, we verified GET above */
        goto failed;
    }

    if (r->status != HTTP_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(03450)
                      "HTTP Request Line; Unable to parse URI: '%.*s'",
                      field_name_len(r->uri), r->uri);
        goto failed;
    }

    if (strict) {
        if (r->parsed_uri.fragment) {
            /* RFC3986 3.5: no fragment */
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02421)
                          "HTTP Request Line; URI must not contain a fragment");
            r->status = HTTP_BAD_REQUEST;
            goto failed;
        }
        if (r->parsed_uri.user || r->parsed_uri.password) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02422)
                          "HTTP Request Line; URI must not contain a "
                          "username/password");
            r->status = HTTP_BAD_REQUEST;
            goto failed;
        }
    }
    return 1;

failed:
    if (error != http_error_none && r->proto_num == HTTP_VERSION(0, 9)) {
        /* Send all parsing and protocol error response with 1.x behavior,
         * and reserve 505 errors for actual HTTP protocols presented.
         * As called out in RFC7230 3.5, any errors parsing the protocol
         * from the request line are nearly always misencoded HTTP/1.x
         * requests. Only a valid 0.9 request with no parsing errors
         * at all may be treated as a simple request, if allowed.
         */
        r->assbackwards = 0;
        r->connection->keepalive = AP_CONN_CLOSE;
        r->proto_num = HTTP_VERSION(1, 0);
        r->protocol  = "HTTP/1.0";
    }
    return 0;

}

AP_DECLARE(request_rec *) ap_read_request(conn_rec *conn)
{
    request_rec *r = NULL;
    (void)ap_read_request_ex(&r, conn, APR_BLOCK_READ);
    return r;
}

AP_DECLARE(apr_status_t) ap_read_request_ex(request_rec **out_r, conn_rec *conn,
                                            apr_read_type_e block)
{
    apr_status_t rv;
    int access_status;
    apr_bucket_brigade *tmp_bb;
    apr_bucket *e, *bdata = NULL;
    ap_bucket_error *berr = NULL;
    ap_bucket_request *breq = NULL;
    const char *method, *uri, *protocol;
    apr_table_t *headers;
    request_rec *r;

    r = (conn->cs) ? conn->cs->partial_request : NULL;
    if (conn->keepalive == AP_CONN_KEEPALIVE) {
        conn->keepalive = AP_CONN_UNKNOWN;
    }
    if (!r) {
        r = ap_create_request(conn);
        ap_run_pre_read_request(r, conn);
        r->request_time = apr_time_now();
    }

    tmp_bb = ap_acquire_brigade(conn);

    rv = ap_get_brigade(r->proto_input_filters, tmp_bb, AP_MODE_READBYTES, block, 0);
    if (APR_STATUS_IS_EAGAIN(rv) && block == APR_NONBLOCK_READ) {
        if (conn->cs && conn->cs->timed_out) {
            /* The MPM's wait for the rest of the request timed out and there
             * is still nothing to read (the server's Timeout, a deadline of
             * mod_reqtimeout's would have failed the read): answer it as a
             * blocking read would.
             */
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO()
                          "request failed: timeout reading the request");
            access_status = HTTP_REQUEST_TIME_OUT;
            goto die_unusable_input;
        }
        AP_DEBUG_ASSERT(conn->cs != NULL);
        conn->cs->partial_request = r;
        r = NULL;
        goto done;
    }
    if (rv != APR_SUCCESS || APR_BRIGADE_EMPTY(tmp_bb)) {
        /* Not worth dying with. */
        conn->keepalive = AP_CONN_CLOSE;
        apr_pool_destroy(r->pool);
        goto ignore;
    }

    for (e = APR_BRIGADE_FIRST(tmp_bb);
         e != APR_BRIGADE_SENTINEL(tmp_bb);
         e = APR_BUCKET_NEXT(e))
    {
        if (AP_BUCKET_IS_REQUEST(e)) {
            if (!breq) breq = e->data;
        }
        else if (AP_BUCKET_IS_ERROR(e)) {
            if (!berr) berr = e->data;
        }
        else if (!APR_BUCKET_IS_METADATA(e) && e->length != 0) {
            if (!bdata) bdata = e;
            break;
        }
    }

    /* If there is a request, we always process it, as it defines
     * the context in which a potential error bucket is handled. */
    if (breq) {
        if (conn->cs) {
            conn->cs->partial_request = NULL;
        }

        if (apr_pool_is_ancestor(r->pool, breq->pool)) {
            method = breq->method;
            uri = breq->uri;
            protocol = breq->protocol;
            headers = breq->headers;
        }
        else {
            method = apr_pstrdup(r->pool, breq->method);
            uri = apr_pstrdup(r->pool, breq->uri);
            protocol = apr_pstrdup(r->pool, breq->protocol);
            headers = breq->headers? apr_table_clone(r->pool, breq->headers) : NULL;
        }

        if (!method || !uri || !protocol) {
            access_status = berr ? berr->status : HTTP_INTERNAL_SERVER_ERROR;
            goto die_unusable_input;
        }

        if (headers) {
            r->headers_in = headers;
        }

        ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                      "checking request: %s %s %s",
                      method, uri, protocol);

        if (!ap_assign_request_line(r, method, uri, protocol)) {
            apr_brigade_cleanup(tmp_bb);
            switch (r->status) {
            case HTTP_REQUEST_URI_TOO_LARGE:
            case HTTP_BAD_REQUEST:
            case HTTP_VERSION_NOT_SUPPORTED:
            case HTTP_NOT_IMPLEMENTED:
                if (r->status == HTTP_REQUEST_URI_TOO_LARGE) {
                    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00565)
                                  "request failed: client's request-line exceeds LimitRequestLine (longer than %d)",
                                  r->server->limit_req_line);
                }
                else if (!strcmp("-", r->method)) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00566)
                                  "request failed: malformed request line");
                }
                access_status = r->status;
                goto die_unusable_input;

            case HTTP_REQUEST_TIME_OUT:
                /* Just log, no further action on this connection. */
                ap_update_child_status(conn->sbh, SERVER_BUSY_LOG, NULL);
                if (!r->connection->keepalives)
                    ap_run_log_transaction(r);
                break;
            }
            /* Not worth dying with. */
            conn->keepalive = AP_CONN_CLOSE;
            apr_pool_destroy(r->pool);
            goto ignore;
        }
    }
    if (berr) {
        /* APLOG_ERR already raised by filters (eventually). */
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(10467)
                      "request failed: error %i at start of input",
                      berr->status);
        access_status = berr->status;
        goto die_unusable_input;
    }
    if (!breq) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10389)
                      "request failed: neither request bucket nor error "
                      "at start of input");
        access_status = HTTP_INTERNAL_SERVER_ERROR;
        goto die_unusable_input;
    }
    if (bdata) {
        /* Since processing of a request body depends on knowing the request, we
         * cannot handle any data here. For example, chunked-encoding filters are
         * added after the request is read, so any data buckets here will not
         * have been de-chunked.
         */
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(10391)
                      "request failed: seeing DATA bucket (len=%" APR_SIZE_T_FMT ") "
                      "of request body, too early to process",
                      bdata->length);
        access_status = HTTP_INTERNAL_SERVER_ERROR;
        goto die_unusable_input;
    }

    apr_brigade_cleanup(tmp_bb);

    /* We may have been in keep_alive_timeout mode, so toggle back
     * to the normal timeout mode as we fetch the header lines,
     * as necessary.
     */
    apply_server_config(r);

    if (!r->assbackwards) {
        const char *clen = apr_table_get(r->headers_in, "Content-Length");
        if (clen) {
            apr_off_t cl;

            if (!ap_parse_strict_length(&cl, clen)) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(10242)
                              "client sent invalid Content-Length "
                              "(%s): %s", clen, r->uri);
                access_status = HTTP_BAD_REQUEST;
                goto die_unusable_input;
            }
        }
    }

    /*
     * Add HTTP_IN here to ensure that content and HEADERS buckets are processed
     * accordingly, e.g. populating r->trailers_in for example.
     */
    ap_add_input_filter_handle(ap_http_input_filter_handle,
                               NULL, r, r->connection);

    /* Validate Host/Expect headers and select vhost. */
    if (!ap_check_request_header(r)) {
        /* we may have switched to another server still */
        apply_server_config(r);
        access_status = r->status;
        goto die_before_hooks;
    }

    /* we may have switched to another server */
    apply_server_config(r);

    if ((access_status = ap_post_read_request(r))) {
        goto die;
    }

    AP_READ_REQUEST_SUCCESS((uintptr_t)r, (char *)r->method,
                            (char *)r->uri, (char *)r->server->defn_name,
                            r->status);
done:
    ap_release_brigade(conn, tmp_bb);
    return (*out_r = r) ? APR_SUCCESS : APR_EAGAIN;

    /* Everything falls through on failure */

die_unusable_input:
    /* Input filters are in an undeterminate state, cleanup (including
     * CORE_IN's socket) such that any further attempt to read is EOF.
     */
    {
        ap_filter_t *f = conn->input_filters;
        while (f) {
            ap_filter_reinstate_brigade(f, tmp_bb, NULL);
            apr_brigade_cleanup(tmp_bb);
            if (f->frec == ap_core_input_filter_handle) {
                break;
            }
            ap_remove_input_filter(f);
            f = f->next;
        }
        conn->input_filters = r->input_filters = f;
        conn->keepalive = AP_CONN_CLOSE;
    }

die_before_hooks:
    /* First call to ap_die() (non recursive) */
    r->status = HTTP_OK;

die:
    ap_die(access_status, r);

    /* ap_die() sent the response through the output filters, we must now
     * end the request with an EOR bucket for stream/pipeline accounting.
     */
    {
        apr_bucket_brigade *eor_bb;
        eor_bb = ap_acquire_brigade(conn);
        APR_BRIGADE_INSERT_TAIL(eor_bb,
                                ap_bucket_eor_create(conn->bucket_alloc, r));
        ap_pass_brigade(conn->output_filters, eor_bb);
        ap_release_brigade(conn, eor_bb);
    }

ignore:
    ap_release_brigade(conn, tmp_bb);
    *out_r = r = NULL;
    if (conn->cs) {
        conn->cs->partial_request = NULL;
    }
    AP_READ_REQUEST_FAILURE((uintptr_t)r);
    return APR_EGENERAL;
}

AP_DECLARE(int) ap_post_read_request(request_rec *r)
{
    int status;

    if ((status = ap_run_post_read_request(r))) {
        return status;
    }

    /* Enforce http(s) only scheme for non-forward-proxy requests */
    if (!r->proxyreq
            && r->parsed_uri.scheme
            && (ap_cstr_casecmpn(r->parsed_uri.scheme, "http", 4) != 0
                || (r->parsed_uri.scheme[4] != '\0'
                    && (apr_tolower(r->parsed_uri.scheme[4]) != 's'
                        || r->parsed_uri.scheme[5] != '\0')))) {
        return HTTP_BAD_REQUEST;
    }

    return OK;
}

/* if a request with a body creates a subrequest, remove original request's
 * input headers which pertain to the body which has already been read.
 * out-of-line helper function for ap_set_sub_req_protocol.
 */

static void strip_headers_request_body(request_rec *rnew)
{
    apr_table_unset(rnew->headers_in, "Content-Encoding");
    apr_table_unset(rnew->headers_in, "Content-Language");
    apr_table_unset(rnew->headers_in, "Content-Length");
    apr_table_unset(rnew->headers_in, "Content-Location");
    apr_table_unset(rnew->headers_in, "Content-MD5");
    apr_table_unset(rnew->headers_in, "Content-Range");
    apr_table_unset(rnew->headers_in, "Content-Type");
    apr_table_unset(rnew->headers_in, "Expires");
    apr_table_unset(rnew->headers_in, "Last-Modified");
    apr_table_unset(rnew->headers_in, "Transfer-Encoding");
}

/*
 * A couple of other functions which initialize some of the fields of
 * a request structure, as appropriate for adjuncts of one kind or another
 * to a request in progress.  Best here, rather than elsewhere, since
 * *someone* has to set the protocol-specific fields...
 */

AP_DECLARE(void) ap_set_sub_req_protocol(request_rec *rnew,
                                         const request_rec *r)
{
    rnew->the_request     = r->the_request;  /* Keep original request-line */

    rnew->assbackwards    = 1;   /* Don't send headers from this. */
    rnew->no_local_copy   = 1;   /* Don't try to send HTTP_NOT_MODIFIED for a
                                  * fragment. */
    rnew->method          = "GET";
    rnew->method_number   = M_GET;
    rnew->protocol        = "INCLUDED";

    rnew->status          = HTTP_OK;

    rnew->headers_in      = apr_table_copy(rnew->pool, r->headers_in);
    rnew->trailers_in     = apr_table_copy(rnew->pool, r->trailers_in);

    /* did the original request have a body?  (e.g. POST w/SSI tags)
     * if so, make sure the subrequest doesn't inherit body headers
     */
    if (!r->kept_body && (apr_table_get(r->headers_in, "Content-Length")
        || apr_table_get(r->headers_in, "Transfer-Encoding"))) {
        strip_headers_request_body(rnew);
    }
    rnew->subprocess_env  = apr_table_copy(rnew->pool, r->subprocess_env);
    rnew->headers_out     = apr_table_make(rnew->pool, 5);
    rnew->err_headers_out = apr_table_make(rnew->pool, 5);
    rnew->trailers_out    = apr_table_make(rnew->pool, 5);
    rnew->notes           = apr_table_make(rnew->pool, 5);

    rnew->expecting_100   = r->expecting_100;
    rnew->read_length     = r->read_length;
    rnew->read_body       = REQUEST_NO_BODY;

    rnew->main = (request_rec *) r;
}

static void end_output_stream(request_rec *r, int status)
{
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb;
    apr_bucket *b;

    bb = apr_brigade_create(r->pool, c->bucket_alloc);
    if (status != OK) {
        b = ap_bucket_error_create(status, NULL, r->pool, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
    }
    b = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    ap_pass_brigade(r->output_filters, bb);
    apr_brigade_cleanup(bb);
}

AP_DECLARE(void) ap_finalize_sub_req_protocol(request_rec *sub)
{
    /* tell the filter chain there is no more content coming */
    if (!sub->eos_sent) {
        end_output_stream(sub, OK);
    }
}

/* finalize_request_protocol is called at completion of sending the
 * response.  Its sole purpose is to send the terminating protocol
 * information for any wrappers around the response message body
 * (i.e., transfer encodings).  It should have been named finalize_response.
 */
AP_DECLARE(void) ap_finalize_request_protocol(request_rec *r)
{
    int status = ap_discard_request_body(r);

    /* tell the filter chain there is no more content coming */
    if (!r->eos_sent) {
        end_output_stream(r, status);
    }
}

/*
 * Support for the Basic authentication protocol, and a bit for Digest.
 */
AP_DECLARE(void) ap_note_auth_failure(request_rec *r)
{
    const char *type = ap_auth_type(r);
    if (type) {
        ap_run_note_auth_failure(r, type);
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00571)
                      "need AuthType to note auth failure: %s", r->uri);
    }
}

AP_DECLARE(void) ap_note_basic_auth_failure(request_rec *r)
{
    ap_note_auth_failure(r);
}

AP_DECLARE(void) ap_note_digest_auth_failure(request_rec *r)
{
    ap_note_auth_failure(r);
}

AP_DECLARE(int) ap_get_basic_auth_pw(request_rec *r, const char **pw)
{
    const char *t, *auth_line;

    if (!(t = ap_auth_type(r)) || ap_cstr_casecmp(t, "Basic"))
        return DECLINED;

    if (!ap_auth_name(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00572) 
                      "need AuthName: %s", r->uri);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    auth_line = apr_table_get(r->headers_in,
                              (PROXYREQ_PROXY == r->proxyreq)
                                  ? "Proxy-Authorization" : "Authorization");

    if (!auth_line) {
        ap_note_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }

    if (ap_cstr_casecmp(ap_getword(r->pool, &auth_line, ' '), "Basic")) {
        /* Client tried to authenticate using wrong auth scheme */
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00573)
                      "client used wrong authentication scheme: %s", r->uri);
        ap_note_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }

    while (*auth_line == ' ' || *auth_line == '\t') {
        auth_line++;
    }

    t = ap_pbase64decode(r->pool, auth_line);
    r->user = ap_getword_nulls (r->pool, &t, ':');
    apr_table_setn(r->notes, AP_GET_BASIC_AUTH_PW_NOTE, "1");
    r->ap_auth_type = "Basic";

    *pw = t;

    return OK;
}

AP_DECLARE(apr_status_t) ap_get_basic_auth_components(const request_rec *r,
                                                      const char **username,
                                                      const char **password)
{
    const char *auth_header;
    const char *credentials;
    const char *decoded;
    const char *user;

    auth_header = (PROXYREQ_PROXY == r->proxyreq) ? "Proxy-Authorization"
                                                  : "Authorization";
    credentials = apr_table_get(r->headers_in, auth_header);

    if (!credentials) {
        /* No auth header. */
        return APR_EINVAL;
    }

    if (ap_cstr_casecmp(ap_getword(r->pool, &credentials, ' '), "Basic")) {
        /* These aren't Basic credentials. */
        return APR_EINVAL;
    }

    while (*credentials == ' ' || *credentials == '\t') {
        credentials++;
    }

    /* XXX Our base64 decoding functions don't actually error out if the string
     * we give it isn't base64; they'll just silently stop and hand us whatever
     * they've parsed up to that point.
     *
     * Since this function is supposed to be a drop-in replacement for the
     * deprecated ap_get_basic_auth_pw(), don't fix this for 2.4.x.
     */
    decoded = ap_pbase64decode(r->pool, credentials);
    user = ap_getword_nulls(r->pool, &decoded, ':');

    if (username) {
        *username = user;
    }
    if (password) {
        *password = decoded;
    }

    return APR_SUCCESS;
}

struct content_length_ctx {
    int data_sent;  /* true if the C-L filter has already sent at
                     * least one bucket on to the next output filter
                     * for this request
                     */
    apr_bucket_brigade *tmpbb;
};

/* This filter computes the content length, but it also computes the number
 * of bytes sent to the client.  This means that this filter will always run
 * through all of the buckets in all brigades
 */
AP_CORE_DECLARE_NONSTD(apr_status_t) ap_content_length_filter(
    ap_filter_t *f,
    apr_bucket_brigade *b)
{
    request_rec *r = f->r;
    struct content_length_ctx *ctx;
    apr_bucket *e;
    int eos = 0;
    apr_read_type_e eblock = APR_NONBLOCK_READ;

    ctx = f->ctx;
    if (!ctx) {
        f->ctx = ctx = apr_palloc(r->pool, sizeof(*ctx));
        ctx->data_sent = 0;
        ctx->tmpbb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    }

    /* Loop through the brigade to count the length. To avoid
     * arbitrary memory consumption with morphing bucket types, this
     * loop will stop and pass on the brigade when necessary. */
    e = APR_BRIGADE_FIRST(b);
    while (e != APR_BRIGADE_SENTINEL(b)) {
        apr_status_t rv;

        if (APR_BUCKET_IS_EOS(e)) {
            eos = 1;
            break;
        }
        /* For a flush bucket, fall through to pass the brigade and
         * flush now. */
        else if (APR_BUCKET_IS_FLUSH(e)) {
            e = APR_BUCKET_NEXT(e);
        }
        /* For metadata bucket types other than FLUSH, loop. */
        else if (APR_BUCKET_IS_METADATA(e)) {
            e = APR_BUCKET_NEXT(e);
            continue;
        }
        /* For determinate length data buckets, count the length and
         * continue. */
        else if (e->length != (apr_size_t)-1) {
            r->bytes_sent += e->length;
            e = APR_BUCKET_NEXT(e);
            continue;
        }
        /* For indeterminate length data buckets, perform one read. */
        else /* e->length == (apr_size_t)-1 */ {
            apr_size_t len;
            const char *ignored;
        
            rv = apr_bucket_read(e, &ignored, &len, eblock);
            if ((rv != APR_SUCCESS) && !APR_STATUS_IS_EAGAIN(rv)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00574)
                              "ap_content_length_filter: "
                              "apr_bucket_read() failed");
                return rv;
            }
            if (rv == APR_SUCCESS) {
                eblock = APR_NONBLOCK_READ;
                e = APR_BUCKET_NEXT(e);
                r->bytes_sent += len;
            }
            else if (APR_STATUS_IS_EAGAIN(rv)) {
                apr_bucket *flush;

                /* Next read must block. */
                eblock = APR_BLOCK_READ;

                /* Ensure the last bucket to pass down is a flush if
                 * the next read will block. */
                flush = apr_bucket_flush_create(f->c->bucket_alloc);
                APR_BUCKET_INSERT_BEFORE(e, flush);
            }
        }

        /* Optimization: if the next bucket is EOS (directly after a
         * bucket morphed to the heap, or a flush), short-cut to
         * handle EOS straight away - allowing C-L to be determined
         * for content which is already entirely in memory. */
        if (e != APR_BRIGADE_SENTINEL(b) && APR_BUCKET_IS_EOS(e)) {
            continue;
        }

        /* On reaching here, pass on everything in the brigade up to
         * this point. */
        apr_brigade_split_ex(b, e, ctx->tmpbb);
        
        rv = ap_pass_brigade(f->next, b);
        if (rv != APR_SUCCESS) {
            return rv;
        }
        else if (f->c->aborted) {
            return APR_ECONNABORTED;
        }
        apr_brigade_cleanup(b);
        APR_BRIGADE_CONCAT(b, ctx->tmpbb);
        e = APR_BRIGADE_FIRST(b);
        
        ctx->data_sent = 1;
    }

    /* If we've now seen the entire response and it's otherwise
     * okay to set the C-L in the response header, then do so now.
     *
     * We can only set a C-L in the response header if we haven't already
     * sent any buckets on to the next output filter for this request.
     */
    if (ctx->data_sent == 0 && eos) {
        core_server_config *conf =
            ap_get_core_module_config(r->server->module_config);

        /* This is a hack, but I can't find anyway around it.  The idea is that
         * we don't want to send out 0 Content-Lengths if it is a HEAD request.
         * [Unless the corresponding body (for a GET) would really be empty!]
         * This happens when modules try to outsmart the server, and return
         * if they see a HEAD request.  Apache 1.3 handlers were supposed to
         * just return in that situation, and the core handled the HEAD.  From
         * 2.0, if a handler returns, then the core sends an EOS bucket down
         * the filter stack, and this content-length filter computes a length
         * of zero and we would end up sending a zero C-L to the client.
         * We can't just remove the this C-L filter, because well behaved 2.0+
         * handlers will send their data down the stack, and we will compute
         * a real C-L for the head request. RBB
         *
         * Allow modification of this behavior through the
         * HttpContentLengthHeadZero directive.
         *
         * The default (unset) behavior is to squelch the C-L in this case.
         */

        /* don't whack the C-L if it has already been set for a HEAD
         * by something like proxy.  the brigade only has an EOS bucket
         * in this case, making r->bytes_sent zero, and either there is
         * an existing C-L we want to preserve, or r->sent_bodyct is not
         * zero (the empty body is being sent) thus we don't want to add
         * a C-L of zero (the backend did not provide it, neither do we).
         *
         * if r->bytes_sent > 0 we have a (temporary) body whose length may
         * have been changed by a filter.  the C-L header might not have been
         * updated so we do it here.  long term it would be cleaner to have
         * such filters update or remove the C-L header, and just use it
         * if present.
         */
        if (!((r->header_only || AP_STATUS_IS_HEADER_ONLY(r->status))
              && !r->bytes_sent
              && (r->sent_bodyct
                  || conf->http_cl_head_zero != AP_HTTP_CL_HEAD_ZERO_ENABLE
                  || apr_table_get(r->headers_out, "Content-Length")))) {
            ap_set_content_length(r, r->bytes_sent);
        }
    }

    ctx->data_sent = 1;
    return ap_pass_brigade(f->next, b);
}

/*
 * Send the body of a response to the client.
 */
AP_DECLARE(apr_status_t) ap_send_fd(apr_file_t *fd, request_rec *r,
                                    apr_off_t offset, apr_size_t len,
                                    apr_size_t *nbytes)
{
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb = NULL;
    apr_status_t rv;

    bb = apr_brigade_create(r->pool, c->bucket_alloc);

    apr_brigade_insert_file(bb, fd, offset, len, r->pool);

    rv = ap_pass_brigade(r->output_filters, bb);
    if (rv != APR_SUCCESS) {
        *nbytes = 0; /* no way to tell how many were actually sent */
    }
    else {
        *nbytes = len;
    }

    return rv;
}

#if APR_HAS_MMAP
/* send data from an in-memory buffer */
AP_DECLARE(apr_size_t) ap_send_mmap(apr_mmap_t *mm,
                                    request_rec *r,
                                    apr_size_t offset,
                                    apr_size_t length)
{
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb = NULL;
    apr_bucket *b;

    bb = apr_brigade_create(r->pool, c->bucket_alloc);
    b = apr_bucket_mmap_create(mm, offset, length, c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    ap_pass_brigade(r->output_filters, bb);

    return mm->size; /* XXX - change API to report apr_status_t? */
}
#endif /* APR_HAS_MMAP */

typedef struct {
    apr_bucket_brigade *bb;
    apr_bucket_brigade *tmpbb;
} old_write_filter_ctx;

AP_CORE_DECLARE_NONSTD(apr_status_t) ap_old_write_filter(
    ap_filter_t *f, apr_bucket_brigade *bb)
{
    old_write_filter_ctx *ctx = f->ctx;

    AP_DEBUG_ASSERT(ctx);

    if (ctx->bb != NULL) {
        /* whatever is coming down the pipe (we don't care), we
         * can simply insert our buffered data at the front and
         * pass the whole bundle down the chain.
         */
        APR_BRIGADE_PREPEND(bb, ctx->bb);
    }

    return ap_pass_brigade(f->next, bb);
}

static ap_filter_t *insert_old_write_filter(request_rec *r)
{
    ap_filter_t *f;
    old_write_filter_ctx *ctx;

    /* future optimization: record some flags in the request_rec to
     * say whether we've added our filter, and whether it is first.
     */

    /* this will typically exit on the first test */
    for (f = r->output_filters; f != NULL; f = f->next) {
        if (ap_old_write_func == f->frec)
            break;
    }

    if (f == NULL) {
        /* our filter hasn't been added yet */
        ctx = apr_pcalloc(r->pool, sizeof(*ctx));
        ctx->tmpbb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

        ap_add_output_filter("OLD_WRITE", ctx, r, r->connection);
        f = r->output_filters;
    }

    return f;
}

static apr_status_t buffer_output(request_rec *r,
                                  const char *str, apr_size_t len)
{
    conn_rec *c = r->connection;
    ap_filter_t *f;
    old_write_filter_ctx *ctx;

    if (len == 0)
        return APR_SUCCESS;

    f = insert_old_write_filter(r);
    ctx = f->ctx;

    /* if the first filter is not our buffering filter, then we have to
     * deliver the content through the normal filter chain
     */
    if (f != r->output_filters) {
        apr_status_t rv;
        apr_bucket *b = apr_bucket_transient_create(str, len, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(ctx->tmpbb, b);

        rv = ap_pass_brigade(r->output_filters, ctx->tmpbb);
        apr_brigade_cleanup(ctx->tmpbb);
        return rv;
    }

    if (ctx->bb == NULL) {
        ctx->bb = apr_brigade_create(r->pool, c->bucket_alloc);
    }

    return ap_fwrite(f->next, ctx->bb, str, len);
}

AP_DECLARE(int) ap_rputc(int c, request_rec *r)
{
    char c2 = (char)c;

    if (r->connection->aborted) {
        return -1;
    }

    if (buffer_output(r, &c2, 1) != APR_SUCCESS)
        return -1;

    return c;
}

AP_DECLARE(int) ap_rwrite(const void *buf, int nbyte, request_rec *r)
{
    if (nbyte < 0)
        return -1;

    if (r->connection->aborted)
        return -1;

    if (buffer_output(r, buf, nbyte) != APR_SUCCESS)
        return -1;

    return nbyte;
}

struct ap_vrprintf_data {
    apr_vformatter_buff_t vbuff;
    request_rec *r;
    char *buff;
};

/* Flush callback for apr_vformatter; returns -1 on error. */
static int r_flush(apr_vformatter_buff_t *buff)
{
    /* callback function passed to ap_vformatter to be called when
     * vformatter needs to write into buff and buff.curpos > buff.endpos */

    /* ap_vrprintf_data passed as a apr_vformatter_buff_t, which is then
     * "downcast" to an ap_vrprintf_data */
    struct ap_vrprintf_data *vd = (struct ap_vrprintf_data*)buff;

    if (vd->r->connection->aborted)
        return -1;

    /* r_flush is called when vbuff is completely full */
    if (buffer_output(vd->r, vd->buff, AP_IOBUFSIZE)) {
        return -1;
    }

    /* reset the buffer position */
    vd->vbuff.curpos = vd->buff;
    vd->vbuff.endpos = vd->buff + AP_IOBUFSIZE;

    return 0;
}

AP_DECLARE(int) ap_vrprintf(request_rec *r, const char *fmt, va_list va)
{
    int written;
    struct ap_vrprintf_data vd;
    char vrprintf_buf[AP_IOBUFSIZE];

    vd.vbuff.curpos = vrprintf_buf;
    vd.vbuff.endpos = vrprintf_buf + AP_IOBUFSIZE;
    vd.r = r;
    vd.buff = vrprintf_buf;

    if (r->connection->aborted)
        return -1;

    written = apr_vformatter(r_flush, &vd.vbuff, fmt, va);

    if (written != -1) {
        int n = vd.vbuff.curpos - vrprintf_buf;

        /* last call to buffer_output, to finish clearing the buffer */
        if (buffer_output(r, vrprintf_buf, n) != APR_SUCCESS)
            return -1;

        written += n;
    }

    return written;
}

AP_DECLARE_NONSTD(int) ap_rprintf(request_rec *r, const char *fmt, ...)
{
    va_list va;
    int n;

    if (r->connection->aborted)
        return -1;

    va_start(va, fmt);
    n = ap_vrprintf(r, fmt, va);
    va_end(va);

    return n;
}

AP_DECLARE_NONSTD(int) ap_rvputs(request_rec *r, ...)
{
    va_list va;
    const char *s;
    apr_size_t len;
    apr_size_t written = 0;

    if (r->connection->aborted)
        return -1;

    /* ### TODO: if the total output is large, put all the strings
     * ### into a single brigade, rather than flushing each time we
     * ### fill the buffer
     */
    va_start(va, r);
    while (1) {
        s = va_arg(va, const char *);
        if (s == NULL)
            break;

        len = strlen(s);
        if (buffer_output(r, s, len) != APR_SUCCESS) {
            va_end(va);
            return -1;
        }

        written += len;
    }
    va_end(va);

    return written;
}

AP_DECLARE(int) ap_rflush(request_rec *r)
{
    conn_rec *c = r->connection;
    apr_bucket *b;
    ap_filter_t *f;
    old_write_filter_ctx *ctx;
    apr_status_t rv;

    f = insert_old_write_filter(r);
    ctx = f->ctx;

    b = apr_bucket_flush_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(ctx->tmpbb, b);

    rv = ap_pass_brigade(r->output_filters, ctx->tmpbb);
    apr_brigade_cleanup(ctx->tmpbb);
    if (rv != APR_SUCCESS)
        return -1;

    return 0;
}

/*
 * This function sets the Last-Modified output header field to the value
 * of the mtime field in the request structure - rationalized to keep it from
 * being in the future.
 */
AP_DECLARE(void) ap_set_last_modified(request_rec *r)
{
    if (!r->assbackwards) {
        apr_time_t mod_time = ap_rationalize_mtime(r, r->mtime);
        char *datestr = apr_palloc(r->pool, APR_RFC822_DATE_LEN);

        apr_rfc822_date(datestr, mod_time);
        apr_table_setn(r->headers_out, "Last-Modified", datestr);
    }
}

typedef struct hdr_ptr {
    ap_filter_t *f;
    apr_bucket_brigade *bb;
} hdr_ptr;

 
AP_DECLARE(void) ap_set_std_response_headers(request_rec *r)
{
    const char *server = NULL, *date;
    char *s;

    /* Before generating a response, we make sure that `Date` and `Server`
     * headers are present. When proxying requests, we preserver existing
     * values and replace them otherwise.
     */
    if (r->proxyreq != PROXYREQ_NONE) {
        date = apr_table_get(r->headers_out, "Date");
        if (!date) {
            s = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
            ap_recent_rfc822_date(s, r->request_time);
            date = s;
        }
        server = apr_table_get(r->headers_out, "Server");
    }
    else {
        s = apr_palloc(r->pool, APR_RFC822_DATE_LEN);
        ap_recent_rfc822_date(s, r->request_time);
        date = s;
    }

    apr_table_setn(r->headers_out, "Date", date);

    if (!server)
        server = ap_get_server_banner();
    if (server && *server)
        apr_table_setn(r->headers_out, "Server", server);
}

AP_DECLARE(apr_status_t) ap_send_interim_response_ex(request_rec *r,
                                                     int send_headers,
                                                     unsigned int flags)
{
    request_rec *rr;
    apr_bucket *b;
    apr_bucket_brigade *bb;
    const char *reason = NULL;
    apr_status_t rv;

    if (r->proto_num < HTTP_VERSION(1,1)) {
        /* don't send interim response to HTTP/1.0 Client */
        return APR_SUCCESS;
    }
    if (!ap_is_HTTP_INFO(r->status)) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00575)
                      "Status is %d - not sending interim response", r->status);
        return APR_SUCCESS;
    }
    if (r->status == HTTP_CONTINUE) {
        if (!r->expecting_100) {
            /*
             * Don't send 100-Continue when there was no Expect: 100-continue
             * in the request headers. For origin servers this is a SHOULD NOT
             * for proxies it is a MUST NOT according to RFC 2616 8.2.3
             */
            return APR_SUCCESS;
        }

        /* if we send an interim response, we're no longer in a state of
         * expecting one.  Also, this could feasibly be in a subrequest,
         * so we need to propagate the fact that we responded.
         */
        for (rr = r; rr != NULL; rr = rr->main) {
            rr->expecting_100 = 0;
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                  "ap_send_interim_response: send %d", r->status);
    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    if (send_headers) {
        ap_set_std_response_headers(r);
    }
    if (r->status_line && strlen(r->status_line) > 4) {
        reason = r->status_line + 4;
        /* Reject control characters in the reason phrase to prevent
         * forwarding backend-controlled bare CR in the status line. */
        if (*ap_scan_http_field_content(reason)) {
            reason = NULL;
        }
    }
    b = ap_bucket_response_create(r->status, reason,
                                  send_headers? r->headers_out : NULL,
                                  r->notes, r->pool, r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    if (send_headers) {
        apr_table_clear(r->headers_out);
    }
    if (flags & AP_SEND_INTERIM_NONBLOCK) {
        b = ap_bucket_wc_create(r->connection->bucket_alloc);
    }
    else {
        b = apr_bucket_flush_create(r->connection->bucket_alloc);
    }
    APR_BRIGADE_INSERT_TAIL(bb, b);
    rv = ap_pass_brigade(r->proto_output_filters, bb);
    apr_brigade_destroy(bb);

    if (rv == APR_SUCCESS && (flags & AP_SEND_INTERIM_NONBLOCK)
        && ap_filter_should_yield(r->connection->output_filters)) {
        rv = APR_EAGAIN;
    }
    return rv;
}

AP_DECLARE(void) ap_send_interim_response(request_rec *r, int send_headers)
{
    (void)ap_send_interim_response_ex(r, send_headers, 0);
}

/*
 * Compare two protocol identifier. Result is similar to strcmp():
 * 0 gives same precedence, >0 means proto1 is preferred.
 */
static int protocol_cmp(const apr_array_header_t *preferences,
                        const char *proto1,
                        const char *proto2)
{
    if (preferences && preferences->nelts > 0) {
        int index1 = ap_array_str_index(preferences, proto1, 0);
        int index2 = ap_array_str_index(preferences, proto2, 0);
        if (index2 > index1) {
            return (index1 >= 0) ? 1 : -1;
        }
        else if (index1 > index2) {
            return (index2 >= 0) ? -1 : 1;
        }
    }
    /* both have the same index (maybe -1 or no pref configured) and we compare
     * the names so that spdy3 gets precedence over spdy2. That makes
     * the outcome at least deterministic. */
    return strcmp(proto1, proto2);
}

AP_DECLARE(const char *) ap_get_protocol(conn_rec *c)
{
    const char *protocol = ap_run_protocol_get(c);
    return protocol? protocol : AP_PROTOCOL_HTTP1;
}

AP_DECLARE(apr_status_t) ap_get_protocol_upgrades(conn_rec *c, request_rec *r, 
                                                  server_rec *s, int report_all, 
                                                  const apr_array_header_t **pupgrades)
{
    apr_pool_t *pool = r? r->pool : c->pool;
    core_server_config *conf;
    const char *existing;
    apr_array_header_t *upgrades = NULL;

    if (!s) {
        s = (r? r->server : c->base_server);
    }
    conf = ap_get_core_module_config(s->module_config);
    
    if (conf->protocols->nelts > 0) {
        existing = ap_get_protocol(c);
        if (conf->protocols->nelts > 1 
            || !ap_array_str_contains(conf->protocols, existing)) {
            int i;
            
            /* possibly more than one choice or one, but not the
             * existing. (TODO: maybe 426 and Upgrade then?) */
            upgrades = apr_array_make(pool, conf->protocols->nelts + 1, 
                                      sizeof(char *));
            for (i = 0; i < conf->protocols->nelts; i++) {
                const char *p = APR_ARRAY_IDX(conf->protocols, i, char *);
                if (strcmp(existing, p)) {
                    /* not the one we have and possible, add in this order */
                    APR_ARRAY_PUSH(upgrades, const char*) = p;
                }
                else if (!report_all) {
                    break;
                }
            }
        }
    }
    
    *pupgrades = upgrades;
    return APR_SUCCESS;
}

AP_DECLARE(const char *) ap_select_protocol(conn_rec *c, request_rec *r, 
                                            server_rec *s,
                                            const apr_array_header_t *choices)
{
    apr_pool_t *pool = r? r->pool : c->pool;
    core_server_config *conf;
    const char *protocol = NULL, *existing;
    apr_array_header_t *proposals;

    if (!s) {
        s = (r? r->server : c->base_server);
    }
    conf = ap_get_core_module_config(s->module_config);
    
    if (APLOGcdebug(c)) {
        const char *p = apr_array_pstrcat(pool, conf->protocols, ',');
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03155) 
                      "select protocol from %s, choices=%s for server %s", 
                      p, apr_array_pstrcat(pool, choices, ','),
                      s->server_hostname);
    }

    if (conf->protocols->nelts <= 0) {
        /* nothing configured, by default, we only allow http/1.1 here.
         * For now...
         */
        if (ap_array_str_contains(choices, AP_PROTOCOL_HTTP1)) {
            return AP_PROTOCOL_HTTP1;
        }
        else {
            return NULL;
        }
    }

    proposals = apr_array_make(pool, choices->nelts + 1, sizeof(char *));
    ap_run_protocol_propose(c, r, s, choices, proposals);

    /* If the existing protocol has not been proposed, but is a choice,
     * add it to the proposals implicitly.
     */
    existing = ap_get_protocol(c);
    if (!ap_array_str_contains(proposals, existing)
        && ap_array_str_contains(choices, existing)) {
        APR_ARRAY_PUSH(proposals, const char*) = existing;
    }

    if (proposals->nelts > 0) {
        int i;
        const apr_array_header_t *prefs = NULL;

        /* Default for protocols_honor_order is 'on' or != 0 */
        if (conf->protocols_honor_order == 0 && choices->nelts > 0) {
            prefs = choices;
        }
        else {
            prefs = conf->protocols;
        }

        /* Select the most preferred protocol */
        if (APLOGcdebug(c)) {
            ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03156) 
                          "select protocol, proposals=%s preferences=%s configured=%s", 
                          apr_array_pstrcat(pool, proposals, ','),
                          apr_array_pstrcat(pool, prefs, ','),
                          apr_array_pstrcat(pool, conf->protocols, ','));
        }
        for (i = 0; i < proposals->nelts; ++i) {
            const char *p = APR_ARRAY_IDX(proposals, i, const char *);
            if (!ap_array_str_contains(conf->protocols, p)) {
                /* not a configured protocol here */
                continue;
            }
            else if (!protocol 
                     || (protocol_cmp(prefs, protocol, p) < 0)) {
                /* none selected yet or this one has preference */
                protocol = p;
            }
        }
    }
    if (APLOGcdebug(c)) {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, c, APLOGNO(03157)
                      "selected protocol=%s", 
                      protocol? protocol : "(none)");
    }

    return protocol;
}

AP_DECLARE(apr_status_t) ap_switch_protocol(conn_rec *c, request_rec *r, 
                                            server_rec *s,
                                            const char *protocol)
{
    const char *current = ap_get_protocol(c);
    int rc;
    
    if (!strcmp(current, protocol)) {
        ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, c, APLOGNO(02906)
                      "already at it, protocol_switch to %s", 
                      protocol);
        return APR_SUCCESS;
    }
    
    rc = ap_run_protocol_switch(c, r, s, protocol);
    switch (rc) {
        case DECLINED:
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(02907)
                          "no implementation for protocol_switch to %s", 
                          protocol);
            return APR_ENOTIMPL;
        case OK:
        case DONE:
            return APR_SUCCESS;
        default:
            ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c, APLOGNO(02905)
                          "unexpected return code %d from protocol_switch to %s"
                          , rc, protocol);
            return APR_EOF;
    }    
}

AP_DECLARE(int) ap_is_allowed_protocol(conn_rec *c, request_rec *r,
                                       server_rec *s, const char *protocol)
{
    core_server_config *conf;

    if (!s) {
        s = (r? r->server : c->base_server);
    }
    conf = ap_get_core_module_config(s->module_config);
    
    if (conf->protocols->nelts > 0) {
        return ap_array_str_contains(conf->protocols, protocol);
    }
    return !strcmp(AP_PROTOCOL_HTTP1, protocol);
}


AP_IMPLEMENT_HOOK_VOID(pre_read_request,
                       (request_rec *r, conn_rec *c),
                       (r, c))
AP_IMPLEMENT_HOOK_RUN_ALL(int,post_read_request,
                          (request_rec *r), (r), OK, DECLINED)
AP_IMPLEMENT_HOOK_RUN_ALL(int,log_transaction,
                          (request_rec *r), (r), OK, DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(const char *,http_scheme,
                            (const request_rec *r), (r), NULL)
AP_IMPLEMENT_HOOK_RUN_FIRST(unsigned short,default_port,
                            (const request_rec *r), (r), 0)
AP_IMPLEMENT_HOOK_RUN_FIRST(int, note_auth_failure,
                            (request_rec *r, const char *auth_type),
                            (r, auth_type), DECLINED)
AP_IMPLEMENT_HOOK_RUN_ALL(int,protocol_propose,
                          (conn_rec *c, request_rec *r, server_rec *s,
                           const apr_array_header_t *offers,
                           apr_array_header_t *proposals), 
                          (c, r, s, offers, proposals), OK, DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,protocol_switch,
                            (conn_rec *c, request_rec *r, server_rec *s,
                             const char *protocol), 
                            (c, r, s, protocol), DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(const char *,protocol_get,
                            (const conn_rec *c), (c), NULL)
