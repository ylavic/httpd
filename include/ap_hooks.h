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
 * @file ap_hooks.h
 * @brief ap hook functions and macros
 */

#ifndef AP_HOOKS_H
#define AP_HOOKS_H

/* Although this file doesn't declare any hooks, declare the hook group here */
/**
 * @defgroup hooks Apache Hooks
 * @ingroup  APACHE_CORE
 */

#if defined(AP_HOOK_PROBES_ENABLED) && !defined(APR_HOOK_PROBES_ENABLED)
#define APR_HOOK_PROBES_ENABLED 1
#endif

#ifdef APR_HOOK_PROBES_ENABLED
#include "ap_hook_probes.h"
#endif

#include "apr.h"
#include "apr_hooks.h"
#include "apr_optional_hooks.h"

#ifdef DOXYGEN
/* define these just so doxygen documents them */

/**
 * AP_DECLARE_STATIC is defined when including Apache's Core headers,
 * to provide static linkage when the dynamic library may be unavailable.
 *
 * @see AP_DECLARE_EXPORT
 *
 * AP_DECLARE_STATIC and AP_DECLARE_EXPORT are left undefined when
 * including Apache's Core headers, to import and link the symbols from the
 * dynamic Apache Core library and assure appropriate indirection and calling
 * conventions at compile time.
 */
# define AP_DECLARE_STATIC
/**
 * AP_DECLARE_EXPORT is defined when building the Apache Core dynamic
 * library, so that all public symbols are exported.
 *
 * @see AP_DECLARE_STATIC
 */
# define AP_DECLARE_EXPORT

#endif /* def DOXYGEN */

/**
 * Declare a hook function
 * @param ret The return type of the hook
 * @param name The hook's name (as a literal)
 * @param args The arguments the hook function takes, in brackets.
 */
#define AP_DECLARE_HOOK(ret,name,args) \
        APR_DECLARE_EXTERNAL_HOOK(ap,AP,ret,name,args)

/** @internal */
#define AP_IMPLEMENT_HOOK_BASE(name) \
        APR_IMPLEMENT_EXTERNAL_HOOK_BASE(ap,AP,name)

/**
 * Implement an Apache core hook that has no return code, and
 * therefore runs all of the registered functions. The implementation
 * is called ap_run_<i>name</i>.
 *
 * @param name The name of the hook
 * @param args_decl The declaration of the arguments for the hook, for example
 * "(int x,void *y)"
 * @param args_use The arguments for the hook as used in a call, for example
 * "(x,y)"
 * @note If IMPLEMENTing a hook that is not linked into the Apache core,
 * (e.g. within a dso) see APR_IMPLEMENT_EXTERNAL_HOOK_VOID.
 */
#define AP_IMPLEMENT_HOOK_VOID(name,args_decl,args_use) \
        APR_IMPLEMENT_EXTERNAL_HOOK_VOID(ap,AP,name,args_decl,args_use)

/**
 * Implement an Apache core hook that runs until one of the functions
 * returns something other than ok or decline. That return value is
 * then returned from the hook runner. If the hooks run to completion,
 * then ok is returned. Note that if no hook runs it would probably be
 * more correct to return decline, but this currently does not do
 * so. The implementation is called ap_run_<i>name</i>.
 *
 * @param ret The return type of the hook (and the hook runner)
 * @param name The name of the hook
 * @param args_decl The declaration of the arguments for the hook, for example
 * "(int x,void *y)"
 * @param args_use The arguments for the hook as used in a call, for example
 * "(x,y)"
 * @param ok The "ok" return value
 * @param decline The "decline" return value
 * @return ok, decline or an error.
 * @note If IMPLEMENTing a hook that is not linked into the Apache core,
 * (e.g. within a dso) use AP_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL instead.
 */
#define AP_IMPLEMENT_HOOK_RUN_ALL(ret,name,args_decl,args_use,ok,decline) \
        APR_IMPLEMENT_EXTERNAL_HOOK_RUN_ALL(ap,AP,ret,name,args_decl, \
                                            args_use,ok,decline)

/**
 * Implement a hook that runs until a function returns something other than
 * decline. If all functions return decline, the hook runner returns decline.
 * The implementation is called ap_run_<i>name</i>.
 *
 * @param ret The return type of the hook (and the hook runner)
 * @param name The name of the hook
 * @param args_decl The declaration of the arguments for the hook, for example
 * "(int x,void *y)"
 * @param args_use The arguments for the hook as used in a call, for example
 * "(x,y)"
 * @param decline The "decline" return value
 * @return decline or an error.
 * @note If IMPLEMENTing a hook that is not linked into the Apache core
 * (e.g. within a dso) use AP_IMPLEMENT_OPTIONAL_HOOK_RUN_FIRST instead.
 */
#define AP_IMPLEMENT_HOOK_RUN_FIRST(ret,name,args_decl,args_use,decline) \
        APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(ap,AP,ret,name,args_decl, \
                                              args_use,decline)

/**
 * Implement a hook as AP_IMPLEMENT_HOOK_RUN_FIRST does, plus its runner from
 * a position, ap_run_<i>name</i>_from(), which runs the functions from *pos
 * on and leaves at *pos the index of the one that stopped the run (or the
 * number of functions if none did), so that the caller can continue the run
 * later from *pos + 1 (e.g. after a function returned SUSPENDED).
 *
 * @param ret The return type of the hook (and the hook runners)
 * @param name The name of the hook
 * @param args_decl The declaration of the arguments for the hook, for example
 * "(request_rec *r)"
 * @param args_use The arguments for the hook as used in a call, for example
 * "(r)"
 * @param from_args_decl The declaration of the arguments for the runner from
 * a position: the hook's and the position, for example
 * "(request_rec *r, int *pos)"
 * @param pos The name of the position (int *) in from_args_decl
 * @param decline The "decline" return value
 * @return decline or an error.
 * @remark Declare the runner from a position by hand beside the hook's
 * AP_DECLARE_HOOK(): it is generated in the file implementing the hook,
 * where the hook's functions are (static). The order of the functions is
 * fixed once they are sorted (before the children start), so a position
 * remains valid for the life of a child.
 * @note There is no optional variant (the hook must be linked into the
 * Apache core).
 */
#define AP_IMPLEMENT_HOOK_RUN_FIRST_FROM(ret,name,args_decl,args_use, \
                                         from_args_decl,pos,decline) \
        AP_IMPLEMENT_HOOK_RUN_FIRST(ret,name,args_decl,args_use,decline) \
        AP_DECLARE(ret) ap_run_##name##_from from_args_decl \
        { \
            ap_LINK_##name##_t *pHook; \
            int n = *(pos); \
            ret rv = decline; \
            APR_HOOK_INT_DCL_UD; \
            APR_HOOK_PROBE_ENTRY(ud, ap, name, args_use); \
            if (_hooks.link_##name) { \
                pHook = (ap_LINK_##name##_t *)_hooks.link_##name->elts; \
                for (; n < _hooks.link_##name->nelts; ++n) { \
                    APR_HOOK_PROBE_INVOKE(ud, ap, name, \
                                          (char *)pHook[n].szName, \
                                          args_use); \
                    rv = pHook[n].pFunc args_use; \
                    APR_HOOK_PROBE_COMPLETE(ud, ap, name, \
                                            (char *)pHook[n].szName, rv, \
                                            args_use); \
                    if (rv != decline) { \
                        break; \
                    } \
                } \
            } \
            *(pos) = n; \
            APR_HOOK_PROBE_RETURN(ud, ap, name, rv, args_use); \
            return rv; \
        }

/* Note that the other optional hook implementations are straightforward but
 * have not yet been needed
 */

/**
 * Implement an optional hook. This is exactly the same as a standard hook
 * implementation, except the hook is optional.
 * @see AP_IMPLEMENT_HOOK_RUN_ALL
 */
#define AP_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ret,name,args_decl,args_use,ok, \
                                           decline) \
        APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(ap,AP,ret,name,args_decl, \
                                            args_use,ok,decline)

/**
 * Implement an optional hook. This is exactly the same as a standard hook
 * implementation, except the hook is optional.
 * @see AP_IMPLEMENT_HOOK_RUN_FIRST
 */
#define AP_IMPLEMENT_OPTIONAL_HOOK_RUN_FIRST(ret,name,args_decl,args_use, \
                                             decline) \
        APR_IMPLEMENT_OPTIONAL_HOOK_RUN_FIRST(ap,AP,ret,name,args_decl, \
                                              args_use,decline)

/**
 * Hook an optional hook. Unlike static hooks, this uses a macro instead of a
 * function.
 */
#define AP_OPTIONAL_HOOK(name,fn,pre,succ,order) \
        APR_OPTIONAL_HOOK(ap,name,fn,pre,succ,order)

#endif /* AP_HOOKS_H */
