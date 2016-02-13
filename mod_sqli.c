/*
 * Copyright (c) 2015, Fakhri Zulkifli <d0lph1n98@yahoo.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of mod_sqli nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "include/libinjection.h"

static int sqli_handler(request_rec *r) {
    char unique_id[8];
    ap_set_content_type(r, "text/html");

    if (strcmp(r->handler, "sqli"))
        return DECLINED;

    if (!strcmp(r->method, "POST"))
        ap_rprintf(r, "POST'ed data: %s\n", r->args);

    if (!strcmp(r->method, "GET"))
        ap_rprintf(r, "GET'ed data: %s\n", r->args);

    if (r->args) {
        ap_rprintf(r, "Query string: %s\n", r->args);

        int issqli = libinjection_sqli(r->args, (size_t) strlen(r->args), unique_id);

        if (issqli)
        {
            ap_rprintf(r, "SQL Injection detected\nUser-Agent: %s\nIP Address: %s\n", r->useragent_addr, r->useragent_ip);
            return HTTP_NOT_FOUND;
        }

        int isxss = libinjection_xss(r->args, (size_t) strlen(r->args));
        if (isxss)
        {
            ap_rprintf(r, "XSS Injection detected\nUser-Agent: %s\nIP Address: %s\n", r->useragent_addr, r->useragent_ip);
            return HTTP_NOT_FOUND;
        }
    }
    return OK;
}

static int log_handler(request_rec *r) {

    /*
     * TODO: Logging
     */
    return DECLINED;
}

static void sqli_register_hooks(apr_pool_t *p) {
    ap_hook_handler(sqli_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA sqli_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,                  /* table of config file commands       */
    sqli_register_hooks  /* register hooks                      */
};

