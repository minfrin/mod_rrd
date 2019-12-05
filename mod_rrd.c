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
 * mod_rrd.c --- The Apache mod_rrd module provides a set of handlers to
 *               manipulate and display RRD graphs.
 *
 * Example config:
 *
 * <IfModule mod_rrd.c>
 *   <Directory "/var/lib/collectd/rrd">
 *     Require all granted
 *   </Directory>
 *   Alias /rrd /var/lib/collectd/rrd
 *   <Location /rrd>
 *     RRDGraph on
 *     RRDGraphOption title %{SERVER_NAME}
 *     RRDGraphEnv METHODS %{REQUEST_METHOD}
 *     RRDGraphElement DEF:xifOutOctets=monitor*.rrd:ifOutOctets:AVERAGE "optional/expression/monitor*.rrd" "/optional/path/prefix/"
 *     RRDGraphElement VDEF:xifOutOctetsmax=xifOutOctets+,MAXIMUM
 *     RRDGraphElement CDEF:xcombined=xifOutOctets,1,+
 *     RRDGraphElement LINE1:xifOutOctets#00ff00:Out+Octets :%{SERVER_NAME}
 *     RRDGraphElement AREA:xifOutOctets#00ff00:Out+Octets :%{SERVER_NAME}
 *     RRDGraphElement TICK:xifOutOctets#00ff00:1.0:Failures :%{SERVER_NAME}
 *     RRDGraphElement "VRULE:0#FF0000:dashed line:dashes" :%{SERVER_NAME}
 *     RRDGraphElement "HRULE:0#FF0000:dashed line:dashes" :%{SERVER_NAME}
 *     RRDGraphElement "COMMENT:Foo" %{env:METHODS}
 *   </Location>
 * </IfModule>
 *
 * Returns a dynamically generated graph file with the format controlled
 * by the given suffix. The graph file in the URL must not already exist,
 * otherwise the existing file will be returned.
 *
 * Options are passed as query parameters, either as a name value pair, or
 * a name only for options that do not take a parameter.
 *
 * Graph elements are passed between & characters.
 *
 * The parameters in the query string must be URLEncoded. Most notably the
 * '+' character is not decoded.
 *
 * All RRD files are checked against Apache httpd permissions, and if not
 * accessible the DEF line is ignored.
 *
 * Unlike rrdgraph, DEF lines can accept wildcard filenames. A CDEF is
 * generated automatically to add the wildcard RRDs together.
 *
 * When a LINE, AREA or TICK is rendered, each RRD file that matches the
 * wildcard will form the basis of the expressions parsed.
 *
 * Example call:
 *   curl "http://localhost/rrd/monitor.png?DEF:ifOutOctets=monitor*.rrd:ifOutOctets:AVERAGE&LINE1:ifOutOctets%2300ff00:Out+Octets"
 *
 * Notes:
 * - Write as a handler, not a filter (alas)
 * - Use rrd_graph_v() to return images in memory buffer
 *
 * - GET with Accept of xml - map to rrdtool dump
 * - PUT with Content-Type of XML - map to rrdtool restore
 * - PATCH - map to update/updatev
 * - PROPFIND - map to rrdtool info?
 *
 * - Graph handler - map specific path to specific graph.
 * - Option to expand each wildcard to one line per rrd, to
 *   supporting a combined syntax, eg ifOutOctets+ for all
 *   the DEFs added together using a CDEF, to ifOutOctets* for all the
 *   DEFs multiplied together using a CDEF.
 *
 * - rrd_fetch_cb_register / rrd_fetch_fn_cb are too limited - we'll
 *   need to build the DEF values ourselves.
 */

#include "apr.h"
#include "apr_escape.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_fnmatch.h"
#include "apr_lib.h"
#include "apr_hash.h"
#include "apr_tables.h"
#include "apr_cstr.h"
#include "apr_uuid.h"

#include "ap_config.h"
#include "ap_expr.h"
#include "ap_mpm.h"
#include "util_filter.h"
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include "config.h"

#include "rrd.h"

#if HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif

#if APR_HAS_THREADS
static apr_thread_mutex_t *rrd_mutex = NULL;
#endif

module AP_MODULE_DECLARE_DATA rrd_module;

typedef struct rrd_conf {
    const char *location;
    apr_array_header_t *options;
    apr_array_header_t *elements;
    apr_hash_t *env;
    const char *format;
    int graph;
    unsigned int location_set:1;
    unsigned int format_set:1;
    unsigned int graph_set:1;
} rrd_conf;

typedef struct rrd_ctx {
    apr_file_t *file;
    apr_bucket_brigade *bb;
} rrd_ctx;

typedef enum rrd_conf_e {
    RRD_CONF_DEF,
    RRD_CONF_CDEF,
    RRD_CONF_VDEF,
    RRD_CONF_PRINT,
    RRD_CONF_GPRINT,
    RRD_CONF_COMMENT,
    RRD_CONF_VRULE,
    RRD_CONF_HRULE,
    RRD_CONF_LINE,
    RRD_CONF_AREA,
    RRD_CONF_TICK,
    RRD_CONF_SHIFT,
    RRD_CONF_TEXTALIGN
} rrd_conf_e;

typedef struct rrd_cmd_t rrd_cmd_t;

typedef struct rrd_def_t {
    const char *vname;
    const char *path;
    const char *dsname;
    const char *cf;
    apr_pool_t *pool;
    apr_array_header_t *requests;
    ap_expr_info_t *epath;
    ap_expr_info_t *edirpath;
} rrd_def_t;

typedef struct rrd_vdef_t {
    const char *vname;
    const char *dsname;
    const char *rpn;
    rrd_cmd_t *ref;
} rrd_vdef_t;

typedef struct rrd_cdef_t {
    const char *vname;
    apr_array_header_t *rpns;
    const char *rpn;
    rrd_cmd_t *ref;
} rrd_cdef_t;

typedef struct rrd_rpn_t {
    const char *rpn;
    rrd_cmd_t *def;
} rrd_rpn_t;

typedef struct rrd_line_t {
    const char *line;
    const char *vname;
    const char *colour;
    const char *legend;
    ap_expr_info_t *elegend;
    const char *args;
} rrd_line_t;

typedef struct rrd_area_t {
    const char *vname;
    const char *colour;
    const char *legend;
    ap_expr_info_t *elegend;
    const char *args;
} rrd_area_t;

typedef struct rrd_tick_t {
    const char *vname;
    const char *colour;
    const char *fraction;
    const char *legend;
    ap_expr_info_t *elegend;
    const char *args;
} rrd_tick_t;

typedef struct rrd_shift_t {
    const char *vname;
    const char *shift;
} rrd_shift_t;

typedef struct rrd_print_t {
    const char *vname;
    const char *format;
} rrd_print_t;

typedef struct rrd_rule_t {
    const char *val;
    const char *colour;
    const char *legend;
    ap_expr_info_t *elegend;
    const char *args;
} rrd_rule_t;

typedef struct rrd_element_t {
    const char *element;
    const char *legend;
    ap_expr_info_t *elegend;
} rrd_element_t;

typedef struct rrd_cmd_t {
    rrd_conf_e type;
    int num;
    rrd_cmd_t *def;
    union {
        rrd_def_t d;
        rrd_vdef_t v;
        rrd_cdef_t c;
        rrd_line_t l;
        rrd_area_t a;
        rrd_rule_t r;
        rrd_tick_t t;
        rrd_shift_t s;
        rrd_element_t e;
        rrd_print_t p;
    };
} rrd_cmd_t;

typedef struct rrd_opt_t {
    const char *key;
    const char *val;
    ap_expr_info_t *eval;
} rrd_opt_t;

typedef struct rrd_cmds_t {
    apr_array_header_t *cmds;
    apr_array_header_t *opts;
    apr_hash_t *names;
} rrd_cmds_t;

typedef struct rrd_cb_t {
    request_rec *r;
    rrd_cmd_t *cmd;
} rrd_cb_t;

static char *substring_quote(apr_pool_t *p, const char *start, int len,
                            char quote)
{
    char *result = apr_palloc(p, len + 1);
    char *resp = result;
    int i;

    for (i = 0; i < len; ++i) {
        if (start[i] == '\\' && (start[i + 1] == '\\'
                                 || (quote && start[i + 1] == quote)))
            *resp++ = start[++i];
        else
            *resp++ = start[i];
    }

    *resp++ = '\0';
    return result;
}

static char *getword_quote(apr_pool_t *p, const char **line, char stop)
{
    const char *str = *line, *strend;
    char *res;
    char quote;

    if (!*str) {
        *line = str;
        return "";
    }

    if ((quote = *str) == '"' || quote == '\'') {
        strend = str + 1;
        while (*strend && *strend != quote) {
            if (*strend == '\\' && strend[1] &&
                (strend[1] == quote || strend[1] == '\\')) {
                strend += 2;
            }
            else {
                ++strend;
            }
        }
        res = substring_quote(p, str + 1, strend - str - 1, quote);

        if (*strend == quote) {
            ++strend;
        }
        while (*strend && *strend != stop) {
            ++strend;
        }
    }
    else {
        strend = str;
        while (*strend && *strend != stop) {
            ++strend;
        }

        res = substring_quote(p, str, strend - str, 0);
    }

    if (*strend == stop) {
        ++strend;
    }
    *line = strend;
    return res;
}

static apr_status_t escape_colon(char *escaped, const char *str,
        apr_ssize_t slen, apr_size_t *len)
{
    unsigned char *d;
    const unsigned char *s;
    apr_size_t size = 1;
    int found = 0;

    d = (unsigned char *) escaped;
    s = (const unsigned char *) str;

    if (s) {
        if (d) {
            for (; *s && slen; ++s, slen--) {
                if (':' == *s) {
                    *d++ = '\\';
                    size++;
                    found = 1;
                }
                *d++ = *s;
                size++;
            }
            *d = '\0';
        }
        else {
            for (; *s && slen; ++s, slen--) {
                if (':' == *s) {
                    size++;
                    found = 1;
                }
                size++;
            }
        }
    }

    if (len) {
        *len = size;
    }
    if (!found) {
        return APR_NOTFOUND;
    }

    return APR_SUCCESS;
}

static const char *pescape_colon(apr_pool_t *p, const char *str)
{
    apr_size_t len;

    switch (escape_colon(NULL, str, APR_ESCAPE_STRING, &len)) {
    case APR_SUCCESS: {
        char *cmd = apr_palloc(p, len);
        escape_colon(cmd, str, APR_ESCAPE_STRING, NULL);
        return cmd;
    }
    case APR_NOTFOUND: {
        break;
    }
    }

    return str;
}

static void log_message(request_rec *r, apr_status_t status,
        const char *message, const char *err)
{

    /* Allow "error-notes" string to be printed by ap_send_error_response() */
    apr_table_setn(r->notes, "verbose-error-to", "*");

    if (err) {

        apr_table_setn(r->notes, "error-notes",
                ap_escape_html(r->pool,
                        apr_pstrcat(r->pool, "RRD error: ", message, ": ", err,
                                NULL)));

        ap_log_rerror(
                APLOG_MARK, APLOG_ERR, status, r, "mod_rrd: "
                "%s (%s)", message, err);
    }
    else {

        apr_table_setn(r->notes, "error-notes",
                ap_escape_html(r->pool,
                        apr_pstrcat(r->pool, "RRD error: ", message, NULL)));

        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, "mod_rrd: "
            "%s", message);
    }

}

static int options_wadl(request_rec *r, rrd_conf *conf)
{
    int rv;

    /* discard the request body */
    if ((rv = ap_discard_request_body(r)) != OK) {
        return rv;
    }

    ap_set_content_type(r, "application/vnd.sun.wadl+xml");

    ap_rprintf(r,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                    "<wadl:application xmlns:wadl=\"http://wadl.dev.java.net/2009/02\"\n"
                    "                  xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n"
                    "                  xsi:schemaLocation=\"http://wadl.dev.java.net/2009/02 file:wadl.xsd\">\n"
                    " <wadl:resources base=\"%s\">\n"
                    "  <wadl:resource path=\"/\">\n"
                    "   <wadl:method name=\"GET\" id=\"\">\n"
                    "   </wadl:method>\n"
                    "  </wadl:resource>\n"
                    " </wadl:resources>\n"
                    "</wadl:application>\n",
            conf->location ? conf->location :
                    apr_pstrcat(r->pool, ap_http_scheme(r), "://",
                            r->server->server_hostname, r->uri, NULL));

    return OK;
}

static const char *lookup_content_type(const char *format)
{
	switch(format[0]) {
    case 'p':
    case 'P':
        if (strcasecmp(format, "PNG") == 0) {
            return "image/png";
        }
        if (strcasecmp(format, "PDF") == 0) {
            return "application/pdf";
        }
        break;
    case 's':
    case 'S':
        if (strcasecmp(format, "SVG") == 0) {
            return "image/svg+xml";
        }
        if (strcasecmp(format, "SSV") == 0) {
            return "text/plain";
        }
        break;
    case 'e':
    case 'E':
        if (strcasecmp(format, "EPS") == 0) {
            return "application/eps";
        }
        break;
    case 'x':
    case 'X':
        if (strcasecmp(format, "XML") == 0) {
            return "application/xml";
        }
        if (strcasecmp(format, "XMLENUM") == 0) {
            return "application/xml";
        }
        break;
    case 'j':
    case 'J':
        if (strcasecmp(format, "JSON") == 0) {
            return "application/json";
        }
        if (strcasecmp(format, "JSONTIME") == 0) {
            return "application/json";
        }
        break;
    case 'c':
    case 'C':
        if (strcasecmp(format, "CSV") == 0) {
            return "text/csv";
        }
        break;
    case 't':
    case 'T':
        if (strcasecmp(format, "TSV") == 0) {
            return "text/tab-separated-values";
        }
        break;
	}
	return NULL;
}

static const char *parse_rrdgraph_suffix(request_rec *r)
{
    const char *fname = ap_strrchr_c(r->filename, '/');

    if (fname) {
        /* PNG|SVG|EPS|PDF|XML|XMLENUM|JSON|JSONTIME|CSV|TSV|SSV */
        const char *suffix = ap_strrchr_c(fname, '.');
        if (suffix) {
            switch (suffix[1]) {
            case 'p':
            case 'P':
                if (strcasecmp(suffix, ".png") == 0) {
                    return "PNG";
                }
                if (strcasecmp(suffix, ".pdf") == 0) {
                    return "PDF";
                }
                break;
            case 's':
            case 'S':
                if (strcasecmp(suffix, ".svg") == 0) {
                    return "SVG";
                }
                if (strcasecmp(suffix, ".ssv") == 0) {
                    return "SSV";
                }
                break;
            case 'e':
            case 'E':
                if (strcasecmp(suffix, ".eps") == 0) {
                    return "EPS";
                }
                break;
            case 'x':
            case 'X':
                if (strcasecmp(suffix, ".xml") == 0) {
                    return "XML";
                }
                if (strcasecmp(suffix, ".xmlenum") == 0) {
                    return "XMLENUM";
                }
                break;
            case 'j':
            case 'J':
                if (strcasecmp(suffix, ".json") == 0) {
                    return "JSON";
                }
                if (strcasecmp(suffix, ".jsontime") == 0) {
                    return "JSONTIME";
                }
                break;
            case 'c':
            case 'C':
                if (strcasecmp(suffix, ".csv") == 0) {
                    return "CSV";
                }
                break;
            case 't':
            case 'T':
                if (strcasecmp(suffix, ".tsv") == 0) {
                    return "TSV";
                }
                break;
            }
        }
    }
    return NULL;
}

static int parse_element(apr_pool_t *p, const char *element, ap_expr_info_t *expr1,
		ap_expr_info_t *expr2, apr_array_header_t *cmds)
{
    switch (element[0]) {
    case 'A':
        /* handle AREA sections */
        if (strncmp(element, "AREA:", 5) == 0) {
            char *vncol;
            rrd_cmd_t *cmd = apr_array_push(cmds);
            cmd->type = RRD_CONF_AREA;
            element += 5;
            vncol = ap_getword(p, &element, ':');
            cmd->a.legend = getword_quote(p, &element, ':');
            cmd->a.elegend = expr1;
            cmd->a.args = element;
            cmd->a.vname = apr_cstr_tokenize("#", &vncol);
            cmd->a.colour = vncol;
            return 1;
        }
        break;
    case 'C':
        /* handle CDEF sections */
        if (strncmp(element, "CDEF:", 5) == 0) {
            char *rpn, *rpns;
            rrd_cmd_t *cmd = apr_array_push(cmds);
            cmd->type = RRD_CONF_CDEF;
            element += 5;
            cmd->c.vname = ap_getword(p, &element, '=');
            cmd->c.rpns = apr_array_make(p, 4, sizeof(rrd_rpn_t));
            cmd->c.rpn = element;
            rpns = apr_pstrdup(p, element);
            while ((rpn = apr_cstr_tokenize(",", &rpns))) {
                rrd_rpn_t *rp = apr_array_push(cmd->c.rpns);
                rp->rpn = rpn;
            }
            return 1;
        }
        /* handle COMMENT sections */
        if (strncmp(element, "COMMENT:", 7) == 0) {
            rrd_cmd_t *cmd = apr_array_push(cmds);
            cmd->type = RRD_CONF_COMMENT;
            cmd->e.element = ap_getword(p, &element, ':');
            cmd->a.legend = getword_quote(p, &element, ':');
            cmd->e.elegend = expr1;
            return 1;
        }
        break;
    case 'D':
        /* handle DEF sections */
        if (strncmp(element, "DEF:", 4) == 0) {
            rrd_cmd_t *cmd = apr_array_push(cmds);
            cmd->type = RRD_CONF_DEF;
            element += 4;
            cmd->d.vname = ap_getword(p, &element, '=');
            cmd->d.path = ap_getword(p, &element, ':');
            cmd->d.dsname = ap_getword(p, &element, ':');
            cmd->d.cf = element;
            cmd->d.pool = p;
            cmd->d.requests = apr_array_make(p, 10, sizeof(request_rec *));
            cmd->d.epath = expr1;
            cmd->d.edirpath = expr2;
            return 1;
        }
        break;
    case 'G':
        /* handle GPRINT sections */
        if (strncmp(element, "GPRINT:", 7) == 0) {
            rrd_cmd_t *cmd = apr_array_push(cmds);
            cmd->type = RRD_CONF_GPRINT;
            element += 7;
            cmd->p.vname = ap_getword(p, &element, ':');
            cmd->p.format = element;
            return 1;
        }
        break;
    case 'H':
        /* handle HRULE sections */
        if (strncmp(element, "HRULE:", 6) == 0) {
            char *vncol;
            rrd_cmd_t *cmd = apr_array_push(cmds);
            cmd->type = RRD_CONF_HRULE;
            element += 6;
            vncol = ap_getword(p, &element, ':');
            cmd->r.legend = getword_quote(p, &element, ':');
            cmd->r.elegend = expr1;
            cmd->r.args = element;
            cmd->r.val = apr_cstr_tokenize("#", &vncol);
            cmd->r.colour = vncol;
            return 1;
        }
        break;
    case 'L':
        /* handle LINE sections */
        if (strncmp(element, "LINE", 4) == 0) {
            char *vncol;
            rrd_cmd_t *cmd = apr_array_push(cmds);
            cmd->type = RRD_CONF_LINE;
            cmd->l.line = ap_getword(p, &element, ':');
            vncol = ap_getword(p, &element, ':');
            cmd->l.legend = getword_quote(p, &element, ':');
            cmd->l.elegend = expr1;
            cmd->l.args = element;
            cmd->l.vname = apr_cstr_tokenize("#", &vncol);
            cmd->l.colour = vncol;
            cmd->l.elegend = expr1;
            return 1;
        }
        break;
    case 'P':
        /* handle PRINT sections */
        if (strncmp(element, "PRINT:", 6) == 0) {
            rrd_cmd_t *cmd = apr_array_push(cmds);
            cmd->type = RRD_CONF_PRINT;
            element += 6;
            cmd->p.vname = ap_getword(p, &element, ':');
            cmd->p.format = element;
            return 1;
        }
        break;
    case 'S':
        /* handle SHIFT sections */
        if (strncmp(element, "SHIFT:", 6) == 0) {
            rrd_cmd_t *cmd = apr_array_push(cmds);
            cmd->type = RRD_CONF_SHIFT;
            element += 6;
            cmd->s.vname = ap_getword(p, &element, ':');
            cmd->s.shift = element;
            return 1;
        }
        break;
    case 'T':
        /* handle TICK sections */
        if (strncmp(element, "TICK:", 5) == 0) {
            char *vncol;
            rrd_cmd_t *cmd = apr_array_push(cmds);
            cmd->type = RRD_CONF_TICK;
            element += 5;
            vncol = ap_getword(p, &element, ':');
            cmd->t.fraction = ap_getword(p, &element, ':');
            cmd->t.legend = getword_quote(p, &element, ':');
            cmd->t.elegend = expr1;
            cmd->t.args = element;
            cmd->t.vname = apr_cstr_tokenize("#", &vncol);
            cmd->t.colour = vncol;
            return 1;
        }
        /* handle TEXTALIGN sections */
        else if (strncmp(element, "TEXTALIGN:", 10) == 0) {
            rrd_cmd_t *cmd = apr_array_push(cmds);
            cmd->type = RRD_CONF_TEXTALIGN;
            cmd->e.element = ap_getword(p, &element, ':');
            cmd->a.legend = getword_quote(p, &element, ':');
            cmd->e.elegend = expr1;
            return 1;
        }
        break;
    case 'V':
        /* handle VDEF sections */
        if (strncmp(element, "VDEF:", 5) == 0) {
            rrd_cmd_t *cmd = apr_array_push(cmds);
            cmd->type = RRD_CONF_VDEF;
            element += 5;
            cmd->v.vname = ap_getword(p, &element, '=');
            cmd->v.dsname = ap_getword(p, &element, ',');
            cmd->v.rpn = element;
            return 1;
        }
        /* handle VRULE sections */
        if (strncmp(element, "VRULE:", 6) == 0) {
            char *vncol;
            rrd_cmd_t *cmd = apr_array_push(cmds);
            cmd->type = RRD_CONF_VRULE;
            element += 6;
            vncol = ap_getword(p, &element, ':');
            cmd->r.legend = getword_quote(p, &element, ':');
            cmd->r.elegend = expr1;
            cmd->r.args = element;
            cmd->r.val = apr_cstr_tokenize("#", &vncol);
            cmd->r.colour = vncol;
            return 1;
        }
        break;
    }
    return 0;
}

static int parse_option(apr_pool_t *p, const char *key, const char *val,
        ap_expr_info_t *eval, apr_array_header_t *opts)
{
    /* with value */
    if (val) {
        switch (key[0]) {
        case 'b':
            /* [--border width] */
            if (strcmp(key, "border") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            break;
        case 'c':
            /* [-c|--color COLORTAG#rrggbb[aa]] */
            if (strcmp(key, "color") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            break;
        case 'f':
            /* [-n|--font FONTTAG:size:font] */
            if (strcmp(key, "font") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            /* [-R|--font-render-mode {normal,light,mono}] */
            if (strcmp(key, "font-render-mode") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            /* [-B|--font-smoothing-threshold size] */
            if (strcmp(key, "font-smoothing-threshold") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            break;
        case 'g':
            /* [-G|--graph-render-mode {normal,mono}] */
            if (strcmp(key, "graph-render-mode") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            break;
        case 'h':
            /* [-h|--height pixels] */
            if (strcmp(key, "height") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            break;
        case 'l':
            /* [--left-axis-format format] */
            if (strcmp(key, "left-axis-format") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            /* [-l|--lower-limit value] */
            if (strcmp(key, "lower-limit") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            break;
        case 'r':
            /* [--right-axis scale:shift] */
            if (strcmp(key, "right-axis") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            /* [--right-axis-label label] */
            if (strcmp(key, "right-axis-label") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            /* [--right-axis-format format] */
            if (strcmp(key, "right-axis-format") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            break;
        case 's':
            /* [-S|--step seconds] */
            if (strcmp(key, "step") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            break;
        case 't':
            /* [-T|--tabwidth width] */
            if (strcmp(key, "tabwidth") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            /* [-t|--title string] */
            if (strcmp(key, "title") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            break;
        case 'u':
            /* [-X|--units-exponent value] */
            if (strcmp(key, "units-exponent") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            /* [-L|--units-length value] */
            if (strcmp(key, "units-length") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            break;
        case 'v':
            /* [-v|--vertical-label string] */
            if (strcmp(key, "vertical-label") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            break;
        case 'w':
            /* [-w|--width pixels] */
            if (strcmp(key, "width") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            /* [-W|--watermark string] */
            if (strcmp(key, "watermark") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            break;
        case 'x':
            /* [-x|--x-grid x-axis grid and label] */
            if (strcmp(key, "x-grid") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            break;
        case 'y':
            /* [-y|--y-grid y-axis grid and label] */
            if (strcmp(key, "y-grid") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            break;
        case 'z':
            /* [-m|--zoom factor] */
            if (strcmp(key, "zoom") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                opt->val = val;
                opt->eval = eval;
                return 1;
            }
            break;
        }
    }

    /* no value */
    else {
        switch (key[0]) {
        case 'a':
            /* [-Y|--alt-y-grid] */
            if (strcmp(key, "alt-y-grid") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                return 1;
            }
            /* [-A|--alt-autoscale] */
            if (strcmp(key, "alt-autoscale") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                return 1;
            }
            /* [-M|--alt-autoscale-max] */
            if (strcmp(key, "alt-autoscale-max") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                return 1;
            }
            break;
        case 'f':
            /* [--full-size-mode] */
            if (strcmp(key, "full-size-mode") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                return 1;
            }
            /* [-F|--force-rules-legend] */
            if (strcmp(key, "force-rules-legend") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                return 1;
            }
            break;
        case 'l':
            /* [-o|--logarithmic] */
            if (strcmp(key, "logarithmic") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                return 1;
            }
            /* [-z|--lazy] */
            if (strcmp(key, "lazy") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                return 1;
            }
            break;
        case 'n':
            /* [-g|--no-legend] */
            if (strcmp(key, "no-legend") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                return 1;
            }
            /* [-N|--no-gridfit] */
            if (strcmp(key, "no-gridfit") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                return 1;
            }
            break;
        case 'o':
            /* [-j|--only-graph] */
            if (strcmp(key, "only-graph") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                return 1;
            }
            break;
        case 'p':
            /* [-P|--pango-markup] */
            if (strcmp(key, "pango-markup") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                return 1;
            }
            break;
        case 'r':
            /* [-r|--rigid] */
            if (strcmp(key, "rigid") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                return 1;
            }
            break;
        case 's':
            /* [-E|--slope-mode] */
            if (strcmp(key, "slope-mode") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                return 1;
            }
            break;
        case 'u':
            /* [-u|--upper-limit value] */
            if (strcmp(key, "upper-limit") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                return 1;
            }
            /* [-Z|--use-nan-for-all-missing-data] */
            if (strcmp(key, "use-nan-for-all-missing-data") == 0) {
                rrd_opt_t *opt = apr_array_push(opts);
                opt->key = key;
                return 1;
            }
            break;
        }

    }
    return 0;
}

static int parse_query(request_rec *r, rrd_cmds_t **pcmds)
{
    rrd_conf *conf = ap_get_module_config(r->per_dir_config,
            &rrd_module);

    char *arg, *args;
    rrd_cmds_t *cmds = *pcmds = apr_pcalloc(r->pool, sizeof(rrd_cmds_t));
    int optnum = 0, cmdnum = 0;

    cmds->names = apr_hash_make(r->pool);

    /* count the query string */
    args = apr_pstrdup(r->pool, r->args);
    while ((arg = apr_cstr_tokenize("&", &args))) {
        if (apr_islower(arg[0])) {
            optnum++;
        }
        else {
            cmdnum++;
        }
    }

    cmds->opts = apr_array_make(r->pool, optnum + conf->options->nelts, sizeof(rrd_opt_t));
    cmds->cmds = apr_array_make(r->pool, cmdnum + conf->elements->nelts, sizeof(rrd_cmd_t));

    /* pass the system wide options */
    apr_array_cat(cmds->opts, conf->options);
    apr_array_cat(cmds->cmds, conf->elements);

    /* parse the query string */
    args = apr_pstrdup(r->pool, r->args);
    while ((arg = apr_cstr_tokenize("&", &args))) {
        const char *key, *val;
        char *element;

        if (!arg[0]) {
            continue;
        }

        element = apr_pstrdup(r->pool, apr_punescape_url(r->pool, arg, NULL, NULL, 0));
        if (!element) {
            log_message(r, APR_SUCCESS,
                apr_psprintf(r->pool,
                        "The following element could not be unescaped: %s", arg), NULL);
            return HTTP_BAD_REQUEST;
        }

        if (parse_element(r->pool, element, NULL, NULL, cmds->cmds)) {
            continue;
        }

        /* try parse options that take the form of name value pairs */
        key = apr_cstr_tokenize("=", &element);
        val = element;

        if (parse_option(r->pool, key, val, NULL, cmds->opts)) {
            continue;
        }

        /* else unrecognised option */
        log_message(r, APR_SUCCESS,
                apr_psprintf(r->pool,
                        "Query was not recognised: %s", arg), NULL);
        return HTTP_BAD_REQUEST;
    }

    return OK;
}

static const char *resolve_def_cb(ap_dir_match_t *w, const char *fname)
{
    rrd_cb_t *ctx = w->ctx;
    request_rec *rr;

    rr = ap_sub_req_lookup_file(fname, ctx->r, NULL);

    if (rr->status == HTTP_OK) {
        APR_ARRAY_PUSH(ctx->cmd->d.requests, request_rec *) = rr;
        ctx->cmd->num++;
    }
    else {
        ap_log_rerror(
                APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, rr, "mod_rrd: Access to path returned %d, ignoring: %s",
                rr->status, fname);
    }

    return NULL;
}

static int resolve_def(request_rec *r, rrd_cmd_t *cmd, rrd_cmds_t *cmds)
{
    ap_dir_match_t w;
    rrd_cb_t ctx;
    apr_pool_t *ptemp;
    const char *last, *path, *dirpath = r->filename;
    apr_hash_index_t *hi, *hi2;
    apr_hash_t *set;

    rrd_conf *conf = ap_get_module_config(r->per_dir_config,
            &rrd_module);

    apr_pool_create(&ptemp, r->pool);

    /* process the wildcards */
    ctx.r = r;
    ctx.cmd = cmd;

    w.prefix = "rrd path: ";
    w.p = r->pool;
    w.ptemp = ptemp;
    w.flags = AP_DIR_FLAG_OPTIONAL | AP_DIR_FLAG_RECURSIVE;
    w.cb = resolve_def_cb;
    w.ctx = &ctx;
    w.depth = 0;

    path = cmd->d.path;
    if (cmd->d.epath) {
        const char *err = NULL;
        path = ap_expr_str_exec(r, cmd->d.epath, &err);
        if (err) {
            log_message(r, APR_SUCCESS,
                apr_psprintf(r->pool,
                        "While evaluating an element expression: %s", err), NULL);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    if (cmd->d.edirpath) {
        const char *err = NULL;
        dirpath = ap_expr_str_exec(r, cmd->d.edirpath, &err);
        if (err) {
            log_message(r, APR_SUCCESS,
                apr_psprintf(r->pool,
                        "While evaluating an element expression: %s", err), NULL);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    else {
    	last = strrchr(r->filename, '/');
    	if (last) {
        	dirpath = apr_pstrndup(ptemp, r->filename, last - r->filename);
    	}
    }

    ap_log_rerror(
            APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r,
            "mod_rrd: Attempting to match wildcard RRD path '%s' against base '%s'",
            path, dirpath);

    const char *err = ap_dir_fnmatch(&w, dirpath, path);
    if (err) {
        log_message(r, APR_SUCCESS,
            apr_psprintf(r->pool,
                    "While parsing DEF path '%s': %s", path, err), NULL);
        return HTTP_BAD_REQUEST;
    }

    /* process the environment lookup */
    set = apr_hash_make(ptemp);
    for (hi = apr_hash_first(NULL, conf->env); hi; hi = apr_hash_next(hi)) {
        const char *err = NULL, *key, *val;
        ap_expr_info_t *eval;
        void *v;
        const void *k;
        int j;

        apr_hash_this(hi, &k, NULL, &v);
        key = k;
        eval = v;

        for (j = 0; j < cmd->d.requests->nelts; ++j) {
            request_rec *rr = APR_ARRAY_IDX(cmd->d.requests, j, request_rec *);

            val = ap_expr_str_exec(rr, eval, &err);
            if (err) {
                log_message(r, APR_SUCCESS,
                        apr_psprintf(r->pool,
                                "While evaluating an element expression: %s", err), NULL);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            if (val && val[0]) {
                apr_hash_set(set, val, APR_HASH_KEY_STRING, val);
            }

        }

        if (apr_hash_count(set)) {
            apr_array_header_t *arr = apr_array_make(ptemp, apr_hash_count(set), sizeof(const char *));
            for (hi2 = apr_hash_first(NULL, set); hi2; hi2 = apr_hash_next(hi2)) {
                apr_hash_this(hi2, apr_array_push(arr), NULL, NULL);
            }
            apr_table_setn(r->subprocess_env, key, apr_array_pstrcat(r->pool, arr, ','));

        }
        apr_hash_clear(set);
    }

    apr_pool_destroy(ptemp);

    cmd->def = cmd;
    apr_hash_set(cmds->names, cmd->d.vname, APR_HASH_KEY_STRING, cmd);

    return OK;
}

static int resolve_vdef(request_rec *r, rrd_cmd_t *cmd, rrd_cmds_t *cmds)
{
    cmd->v.ref = apr_hash_get(cmds->names, cmd->v.dsname, APR_HASH_KEY_STRING);
    if (cmd->v.ref) {
        cmd->def = cmd->v.ref->def;
    }

    if (!cmd->v.ref) {
        log_message(r, APR_SUCCESS,
            apr_psprintf(r->pool,
                    "While parsing VDEF '%s': '%s' was not found", cmd->v.vname, cmd->v.dsname), NULL);
        return HTTP_BAD_REQUEST;
    }
    else {
        cmd->num = cmd->v.ref->num;
    }

    apr_hash_set(cmds->names, cmd->v.vname, APR_HASH_KEY_STRING, cmd);
    return OK;
}

static int resolve_cdef(request_rec *r, rrd_cmd_t *cmd, rrd_cmds_t *cmds)
{
    int i;

    for (i = 0; i < cmd->c.rpns->nelts; ++i) {
        rrd_rpn_t *rp = &((rrd_rpn_t *) cmd->c.rpns->elts)[i];

        if (!cmd->c.ref) {
            rrd_cmd_t *ref = apr_hash_get(cmds->names, rp->rpn,
                    APR_HASH_KEY_STRING);
            if (ref) {
                cmd->c.ref = ref;
                rp->def = cmd->def = ref->def;
            }
        }

    }
    if (cmd->c.ref) {
        cmd->num = cmd->c.ref->num;
    }
    apr_hash_set(cmds->names, cmd->c.vname, APR_HASH_KEY_STRING, cmd);
    return OK;
}

static int resolve_area(request_rec *r, rrd_cmd_t *cmd, rrd_cmds_t *cmds)
{
    rrd_cmd_t *ref;

    ref = apr_hash_get(cmds->names, cmd->a.vname, APR_HASH_KEY_STRING);
    if (ref) {
        cmd->def = ref->def;
    }
    else {
        log_message(r, APR_SUCCESS,
            apr_psprintf(r->pool,
                    "While parsing AREA: '%s' was not found", cmd->a.vname), NULL);
        return HTTP_BAD_REQUEST;
    }

    return OK;
}

static int resolve_line(request_rec *r, rrd_cmd_t *cmd, rrd_cmds_t *cmds)
{
    rrd_cmd_t *ref;

    ref = apr_hash_get(cmds->names, cmd->l.vname, APR_HASH_KEY_STRING);
    if (ref) {
        cmd->def = ref->def;
    }
    else {
        log_message(r, APR_SUCCESS,
            apr_psprintf(r->pool,
                    "While parsing LINE: '%s' was not found", cmd->l.vname), NULL);
        return HTTP_BAD_REQUEST;
    }

    return OK;
}

static int resolve_tick(request_rec *r, rrd_cmd_t *cmd, rrd_cmds_t *cmds)
{
    rrd_cmd_t *ref;

    ref = apr_hash_get(cmds->names, cmd->t.vname, APR_HASH_KEY_STRING);
    if (ref) {
        cmd->def = ref->def;
    }
    else {
        log_message(r, APR_SUCCESS,
            apr_psprintf(r->pool,
                    "While parsing TICK: '%s' was not found", cmd->t.vname), NULL);
        return HTTP_BAD_REQUEST;
    }

    return OK;
}

static int resolve_shift(request_rec *r, rrd_cmd_t *cmd, rrd_cmds_t *cmds)
{
    rrd_cmd_t *ref;

    ref = apr_hash_get(cmds->names, cmd->s.vname, APR_HASH_KEY_STRING);
    if (ref) {
        cmd->def = ref->def;
    }
    else {
        log_message(r, APR_SUCCESS,
            apr_psprintf(r->pool,
                    "While parsing SHIFT: '%s' was not found", cmd->s.vname), NULL);
        return HTTP_BAD_REQUEST;
    }

    return OK;
}

static int resolve_gprint(request_rec *r, rrd_cmd_t *cmd, rrd_cmds_t *cmds)
{
    rrd_cmd_t *ref;

    ref = apr_hash_get(cmds->names, cmd->p.vname, APR_HASH_KEY_STRING);
    if (ref) {
        cmd->def = ref->def;
    }
    else {
        log_message(r, APR_SUCCESS,
            apr_psprintf(r->pool,
                    "While parsing GPRINT: '%s' was not found", cmd->p.vname), NULL);
        return HTTP_BAD_REQUEST;
    }

    return OK;
}

static int resolve_print(request_rec *r, rrd_cmd_t *cmd, rrd_cmds_t *cmds)
{
    rrd_cmd_t *ref;

    ref = apr_hash_get(cmds->names, cmd->p.vname, APR_HASH_KEY_STRING);
    if (ref) {
        cmd->def = ref->def;
    }
    else {
        log_message(r, APR_SUCCESS,
            apr_psprintf(r->pool,
                    "While parsing PRINT: '%s' was not found", cmd->p.vname), NULL);
        return HTTP_BAD_REQUEST;
    }

    return OK;
}

static int resolve_rrds(request_rec *r, rrd_cmds_t *cmds)
{
    rrd_cmd_t *cmd;
    int i, ret;

    for (i = 0; i < cmds->cmds->nelts; ++i) {

        cmd = &((rrd_cmd_t *)cmds->cmds->elts)[i];

        switch (cmd->type) {
        case RRD_CONF_DEF:

            ret = resolve_def(r, cmd, cmds);
            if (OK != ret) {
                return ret;
            }

            break;
        case RRD_CONF_CDEF:

            ret = resolve_cdef(r, cmd, cmds);
            if (OK != ret) {
                return ret;
            }

            break;
        case RRD_CONF_VDEF:

            ret = resolve_vdef(r, cmd, cmds);
            if (OK != ret) {
                return ret;
            }

            break;
        case RRD_CONF_AREA:

            ret = resolve_area(r, cmd, cmds);
            if (OK != ret) {
                return ret;
            }

            break;
        case RRD_CONF_LINE:

            ret = resolve_line(r, cmd, cmds);
            if (OK != ret) {
                return ret;
            }

            break;
        case RRD_CONF_TICK:

            ret = resolve_tick(r, cmd, cmds);
            if (OK != ret) {
                return ret;
            }

            break;
        case RRD_CONF_SHIFT:

            ret = resolve_shift(r, cmd, cmds);
            if (OK != ret) {
                return ret;
            }

            break;
        case RRD_CONF_GPRINT:

            ret = resolve_gprint(r, cmd, cmds);
            if (OK != ret) {
                return ret;
            }

            break;
        case RRD_CONF_PRINT:

            ret = resolve_print(r, cmd, cmds);
            if (OK != ret) {
                return ret;
            }

            break;
        default:
            break;
        }

    }

    return OK;
}

static int generate_element(request_rec *r, rrd_cmd_t *cmd,
        apr_array_header_t *args)
{
    /* one result */
    const char *arg;

    const char *legend = cmd->e.legend;
    if (cmd->e.elegend) {
        const char *err = NULL;
        legend = ap_expr_str_exec(r, cmd->e.elegend, &err);
        if (err) {
            log_message(r, APR_SUCCESS,
                    apr_psprintf(r->pool,
                            "While evaluating an element expression: %s", err), NULL);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        legend = pescape_colon(r->pool, legend);
    }

    arg = apr_psprintf(r->pool, "%s:%s",
            cmd->e.element, legend);
    APR_ARRAY_PUSH(args, const char *) = arg;

    return OK;
}

static int generate_gprint(request_rec *r, rrd_cmd_t *cmd, apr_array_header_t *args)
{
    int j;

    /* no reference */
    if (!cmd->def) {
        log_message(r, APR_SUCCESS,
                apr_psprintf(r->pool,
                        "GPRINT element referred to '%s', which does not exist",
                        cmd->p.vname), NULL);
        return HTTP_BAD_REQUEST;
    }

    /* no results */
    else if (cmd->def->num == 0) {
        /* output nothing */
    }

    /* one result */
    else if (cmd->def->num == 1) {
        const char *arg = apr_psprintf(r->pool, "GPRINT:%s:%s",
                cmd->p.vname, cmd->p.format);
        APR_ARRAY_PUSH(args, const char *) = arg;
    }

    /* more than one result */
    else {
        /* handle each PRINT: line */
        for (j = 0; j < cmd->def->num; ++j) {
            const char *arg = apr_psprintf(r->pool, "GPRINT:%sw%d:%s",
                    cmd->p.vname, j, cmd->p.format);
            APR_ARRAY_PUSH(args, const char *) = arg;
        }
    }

    return OK;
}

static int generate_print(request_rec *r, rrd_cmd_t *cmd, apr_array_header_t *args)
{
    int j;

    /* no reference */
    if (!cmd->def) {
        log_message(r, APR_SUCCESS,
                apr_psprintf(r->pool,
                        "PRINT element referred to '%s', which does not exist",
                        cmd->p.vname), NULL);
        return HTTP_BAD_REQUEST;
    }

    /* no results */
    else if (cmd->def->num == 0) {
        /* output nothing */
    }

    /* one result */
    else if (cmd->def->num == 1) {
        const char *arg = apr_psprintf(r->pool, "PRINT:%s:%s",
                cmd->p.vname, cmd->p.format);
        APR_ARRAY_PUSH(args, const char *) = arg;
    }

    /* more than one result */
    else {
        /* handle each PRINT: line */
        for (j = 0; j < cmd->def->num; ++j) {
            const char *arg = apr_psprintf(r->pool, "PRINT:%sw%d:%s",
                    cmd->p.vname, j, cmd->p.format);
            APR_ARRAY_PUSH(args, const char *) = arg;
        }
    }

    return OK;
}

static int generate_shift(request_rec *r, rrd_cmd_t *cmd, apr_array_header_t *args)
{
    int j;

    /* no reference */
    if (!cmd->def) {
        log_message(r, APR_SUCCESS,
                apr_psprintf(r->pool,
                        "SHIFT element referred to '%s', which does not exist",
                        cmd->s.vname), NULL);
        return HTTP_BAD_REQUEST;
    }

    /* no results */
    else if (cmd->def->num == 0) {
        /* output nothing */
    }

    /* one result */
    else if (cmd->def->num == 1) {
        const char *arg = apr_psprintf(r->pool, "SHIFT:%s:%s",
                cmd->s.vname, cmd->s.shift);
        APR_ARRAY_PUSH(args, const char *) = arg;
    }

    /* more than one result */
    else {
        /* handle each LINE: line */
        for (j = 0; j < cmd->def->num; ++j) {
            const char *arg = apr_psprintf(r->pool, "SHIFT:%sw%d:%s",
                    cmd->s.vname, j, cmd->s.shift);
            APR_ARRAY_PUSH(args, const char *) = arg;
        }
    }

    return OK;
}

static int generate_hrule(request_rec *r, rrd_cmd_t *cmd,
        apr_array_header_t *args)
{
    /* one result */
    const char *arg;

    const char *legend = cmd->r.legend;
    if (cmd->r.elegend) {
        const char *err = NULL;
        legend = ap_expr_str_exec(r, cmd->r.elegend, &err);
        if (err) {
            log_message(r, APR_SUCCESS,
                    apr_psprintf(r->pool,
                            "While evaluating an element expression: %s", err), NULL);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        legend = pescape_colon(r->pool, legend);
    }

    arg = apr_psprintf(r->pool, "HRULE:%s%s%s:%s%s%s",
            cmd->r.val,
            cmd->r.colour ? "#" : "", cmd->r.colour ? cmd->r.colour : "",
            legend,
            cmd->r.args[0] ? ":" : "", cmd->r.args);
    APR_ARRAY_PUSH(args, const char *) = arg;

    return OK;
}

static int generate_vrule(request_rec *r, rrd_cmd_t *cmd,
        apr_array_header_t *args)
{
    /* one result */
    const char *arg;

    const char *legend = cmd->r.legend;
    if (cmd->r.elegend) {
        const char *err = NULL;
        legend = ap_expr_str_exec(r, cmd->r.elegend, &err);
        if (err) {
            log_message(r, APR_SUCCESS,
                    apr_psprintf(r->pool,
                            "While evaluating an element expression: %s", err), NULL);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        legend = pescape_colon(r->pool, legend);
    }

    arg = apr_psprintf(r->pool, "VRULE:%s%s%s:%s%s%s",
            cmd->r.val,
            cmd->r.colour ? "#" : "", cmd->r.colour ? cmd->r.colour : "",
            legend,
            cmd->r.args[0] ? ":" : "", cmd->r.args);
    APR_ARRAY_PUSH(args, const char *) = arg;

    return OK;
}

static int generate_tick(request_rec *r, rrd_cmd_t *cmd, rrd_cmds_t *cmds,
        apr_array_header_t *args, int *i)
{
    int j, k;

    /* no reference */
    if (!cmd->def) {
        log_message(r, APR_SUCCESS,
                apr_psprintf(r->pool,
                        "TICK element referred to '%s', which does not exist",
                        cmd->t.vname), NULL);
        return HTTP_BAD_REQUEST;
    }

    /* no results */
    else if (cmd->def->num == 0) {
        /* output nothing */
    }

    /* one result */
    else if (cmd->def->num == 1) {
        const char *arg;
        request_rec *rr = ((request_rec **)cmd->def->d.requests->elts)[0];

        const char *legend = cmd->t.legend;
        if (cmd->t.elegend) {
            const char *err = NULL;
            legend = ap_expr_str_exec(rr, cmd->t.elegend, &err);
            if (err) {
                log_message(r, APR_SUCCESS,
                    apr_psprintf(r->pool,
                            "While evaluating an element expression: %s", err), NULL);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            legend = pescape_colon(r->pool, legend);
        }
        arg = apr_psprintf(r->pool, "TICK:%s%s%s:%s:%s%s%s",
                cmd->t.vname,
                cmd->t.colour ? "#" : "", cmd->t.colour ? cmd->t.colour : "",
                cmd->t.fraction,
                legend,
                cmd->t.args[0] ? ":" : "", cmd->t.args);
        APR_ARRAY_PUSH(args, const char *) = arg;
    }

    /* more than one result */
    else {
        int skip = 0;

        /* handle each TICK: line */
        for (j = 0; j < cmd->def->num; ++j) {
            const char *arg;
            request_rec *rr = ((request_rec **)cmd->def->d.requests->elts)[j];

            const char *legend = cmd->t.legend;
            if (cmd->t.elegend) {
                const char *err = NULL;
                legend = ap_expr_str_exec(rr, cmd->t.elegend, &err);
                if (err) {
                    log_message(r, APR_SUCCESS,
                        apr_psprintf(r->pool,
                                "While evaluating an element expression: %s", err), NULL);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
                legend = pescape_colon(r->pool, legend);
            }

            arg = apr_psprintf(r->pool, "TICK:%sw%d%s%s:%s:%s%s%s",
                    cmd->t.vname, j,
                    cmd->t.colour ? "#" : "", cmd->t.colour ? cmd->t.colour : "",
                    cmd->t.fraction,
                    legend,
                    cmd->t.args[0] ? ":" : "", cmd->t.args);
            APR_ARRAY_PUSH(args, const char *) = arg;

            for (k = *i + 1; k < cmds->cmds->nelts; ++k) {
                rrd_cmd_t *pcmd = &((rrd_cmd_t *)cmds->cmds->elts)[k];
                if (pcmd->def == cmd->def) {
                    switch (pcmd->type) {
                    case RRD_CONF_PRINT:

                        APR_ARRAY_PUSH(args, const char *) =
                            apr_psprintf(r->pool, "PRINT:%sw%d:%s",
                                pcmd->p.vname, j, pcmd->p.format);

                        break;
                    case RRD_CONF_GPRINT:

                        APR_ARRAY_PUSH(args, const char *) =
                            apr_psprintf(r->pool, "GPRINT:%sw%d:%s",
                                pcmd->p.vname, j, pcmd->p.format);

                        break;
                    default:
                        /* skip the print/grint */
                        skip = k - *i - 1;
                        /* jump out of the loop */
                        k = cmds->cmds->nelts;
                    }
                }
                else {
                    /* skip the print/grint */
                    skip = k - *i - 1;
                    /* jump out of the loop */
                    k = cmds->cmds->nelts;
                }
            }

        }
        *i += skip;
    }

    return OK;
}

static int generate_area(request_rec *r, rrd_cmd_t *cmd, rrd_cmds_t *cmds,
        apr_array_header_t *args, int *i)
{
    int j, k;

    /* no reference */
    if (!cmd->def) {
        log_message(r, APR_SUCCESS,
                apr_psprintf(r->pool,
                        "AREA element referred to '%s', which does not exist",
                        cmd->a.vname), NULL);
        return HTTP_BAD_REQUEST;
    }

    /* no results */
    else if (cmd->def->num == 0) {
        /* output nothing */
    }

    /* one result */
    else if (cmd->def->num == 1) {
        const char *arg;
        request_rec *rr = ((request_rec **)cmd->def->d.requests->elts)[0];

        const char *legend = cmd->a.legend;
        if (cmd->a.elegend) {
            const char *err = NULL;
            legend = ap_expr_str_exec(rr, cmd->a.elegend, &err);
            if (err) {
                log_message(r, APR_SUCCESS,
                    apr_psprintf(r->pool,
                            "While evaluating an element expression: %s", err), NULL);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            legend = pescape_colon(r->pool, legend);
        }

        arg = apr_psprintf(r->pool, "AREA:%s%s%s:%s%s%s",
                cmd->a.vname,
                cmd->a.colour ? "#" : "", cmd->a.colour ? cmd->a.colour : "",
                legend,
                cmd->a.args[0] ? ":" : "", cmd->a.args);
        APR_ARRAY_PUSH(args, const char *) = arg;
    }

    /* more than one result */
    else {
        int skip = 0;

        /* handle each AREA: line */
        for (j = 0; j < cmd->def->num; ++j) {
            const char *arg;
            request_rec *rr = ((request_rec **)cmd->def->d.requests->elts)[j];

            const char *legend = cmd->a.legend;
            if (cmd->a.elegend) {
                const char *err = NULL;
                legend = ap_expr_str_exec(rr, cmd->a.elegend, &err);
                if (err) {
                    log_message(r, APR_SUCCESS,
                        apr_psprintf(r->pool,
                                "While evaluating an element expression: %s", err), NULL);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
                legend = pescape_colon(r->pool, legend);
            }

            arg = apr_psprintf(r->pool, "AREA:%sw%d%s%s:%s%s%s",
                    cmd->a.vname, j,
                    cmd->a.colour ? "#" : "", cmd->a.colour ? cmd->a.colour : "",
                    legend,
                    cmd->a.args[0] ? ":" : "", cmd->a.args);
            APR_ARRAY_PUSH(args, const char *) = arg;

            for (k = *i + 1; k < cmds->cmds->nelts; ++k) {
                rrd_cmd_t *pcmd = &((rrd_cmd_t *)cmds->cmds->elts)[k];
                if (pcmd->def == cmd->def) {
                    switch (pcmd->type) {
                    case RRD_CONF_PRINT:

                        APR_ARRAY_PUSH(args, const char *) =
                            apr_psprintf(r->pool, "PRINT:%sw%d:%s",
                                pcmd->p.vname, j, pcmd->p.format);

                        break;
                    case RRD_CONF_GPRINT:

                        APR_ARRAY_PUSH(args, const char *) =
                            apr_psprintf(r->pool, "GPRINT:%sw%d:%s",
                                pcmd->p.vname, j, pcmd->p.format);

                        break;
                    default:
                        /* skip the print/grint */
                        skip = k - *i - 1;
                        /* jump out of the loop */
                        k = cmds->cmds->nelts;
                    }
                }
                else {
                    /* skip the print/grint */
                    skip = k - *i - 1;
                    /* jump out of the loop */
                    k = cmds->cmds->nelts;
                }
            }

        }
        *i += skip;
    }

    return OK;
}

static int generate_line(request_rec *r, rrd_cmd_t *cmd, rrd_cmds_t *cmds,
        apr_array_header_t *args, int *i)
{
    int j, k;

    /* no reference */
    if (!cmd->def) {
        log_message(r, APR_SUCCESS,
                apr_psprintf(r->pool,
                        "LINE element referred to '%s', which does not exist",
                        cmd->l.vname), NULL);
        return HTTP_BAD_REQUEST;
    }

    /* no results */
    else if (cmd->def->num == 0) {
        /* output nothing */
    }

    /* one result */
    else if (cmd->def->num == 1) {
        const char *arg;
        request_rec *rr = ((request_rec **)cmd->def->d.requests->elts)[0];

        const char *legend = cmd->l.legend;
        if (cmd->l.elegend) {
            const char *err = NULL;
            legend = ap_expr_str_exec(rr, cmd->l.elegend, &err);
            if (err) {
                log_message(r, APR_SUCCESS,
                    apr_psprintf(r->pool,
                            "While evaluating an element expression: %s", err), NULL);
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            legend = pescape_colon(r->pool, legend);
        }
        arg = apr_psprintf(r->pool, "%s:%s%s%s:%s%s%s",
                cmd->l.line, cmd->l.vname,
                cmd->l.colour ? "#" : "", cmd->l.colour ? cmd->l.colour : "",
                legend,
                cmd->l.args[0] ? ":" : "", cmd->l.args);
        APR_ARRAY_PUSH(args, const char *) = arg;
    }

    /* more than one result */
    else {
        int skip = 0;

        /* handle each LINE: line */
        for (j = 0; j < cmd->def->num; ++j) {
            const char *arg;
            request_rec *rr = ((request_rec **)cmd->def->d.requests->elts)[j];

            const char *legend = cmd->l.legend;
            if (cmd->l.elegend) {
                const char *err = NULL;
                legend = ap_expr_str_exec(rr, cmd->l.elegend, &err);
                if (err) {
                    log_message(r, APR_SUCCESS,
                        apr_psprintf(r->pool,
                                "While evaluating an element expression: %s", err), NULL);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
                legend = pescape_colon(r->pool, legend);
            }

            arg = apr_psprintf(r->pool, "%s:%sw%d%s%s:%s%s%s",
                    cmd->l.line, cmd->l.vname, j,
                    cmd->l.colour ? "#" : "", cmd->l.colour ? cmd->l.colour : "",
                    legend,
                    cmd->l.args[0] ? ":" : "", cmd->l.args);
            APR_ARRAY_PUSH(args, const char *) = arg;

            for (k = *i + 1; k < cmds->cmds->nelts; ++k) {
                rrd_cmd_t *pcmd = &((rrd_cmd_t *)cmds->cmds->elts)[k];
                if (pcmd->def == cmd->def) {
                    switch (pcmd->type) {
                    case RRD_CONF_PRINT:

                        APR_ARRAY_PUSH(args, const char *) =
                            apr_psprintf(r->pool, "PRINT:%sw%d:%s",
                                pcmd->p.vname, j, pcmd->p.format);

                        break;
                    case RRD_CONF_GPRINT:

                        APR_ARRAY_PUSH(args, const char *) =
                            apr_psprintf(r->pool, "GPRINT:%sw%d:%s",
                                pcmd->p.vname, j, pcmd->p.format);

                        break;
                    default:
                        /* skip the print/grint */
                        skip = k - *i - 1;
                        /* jump out of the loop */
                        k = cmds->cmds->nelts;
                    }
                }
                else {
                    /* skip the print/grint */
                    skip = k - *i - 1;
                    /* jump out of the loop */
                    k = cmds->cmds->nelts;
                }
            }

        }
        *i += skip;
    }

    return OK;
}

static int generate_vdef(request_rec *r, rrd_cmd_t *cmd, apr_array_header_t *args)
{
    int j;

    /* no reference */
    if (!cmd->def) {
        log_message(r, APR_SUCCESS,
                apr_psprintf(r->pool,
                        "VDEF element referred to '%s', which does not exist",
                        cmd->v.vname), NULL);
        return HTTP_BAD_REQUEST;
    }

    /* no results */
    else if (cmd->def->num == 0) {
        /* output nothing */
    }

    /* one result */
    else if (cmd->def->num == 1) {
        APR_ARRAY_PUSH(args, const char *) =
                apr_pstrcat(r->pool, "VDEF:", cmd->v.vname, "=",
                        cmd->v.dsname, ",", cmd->v.rpn, NULL);
    }

    /* more than one result */
    else {
        /* handle each VDEF: line */
        for (j = 0; j < cmd->def->num; ++j) {
            const char *arg = apr_psprintf(r->pool, "VDEF:%sw%d=%sw%d,%s", cmd->v.vname,
                j, cmd->v.dsname, j, cmd->v.rpn);
            APR_ARRAY_PUSH(args, const char *) = arg;
        }
    }

    return OK;
}

static int generate_cdef(request_rec *r, rrd_cmd_t *cmd, apr_array_header_t *args)
{
    int j, k;

    /* no reference */
    if (!cmd->def) {
        log_message(r, APR_SUCCESS,
                apr_psprintf(r->pool,
                        "CDEF element '%s' referred to no existing definitions",
                        cmd->c.vname), NULL);
        return HTTP_BAD_REQUEST;
    }

    /* no results */
    else if (cmd->def->num == 0) {
        /* output nothing */
    }

    /* one result */
    else if (cmd->def->num == 1) {
        APR_ARRAY_PUSH(args, const char *) =
                apr_pstrcat(r->pool, "CDEF:", cmd->c.vname, "=",
                        cmd->c.rpn, NULL);
    }

    /* more than one result */
    else {
        /* handle each CDEF: line */
        for (j = 0; j < cmd->num; ++j) {
            char *cdef;
            int len;

            /* first pass - work out the length */
            len = apr_snprintf(NULL, 0, "CDEF:%sw%d=", cmd->c.vname, j);
            for (k = 0; k < cmd->c.rpns->nelts; ++k) {
                rrd_rpn_t *rp = (((rrd_rpn_t *)cmd->c.rpns->elts) + k);
                if (k) {
                    len++;
                }
                if (!rp->def || rp->def->num < 2) {
                    len += apr_snprintf(NULL, 0, "%s", rp->rpn);
                }
                else {
                    len += apr_snprintf(NULL, 0, "%sw%d", rp->rpn, j);
                }
            }

            /* second pass, write the cdef */
            cdef = apr_palloc(r->pool, len + 1);
            APR_ARRAY_PUSH(args, const char *) = cdef;
            cdef += apr_snprintf(cdef, len, "CDEF:%sw%d=", cmd->c.vname, j);
            for (k = 0; k < cmd->c.rpns->nelts; ++k) {
                rrd_rpn_t *rp = (((rrd_rpn_t *)cmd->c.rpns->elts) + k);
                if (k) {
                    *cdef++ = ',';
                }
                if (!rp->def || rp->def->num < 2) {
                    cdef += apr_snprintf(cdef, len, "%s", rp->rpn);
                }
                else {
                    cdef += apr_snprintf(cdef, len, "%sw%d", rp->rpn, j);
                }
            }
        }
    }

    return OK;
}

static int generate_def(request_rec *r, rrd_cmd_t *cmd, apr_array_header_t *args)
{
    int j;

    /* safety check - reject anything trying to set the daemon */
    if (ap_strstr_c(cmd->d.cf, ":daemon=")) {
        log_message(r, APR_SUCCESS,
                    "DEF elements must not contain a 'daemon' parameter", NULL);
        return HTTP_BAD_REQUEST;
    }

    /* no results */
    if (cmd->d.requests->nelts == 0) {
        /* output nothing */
    }

    /* one result */
    else if (cmd->d.requests->nelts == 1) {
        request_rec *rr = APR_ARRAY_IDX(cmd->d.requests, 0, request_rec *);
        const char *arg = apr_psprintf(r->pool, "DEF:%s=%s:%s:%s", cmd->d.vname,
        		pescape_colon(r->pool, rr->filename), cmd->d.dsname, cmd->d.cf);
        APR_ARRAY_PUSH(args, const char *) = arg;
    }

    /* more than one result */
    else {
        char *cdef;
        int len = apr_snprintf(NULL, 0, "CDEF:%s=", cmd->d.vname);

        /* handle each DEF: line */
        for (j = 0; j < cmd->d.requests->nelts; ++j) {
            request_rec *rr = APR_ARRAY_IDX(cmd->d.requests, j, request_rec *);
            const char *arg = apr_psprintf(r->pool, "DEF:%sw%d=%s:%s:%s", cmd->d.vname,
                j, pescape_colon(r->pool, rr->filename), cmd->d.dsname, cmd->d.cf);
            APR_ARRAY_PUSH(args, const char *) = arg;
            len += apr_snprintf(NULL, 0, "%s%sw%d%s", j ? "," : "", cmd->d.vname, j, j ? ",+" : "");
        }

        /* calculate the CDEF summary line */
        cdef = apr_palloc(r->pool, len + 1);
        APR_ARRAY_PUSH(args, const char *) = cdef;
        cdef += apr_snprintf(cdef, len, "CDEF:%s=", cmd->d.vname);
        for (j = 0; j < cmd->d.requests->nelts; ++j) {
            cdef += apr_snprintf(cdef, len, "%s%sw%d%s", j ? "," : "", cmd->d.vname, j, j ? ",+" : "");
        }

    }

    return OK;
}

static int generate_args(request_rec *r, rrd_cmds_t *cmds, apr_array_header_t **pargs)
{
    apr_array_header_t *args;
    rrd_cmd_t *cmd;
    rrd_opt_t *opt;
    const char *format;
    int i, num = 4, ret = OK;

    rrd_conf *conf = ap_get_module_config(r->per_dir_config,
            &rrd_module);

    /* count the options */
    for (i = 0; i < cmds->opts->nelts; ++i) {

        opt = &((rrd_opt_t *)cmds->opts->elts)[i];

        if (opt->val) {
            num++;
        }

        num++;
    }
    /* count the number of elements we need */
    for (i = 0; i < cmds->cmds->nelts; ++i) {

        cmd = &APR_ARRAY_IDX(cmds->cmds, i, rrd_cmd_t);

        if (cmd->def) {
            num += cmd->def->d.requests->nelts;
        }

        num++;
    }

    /* work out the format */
    format = conf->format ? conf->format : parse_rrdgraph_suffix(r);

    /* set the content type */
    ap_set_content_type(r, lookup_content_type(format));

    /* create arguments of the correct size */
    args = *pargs = apr_array_make(r->pool, num, sizeof(const char *));

    /* the argv array */
    APR_ARRAY_PUSH(args, const char *) = "rrdgraph";
    APR_ARRAY_PUSH(args, const char *) = "-";
    APR_ARRAY_PUSH(args, const char *) = "--imgformat";
    APR_ARRAY_PUSH(args, const char *) = format;

    /* first create the options */
    for (i = 0; i < cmds->opts->nelts; ++i) {

        opt = &((rrd_opt_t *)cmds->opts->elts)[i];

        APR_ARRAY_PUSH(args, const char *) =
                apr_pstrcat(r->pool, "--", opt->key, NULL);
        if (opt->eval) {
            const char *err = NULL;

            APR_ARRAY_PUSH(args, const char *) = ap_expr_str_exec(r, opt->eval, &err);
            if (err) {
                log_message(r, APR_SUCCESS,
                    apr_psprintf(r->pool,
                            "While evaluating expressions for '%s': %s", opt->key, err), NULL);
                return HTTP_INTERNAL_SERVER_ERROR;
            }

        }
        else if (opt->val) {
            APR_ARRAY_PUSH(args, const char *) = opt->val;
        }

    }

    /* and finally create the elements */
    for (i = 0; i < cmds->cmds->nelts; ++i) {

        cmd = &((rrd_cmd_t *)cmds->cmds->elts)[i];

        switch (cmd->type) {
        case RRD_CONF_DEF:

            ret = generate_def(r, cmd, args);

            break;
        case RRD_CONF_CDEF:

            ret = generate_cdef(r, cmd, args);

            break;
        case RRD_CONF_VDEF:

            ret = generate_vdef(r, cmd, args);

            break;
        case RRD_CONF_LINE:

            ret = generate_line(r, cmd, cmds, args, &i);

            break;
        case RRD_CONF_AREA:

            ret = generate_area(r, cmd, cmds, args, &i);

            break;
        case RRD_CONF_TICK:

            ret = generate_tick(r, cmd, cmds, args, &i);

            break;
        case RRD_CONF_SHIFT:

            ret = generate_shift(r, cmd, args);

            break;
        case RRD_CONF_PRINT:

            ret = generate_print(r, cmd, args);

            break;
        case RRD_CONF_GPRINT:

            ret = generate_gprint(r, cmd, args);

            break;
        case RRD_CONF_HRULE:

            ret = generate_hrule(r, cmd, args);

            break;
        case RRD_CONF_VRULE:

            ret = generate_vrule(r, cmd, args);

            break;
        case RRD_CONF_COMMENT:
        case RRD_CONF_TEXTALIGN:

            ret = generate_element(r, cmd, args);

            break;
        }

        if (OK != ret) {
            return ret;
        }

    }

    for (i = 0; i < args->nelts; ++i) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r, "mod_rrd: rrdgraph:%d: %s",
                i, ((const char **) args->elts)[i]);
    }

    return OK;
}

static int cleanup_args(request_rec *r, rrd_cmds_t *cmds)
{
    rrd_cmd_t *cmd;
    int i;

    for (i = 0; i < cmds->cmds->nelts; ++i) {
        request_rec **rr;

        cmd = &APR_ARRAY_IDX(cmds->cmds, i, rrd_cmd_t);

        /* free all the saved requests */
        if (RRD_CONF_DEF == cmd->type && cmd->d.requests) {
            while ((rr = apr_array_pop(cmd->d.requests))) {
                apr_pool_destroy((*rr)->pool);
            }
        }

    }

    return OK;
}

static int get_rrdgraph(request_rec *r)
{
    rrd_info_t *grinfo = NULL;
    apr_array_header_t *args;
    apr_bucket_brigade *bb = apr_brigade_create(r->pool,
            r->connection->bucket_alloc);
    rrd_cmds_t *cmds;

    apr_status_t rv;
    int ret;

    /* pull apart the query string, reject unrecognised options */
    ret = parse_query(r, &cmds);
    if (OK != ret) {
        return ret;
    }

    /* resolve permissions and wildcards of rrd files */
    ret = resolve_rrds(r, cmds);
    if (OK != ret) {
        return ret;
    }

    /* create the args string for rrd_graph */
    ret = generate_args(r, cmds, &args);
    if (OK != ret) {
        return ret;
    }

    /* rrd_graph_v is not thread safe */
#if APR_HAS_THREADS
    if (rrd_mutex) {
        apr_thread_mutex_lock(rrd_mutex);
    }
#endif

    /* we're ready, let's generate the graph */
    grinfo = rrd_graph_v(args->nelts, (char **)args->elts);
    if (grinfo == NULL) {
        log_message(r, APR_SUCCESS, "Call to rrd_graph_v failed", rrd_get_error());
        ret = HTTP_INTERNAL_SERVER_ERROR;
    }
    else {
        /* grab the image data from the results */
        while (grinfo) {
            if (strcmp(grinfo->key, "image") == 0) {
                apr_brigade_write(bb, NULL, NULL, (const char *)grinfo->value.u_blo.ptr,
                        grinfo->value.u_blo.size);
                ap_set_content_length(r, grinfo->value.u_blo.size);
                break;
            }
            /* skip anything else */
            grinfo = grinfo->next;
        }
        rrd_info_free(grinfo);
    }
    rrd_clear_error();

#if APR_HAS_THREADS
    if (rrd_mutex) {
        apr_thread_mutex_unlock(rrd_mutex);
    }
#endif

    /* trigger an early cleanup to save memory */
    ret = cleanup_args(r, cmds);
    if (OK != ret) {
        return ret;
    }

    /* send our response down the stack */
    if (OK == ret) {
        rv = ap_pass_brigade(r->output_filters, bb);
        if (rv == APR_SUCCESS || r->status != HTTP_OK
                || r->connection->aborted) {
            return OK;
        }
        else {
            /* no way to know what type of error occurred */
            ap_log_rerror(
                    APLOG_MARK, APLOG_DEBUG, rv, r, "rrd_handler: ap_pass_brigade returned %i", rv);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return ret;
}

static int get_rrd(request_rec *r)
{
    rrd_conf *conf = ap_get_module_config(r->per_dir_config,
            &rrd_module);
    /*
     * if a file does not exist, assume it is a request for a graph, otherwise
     * go with the original file.
     */
    if ((conf->format) ||
    		(r->filename && r->finfo.filetype == APR_NOFILE && parse_rrdgraph_suffix(r))) {
        return get_rrdgraph(r);
    }

    return DECLINED;
}

static int rrd_fixups(request_rec *r)
{
    rrd_conf *conf = ap_get_module_config(r->per_dir_config,
            &rrd_module);

    if (!conf) {
        return DECLINED;
    }

    if (conf->graph) {
    	r->handler = "rrdgraph";
    	return OK;
    }

    return DECLINED;
}

static int rrd_handler(request_rec *r)
{

    rrd_conf *conf = ap_get_module_config(r->per_dir_config,
            &rrd_module);

    if (!conf || !conf->graph) {
        return DECLINED;
    }

    /* A GET should return the CRL, OPTIONS should return the WADL */
    ap_allow_methods(r, 1, "GET", "OPTIONS", NULL);
    if (!strcmp(r->method, "GET")) {
        return get_rrd(r);
    }
    else if (!strcmp(r->method, "OPTIONS")) {
        return options_wadl(r, conf);
    }
    else {
        return HTTP_METHOD_NOT_ALLOWED;
    }

}

static void rrd_child_init(apr_pool_t *pchild, server_rec *s)
{
#if APR_HAS_THREADS
    int threaded_mpm;
    if (ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded_mpm) == APR_SUCCESS
        && threaded_mpm)
    {
        apr_thread_mutex_create(&rrd_mutex, APR_THREAD_MUTEX_DEFAULT, pchild);
    }
#endif
}

static void *create_rrd_config(apr_pool_t *p, char *dummy)
{
    rrd_conf *new = (rrd_conf *) apr_pcalloc(p, sizeof(rrd_conf));

    new->options = apr_array_make(p, 10, sizeof(rrd_opt_t));
    new->elements = apr_array_make(p, 10, sizeof(rrd_cmd_t));
    new->env = apr_hash_make(p);

    return (void *) new;
}

static void *merge_rrd_config(apr_pool_t *p, void *basev, void *addv)
{
    rrd_conf *new = (rrd_conf *) apr_pcalloc(p, sizeof(rrd_conf));
    rrd_conf *add = (rrd_conf *) addv;
    rrd_conf *base = (rrd_conf *) basev;

    new->options = apr_array_append(p, add->options, base->options);
    new->elements = apr_array_append(p, add->elements, base->elements);
    new->env = apr_hash_overlay(p, add->env, base->env);

    new->location = (add->location_set == 0) ? base->location : add->location;
    new->location_set = add->location_set || base->location_set;

    new->format = (add->format_set == 0) ? base->format : add->format;
    new->format_set = add->format_set || base->format_set;

    new->graph = (add->graph_set == 0) ? base->graph : add->graph;
    new->graph_set = add->graph_set || base->graph_set;

    return new;
}

static const char *set_rrd_graph_format(cmd_parms *cmd, void *dconf, const char *format)
{
    rrd_conf *conf = dconf;

    conf->format = format;
    conf->format_set = 1;

    return NULL;
}

static const char *set_rrd_graph_option(cmd_parms *cmd, void *dconf, const char *key, const char *val)
{
    rrd_conf *conf = dconf;
    ap_expr_info_t *eval = NULL;
    const char *expr_err = NULL;

    if (val) {

        eval = ap_expr_parse_cmd(cmd, val, AP_EXPR_FLAG_STRING_RESULT,
                &expr_err, NULL);

        if (expr_err) {
            return apr_pstrcat(cmd->temp_pool,
                    "Cannot parse expression '", val, "': ",
                    expr_err, NULL);
        }

    }

    if (!parse_option(cmd->pool, key, val, eval, conf->options)) {
        return apr_pstrcat(cmd->pool, "Could not recognise option: ", key, NULL);
    }

    return NULL;
}

static const char *set_rrd_graph_element(cmd_parms *cmd, void *dconf,
        const char *element, const char *val1, const char *val2)
{
    rrd_conf *conf = dconf;
    ap_expr_info_t *eval1 = NULL, *eval2 = NULL;
    const char *expr_err = NULL;

    if (val1) {

        eval1 = ap_expr_parse_cmd(cmd, val1, AP_EXPR_FLAG_STRING_RESULT,
                &expr_err, NULL);

        if (expr_err) {
            return apr_pstrcat(cmd->temp_pool,
                    "Cannot parse expression '", val1, "': ",
                    expr_err, NULL);
        }

    }

    if (val2) {

        eval2 = ap_expr_parse_cmd(cmd, val2, AP_EXPR_FLAG_STRING_RESULT,
                &expr_err, NULL);

        if (expr_err) {
            return apr_pstrcat(cmd->temp_pool,
                    "Cannot parse expression '", val2, "': ",
                    expr_err, NULL);
        }

    }

    if (!parse_element(cmd->pool, element, eval1, eval2, conf->elements)) {
        return apr_psprintf(cmd->pool,
                "RRDGraphElement was not recognised: %s", element);
    }

    return NULL;
}

static const char *set_rrd_graph_env(cmd_parms *cmd, void *dconf,
const char *key, const char *val)
{
    rrd_conf *conf = dconf;
    ap_expr_info_t *eval;
    const char *expr_err = NULL;

    eval = ap_expr_parse_cmd(cmd, val, AP_EXPR_FLAG_STRING_RESULT,
            &expr_err, NULL);

    if (expr_err) {
        return apr_pstrcat(cmd->temp_pool,
                "Cannot parse expression '", val, "': ",
                expr_err, NULL);
    }

    apr_hash_set(conf->env, key, APR_HASH_KEY_STRING, eval);

    return NULL;
}

static const char *set_rrd_graph(cmd_parms *cmd, void *dconf, int flag)
{
    rrd_conf *conf = dconf;

    conf->graph = flag;
    conf->graph_set = 1;

    return NULL;
}

static const command_rec rrd_cmds[] = {
    AP_INIT_FLAG("RRDGraph", set_rrd_graph, NULL, RSRC_CONF | ACCESS_CONF,
        "Enable the rrdgraph image generator."),
    AP_INIT_TAKE1("RRDGraphFormat", set_rrd_graph_format, NULL, RSRC_CONF | ACCESS_CONF,
        "Explicitly set the image format. Takes any valid --imgformat value."),
    AP_INIT_TAKE12("RRDGraphOption", set_rrd_graph_option, NULL, RSRC_CONF | ACCESS_CONF,
        "Options for the rrdgraph image generator."),
    AP_INIT_TAKE123("RRDGraphElement", set_rrd_graph_element, NULL, RSRC_CONF | ACCESS_CONF,
        "Elements for the rrdgraph image generator. If specified, an optional expression can be set for the legend where appropriate."),
    AP_INIT_TAKE2("RRDGraphEnv", set_rrd_graph_env, NULL, RSRC_CONF | ACCESS_CONF,
        "Summarise environment variables from the RRD file requests."), { NULL }
};

static void register_hooks(apr_pool_t *p)
{
    ap_hook_child_init(rrd_child_init,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_fixups(rrd_fixups, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_handler(rrd_handler, NULL, NULL, APR_HOOK_FIRST);
}

AP_DECLARE_MODULE(rrd) = {
    STANDARD20_MODULE_STUFF,
    create_rrd_config, /* create per-directory config structure */
    merge_rrd_config, /* merge per-directory config structures */
    NULL, /* create per-server config structure */
    NULL, /* merge per-server config structures */
    rrd_cmds, /* command apr_table_t */
    register_hooks /* register hooks */
};
