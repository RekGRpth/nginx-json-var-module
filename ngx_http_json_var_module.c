#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

// typedefs
typedef struct {
    ngx_str_t name;
    ngx_http_complex_value_t cv;
} ngx_http_json_var_field_t;

typedef struct {
    ngx_str_t v;
    uintptr_t escape;
} ngx_http_json_var_value_t;

typedef struct {
    ngx_array_t fields;        // of ngx_http_json_var_field_t
    size_t base_json_size;
} ngx_http_json_var_ctx_t;

typedef struct {
    ngx_http_json_var_ctx_t* ctx;
    ngx_conf_t *cf;
} ngx_http_json_var_conf_ctx_t;

// forward decls
static char *ngx_http_json_var_json_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

// globals
static ngx_command_t ngx_http_json_var_commands[] = {

    { ngx_string("json_var"),
    NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE1,
    ngx_http_json_var_json_block,
    0,
    0,
    NULL },

    ngx_null_command
};

static ngx_int_t ngx_http_json_headers_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_json_cookies_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_json_get_vars_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_json_post_vars_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_http_variable_t ngx_http_json_var_variables[] = {

    { ngx_string("json_headers"), NULL,
      ngx_http_json_headers_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE, 0 },
    { ngx_string("json_cookies"), NULL,
      ngx_http_json_cookies_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE, 0 },
    { ngx_string("json_get_vars"), NULL,
      ngx_http_json_get_vars_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE, 0 },
    { ngx_string("json_post_vars"), NULL,
      ngx_http_json_post_vars_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_int_t ngx_http_json_var_add_variables(ngx_conf_t *cf);
static ngx_http_module_t ngx_http_json_var_module_ctx = {
    ngx_http_json_var_add_variables,    /* preconfiguration */
    NULL,                                /* postconfiguration */

    NULL,                                /* create main configuration */
    NULL,                                /* init main configuration */

    NULL,                                /* create server configuration */
    NULL,                                /* merge server configuration */

    NULL,                                /* create location configuration */
    NULL                                /* merge location configuration */
};

ngx_module_t ngx_http_json_var_module = {
    NGX_MODULE_V1,
    &ngx_http_json_var_module_ctx,        /* module context */
    ngx_http_json_var_commands,            /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};

static char *
ngx_http_json_var_json(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    ngx_http_compile_complex_value_t ccv;
    ngx_http_json_var_field_t* item;
    ngx_http_json_var_conf_ctx_t* conf_ctx;
    ngx_str_t *value;

    conf_ctx = cf->ctx;

    value = cf->args->elts;

    if (cf->args->nelts != 2) 
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid number of parameters");
        return NGX_CONF_ERROR;
    }

    item = ngx_array_push(&conf_ctx->ctx->fields);
    if (item == NULL)
    {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = conf_ctx->cf;
    ccv.value = &value[1];
    ccv.complex_value = &item->cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    item->name = value[0];

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_json_var_variable(
    ngx_http_request_t *r, 
    ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_json_var_field_t* fields;
    ngx_http_json_var_value_t* values;
    ngx_http_json_var_ctx_t* ctx = (ngx_http_json_var_ctx_t *)data;
    ngx_uint_t i;
    size_t size;
    u_char* p;

    // allocate the values array
    values = ngx_palloc(r->pool, sizeof(values[0]) * ctx->fields.nelts);
    if (values == NULL)
    {
        return NGX_ERROR;
    }

    // evaluate the complex values
    fields = ctx->fields.elts;
    size = ctx->base_json_size;

    for (i = 0; i < ctx->fields.nelts; i++)
    {
        if (ngx_http_complex_value(r, &fields[i].cv, &values[i].v) != NGX_OK)
        {
            return NGX_ERROR;
        }

        values[i].escape = ngx_escape_json(NULL, values[i].v.data, values[i].v.len);

        size += values[i].v.len + values[i].escape;
    }

    // allocate the result size
    p = ngx_palloc(r->pool, size);
    if (p == NULL)
    {
        return NGX_ERROR;
    }

    // build the result
    v->data = p;

    *p++ = '{';
    i = 0;
    for (;;)
    {
        *p++ = '"';
        p = ngx_copy(p, fields[i].name.data, fields[i].name.len);
        *p++ = '"';
        *p++ = ':';
        if (ngx_strncasecmp(fields[i].name.data, (u_char *)"json_headers", sizeof("json_headers") - 1) == 0) {
            p = ngx_copy(p, values[i].v.data, values[i].v.len);
        } else if (ngx_strncasecmp(fields[i].name.data, (u_char *)"json_cookies", sizeof("json_cookies") - 1) == 0) {
            p = ngx_copy(p, values[i].v.data, values[i].v.len);
        } else if (ngx_strncasecmp(fields[i].name.data, (u_char *)"json_get_vars", sizeof("json_get_vars") - 1) == 0) {
            p = ngx_copy(p, values[i].v.data, values[i].v.len);
        } else if (ngx_strncasecmp(fields[i].name.data, (u_char *)"json_post_vars", sizeof("json_post_vars") - 1) == 0) {
            p = ngx_copy(p, values[i].v.data, values[i].v.len);
//        } else if (ngx_strncasecmp(fields[i].name.data, (u_char *)"request_body", sizeof("request_body") - 1) == 0 && r->headers_in.content_type && ngx_strncasecmp(r->headers_in.content_type->value.data, (u_char *)"application/json", sizeof("application/json") - 1) == 0) {
//            p = ngx_copy(p, values[i].v.data, values[i].v.len);
        } else {
            *p++ = '"';
            if (values[i].escape)
            {
                p = (u_char*)ngx_escape_json(p, values[i].v.data, values[i].v.len);
            }
            else
            {
                p = ngx_copy(p, values[i].v.data, values[i].v.len);
            }
            *p++ = '"';
        }

        i++;
        if (i >= ctx->fields.nelts)
        {
            break;
        }
        *p++ = ',';
    }
    *p++ = '}';
    *p = '\0';

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = p - v->data;

    if (v->len >= size)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "result length %uD exceeded allocated length %uz", (uint32_t)v->len, size);
        return NGX_ERROR;
    }

    return NGX_OK;
}

static char *
ngx_http_json_var_json_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_json_var_conf_ctx_t conf_ctx;
    ngx_http_json_var_field_t* fields;
    ngx_http_json_var_ctx_t *ctx;
    ngx_http_variable_t *var;
    ngx_conf_t save;
    ngx_uint_t i;
    ngx_str_t *value;
    ngx_str_t name;
    char *rv;

    value = cf->args->elts;

    // get the variable name
    name = value[1];

    if (name.data[0] != '$') 
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid variable name \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    name.len--;
    name.data++;

    // initialize the context
    ctx = ngx_pcalloc(cf->pool, sizeof(*ctx));
    if (ctx == NULL)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_array_init(&ctx->fields, cf->pool, 10, sizeof(ngx_http_json_var_field_t)) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    // add the variable
    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) 
    {
        return NGX_CONF_ERROR;
    }

    // parse the block
    var->get_handler = ngx_http_json_var_variable;
    var->data = (uintptr_t)ctx;

    conf_ctx.cf = &save;
    conf_ctx.ctx = ctx;

    save = *cf;
    cf->ctx = &conf_ctx;
    cf->handler = ngx_http_json_var_json;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NGX_CONF_OK) 
    {
        return rv;
    }

    if (ctx->fields.nelts <= 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "no fields defined in \"json_var\" block");
        return NGX_CONF_ERROR;
    }

    // get the base json size
    ctx->base_json_size = sizeof("{}");

    fields = ctx->fields.elts;
    for (i = 0; i < ctx->fields.nelts; i++)
    {
        ctx->base_json_size += sizeof("\"\":\"\",") + fields[i].name.len;
    }

    return rv;
}

static ngx_int_t ngx_http_json_headers_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_uint_t i;
    size_t size = sizeof("{}");
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *header = part->elts;
    for (i = 0; ; ) {
        size += sizeof("\"\":\"\",") + header[i].key.len + header[i].value.len + ngx_escape_json(NULL, header[i].value.data, header[i].value.len);
        i++;
        if (i >= part->nelts) {
            if (part->next == NULL) break;
            part = part->next;
            header = part->elts;
            i = 0;
        }
    }
    u_char *p = ngx_palloc(r->pool, size);
    if (p == NULL) return NGX_ERROR;
    v->data = p;
    *p++ = '{';
    part = &r->headers_in.headers.part;
    header = part->elts;
    for (i = 0; ; ) {
        *p++ = '"';
        p = ngx_copy(p, header[i].key.data, header[i].key.len);
        *p++ = '"';
        *p++ = ':';
        *p++ = '"';
        p = (u_char*)ngx_escape_json(p, header[i].value.data, header[i].value.len);
        *p++ = '"';
        i++;
        if (i >= part->nelts) {
            if (part->next == NULL) break;
            part = part->next;
            header = part->elts;
            i = 0;
        }
        *p++ = ',';
    }
    *p++ = '}';
    *p = '\0';
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = p - v->data;
    if (v->len >= size) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "result length %uD exceeded allocated length %uz", (uint32_t)v->len, size);
        return NGX_ERROR;
    }
    return NGX_OK;
}

static size_t ngx_http_json_cookies_size(size_t size, u_char *start, u_char *end) {
    for (; start < end; start++, size++) {
        if (*start == '\'' || *start == '"') size++;
        else if (*start == ';') size += sizeof("\"\":\"\",") - 1;
    }
    return size;
}

static u_char *ngx_http_json_cookies_data(u_char *p, u_char *start, u_char *end, u_char *cookies_start) {
    for (u_char *name = p ; start < end; ) {
        while(*start == ' ' && start < end) ++start;
        name = p;
        if (p != cookies_start) *p++ = ',';
        *p++ = '"';
        while (*start != ';' && *start != '=' && start < end) {
            if (*start == '\'') *p++ = '\'';
            else if (*start == '"') *p++ = '\\';
            *p++ = *start++;
        }
        if (*start == ';') {
            p = name;
            start++;
        } else if (start >= end) {
            p = name;
        } else {
            start++;
            *p++ = '"';
            *p++ = ':';
            *p++ = '"';
            while (*start == ' ' && start < end) ++start;
            while (*start != ';' && *start != '=' && start < end) {
                if (*start == '\'') *p++ = '\'';
                else if (*start == '"') *p++ = '\\';
                *p++ = *start++;
            }
            *p++ = '"';
            start++;
            if (*(name + (*name == ',' ? 1 : 0)) == '"' && *(name + (*name == ',' ? 2 : 1)) == '"') {
                p = name;
            }
        }
    }
    return p;
}

static ngx_int_t ngx_http_json_cookies_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_uint_t i;
    size_t size = sizeof("{}") + 1;
    ngx_table_elt_t **h = r->headers_in.cookies.elts;
    for (i = 0; i < r->headers_in.cookies.nelts; i++) size = ngx_http_json_cookies_size(size, h[i]->value.data, h[i]->value.data + h[i]->value.len);
    u_char* p = ngx_palloc(r->pool, size);
    if (p == NULL) return NGX_ERROR;
    v->data = p;
    *p++ = '{';
    for (i = 0; i < r->headers_in.cookies.nelts; i++) p = ngx_http_json_cookies_data(p, h[i]->value.data, h[i]->value.data + h[i]->value.len, v->data + 1);
    *p++ = '}';
    *p = '\0';
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = p - v->data;
    if (v->len >= size) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "result length %uD exceeded allocated length %uz", (uint32_t)v->len, size);
        return NGX_ERROR;
    }
    return NGX_OK;
}

static size_t ngx_http_json_vars_size(size_t size, u_char *start, u_char *end) {
    for (; start < end; start++, size++) {
        if (*start == '\'' || *start == '"') size++;
        else if (*start == '&') size += sizeof("\"\":\"\",");// - 3;
    }
    return size;
}

static u_char *ngx_http_json_vars_data(u_char *p, u_char *start, u_char *end, u_char *args_start) {
    for (u_char c; start < end; ) {
        if (p != args_start) *p++ = ',';
        *p++ = '"';
        while ((*start == '=' || *start == '&') && start < end) start++;
        while (*start != '=' && *start != '&' && start < end) {
            if (*start == '%') {
                start++;
                c = *start++;
                if (c >= 0x30) c -= 0x30;
                if (c >= 0x10) c -= 0x07;
                *p = (c << 4);
                c = *start++;
                if (c >= 0x30) c -= 0x30;
                if (c >= 0x10) c -= 0x07;
                *p += c;
                c = *p;
            } else if (*start == '+') {
                start++;
                c = ' ';
            } else c = *start++;
            if (c == '\'') *p++ = '\'';
            else if (c == '"') *p++ = '\\';
            *p++ = c;
        }
        *p++ = '"';
        *p++ = ':';
        if (*start != '&' && start < end) {
            *p++ = '"';
            if (*start != '&') {
                start++;
                while (*start != '&' && start < end) {
                    if (*start == '%') {
                        start++;
                        c = *start++;
                        if (c >= 0x30) c -= 0x30;
                        if (c >= 0x10) c -= 0x07;
                        *p = (c << 4);
                        c = *start++;
                        if (c >= 0x30) c -= 0x30;
                        if (c >= 0x10) c -= 0x07;
                        *p += c;
                        c = *p;
                    } else if (*start == '+') {
                        start++;
                        c = ' ';
                    } else c = *start++;
                    if (c == '\'') *p++ = '\'';
                    else if (c == '"') *p++ = '\\';
                    *p++ = c;
                }
            } else start++;
            *p++ = '"';
        } else {
            *p++ = 'n';
            *p++ = 'u';
            *p++ = 'l';
            *p++ = 'l';
        }
    }
    return p;
}

static ngx_int_t ngx_http_json_get_vars_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    size_t size = sizeof("{}\"\":\"\"") - 1;
    size = ngx_http_json_vars_size(size, r->args.data, r->args.data + r->args.len);
    u_char *p = ngx_palloc(r->pool, size);
    if (p == NULL) return NGX_ERROR;
    v->data = p;
    *p++ = '{';
    p = ngx_http_json_vars_data(p, r->args.data, r->args.data + r->args.len, v->data + 1);
    *p++ = '}';
    *p = '\0';
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = p - v->data;
//    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "v->data = %s, v->len = %i, size = %i", v->data, v->len, size);
    if (v->len >= size) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "result length %uD exceeded allocated length %uz", (uint32_t)v->len, size);
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_json_post_vars_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    char parse_body = 0;
    ngx_str_t echo_request_body_var = ngx_string("echo_request_body");
    ngx_http_variable_value_t *echo_request_body = ngx_http_get_variable(r, &echo_request_body_var, ngx_hash_key(echo_request_body_var.data, echo_request_body_var.len));
    if (echo_request_body->data != NULL) {
        if (r->headers_in.content_type) {
            if (ngx_strncasecmp(r->headers_in.content_type->value.data, (u_char *)"application/x-www-form-urlencoded", sizeof("application/x-www-form-urlencoded") - 1) == 0) {
                parse_body = 1;
            } else if (ngx_strncasecmp(r->headers_in.content_type->value.data, (u_char *)"application/json", sizeof("application/json") - 1) == 0) {
                parse_body = 2;
            } else if (ngx_strncasecmp(r->headers_in.content_type->value.data, (u_char *)"multipart/form-data", sizeof("multipart/form-data") - 1) == 0) {
                u_char *mime_type_end_ptr = (u_char*) ngx_strchr(r->headers_in.content_type->value.data, ';');
                if (mime_type_end_ptr == NULL) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "mime_type_end_ptr == NULL");
                } else {
                    u_char *boundary_start_ptr = ngx_strstrn(mime_type_end_ptr, "boundary=", sizeof("boundary=") - 1 - 1);
                    if (boundary_start_ptr == NULL) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "boundary_start_ptr == NULL");
                    } else {
                        boundary_start_ptr += sizeof("boundary=") - 1;
                        u_char *boundary_end_ptr = boundary_start_ptr + strcspn((char *)boundary_start_ptr, " ;\n\r");
                        if (boundary_end_ptr == boundary_start_ptr) {
                            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "boundary_end_ptr == boundary_start_ptr");
                        } else {
                            ngx_str_t boundary = {.len = boundary_end_ptr - boundary_start_ptr + 4, .data = ngx_palloc(r->pool, boundary_end_ptr - boundary_start_ptr + 4 + 1)};
                            if (boundary.data == NULL) {
                                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "boundary.data == NULL");
                            } else {
                                (void) ngx_cpystrn(boundary.data + 4, boundary_start_ptr, boundary_end_ptr - boundary_start_ptr + 1);
                                boundary.data[0] = '\r'; 
                                boundary.data[1] = '\n'; 
                                boundary.data[2] = '-'; 
                                boundary.data[3] = '-'; 
                                boundary.data[boundary.len] = '\0';
//                                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "boundary = %V", &boundary);
                                u_char *d = echo_request_body->data;
//                                u_char *s = d;
//                                u_char *name_start_ptr;
                                for (
                                    u_char *s = d, *name_start_ptr;
                                    (name_start_ptr = ngx_strstrn(s, "\r\nContent-Disposition: form-data; name=\"", sizeof("\r\nContent-Disposition: form-data; name=\"") - 1 - 1)) != NULL;
                                    s += boundary.len
                                ) {
//                                if (name_start_ptr == NULL) {
//                                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "name_start_ptr == NULL");
//                                } else {
                                    name_start_ptr += sizeof("\r\nContent-Disposition: form-data; name=\"") - 1;                                    
                                    u_char *name_end_ptr = ngx_strstrn(name_start_ptr, "\"\r\n\r\n", sizeof("\"\r\n\r\n") - 1 - 1);
                                    if (name_end_ptr == NULL) {
                                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "name_end_ptr == NULL");
                                    } else {
//                                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "name_start_ptr = %s", name_start_ptr);
//                                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "name_end_ptr = %s", name_end_ptr);                                        
                                        if (d != echo_request_body->data) *d++ = '&';
                                        for (s = name_start_ptr; s < name_end_ptr; *d++ = *s++);
                                        *d++ = '=';
                                        u_char *value_start_ptr = name_end_ptr + sizeof("\"\r\n\r\n") - 1;
                                        u_char *value_end_ptr = ngx_strstrn(value_start_ptr, (char *)boundary.data, boundary.len - 1);
                                        if (value_end_ptr == NULL) {
                                            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "value_end_ptr == NULL");
                                        } else {
//                                            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "value_start_ptr = %s", value_start_ptr);
//                                            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "value_end_ptr = %s", value_end_ptr);
                                            for (s = value_start_ptr; s < value_end_ptr; *d++ = *s++);
//                                            *d++ = '&';
//                                            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "echo_request_body->data = %s", echo_request_body->data);
//                                            s += boundary.len;
//                                            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "s = %s", s);
//                                          parse_body = 3;
                                        }
                                    }
                                }
                                *d++ = '\0';
                                echo_request_body->len = d - echo_request_body->data - 1;
                                //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "echo_request_body->data = %s", echo_request_body->data);
                                parse_body = 1;
                            }
                        }
                    }
                }
            }
        }
    }
    size_t size = sizeof("{}\"\":\"\"") - 1;
    if (parse_body == 1) {
        size = ngx_http_json_vars_size(size, echo_request_body->data, echo_request_body->data + echo_request_body->len);
    } else if (parse_body == 2) {
        size = echo_request_body->len + 1;
    }
    u_char *p = ngx_palloc(r->pool, size);
    if (p == NULL) return NGX_ERROR;
    v->data = p;
    if (parse_body == 2) {
        p = ngx_copy(p, echo_request_body->data, echo_request_body->len);
    } else {
        *p++ = '{';
        if (parse_body == 1) {
            p = ngx_http_json_vars_data(p, echo_request_body->data, echo_request_body->data + echo_request_body->len, v->data + 1);
        }
        *p++ = '}';
    }
    *p = '\0';
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = p - v->data;
//    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "v->data = %s, v->len = %i, size = %i", v->data, v->len, size);
    if (v->len >= size) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "result length %uD exceeded allocated length %uz", (uint32_t)v->len, size);
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_json_var_add_variables(ngx_conf_t *cf) {
    ngx_http_variable_t  *var, *v;
    for (v = ngx_http_json_var_variables; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }
        var->get_handler = v->get_handler;
        var->data = v->data;
    }
    return NGX_OK;
}
