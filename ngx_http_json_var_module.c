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
static ngx_int_t ngx_http_json_args_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_http_variable_t ngx_http_json_var_variables[] = {

    { ngx_string("json_headers"), NULL,
      ngx_http_json_headers_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_CHANGEABLE, 0 },
    { ngx_string("json_args"), NULL,
      ngx_http_json_args_variable, 0,
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
        if (ngx_memcmp(fields[i].name.data, "json_headers", sizeof("json_headers") - 1) == 0) {
            p = ngx_copy(p, values[i].v.data, values[i].v.len);
        } else if (ngx_memcmp(fields[i].name.data, "json_args", sizeof("json_args") - 1) == 0) {
//            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "json_args.data = %V, json_args.len = %i", &values[i].v, values[i].v.len);
            p = ngx_copy(p, values[i].v.data, values[i].v.len);
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
    u_char* p;
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
    p = ngx_palloc(r->pool, size);
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

static ngx_int_t ngx_http_json_args_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
//    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "r->args.data = %V, r->args.len = %i", &r->args, r->args.len);
    size_t size = sizeof("{}\"\":\"\"") - 1;
    u_char c, *p, *start, *end;
    for (start = end = r->args.data, end += r->args.len; start < end; start++) {
        size++;
        if (*start == '\'' || *start == '"') size++;
        else if (*start == '&') size += sizeof("\"\":\"\",");// - 3;
    }
    p = ngx_palloc(r->pool, size);
    if (p == NULL) return NGX_ERROR;
    v->data = p;
    *p++ = '{';
    for (start = end = r->args.data, end += r->args.len; start < end; start++) {
        if (p != v->data + 1) *p++ = ',';
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
