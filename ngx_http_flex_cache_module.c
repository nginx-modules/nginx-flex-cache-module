/*
 * Copyright (C) 2012 Yasar Semih Alev
 *
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#if (NGX_HTTP_CACHE)

ngx_int_t   ngx_http_flex_cache_init(ngx_conf_t *);
ngx_int_t   ngx_http_flex_cache_add_variables(ngx_conf_t *);
void       *ngx_http_flex_cache_create_loc_conf(ngx_conf_t *);
char       *ngx_http_flex_cache_merge_loc_conf(ngx_conf_t *, void *, void *);
char       *ngx_http_flex_cache_conf(ngx_conf_t *, ngx_command_t *, void *);
char       *ngx_http_flex_cache_key_conf(ngx_conf_t *, ngx_command_t *, void *);
ngx_int_t   ngx_http_flex_cache_status(ngx_http_request_t *,
                ngx_http_variable_value_t *, uintptr_t);
ngx_int_t   ngx_http_flex_cache_handler(ngx_http_request_t *);

typedef struct {
    ngx_flag_t                 enabled;
    ngx_shm_zone_t            *cache;
    size_t                     block_size;
    ngx_http_complex_value_t   cache_key;
    ngx_uint_t                 cache_min_uses;
    ngx_array_t               *cache_valid;
} ngx_http_flex_cache_loc_conf_t;

typedef struct {
    ngx_uint_t                 cache_status;
} ngx_http_flex_cache_ctx_t;

ngx_module_t  ngx_http_flex_cache_module;

static ngx_command_t  ngx_http_flex_cache_module_commands[] = {

    { ngx_string("flex_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_flex_cache_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("flex_cache_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_flex_cache_key_conf,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("flex_cache_path"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      ngx_http_file_cache_set_slot,
      0,
      0,
      &ngx_http_flex_cache_module },

    { ngx_string("flex_cache_block_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, 
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flex_cache_loc_conf_t, block_size),
      NULL },

    { ngx_string("flex_cache_min_uses"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, 
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flex_cache_loc_conf_t, cache_min_uses),
      NULL },

    { ngx_string("flex_cache_valid"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_file_cache_valid_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_flex_cache_loc_conf_t, cache_valid),
      NULL }, 

      ngx_null_command

};

static ngx_http_variable_t ngx_http_flex_cache_module_variables[] = {

    { ngx_string("flex_cache_status"), NULL,
      ngx_http_flex_cache_status, 0,
      NGX_HTTP_VAR_NOHASH|NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }

};

static ngx_http_module_t  ngx_http_flex_cache_module_ctx = {
    ngx_http_flex_cache_add_variables,    /* preconfiguration */
    ngx_http_flex_cache_init,             /* postconfiguration */

    NULL,                                 /* create main configuration */
    NULL,                                 /* init main configuration */

    NULL,                                 /* create server configuration */
    NULL,                                 /* merge server configuration */

    ngx_http_flex_cache_create_loc_conf,  /* create location configuration */
    ngx_http_flex_cache_merge_loc_conf    /* merge location configuration */
};

ngx_module_t  ngx_http_flex_cache_module = {
    NGX_MODULE_V1,
    &ngx_http_flex_cache_module_ctx,      /* module context */
    ngx_http_flex_cache_module_commands,  /* module directives */
    NGX_HTTP_MODULE,                      /* module type */
    NULL,                                 /* init master */
    NULL,                                 /* init module */
    NULL,                                 /* init process */
    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */
    NULL,                                 /* exit process */
    NULL,                                 /* exit master */
    NGX_MODULE_V1_PADDING
};

ngx_int_t
ngx_http_flex_cache_handler(ngx_http_request_t *r)
{
    return NGX_DECLINED;
}

ngx_int_t
ngx_http_flex_cache_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_flex_cache_handler;

    return NGX_OK;
}

ngx_int_t
ngx_http_flex_cache_status(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_flex_cache_ctx_t  *fcctx;
    ngx_uint_t                  n;

    fcctx = ngx_http_get_module_ctx(r, ngx_http_flex_cache_module);

    if (fcctx == NULL || fcctx->cache_status == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    n = fcctx->cache_status - 1;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ngx_http_cache_status[n].len;
    v->data = ngx_http_cache_status[n].data;

    return NGX_OK;
}

char *
ngx_http_flex_cache_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                       *value = cf->args->elts;
    ngx_http_flex_cache_loc_conf_t  *fc = conf;

    if (fc->cache != NGX_CONF_UNSET_PTR && fc->cache != NULL) {
        return "is duplicate";
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        fc->enabled = 0;
        fc->cache = NULL;
        return NGX_CONF_OK;
    }

    fc->cache = ngx_shared_memory_add(cf, &value[1], 0,
                                          &ngx_http_flex_cache_module);
    if (fc->cache == NULL) {
        return NGX_CONF_ERROR;
    }

    fc->enabled = 1;

    return NGX_CONF_OK;
}

char *
ngx_http_flex_cache_key_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                         *value = cf->args->elts;
    ngx_http_flex_cache_loc_conf_t    *fc = conf;
    ngx_http_compile_complex_value_t   ccv;

    if (fc->cache_key.value.len) {
        return "is duplicate";
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &fc->cache_key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

void *
ngx_http_flex_cache_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_flex_cache_loc_conf_t  *fc;

    fc = ngx_pcalloc(cf->pool, sizeof(ngx_http_flex_cache_loc_conf_t));
    if (fc == NULL) {
        return NGX_CONF_ERROR;
    }

    fc->enabled = NGX_CONF_UNSET;
    fc->cache = NGX_CONF_UNSET_PTR;
    fc->block_size = NGX_CONF_UNSET_SIZE;
    fc->cache_min_uses = NGX_CONF_UNSET_UINT;
    fc->cache_valid = NGX_CONF_UNSET_PTR;

    return fc;
}

char *
ngx_http_flex_cache_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_flex_cache_loc_conf_t  *prev = parent;
    ngx_http_flex_cache_loc_conf_t  *fc = child;

    ngx_conf_merge_value(fc->enabled, prev->enabled, 0);

    if (fc->cache_key.value.data == NULL) {
        fc->cache_key = prev->cache_key;
    }

    ngx_conf_merge_ptr_value(fc->cache, prev->cache, NULL);
    if (fc->cache && fc->cache->data == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"flex cache\" zone \"%V\" is unknown",
                           &fc->cache->shm.name);
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_size_value(fc->block_size, prev->block_size, 512 * 1024);

    ngx_conf_merge_uint_value(fc->cache_min_uses, prev->cache_min_uses, 1);

    ngx_conf_merge_ptr_value(fc->cache_valid, prev->cache_valid, NULL);

    return NGX_CONF_OK;
}

ngx_int_t
ngx_http_flex_cache_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    v = ngx_http_flex_cache_module_variables;

    var = ngx_http_add_variable(cf, &v->name, v->flags);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = v->get_handler;
    var->data = v->data;

    return NGX_OK;
}

#else

static ngx_http_module_t  ngx_http_flex_cache_module_ctx = {
    NULL,  /* preconfiguration */
    NULL,  /* postconfiguration */

    NULL,  /* create main configuration */
    NULL,  /* init main configuration */

    NULL,  /* create server configuration */
    NULL,  /* merge server configuration */

    NULL,  /* create location configuration */
    NULL,  /* merge location configuration */
};

ngx_module_t  ngx_http_flex_cache_module = {
    NGX_MODULE_V1,
    &ngx_http_flex_cache_module_ctx,  /* module context */
    NULL,                             /* module directives */
    NGX_HTTP_MODULE,                  /* module type */
    NULL,                             /* init master */
    NULL,                             /* init module */
    NULL,                             /* init process */
    NULL,                             /* init thread */
    NULL,                             /* exit thread */
    NULL,                             /* exit process */
    NULL,                             /* exit master */
    NGX_MODULE_V1_PADDING
};

#endif
