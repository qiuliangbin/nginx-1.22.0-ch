/*
 * Copyright (C) qiulb
 * Copyright (C) Sangfor, Inc.
 */
#include <ngx_http.h>
#include <ngx_config.h>
#include <ngx_core.h>


static void *ngx_http_location_count_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_location_count_create_cmd_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/*
    提供8个方法，解析配置文件的
    解析 http {}
    1 8 2 7 3 6 4 5 这种顺序解析的
*/
static ngx_http_module_t ngx_http_location_count_ctx = {

        NULL,                                       /* preconfiguration */
        NULL,                                       /* postconfiguration */

        NULL,                                       /* create main configuration */
        NULL,                                       /* init main configuration */

        NULL,                                       /* create server configuration */
        NULL,                                       /* merge server configuration */

        ngx_http_location_count_create_loc_conf,    /* create location configuration */
        NULL                                        /* merge location configuration */
};

static ngx_command_t ngx_http_location_count_commands[] = {

        {
                ngx_string("count"),
                NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
                ngx_http_location_count_create_cmd_set,
                NGX_HTTP_LOC_CONF_OFFSET,
                0,
                NULL
        },

}

ngx_module_t ngx_http_location_count_module = {
        NGX_MODULE_V1,
        &ngx_http_count_ctx,     /* module context */
        NULL,                                  /* module directives */
        NGX_HTTP_MODULE,                       /* module type */
        NULL,                                  /* init master */
        NULL,                                  /* init module */
        NULL,                                  /* init process */
        NULL,                                  /* init thread */
        NULL,                                  /* exit thread */
        NULL,                                  /* exit process */
        NULL,                                  /* exit master */
        NGX_MODULE_V1_PADDING
};

static void *ngx_http_location_count_create_loc_conf(ngx_conf_t *cf)
{
    return ;
}

static char *ngx_http_location_count_create_cmd_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    return ;
}