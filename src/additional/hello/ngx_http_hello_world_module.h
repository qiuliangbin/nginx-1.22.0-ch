//
// Created by Administrator on 2023/5/18.
//

#ifndef NGINX_1_22_0_CH_NGX_HTTP_HELLO_WORLD_MODULE_H
#define NGINX_1_22_0_CH_NGX_HTTP_HELLO_WORLD_MODULE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_slab.h>

extern ngx_slab_pool_t *ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size);

typedef struct{
    ngx_shm_zone_t *shm_zone;
} ngx_http_hello_world_loc_conf_t;

typedef struct{
    int count;
} ngx_http_hello_world_shm_count_t;

static char* ngx_http_hello_world(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);
static void* ngx_http_hello_world_create_loc_conf(ngx_conf_t* cf);
static char* ngx_http_hello_world_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child);

static ngx_int_t ngx_http_hello_world_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data);

static ngx_command_t ngx_http_hello_world_commands[] = {
        {
                ngx_string("hello_world"), //The command name
                NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
                ngx_http_hello_world, //The command handler
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_hello_world_loc_conf_t, shm_zone),
                NULL
        },
        ngx_null_command
};

static ngx_http_module_t ngx_http_hello_world_module_ctx = {
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        ngx_http_hello_world_create_loc_conf,
        ngx_http_hello_world_merge_loc_conf
};

ngx_module_t ngx_http_hello_world_module = {
        NGX_MODULE_V1,
        &ngx_http_hello_world_module_ctx,
        ngx_http_hello_world_commands,
        NGX_HTTP_MODULE,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NGX_MODULE_V1_PADDING
};

#endif //NGINX_1_22_0_CH_NGX_HTTP_HELLO_WORLD_MODULE_H
