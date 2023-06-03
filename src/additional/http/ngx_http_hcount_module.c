/*
 * Copyright (C) qiulb
 * Copyright (C) Sangfor, Inc.
 */
#include <ngx_http.h>
#include <ngx_config.h>
#include <ngx_core.h>


static void *ngx_http_hash_count_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_hash_count(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

typedef struct {
    ngx_rbtree_t rbtree;
    ngx_rbtree_node_t sentinel;
} ngx_http_location_hash_count_shm_t;   // 共享内存

typedef struct {
    ssize_t zone_size;
    ngx_slab_pool_t *pool;
    ngx_http_location_hash_count_shm_t *lcshm;

//    ngx_str_t limit_hash_index; /* $remote_ip$url_path */
//    ngx_int_t limit_count; /* 10 */
//    ngx_str_t limit_time_unit; /* h;m;s -> 小时;分钟;秒 */
} ngx_http_hash_count_loc_conf_t;
/*
    提供8个方法，解析配置文件的
    解析 http {}
    1 8 2 7 3 6 4 5 这种顺序解析的
*/
static ngx_http_module_t
        ngx_http_location_hash_count_ctx = {

        NULL,                                       /* preconfiguration */
        NULL,                                       /* postconfiguration */

        NULL,                                       /* create main configuration */
        NULL,                                       /* init main configuration */

        NULL,                                       /* create server configuration */
        NULL,                                       /* merge server configuration */

        ngx_http_hash_count_create_loc_conf,    /* create location configuration */
        NULL                                        /* merge location configuration */
};

static ngx_command_t
        ngx_http_hash_count_commands[] = {

        {
                ngx_string("count"),
                NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
                ngx_http_hash_count,
                NGX_HTTP_LOC_CONF_OFFSET,
                0,
                NULL
        },
        ngx_null_command
}

ngx_module_t ngx_http_location_hash_count_module = {
        NGX_MODULE_V1,
        &ngx_http_hash_count_module_ctx,       /* module context */
        ngx_http_hash_count_commands,          /* module directives */
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

static void *
ngx_http_hash_count_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_hash_count_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hash_count_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

static char *
ngx_http_hash_count(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_hash_count_loc_conf_t *hclcf = conf;

    ngx_str_t name = ngx_string("location_hash_count_slab");
    hclcf->zone_size = 1024 * 1024;

    /* 提交内存申请 */
    ngx_shm_zone_t *zone = ngx_shared_memory_add(cf, &name, hclcf->zone_size,
                                                 &ngx_http_location_hash_count_module);
    if (zone == NULL) // 分配失败
    {
        return NGX_CONF_ERROR;
    }
    /* 真正分配申请的内存 */
    zone->init = ngx_http_hash_count_loc_shm_zone_init;
    zone->data = hclcf;

    // 设置count命令的handler回调函数
    ngx_http_core_loc_conf_t *clcf = NULL;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_hash_count_loc_handler;


    return NULL;
}

static ngx_int_t
ngx_http_hash_count_loc_shm_zone_init(ngx_shm_zone_t *zone, void *data) {
    ngx_http_hash_count_loc_conf_t *hclcf = (ngx_http_hash_count_loc_conf_t *) zone->data;
    ngx_http_hash_count_loc_conf_t *p = data;
    if (p) {
        hclcf->lcshm = p->lcshm;
        hclcf->pool = p->pool;
        return NGX_OK;
    }
    hclcf->pool = (ngx_slab_pool_t *) zone->shm.addr;
    hclcf->lcshm = ngx_slab_alloc(hclcf->pool, sizeof(ngx_http_location_hash_count_shm_t));
    if (hclcf->lcshm == NULL) {
        return NGX_ERROR;
    }
    hclcf->pool->data = hclcf->lcshm;

    ngx_rbtree_init(&hclcf->lcshm->rbtree, &hclcf->lcshm->sentinel, ngx_rbtree_insert_value);

    return NGx_OK;
}

static ngx_int_t
ngx_http_hash_count_loc_handler(ngx_http_request_t *r) //ngx_http_empty_gif_handler
{
    ngx_http_complex_value_t cv;

    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_POST))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));

    cv.value.len = sizeof(ngx_empty_gif);
    cv.value.data = ngx_empty_gif;
    r->headers_out.last_modified_time = 23349600;

    return ngx_http_send_response(r, NGX_HTTP_OK, &ngx_http_gif_type, &cv);
}