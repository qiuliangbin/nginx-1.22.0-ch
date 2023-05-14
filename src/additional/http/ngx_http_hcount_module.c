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
} ngx_http_hcount_loc_conf_t;
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

ngx_module_t ngx_http_location_hcount_module = {
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
    ngx_http_hcount_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hcount_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

static char *
ngx_http_hash_count(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_hcount_loc_conf_t *hclcf = conf;

    ngx_str_t name = ngx_string("location_hash_count_slab");
    hclcf->zone_size = 1024 * 1024;

    /* 提交内存申请 */
    ngx_shm_zone_t *zone = ngx_shared_memory_add(cf, &name, hclcf->zone_size,
                                                 &ngx_http_location_hcount_module);
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
    clcf->handler = ngx_http_hcount_loc_handler;


    return NULL;
}

static ngx_int_t
ngx_http_hash_count_loc_shm_zone_init(ngx_shm_zone_t *zone, void *data) {
    ngx_http_hcount_loc_conf_t *hclcf = (ngx_http_hcount_loc_conf_t *) zone->data;
    ngx_http_hcount_loc_conf_t *p = data;
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

    return NGX_OK;
}

static ngx_str_t  ngx_http_gif_type = ngx_string("image/gif");

/* 组织请求的响应包 */
static ngx_int_t
ngx_http_hcount_loc_handler(ngx_http_request_t *r) //ngx_http_empty_gif_handler
{
    u_char ngx_default_html[1024] = {0};

    ngx_http_complex_value_t cv;

    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_POST))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));

    cv.value.len = sizeof(ngx_default_html);
    cv.value.data = ngx_default_html;
    r->headers_out.last_modified_time = 23349600;

    return ngx_http_send_response(r, NGX_HTTP_OK, &ngx_http_core_text_html_type, &cv);
}

static ngx_int_t get_request_from_module(ngx_http_request_t *r, u_char* page_content)
{
    ngx_uint_t hkey = 0;
    struct sockaddr_in* remote_client_addr = (struct sockaddr_in*)r->connection->sockaddr;
    hkey = remote_client_addr->sin_addr.s_addr;
    ngx_http_hcount_loc_conf_t* hclcf = ngx_http_get_module_loc_conf(r, ngx_http_location_hcount_module);


    // key , value          // ip地址和访问次数
    ngx_shmtx_lock(&hclcf->pool->mutex);
    ngx_http_page_count_lookup(r, hclcf, hkey);
    ngx_shmtx_unlock(&hclcf->pool->mutex);

    ngx_encode_http_page_rb(conf, (char*)page_content);

    return NGX_OK;
}

// 红黑树的查找，插入
// 参数r 方便日志的打印
static ngx_int_t
ngx_http_page_count_lookup(ngx_http_request_t *r, ngx_http_location_conf_t *conf, ngx_uint_t key)
{
    ngx_rbtree_node_t *node, *sentinel;

    node = conf->lcshm->rbtree.root;
    sentinel = conf->lcshm->rbtree.sentinel;

    while(node != sentinel)   //  node == sentinel 需要进行下面操作，在slab中分配节点
    {
        if(key < node->key)
        {
            node = node->left;
            continue;
        }
        else if (key > node->key)
        {
            node = node->right;
            continue;
        }
        else
        {
            node->data++;   // 找到了,  需要做一个原子操作
            return NGX_OK;
        }
    }

    // 添加之前 需要在slab中分配一个节点
    node = ngx_slab_alloc_locked(conf->pool, sizeof(ngx_rbtree_node_t));
    if (NULL == node) {
        return NGX_ERROR;
    }

    node->key = key;
    node->data = 1;
    ngx_rbtree_insert(&conf->lcshm->rbtree, node);

    return NGX_OK;
}

static ngx_int_t
ngx_encode_http_page_rb(ngx_http_location_conf_t *conf, char *html)
{

    sprintf(html, "<h1>Ip Access Count</h1>");
    strcat(html, "<h2>");

    ngx_rbtree_node_t *node = ngx_rbtree_min(conf->lcshm->rbtree.root, conf->lcshm->rbtree.sentinel);

    do {

        char str[INET_ADDRSTRLEN] = {0};
        char buffer[128] = {0};

        sprintf(buffer, "req from : %s, count: %d <br/>",
                inet_ntop(AF_INET, &node->key, str, sizeof(str)), node->data);

        strcat(html, buffer);

        node = ngx_rbtree_next(&conf->lcshm->rbtree, node);

    } while (node);

    strcat(html, "</h2>");

    return NGX_OK;
}