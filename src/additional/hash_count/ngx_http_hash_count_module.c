/*
 * Copyright (C) qiulb
 * Copyright (C) Sangfor, Inc.
 */
#include <ngx_http.h>
#include <ngx_config.h>
#include <ngx_core.h>

typedef struct {
	ngx_rbtree_t rbtree;
	ngx_rbtree_node_t sentinel;
} ngx_http_hash_count_shm_t;   // 共享内存

typedef struct {
	ngx_shm_zone_t *shm_zone;
//    ngx_str_t limit_hash_index; /* $remote_ip$url_path */
//    ngx_int_t limit_count; /* 10 */
//    ngx_str_t limit_time_unit; /* h;m;s -> 小时;分钟;秒 */
} ngx_http_hash_count_loc_conf_t;

static char *ngx_http_hash_count(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void *ngx_http_hash_count_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_hash_count_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_hash_count_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data);

static ngx_int_t ngx_http_hash_count_loc_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_page_lookup(ngx_http_request_t *r, ngx_slab_pool_t *pool, ngx_uint_t key);

static ngx_int_t build_html_page_content(ngx_http_hash_count_loc_conf_t *conf, char *page);

/*
    提供8个方法，解析配置文件的
    解析 http {}
    1 8 2 7 3 6 4 5 这种顺序解析的
*/
static ngx_http_module_t ngx_http_hash_count_module_ctx = {

		NULL,                                       /* preconfiguration */
		NULL,                                       /* postconfiguration */

		NULL,                                       /* create main configuration */
		NULL,                                       /* init main configuration */

		NULL,                                       /* create server configuration */
		NULL,                                       /* merge server configuration */

		ngx_http_hash_count_create_loc_conf,        /* create location configuration */
		ngx_http_hash_count_merge_loc_conf          /* merge location configuration */
};

static ngx_command_t ngx_http_hash_count_commands[] = {
		{
				ngx_string("hash_count"), // 指令的名称
				NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS, // 指令的作用域和类型
				ngx_http_hash_count, // 解析指令的函数指针
				NGX_HTTP_LOC_CONF_OFFSET, // 数据的存储位置
				0, // 数据具体存储变量
				NULL
		},
		ngx_null_command
};

ngx_module_t ngx_http_hash_count_module = {
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

static char *
ngx_http_hash_count(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno, "___ngx_http_hash_count");
	// 设置count命令的handler回调函数
	ngx_http_core_loc_conf_t *clcf = NULL;
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_hash_count_loc_handler;

	return NGX_CONF_OK;
}

static void *
ngx_http_hash_count_create_loc_conf(ngx_conf_t *cf) {
	printf("___ngx_http_hash_count_create_loc_conf\n");
	ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno, "___ngx_http_hash_count_create_loc_conf");
	ngx_http_hash_count_loc_conf_t *conf;
	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hash_count_loc_conf_t));
	if (conf == NULL) {
		return NULL;
	}

	return conf;
}

static char *
ngx_http_hash_count_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
	ngx_log_error(NGX_LOG_EMERG, cf->log, ngx_errno, "___ngx_http_hash_count_merge_loc_conf");
	ngx_shm_zone_t *shm_zone;
	ngx_http_hash_count_loc_conf_t *prev = parent;
	ngx_http_hash_count_loc_conf_t *conf = child;
	ngx_str_t shm_name = ngx_string("hash_count");

	shm_zone = ngx_shared_memory_add(cf, &shm_name, 8 * ngx_pagesize, &ngx_http_hash_count_module);
	if (shm_zone == NULL) {
		return NGX_CONF_ERROR;
	}

	shm_zone->init = ngx_http_hash_count_init_shm_zone;
	conf->shm_zone = shm_zone;

	ngx_conf_merge_ptr_value(conf->shm_zone, prev->shm_zone, NULL);
	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_hash_count_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data) {
	ngx_slab_pool_t *shpool;
	ngx_http_hash_count_shm_t *hash_count_rbtree_shm;
	if (data) {
		shm_zone->data = data;
		return NGX_OK;
	}
	shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
	hash_count_rbtree_shm = ngx_slab_alloc(shpool, sizeof *hash_count_rbtree_shm);
	if (hash_count_rbtree_shm == NULL) {
		return NGX_ERROR;
	}

	/* init rbtree */
	ngx_rbtree_init(&hash_count_rbtree_shm->rbtree, &hash_count_rbtree_shm->sentinel, ngx_rbtree_insert_value);
	shpool->data = hash_count_rbtree_shm;

	return NGX_OK;
}

/**
  * @brief   handler依次做4件事情: 获取location配置、生成合适的响应、发送响应的header头部、发送响应的body包体
  * @note    原型函数指针: typedef ngx_int_t (*ngx_http_handler_pt)(ngx_http_request_t *r);
  * @param   r:  request结构和自定义的module模块的组合体
  * @retval  None
  **/
static ngx_int_t
ngx_http_hash_count_loc_handler(ngx_http_request_t *r) //ngx_http_empty_gif_handler
{
	ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "___ngx_http_hash_count_loc_handler");
	ngx_http_hash_count_loc_conf_t *hclcf;
	ngx_shm_zone_t *shm_zone;
	struct sockaddr_in *remote_sock_addr;
	ngx_uint_t remote_ip;
	char html_page_content[ngx_pagesize];

	if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_POST))) {
		return NGX_HTTP_NOT_ALLOWED;
	}
	// 从hash_count模块对应的配置内存中拿到共享内存地址
	hclcf = ngx_http_get_module_loc_conf(r, ngx_http_hash_count_module);
	if (hclcf->shm_zone == NULL) {
		return NGX_DECLINED;
	}
	shm_zone = hclcf->shm_zone;
	// 2.获取红黑树查询的key值(remote client ip)
	remote_sock_addr = (struct sockaddr_in *) r->connection->sockaddr;
	remote_ip = remote_sock_addr->sin_addr.s_addr;

	ngx_slab_pool_t *shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
	// 3.根据key值在红黑树中查询remote ip地址和访问次数
	ngx_shmtx_lock(&shpool->mutex);
	ngx_http_page_lookup(r, shpool, remote_ip);
	ngx_shmtx_unlock(&shpool->mutex);
	// 构建回复包的body部分
	memset(html_page_content,0x0,sizeof(html_page_content));
	build_html_page_content(hclcf, html_page_content);
	// 发送http头
	r->headers_out.status = NGX_HTTP_OK;
	ngx_str_set(&r->headers_out.content_type, "text/html");
	ngx_http_send_header(r);

	ngx_buf_t *b;
	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	ngx_chain_t out;
	out.buf = b;
	out.next = NULL;

	b->pos = (u_char *)html_page_content;
	b->last = (u_char *)html_page_content + sizeof(html_page_content);
	b->memory = 1;
	b->last_buf = 1;

	return ngx_http_output_filter(r, &out);
}

static ngx_int_t
ngx_http_page_lookup(ngx_http_request_t *r, ngx_slab_pool_t *pool, ngx_uint_t key) {
	ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "___ngx_http_page_lookup");
	ngx_rbtree_node_t *node, *sentinel;
	ngx_http_hash_count_shm_t *hash_count_shm;
	hash_count_shm = (ngx_http_hash_count_shm_t *) pool->data;
	node = hash_count_shm->rbtree.root;
	sentinel = hash_count_shm->rbtree.sentinel;

	while (node != sentinel)   //  node == sentinel 需要进行下面操作，在slab中分配节点
	{
		if (key < node->key) {
			node = node->left;
			continue;
		} else if (key > node->key) {
			node = node->right;
			continue;
		} else {
			node->data++;   // 找到了,  需要做一个原子操作
			return NGX_OK;
		}
	}

	// 添加之前 需要在slab中分配一个节点
	node = ngx_slab_alloc_locked(pool, sizeof(ngx_rbtree_node_t));
	if (NULL == node) {
		return NGX_ERROR;
	}

	node->key = key;
	node->data = 1;
	ngx_rbtree_insert(&hash_count_shm->rbtree, node);

	return NGX_OK;
}

static ngx_int_t
build_html_page_content(ngx_http_hash_count_loc_conf_t *conf, char *page) {
	ngx_slab_pool_t *shpool;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
	sprintf(page, "<h1>Remote Ip Access Count</h1>\n<h2>");
#pragma GCC diagnostic pop
	shpool = (ngx_slab_pool_t *) conf->shm_zone->shm.addr;
	ngx_http_hash_count_shm_t *hash_count_shm = (ngx_http_hash_count_shm_t *) shpool->data;
	ngx_rbtree_node_t *node = ngx_rbtree_min(hash_count_shm->rbtree.root, hash_count_shm->rbtree.sentinel);

	do {

		char request_remote_ip[INET_ADDRSTRLEN];
		memset(request_remote_ip,0x0,sizeof(request_remote_ip));
		if (inet_ntop(AF_INET, &node->key, request_remote_ip, sizeof(request_remote_ip)) == NULL) {
			return NGX_ERROR;
		}

		char page_line[ngx_pagesize];
		memset(page_line,0x0,sizeof(page_line));
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
		sprintf(page_line, "request remote ip: %s, count: %d <br/>", request_remote_ip, node->data);
		strncat(page, page_line, strlen(page_line));
#pragma GCC diagnostic pop
		node = ngx_rbtree_next(&hash_count_shm->rbtree, node);

	} while (node);

	strcat(page, "</h2>");

	return NGX_OK;
}

