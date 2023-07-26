
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_CONFIG_H_INCLUDED_
#define _NGX_HTTP_CONFIG_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    void        **main_conf;
    void        **srv_conf;
    void        **loc_conf;
} ngx_http_conf_ctx_t;


typedef struct { /* 可以把不需要调用的函数指针设置为 NULL */
    /* 在解析http{}块内的配置项前回调 */
    ngx_int_t   (*preconfiguration)(ngx_conf_t *cf);
    /* 在解析http{}块内的配置项后回调 */
    ngx_int_t   (*postconfiguration)(ngx_conf_t *cf);
    /*
     * 创建用于存储HTTP全局配置项的结构体；
     * 该结构体中的成员将保存直属于http{}块的配置项参数；
     * 该方法在解析main配置项前调用；
     */
    void       *(*create_main_conf)(ngx_conf_t *cf);
    /* 解析完main配置项后回调 */
    char       *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    /* 创建存储srv级别的配置项的结构体（直属于server块） */
    void       *(*create_srv_conf)(ngx_conf_t *cf);
    /* 合并main级别与srv级别下的同名配置项 */
    char       *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void *conf);

    /* 创建存储loc级别的配置项的结构体（直属于location块） */
    void       *(*create_loc_conf)(ngx_conf_t *cf);
    /* 合并srv级别与loc级别下的同名配置项 */
    /* 作用是将 prev 和 conf 中的 uint 类型的值进行合并，如果 prev 的值为 NGX_CONF_UNSET_UINT，
     * 则将 conf 的值赋给 prev；否则，将 prev 和 conf 中的值进行比较，取较大的值赋给 prev */
    char       *(*merge_loc_conf)(ngx_conf_t *cf, void *prev, void *conf);
} ngx_http_module_t;


#define NGX_HTTP_MODULE           0x50545448   /* "HTTP" */
// 指定配置指令出现位置的宏
#define NGX_HTTP_MAIN_CONF        0x02000000 // 配置指令只能出现在http-server主配置级别
#define NGX_HTTP_SRV_CONF         0x04000000 // 配置指令只能出现在http-server的虚拟主机配置级别
#define NGX_HTTP_LOC_CONF         0x08000000 // 配置指令只能出现在http-server的location配置级别
#define NGX_HTTP_UPS_CONF         0x10000000 // 配置指令只能出现在http-server的if()块中
#define NGX_HTTP_SIF_CONF         0x20000000 // 配置指令只能出现在http-server的if()块中
#define NGX_HTTP_LIF_CONF         0x40000000 // 配置指令只能出现在http的upstream块中
#define NGX_HTTP_LMT_CONF         0x80000000 // 配置指令只能出现在limit_except块中


#define NGX_HTTP_MAIN_CONF_OFFSET  offsetof(ngx_http_conf_ctx_t, main_conf)
#define NGX_HTTP_SRV_CONF_OFFSET   offsetof(ngx_http_conf_ctx_t, srv_conf)
#define NGX_HTTP_LOC_CONF_OFFSET   offsetof(ngx_http_conf_ctx_t, loc_conf)


#define ngx_http_get_module_main_conf(r, module)                             \
    (r)->main_conf[module.ctx_index]
#define ngx_http_get_module_srv_conf(r, module)  (r)->srv_conf[module.ctx_index]
#define ngx_http_get_module_loc_conf(r, module)  (r)->loc_conf[module.ctx_index]


#define ngx_http_conf_get_module_main_conf(cf, module)                        \
    ((ngx_http_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_http_conf_get_module_srv_conf(cf, module)                         \
    ((ngx_http_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]
#define ngx_http_conf_get_module_loc_conf(cf, module)                         \
    ((ngx_http_conf_ctx_t *) cf->ctx)->loc_conf[module.ctx_index]

#define ngx_http_cycle_get_module_main_conf(cycle, module)                    \
    (cycle->conf_ctx[ngx_http_module.index] ?                                 \
        ((ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index])      \
            ->main_conf[module.ctx_index]:                                    \
        NULL)


#endif /* _NGX_HTTP_CONFIG_H_INCLUDED_ */
