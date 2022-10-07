/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */

#ifndef _NGX_PROXY_PROTOCOL_H_INCLUDED_
#define _NGX_PROXY_PROTOCOL_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#define NGX_PROXY_PROTOCOL_MAX_HEADER 107

struct ngx_proxy_protocol_s
{
    ngx_str_t src_addr; //源地址
    ngx_str_t dst_addr; //目的地址
    in_port_t src_port; //源端口
    in_port_t dst_port; //目的端口
};

u_char *ngx_proxy_protocol_read(ngx_connection_t *c, u_char *buf,
                                u_char *last);
u_char *ngx_proxy_protocol_write(ngx_connection_t *c, u_char *buf,
                                 u_char *last);

#endif /* _NGX_PROXY_PROTOCOL_H_INCLUDED_ */
