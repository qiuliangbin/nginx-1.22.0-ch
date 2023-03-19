
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

typedef struct ngx_listening_s ngx_listening_t;

struct ngx_listening_s
{
    ngx_socket_t fd; // socket套接字

    struct sockaddr *sockaddr; // 监听的IP和端口
    socklen_t socklen;         // size of sockaddr
    size_t addr_text_max_len;  // 存储ip地址的字符串 addr_text 最大长度
    ngx_str_t addr_text;       // 以字符串存储的ip地址

    int type; //套接字类型。例如：type为SOCK_STREAM时，表示是TCP
    /*
    backlog：半连接状态和全连接状态两种队列大小
　      半连接状态为：
            服务器处于 Listen 状态时收到客户端 SYN=1 报文时放入半连接队列中，即 SYN queue(服务器端口状态为: SYN_RCVD)
　      全连接状态为：
            TCP 的连接状态从服务器 (SYN+ACK) 响应客户端后，到客户端的 ACK 报文到达服务器之前，则一直保留在半连接状态中；
            当服务器接收到客户端的 ACK 报文后，该条目将从半连接队列搬到全连接队列尾部，
            即 accept queue （服务器端口状态为：ESTABLISHED）
    */
    int backlog; //记录监听套接字的连接数大小(2个队列：完成3次连接和未完成3次连接)
    int rcvbuf;  //套接字接收进程缓冲区大小
    int sndbuf;  //套接字发送进程缓冲区大小
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int keepidle;
    int keepintvl;
    int keepcnt;
#endif

    /* handler of accepted connection */
    ngx_connection_handler_pt handler; //当新的tcp连接成功建立后的回调处理方法
    //目前主要用于HTTP或者mail等模块，用于保存当前监听端口对应着的所有主机名
    void *servers; /* array of ngx_http_in_addr_t, for example */

    ngx_log_t log;
    ngx_log_t *logp;

    size_t pool_size; //如果为新的tcp连接创建内存池，则内存池的初始大小应该是pool_size
    /* should be here because of the AcceptEx() preread */
    size_t post_accept_buffer_size; // accept事件的buffer大小

    ngx_listening_t *previous;    //前一个ngx_listening_t结构，用于组成单链表
    ngx_connection_t *connection; //监听连接池的第一个指针

    ngx_rbtree_t rbtree;
    ngx_rbtree_node_t sentinel;

    ngx_uint_t worker; // worker进程的个数

    unsigned open : 1;   //当前套接字，为1表示监听句柄有效，为0表示正常关闭
    unsigned remain : 1; //为1表示不关闭原先打开的监听端口，为0表示关闭曾经打开的监听端口
    unsigned ignore : 1; //为1表示跳过设置当前ngx_listening_t结构体中的套接字，为0时正常初始化套接字

    unsigned bound : 1;              // 是否已绑定
    unsigned inherited : 1;          // 是否从上一个进程中继承
    unsigned nonblocking_accept : 1; //是否非阻塞接受
    unsigned listen : 1;             //是否为1表示当前结构体对应的套接字已经监听
    unsigned nonblocking : 1;        //是否非阻塞接受
    unsigned shared : 1;             /* shared between threads or processes */
    unsigned addr_ntop : 1;          //为1表示将网络地址转变为字符串形式的地址
    unsigned wildcard : 1;

#if (NGX_HAVE_INET6)
    unsigned ipv6only : 1;
#endif
    unsigned reuseport : 1; // 是否开启端口复用
    unsigned add_reuseport : 1;
    unsigned keepalive : 2;

    unsigned deferred_accept : 1;
    unsigned delete_deferred : 1;
    unsigned add_deferred : 1;
#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char *accept_filter;
#endif
#if (NGX_HAVE_SETFIB)
    int setfib;
#endif

#if (NGX_HAVE_TCP_FASTOPEN)
    int fastopen;
#endif
};

typedef enum
{
    NGX_ERROR_ALERT = 0,
    NGX_ERROR_ERR,
    NGX_ERROR_INFO,
    NGX_ERROR_IGNORE_ECONNRESET,
    NGX_ERROR_IGNORE_EINVAL
} ngx_connection_log_error_e;

typedef enum
{
    NGX_TCP_NODELAY_UNSET = 0,
    NGX_TCP_NODELAY_SET,
    NGX_TCP_NODELAY_DISABLED
} ngx_connection_tcp_nodelay_e;

typedef enum
{
    NGX_TCP_NOPUSH_UNSET = 0,
    NGX_TCP_NOPUSH_SET,
    NGX_TCP_NOPUSH_DISABLED
} ngx_connection_tcp_nopush_e;

#define NGX_LOWLEVEL_BUFFERED 0x0f
#define NGX_SSL_BUFFERED 0x01
#define NGX_HTTP_V2_BUFFERED 0x02

struct ngx_connection_s
{
    /*
        连接未使用时，data用于充当连接池中空闲链表中的next指针。
        有连接套接字使用时，由模块而定: http中data指向ngx_http_connection_t
    */
    void *data; // 关联其它的ngx_connection_s
    ngx_event_t *read;  //连接对应的读事件
    ngx_event_t *write; //连接对应的写事件

    ngx_socket_t fd; //套接字描述符

    ngx_recv_pt recv;             // 接收数据的函数指针
    ngx_send_pt send;             // 发送数据的函数指针
    ngx_recv_chain_pt recv_chain; // 批量接收数据的函数指针
    ngx_send_chain_pt send_chain; // 批量发送数据的函数指针

    ngx_listening_t *listening; // 该连接的网络监听数据结构

    off_t sent; //连接上已发送的字符数

    ngx_log_t *log; //日志对象

    ngx_pool_t *pool; //内存池

    int type;
    /*
    struct sockaddr {
        unsigned short sa_family; // 2 bytes address family, af_xxx
        char sa_data[14]; // 14 bytes of protocol address
    };

    // ipv4 af_inet sockets:
    struct sockaddr_in {
        short sin_family; // 2 bytes e.g. af_inet, af_inet6
        unsigned short sin_port; // 2 bytes e.g. htons(3490)
        struct in_addr sin_addr; // 4 bytes see struct in_addr, below
        char sin_zero[8]; // 8 bytes zero this if you want to
    };

    struct in_addr {
        unsigned long s_addr; // 4 bytes load with inet_pton()
    };
    */
    struct sockaddr *sockaddr; // 连接客户端的sockaddr
    socklen_t socklen;         // sockaddr结构体的长度
    ngx_str_t addr_text;       // 连接客户端字符串形式的IP地址

    ngx_proxy_protocol_t *proxy_protocol; //代理源地址和端口/目的地址和端口

#if (NGX_SSL || NGX_COMPAT)
    ngx_ssl_connection_t *ssl;
#endif

    ngx_udp_connection_t *udp;

    struct sockaddr *local_sockaddr; //本机监听端口对应的sockaddr结构体，实际上是listening监听对象的sockaddr对象
    socklen_t local_socklen;         //监听端口个数
    //用户接受、缓存客户端发来的字符流；buffer是由连接内池分配，大小自由决定
    ngx_buf_t *buffer;
    //用来将当前连接以双向链表元素的形式添加到ngx_cycle_t核心结构体的reuseable_connection_queue双向链表中，表示可以重用的连接
    ngx_queue_t queue;
    //连接使用次数。ngx_connection_t结构体每次建立一条来自客户端的连接，或主动向后端服务器发起连接时，number都会加1
    ngx_atomic_uint_t number;

    ngx_msec_t start_time;
    ngx_uint_t requests; //处理请求的次数

    unsigned buffered : 8; //缓存业务类型

    unsigned log_error : 3; /* ngx_connection_log_error_e */

    unsigned timedout : 1;  //为1表示连接已经超时
    unsigned error : 1;     //为1表示连接处理过程中出现错误
    unsigned destroyed : 1; //为1表示连接已经销毁

    unsigned idle : 1;     //为1表示连接处于空闲状态，如keepalive两次请求中间的状态
    unsigned reusable : 1; //为1表示连接可重用，与上面的queue字段对应使用
    unsigned close : 1;    //为1表示连接关闭
    unsigned shared : 1;

    unsigned sendfile : 1; //为1表示正在将文件中的数据发往连接的另一端
    unsigned sndlowat : 1;
    unsigned tcp_nodelay : 2; /* ngx_connection_tcp_nodelay_e */
    unsigned tcp_nopush : 2;  /* ngx_connection_tcp_nopush_e */

    /*
       为1表示只有连接套接字对应的发送缓冲区必须满足最低设置的大小阀值时，
       件驱动模块才会分发该事件。这与ngx_handle_write_event方法中的lowat参数是对应的
    */
    unsigned need_last_buf : 1;

#if (NGX_HAVE_SENDFILE_NODISKIO || NGX_COMPAT)
    unsigned busy_count : 2;
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_thread_task_t *sendfile_task;
#endif
};

#define ngx_set_connection_log(c, l)                     \
                                                         \
    c->log->file = l->file;                              \
    c->log->next = l->next;                              \
    c->log->writer = l->writer;                          \
    c->log->wdata = l->wdata;                            \
    if (!(c->log->log_level & NGX_LOG_DEBUG_CONNECTION)) \
    {                                                    \
        c->log->log_level = l->log_level;                \
    }

ngx_listening_t *ngx_create_listening(ngx_conf_t *cf, struct sockaddr *sockaddr,
                                      socklen_t socklen);
ngx_int_t ngx_clone_listening(ngx_cycle_t *cycle, ngx_listening_t *ls);
ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle);
ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle);
void ngx_configure_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_connection(ngx_connection_t *c);
void ngx_close_idle_connections(ngx_cycle_t *cycle);
ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s,
                                        ngx_uint_t port);
ngx_int_t ngx_tcp_nodelay(ngx_connection_t *c);
ngx_int_t ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text);

ngx_connection_t *ngx_get_connection(ngx_socket_t s, ngx_log_t *log);
void ngx_free_connection(ngx_connection_t *c);

void ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable);

#endif /* _NGX_CONNECTION_H_INCLUDED_ */
