
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define DEFAULT_CONNECTIONS  512


extern ngx_module_t ngx_kqueue_module;
extern ngx_module_t ngx_eventport_module;
extern ngx_module_t ngx_devpoll_module;
extern ngx_module_t ngx_epoll_module;
extern ngx_module_t ngx_select_module;


static char *ngx_event_init_conf(ngx_cycle_t *cycle, void *conf);

static ngx_int_t ngx_event_module_init(ngx_cycle_t *cycle);

static ngx_int_t ngx_event_process_init(ngx_cycle_t *cycle);

static char *ngx_events_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_event_connections(ngx_conf_t *cf, ngx_command_t *cmd,
                                   void *conf);

static char *ngx_event_use(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_event_debug_connection(ngx_conf_t *cf, ngx_command_t *cmd,
                                        void *conf);

static void *ngx_event_core_create_conf(ngx_cycle_t *cycle);

static char *ngx_event_core_init_conf(ngx_cycle_t *cycle, void *conf);


static ngx_uint_t ngx_timer_resolution;
sig_atomic_t ngx_event_timer_alarm;

static ngx_uint_t ngx_event_max_module;

ngx_uint_t ngx_event_flags;
ngx_event_actions_t ngx_event_actions;


static ngx_atomic_t connection_counter = 1;
ngx_atomic_t *ngx_connection_counter = &connection_counter;


ngx_atomic_t *ngx_accept_mutex_ptr;
ngx_shmtx_t ngx_accept_mutex;
ngx_uint_t ngx_use_accept_mutex;
ngx_uint_t ngx_accept_events;
ngx_uint_t ngx_accept_mutex_held;
ngx_msec_t ngx_accept_mutex_delay;
ngx_int_t ngx_accept_disabled;
ngx_uint_t ngx_use_exclusive_accept;


#if (NGX_STAT_STUB)

static ngx_atomic_t   ngx_stat_accepted0;
ngx_atomic_t         *ngx_stat_accepted = &ngx_stat_accepted0;
static ngx_atomic_t   ngx_stat_handled0;
ngx_atomic_t         *ngx_stat_handled = &ngx_stat_handled0;
static ngx_atomic_t   ngx_stat_requests0;
ngx_atomic_t         *ngx_stat_requests = &ngx_stat_requests0;
static ngx_atomic_t   ngx_stat_active0;
ngx_atomic_t         *ngx_stat_active = &ngx_stat_active0;
static ngx_atomic_t   ngx_stat_reading0;
ngx_atomic_t         *ngx_stat_reading = &ngx_stat_reading0;
static ngx_atomic_t   ngx_stat_writing0;
ngx_atomic_t         *ngx_stat_writing = &ngx_stat_writing0;
static ngx_atomic_t   ngx_stat_waiting0;
ngx_atomic_t         *ngx_stat_waiting = &ngx_stat_waiting0;

#endif

/*
 * event模块命令集
 * 回调函数: ngx_events_block() 用于解析 event{}块中的配置参数
 *
 * */
static ngx_command_t ngx_events_commands[] = {

        {ngx_string("events"), /* 模块名称 */
         /*
          * NGX_MAIN_CONF: 配置文件的最外层指令
          * NGX_CONF_BLOCK: 块命令 "{"字符开始和"}"字符结束
          * NGX_CONF_NOARGS: 没有入参
          * */
         NGX_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_NOARGS,
         ngx_events_block, /* 创建ngx_event_core_module事件的核心模块以及配置信息的回调函数 */
         0,
         0,
         NULL},

        ngx_null_command  /* 结束命令 */
};

/* event模块上下文 */
static ngx_core_module_t ngx_events_module_ctx = {
        ngx_string("events"),
        NULL,
        ngx_event_init_conf
};

/*
 * event模块
 * 模块类型: NGX_CORE_MODULE
 * 模块类型为核心模块, 所以在ngx_init_cycle就会初始化conf
 * */
ngx_module_t ngx_events_module = {
        NGX_MODULE_V1,
        &ngx_events_module_ctx,                /* module context */
        ngx_events_commands,                   /* module directives */
        NGX_CORE_MODULE,                       /* module type */
        NULL,                                  /* init master */
        NULL,                                  /* init module */
        NULL,                                  /* init process */
        NULL,                                  /* init thread */
        NULL,                                  /* exit thread */
        NULL,                                  /* exit process */
        NULL,                                  /* exit master */
        NGX_MODULE_V1_PADDING
};

/* event核心模块名称 */
static ngx_str_t event_core_name = ngx_string("event_core");

/* 定义Event核心模块的命令参数
 * 命令参数定义参照: https://blog.redis.com.cn/doc/core/events.html
 * 详细描述参照: https://www.linuxdashen.com/nginx%E6%9C%8D%E5%8A%A1%E5%99%A8%E6%80%A7%E8%83%BD%E4%BC%98%E5%8C%96
 * */
static ngx_command_t ngx_event_core_commands[] = {
        /* worker_connections的默认值是512,它在events模块中。它指定了一个worker进程在同一时间可以处理的最大请求数。
         * */
        {ngx_string("worker_connections"), // events { worker_connections 512; }
         NGX_EVENT_CONF | NGX_CONF_TAKE1,
         ngx_event_connections,
         0,
         0,
         NULL},
        /*
         * Nginx处理请求的方法有很多种，每一个方法都允许Nginx Worker进程监测多个socket文件描述符
         * Nginx支持以下请求处理方法:
         *  1. select: 一种标准的请求处理方法。如果一个平台上缺少相应的更加有效的方法，那么Nginx会自动使用select方法
         *  2. poll: 一种标准的请求处理方法。如果一个平台上缺少相应的更加有效的方法，那么Nginx会自动使用poll方法
         *  3. kqueue: BSD家族操作系统上可用的一种高效的请求处理方法。可用于FreeBSD, OpenBSD, NetBSD和OS X。
         *             kqueue方法会忽略multi_accept
         *  4. epoll: Linux系统上可用的一种高效的请求处理方法，类似于kqueue。
         *            它有一个额外的directive，那就是epoll_events。
         *            epoll_events指定了Nginx可以向内核传递的事件数量。默认的值是512
         * */
        {ngx_string("use"), // events { use epoll; }
         NGX_EVENT_CONF | NGX_CONF_TAKE1,
         ngx_event_use,
         0,
         0,
         NULL},
        /*
         * multi_accept可以让nginx worker进程尽可能多地接受请求。
         * 它的作用是让worker进程一次性地接受监听队列里的所有请求，然后处理。
         * 如果multi_accept的值设为off，那么worker进程必须一个一个地接受监听队列里的请求。
         *
         * 如果web服务器面对的是一个持续的请求流，那么启用multi_accept可能会造成worker进程一次接受的请求
         * 大于worker_connections指定可以接受的请求数。这就是overflow，这个overflow会造成性能损失，
         * overflow这部分的请求不会受到处理. 建议不开启，Nginx官方默认没有开启multi_accept
         * */
        {ngx_string("multi_accept"), // events { multi_accept off; }
         NGX_EVENT_CONF | NGX_CONF_FLAG,
         ngx_conf_set_flag_slot,
         0,
         offsetof(ngx_event_conf_t, multi_accept),
         NULL},

         /* 当我们为nginx打开了多个worker进程后，我们需要配置如何选择worker进程来完成相应的请求处理.
          * 在events模块中，我们可以设置 events { accept_mutex on; }
          * accept_mutex会轮流来选择worker进程。Nginx默认开启了accept_mutex。
          * 如果accept_mutex的值被设为off，那么当有请求需要处理时，所有的worker进程都会从waiting状态中唤醒，
          * 但是只有一个worker进程能处理请求，这造成了thundering herd现象，这个现象每一秒钟会发生多次。
          * 它使服务器的性能下降，因为所有被唤醒的worker进程在重新进入waiting状态前会占用一段CPU时间.
          * */
        {ngx_string("accept_mutex"), // events { accept_mutex on; } // nginx使用连接互斥锁进行顺序的accept()系统调用.
         NGX_EVENT_CONF | NGX_CONF_FLAG,
         ngx_conf_set_flag_slot,
         0,
         offsetof(ngx_event_conf_t, accept_mutex),
         NULL},
        /*
         * 当accept_mutex功能启用后，只有一个持有mutex锁的worker进程会接受并处理请求，其他worker进程等待。
         * accept_mutex_delay指定的时间就是这些worker进程的等待时间，过了等待时间下一个worker进程便取得mutex锁，处理请求。
         * accept_mutex_delay在events模块中指定，默认的值为500ms
         * */
        {ngx_string("accept_mutex_delay"),
         NGX_EVENT_CONF | NGX_CONF_TAKE1,
         ngx_conf_set_msec_slot,
         0,
         offsetof(ngx_event_conf_t, accept_mutex_delay),
         NULL},

         /*
          * 为选定的客户端连接启用调试日志，其他连接将使用由 error_log 指令设置的日志记录级别。
          * 调试连接由 IPv4 或 IPv6 (1.3.0, 1.2.1) 地址或网络指定。也可以使用主机名指定连接。
          * 对于使用 UNIX 域套接字（1.3.0、1.2.1）的连接，调试日志由 “unix:” 参数启用。
          *
          * 示例如下:
                events {
                    debug_connection 127.0.0.1;
                    debug_connection localhost;
                    debug_connection 192.0.2.0/24;
                    debug_connection ::1;
                    debug_connection 2001:0db8::/32;
                    debug_connection unix:;
                    ...
                }
          * */
        {ngx_string("debug_connection"),
         NGX_EVENT_CONF | NGX_CONF_TAKE1,
         ngx_event_debug_connection,
         0,
         0,
         NULL},

        ngx_null_command
};

/*
 * Event核心模块上下文
 * ngx_event_core_create_conf：创建配置文件
 * ngx_event_core_init_conf：初始化配置文件
 */
static ngx_event_module_t ngx_event_core_module_ctx = {
        &event_core_name,
        ngx_event_core_create_conf,            /* create configuration */
        ngx_event_core_init_conf,              /* init configuration */

        {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL}
};

/*
 * Event核心模块
 * ngx_event_module_init：模块初始化
 * ngx_event_process_init：进程初始化
 * 类型：NGX_EVENT_MODULE
 */
ngx_module_t ngx_event_core_module = {
        NGX_MODULE_V1,
        &ngx_event_core_module_ctx,            /* module context */
        ngx_event_core_commands,               /* module directives */
        NGX_EVENT_MODULE,                      /* module type */
        NULL,                                  /* init master */
        ngx_event_module_init,                 /* init module */
        ngx_event_process_init,                /* init process */
        NULL,                                  /* init thread */
        NULL,                                  /* exit thread */
        NULL,                                  /* exit process */
        NULL,                                  /* exit master */
        NGX_MODULE_V1_PADDING
};

/**
  * @brief   进程事件分发器
  * @note    事件分发; 惊群处理; 简单的负载均衡
  * @param   cycle
  * @retval  None
  **/
void
ngx_process_events_and_timers(ngx_cycle_t *cycle) {
    ngx_uint_t flags;
    ngx_msec_t timer, delta;
    /* Nginx何时更新缓存? Nginx更新时间缓存的时机是什么时候呢？
     * 当然初启动和cycle的初始化有几次更新的时机，这里我们主要考虑事件处理过程中时间更新的时机。
     * Nginx给出了两种不同的解决方案，由ngx_time_resolution变量决定：
     * 1.在ngx_timer_resolution为0的时候，Nginx会在每次调用epoll_wait后进行一次时间缓存的更新
     * 2.在ngx_timer_resolution不为0的时候，这个值代表着时间精度，即“多长时间更新一次缓存”，
     * 这时候Nginx会在时间模块初始化的时候设置定时器，让定时器的中断时间为ngx_timer_resolution规定的毫秒数，
     * 每触发一次SIGALRM信号，就调用一次ngx_time_update()
     */
    if (ngx_timer_resolution) {
        timer = NGX_TIMER_INFINITE;
        flags = 0; // 定时进行时间缓存的更新

    } else {
        timer = ngx_event_find_timer();
        flags = NGX_UPDATE_TIME; // Nginx会在每次调用epoll_wait后进行一次时间缓存的更新

#if (NGX_WIN32)

        /* handle signals from master in case of network inactivity */

        if (timer == NGX_TIMER_INFINITE || timer > 500) {
            timer = 500;
        }

#endif
    }
    /*
     * ngx_use_accept_mutex变量代表是否使用accept互斥体,默认情况下是使用的;
     * 可以通过accept_mutex off; 指令进行关闭;
     * accept_mutex 的作用是避免惊群,同时实现负载均衡.
     */
    if (ngx_use_accept_mutex) {
        /*
         * 当事件配置初始化的时候，会设置一个全局变量：
         * ngx_accept_disabled = ngx_cycle->connection_n/8 - ngx_cycle->free_connection_n
         * 当ngx_accept_disabled为正数的时候，connection达到连接总数的7/8的时候，就不再处理新的连接accept事件，
         * 只处理当前连接的read事件, 这是比较简单的一种负载均衡方法
         */
        if (ngx_accept_disabled > 0) { // 超过负载均衡的阈值,不再accept新的客户端连接请求
            ngx_accept_disabled--;// 不抢; 为了避免一致不抢,也要递减它的disable程度

        } else { // 还可以accept客户端的连接请求
            // 获取锁失败
            if (ngx_trylock_accept_mutex(cycle) == NGX_ERROR) {
                return;
            }
            // 获取锁成功
            if (ngx_accept_mutex_held) {
                /*
                 * 给flags增加标记NGX_POST_EVENTS, 处理时间核心函数ngx_process_events的一个参数，该函数中所有事件将延后处理。
                 * accept事件都放到ngx_posted_accept_events链表中, epollin|epollout普通事件都放到ngx_posted_events链表中。
                 * 注: accept事件处理优先级大于epollin|epollout普通事件
                 */
                flags |= NGX_POST_EVENTS;

            } else {
                /*
                 * 1.获取锁失败, 意味着既不能让当前worker进程频繁抢锁,也不能让他长时间不去抢锁
                 * 2.开启了timer_resolution时间精度，需要让ngx_process_events方法在没有新事件的时候
                 *      至少等待ngx_accept_mutex_delay毫秒之后再去试图抢锁
                 * 3. 没有开启时间精度时，如果最近一个定时器事件的超时时间距离现在超过了ngx_accept_mutex_delay毫秒，
                 *      也要把timer设置为ngx_accept_mutex_delay毫秒
                 * 4. 不能让ngx_process_events方法在没有新事件的时候等待的时间超过ngx_accept_mutex_delay，
                 *      这会影响整个负载均衡机制
                 * 5. 如果拿到锁的进程能很快处理完accpet，而没拿到锁的一直在等待，容易造成进程忙的很忙，空的很空
                 * */
                if (timer == NGX_TIMER_INFINITE || timer > ngx_accept_mutex_delay) {
                    timer = ngx_accept_mutex_delay;
                }
            }
        }
    }

    if (!ngx_queue_empty(&ngx_posted_next_events)) {
        ngx_event_move_posted_next(cycle);
        timer = 0;
    }

    delta = ngx_current_msec;
    /*
     * 事件调度函数
     * 1.当拿到锁, flags=NGX_POST_EVENTS的时候,不会直接处理事件.
     * 将accept事件放入ngx_posted_accept_events, read时间放到ngx_posted_events队列
     * 2.当没有拿到锁, 则处理的全部是read事件,直接进行回调函数处理
     * 参数: timer-epoll_wait超时时间(ngx_accept_mutex_delay-延迟拿锁事件   NGX_TIMER_INFINITE-正常的epoll_wait等待事件)
     * */
    (void) ngx_process_events(cycle, timer, flags);

    delta = ngx_current_msec - delta; // 计算处理events事件所消耗的时间

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "timer delta: %M", delta);
    /*
     * 1.ngx_posted_accept_events: 暂存epoll从监听套接口wait到的accept事件的事件队列
     * 2.ngx_event_process_posted: 循环处理ngx_posted_accept_events队列上的accept事件
     * */
    ngx_event_process_posted(cycle, &ngx_posted_accept_events);
    // 处理完accept事件后,释放锁
    if (ngx_accept_mutex_held) {
        ngx_shmtx_unlock(&ngx_accept_mutex);
    }

    ngx_event_expire_timers();
    /*
     * 1.ngx_posted_events: 暂存epollin|epollout普通事件的队列
     * 2.ngx_event_process_posted: 循环处理ngx_posted_events上的epollin|epollout事件
     */
    ngx_event_process_posted(cycle, &ngx_posted_events);
}


ngx_int_t
ngx_handle_read_event(ngx_event_t *rev, ngx_uint_t flags) {
    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

        /* kqueue, epoll */

        if (!rev->active && !rev->ready) {
            if (ngx_add_event(rev, NGX_READ_EVENT, NGX_CLEAR_EVENT)
                == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

        return NGX_OK;

    } else if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {

        /* select, poll, /dev/poll */

        if (!rev->active && !rev->ready) {
            if (ngx_add_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT)
                == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (rev->active && (rev->ready || (flags & NGX_CLOSE_EVENT))) {
            if (ngx_del_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT | flags)
                == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

    } else if (ngx_event_flags & NGX_USE_EVENTPORT_EVENT) {

        /* event ports */

        if (!rev->active && !rev->ready) {
            if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (rev->oneshot && rev->ready) {
            if (ngx_del_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

    /* iocp */

    return NGX_OK;
}


ngx_int_t
ngx_handle_write_event(ngx_event_t *wev, size_t lowat) {
    ngx_connection_t *c;

    if (lowat) {
        c = wev->data;

        if (ngx_send_lowat(c, lowat) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }

    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

        /* kqueue, epoll */

        if (!wev->active && !wev->ready) {
            if (ngx_add_event(wev, NGX_WRITE_EVENT,
                              NGX_CLEAR_EVENT | (lowat ? NGX_LOWAT_EVENT : 0))
                == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

        return NGX_OK;

    } else if (ngx_event_flags & NGX_USE_LEVEL_EVENT) {

        /* select, poll, /dev/poll */

        if (!wev->active && !wev->ready) {
            if (ngx_add_event(wev, NGX_WRITE_EVENT, NGX_LEVEL_EVENT)
                == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (wev->active && wev->ready) {
            if (ngx_del_event(wev, NGX_WRITE_EVENT, NGX_LEVEL_EVENT)
                == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

    } else if (ngx_event_flags & NGX_USE_EVENTPORT_EVENT) {

        /* event ports */

        if (!wev->active && !wev->ready) {
            if (ngx_add_event(wev, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (wev->oneshot && wev->ready) {
            if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

    /* iocp */

    return NGX_OK;
}


static char *
ngx_event_init_conf(ngx_cycle_t *cycle, void *conf) {
#if (NGX_HAVE_REUSEPORT)
    ngx_uint_t        i;
    ngx_listening_t  *ls;
#endif

    if (ngx_get_conf(cycle->conf_ctx, ngx_events_module) == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "no \"events\" section in configuration");
        return NGX_CONF_ERROR;
    }

    if (cycle->connection_n < cycle->listening.nelts + 1) {

        /*
         * there should be at least one connection for each listening
         * socket, plus an additional connection for channel
         */

        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "%ui worker_connections are not enough "
                      "for %ui listening sockets",
                      cycle->connection_n, cycle->listening.nelts);

        return NGX_CONF_ERROR;
    }

#if (NGX_HAVE_REUSEPORT)

    if (!ngx_test_config) {

        ls = cycle->listening.elts;
        for (i = 0; i < cycle->listening.nelts; i++) {

            if (!ls[i].reuseport || ls[i].worker != 0) {
                continue;
            }

            if (ngx_clone_listening(cycle, &ls[i]) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            /* cloning may change cycle->listening.elts */

            ls = cycle->listening.elts;
        }
    }

#endif

    return NGX_CONF_OK;
}


/*
 * event事件核心模块初始化函数
 */
static ngx_int_t
ngx_event_module_init(ngx_cycle_t *cycle) {
    void ***cf;
    u_char *shared;
    size_t size, cl;
    ngx_shm_t shm;
    ngx_time_t *tp;
    ngx_core_conf_t *ccf;
    ngx_event_conf_t *ecf;
    // 获取配置信息
    cf = ngx_get_conf(cycle->conf_ctx, ngx_events_module);
    ecf = (*cf)[ngx_event_core_module.ctx_index];

    if (!ngx_test_config && ngx_process <= NGX_PROCESS_MASTER) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "using the \"%s\" event method", ecf->name);
    }

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    ngx_timer_resolution = ccf->timer_resolution;

#if !(NGX_WIN32)
    {
        ngx_int_t limit;
        struct rlimit rlmt;

        if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "getrlimit(RLIMIT_NOFILE) failed, ignored");

        } else {
            if (ecf->connections > (ngx_uint_t) rlmt.rlim_cur
                && (ccf->rlimit_nofile == NGX_CONF_UNSET
                    || ecf->connections > (ngx_uint_t) ccf->rlimit_nofile)) {
                limit = (ccf->rlimit_nofile == NGX_CONF_UNSET) ?
                        (ngx_int_t) rlmt.rlim_cur : ccf->rlimit_nofile;

                ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                              "%ui worker_connections exceed "
                              "open file resource limit: %i",
                              ecf->connections, limit);
            }
        }
    }
#endif /* !(NGX_WIN32) */


    if (ccf->master == 0) {
        return NGX_OK;
    }

    if (ngx_accept_mutex_ptr) {
        return NGX_OK;
    }


    /* cl should be equal to or greater than cache line size */

    cl = 128;

    size = cl            /* ngx_accept_mutex */
           + cl          /* ngx_connection_counter */
           + cl;         /* ngx_temp_number */

#if (NGX_STAT_STUB)

    size += cl           /* ngx_stat_accepted */
           + cl          /* ngx_stat_handled */
           + cl          /* ngx_stat_requests */
           + cl          /* ngx_stat_active */
           + cl          /* ngx_stat_reading */
           + cl          /* ngx_stat_writing */
           + cl;         /* ngx_stat_waiting */

#endif

    shm.size = size;
    ngx_str_set(&shm.name, "nginx_shared_zone");
    shm.log = cycle->log;

    if (ngx_shm_alloc(&shm) != NGX_OK) {
        return NGX_ERROR;
    }

    shared = shm.addr;

    ngx_accept_mutex_ptr = (ngx_atomic_t *) shared;
    ngx_accept_mutex.spin = (ngx_uint_t) - 1;

    if (ngx_shmtx_create(&ngx_accept_mutex, (ngx_shmtx_sh_t *) shared,
                         cycle->lock_file.data)
        != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_connection_counter = (ngx_atomic_t * )(shared + 1 * cl);

    (void) ngx_atomic_cmp_set(ngx_connection_counter, 0, 1);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "counter: %p, %uA",
                   ngx_connection_counter, *ngx_connection_counter);

    ngx_temp_number = (ngx_atomic_t * )(shared + 2 * cl);

    tp = ngx_timeofday();

    ngx_random_number = (tp->msec << 16) + ngx_pid;

#if (NGX_STAT_STUB)

    ngx_stat_accepted = (ngx_atomic_t *) (shared + 3 * cl);
    ngx_stat_handled = (ngx_atomic_t *) (shared + 4 * cl);
    ngx_stat_requests = (ngx_atomic_t *) (shared + 5 * cl);
    ngx_stat_active = (ngx_atomic_t *) (shared + 6 * cl);
    ngx_stat_reading = (ngx_atomic_t *) (shared + 7 * cl);
    ngx_stat_writing = (ngx_atomic_t *) (shared + 8 * cl);
    ngx_stat_waiting = (ngx_atomic_t *) (shared + 9 * cl);

#endif

    return NGX_OK;
}


#if !(NGX_WIN32)

static void
ngx_timer_signal_handler(int signo) {
    ngx_event_timer_alarm = 1;

#if 1
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0, "timer signal");
#endif
}

#endif


static ngx_int_t
ngx_event_process_init(ngx_cycle_t *cycle) {
    ngx_uint_t m, i;
    ngx_event_t *rev, *wev;
    ngx_listening_t *ls;
    ngx_connection_t *c, *next, *old;
    ngx_core_conf_t *ccf;
    ngx_event_conf_t *ecf;
    ngx_event_module_t *module;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);

    if (ccf->master && ccf->worker_processes > 1 && ecf->accept_mutex) {
        ngx_use_accept_mutex = 1;
        ngx_accept_mutex_held = 0;
        ngx_accept_mutex_delay = ecf->accept_mutex_delay;

    } else {
        ngx_use_accept_mutex = 0;
    }

#if (NGX_WIN32)

    /*
     * disable accept mutex on win32 as it may cause deadlock if
     * grabbed by a process which can't accept connections
     */

    ngx_use_accept_mutex = 0;

#endif

    ngx_use_exclusive_accept = 0;

    ngx_queue_init(&ngx_posted_accept_events);
    ngx_queue_init(&ngx_posted_next_events);
    ngx_queue_init(&ngx_posted_events);

    if (ngx_event_timer_init(cycle->log) == NGX_ERROR) {
        return NGX_ERROR;
    }

    for (m = 0; cycle->modules[m]; m++) {
        if (cycle->modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        if (cycle->modules[m]->ctx_index != ecf->use) {
            continue;
        }

        module = cycle->modules[m]->ctx;

        if (module->actions.init(cycle, ngx_timer_resolution) != NGX_OK) {
            /* fatal */
            exit(2);
        }

        break;
    }

#if !(NGX_WIN32)

    if (ngx_timer_resolution && !(ngx_event_flags & NGX_USE_TIMER_EVENT)) {
        struct sigaction sa;
        struct itimerval itv;

        ngx_memzero(&sa, sizeof(struct sigaction));
        sa.sa_handler = ngx_timer_signal_handler;
        sigemptyset(&sa.sa_mask);

        if (sigaction(SIGALRM, &sa, NULL) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "sigaction(SIGALRM) failed");
            return NGX_ERROR;
        }

        itv.it_interval.tv_sec = ngx_timer_resolution / 1000;
        itv.it_interval.tv_usec = (ngx_timer_resolution % 1000) * 1000;
        itv.it_value.tv_sec = ngx_timer_resolution / 1000;
        itv.it_value.tv_usec = (ngx_timer_resolution % 1000) * 1000;

        if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "setitimer() failed");
        }
    }

    if (ngx_event_flags & NGX_USE_FD_EVENT) {
        struct rlimit rlmt;

        if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "getrlimit(RLIMIT_NOFILE) failed");
            return NGX_ERROR;
        }

        cycle->files_n = (ngx_uint_t) rlmt.rlim_cur;

        cycle->files = ngx_calloc(sizeof(ngx_connection_t * ) * cycle->files_n,
                                  cycle->log);
        if (cycle->files == NULL) {
            return NGX_ERROR;
        }
    }

#else

    if (ngx_timer_resolution && !(ngx_event_flags & NGX_USE_TIMER_EVENT)) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "the \"timer_resolution\" directive is not supported "
                      "with the configured event method, ignored");
        ngx_timer_resolution = 0;
    }

#endif

    cycle->connections =
            ngx_alloc(sizeof(ngx_connection_t) * cycle->connection_n, cycle->log);
    if (cycle->connections == NULL) {
        return NGX_ERROR;
    }

    c = cycle->connections;

    cycle->read_events = ngx_alloc(sizeof(ngx_event_t) * cycle->connection_n,
                                   cycle->log);
    if (cycle->read_events == NULL) {
        return NGX_ERROR;
    }

    rev = cycle->read_events;
    for (i = 0; i < cycle->connection_n; i++) {
        rev[i].closed = 1;
        rev[i].instance = 1;
    }

    cycle->write_events = ngx_alloc(sizeof(ngx_event_t) * cycle->connection_n,
                                    cycle->log);
    if (cycle->write_events == NULL) {
        return NGX_ERROR;
    }

    wev = cycle->write_events;
    for (i = 0; i < cycle->connection_n; i++) {
        wev[i].closed = 1;
    }

    i = cycle->connection_n;
    next = NULL;

    do {
        i--;

        c[i].data = next;
        c[i].read = &cycle->read_events[i];
        c[i].write = &cycle->write_events[i];
        c[i].fd = (ngx_socket_t) - 1;

        next = &c[i];
    } while (i);

    cycle->free_connections = next;
    cycle->free_connection_n = cycle->connection_n;

    /* for each listening socket */

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {

#if (NGX_HAVE_REUSEPORT)
        if (ls[i].reuseport && ls[i].worker != ngx_worker) {
            continue;
        }
#endif

        c = ngx_get_connection(ls[i].fd, cycle->log);

        if (c == NULL) {
            return NGX_ERROR;
        }

        c->type = ls[i].type;
        c->log = &ls[i].log;

        c->listening = &ls[i];
        ls[i].connection = c;

        rev = c->read;

        rev->log = c->log;
        rev->accept = 1;

#if (NGX_HAVE_DEFERRED_ACCEPT)
        rev->deferred_accept = ls[i].deferred_accept;
#endif

        if (!(ngx_event_flags & NGX_USE_IOCP_EVENT)) {
            if (ls[i].previous) {

                /*
                 * delete the old accept events that were bound to
                 * the old cycle read events array
                 */

                old = ls[i].previous->connection;

                if (ngx_del_event(old->read, NGX_READ_EVENT, NGX_CLOSE_EVENT)
                    == NGX_ERROR) {
                    return NGX_ERROR;
                }

                old->fd = (ngx_socket_t) - 1;
            }
        }

#if (NGX_WIN32)

        if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
            ngx_iocp_conf_t  *iocpcf;

            rev->handler = ngx_event_acceptex;

            if (ngx_use_accept_mutex) {
                continue;
            }

            if (ngx_add_event(rev, 0, NGX_IOCP_ACCEPT) == NGX_ERROR) {
                return NGX_ERROR;
            }

            ls[i].log.handler = ngx_acceptex_log_error;

            iocpcf = ngx_event_get_conf(cycle->conf_ctx, ngx_iocp_module);
            if (ngx_event_post_acceptex(&ls[i], iocpcf->post_acceptex)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }

        } else {
            rev->handler = ngx_event_accept;

            if (ngx_use_accept_mutex) {
                continue;
            }

            if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }

#else

        rev->handler = (c->type == SOCK_STREAM) ? ngx_event_accept
                                                : ngx_event_recvmsg;

#if (NGX_HAVE_REUSEPORT)

        if (ls[i].reuseport) {
            if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            continue;
        }

#endif

        if (ngx_use_accept_mutex) {
            continue;
        }

#if (NGX_HAVE_EPOLLEXCLUSIVE)

        if ((ngx_event_flags & NGX_USE_EPOLL_EVENT)
            && ccf->worker_processes > 1)
        {
            ngx_use_exclusive_accept = 1;

            if (ngx_add_event(rev, NGX_READ_EVENT, NGX_EXCLUSIVE_EVENT)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }

            continue;
        }

#endif

        if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
            return NGX_ERROR;
        }

#endif

    }

    return NGX_OK;
}


ngx_int_t
ngx_send_lowat(ngx_connection_t *c, size_t lowat) {
    int sndlowat;

#if (NGX_HAVE_LOWAT_EVENT)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
        c->write->available = lowat;
        return NGX_OK;
    }

#endif

    if (lowat == 0 || c->sndlowat) {
        return NGX_OK;
    }

    sndlowat = (int) lowat;

    if (setsockopt(c->fd, SOL_SOCKET, SO_SNDLOWAT,
                   (const void *) &sndlowat, sizeof(int))
        == -1) {
        ngx_connection_error(c, ngx_socket_errno,
                             "setsockopt(SO_SNDLOWAT) failed");
        return NGX_ERROR;
    }

    c->sndlowat = 1;

    return NGX_OK;
}


static char *
ngx_events_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    char *rv;
    void ***ctx;
    ngx_uint_t i;
    ngx_conf_t pcf;
    ngx_event_module_t *m;

    if (*(void **) conf) {
        return "is duplicate";
    }

    /* count the number of the event modules and set up their indices */

    ngx_event_max_module = ngx_count_modules(cf->cycle, NGX_EVENT_MODULE);

    ctx = ngx_pcalloc(cf->pool, sizeof(void *));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }
    /* 分配内存空间 */
    *ctx = ngx_pcalloc(cf->pool, ngx_event_max_module * sizeof(void *));
    if (*ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *(void **) conf = ctx;
    /* 模块初始化，如果是NGX_EVENT_MODULE，则调用模块的create_conf方法 */
    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != NGX_EVENT_MODULE) {
            continue;
        }

        m = cf->cycle->modules[i]->ctx;

        if (m->create_conf) {
            (*ctx)[cf->cycle->modules[i]->ctx_index] =
                    m->create_conf(cf->cycle);
            if ((*ctx)[cf->cycle->modules[i]->ctx_index] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }

    pcf = *cf;
    cf->ctx = ctx;
    cf->module_type = NGX_EVENT_MODULE;
    cf->cmd_type = NGX_EVENT_CONF;
    /* 调用配置解析，这次解析的是{}块中的内容，非文件内容 */
    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != NGX_CONF_OK) {
        return rv;
    }
    /* 初始化event模块的init_conf方法*/
    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != NGX_EVENT_MODULE) {
            continue;
        }

        m = cf->cycle->modules[i]->ctx;

        if (m->init_conf) {
            rv = m->init_conf(cf->cycle,
                              (*ctx)[cf->cycle->modules[i]->ctx_index]);
            if (rv != NGX_CONF_OK) {
                return rv;
            }
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_event_connections(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_event_conf_t *ecf = conf;

    ngx_str_t *value;

    if (ecf->connections != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;
    ecf->connections = ngx_atoi(value[1].data, value[1].len);
    if (ecf->connections == (ngx_uint_t) NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number \"%V\"", &value[1]);

        return NGX_CONF_ERROR;
    }

    cf->cycle->connection_n = ecf->connections;

    return NGX_CONF_OK;
}


static char *
ngx_event_use(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_event_conf_t *ecf = conf;

    ngx_int_t m;
    ngx_str_t *value;
    ngx_event_conf_t *old_ecf;
    ngx_event_module_t *module;

    if (ecf->use != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->cycle->old_cycle->conf_ctx) {
        old_ecf = ngx_event_get_conf(cf->cycle->old_cycle->conf_ctx,
                                     ngx_event_core_module);
    } else {
        old_ecf = NULL;
    }


    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        if (module->name->len == value[1].len) {
            if (ngx_strcmp(module->name->data, value[1].data) == 0) {
                ecf->use = cf->cycle->modules[m]->ctx_index;
                ecf->name = module->name->data;

                if (ngx_process == NGX_PROCESS_SINGLE
                    && old_ecf
                    && old_ecf->use != ecf->use) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "when the server runs without a master process "
                                       "the \"%V\" event type must be the same as "
                                       "in previous configuration - \"%s\" "
                                       "and it cannot be changed on the fly, "
                                       "to change it you need to stop server "
                                       "and start it again",
                                       &value[1], old_ecf->name);

                    return NGX_CONF_ERROR;
                }

                return NGX_CONF_OK;
            }
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid event type \"%V\"", &value[1]);

    return NGX_CONF_ERROR;
}


static char *
ngx_event_debug_connection(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
#if (NGX_DEBUG)
    ngx_event_conf_t  *ecf = conf;

    ngx_int_t             rc;
    ngx_str_t            *value;
    ngx_url_t             u;
    ngx_cidr_t            c, *cidr;
    ngx_uint_t            i;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    value = cf->args->elts;

#if (NGX_HAVE_UNIX_DOMAIN)

    if (ngx_strcmp(value[1].data, "unix:") == 0) {
        cidr = ngx_array_push(&ecf->debug_connection);
        if (cidr == NULL) {
            return NGX_CONF_ERROR;
        }

        cidr->family = AF_UNIX;
        return NGX_CONF_OK;
    }

#endif

    rc = ngx_ptocidr(&value[1], &c);

    if (rc != NGX_ERROR) {
        if (rc == NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "low address bits of %V are meaningless",
                               &value[1]);
        }

        cidr = ngx_array_push(&ecf->debug_connection);
        if (cidr == NULL) {
            return NGX_CONF_ERROR;
        }

        *cidr = c;

        return NGX_CONF_OK;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.host = value[1];

    if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in debug_connection \"%V\"",
                               u.err, &u.host);
        }

        return NGX_CONF_ERROR;
    }

    cidr = ngx_array_push_n(&ecf->debug_connection, u.naddrs);
    if (cidr == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(cidr, u.naddrs * sizeof(ngx_cidr_t));

    for (i = 0; i < u.naddrs; i++) {
        cidr[i].family = u.addrs[i].sockaddr->sa_family;

        switch (cidr[i].family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) u.addrs[i].sockaddr;
            cidr[i].u.in6.addr = sin6->sin6_addr;
            ngx_memset(cidr[i].u.in6.mask.s6_addr, 0xff, 16);
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) u.addrs[i].sockaddr;
            cidr[i].u.in.addr = sin->sin_addr.s_addr;
            cidr[i].u.in.mask = 0xffffffff;
            break;
        }
    }

#else

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"debug_connection\" is ignored, you need to rebuild "
                       "nginx using --with-debug option to enable it");

#endif

    return NGX_CONF_OK;
}


/*
 * 创建Event的核心配置文件
 */
static void *
ngx_event_core_create_conf(ngx_cycle_t *cycle) {
    ngx_event_conf_t *ecf;
    /* 分配配置文件内容 */
    ecf = ngx_palloc(cycle->pool, sizeof(ngx_event_conf_t));
    if (ecf == NULL) {
        return NULL;
    }
    /* 设置默认值 */
    ecf->connections = NGX_CONF_UNSET_UINT;
    ecf->use = NGX_CONF_UNSET_UINT;
    ecf->multi_accept = NGX_CONF_UNSET;
    ecf->accept_mutex = NGX_CONF_UNSET;
    ecf->accept_mutex_delay = NGX_CONF_UNSET_MSEC;
    ecf->name = (void *) NGX_CONF_UNSET;

#if (NGX_DEBUG)

    if (ngx_array_init(&ecf->debug_connection, cycle->pool, 4,
                       sizeof(ngx_cidr_t)) == NGX_ERROR)
    {
        return NULL;
    }

#endif

    return ecf;
}

/*
 * 初始化Event的核心配置文件
 */
static char *
ngx_event_core_init_conf(ngx_cycle_t *cycle, void *conf) {
    ngx_event_conf_t *ecf = conf;

#if (NGX_HAVE_EPOLL) && !(NGX_TEST_BUILD_EPOLL)
    int                  fd;
#endif
    ngx_int_t i;
    ngx_module_t *module;
    ngx_event_module_t *event_module;

    module = NULL;

#if (NGX_HAVE_EPOLL) && !(NGX_TEST_BUILD_EPOLL)

    fd = epoll_create(100);

    if (fd != -1) {
        (void) close(fd);
        module = &ngx_epoll_module;

    } else if (ngx_errno != NGX_ENOSYS) {
        module = &ngx_epoll_module;
    }

#endif

#if (NGX_HAVE_DEVPOLL) && !(NGX_TEST_BUILD_DEVPOLL)

    module = &ngx_devpoll_module;

#endif

#if (NGX_HAVE_KQUEUE)

    module = &ngx_kqueue_module;

#endif

#if (NGX_HAVE_SELECT)

    if (module == NULL) {
        module = &ngx_select_module;
    }

#endif

    if (module == NULL) {
        for (i = 0; cycle->modules[i]; i++) {

            if (cycle->modules[i]->type != NGX_EVENT_MODULE) {
                continue;
            }

            event_module = cycle->modules[i]->ctx;

            if (ngx_strcmp(event_module->name->data, event_core_name.data) == 0) {
                continue;
            }

            module = cycle->modules[i];
            break;
        }
    }

    if (module == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "no events module found");
        return NGX_CONF_ERROR;
    }

    ngx_conf_init_uint_value(ecf->connections, DEFAULT_CONNECTIONS);
    cycle->connection_n = ecf->connections;
    /* 存储使用的事件模型模块索引 例如：epoll、kqueue */
    ngx_conf_init_uint_value(ecf->use, module->ctx_index);

    event_module = module->ctx;
    ngx_conf_init_ptr_value(ecf->name, event_module->name->data);

    ngx_conf_init_value(ecf->multi_accept, 0);
    ngx_conf_init_value(ecf->accept_mutex, 0);
    ngx_conf_init_msec_value(ecf->accept_mutex_delay, 500);

    return NGX_CONF_OK;
}
