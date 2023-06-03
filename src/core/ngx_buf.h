
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_BUF_H_INCLUDED_
#define _NGX_BUF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef void *            ngx_buf_tag_t;

typedef struct ngx_buf_s  ngx_buf_t;

struct ngx_buf_s {
    u_char          *pos; // 距离缓存开始位置的偏移量
    u_char          *last; // 当buf指向的数据在内存中的时候, pos指向的是这段数据的结束位置
    off_t            file_pos; // 文件距离开始位置的偏移量
    off_t            file_last; // 文件结束位置
    /*
    当buf指向的数据是在内存里的时候，这一整块内存所包含的内容可能被包含在多个buf中（比如某段数据中间插入了其他数据，
    这一块数据就需要被拆分开），那么这些buf中的start和end都指向这一块内存的开始地址和结束地址。
    而pos和last指向其中一个配置项所实际包含的数据的开始和结尾。
    */
    u_char          *start;         /* start of buffer */
    u_char          *end;           /* end of buffer */
    ngx_buf_tag_t    tag; // buffer属于哪个模块的标志, 实际上是一个void *类型的指针，使用者可以关联任意的对象上去，只要对使用者有意义
    ngx_file_t      *file; // buffer引用的文件,当buf所包含的内容在文件时，file字段指向对应的文件对象
    /*
    当这个buf完整copy了另外一个buf的所有字段的时候，那么这两个buf实际指向的是同一块内存，或是同一个文件的同一部分，
    此时这两个buf的shadow字段都是指向对方的。那么对于这样的两个buf，在释放的时候，就需要使用者特别小心，
    具体由哪里释放，要提前考虑好，如果造成资源的多次释放，可能造成程序崩溃。使用shadow主要是为了节约内存，
    因为当有多个地方要操作这一块内存的时候，就可以新建一个shadow,对shadow的操作（这里并不修改所指向内存块的内容）
    不会影响到原buf。

    注：当前缓冲区的影子缓冲区，该成员很少用到。仅仅在使用缓冲区转发上游服务器的响应时才使用了shadow成员，
    这是因为nginx太节约内存了。分配一块内存并使用ngx_buf_t表示接收到的上游服务器响应后，在向下游客户端转发时
    可能会把这块内存存储到文件中，也可能直接向下游发送，此时nginx绝对不会重新复制一份内存用于新的目的，而是
    再次建立一个ngx_buf_t结构体指向原内存，这样多个ngx_buf_t结构体指向了同一块内存，它们之间的关系就通过
    shadow成员来引用，这种设计过于复杂，通常不建议使用。
    */
    ngx_buf_t       *shadow;    /* 用来引用替换过后的buffer，以便当所有buffer输出以后，这个影子buffer可以被释放。*/


    /* the buf's content could be changed */
    // 为1时表示该buf所包含的内容是在一个用户创建的内存块中，并且可以被在filter处理的过程中进行变更，而不会造成问题
    unsigned         temporary:1; 

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    // 为1时表示该buf所包含的内容是在内存中，但是这些内容却不能被进行处理的filter进行变更
    unsigned         memory:1;

    /* the buf's content is mmap()ed and must not be changed */
    // 为1时表示该buf所包含的内容是在内存中，是通过mmap()使用内存映射从文件映射到内存中的，这些内容却不能被进行处理的filter进行变更
    unsigned         mmap:1;
    // 可以回收的。也就是这个buf是可以被释放的。这个字段通常是配合shadow字段一起使用的，
    // 对于使用ngx_create_temp_buf()函数所创建的buf，并且是另外一个buf的shadow，那么使用这个字段来标示这个buf是可以释放的
    unsigned         recycled:1; /* 内存可以被输出并回收 */
    // 为1时表示该buf所包含的内容是在文件中
    unsigned         in_file:1; /* buffer的内容在文件中 */
    // 遇到有flush字段被设置为1的buf chain，则该chain的数据即便不是最后结束的数据(last_buf被设置，
    // 标示所有要输出的内容都完了），也会进行输出，不会受postpone_output配置的限制，但是会受到发送速率等其他条件的限制
    unsigned         flush:1; /* 马上全部输出buffer的内容, gzip模块里面用得比较多 */
    // 为1时表示可以对该buf进行同步操作，容易引起堵塞
    unsigned         sync:1;  /* 基本上是一段输出链的最后一个buffer带的标志，标示可以输出，有些零长度的buffer也可以置该标志*/
    // 数据被以多个chain传递给了过滤器，此字段为1表示这是缓冲区链表ngx_chain_t上最后一块待处理的缓冲区
    unsigned         last_buf:1; /* 所有请求里面最后一块buffer，包含子请求 */
    // 在当前的chain里面，此buf是最后一个。特别要注意的是标志为last_in_chain的buf并不一定是last_buf，
    // 但是标志为last_buf的buf则一定是last_in_chain的。这是因为数据会被以多个chain传递给某个filter模块
    unsigned         last_in_chain:1;  /* 当前请求输出链的最后一块buffer */
    // 在创建一个buf的shadow的时候，通常将新创建的一个buf的last_shadow置为1，表示为最后一个影子缓冲区
    unsigned         last_shadow:1; /* shadow链里面的最后buffer，可以释放buffer了 */
    // 由于受内存使用的限制，有时候一些buf的内容需要被写到磁盘上的临时文件中去，那么这时就设置此标志
    unsigned         temp_file:1; /* 是否是暂存文件 */

    /* STUB */ int   num; /* 统计用，表示使用次数 */
};

// 数据结构形成一个nginx buf链
struct ngx_chain_s {
    ngx_buf_t    *buf; 
    ngx_chain_t  *next;
};

// 数据结构一般在创建buf链的时候使用
typedef struct {
    ngx_int_t    num; // 当前的buf数目
    size_t       size;// 每一个buf的空间大小
} ngx_bufs_t;


typedef struct ngx_output_chain_ctx_s  ngx_output_chain_ctx_t;

typedef ngx_int_t (*ngx_output_chain_filter_pt)(void *ctx, ngx_chain_t *in);

typedef void (*ngx_output_chain_aio_pt)(ngx_output_chain_ctx_t *ctx,
    ngx_file_t *file);

struct ngx_output_chain_ctx_s {
    ngx_buf_t                   *buf;
    ngx_chain_t                 *in;
    ngx_chain_t                 *free;
    ngx_chain_t                 *busy;

    unsigned                     sendfile:1;
    unsigned                     directio:1;
    unsigned                     unaligned:1;
    unsigned                     need_in_memory:1;
    unsigned                     need_in_temp:1;
    unsigned                     aio:1;

#if (NGX_HAVE_FILE_AIO || NGX_COMPAT)
    ngx_output_chain_aio_pt      aio_handler;
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_int_t                  (*thread_handler)(ngx_thread_task_t *task,
                                                 ngx_file_t *file);
    ngx_thread_task_t           *thread_task;
#endif

    off_t                        alignment;

    ngx_pool_t                  *pool;
    ngx_int_t                    allocated;
    ngx_bufs_t                   bufs;
    ngx_buf_tag_t                tag;

    ngx_output_chain_filter_pt   output_filter;
    void                        *filter_ctx;
};


typedef struct {
    ngx_chain_t                 *out;
    ngx_chain_t                **last;
    ngx_connection_t            *connection;
    ngx_pool_t                  *pool;
    off_t                        limit;
} ngx_chain_writer_ctx_t;


#define NGX_CHAIN_ERROR     (ngx_chain_t *) NGX_ERROR


#define ngx_buf_in_memory(b)       ((b)->temporary || (b)->memory || (b)->mmap)
#define ngx_buf_in_memory_only(b)  (ngx_buf_in_memory(b) && !(b)->in_file)

#define ngx_buf_special(b)                                                   \
    (((b)->flush || (b)->last_buf || (b)->sync)                              \
     && !ngx_buf_in_memory(b) && !(b)->in_file)

#define ngx_buf_sync_only(b)                                                 \
    ((b)->sync && !ngx_buf_in_memory(b)                                      \
     && !(b)->in_file && !(b)->flush && !(b)->last_buf)

#define ngx_buf_size(b)                                                      \
    (ngx_buf_in_memory(b) ? (off_t) ((b)->last - (b)->pos):                  \
                            ((b)->file_last - (b)->file_pos))

ngx_buf_t *ngx_create_temp_buf(ngx_pool_t *pool, size_t size);
ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs);


#define ngx_alloc_buf(pool)  ngx_palloc(pool, sizeof(ngx_buf_t))
#define ngx_calloc_buf(pool) ngx_pcalloc(pool, sizeof(ngx_buf_t))

ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool);
#define ngx_free_chain(pool, cl)                                             \
    (cl)->next = (pool)->chain;                                              \
    (pool)->chain = (cl)



ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in);
ngx_int_t ngx_chain_writer(void *ctx, ngx_chain_t *in);

ngx_int_t ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in);
ngx_chain_t *ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free);
void ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free,
    ngx_chain_t **busy, ngx_chain_t **out, ngx_buf_tag_t tag);

off_t ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit);

ngx_chain_t *ngx_chain_update_sent(ngx_chain_t *in, off_t sent);

#endif /* _NGX_BUF_H_INCLUDED_ */
