
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONF_FILE_H_INCLUDED_
#define _NGX_CONF_FILE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 *        AAAA  number of arguments
 *      FF      command flags
 *    TT        command type, i.e. HTTP "location" or "server" command
 */

#define NGX_CONF_NOARGS      0x00000001 // 配置指令不接受任何参数
#define NGX_CONF_TAKE1       0x00000002 // 配置指令接受1个参数
#define NGX_CONF_TAKE2       0x00000004 // 配置指令接受2个参数
#define NGX_CONF_TAKE3       0x00000008 // 配置指令接受3个参数
#define NGX_CONF_TAKE4       0x00000010 // 配置指令接受4个参数
#define NGX_CONF_TAKE5       0x00000020 // 配置指令接受5个参数
#define NGX_CONF_TAKE6       0x00000040 // 配置指令接受6个参数
#define NGX_CONF_TAKE7       0x00000080 // 配置指令接受7个参数

#define NGX_CONF_MAX_ARGS    8 // nginx配置指令最大参数大小，目前该值被定义为8，也就是不能超过8个参数值

#define NGX_CONF_TAKE12      (NGX_CONF_TAKE1|NGX_CONF_TAKE2) // 配置指令接受1个或2个参数
#define NGX_CONF_TAKE13      (NGX_CONF_TAKE1|NGX_CONF_TAKE3) // 配置指令接受1个或3个参数

#define NGX_CONF_TAKE23      (NGX_CONF_TAKE2|NGX_CONF_TAKE3) // 配置指令接受2个或3个参数

#define NGX_CONF_TAKE123     (NGX_CONF_TAKE1|NGX_CONF_TAKE2|NGX_CONF_TAKE3) // 配置指令接受1个或2个或3个参数
#define NGX_CONF_TAKE1234    (NGX_CONF_TAKE1|NGX_CONF_TAKE2|NGX_CONF_TAKE3   \
                              |NGX_CONF_TAKE4) //  配置指令接受1个或2个或3个或4个参数

#define NGX_CONF_ARGS_NUMBER 0x000000ff // 用于取参数个数的宏定义
/*
配置指令可以接受的值是一个配置信息块。也就是一对大括号括起来的内容。里面可以再包括很多的配置指令，比如常见的server指令就是这个属性的：
http {
    ...
    server {
        listen       8000;
        server_name  somename  alias  another.alias;

        location / {
            root   html;
            index  index.html index.htm;
        }
    }
    ....
}
*/
#define NGX_CONF_BLOCK       0x00000100 // 配置指令可以接受的值是一个配置信息块
#define NGX_CONF_FLAG        0x00000200 // 配置指令可以接受的值是on或者off，最终会被转成bool值
#define NGX_CONF_ANY         0x00000400 // 配置指令可以接受任意参数值。一个或者多个，或者on，或者off，或者是配置块
#define NGX_CONF_1MORE       0x00000800 // 配置指令至少接受1个参数
#define NGX_CONF_2MORE       0x00001000 // 配置指令至少接受2个参数
/* 配置指令可以出现的位置的属性 */
#define NGX_DIRECT_CONF      0x00010000 // 配置指令只能出现在主配置文件中

#define NGX_MAIN_CONF        0x01000000 // 配置指令只能出现在主配置级别，例如http、mail、events、error_log等配置指令
#define NGX_ANY_CONF         0xFF000000 // 该配置指令可以出现在任意配置级别上


// 表示当前某一种类型的配置项未设置
#define NGX_CONF_UNSET       -1
#define NGX_CONF_UNSET_UINT  (ngx_uint_t) -1
#define NGX_CONF_UNSET_PTR   (void *) -1
#define NGX_CONF_UNSET_SIZE  (size_t) -1
#define NGX_CONF_UNSET_MSEC  (ngx_msec_t) -1


#define NGX_CONF_OK          NULL
#define NGX_CONF_ERROR       (void *) -1
// 表示配置信息块的开始/结束，整个配置文件的结束， 主要是用于解析配置文件时使用
#define NGX_CONF_BLOCK_START 1
#define NGX_CONF_BLOCK_DONE  2
#define NGX_CONF_FILE_DONE   3
// 模块类型的magic值
#define NGX_CORE_MODULE      0x45524F43  /* "CORE" */
#define NGX_CONF_MODULE      0x464E4F43  /* "CONF" */

//配置文件最长错误字符串长度
#define NGX_MAX_CONF_ERRSTR  1024

/**
 * 模块支持的命令集结构
 */
struct ngx_command_s {
    ngx_str_t             name; // 本条指令的名字，例如worker_processes 1;对应的ngx_command_s.name就是worker_processes
    /*
        type：配置指令属性的集合。例如，worker_processes这条指令对应的type定义为：
            NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1
        这就表示该指令用于main上下文; 且是属于main上下文的简单指令; 该指令后跟一个参数,例如: worker_processes 1;
    */
    ngx_uint_t            type; // 配置指令属性的集合
    // 函数指针set用来表示，当nginx解析配置文件碰到此指令时，该执行怎样的操作。
    // 而该操作本身，自然是用来设置本模块所对应的ngx_<module_name>_conf_t结构体
    char               *(*set)(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
    /*
        conf：这个变量只在NGX_HTTP_MODULE类型模块的ngx_command_t使用，指定当前配置项存储的内存位置。
        实际上是使用哪个内存池的问题。因为http模块对所有该模块要保存的信息划分了main、server、location三个地方进行存储，
        每个地方都有一个内存池用来分配存储这些信息的内存。这里可能的取值为：
            NGX_HTTP_MAIN_CONF_OFFSET、NGX_HTTP_SRV_CONF_OFFSET或NGX_HTTP_LOC_CONF_OFFSET
    */
    ngx_uint_t            conf;
    // 表示当前配置项在整个存储配置项的结构体中的偏移位置
    ngx_uint_t            offset; // 用来标记ngx_<module_name>_conf_t中某成员变量的偏移量，纯粹是为了使用方便
    // 配置项读取后的处理方法 必须是ngx_conf_post_t结构体的指针
    void                 *post;
};
// 一般作为ngx_command_s配置数组的结束标志
#define ngx_null_command  { ngx_null_string, 0, NULL, 0, 0, NULL }

/*
* 代表一个已打开的文件
*/
struct ngx_open_file_s {
    ngx_fd_t              fd;//已打开文件句柄
    ngx_str_t             name;//已打开文件的文件名
    // 函数指针flush，用于指定当有数据需要写入到文件时，所进行的操作（此过程可能不是简单的文件写入操作，可能还涉及到其他变量的更新）
    void                (*flush)(ngx_open_file_t *file, ngx_log_t *log);
    void                 *data; // 辅助数据
};


typedef struct {
    ngx_file_t            file;   // 该配置所对应的文件
    ngx_buf_t            *buffer; // 该配置文件所关联的缓冲
    ngx_buf_t            *dump;   // 主要用于在执行./nginx -T命令时，用于指定dump时所用的缓冲
    ngx_uint_t            line;   // 用于指定当前解析到的行数
} ngx_conf_file_t;

// dump配置文件时用到
typedef struct {
    ngx_str_t             name;
    ngx_buf_t            *buffer;
} ngx_conf_dump_t;


typedef char *(*ngx_conf_handler_pt)(ngx_conf_t *cf,
    ngx_command_t *dummy, void *conf);


struct ngx_conf_s {
    char                 *name; // 存放当前所解析到的指令
    ngx_array_t          *args; // 存放该指令包含的所有参数。args[0]存放的是指令本身

    ngx_cycle_t          *cycle;     // 所关联的全局ngx_cycle_t变量
    ngx_pool_t           *pool;      // 所关联的内存池
    ngx_pool_t           *temp_pool; // 用于解析配置文件的临时内存池，解析完后释放
    ngx_conf_file_t      *conf_file; // 存放nginx配置文件相关信息
    ngx_log_t            *log;       // 描述日志文件的相关属性

    void                 *ctx;         // 描述指令的上下文信息
    ngx_uint_t            module_type; // 当前指令所属模块类型，core、http、event和mail中的一种
    ngx_uint_t            cmd_type;    // 指令的类型

    ngx_conf_handler_pt   handler;      // 指令自定义的处理函数
    void                 *handler_conf; // 自定义处理函数需要的相关配置
};


typedef char *(*ngx_conf_post_handler_pt) (ngx_conf_t *cf,
    void *data, void *conf);

typedef struct {
    ngx_conf_post_handler_pt  post_handler;
} ngx_conf_post_t;


typedef struct {
    ngx_conf_post_handler_pt  post_handler;
    char                     *old_name;
    char                     *new_name;
} ngx_conf_deprecated_t;

// 对nginx配置指令取值的上下界的封装
typedef struct {
    ngx_conf_post_handler_pt  post_handler;
    ngx_int_t                 low;
    ngx_int_t                 high;
} ngx_conf_num_bounds_t;

//配置中的枚举结构。
typedef struct {
    ngx_str_t                 name;
    ngx_uint_t                value;
} ngx_conf_enum_t;


#define NGX_CONF_BITMASK_SET  1

// 配置中的位掩码结构
typedef struct {
    ngx_str_t                 name;
    ngx_uint_t                mask;
} ngx_conf_bitmask_t;


char * ngx_conf_deprecated(ngx_conf_t *cf, void *post, void *data); // 处理过时指令
char *ngx_conf_check_num_bounds(ngx_conf_t *cf, void *post, void *data); // 检测配置指令中的上下界

// 获得配置上下文中的对应模块的配置
#define ngx_get_conf(conf_ctx, module)  conf_ctx[module.index]


// 采用default值初始化当前conf变量（conf一般为bool类型，因此default一般取0或1）
// 注意： C语言中bool类型一般用int表示
#define ngx_conf_init_value(conf, default)                                   \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = default;                                                      \
    }
// 初始化指针类型变量
#define ngx_conf_init_ptr_value(conf, default)                               \
    if (conf == NGX_CONF_UNSET_PTR) {                                        \
        conf = default;                                                      \
    }
// 初始化uint类型变量
#define ngx_conf_init_uint_value(conf, default)                              \
    if (conf == NGX_CONF_UNSET_UINT) {                                       \
        conf = default;                                                      \
    }
// 初始化size类型变量
#define ngx_conf_init_size_value(conf, default)                              \
    if (conf == NGX_CONF_UNSET_SIZE) {                                       \
        conf = default;                                                      \
    }
// 初始化时间类型变量
#define ngx_conf_init_msec_value(conf, default)                              \
    if (conf == NGX_CONF_UNSET_MSEC) {                                       \
        conf = default;                                                      \
    }
// 在conf当前未设置的情况下，如果prev值为NGX_CONF_UNSET,则将conf设置为default；否则设置为prev
#define ngx_conf_merge_value(conf, prev, default)                            \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = (prev == NGX_CONF_UNSET) ? default : prev;                    \
    }

#define ngx_conf_merge_ptr_value(conf, prev, default)                        \
    if (conf == NGX_CONF_UNSET_PTR) {                                        \
        conf = (prev == NGX_CONF_UNSET_PTR) ? default : prev;                \
    }

#define ngx_conf_merge_uint_value(conf, prev, default)                       \
    if (conf == NGX_CONF_UNSET_UINT) {                                       \
        conf = (prev == NGX_CONF_UNSET_UINT) ? default : prev;               \
    }

#define ngx_conf_merge_msec_value(conf, prev, default)                       \
    if (conf == NGX_CONF_UNSET_MSEC) {                                       \
        conf = (prev == NGX_CONF_UNSET_MSEC) ? default : prev;               \
    }

#define ngx_conf_merge_sec_value(conf, prev, default)                        \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = (prev == NGX_CONF_UNSET) ? default : prev;                    \
    }

#define ngx_conf_merge_size_value(conf, prev, default)                       \
    if (conf == NGX_CONF_UNSET_SIZE) {                                       \
        conf = (prev == NGX_CONF_UNSET_SIZE) ? default : prev;               \
    }

#define ngx_conf_merge_off_value(conf, prev, default)                        \
    if (conf == NGX_CONF_UNSET) {                                            \
        conf = (prev == NGX_CONF_UNSET) ? default : prev;                    \
    }
// 对字符串类型进行合并设置
#define ngx_conf_merge_str_value(conf, prev, default)                        \
    if (conf.data == NULL) {                                                 \
        if (prev.data) {                                                     \
            conf.len = prev.len;                                             \
            conf.data = prev.data;                                           \
        } else {                                                             \
            conf.len = sizeof(default) - 1;                                  \
            conf.data = (u_char *) default;                                  \
        }                                                                    \
    }
// 对buf类型进行合并设置
#define ngx_conf_merge_bufs_value(conf, prev, default_num, default_size)     \
    if (conf.num == 0) {                                                     \
        if (prev.num) {                                                      \
            conf.num = prev.num;                                             \
            conf.size = prev.size;                                           \
        } else {                                                             \
            conf.num = default_num;                                          \
            conf.size = default_size;                                        \
        }                                                                    \
    }

#define ngx_conf_merge_bitmask_value(conf, prev, default)                    \
    if (conf == 0) {                                                         \
        conf = (prev == 0) ? default : prev;                                 \
    }

// 主要是用来处理通过命令行-g选项传递进来的“全局配置指令”
char *ngx_conf_param(ngx_conf_t *cf);
// 用于解析配置信息
char *ngx_conf_parse(ngx_conf_t *cf, ngx_str_t *filename);
// 用于解析include指令
char *ngx_conf_include(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

// 获取配置文件的全路径名称
ngx_int_t ngx_conf_full_name(ngx_cycle_t *cycle, ngx_str_t *name,
    ngx_uint_t conf_prefix);
// 打开配置文件中指定的一个文件
ngx_open_file_t *ngx_conf_open_file(ngx_cycle_t *cycle, ngx_str_t *name);
// 处理配置文件中的log_error指令
void ngx_cdecl ngx_conf_log_error(ngx_uint_t level, ngx_conf_t *cf,
    ngx_err_t err, const char *fmt, ...);

// 用来设置flag类型（bool类型）的变量; 把 "on" 或 "off" 解析为 1 或 0
char *ngx_conf_set_flag_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// 用来设置字符串类型的变量; 解析字符串并保存 ngx_str_t类型
char *ngx_conf_set_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// 用来设置字符串数组类型的变量
char *ngx_conf_set_str_array_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// 用来设置key/value类型的数组变量
char *ngx_conf_set_keyval_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// 用于设置数字类型变量; 解析一个数字并将其保存为int 类型
char *ngx_conf_set_num_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// 用于设置size_t类型变量; 解析数据大小 ("8k", "1m", etc.) 并将其保存为size_t
char *ngx_conf_set_size_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// 用于设置offset类型变量
char *ngx_conf_set_off_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// 用于设置毫秒类型变量
char *ngx_conf_set_msec_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// 用于设置秒类型变量
char *ngx_conf_set_sec_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// 用于设置buf类型的变量
char *ngx_conf_set_bufs_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// 用于设置枚举类型变量
char *ngx_conf_set_enum_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// 用于设置掩码类型变量
char *ngx_conf_set_bitmask_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


#endif /* _NGX_CONF_FILE_H_INCLUDED_ */
