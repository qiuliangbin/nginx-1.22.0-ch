
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_RBTREE_H_INCLUDED_
#define _NGX_RBTREE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef ngx_uint_t  ngx_rbtree_key_t;
typedef ngx_int_t   ngx_rbtree_key_int_t;

// 红黑树节点
typedef struct ngx_rbtree_node_s  ngx_rbtree_node_t;

struct ngx_rbtree_node_s {
    ngx_rbtree_key_t       key;     // 索引值
    ngx_rbtree_node_t     *left;    // 指向左子节点
    ngx_rbtree_node_t     *right;   // 指向右子节点
    ngx_rbtree_node_t     *parent;  // 指向父节点
    u_char                 color;   // 颜色(红|黑)
    u_char                 data;    // 数据(由于data只有一个字节,表示太少,很少使用到)
};


typedef struct ngx_rbtree_s  ngx_rbtree_t;

//插入函数指针。可以调用ngx_rbtree_insert_value(作用是找到合适的插入点)
typedef void (*ngx_rbtree_insert_pt) (ngx_rbtree_node_t *root,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

struct ngx_rbtree_s {
    ngx_rbtree_node_t     *root;    // 根结点的指针
    ngx_rbtree_node_t     *sentinel;// 哨兵结点的指针
    ngx_rbtree_insert_pt   insert;  // 插入结点的指针
};
//将函数指针变量作为结构体成员变量以达成可以把结构体当做类来使用（既有成员变量又有成员方法）的效果，
//这种手法在nginx的源码中相当普遍。关于函数，nginx还有一种更神奇的手段——宏：

/* 初始化红黑树，即为空的红黑树 */
/* tree 是指向红黑树的指针，
 * s 是红黑树的一个NIL节点，表示无值，任何变量在没有被赋值之前的值都为nil。
 * i 表示函数指针，决定节点是新增还是替换
 */
#define ngx_rbtree_init(tree, s, i)                                           \
    ngx_rbtree_sentinel_init(s);                                              \
    (tree)->root = s;                                                         \
    (tree)->sentinel = s;                                                     \
    (tree)->insert = i  // 这里insert函数指针的赋值实现了多态

#define ngx_rbtree_data(node, type, link)                                     \
    (type *) ((u_char *) (node) - offsetof(type, link))


void ngx_rbtree_insert(ngx_rbtree_t *tree, ngx_rbtree_node_t *node);
void ngx_rbtree_delete(ngx_rbtree_t *tree, ngx_rbtree_node_t *node);
void ngx_rbtree_insert_value(ngx_rbtree_node_t *root, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel);
// ngx_rbtree_insert_timer_value函数跟ngx_rbtree_insert_value函数唯一区别就是判断大小时，
// 采用了两个值相减，避免溢出
void ngx_rbtree_insert_timer_value(ngx_rbtree_node_t *root,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
ngx_rbtree_node_t *ngx_rbtree_next(ngx_rbtree_t *tree,
    ngx_rbtree_node_t *node);


/* 给节点着色，1表示红色，0表示黑色  */
#define ngx_rbt_red(node)               ((node)->color = 1)
#define ngx_rbt_black(node)             ((node)->color = 0)
/* 判断节点的颜色 */
#define ngx_rbt_is_red(node)            ((node)->color)
#define ngx_rbt_is_black(node)          (!ngx_rbt_is_red(node))
/* 复制某个节点的颜色 */
#define ngx_rbt_copy_color(n1, n2)      (n1->color = n2->color)


/* a sentinel must be black */
/* 节点着黑色的宏定义 */

#define ngx_rbtree_sentinel_init(node)  ngx_rbt_black(node)

/* 寻找红黑树的最小值 */
static ngx_inline ngx_rbtree_node_t *
ngx_rbtree_min(ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    while (node->left != sentinel) {
        node = node->left;
    }

    return node;
}


#endif /* _NGX_RBTREE_H_INCLUDED_ */
