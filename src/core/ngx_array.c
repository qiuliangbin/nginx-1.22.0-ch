
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>

ngx_array_t *
ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size)
{
    ngx_array_t *a;

    a = ngx_palloc(p, sizeof(ngx_array_t));
    if (a == NULL)
    {
        return NULL;
    }

    if (ngx_array_init(a, p, n, size) != NGX_OK)
    {
        return NULL;
    }

    return a;
}

void ngx_array_destroy(ngx_array_t *a)
{
    ngx_pool_t *p;

    p = a->pool;

    if ((u_char *)a->elts + a->size * a->nalloc == p->d.last)
    {
        p->d.last -= a->size * a->nalloc;
    }

    if ((u_char *)a + sizeof(ngx_array_t) == p->d.last)
    {
        p->d.last = (u_char *)a;
    }
}

/**
 * @description: 数组插入数据元素
 * @return {*} 当前数组插入数据后的数据地址
 */
void *ngx_array_push(ngx_array_t *a)
{
    void *elt, *new;
    size_t size;
    ngx_pool_t *p;

    if (a->nelts == a->nalloc)
    {

        /* the array is full */

        size = a->size * a->nalloc;

        p = a->pool;
        // Nginx的数组容量是在内存池上分配的,因此不一定需要新开辟空间,这需要依据内存池是否由新的可用空间来确定
        if ((u_char *)a->elts + size == p->d.last && p->d.last + a->size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */
            // 内存池当前节点上仍然剩余空间存放数组新数据
            p->d.last += a->size; // 更新数组已使用大小
            a->nalloc++;          // 更新数组已使用的个数+1
        }
        else
        {
            /* allocate a new array */
            // 当内存池地址不够用时,需要新申请内存池。申请内存池的大小是原数组大小的2倍
            new = ngx_palloc(p, 2 * size);
            if (new == NULL)
            {
                return NULL;
            }
            // 内存池初始化之后, 将原数组依次赋值到新地址上
            ngx_memcpy(new, a->elts, size);
            a->elts = new;
            a->nalloc *= 2;
        }
    }

    elt = (u_char *)a->elts + a->size * a->nelts; //当前数组插入数据后的数据地址
    a->nelts++;                                   //当前数组一存放数据的数量+1

    return elt;
}

void *
ngx_array_push_n(ngx_array_t *a, ngx_uint_t n)
{
    void *elt, *new;
    size_t size;
    ngx_uint_t nalloc;
    ngx_pool_t *p;

    size = n * a->size;

    if (a->nelts + n > a->nalloc)
    {

        /* the array is full */

        p = a->pool;

        if ((u_char *)a->elts + a->size * a->nalloc == p->d.last && p->d.last + size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += size;
            a->nalloc += n;
        }
        else
        {
            /* allocate a new array */

            nalloc = 2 * ((n >= a->nalloc) ? n : a->nalloc);

            new = ngx_palloc(p, nalloc * a->size);
            if (new == NULL)
            {
                return NULL;
            }

            ngx_memcpy(new, a->elts, a->nelts * a->size);
            a->elts = new;
            a->nalloc = nalloc;
        }
    }

    elt = (u_char *)a->elts + a->size * a->nelts;
    a->nelts += n;

    return elt;
}
