
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * The red-black tree code is based on the algorithm described in
 * the "Introduction to Algorithms" by Cormen, Leiserson and Rivest.
 */
/*
红黑树的特质:
    1 节点是红色或黑色；
    2 根节点是黑色；
    3 所有叶子节点都是黑色节点(NULL)；
    4 每个红色节点必须有两个黑色的子节点（如果叶子结点是红色，那么我的黑色结点可以不画出来）。
 (从每个叶子到根的所有路径上不能有两个连续的红色节点)
    5 从任一节点到其每个叶子的所有简单路径都包含相同数目的黑色节点
*/

static ngx_inline void ngx_rbtree_left_rotate(ngx_rbtree_node_t **root,
    ngx_rbtree_node_t *sentinel, ngx_rbtree_node_t *node); // 左旋
static ngx_inline void ngx_rbtree_right_rotate(ngx_rbtree_node_t **root,
    ngx_rbtree_node_t *sentinel, ngx_rbtree_node_t *node); // 右旋

/*  红黑树的插入新节点,步骤如下:
 *      1) 首先按照二叉搜索树的插入操作插入新节点
 *      2) 把新节点着色为红色(特质5)
 *      3) 为维持红黑树的特质,调整红黑树的节点(着色&旋转),使其满足红黑树特质
 *
 *      红黑树的性质：
        1.每个节点或是红色的，或是黑色的。
        2.根节点是黑色的。
        3.每个叶节点（NULL）是黑色的。
        4.如果一个节点是红色的，则它的两个孩子节点都是黑色的。
        5.对每个节点，从该节点到其所有后代叶节点的简单路径上，均包含相同数目的黑色节点。
 * */
void
ngx_rbtree_insert(ngx_rbtree_t *tree, ngx_rbtree_node_t *node)
{
    ngx_rbtree_node_t  **root, *temp, *sentinel;

    /* a binary tree insert */

    root = &tree->root;
    sentinel = tree->sentinel;
    // 空树,那么插入的节点变成根节点,伴随着左右子节点变成哨兵节点
    if (*root == sentinel) { // 特殊判定,如果根是哨兵,则树是空的
        node->parent = NULL;    // 新插入的节点变成根节点
        node->left = sentinel;  // 新节点的左子节点变为哨兵
        node->right = sentinel; // 新节点的右子节点变为哨兵
        ngx_rbt_black(node);    // 新根节点着色为黑色(特质2)
        *root = node; //确认新结点为新根

        return;
    }
    /* 若红黑树不为空，则按照二叉查找树的插入操作进行; 该操作由函数指针提供,可以参照官方样例函数:ngx_str_rbtree_insert_value */
    tree->insert(*root, node, sentinel); // 插入操作(通过这个函数指针的调用就能找到我们的插入点了)

    /* re-balance tree */
    // 如果新结点不是根结点而且其父结点是红的，循环
    /* 调整红黑树，使其满足性质，
     * 其实这里只是破坏了性质4：若一个节点是红色，则孩子节点都为黑色；
     * 若破坏了性质4，则新节点 node 及其父亲节点 node->parent 都为红色；
     */
    while (node != *root && ngx_rbt_is_red(node->parent)) {
        /* 若node的父亲节点是其祖父节点的左孩子 */
        if (node->parent == node->parent->parent->left) {
            /*
                    node->parent->parent
                    /               \
                  node->parent      temp(node的叔叔节点)
                  /
                node
             */
            temp = node->parent->parent->right;

            if (ngx_rbt_is_red(temp)) {
                /* case1：node的叔叔节点是红色 */
                /* 此时，node的父亲及叔叔节点都为红色；
                 * 解决办法：将node的父亲及叔叔节点着色为黑色，将node祖父节点着色为红色；
                 * 然后沿着祖父节点向上判断是否会破会红黑树的性质；
                 */
                ngx_rbt_black(node->parent);
                ngx_rbt_black(temp);
                ngx_rbt_red(node->parent->parent);
                node = node->parent->parent;

            } else {
                /* case2：node的叔叔节点是黑色且node是父亲节点的右孩子 */
                /* 则此时，以node父亲节点进行左旋转，使case2转变为case3；
                 */
                if (node == node->parent->right) {
                    node = node->parent;
                    ngx_rbtree_left_rotate(root, sentinel, node);
                }
                /* case3：node的叔叔节点是黑色且node是父亲节点的左孩子 */
                /* 首先，将node的父亲节点着色为黑色，祖父节点着色为红色；
                 * 然后以祖父节点进行一次右旋转；
                 */
                ngx_rbt_black(node->parent);
                ngx_rbt_red(node->parent->parent);
                ngx_rbtree_right_rotate(root, sentinel, node->parent->parent);
            }

        } else { /* 若node的父亲节点是其祖父节点的右孩子 */
            temp = node->parent->parent->left;

            if (ngx_rbt_is_red(temp)) {  /* case1：node的叔叔节点是红色 */
                ngx_rbt_black(node->parent);
                ngx_rbt_black(temp);
                ngx_rbt_red(node->parent->parent);
                node = node->parent->parent;

            } else {
                /*   新增节点为75
                           60(Black)                                              60(Black)
                      /                  \                                  /                  \
                    50(Black)          70(black)             右旋         50(Black)           70(black)
                  /       \            /        \          ------>     /       \            /        \
                35(red) 55(red)      null    78(red)              35(red)    55(red)       null     75(Red)
                /   \     /   \               /     \               /   \     /   \               /     \
               null null null null   node -> 75(Red) null          null null null null           null   78(red) <-node
                                           /   \                                                      /   \
                                         null null                                                   null null
                */
                if (node == node->parent->left) {
                    node = node->parent;
                    ngx_rbtree_right_rotate(root, sentinel, node);
                }
                /*   新增节点为75
                           60(Black)                                              60(Black)
                      /                  \                                  /                \
                    50(Black)          70(black)             染色         50(Black)         70(red)
                  /       \            /        \          ------>     /       \          /        \
                35(red) 55(red)      null    75(Red)              35(red) 55(red)        null    75(black)
                /   \     /   \               /     \               /   \     /   \               /     \
               null null null null          null 78(Red) <-node    null null null null           null   78(Red) <-node
                                                  /   \                                                  /   \
                                                 null null                                             null null
                */
                ngx_rbt_black(node->parent);
                ngx_rbt_red(node->parent->parent);
                /*   新增节点为75
                           60(Black)                                          60(Black)
                      /                  \                                 /             \
                    50(Black)          70(red)           左旋         50(Red)           75(black)
                  /       \            /        \          ------>     /       \          /      \
                35(red) 55(red)     null    75(black)               35(Black) 55(black) 70(red)  78(red)
                /   \     /   \               /     \               /   \     /   \     /  \     /    \
                null null null null          null 78(Red) <-node  null null null null null null null  null
                                                  /   \
                                                 null null
                */
                ngx_rbtree_left_rotate(root, sentinel, node->parent->parent);
            }
        }
    }
    /* root节点染色为黑色 */
    ngx_rbt_black(*root);
}

/**
  * @brief   将节点插入到红黑树中,并没有判断是否满足红黑树的特质
  * @note    None
  * @param   temp: 顶节点; node: 待插入节点; sentinel: 哨兵节点;
  * @retval  None
  **/
void
ngx_rbtree_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t  **p;

    for ( ;; ) {
        /* 判断node节点键值与temp节点键值的大小，以决定node插入到temp节点的左子树还是右子树 */
        p = (node->key < temp->key) ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }
    /* 初始化node节点，并着色为红色 */
    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


void
ngx_rbtree_insert_timer_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t  **p;

    for ( ;; ) {

        /*
         * Timer values
         * 1) are spread in small range, usually several minutes,
         * 2) and overflow each 49 days, if milliseconds are stored in 32 bits.
         * The comparison takes into account that overflow.
         */

        /*  node->key < temp->key */

        p = ((ngx_rbtree_key_int_t) (node->key - temp->key) < 0)
            ? &temp->left : &temp->right;

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

/**
  * @brief   红黑树的删除节点
  * @note    None
  * @param   None
  * @retval  None
  **/
void
ngx_rbtree_delete(ngx_rbtree_t *tree, ngx_rbtree_node_t *node)
{
    ngx_uint_t           red;
    ngx_rbtree_node_t  **root, *sentinel, *subst, *temp, *w;

    /* a binary tree delete */

    root = &tree->root;
    sentinel = tree->sentinel;
    /* 下面是获取temp节点值，temp保存的节点是准备替换节点node;
     * subst是保存要被替换的节点的后继节点；
     */
    if (node->left == sentinel) {
        /* case1：若node节点没有左孩子（这里包含了存在或不存在右孩子的情况）
              A <-node           A <- subst
             /  \       --->    /  \
            nil  B           nil    B <-temp
         */
        temp = node->right;
        subst = node;

    } else if (node->right == sentinel) {
        /* case2：node节点存在左孩子，但是不存在右孩子
              A <-node           A <-subst
             /  \       --->    /  \
            B   nil     temp-> B   nil
         */
        temp = node->left;
        subst = node;

    } else {
        /* case3：node节点既有左孩子，又有右孩子
              A <-node           A
             /  \     delete A  /  \
            B    C    -------> B    C
           /    / \           /    / \
          G    D   E         G    D   E
         /    /     \            /     \
        nil   F     nil subst-> F      nil
             / \               / \
           nil nil           nil nil <-temp
         */
        subst = ngx_rbtree_min(node->right, sentinel);
        temp = subst->right;
    }
    /* 若被替换的节点subst是根节点，则temp直接替换subst称为根节点 */
    if (subst == *root) {
        *root = temp;
        ngx_rbt_black(temp);

        /* DEBUG stuff */
        node->left = NULL;
        node->right = NULL;
        node->parent = NULL;
        node->key = 0;

        return;
    }
    /* red记录subst节点的颜色 */
    red = ngx_rbt_is_red(subst);
    /* temp节点替换subst 节点 */
    if (subst == subst->parent->left) {
        subst->parent->left = temp;

    } else {
        subst->parent->right = temp;
    }
    /* 根据subst是否为node节点进行处理 */
    if (subst == node) {

        temp->parent = subst->parent;

    } else {
        /* 设置subst指向父节点 */
        if (subst->parent == node) {
            temp->parent = subst;

        } else {
            temp->parent = subst->parent;
        }
        /* 复制node节点属性 */
        subst->left = node->left;
        subst->right = node->right;
        subst->parent = node->parent;
        ngx_rbt_copy_color(subst, node);

        if (node == *root) {
            /* 当为case3情景时, node节点既有左孩子，又有右孩子;
                  A <-node           A                   F <-subst
                 /  \     delete A  /  \               /  \
                B    C    -------> B    C   ------->  B    C
               /    / \           /    / \           /    /  \
              G    D   E         G    D   E         G    D    E
             /    /     \            /     \
            nil   F     nil subst-> F      nil
                 / \               / \
               nil nil           nil nil <-temp
             */
            *root = subst;

        } else {
            /* 设置源node节点的父节点指向subst */
            if (node == node->parent->left) {
                node->parent->left = subst;
            } else {
                node->parent->right = subst;
            }
        }
        /* 当为case3情景时, node节点既有左孩子，又有右孩子;
              A                          A                 A
             /  \            delete C  /  \               /  \
            B    C  <-node   -------> B    C   ------->  B    F <-subst
           /    / \                  /    / \           /    /  \
          G    D   E                 G    D   E         G    D    E
         /    /     \                    /     \
        nil   F     nil          subst-> F      nil
             / \                        / \
           nil nil                     nil nil <-temp
         */
        if (subst->left != sentinel) {
            subst->left->parent = subst;
        }

        if (subst->right != sentinel) {
            subst->right->parent = subst;
        }
    }

    /* DEBUG stuff */
    node->left = NULL;
    node->right = NULL;
    node->parent = NULL;
    node->key = 0;
    /* 如果被删除的节点y是红色的，则删除后不会破坏红黑树的性质 */
    if (red) {
        return;
    }
    /* 下面开始是调整红黑树的性质 */
    /* a delete fixup */
    /* 根据temp节点进行处理 ，若temp不是根节点,且temp为黑色 */
    while (temp != *root && ngx_rbt_is_black(temp)) {
        /* 若temp是其父亲节点的左孩子 */
        if (temp == temp->parent->left) {
            w = temp->parent->right; /* w为temp的兄弟节点 */
            /* case A：temp兄弟节点为红色 */
            /* 解决办法：
             * 1、改变w节点及temp父亲节点的颜色；
             * 2、对temp父亲节的做一次左旋转，此时，temp的兄弟节点是旋转之前w的某个子节点，该子节点颜色为黑色；
             * 3、此时，case A已经转换为case B、case C 或 case D；
             */
            if (ngx_rbt_is_red(w)) {
                ngx_rbt_black(w);
                ngx_rbt_red(temp->parent);
                ngx_rbtree_left_rotate(root, sentinel, temp->parent);
                w = temp->parent->right;
            }
            /* case B：temp的兄弟节点w是黑色，且w的两个子节点都是黑色 */
            /* 解决办法：
             * 1、改变w节点的颜色；
             * 2、把temp的父亲节点作为新的temp节点；
             */
            if (ngx_rbt_is_black(w->left) && ngx_rbt_is_black(w->right)) {
                ngx_rbt_red(w);
                temp = temp->parent;

            } else {
                /* case C：temp的兄弟节点是黑色，且w的左孩子是红色，右孩子是黑色 */
                /* 解决办法：
                 * 1、将改变w及其左孩子的颜色；
                 * 2、对w节点进行一次右旋转；
                 * 3、此时，temp新的兄弟节点w有着一个红色右孩子的黑色节点，转为case D；
                 */
                if (ngx_rbt_is_black(w->right)) {
                    ngx_rbt_black(w->left);
                    ngx_rbt_red(w);
                    ngx_rbtree_right_rotate(root, sentinel, w);
                    w = temp->parent->right;
                }
                /* case D：temp的兄弟节点w为黑色，且w的右孩子为红色 */
                /* 解决办法：
                 * 1、将w节点设置为temp父亲节点的颜色，temp父亲节点设置为黑色；
                 * 2、w的右孩子设置为黑色；
                 * 3、对temp的父亲节点做一次左旋转；
                 * 4、最后把根节点root设置为temp节点；*/
                ngx_rbt_copy_color(w, temp->parent);
                ngx_rbt_black(temp->parent);
                ngx_rbt_black(w->right);
                ngx_rbtree_left_rotate(root, sentinel, temp->parent);
                temp = *root;
            }

        } else { /* 这里针对的是temp节点为其父亲节点的左孩子的情况 */
            w = temp->parent->left;

            if (ngx_rbt_is_red(w)) {
                ngx_rbt_black(w);
                ngx_rbt_red(temp->parent);
                ngx_rbtree_right_rotate(root, sentinel, temp->parent);
                w = temp->parent->left;
            }

            if (ngx_rbt_is_black(w->left) && ngx_rbt_is_black(w->right)) {
                ngx_rbt_red(w);
                temp = temp->parent;

            } else {
                if (ngx_rbt_is_black(w->left)) {
                    ngx_rbt_black(w->right);
                    ngx_rbt_red(w);
                    ngx_rbtree_left_rotate(root, sentinel, w);
                    w = temp->parent->left;
                }

                ngx_rbt_copy_color(w, temp->parent);
                ngx_rbt_black(temp->parent);
                ngx_rbt_black(w->left);
                ngx_rbtree_right_rotate(root, sentinel, temp->parent);
                temp = *root;
            }
        }
    }

    ngx_rbt_black(temp);
}

/**
  * @brief   左旋转操作(逆时针旋转)
  * @note    None
  * @param   root: 根节点; sentinel: 哨兵节点; node: 源平衡子树的顶节点
  * @retval  None
  * -------------------------------------演示样例-----------------------------------------------
  *        *root                                            *root
  *       /    \                                           /     \
  *     ...    ...                                       ...     ...
  *              \                                                 \
  *             A(node)  源平衡子树的顶节点                           B(temp) 目的平衡子树的顶节点
  *         /          \                                         /    \
  *  D(xxx)           B(yyy)           ----->                  A       C
  *                    /    \                                /   \      \
  *                  E(zzz)  C                              D     E      N(新插入的节点)
  *                           \
  *                            N(新插入的节点)
  * -------------------------------------演示样例-----------------------------------------------
  **/
static ngx_inline void
ngx_rbtree_left_rotate(ngx_rbtree_node_t **root, ngx_rbtree_node_t *sentinel,
    ngx_rbtree_node_t *node)
{
    ngx_rbtree_node_t  *temp;

    temp = node->right;// 左旋后,目的平衡子树(新的平衡子树)的顶节点(演示样例中的B节点)
    node->right = temp->left; // A节点的右子树更新为E节点

    if (temp->left != sentinel) {
        temp->left->parent = node; // E节点的父节点更新为A节点
    }

    temp->parent = node->parent;//B节点的父节点更新为源平衡子树的A节点的父节点

    if (node == *root) { // 如果root指向的地址为A节点的地址,则变更root节点的指向地址为目的平衡子树的顶节点(B)
        *root = temp;

    } else if (node == node->parent->left) { // 如果源平衡子树的顶节点(A)为左节点
        node->parent->left = temp;

    } else { // 如果源平衡子树的顶节点(A)为右节点
        node->parent->right = temp;
    }

    temp->left = node; // 目的平衡子树的顶节点(B)的左子树更新为 源平衡子树的顶节点(A)
    node->parent = temp; // 源平衡子树的顶节点(A)的父节点更新为 目的平衡子树的顶节点(B)
}

/**
  * @brief   右旋转操作(顺时针旋转)
  * @note    None
  * @param   root: 根节点; sentinel: 哨兵节点; node: 源平衡子树的顶节点
  * @retval  None
  * -------------------------------------演示样例-----------------------------------------------
  *                 *root                                            *root
  *                /    \                                           /     \
  *              ...    ...                                       ...     ...
  *              /                                                /
  *             A(node)  源平衡子树的顶节点                         B(temp) 目的平衡子树的顶节点
  *            /     \                                         /    \
  *          B(yyy)   D                  ----->               C      A
  *          /    \                                          /      / \
  *         C      E(zzz)                                   N      E   D
  *        /
  *       N(新插入的节点)
  * -------------------------------------演示样例-----------------------------------------------
  **/
static ngx_inline void
ngx_rbtree_right_rotate(ngx_rbtree_node_t **root, ngx_rbtree_node_t *sentinel,
    ngx_rbtree_node_t *node)
{
    ngx_rbtree_node_t  *temp;

    temp = node->left; // 右旋后,目的平衡子树(新的平衡子树)的顶节点(演示样例中的B节点)
    node->left = temp->right; // A节点的左子树更新为E节点

    if (temp->right != sentinel) {
        temp->right->parent = node; // E节点的父节点更新为A节点
    }

    temp->parent = node->parent; // B节点的父节点更新为源平衡子树的A节点的父节点

    if (node == *root) { // 如果root指向的地址为A节点的地址,则变更root节点的指向地址为目的平衡子树的顶节点(B)
        *root = temp;

    } else if (node == node->parent->right) { // 如果源平衡子树的顶节点(A)为右节点
        node->parent->right = temp;

    } else { // 如果源平衡子树的顶节点(A)为左节点
        node->parent->left = temp;
    }

    temp->right = node; // 目的平衡子树的顶节点(B)的右子树更新为 源平衡子树的顶节点(A)
    node->parent = temp; // 源平衡子树的顶节点(A)的父节点更新为 目的平衡子树的顶节点(B)
}

/**
  * @brief   查看node节点的下一个节点
  * @note    None
  * @param   tree: 红黑树本尊; node: 本节点;
  * @retval  node节点的下一个节点
  **/
ngx_rbtree_node_t *
ngx_rbtree_next(ngx_rbtree_t *tree, ngx_rbtree_node_t *node)
{
    ngx_rbtree_node_t  *root, *sentinel, *parent;

    sentinel = tree->sentinel;

    if (node->right != sentinel) { 
        /* 如下所示：node的下一个节点是G
               R <- tree->root
             /  \
           ...  ...
                  A <-node
               /    \
              B      C
             /      / \
            D      E   F
                  /
                 G <-@retval
         */
        return ngx_rbtree_min(node->right, sentinel);
    }
    // node节点没有右节点
    root = tree->root;

    for ( ;; ) { // 二叉搜索树遍历
        parent = node->parent;

        if (node == root) { // node节点没有右节点& node为root节点, 则没有下一个节点
            return NULL;
        }

        if (node == parent->left) { // node节点没有右节点& node不为root节点, 则返回node节点的父节点
            return parent;
        }

        node = parent;
    }
}
