/*
 * list.h
 *
 * Copyright (c) 2019 sunvalley
 * Copyright (c) 2019 dawson <dawson.wu@sunvalley.com.cn>
 */

#ifndef _LIST_H_
#define _LIST_H_
// pthread_mutex_t
#include <pthread.h>
// assert
#include <assert.h>
// malloc calloc
#include <stdlib.h>
// memset
#include <string.h>
//#define ENABLE_PTHREAD_MUTEX_LOCK
#define LBLIST_ENUM_BEGIN(T, plist, pit)    for(lblist_node* pnode = plist->head; pnode != NULL; pnode = pnode->pnext) {\
                                                pit = (T*)pnode->pitem;

#define LBLIST_ENUM_END()               }
typedef struct lblist_node
{
    struct lblist_node* pprev;
    struct lblist_node* pnext;
    void* pitem;
} node;

typedef struct lblist_context
{
    struct lblist_node* head;
    struct lblist_node* tail;
    int count;
    int max_num;
#ifdef ENABLE_PTHREAD_MUTEX_LOCK
    pthread_mutex_t* pmutex;
#endif
} lblist_ctx;

static lblist_ctx* lblist_create_context(int max_num)
{
    lblist_ctx* plist = (lblist_ctx*)malloc(sizeof(lblist_ctx));
    memset(plist, 0, sizeof(lblist_ctx));
#ifdef ENABLE_PTHREAD_MUTEX_LOCK
    plist->pmutex = (pthread_mutex_t*)calloc(1, sizeof(pthread_mutex_t));
    pthread_mutexattr_t attr;
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(plist->pmutex, &attr);
#endif
    plist->max_num = max_num;

    return plist;
}

static void lblist_close_context(lblist_ctx** pplistctx)
{
    if(pplistctx && *pplistctx)
    {
        lblist_ctx* plist = *pplistctx;
#ifdef ENABLE_PTHREAD_MUTEX_LOCK
        pthread_mutex_destroy(plist->pmutex);
        free(plist->pmutex);
#endif
        free(plist);
        *pplistctx = NULL;
    }
}

static int lblist_push(lblist_ctx*  plist, void* pitem)
{
    if(NULL == plist)
    {
        assert(0);
        return -1;
    }
#ifdef ENABLE_PTHREAD_MUTEX_LOCK
    pthread_mutex_lock(plist->pmutex);
#endif
    struct lblist_node* pnode = (struct lblist_node*)malloc(sizeof(struct lblist_node));
    pnode->pitem = pitem;
    if(plist->tail)
    {
        plist->tail->pnext = pnode;
        pnode->pprev = plist->tail;
        pnode->pnext = NULL;
        plist->tail = pnode;
        plist->count++;
    }
    else
    {
        plist->head = pnode;
        plist->tail = pnode;
        pnode->pprev = NULL;
        pnode->pnext = NULL;
        plist->count++;
    }
    assert(plist->head);
#ifdef ENABLE_PTHREAD_MUTEX_LOCK
    pthread_mutex_unlock(plist->pmutex);
#endif
    return 0;
}

static void* lblist_pop(lblist_ctx*  plist)
{
#ifdef ENABLE_PTHREAD_MUTEX_LOCK
    pthread_mutex_lock(plist->pmutex);
#endif
    if(NULL == plist && plist->count <= 0)
    {
#ifdef ENABLE_PTHREAD_MUTEX_LOCK
        pthread_mutex_unlock(plist->pmutex);
#endif
        return NULL;
    }
    
    assert(plist->head);
    struct lblist_node* pnode = plist->head;
    plist->head = pnode->pnext;
    plist->count--;
    void* pitem = pnode->pitem;
    free(pnode);
    if(NULL == plist->head)
    {
        plist->tail = NULL;
        assert(0 == plist->count);
    }
    //assert(plist->head);
#ifdef ENABLE_PTHREAD_MUTEX_LOCK
    pthread_mutex_unlock(plist->pmutex);
#endif
    return pitem;
}

static void* lblist_remove_node(lblist_ctx*  plist, lblist_node* pnode)
{
    if(NULL == pnode)
    {
        return 0;
    }
#ifdef ENABLE_PTHREAD_MUTEX_LOCK
    pthread_mutex_lock(plist->pmutex);
#endif
    lblist_node* pprev = pnode->pprev;
    lblist_node* pnext = pnode->pnext;
    if(pprev)
    {
        pprev->pnext = pnext;
    }
    else
    {
        // remove head node, next node change to head node
        plist->head = pnext;
        // assert head node's prev node is NULL
        plist->head->pprev = NULL;
    }
    
    if(pnext)
    {
        pnext->pprev = pprev;
    }
    else
    {
        // remove tail node, prev node change to tail node
        plist->tail = pprev;
        // assert tail node's next node is NULL
        plist->tail->pnext = NULL;
    }
    void* pitem = pnode->pitem;
    free(pnode);
    assert(plist->count >= 1);
    plist->count--;
#ifdef ENABLE_PTHREAD_MUTEX_LOCK
    pthread_mutex_unlock(plist->pmutex);
#endif
    return pitem;
}

static void* lblist_front(lblist_ctx*  plist)
{
#ifdef ENABLE_PTHREAD_MUTEX_LOCK
    pthread_mutex_lock(plist->pmutex);
#endif
    if(NULL == plist && plist->count <= 0)
    {
#ifdef ENABLE_PTHREAD_MUTEX_LOCK
        pthread_mutex_unlock(plist->pmutex);
#endif
        return NULL;
    }
    assert(plist->head);
    void* pitem = plist->head->pitem;
#ifdef ENABLE_PTHREAD_MUTEX_LOCK
    pthread_mutex_unlock(plist->pmutex);
#endif
    return pitem;
}
static int lblist_size(lblist_ctx*  plist)
{
    return plist ? plist->count : 0;
}
#endif
