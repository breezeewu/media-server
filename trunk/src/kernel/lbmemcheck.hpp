#pragma once
// printf
#include <stdio.h>
// mutex
#include <pthread.h>
#include <stdlib.h>
// strlen
#include <string.h>
// lblist_ctx
#include "lblist.h"
#define LAZY_MEM_CHECK
// memory block struct
typedef struct
{
    void*   pblock_ptr;
    int     nblock_size;
    char*   pfile_name;
    char*   pfunc_name;
    int     nfile_line;
} lbmem_blk;

// memory check context
typedef struct
{
    lblist_ctx*         plist;
#ifdef ENABLE_PTHREAD_MUTEX_LOCK
    pthread_mutex_t*    pmutex;
#endif
    __int64_t           lltotal_mem_size;
    
} lbmemcheck_ctx;

extern lbmemcheck_ctx* g_pmcc;


lbmemcheck_ctx* lbmemcheck_initialize();

void lbmemcheck_finialize(lbmemcheck_ctx** ppmcc);

int lbmemcheck_add_block(lbmemcheck_ctx* pmcc, void* ptr, int size, const char* pfile_name, const int nfile_line, const char* pfunc_name);

int lbmemcheck_remove_block(lbmemcheck_ctx* pmcc, void* ptr);

#ifdef __cplusplus
template<class T>
inline T* lbmem_new(int count, const char* pfile_name, const int nfile_line, const char* pfunc_name);
template<class T>
inline void lbmem_delete(T* ptr, int isarray);
#endif
#if defined(LAZY_MEM_CHECK)
#define LB_NEW(T, count)                        lbmem_new<T>(count, __FILE__, __LINE__, __FUNCTION__)
#define LB_DEL(ptr)                             if(ptr) {delete ptr; lbmemcheck_remove_block(g_pmcc, ptr); ptr = NULL;}
#define LB_DEL_ARR(ptr)                         if(ptr) { delete[] ptr; lbmemcheck_remove_block(g_pmcc, ptr); ptr = NULL;}//lbmem_delete<T>(ptr, 1);
#define LB_ADD_MEM(ptr, size)                   lbmemcheck_add_block(g_pmcc, (void*)ptr, (int)size, __FILE__, __LINE__, __FUNCTION__)
#define LB_RM_MEM(ptr)                          lbmemcheck_remove_block(g_pmcc, (void*)ptr);
#else
#define LB_NEW(T, count)                    count > 1 ? new T[count] : new T
//#define NEW T(...)         new T(__AV_ARGS__);
//#define LB_NEW(T)            count > 1 ? new T[count] : new T
#define LB_DEL(ptr)                             if(ptr) {delete ptr; ptr = NULL;}
#define LB_DEL_ARR(ptr)                         if(ptr) { delete[] ptr; ptr = NULL;}
#define LB_ADD_MEM(ptr, size)
#define LB_RM_MEM(ptr)
#endif


void* lbmem_malloc(size_t size, const char* pfile_name, const int nfile_line, const char* pfunc_name);

void* lbmem_calloc(size_t count, size_t block_size, const char* pfile_name, const int nfile_line, const char* pfunc_name);

void lbmem_free(void* ptr);

#if defined(LAZY_MEM_CHECK)
//#define malloc(size)                            lbmem_malloc(size, __FILE__, __LINE__, __FUNCTION__)
//#define calloc(count, blk_size)                 lbmem_calloc(count, blk_size, __FILE__, __LINE__, __FUNCTION__)
//#define free(ptr)                               lbmem_free(ptr)
#define LB_MALLOC(size)                         lbmem_malloc(size, __FILE__, __LINE__, __FUNCTION__)
#define LB_CALLOC(count, blk_size)              lbmem_calloc(count, blk_size, __FILE__, __LINE__, __FUNCTION__)
#define LB_FREE(ptr)                            lbmem_free(ptr)
#else
#define LB_MALLOC(size)                     malloc(size)
#define LB_CALLOC(count, blk_size)          calloc(count, blk_size)
#define LB_FREE(ptr)                        free(ptr)
#endif
