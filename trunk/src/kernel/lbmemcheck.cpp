#include <lbmemcheck.hpp>
#include <srs_kernel_log.hpp>
#ifndef lbtrace
#define lbtrace srs_trace
#endif
#ifndef lberror
#define lberror srs_error
#endif

lbmemcheck_ctx* g_pmcc = NULL;

lbmemcheck_ctx* lbmemcheck_initialize()
{
    lbmemcheck_ctx* pmcc = (lbmemcheck_ctx*)::calloc(1, sizeof(lbmemcheck_ctx));
    pmcc->plist = lblist_create_context(__INT32_MAX__);
#ifdef ENABLE_PTHREAD_MUTEX_LOCK
    pmcc->pmutex = (pthread_mutex_t*)::malloc(sizeof(pthread_mutex_t));
    memset(pmcc->pmutex, 0, sizeof(pthread_mutex_t));
    pthread_mutexattr_t attr;
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(pmcc->plist->pmutex, &attr);
#endif
    lbtrace("pmcc:%p = lbmemcheck_initialize\n", pmcc);
    return pmcc;
}

void lbmemcheck_finialize(lbmemcheck_ctx** ppmcc)
{
    lbtrace("lbmemcheck_finialize, ppmcc:%p\n", ppmcc);
    if(ppmcc && *ppmcc)
    {
        lbmemcheck_ctx* pmcc = *ppmcc;
        lbtrace("lbmemcheck_finialize, pmcc:%p\n", pmcc);
    #ifdef ENABLE_PTHREAD_MUTEX_LOCK
        pthread_mutex_lock(pmcc->pmutex);
    #endif
        lbmem_blk* pmb = NULL;
        lblist_node* pnode = NULL;
        lbtrace("%d block of memory maybe leak\n", lblist_size(pmcc->plist));
        while(lblist_size(pmcc->plist) > 0)//(pmb = (lbmem_blk*)lblist_pop(pmcc->plist))
        {
            pmb = (lbmem_blk*)lblist_pop(pmcc->plist);
            lbtrace("leak memory [%s:%d %s] memory ptr:%p, size:%d\n", pmb->pfile_name, pmb->nfile_line, pmb->pfunc_name, pmb->pblock_ptr, pmb->nblock_size);
            if(pmb->pfile_name)
            {
                ::free(pmb->pfile_name);
                pmb->pfile_name = NULL;
            }
            if(pmb->pfunc_name)
            {
                ::free(pmb->pfunc_name);
                pmb->pfunc_name = NULL;
            }
            ::free(pmb);
        }
        lblist_close_context(&pmcc->plist);
#ifdef ENABLE_PTHREAD_MUTEX_LOCK
        pthread_mutex_unlock(pmcc->pmutex);
        pthread_mutex_destroy(pmcc->pmutex);
        free(pmcc->pmutex);
#endif
        ::free(pmcc);
        *ppmcc = pmcc = NULL;
    }
}

int lbmemcheck_add_block(lbmemcheck_ctx* pmcc, void* ptr, int size, const char* pfile_name, const int nfile_line, const char* pfunc_name)
{
    if(!pmcc || !ptr)
    {
        return -1;
    }

    //lbtrace("new T(pmcc:%p, ptr:%p, size:%d, pfile_name:%s, nfile_line:%d, pfunc_name:%s)\n", pmcc, ptr, size, pfile_name, nfile_line, pfunc_name);
    assert(pmcc);
    assert(ptr);
    lbmem_blk* pmb = (lbmem_blk*)::calloc(1, sizeof(lbmem_blk));
    if(NULL == pmb)
    {
        lberror("out of memory calloc lbmem_blk failed!\n");
        assert(0);
        return -1;
    }
    pmb->pblock_ptr = ptr;
    pmb->nblock_size = size;
    int len = strlen(pfile_name) + 1;
    pmb->pfile_name = (char*)::calloc(len, sizeof(char));
    if(NULL == pmb->pfile_name)
    {
        lberror("out of memory calloc pfile_name %s failed!\n", pfile_name);
        assert(0);
        return -1;
    }
    memcpy(pmb->pfile_name, pfile_name, len);
    pmb->nfile_line = nfile_line;
    len = strlen(pfunc_name);
    pmb->pfunc_name = (char*)::calloc(len, sizeof(char));
    if(NULL == pmb->pfunc_name)
    {
        lberror("out of memory calloc pfunc_name %s failed!\n", pfunc_name);
        assert(0);
        return -1;
    }
    memcpy(pmb->pfunc_name, pfunc_name, len);
    return lblist_push(pmcc->plist, pmb);
}

int lbmemcheck_remove_block(lbmemcheck_ctx* pmcc, void* ptr)
{
    /*assert(pmcc);
    assert(ptr);*/
    //lbtrace("pmcc:%p, delete ptr:%p", pmcc, ptr);
    if(!pmcc || !ptr || !pmcc->plist)
    {
        return -1;
    }
    lbmem_blk* pmb = NULL;
    for(lblist_node* pnode = pmcc->plist->head; pnode != NULL; pnode = pnode->pnext)
    {
        pmb = (lbmem_blk*)pnode->pitem;
        //LBLIST_ENUM_BEGIN(lbmem_blk, pmcc->plist, pmb);
        if(pmb && ptr == pmb->pblock_ptr)
        {
            if(pmb->pfile_name)
            {
                ::free(pmb->pfile_name);
                pmb->pfile_name = NULL;
            }
            if(pmb->pfunc_name)
            {
                ::free(pmb->pfunc_name);
                pmb->pfunc_name = NULL;
            }
            ::free(pmb);
            lblist_remove_node(pmcc->plist, pnode);
            return 0;
        }
    }
    //LBLIST_ENUM_END()
    lberror("Invalid ptr:%p, not foud from alloc list!\n", ptr);
    return -1;
}

#ifdef __cplusplus
template<class T>
inline T* lbmem_new(int count, const char* pfile_name, const int nfile_line, const char* pfunc_name)
{
    T* ptr = NULL;
    if(count > 1)
    {
        ptr = new T[count];
    }
    else
    {
        ptr = new T();
    }
    
    lbmemcheck_add_block(g_pmcc, ptr, sizeof(T) * count, pfile_name, nfile_line, pfunc_name);

    return ptr;
}
template<class T>
inline void lbmem_delete(T* ptr, int isarray)
{
    if(isarray)
    {
        delete[] ptr;
    }
    else
    {
        delete ptr;
    }

    lbmemcheck_remove_block(g_pmcc, ptr);
}
#endif
