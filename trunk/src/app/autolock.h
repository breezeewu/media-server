/****************************************************************************************************************
 * filename     autolock.h
 * describe     auto mutex lock implement
 * author       Created by dawson on 2019/04/18
 * Copyright    ©2007 - 2029 Sunvally. All Rights Reserved.
 ***************************************************************************************************************/

#ifndef _AUTO_LOCK_H_
#define _AUTO_LOCK_H_
#ifdef WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define CRITICAL_SECTION                        pthread_mutex_t
#define InitializeCriticalSection(px)            pthread_mutex_init(px, PTHREAD_MUTEX_RECURSIVE)
#define DeleteCriticalSection(px)                pthread_mutex_destroy(px)
#define EnterCriticalSection(px)                pthread_mutex_lock(px)
#define LeaveCriticalSection(px)                pthread_mutex_unlock(px)
#endif
class CAutoLock;
// auto lock critical section
class CCriSec
{
public:
    friend CAutoLock;
    CCriSec()
    {
        // constructor, create and init mutex
        m_pmutex = new CRITICAL_SECTION();
        int ret = 0;
        pthread_mutexattr_t attr;
        if(( ret = pthread_mutexattr_init(&attr)) != 0){
            fprintf(stderr, "create mutex attribute error. msg:%s", strerror(ret));
            return;
            //exit(1);
        }
        // 将c互斥锁设置为PTHREAD_MUTEX_RECURSIVE，统一线程可以多次进入临界区
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(m_pmutex, &attr);
        //InitializeCriticalSection(m_pmutex);
    }
    
    ~CCriSec()
    {
        // deconstructor, destroy mutex and delete it
        if(m_pmutex)
        {
            DeleteCriticalSection(m_pmutex);
            delete m_pmutex;
            m_pmutex = NULL;
        }
    }
    // lock, enter critical section
    void lock()
    {
        if(m_pmutex)
        {
            EnterCriticalSection(m_pmutex);
        }
    }
    
    // unlock, leave critical section
    void unlock()
    {
        if(m_pmutex)
        {
            LeaveCriticalSection(m_pmutex);
        }
    }
    
private:
    CRITICAL_SECTION*  m_pmutex;
};
//#define lbmutex_lock CRITICAL_SECTION
class CAutoLock
 {
 public:
     // auto lock constructor, initialize CCriSec
     CAutoLock(CCriSec& crisec)
     {
         m_pmutex = crisec.m_pmutex;
         lock();
     }
     // auto lock constructor, initialize with mutex
     CAutoLock(CRITICAL_SECTION*   pmutex)
     {
         m_pmutex = pmutex;
         lock();
     }
     
     // auto lock deconstructor, unlock before destroy it
     ~CAutoLock()
     {
         unlock();
     }
     
     // lockl mutex, enter critical section
     void lock()
     {
         if(m_pmutex)
         {
             EnterCriticalSection(m_pmutex);
         }
     }
     
     // unlock mutex, leave critical section
     void unlock()
     {
         if(m_pmutex)
         {
             LeaveCriticalSection(m_pmutex);
         }
     }
 
 private:
     // mutex for lock
     CRITICAL_SECTION*   m_pmutex;
 };

// add end
#endif /* autolock.h */
