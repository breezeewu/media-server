/****************************************************************************************************************
 * filename     sv_thread.h
 * describe     thread can be simple create by inherit this class
 * author       Created by dawson on 2019/04/19
 * Copyright    ©2007 - 2029 Sunvally. All Rights Reserved.
 ***************************************************************************************************************/

#ifndef _SV_THREAD_H_
#define _SV_THREAD_H_
#include <stdint.h>
#include <stdio.h>
#include <pthread.h>
#define THREAD_RETURN void*
typedef THREAD_RETURN (*routine_pt)(void*);
class CLazyThread
{
public:
    CLazyThread()
    {
        m_Tid       = 0;
        m_bRun      = 0;
        m_nPriority = 0;
        m_bSystem   = 0;
    }

    ~CLazyThread()
    {
        Stop();
    }

    virtual THREAD_RETURN ThreadProc() = 0;

    virtual int Run(int priority = 0, int bsystem = 0)
    {
        int ret = 0;
        if(m_bRun)
        {
            return ret;
        }

        if(0 == m_Tid)
        {
            ret = Create(priority, bsystem);
        }

        m_bRun = 1;
        return ret;
    }

    virtual int Stop()
    { 
        
        if(m_bRun)
        {
            m_bRun = 0;
            //pthread_detach(m_Tid);
            pthread_join(m_Tid, NULL);
        }

        memset(&m_Tid, 0, sizeof(m_Tid));
        return 0;
    }

    bool IsAlive()
    {
        return m_bRun;
    }

private:
    int Create(int priority = 0, int bsystem = 0)
    {
        int res = 0;
        if(0 == m_Tid)
        {
            pthread_attr_t tattr;
            m_bSystem = bsystem;
            m_nPriority = priority;

            res = pthread_attr_init(&tattr);
            
            if (0 != res) {
                /* error */
                //CloseDebug("pthread_attr_init error\n");
                printf("res:%d = pthread_attr_init(&tattr) faild\n", res);
                return res;
            }
            res = pthread_attr_setstacksize(&tattr, 64*1024);
            if (0 != res) {
                /* error */
                //CloseDebug("pthread_attr_init error\n");
                printf("res:%d = pthread_attr_setstacksize(&tattr, 64*1024) faild\n", res);
                return res;
            }
            // 设置为内核级的线程，以获取较高的响应速度
            if(bsystem)
            {
                res = pthread_attr_setscope(&tattr, PTHREAD_SCOPE_SYSTEM);
                //pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
                printf("res:%d = pthread_attr_setscope(&tattr, PTHREAD_SCOPE_SYSTEM)\n", res);
            }

            res = pthread_create(&m_Tid, &tattr, InitialThreadProc, this);
            if(0 != res)
            {
                printf("res:%d = pthread_create(&m_Tid, &tattr, InitialThreadProc, this) failed\n", res);
                return res;
            }

            res = pthread_attr_destroy(&tattr);
            if(0 != res)
            {
                printf("res:%d = pthread_attr_destroy(&tattr) failed\n", res);
                return res;
            }
            return res;
        }
        else
        {
            printf("thread already had been create!, m_Tid:%lu\n", m_Tid);
        }

        return res;
    }

    static THREAD_RETURN InitialThreadProc(void* arg)
    {
        THREAD_RETURN ret = NULL;
        CLazyThread* pThread = static_cast<CLazyThread*>(arg);
        if(pThread)
        {
            pThread->m_bRun = 1;
            ret = pThread->ThreadProc();
            if(pThread->m_bRun)
            {
                pthread_detach(pThread->m_Tid);
            }
        }
        pThread->m_bRun = 0;
        return ret;
    }

protected:
    int		    	m_bRun;
    int         	m_nPriority;
    int         	m_bSystem;
	pthread_t	m_Tid;
};

template<class T>
class CLazyThreadEx:public CLazyThread
{
public:
	CLazyThreadEx()
	{
		m_powner		= NULL;
		m_pcallback_proc	= NULL;
	}

	~CLazyThreadEx()
	{
	}

	typedef int (T::*callback)();

	virtual int init_class_func(T* powner, callback class_func)
	{
		m_powner = powner;
		m_pcallback_proc = class_func;

		return 0;
	}

	virtual THREAD_RETURN ThreadProc()
	{
		printf("CLazyThreadEx::ThreadProc begin");
		if(m_pcallback_proc && m_powner)
		{
			//printf("before ret = (m_powner:%p->*m_pcallback_proc:%p)()\n", m_powner, m_pcallback_proc);
			int ret = (m_powner->*m_pcallback_proc)();
			//printf("ret:%d = (m_powner->*m_pcallback_proc)()\n", ret);
		}

		return NULL;
	}

protected:
	callback		m_pcallback_proc;
	T*				m_powner;
};
#endif /* sv_thread.h */
