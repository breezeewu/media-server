//printf,sprintf
#include <stdio.h>
//system
#include <stdlib.h>
//strlen
#include <string.h>
//sleep
#include <unistd.h>
//signal
#include <signal.h>
 
/**
 进程名可以不等于执行文件名。
 这时要传递另外一个参数。
不考虑进程名是pts这种故意捣乱的情况。
通过ps，检查输出结果是否是进程名。
参考字串如下：
　9548 pts/19   00:00:25 gh_main
 */
int   process_check_state(const char* psProcessName)
{
    int state = 0;
    
    FILE *fstream=NULL;    
    char buff[1024] = {0};
 
    //用空格，是去掉类似dah_main的噪声
    sprintf(buff, "ps -A | grep \" %s\"", psProcessName); 
    if (NULL==(fstream=popen(buff, "r")))
    {
        return -1;
    }
 
    while (NULL != fgets(buff, sizeof(buff), fstream))
    {
        if (strlen(buff) <= 0)
        {
            break;
        }
        
        char* psHead = strstr(buff, psProcessName);
        if (psHead == NULL)
        {
            continue;
        }
 
        int pos = strlen(psHead)-1;
        if (psHead[pos] == '\n')
        {
            psHead[pos] = 0;
        }
 
        //GH_LOG_INFO("|||%s|||", psHead);
        if (!strcmp(psHead, psProcessName))
        {
            state = 1;
            //printf("psHead:%s, psProcessName:%s\n", psHead, psProcessName);
            break;
        }
    }
 
    pclose(fstream);
    
    return state;
}

int g_brunning = 0;
void sig_stop(int signo)
{
    g_brunning = 0;
    printf("sig_stop(%d)", signo);
}

int main(int argc, char** args)
{
    if(argc < 3)
    {
	    printf("please input process name you want to watch and run shell script!");
	    return -1;
    }
    g_brunning = 1;
    signal(SIGINT,  sig_stop);
	signal(SIGQUIT, sig_stop);
	signal(SIGTERM, sig_stop);
	//signal(SIGPIPE, sig_continue);

    char exec_cmd[256] = {0};
    sprintf(exec_cmd, "sh %s", args[2]);
    while(g_brunning)
    {
        if(process_check_state(args[1]) == 0)
        {
            printf("%s have die, restart it!", args[1]);
            system(exec_cmd);
            sleep(1);
        }
        else
        {
            sleep(2);
        }
        
    }
    /*int ret = process_check_state(args[1]);
    if(ret == 0)
    {
	    printf("process %s alive!", args[1]);
    }
    else
    {
	    printf("process %s is die!", args[1]);
    }*/
    return 0;
}
