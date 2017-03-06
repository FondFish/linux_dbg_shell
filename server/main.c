
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bits/pthreadtypes.h>
#include <pthread.h>
#include <signal.h>
#include <mqueue.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/unistd.h>


#include "server.h"

pid_t   gSelfPid = 0;
int      g_dwCurProcessId = 0;

static int g_stop_delay=1;
int user_test1(void)
{
    int a=100;
    int b=200;
    printf("user_test1:%d\n",a+b);
    return 1;
}

int user_test2(int a, int b)
{
    printf("user_test2:%d\n",a+b);
    return 2;
}

pid_t getpid()
{
    if (0 == gSelfPid)
    {    
        gSelfPid = (pid_t)syscall(__NR_getpid);
    }
    return gSelfPid;
}

int main(int argc, char *argv[])
{
    g_dwCurProcessId = (int)getpid();
    shell_server_init();

    while(1)
    {
        sleep(1);
        printf("main:%d still running\n",g_dwCurProcessId);
    }
    
    return 0;
}
