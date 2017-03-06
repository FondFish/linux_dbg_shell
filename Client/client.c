#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <mqueue.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/unistd.h>


#include "client.h"

#define    PASSWORD           "aaa"
#define    SH_TAG                 "sh "

/****Global Variable****/
ProcessInfo g_tProcessInfo[MAX_PROCESS_NUM];    /*dbg proc record array*/
char            msg_buf[IPC_MSG_LENTH];    /* buf to mq */
pthread_t    fifo_thread;      /*Daemon fifo ID*/
char           msg_type[IPC_MSG_LENTH];    /*input buf*/
fd_set         readfds;               /*fifo fd set*/

ProcessInfo* get_dbg_proc_tbl()
{
    return g_tProcessInfo;
}

void init_dbg_proc_tbl()
{
    int i =0;
    ProcessInfo * pProcessInfo = get_dbg_proc_tbl();

    for(i =0;i<MAX_PROCESS_NUM;i++)
    {
        (pProcessInfo+i)->IsUseed = false;
        (pProcessInfo+i)->IsPrintState = false;
        (pProcessInfo+i)->IsCommandState = false;
        (pProcessInfo+i)->pid = -1;
        (pProcessInfo+i)->fifoFd = -1;
        (pProcessInfo+i)->mqd = -1;
    }
}

void shell_exit(int signo, siginfo_t *info, void *context)
{
    /*exc handler*/
    int i = 0;
    ProcessInfo * pProcessInfo = get_dbg_proc_tbl();
    
    printf("shell recv signo:%d.\n", signo);
	
    memset(msg_buf,0,IPC_MSG_LENTH); 
    memcpy(msg_buf, "not_print_fifo_and_debug", strlen("not_print_fifo_and_debug"));
    
    for(i =0;i<MAX_PROCESS_NUM;i++)
    {
        if((pProcessInfo+i)->IsUseed == true)
        {
            mq_send(((pProcessInfo+i)->mqd), msg_buf, IPC_MSG_LENTH, 0);
            mq_close((pProcessInfo+i)->mqd);
            
            (pProcessInfo+i)->mqd = -1;
            (pProcessInfo+i)->IsUseed = false;
            (pProcessInfo+i)->IsPrintState = false;
            (pProcessInfo+i)->IsCommandState = false;
            
            if((pProcessInfo+i)->fifoFd != -1)
                close((pProcessInfo+i)->fifoFd);
            
            (pProcessInfo+i)->fifoFd = -1;
            (pProcessInfo+i)->pid = -1;
        }
    }
    
    printf("quit debug and exit shell!\n");
    exit(0);
}

void signal_register()
{
    struct sigaction act;

    sigemptyset(&act.sa_mask);
    act.sa_flags=SA_SIGINFO;
    act.sa_sigaction=shell_exit;	/*exit handle*/
    sigaction(SIGINT,&act,NULL);
    sigaction(SIGSEGV,&act,NULL);
    sigaction(SIGILL,&act,NULL);
    sigaction(SIGFPE,&act,NULL);
    sigaction(SIGBUS,&act,NULL);
    sigaction(SIGABRT,&act,NULL);
    sigaction(SIGTERM,&act,NULL);
    sigaction(SIGHUP,&act,NULL);
}

void *shell_pthread_fifo(void *arg)
{
    int fdmax =0, read_num;
    char r_buf[IPC_FIFO_LENTH + 1];
    int i =0;
    ProcessInfo * pProcessInfo;
    bool havefindfifo;
    
    while (1)
    {       
        FD_ZERO(&readfds);
        havefindfifo = false;
        pProcessInfo = get_dbg_proc_tbl();
        
        for(i=0;i<MAX_PROCESS_NUM;i++)
        {
            if(((pProcessInfo+i)->IsUseed == true)&&((pProcessInfo+i)->fifoFd != -1)
                    &&((pProcessInfo+i)->IsPrintState == true))
            {
                FD_SET((pProcessInfo+i)->fifoFd, &readfds);
                if(((pProcessInfo+i)->fifoFd) >fdmax)
                {
                    fdmax = (pProcessInfo+i)->fifoFd;
                }
                havefindfifo = true;
            }
        }
        if(havefindfifo == false)
        {
            sleep(1);
            continue;
        }
        if(-1 == select(fdmax+1, &readfds, NULL, NULL, NULL))   
        {    
            if(EINTR == errno)
            {
                continue;
            }
            else
            {
                break;
            }
        }
        pProcessInfo = get_dbg_proc_tbl();
        for(i=0;i<MAX_PROCESS_NUM;i++)
        {
            if(((pProcessInfo+i)->IsUseed == true)&&((pProcessInfo+i)->fifoFd != -1)
                    &&((pProcessInfo+i)->IsPrintState == true))
            {
                if (FD_ISSET(((pProcessInfo+i)->fifoFd), &readfds))
                {
                    memset(r_buf, 0 ,IPC_FIFO_LENTH + 1);
                    read_num=read(((pProcessInfo+i)->fifoFd),r_buf, IPC_FIFO_LENTH);
                    if (read_num > 0)
                    {
                        printf("\n[%d]\n%s", ((pProcessInfo+i)->pid),r_buf);
                    }
                    else
                    {    
                        FD_CLR(((pProcessInfo+i)->fifoFd),&readfds);
                        
                        if((pProcessInfo+i)->fifoFd != -1)
                        {
                            close((pProcessInfo+i)->fifoFd);
                        }
                        
                        (pProcessInfo+i)->fifoFd = -1;
                        (pProcessInfo+i)->IsPrintState = false;
                        
                        if((pProcessInfo+i)->IsCommandState == false)
                        {
                            if((pProcessInfo+i)->mqd != -1)
                            {
                                mq_close((pProcessInfo+i)->mqd);
                            }
                            (pProcessInfo+i)->IsUseed = false;
                            (pProcessInfo+i)->pid = -1;
                            (pProcessInfo+i)->mqd = -1;
                        }
                    }  
                }
            }
        }
    }
    return NULL;
}

bool create_fifo_daemon_thread()
{
    pthread_attr_t attr;
    
    pthread_attr_init(&attr);
    pthread_attr_setinheritsched(&attr,PTHREAD_INHERIT_SCHED);
    
    if(0 != pthread_create(&fifo_thread, &attr, shell_pthread_fifo,NULL))
    {	 
        return false;
    }
    return true;
}

bool login_process()
{
    int        i = 0;
    int        tryLoginNum = 0;
    char*    buf;

    while(1)
    {
        printf("-> Please input password!\n");
        buf = getpass("->");
        
        for(i=0;i<strlen(buf);i++)
        {
            printf("*");
        }
        printf("\n");
        
        if (NULL == buf)
            shell_exit(0,0,0);
        
        if (strcmp(buf,PASSWORD) == 0)
        {   
            printf("-> Login success!!\n");
            xfree(buf); /*release buf*/
            return true;
        }
        else if (strcmp(buf,"exit") == 0)
        {
            shell_exit(0,0,0);
            return false;
        }
        else
        {
            printf("-> Error  password!!\n");
            tryLoginNum++;
            if(tryLoginNum >= MAX_TRY_NUM)
            {
                printf("-> Input password exceed %d times，ushell exit \n",tryLoginNum);
                shell_exit(0,0,0);
                return false;
            }
            continue;
        }
    }
}

void shell_help()
{
    printf("pad xxx : debug process and take over print info\n");
    printf("npad xxx : quit debug process and take over print info\n");
    printf("q : quit all debug process and take over print info\n");
    printf("exit : exit debug shell\n");
}

void shell_take_over_print()
{
}
void shell_not_take_over_print()
{
}
void shell_debug_process()
{
}
void shell_exit_debug_process()
{
}

void shell_wake_up_select()
{
    if (0 != pthread_kill(fifo_thread,SIGRTMAX-1))
        printf("pthread_kill failed to send signal! errno: %d %s \n",errno,strerror(errno));
    
    return;
}

void mq_open_fail_handler(ProcessInfo* ptProc)
{
        ptProc->IsUseed = false;
        ptProc->IsPrintState = false;
        ptProc->IsCommandState = false;
        if(ptProc->fifoFd != -1)
        {
            FD_CLR((ptProc->fifoFd),&readfds);
            close(ptProc->fifoFd);
        }
        ptProc->pid = -1;
        ptProc->fifoFd = -1;
        ptProc->mqd = -1;
        shell_wake_up_select();
}

void fifo_open_fail_handler(ProcessInfo* ptProc)
{
        if(-1 == ptProc->mqd)
            mq_close(ptProc->mqd);
        
        ptProc->IsUseed = false;
        ptProc->IsPrintState = false;
        ptProc->IsCommandState = false;
        ptProc->pid = -1;
        ptProc->fifoFd = -1;
        ptProc->mqd = -1;
        shell_wake_up_select();
}
int get_pid_from_input(int startPos)
{
    int i,j;
    int pid = -1;
    char pidchar[10];
    
    for(i=startPos,j=0;i<IPC_MSG_LENTH&&msg_type[i]!='\0'&&j<9;i++)
    {
        if(msg_type[i]==' ')
            continue;
        pidchar[j++]=msg_type[i];
    }
    
    pidchar[j]='\0';
    pid = atoi(pidchar);
    
    return pid;
}
void shell_print_and_debug_process(void)
{
    int i = 0;
    int pid = -1;
    ProcessInfo * pProcessInfo = get_dbg_proc_tbl();
    
    pid = get_pid_from_input(4);
    
    for(i=0;i<MAX_PROCESS_NUM;i++)
    {
        if(((pProcessInfo+i)->pid == pid)&&((pProcessInfo+i)->IsUseed == true))
        {
            printf(" Proccess :%d is already enter take over print or/and debug mod\n",pid);
            printf(" IsCommandState:%d,IsPrintState:%d \n",(pProcessInfo+i)->IsCommandState,(pProcessInfo+i)->IsPrintState);
            return;
        }
    }
    
    for(i=0;i<MAX_PROCESS_NUM;i++)
    {
        if(((pProcessInfo+i)->IsUseed == false))
            break;
    }

    if(i >= MAX_PROCESS_NUM)	
    {
        printf("can not find free proccess from array g_tProcessInfo\n");
        return;
    }
	
    pProcessInfo = pProcessInfo+i;
    pProcessInfo->IsUseed = true;
    pProcessInfo->pid = pid;
    sprintf((char *)pProcessInfo->ucFifoName,FIFO_NAME,pid);
    sprintf((char *)pProcessInfo->ucMsgqName,MSGQ_NAME,pid);
    
    pProcessInfo->mqd = mq_open((char *)pProcessInfo->ucMsgqName, O_WRONLY);
    
    if ((mqd_t)-1 == pProcessInfo->mqd)
    {    
        printf("open msgQ:%s error!\n",pProcessInfo->ucMsgqName);
        mq_open_fail_handler(pProcessInfo);
        return;
    }
    
    pProcessInfo->fifoFd = open((char *)pProcessInfo->ucFifoName, O_RDONLY|O_NONBLOCK,0);
    
    if (-1 == pProcessInfo->fifoFd)
    {
        printf("open fifo:%s error!\n",pProcessInfo->ucFifoName);
        fifo_open_fail_handler(pProcessInfo);
        return;
    }
    
    pProcessInfo->IsCommandState = true;
    pProcessInfo->IsPrintState = true;
    
    memset(msg_buf,0,IPC_MSG_LENTH); 
    memcpy(msg_buf, "print_fifo_and_debug", strlen("print_fifo_and_debug"));
    mq_send(pProcessInfo->mqd, msg_buf, IPC_MSG_LENTH, 0);

    //shell_wake_up_select();               
}

void shell_exit_print_and_debug_process()
{
    int i = 0;
    int pid = -1;
    ProcessInfo * pProcessInfo = get_dbg_proc_tbl();
    
    pid = get_pid_from_input(5);
    
    for(i=0;i<MAX_PROCESS_NUM;i++)
    {
        if(((pProcessInfo+i)->pid == pid)&&((pProcessInfo+i)->IsUseed == true))
        {
            if(((pProcessInfo+i)->IsCommandState != true) ||((pProcessInfo+i)->IsPrintState != true))
            {
                printf(" Proccess :%d is not in print and debug mod\n",pid);
                return;
            }
            memset(msg_buf,0,IPC_MSG_LENTH); 
            memcpy(msg_buf, "not_print_fifo_and_debug", strlen("not_print_fifo_and_debug"));   
            mq_send(((pProcessInfo+i)->mqd), msg_buf, IPC_MSG_LENTH,0);
            
            (pProcessInfo+i)->IsCommandState = false;
            (pProcessInfo+i)->IsPrintState = false;
            (pProcessInfo+i)->IsUseed = false;
            (pProcessInfo+i)->pid = -1;
        
            if((pProcessInfo+i)->fifoFd != -1)
            {
                FD_CLR(((pProcessInfo+i)->fifoFd),&readfds);
                close((pProcessInfo+i)->fifoFd);
            }
        
            if((pProcessInfo+i)->mqd != -1)
                mq_close((pProcessInfo+i)->mqd);
            
            (pProcessInfo+i)->fifoFd = -1;
            (pProcessInfo+i)->mqd = -1;
            
            //shell_wake_up_select();
        }
    }
}

void shell_exit_all_proccess_debug()
{
    int i = 0;
    ProcessInfo * pProcessInfo;
    
    memset(msg_buf,0,IPC_MSG_LENTH); 
    memcpy(msg_buf, "not_print_fifo_and_debug", strlen("not_print_fifo_and_debug"));
    pProcessInfo = get_dbg_proc_tbl();
    
    for(i=0;i<MAX_PROCESS_NUM;i++)
    {
        if((pProcessInfo+i)->IsUseed == true)
        {
            mq_send((pProcessInfo+i)->mqd, msg_buf, IPC_MSG_LENTH, 0);
            (pProcessInfo+i)->IsUseed = false;
            (pProcessInfo+i)->IsPrintState = false;
            (pProcessInfo+i)->IsCommandState = false;

            (pProcessInfo+i)->pid = -1;
            if((pProcessInfo+i)->fifoFd != -1)
            {
                FD_CLR(((pProcessInfo+i)->fifoFd),&readfds);
                close((pProcessInfo+i)->fifoFd);
            }
            (pProcessInfo+i)->fifoFd = -1;
            
            if((pProcessInfo+i)->mqd != -1)
                mq_close((pProcessInfo+i)->mqd);
            (pProcessInfo+i)->mqd = -1;
            
            //shell_wake_up_select();
        }
    }
    return;
}

void shell_send_command()
{
    int i = 0;
    bool bFind = false;
    ProcessInfo * pProcessInfo =get_dbg_proc_tbl();
    
    for(i=0;i<MAX_PROCESS_NUM;i++)
    {
        if(((pProcessInfo+i)->IsUseed == true) &&((pProcessInfo+i)->IsCommandState == true))
        {
            mq_send((pProcessInfo+i)->mqd, msg_type, IPC_MSG_LENTH, 0);
            bFind = true;
        }
    }
    
    if(false == bFind)
        printf("Input error!:%s\n",msg_type);

    return;
}

void input_cmd_handler()
{
    if(strlen(msg_type) == 0)
        return;
    else if(strncmp(msg_type,"pr ",3) == 0)
        shell_take_over_print();
    else if(strncmp(msg_type,"npr ",4) == 0)
        shell_not_take_over_print();
    else if(strncmp(msg_type,"db ",3) == 0)
        shell_debug_process();
    else if(strncmp(msg_type,"ndb ",4) == 0)
        shell_exit_debug_process();
    else if(strncmp(msg_type,"pad ",4) == 0)
        shell_print_and_debug_process();
    else if(strncmp(msg_type,"npad ",5) == 0)
        shell_exit_print_and_debug_process();
    else if(strcmp(msg_type,"q")==0)
        shell_exit_all_proccess_debug();
    else if(strcmp(msg_type,"exit")==0)
        shell_exit(0,0,0);
    else if(strcmp(msg_type,"help")==0)
        shell_help();
    else if(strcmp(msg_type,"ps")==0) 
        system("ps");
    else if(0 == strncmp(msg_type, SH_TAG, strlen(SH_TAG)))
        system((void *)msg_type + strlen(SH_TAG));
    else
        shell_send_command();
}

int main(int argc, char *argv[])
{
    char *buf;

    memset(msg_type,0,IPC_MSG_LENTH);
    
    init_dbg_proc_tbl();   
    signal_register();
    
    if(false == create_fifo_daemon_thread())
    {	 
        printf("create fifo_read thread error!\n");
        exit(0);
    }
    
    login_process();
        
    while(1) 
    {
        buf  = readline("$$"); 

        if (NULL == buf)
            shell_exit(0,0,0);

        strcpy(msg_type,buf); 
        xfree(buf); 
        
        if(strlen(msg_type) == 0)
    	    continue;
        else
            input_cmd_handler();

        usleep(10*1000); 
        printf("\n"); 
    }
    
   return 0;
}

