#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <mqueue.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <setjmp.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "server.h"

#define PRIVATE	static

/*Global variable*/
char     g_aucProccessName[PROC_LENGTH];
char     g_aucFifoName[FIFO_LENGTH];
char     g_aucMsgqName[MSGQ_LENGTH];

mqd_t          g_tmqd;
pthread_t    fifo_thread;      /*Daemon fifo ID*/


static SYMBOL_ENT* taSymTbl; 
static int ulSymTblSize;
static bool bSymTabInitFlag;
static char s_aSecNames[MAX_SEC_NUM][MAX_SEC_NAME_LEN];

WORD32    wUshellThreadId = 0xffffffff;
static char g_acFifoMsg[IPC_MSG_LENTH];
int fd_fifo, fd_STDOUT; 

static int flag_print = 0; //flag of stdout direct (fifo ? 1 : 0)
static int flag_debug = 0; //flag of debug command state

LONG(*testFUNC)(LONG, LONG, LONG, LONG, LONG, LONG, LONG, LONG, LONG, LONG);


typedef struct tag_UniExcProtectBuf
{
    sigjmp_buf *pUniExcProtectJmpbuf;
    int        UniExcProtectFlag;
}T_UniExcProtectBuf;


#define IS_IN_EXC  0x1a2b3c4d
#define NOT_IN_EXC  0


__thread T_UniExcProtectBuf  tUniExcProtectBuf;
extern int      g_dwCurProcessId;

/*去除命令和参数之间多余的空格*/
char *trim(char *str)  
{ 
    char *start = str;
    char *end;
    if(start)
    {
        end = start + strlen(str) - 1;
        while(*start && isspace(*start))
        {
            start++;
        }

        if ('\0' == *start)
        {
            str[0] = '\0';
            return str;
        }
        
        while(isspace(*end))
        {
            *end-- = '\0';
        }
        memmove(str, start, end - start + 2);
    }

    return str;
    
} 

PRIVATE bool init_server_fifo()
{
    BYTE    aucbuf[180]={0};
    
    sprintf((char*)(g_aucFifoName),FIFO_NAME,g_dwCurProcessId);
    sprintf(aucbuf,RM_FIFO,g_dwCurProcessId);
    
    system((char *)aucbuf);
    unlink((char *)g_aucFifoName); 

    /* fifo for redirect stdout */
    if(0 != mkfifo((char *)g_aucFifoName,O_CREAT))
    {
        printf("[%s:%d]Create fifo:%s error %d %s!\n",__FUNCTION__,__LINE__,g_aucFifoName,errno,strerror(errno));
        return false;
    }
    
    return true;
}


PRIVATE bool init_server_msgQ()
{
    struct  mq_attr  g_tmqattr;

    sprintf((char*)(g_aucMsgqName),MSGQ_NAME,g_dwCurProcessId);
    
    memset(&g_tmqattr, 0, sizeof(g_tmqattr));
    g_tmqattr.mq_maxmsg  = IPC_MSG_NUM;
    g_tmqattr.mq_msgsize = IPC_MSG_LENTH;
    shm_unlink((char *)g_aucMsgqName);
    g_tmqd = mq_open((char *)g_aucMsgqName, O_RDONLY | O_CREAT,666,&g_tmqattr);
    if ((mqd_t)-1 == g_tmqd)
    {
        printf("[%s:%d]Open MsgQueue:%s error!",__FUNCTION__,__LINE__,g_aucMsgqName);
        return false;
    }
    return true;
}


/**********************************************************************
* 函数名称：
* 功能描述：设置ushell的阻塞模式
* 访问的表：
* 修改的表：fd: 文件描述符
* 输入参数：isBlock:true: 设置为阻塞模式 false: 设置为非阻塞模式 
* 输出参数：
* 返 回 值：
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
void set_fd_block_mode(int fd, bool isBlock)
{
    int flags;
    flags = fcntl(fd, F_GETFL);
    if(true == isBlock)
    {
        flags &= ~O_NONBLOCK; 
    }
    else
    {
        flags |= O_NONBLOCK;
    }
    
    if(fcntl(fd, F_SETFL, flags) < 0)
    {
        printf("SetFdBlockMode fcntl fd %d isBlock %d error %d\n", fd, isBlock, errno);
    }
}


PRIVATE bool deal_print_and_dbg_cmd()
{
    /*处理pad请求*/
    
    if(flag_print == 0) 
    {
        fd_fifo = -1;
        fd_fifo = open((char *)g_aucFifoName,O_WRONLY,0);
        if(-1 == fd_fifo)
        {
            printf("open fifo:%s error: %d %s \n",g_aucFifoName,errno,strerror(errno));
            return false;
        }
        /* 设置ushell的非阻塞模式 */
        set_fd_block_mode(fd_fifo, false);     

        fd_STDOUT = dup(STDOUT_FILENO);
        dup2(fd_fifo,STDOUT_FILENO);
        printf("ushell enter print mod \n ");
        flag_print = 1;
    }
    
    printf("ushell enter debug mod \n ");
    flag_debug = 1;
    return true;
}


PRIVATE bool deal_not_print_and_dbg_cmd()
{
    /*处理npad请求*/
    
    if(flag_print == 1)
    {
        dup2(fd_STDOUT,STDOUT_FILENO);
        close(fd_STDOUT);
        close(fd_fifo);

        flag_print = 0;
    }
    
    flag_debug = 0;
    return true;
}

char *s_strcpy( char *pcDst, WORD32 dwMaxSize, const char *pcSrc )
{
    WORD32  dwIndex = 0;
    char   *pcResult = pcDst;

    if ( ( pcDst == NULL ) || ( pcSrc == NULL ) || ( dwMaxSize == 0 ) )
    {
        return pcResult;
    }

    while ( ( dwIndex++ < dwMaxSize ) && ( '\0' != ( *pcDst++ = *pcSrc++ ) ) )
    {
    }

    if ( dwIndex >= dwMaxSize )
    {
        *( pcResult + dwMaxSize - 1 ) = '\0';
    }
    return pcResult;
}

PRIVATE bool is_danger_cmd(CHAR command[])
{
    if((0 == strcmp("err" , command))\
        ||(0 == strcmp("errx" , command))\
        ||(0 == strcmp("verr" , command))\
        ||(0 == strcmp("verrx" , command)))
    {
        return true;
    }
    return false;
}

PRIVATE void ShowVarValue(CHAR command[],CHAR argstr[ARG_NUM][ARG_LENGTH], int symsize, LONG firstArgInt)
{
    int iloop      = 0;
    BYTE *ucptemp = NULL;
    
    if((NULL == command) || (NULL == argstr))
        return;

    switch(symsize)
    {
    case 1:
        {
            if(argstr[0][0]!='\0')
            {
               *(char *)testFUNC= firstArgInt;
            }
            printf("%s = 0x%lx value=0x%02lx\n", command, (LONG)testFUNC,*(char *)testFUNC); 
            break;
        }
    case 2:
        {
            if(argstr[0][0]!='\0')
            {
               *(WORD16 *)testFUNC = firstArgInt;
            }
            printf("%s = 0x%lx value=0x%04lx\n",command, (LONG)testFUNC,*(WORD16 *)testFUNC);
            break;
        }
   case 4:
        {
            if(argstr[0][0]!='\0')
            {
               *(WORD32 *)testFUNC = firstArgInt;
            }
            printf("%s = 0x%lx value=0x%08lx\n",command, (LONG)testFUNC,*(WORD32 *)testFUNC);
            break;
        }
   case 8:
        {
            if(argstr[0][0]!='\0')
            {
               *(WORD64 *)testFUNC = firstArgInt;
            }
            printf("%s = 0x%lx value=0x%016lx\n",command, (LONG)testFUNC,*(WORD64 *)testFUNC);
            break;
        }
   default:
        {
            ucptemp = (char *)testFUNC;
            printf("%s= addr:0x%lx\n",command, testFUNC);
            for(iloop=0;iloop<symsize;iloop++)
            {
                if((iloop%4==0)&&(iloop>0))
                {
                    printf("  ");
                }
                if((iloop%16==0)&&(iloop>0))
                {
                    printf("\n");
                }
                printf("%02lx",*(ucptemp+iloop));
                
            }
            printf("\n");
        }
    }
}

PRIVATE void ExcuteDebugCommand(CHAR command[],
    LONG arg1, LONG arg2, LONG arg3, LONG arg4, LONG arg5, 
    LONG arg6, LONG arg7, LONG arg8, LONG arg9, LONG arg10)
{ 
    LONG value = -1;

    if(NULL == command)
        return ;
    if(true == is_danger_cmd(command))
    {
        printf("can not input fun: %s,it will make process exit!\n",command);
        return;
    }

    printf("[   begin to excel fun:%s      ]\n", command);

    if(NULL == tUniExcProtectBuf.pUniExcProtectJmpbuf)      
        tUniExcProtectBuf.pUniExcProtectJmpbuf = (sigjmp_buf *)malloc(sizeof(sigjmp_buf)); 
    
    if(0 == sigsetjmp (*(tUniExcProtectBuf.pUniExcProtectJmpbuf), 1))                     
    {                                                           
        tUniExcProtectBuf.UniExcProtectFlag = IS_IN_EXC; 
        
        value = testFUNC(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
        printf("value = %ld(0x%lx)\n",value,value);
        
        tUniExcProtectBuf.UniExcProtectFlag = NOT_IN_EXC;            
    }                                                                             
    else                                                                         
    {                                                          
        tUniExcProtectBuf.UniExcProtectFlag = NOT_IN_EXC;     
        printf("\nUshell Input Is Wrong! Data Access Error Happened,");
        printf(" Please Check Your Input Again!!\n");
    }
            
    printf("[   end to excel fun:%s      ]\n", command);
}

PRIVATE bool deal_user_cmd()
{
    int i,j,k;
    char command_buf[ARG_LENGTH],argstr[ARG_NUM][ARG_LENGTH],argtemp[ARG_LENGTH];
    LONG argint[ARG_NUM],argflag[ARG_NUM];
    int  symtype,symsize; 
    char ExcCodeName[255];
    bool bAddrFunc = false;
    bool bAccessBySymName = false;
    
    if(1 == flag_debug)
    {
        memset(command_buf,'\0',ARG_LENGTH);
        memset(argstr[0],'\0',sizeof(argstr));
        
        for(i=0;i<ARG_NUM;i++)
        {
          argflag[i]=0;
          argint[i]=0;
        }
        
        bAddrFunc = verify_address_func_cmd(g_acFifoMsg);
        /* 将字符串调试命令分解为函数和参数 */
        i=0;j=0;k=0;
        for(i = 0;(i<IPC_MSG_LENTH);i++)
        {/* 函数名分离 */
            if(j == 0)
            {
                    if((g_acFifoMsg[i]!=' ')&&(g_acFifoMsg[i]!='\0'))
                    {    
                        command_buf[k] = g_acFifoMsg[i];
                        k++;
                    }
                    else   
                    {          
                        command_buf[k] = '\0';      
                        j++;
                        k = 0;                    
                    }
            }
            else
            {/* 参数分离，字符串形式 */
                if((g_acFifoMsg[i]!=',')&&(g_acFifoMsg[i]!='\0'))
                {    
                    if(k<ARG_LENGTH -1) 
                    {
                        argstr[j-1][k] = g_acFifoMsg[i];
                        k++;
                    }
                    else
                    {
                        printf(" para %d is too long \n",j);
                         return false;
                    }
                }
                else   
                {       
                    argstr[j-1][k] = '\0';         
                    j++;
                    k = 0;
                    if(g_acFifoMsg[i]=='\0')
                    {
                        break;
                    }
                    if (j > ARG_NUM)
                    {
                        printf(" para num is too much\n");
                        return false;
                    }
                }
            }
        }
        
        /* 参数字符串形式转化为整型数 */
        for(i = 0; i < 10; i++)
        {
            /*去除命令和参数之间多余的空格*/
            trim(argstr[i]);
           
            //参数为16进制数
            if(((argstr[i][0] == '0')&&(argstr[i][1] == 'x'))
                ||((argstr[i][0] == '0')&&(argstr[i][1] == 'X')))
            {
                #ifdef SUPPORT_64BIT
                sscanf(argstr[i],"0x%llx",&argint[i]); /* 64位%lx,%p */
                #else
                sscanf(argstr[i],"0x%x",&argint[i]); /* 32位%lx,%p */
                #endif
            }
            //参数为字符串
            else if(argstr[i][0] == '\"')
            {
                argflag[i]=1;
                memcpy(argtemp,&argstr[i][1],strlen(&argstr[i][1]));
                argtemp[strlen(&argstr[i][1])-1]='\0';
                s_strcpy(argstr[i],ARG_LENGTH,argtemp);
            }
            //参数为十进制
            else
            {
                #ifdef SUPPORT_64BIT
                argint[i] = atoll(argstr[i]);
                #else
                argint[i] = atoi(argstr[i]);
                #endif
            }
        }
        
        /* 分解出调试函数形式: command_buf(argint[0], argint[1], argint[2]) */        

        /* 命令是函数或者全局变量，命令为0x开头的一个地址也要判断 */
        memset(ExcCodeName, 0, sizeof(ExcCodeName));
        bAccessBySymName = (symFindByName(command_buf,(ULONG*)&testFUNC,&symsize,&symtype) == 0) ? true : false;
        if((true == bAccessBySymName) ||
            ((true == bAddrFunc) && (true == symFindByAddress(command_buf, ExcCodeName, (ULONG*)&testFUNC, (WORD32*)&symsize,(WORD32*)&symtype)))) 
            { 
                /* 设置ushell为阻塞模式 */
                set_fd_block_mode(fd_fifo, true);
                
                if(STT_FUNC == symtype )
                {
                    //执行函数
                    ExcuteDebugCommand(((bAddrFunc == true) ? ExcCodeName : command_buf),
                                       ((argflag[0]== 0)?argint[0]:(LONG)argstr[0]),
                                       ((argflag[1]== 0)?argint[1]:(LONG)argstr[1]),
                                       ((argflag[2]== 0)?argint[2]:(LONG)argstr[2]),
                                       ((argflag[3]== 0)?argint[3]:(LONG)argstr[3]),
                                       ((argflag[4]== 0)?argint[4]:(LONG)argstr[4]),
                                       ((argflag[5]== 0)?argint[5]:(LONG)argstr[5]),
                                       ((argflag[6]== 0)?argint[6]:(LONG)argstr[6]),
                                       ((argflag[7]== 0)?argint[7]:(LONG)argstr[7]),
                                       ((argflag[8]== 0)?argint[8]:(LONG)argstr[8]),
                                       ((argflag[9]== 0)?argint[9]:(LONG)argstr[9]));
                }
                
                else if(STT_OBJECT == symtype )
                {
                    //显示变量值
                    if (true == bAccessBySymName)
                    {
                        ShowVarValue(command_buf, &argstr[0], symsize, argint[0]);
                    }
                    else
                    {
                        printf("address  %s is not in code segment!\n",command_buf);
                    }
                }
                else 
                {
                   printf("symtype:%d error \n",symtype);
                }
                /* 设置ushell的非阻塞模式 */
                set_fd_block_mode(fd_fifo, false);
        }   
        else 
        {
            printf("sym:%s not found!\n",command_buf);
            return false;
        }
      }
    
    return true;
}

PRIVATE void *shell_pthread_mq(void *arg)
{
    //屏蔽掉时钟信号
    //blockticksig();
    wUshellThreadId = pthread_self();
    
    while(1) 
    {
        memset(g_acFifoMsg,0,IPC_MSG_LENTH);
        if(-1 == mq_receive(g_tmqd, g_acFifoMsg, IPC_MSG_LENTH, NULL))//len must bigger than the msg len sent
            perror("mq_receive()");

        if((strcmp(g_acFifoMsg,"print_fifo_and_debug")) == 0)
        {
            deal_print_and_dbg_cmd();
        }
        else if((strcmp(g_acFifoMsg,"not_print_fifo_and_debug")) == 0)
        {
            deal_not_print_and_dbg_cmd();
        }
        else
        {
            if(!deal_user_cmd())
                continue;
        }
    }
}

PRIVATE bool create_fifo_daemon_thread()
{
    pthread_attr_t attr;
    
    pthread_attr_init(&attr);
    pthread_attr_setinheritsched(&attr,PTHREAD_INHERIT_SCHED);
    
     /* shell command queue daemon thread */
    if(0 != pthread_create(&fifo_thread, &attr, shell_pthread_mq,NULL))
    {	 
        printf("[%s:%d] Create fifo_thread error!\n ",__FUNCTION__,__LINE__);
        return false;
    }
    return true;
}

bool shell_server_init()
{
    if(!module_sym_init())
    {
        printf("[%s:%d] module_sym_init fail\n",__FUNCTION__,__LINE__);
        return false;
    }
    
    if(init_server_fifo() && init_server_msgQ() && create_fifo_daemon_thread())
        return true;
    else
        return false;
}
