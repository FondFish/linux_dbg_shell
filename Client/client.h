#ifndef _SHELL_CLIENT_H
#define _SHELL_CLIENT_H

#include <mqueue.h>
#include "type.h"

#define  FIFO_LENGTH          32
#define  MSGQ_LENGTH       32
#define  IPC_MSG_LENTH     512
#define  IPC_FIFO_LENTH     4096

#define  MAX_PROCESS_NUM    (WORD16)5
#define  MAX_TRY_NUM        3

#define FIFO_NAME  "/shell_fifo%d"
#define MSGQ_NAME "/shell_msq%d"

typedef struct T_ProcessInfo
{
  bool   IsUseed;
  bool   IsPrintState;       /*print is/not take over*/
  bool   IsCommandState;    /*cmd send state*/
  int      pid;                           /*dbg pid*/
  int      fifoFd;                       /*fifo fd*/
  mqd_t     mqd;                /*msg queue ID*/
  char ucFifoName[FIFO_LENGTH];   /*PIPE name*/
  char ucMsgqName[MSGQ_LENGTH];   /*mq name*/
}ProcessInfo;

#endif
