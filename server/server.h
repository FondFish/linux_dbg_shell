
#ifndef _SHELL_SERVER_H
#define _SHELL_SERVER_H

#include "type.h"

#define  FIFO_LENGTH          64
#define  MSGQ_LENGTH       64
#define  PROC_LENGTH        32

#define MAX_SEC_NUM     100
#define MAX_SEC_NAME_LEN    30

#define PROC_NAME "shell_server"
#define FIFO_NAME  "/shell_fifo%d"
#define MSGQ_NAME "/shell_msq%d"
#define RM_FIFO  "rm -f shell_fifo%d"

#define IPC_MSG_NUM      50
#define IPC_MSG_LENTH  512

#define EI_MAG0		    0                /* ELF文件的前四个数保存魔术数 */
#define EI_MAG1		    1
#define EI_MAG2		    2
#define EI_MAG3		    3
#define EI_CLASS	    4                /* ELF文件的类型:ELFCLASS32或ELFCLASS32 */
#define EI_DATA		    5                /* 大段和小端字节顺序标识 */

#define ARG_NUM          10
#define ARG_LENGTH     512

#define ERROR -1
#define OK 0

/*符号的类型宏定义*/
#define STT_NOTYPE	    0
#define STT_OBJECT	    1
#define STT_FUNC	    2
#define STT_SECTION	    3
#define STT_FILE	    4
#define STT_LOPROC	    13
#define STT_HIPROC	    15

#define PERR printf("error at line %d\n", __LINE__)


typedef struct {
    CHAR *name;
    CHAR *addr;
    WORD32 size;
    WORD32  type;
} SYMBOL_ENT;

#endif
