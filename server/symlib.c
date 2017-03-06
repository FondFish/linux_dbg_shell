
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <elf.h> 
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


#include "server.h"


/*****************************************************/
#define   FAST   register
#define PRIVATE	static

#define   LITTLE_ENDIAN	    1                /* 小端法:高位字节在低地址 */
#define   BIG_ENDIAN	    2                /* 大端法:高位字节在高地址 */
#define   EOS     '\0' 

#define SYM_HFUNC_SEED 1370364821 /* magic seed */
#define SYM_TBL_HASH_SIZE_LOG2 8 /* 256 entry hash table symbol table */

#define SYM_MASK_ALL    0xff          /* all bits of symbol type valid */
#define SYM_MASK_NONE   0x00          /* no bits of symbol type valid */
#define SYM_MASK_EXACT  0x1ff         /* match symbol pointer exactly */
#define SYM_SDA_MASK    0xc0          /* for SDA and SDA2 symbols */

#define SYM_MASK_ANY_TYPE    SYM_MASK_NONE  /* ignore type in searches */
#define SYM_MASK_EXACT_TYPE  SYM_MASK_ALL   /* match type exactly in searches */

#define MODULE_PATH_LENGTH 128

#define ELF32_ST_TYPE(info)		 ((info) & 0xf)

extern int      g_dwCurProcessId;
extern char *trim(char *str);
/************************************************/
static UINT8 ffsMsbTbl [256] =			/* lookup table for ffsMsb() */
{
    0, 0, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
};

typedef struct slnode       
{
    struct slnode *next;    
} SL_NODE;

typedef struct          /* Header for a linked list. */
{
    SL_NODE *head;  /* header of list */
    SL_NODE *tail;  /* tail of list */
} SL_LIST;

typedef struct hashtbl      /* HASH_TBL */
{
    int     elements;       /* number of elements in table */
    FUNCPTR keyCmpRtn;      /* comparator function */
    FUNCPTR keyRtn;         /* hash function */
    int     keyArg;         /* hash function argument */
    SL_LIST *pHashTbl;      /* pointer to hash table array */
} HASH_TBL;
typedef HASH_TBL *HASH_ID;

typedef struct symtab   /* SYMTAB - symbol table */
{
    HASH_ID nameHashId; /* hash table for names */
    int   symMutex;   /* symbol table mutual exclusion sem */
    bool    sameNameOk; /* symbol table name clash policy */
    int     nsymbols;   /* current number of symbols in table */
} SYMTAB;

typedef struct tagT_ModuleInfo
{
    WORD16    ModuleType;
    WORD16    reserve;
    LONG    ModuleLoadAddress;/*模块加载地址*/
    WORD32    TotalSymbolNum;/*总的符号数*/
    struct tagT_ModuleInfo * pModuleSYMNext;
    struct tagT_ModuleInfo * pModuleSYMPrev;
    CHAR     pcModulePath[MODULE_PATH_LENGTH];
    LONG    CodeEndAddr;/*模块加载地址*/
}T_ModuleSYMInfo;

typedef SYMTAB *SYMTAB_ID;
typedef SL_NODE HASH_NODE; 

typedef struct /* SYMBOL - entry in symbol table */
{
    SL_NODE nameHNode; /* hash node (must come first) */
    char    *name;/* pointer to symbol name */
    void    *value;/* symbol value */
    T_ModuleSYMInfo *  group;/* symbol group */
    WORD32 size;
    BYTE type;/* symbol type */
} SYMBOL;

typedef SYMBOL* SYMBOL_ID;

/********************************************/

#define B2L(a, size) toLE((BYTE*)&a, size)
#define B2L2(a) (B2L(a, 2))
#define B2L4(a) (B2L(a, 4))
#define B2L8(a) (B2L(a, 8))

#define FREE(ptr) if(NULL != ptr) \
{\
    free(ptr); \
}

#define SLL_FIRST(pList) ((((SL_LIST *)pList)->head))
#define SLL_LAST(pList) ((((SL_LIST *)pList)->tail))
#define SLL_NEXT(pNode) ((((SL_NODE *)pNode)->next))

/********************************************/
int   g_iEndianType;
int   g_cpu_Family = 0;

SYMTAB_ID g_ModuleSymTbl = NULL; /* system symbol table id */
T_ModuleSYMInfo * g_pT_ModuleSYMInfo_Head = NULL;

/********************************************/

unsigned short get_cpu_family()
{
    return g_cpu_Family;
}

int get_endian_type()
{
	return g_iEndianType;
}

static SIZE_T toLE(BYTE *p, int size)
{
#ifdef SUPPORT_64BIT  
    WORD64 val;
#endif
    WORD32 i;
    WORD16 s;
    if (g_iEndianType == BIG_ENDIAN)
    {
#ifdef SUPPORT_64BIT    
        if (8 == size)
        {
            val = ((WORD64)(p[0]) << 56) + ((WORD64)(p[1]) << 48) + ((WORD64)(p[2]) << 40) 
                + ((WORD64)(p[3]) << 32) + (p[4] << 24) + (p[5] << 16) + (p[6] << 8) + p[7];
            *(WORD64*)p = val;
        }
#endif            
        if (4 == size)
        {
            i = (p[0] << 24) + (p[1] << 16) + (p[2] << 8) + p[3];
            *(WORD32*)p = i;
        }
        else if (2 == size)
        {
            s = (p[0] << 8) + p[1];
            *(WORD16*)p = s;
        }
    }
    return 0;
} 
/**********************************************************************
* 函数名称：
* 功能描述：
* 访问的表：
* 修改的表：i: argument to find first set bit in 
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
PRIVATE int ffsMsb(UINT32 i)
{
    UINT16 msw = (UINT16) (i >> 16);		/* most significant word */
    UINT16 lsw = (UINT16) (i & 0xffff);		/* least significant word */
    UINT8  byte;

    if (i == 0)
        return 0;

    if (msw)
    {
        byte = (UINT8) (msw >> 8);		/* byte is bits [24:31] */
        if (byte)
            return (ffsMsbTbl[byte] + 24 + 1);
        else
            return (ffsMsbTbl[(UINT8) msw] + 16 + 1);
    }
    else
    {
        byte = (UINT8) (lsw >> 8);		/* byte is bits [8:15] */
        if (byte)
            return (ffsMsbTbl[byte] + 8 + 1);
        else
            return (ffsMsbTbl[(UINT8) lsw] + 1);
    }
}
/**********************************************************************
* 函数名称：
* 功能描述： hashing function to generate hash from key
* 访问的表：
* 修改的表：elements: no. of elements in hash table
* 输入参数：pSymbol : pointer to symbol
* 输出参数：seed:  seed to be used as scalar
* 返 回 值：
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
int sym_hFunc_name(int elements,SYMBOL *pSymbol, int  seed)
{
    int  hash;
    char *tkey;
    int  key = 0;

    /* checksum the string and use a multiplicative hashing function */

    for (tkey = pSymbol->name; *tkey != '\0'; tkey++)
    {
        key = key + (unsigned int) *tkey;
    }

    hash = key * seed;/* multiplicative hash func */

    hash = hash >> (33 - ffsMsb (elements));/* take only the leading bits */

    return (hash & (elements - 1));/* mask hash to (0,elements-1)*/
}
/**********************************************************************
* 函数名称：
* 功能描述：function to test keys for equivalence 
* 访问的表：
* 修改的表：pMatchSymbol: pointer to match criteria symbol 
* 输入参数：pSymbol : pointer to symbol 
* 输出参数：maskArg: symbol type bits than matter 
* 返 回 值：
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
PRIVATE bool sym_key_cmp_name(SYMBOL *pMatchSymbol, SYMBOL *pSymbol, int maskArg)
{
    unsigned char    mask;                   /* symbol type bits than matter (char)*/

    if (maskArg == SYM_MASK_EXACT)
    {
        return (pMatchSymbol == pSymbol ? true : false);
    }

    mask = (unsigned char) maskArg;
    return ( ((pSymbol->type & mask) == (pMatchSymbol->type & mask)) 
           &&(strcmp (pMatchSymbol->name, pSymbol->name) == 0));
}

bool verify_address_func_cmd(char *pcCommand)
{
    char   *pcCmd       = NULL;  
    char   *pcLeft      = NULL;  /*查找左括号指针*/
    bool    bFind       = false;
    WORD32  dwAddr;
        
    if (NULL == pcCommand)
    {
        return false;
    }

    pcCmd  = trim(pcCommand);

    /* 按照地址执行函数，末尾必须有右括号 */
    if ( pcCmd[strlen(pcCmd) - 1] != ')' )
    {
        return false;
    }    

    /* 这里修改右括号为空格以便后面取参数*/
    pcCmd[strlen(pcCmd) - 1] = ' ';
   
    /* 检查字符串格式 */
    if(  '0' == pcCmd[0] && ('x' == pcCmd[1] || ('X' == pcCmd[1])))
    {
        pcLeft = pcCmd;
        while(*pcLeft++ != '\0')
        {
            /* 找到左括号 */
            if (*pcLeft == '(')
            {
                /* 这里修改左括号为空格以便后面取参数*/
                *pcLeft = ' ';
                bFind   = true;
                break;
            }
        }
        
        /* 没有找到左括号，输入不能作为函数执行 */
        if (false == bFind)
        {
            return false;
        }
    
        /* 判断左括号之前是否真能取得一个地址值 */
        if(sscanf(pcCmd,"0x%x",&dwAddr) <= 0)
            return false;
    }
    else
    {
        return false;
    }

    return true;
}
/**********************************************************************
* 函数名称：
* 功能描述：是否是所关注的section段
* 访问的表：
* 修改的表：
* 输入参数：分64/32位
* 输出参数：
* 返 回 值：
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
static bool is_concerned_section (char * pucSectionName)
{
    if(NULL == pucSectionName)
    {
        return false;
    }

    /* .text: 代码和常量 */
    /* .data: 已初始化数据 */
    /* .bss: 未初始化数据 */
    /* .sdata: 已初始化small数据，大小跟CPU体系有关 */
    /* .sbss: 未初始化small数据，大小跟CPU体系有关 */
    /* .tdata: 已初始化tls数据，ARM */
    /* .tbss: 未初始化tls数据，ARM */
    if(  (strcmp(pucSectionName,".text") == 0 )
       ||(strcmp(pucSectionName,".data") == 0 )
       ||(strcmp(pucSectionName,".bss") == 0 )
       ||(strcmp(pucSectionName,".sbss") == 0 )
       ||(strcmp(pucSectionName,".sdata") == 0 )
       ||(strcmp(pucSectionName,".tbss") == 0 )
       ||(strcmp(pucSectionName,".opd") == 0 )
       ||(strcmp(pucSectionName,".tdata") == 0)
       )
    {
        return true;
    }

    return false;
}
/**********************************************************************
* 函数名称：
* 功能描述：
* 访问的表：pList : pointer to list descriptor
* 修改的表：pNode : pointer to node to be added 
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
void sllPutAtTail(SL_LIST *pList,SL_NODE *pNode)
{
    pNode->next = NULL;

    if (pList->head == NULL)
    {
        pList->tail = pList->head = pNode;
    }
    else
    {
        pList->tail->next = pNode;
        pList->tail = pNode;
    }
}
/**********************************************************************
* 函数名称：
* 功能描述：
* 访问的表：hashId : id of hash table in which to put node
* 修改的表：pHashNode : pointer to hash node to put in hash table
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
int hashTblPut(HASH_ID  hashId,HASH_NODE   *pHashNode)
{
    int index;

    /* invoke hash table's hashing routine to get index into table */
    index = (* hashId->keyRtn) (hashId->elements, pHashNode, hashId->keyArg);

    /* add hash node to head of linked list */
    sllPutAtTail(&hashId->pHashTbl [index], pHashNode);

    return OK;
}
/**********************************************************************
* 函数名称：
* 功能描述：
* 访问的表：hashId : id of hash table from which to find node
* 修改的表：pMatchNode : pointer to hash node to match
* 输入参数：keyCmpArg: parameter to be passed to key comparator 
* 输出参数：
* 返 回 值：
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
HASH_NODE *hashTblFind(FAST HASH_ID hashId,HASH_NODE *pMatchNode,int  keyCmpArg)
{
    FAST HASH_NODE *pHNode;
    int             ix;

    /* invoke hash table's hashing routine to get index into table */

    ix = (* hashId->keyRtn) (hashId->elements, pMatchNode, hashId->keyArg);

    /* search linked list for above hash index and return matching hash node */

    pHNode = (HASH_NODE *) SLL_FIRST (&hashId->pHashTbl [ix]);

    while ((pHNode != NULL) 
          &&!((* hashId->keyCmpRtn) (pMatchNode, pHNode, keyCmpArg)))
    {
        pHNode = (HASH_NODE *) SLL_NEXT (pHNode);
    }

    return (pHNode);
}
/**********************************************************************
* 函数名称：
* 功能描述：
* 访问的表：symTblId : symbol table to add symbol to
* 修改的表：pSymbol : pointer to symbol to add 
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
int symTblAdd(SYMTAB_ID symTblId,SYMBOL *pSymbol)
{
    if((!symTblId->sameNameOk) 
        &&(hashTblFind (symTblId->nameHashId, &pSymbol->nameHNode,SYM_MASK_EXACT_TYPE) != NULL))
    {
        printf("%s line:%d S_symLib_NAME_CLASH \n",(char * )__func__,__LINE__);
        return ERROR;
    }
    
    hashTblPut (symTblId->nameHashId, &pSymbol->nameHNode);

    symTblId->nsymbols ++;/* increment symbol count */
    
    return OK;
}
/**********************************************************************
* 函数名称：
* 功能描述：添加符号
* 访问的表：无
* 修改的表：无
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
int symSAdd(SYMBOL *pSym)
{
    int length;
    SYMBOL *pSymbol;
    char   *symName;

    if (NULL == pSym) 
    {
        printf("%s line:%d pSym is null \n",(char * )__func__,__LINE__);
        return ERROR;
    }

    if (NULL == pSym->name) 
    {
        printf("%s line:%d pSym->name is null \n",(char * )__func__,__LINE__);
        return ERROR;
    }
        
    length = strlen (pSym->name);
    pSymbol = (SYMBOL *)malloc((unsigned)(sizeof(SYMBOL) + length + 1));

    if (NULL == pSymbol )
    {
        printf("%s line:%d malloc fail size:%d \n",(char * )__func__,__LINE__,(sizeof(SYMBOL) + length + 1));
        return ERROR;
    }

    *pSymbol = *pSym;
#ifdef SUPPORT_64BIT
    symName = (char *) ((unsigned long) pSymbol + sizeof (SYMBOL));
#else
    symName = (char *) ((unsigned) pSymbol + sizeof (SYMBOL));
#endif
    symName[length] = EOS;/* null terminate string */
    strncpy (symName, pSym->name, length);/* copy name into place */
    pSymbol->name  = symName;/* symbol name */
    
    if (symTblAdd (g_ModuleSymTbl, pSymbol) != OK)/* try to add symbol */
    {
        printf("%s line:%d symTblAdd fail \n",(char * )__func__,__LINE__);
        FREE(pSymbol); /* deallocate symbol if fail */
        return ERROR;
    }

    return OK;
}

#ifdef SUPPORT_64BIT

/**********************************************************************
* 函数名称：
* 功能描述：验证ELF文件头
* 访问的表：无
* 修改的表：无
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
PRIVATE int verify_elf_header(int fd, Elf64_Ehdr *pHdr)
{
    int iReadRv;
    int iHdrSize;
    iHdrSize = sizeof(*pHdr);
    iReadRv = read(fd, (CHAR*)pHdr, iHdrSize);
    if (iReadRv != iHdrSize)
    {
        printf("iReadRv = %d\n", iReadRv);
        printf("Erroneous header read\n");
        return ERROR;
    }
    /* Is it an ELF file */
    if (strncmp((CHAR*)pHdr->e_ident, (CHAR*)ELFMAG, SELFMAG) != 0)
    {
        return (ERROR);
    }
    if (BIG_ENDIAN == pHdr->e_ident[EI_DATA])
    {
        g_iEndianType = BIG_ENDIAN;
    }
    else if (LITTLE_ENDIAN == pHdr->e_ident[EI_DATA])
    {
        g_iEndianType = LITTLE_ENDIAN;
    }
    else
    {
        printf("unknown enidan type\n");
        return (ERROR);
    }
    return OK;
}

/**********************************************************************
* 函数名称：
* 功能描述：添加一个库的符号表
* 访问的表：
* 修改的表：
* 输入参数：分64/32位
* 输出参数：
* 返 回 值：
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
WORD64 add_one_module_sym(Elf64_Ehdr *elfHdr, int fd,T_ModuleSYMInfo *pT_ModuleSYMInfo)
{
    int i;
    WORD64 ret;
    SWORD64 iSymStrTabOffset = 0;   /* .strtab偏移 */
    WORD64 iSymStrTabSize = 0;     /* .strtab大小 */
    WORD64 iSymTabOffset = 0;      /* .symtab偏移 */
    WORD64 iSymTabSize = 0;         /* .symtab大小 */
    WORD64 iSymTabEntSize = 0;    /* .symtab中entry的大小 */
    WORD64 iSymTabEntryNum = 0;
    Elf64_Shdr shSecNameStrTab; /* .shstrtab section header */
    CHAR *pSecNameStrTab = NULL;  /* .shstrtab */
    CHAR *pSymStrTab = NULL;      /* .strtab */
    CHAR *pSymTab = NULL;            /* .symtab */
    SYMBOL *pSym = NULL;
    SYMBOL TempMemoryForSymbol;
    
    Elf64_Shdr * pSectionHeaderTbl = NULL;//节头表
    Elf64_Shdr * pSectionHdr = NULL;//段指针
    int     SectionHeaderTblLength = 0;//段头表的长度
    BYTE    bRet;
    pSym = &TempMemoryForSymbol;
    
    /* 找到.shstrtab section header */
    ret=lseek(fd, elfHdr->e_shoff + sizeof(Elf64_Shdr)*(elfHdr->e_shstrndx),SEEK_SET);
    if(-1==ret)
    {
        printf("%s line:%d lseek error \n",(char * )__func__,__LINE__);
        bRet = ERROR;
        goto BUILD_ERROR;
    }
    ret=read(fd, &shSecNameStrTab, sizeof(Elf64_Shdr));
    if ( -1 == ret||0 == ret)
    {
        printf("%s line:%d read error \n",(char * )__func__,__LINE__);
        bRet = ERROR;
        goto BUILD_ERROR;
    }    
    B2L4 (shSecNameStrTab.sh_name);
    B2L4 (shSecNameStrTab.sh_type);
    B2L8 (shSecNameStrTab.sh_offset);
    B2L8 (shSecNameStrTab.sh_addr);
    B2L8 (shSecNameStrTab.sh_addralign);
    B2L8 (shSecNameStrTab.sh_size);
    B2L8 (shSecNameStrTab.sh_entsize);

    /* 根据.shstrtab section header得到.shstrtab section的偏移和大小 */
    /* 从而将.shstrtab section读入pSecNameStrTab */
    pSecNameStrTab = (CHAR*)malloc(shSecNameStrTab.sh_size);
    if (NULL == pSecNameStrTab)
    {
        printf("%s line:%d malloc fail \n",(char * )__func__,__LINE__);
        bRet = ERROR;
        goto BUILD_ERROR;
    }
    ret=lseek(fd, shSecNameStrTab.sh_offset, SEEK_SET);
    if(-1==ret)
    {
        printf("%s line:%d lseek fail \n",(char * )__func__,__LINE__);
        bRet = ERROR;
        goto BUILD_ERROR;
    }
    ret=read(fd, pSecNameStrTab, shSecNameStrTab.sh_size);
    if ( -1 == ret||0 == ret)
    {
        printf("%s line:%d read fail \n",(char * )__func__,__LINE__);
        bRet = ERROR;
        goto BUILD_ERROR;
    } 
    /* 遍历各个section header，得到.strtab和.symtab的偏移和大小 */
    /* 其间各个section的名称都可以在.shstrtab section中找到 */
    ret=lseek(fd, elfHdr->e_shoff, SEEK_SET);
    if(-1==ret)
    {
        printf("%s line:%d lseek fail \n",(char * )__func__,__LINE__);
        bRet = ERROR;
        goto BUILD_ERROR;
    }
        /*把节头表从elf文件中读出*/
    SectionHeaderTblLength = (elfHdr->e_shnum)*sizeof(Elf64_Shdr);
    
    pSectionHeaderTbl = (Elf64_Shdr * )malloc(SectionHeaderTblLength);
    if (NULL == pSectionHeaderTbl)
    {
        printf("%s line:%d malloc :%d fail \n",(char * )__func__,__LINE__,SectionHeaderTblLength);
        bRet = ERROR;
        goto BUILD_ERROR;

    }
    ret=read(fd, pSectionHeaderTbl, SectionHeaderTblLength);
    if ( -1 == ret||0 == ret)
    {
        printf("%s line:%d read fail \n",(char * )__func__,__LINE__);
        bRet = ERROR;
        goto BUILD_ERROR;
    } 
    for (i = 0; i < elfHdr->e_shnum; i++)
    {
        pSectionHdr = pSectionHeaderTbl + i; 
        B2L4 (pSectionHdr->sh_name);
        B2L4 (pSectionHdr->sh_type);
        B2L8 (pSectionHdr->sh_offset);
        B2L8 (pSectionHdr->sh_addr);
        B2L8 (pSectionHdr->sh_addralign);
        B2L8 (pSectionHdr->sh_size);
        B2L8 (pSectionHdr->sh_entsize);
        
        /* 找到.strtab section的偏移和大小 */
        if ((SHT_STRTAB == pSectionHdr->sh_type) && (0 == strncmp(".strtab", &pSecNameStrTab[pSectionHdr->sh_name], 7)))
        {
            iSymStrTabOffset = pSectionHdr->sh_offset; /* 节区的第一个字节与文件头之间的偏移 */
            iSymStrTabSize = pSectionHdr->sh_size;      /* 节区的长度（字节数） */
            printf("%s line:%d find strtab section, sh_offset:%d,sh_size: %d \n",(char * )__func__,__LINE__,iSymStrTabOffset,iSymStrTabSize);
            continue;
        }
        /* 找到.symtab section的偏移和大小 */
        if ((SHT_SYMTAB == pSectionHdr->sh_type) && (0 == strncmp(".symtab", &pSecNameStrTab[pSectionHdr->sh_name], 7)))
        {
            iSymTabOffset = pSectionHdr->sh_offset;  /* 节区的第一个字节与文件头之间的偏移 */
            iSymTabSize = pSectionHdr->sh_size;       /* 节区的长度（字节数） */
            iSymTabEntSize = pSectionHdr->sh_entsize; /* 某些节区中包含固定大小的项目，如符号表。对于这类节区，此成员给出每个表项的长度字节数。 */
            continue;
        }
    }
    
    /* 读出.strtab section至pSymStrTable */
    pSymStrTab = (CHAR*)malloc(iSymStrTabSize);
    if (NULL == pSymStrTab)
    {
        printf("%s line:%d malloc :%d fail \n",(char * )__func__,__LINE__,iSymStrTabSize);
        bRet = ERROR;
        goto BUILD_ERROR;

    }
    ret=lseek(fd, iSymStrTabOffset, SEEK_SET);
    if(-1==ret)
    {
        printf("%s line:%d lseek  fail \n",(char * )__func__,__LINE__);
        bRet = ERROR;
        goto BUILD_ERROR;
    }
    ret=read(fd, pSymStrTab, iSymStrTabSize);
    if ( -1 == ret||0 == ret)
    {
        printf("%s line:%d read fail \n",(char * )__func__,__LINE__);
        bRet = ERROR;
        goto BUILD_ERROR;
    }
    /* 读出.symtab section至pSymTab */
    pSymTab = (CHAR*)malloc(iSymTabSize);
    if (NULL == pSymTab)
    {
        printf("%s line:%d malloc :%d fail \n",(char * )__func__,__LINE__,iSymTabSize);
        bRet = ERROR;
        goto BUILD_ERROR;

    }
    ret=lseek(fd, iSymTabOffset, SEEK_SET);
    if(-1==ret)
    {
        printf("%s line:%d lseek fail \n",(char * )__func__,__LINE__);
        bRet = ERROR;
        goto BUILD_ERROR;
    }
    ret=read(fd, pSymTab, iSymTabSize);
    if ( -1 == ret||0 == ret)
    {
        printf("%s line:%d read  fail \n",(char * )__func__,__LINE__);
        bRet = ERROR;
        goto BUILD_ERROR;
    }
    /* 下面进入符号表提取符号： */
    if(iSymTabEntSize != 0)
    {
        iSymTabEntryNum = iSymTabSize / iSymTabEntSize;  /* .symtab中entry的数量 */
    }
    printf("[%s line:%d] module:%s have %d symbol\n",(char * )__func__,__LINE__,
                                                     pT_ModuleSYMInfo->pcModulePath,iSymTabEntryNum);
    
    /* 用在循环体中，指向.symtab中当前处理的entry */
    Elf64_Sym *pSymEnt = (Elf64_Sym*)pSymTab; 
    
    pSym->name  = NULL;
    pSym->group = pT_ModuleSYMInfo;
    pT_ModuleSYMInfo->TotalSymbolNum = 0;

    for (i = 0; i < iSymTabEntryNum; i++)
    {
        if  ((STT_FUNC == ELF64_ST_TYPE(pSymEnt->st_info) || (STT_OBJECT == ELF64_ST_TYPE(pSymEnt->st_info))) 
            &&((pSymEnt->st_shndx)< elfHdr->e_shnum)    
            &&(true == is_concerned_section(pSecNameStrTab+(pSectionHeaderTbl+(pSymEnt->st_shndx))->sh_name)))
        {
            pSym->name = &pSymStrTab[pSymEnt->st_name];

            /*如果是动态库，需要加上加载地址*/
            if(pT_ModuleSYMInfo->ModuleType == ET_DYN)
            {
                pSym->value = (CHAR*)pSymEnt->st_value + pT_ModuleSYMInfo->ModuleLoadAddress;
            }
            else
            {
                pSym->value = (CHAR*)pSymEnt->st_value;
            }

            pSym->type = pSymEnt->st_info;
            pSym->size = pSymEnt->st_size;
            
            if (symSAdd(pSym) != OK)
            {
                printf("%s line:%d call symSAdd fail \n",(char * )__func__,__LINE__);
            }
            else
            {
                (pT_ModuleSYMInfo->TotalSymbolNum)++;
            }
        }
        pSymEnt++;
    }/* end for loop */

    bRet = OK;
    
BUILD_ERROR:
    /* 释放堆内存 */
    FREE((BYTE *)pSecNameStrTab);  
    FREE((BYTE *)pSymTab);       
    FREE((BYTE *)pSymStrTab);       
    FREE((BYTE *)pSectionHeaderTbl);       
    return bRet;
}
#else

/**********************************************************************
* 函数名称：
* 功能描述：验证ELF文件头
* 访问的表：无
* 修改的表：无
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
PRIVATE int verify_elf_header(int fd, Elf32_Ehdr *pHdr)
{
    int iReadRv;
    int iHdrSize;
    
    iHdrSize = sizeof(*pHdr);
    iReadRv = read(fd, (CHAR*)pHdr, iHdrSize);
    
    if (iReadRv != iHdrSize)
    {
        printf("iReadRv = %d\n", iReadRv);
        printf("Erroneous header read\n");
        return (ERROR);
    }
    /* Is it an ELF file */
    if (strncmp((CHAR*)pHdr->e_ident, (CHAR*)ELFMAG, SELFMAG) != 0)
    {
        return ERROR;
    }
    if (BIG_ENDIAN == pHdr->e_ident[EI_DATA])
    {
        g_iEndianType = BIG_ENDIAN;
    }
    else if (LITTLE_ENDIAN == pHdr->e_ident[EI_DATA])
    {
        g_iEndianType = LITTLE_ENDIAN;
    }
    else
    {
        printf("unknown enidan type\n");
        return ERROR;
    }
    return OK;
}
/**********************************************************************
* 函数名称：
* 功能描述：
* 访问的表：无
* 修改的表：无
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
WORD64 add_one_module_sym(Elf32_Ehdr *elfHdr, int fd,T_ModuleSYMInfo *pT_ModuleSYMInfo)
{
    int i;
    int ret;
    int iSymStrTabOffset = 0;   /* .strtab偏移 */
    int iSymStrTabSize = 0;     /* .strtab大小 */
    int iSymTabOffset = 0;      /* .symtab偏移 */
    int iSymTabSize = 0;         /* .symtab大小 */
    int iSymTabEntSize = 0;    /* .symtab中entry的大小 */
    int iSymTabEntryNum = 0;
    Elf32_Shdr shSecNameStrTab; /* .shstrtab section header */
    CHAR *pSecNameStrTab = NULL;  /* .shstrtab */
    CHAR *pSymStrTab = NULL;      /* .strtab */
    CHAR *pSymTab = NULL;            /* .symtab */
    SYMBOL *pSym = NULL;
    SYMBOL TempMemoryForSymbol;
    
    Elf32_Shdr * pSectionHeaderTbl = NULL;//节头表
    Elf32_Shdr * pSectionHdr = NULL;//段指针
    int     SectionHeaderTblLength = 0;//段头表的长度
     
    pSym = &TempMemoryForSymbol;
    
    /* 找到.shstrtab section header */
    ret=lseek(fd, elfHdr->e_shoff + sizeof(Elf32_Shdr)*(elfHdr->e_shstrndx),SEEK_SET);
    if(-1==ret)
    {
        printf("%s line:%d lseek error \n",(char * )__func__,__LINE__);
        goto BUILD_ERROR;
    }
    ret=read(fd, &shSecNameStrTab, sizeof(Elf32_Shdr));
    if ( -1 == ret||0 == ret)
    {
        printf("%s line:%d read error \n",(char * )__func__,__LINE__);
        goto BUILD_ERROR;
    }    
    B2L4 (shSecNameStrTab.sh_name);
    B2L4 (shSecNameStrTab.sh_type);
    B2L4 (shSecNameStrTab.sh_offset);
    B2L4 (shSecNameStrTab.sh_addr);
    B2L4 (shSecNameStrTab.sh_addralign);
    B2L4 (shSecNameStrTab.sh_size);
    B2L4 (shSecNameStrTab.sh_entsize);

    /* 根据.shstrtab section header得到.shstrtab section的偏移和大小 */
    /* 从而将.shstrtab section读入pSecNameStrTab */
    pSecNameStrTab = (CHAR*)malloc(shSecNameStrTab.sh_size);
    if (NULL == pSecNameStrTab)
    {
        printf("%s line:%d malloc fail \n",(char * )__func__,__LINE__);
        goto BUILD_ERROR;
    }
    ret=lseek(fd, shSecNameStrTab.sh_offset, SEEK_SET);
    if(-1==ret)
    {
        printf("%s line:%d lseek fail \n",(char * )__func__,__LINE__);
        goto BUILD_ERROR;
    }
    ret=read(fd, pSecNameStrTab, shSecNameStrTab.sh_size);
    if ( -1 == ret||0 == ret)
    {
        printf("%s line:%d read fail \n",(char * )__func__,__LINE__);
        goto BUILD_ERROR;
    } 
    /* 遍历各个section header，得到.strtab和.symtab的偏移和大小 */
    /* 其间各个section的名称都可以在.shstrtab section中找到 */
    ret=lseek(fd, elfHdr->e_shoff, SEEK_SET);
    if(-1==ret)
    {
        printf("%s line:%d lseek fail \n",(char * )__func__,__LINE__);
        goto BUILD_ERROR;
    }

    /*把节头表从elf文件中读出*/
    SectionHeaderTblLength = (elfHdr->e_shnum)*sizeof(Elf32_Shdr);
    
    pSectionHeaderTbl = (Elf32_Shdr * )malloc(SectionHeaderTblLength);
    if (NULL == pSectionHeaderTbl)
    {
        printf("%s line:%d malloc :%d fail \n",(char * )__func__,__LINE__,SectionHeaderTblLength);
        goto BUILD_ERROR;

    }
    ret=read(fd, pSectionHeaderTbl, SectionHeaderTblLength);
    if ( -1 == ret||0 == ret)
    {
        printf("%s line:%d read fail \n",(char * )__func__,__LINE__);
        goto BUILD_ERROR;
    } 
    for (i = 0; i < elfHdr->e_shnum; i++)
    {
        pSectionHdr = pSectionHeaderTbl + i; 
        B2L4 (pSectionHdr->sh_name);
        B2L4 (pSectionHdr->sh_type);
        B2L4 (pSectionHdr->sh_offset);
        B2L4 (pSectionHdr->sh_addr);
        B2L4 (pSectionHdr->sh_addralign);
        B2L4 (pSectionHdr->sh_size);
        B2L4 (pSectionHdr->sh_entsize);

        /* 找到.strtab section的偏移和大小 */
        if ((SHT_STRTAB == pSectionHdr->sh_type) && (0 == strncmp(".strtab", &pSecNameStrTab[pSectionHdr->sh_name], 7)))
        {
            iSymStrTabOffset = pSectionHdr->sh_offset; /* 节区的第一个字节与文件头之间的偏移 */
            iSymStrTabSize = pSectionHdr->sh_size;      /* 节区的长度（字节数） */
            continue;
        }
        /* 找到.symtab section的偏移和大小 */
        if ((SHT_SYMTAB == pSectionHdr->sh_type) && (0 == strncmp(".symtab", &pSecNameStrTab[pSectionHdr->sh_name], 7)))
        {
            iSymTabOffset = pSectionHdr->sh_offset;  /* 节区的第一个字节与文件头之间的偏移 */
            iSymTabSize = pSectionHdr->sh_size;       /* 节区的长度（字节数） */
            iSymTabEntSize = pSectionHdr->sh_entsize; /* 某些节区中包含固定大小的项目，如符号表。对于这类节区，此成员给出每个表项的长度字节数。 */
            continue;
        }
    }
    
    /* 读出.strtab section至pSymStrTable */
    pSymStrTab = (CHAR*)malloc(iSymStrTabSize);
    if (NULL == pSymStrTab)
    {
        printf("%s line:%d malloc :%d fail \n",(char * )__func__,__LINE__,iSymStrTabSize);
        goto BUILD_ERROR;

    }
    ret=lseek(fd, iSymStrTabOffset, SEEK_SET);
    if(-1==ret)
    {
        printf("%s line:%d lseek  fail \n",(char * )__func__,__LINE__);
        goto BUILD_ERROR;
    }
    ret=read(fd, pSymStrTab, iSymStrTabSize);
    if ( -1 == ret||0 == ret)
    {
        printf("%s line:%d read fail \n",(char * )__func__,__LINE__);
        goto BUILD_ERROR;
    }
    /* 读出.symtab section至pSymTab */
    pSymTab = (CHAR*)malloc(iSymTabSize);
    if (NULL == pSymTab)
    {
        printf("%s line:%d malloc :%d fail \n",(char * )__func__,__LINE__,iSymTabSize);
        goto BUILD_ERROR;
    }
    ret=lseek(fd, iSymTabOffset, SEEK_SET);
    if(-1==ret)
    {
        printf("%s line:%d lseek fail \n",(char * )__func__,__LINE__);
        goto BUILD_ERROR;
    }
    ret=read(fd, pSymTab, iSymTabSize);
    if ( -1 == ret||0 == ret)
    {
        printf("%s line:%d read  fail \n",(char * )__func__,__LINE__);
        goto BUILD_ERROR;
    }
    /* 下面进入符号表提取符号： */
    if(iSymTabEntSize != 0)
    {
        iSymTabEntryNum = iSymTabSize / iSymTabEntSize;  /* .symtab中entry的数量 */
    }
    printf("[info]%s line:%d module:%s have %d symbol\n",(char * )__func__,__LINE__,
                                                     pT_ModuleSYMInfo->pcModulePath,iSymTabEntryNum);
    
    /* 用在循环体中，指向.symtab中当前处理的entry */
    Elf32_Sym *pSymEnt = (Elf32_Sym*)pSymTab; 
    
    pSym->name  = NULL;
    
    pSym->group = pT_ModuleSYMInfo;
    pT_ModuleSYMInfo->TotalSymbolNum = 0;

    for (i = 0; i < iSymTabEntryNum; i++)
    {
        if  ((STT_FUNC == ELF32_ST_TYPE(pSymEnt->st_info) || (STT_OBJECT == ELF32_ST_TYPE(pSymEnt->st_info))) 
            &&((pSymEnt->st_shndx)< elfHdr->e_shnum)    
            &&(true == is_concerned_section(pSecNameStrTab+(pSectionHeaderTbl+(pSymEnt->st_shndx))->sh_name)))
        {
            pSym->name = &pSymStrTab[pSymEnt->st_name];

            /*如果是动态库，需要加上加载地址*/
            if(pT_ModuleSYMInfo->ModuleType == ET_DYN)
            {
                pSym->value = (CHAR*)pSymEnt->st_value + pT_ModuleSYMInfo->ModuleLoadAddress;
            }
            else
            {
                pSym->value = (CHAR*)pSymEnt->st_value;
            }
            pSym->type = pSymEnt->st_info;
            pSym->size = pSymEnt->st_size;
            
            if (symSAdd(pSym) != OK)
            {
                printf("%s line:%d call sym_SAdd fail \n",(char * )__func__,__LINE__);
            }
            else
            {
                (pT_ModuleSYMInfo->TotalSymbolNum)++;
            }
        }
        pSymEnt++;
    }/* end for loop */

    /* 释放堆内存 */
    FREE((BYTE *)pSecNameStrTab);  
    FREE((BYTE *)pSymTab);       
    FREE((BYTE *)pSymStrTab);       
    FREE((BYTE *)pSectionHeaderTbl);       
    return OK;
    
BUILD_ERROR:
    /* 释放堆内存 */
    FREE((BYTE *)pSecNameStrTab);  
    FREE((BYTE *)pSymTab);       
    FREE((BYTE *)pSymStrTab);       
    FREE((BYTE *)pSectionHeaderTbl);       
    return ERROR;
}

#endif
/**********************************************************************
* 函数名称：
* 功能描述：链表初始化
* 访问的表：
* 修改的表：
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
int module_sym_sllInit(SL_LIST *pList)
{
    pList->head  = NULL;/* initialize list */
    pList->tail  = NULL;

    return OK;
}
/**********************************************************************
* 函数名称：
* 功能描述：哈希表初始化
* 访问的表：
* 修改的表：
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
int module_sym_hash_tbl_init(HASH_TBL *pHashTbl,SL_LIST *pTblMem,int sizeLog2,FUNCPTR keyCmpRtn,FUNCPTR keyRtn,int keyArg)
{
    FAST int ix;

    pHashTbl->elements  = 1 << sizeLog2;/* store number of elements 256*/
    pHashTbl->keyCmpRtn = keyCmpRtn;/* store comparator routine */
    pHashTbl->keyRtn    = keyRtn;/* store hashing function */
    pHashTbl->keyArg    = keyArg;/* store hashing function arg */
    pHashTbl->pHashTbl  = pTblMem;

    /* initialize all of the linked list heads in the table */

    for (ix = 0; ix < pHashTbl->elements; ix++)
        module_sym_sllInit (&pHashTbl->pHashTbl[ix]);

    return OK;
}
/**********************************************************************
* 函数名称：
* 功能描述：创建哈希表
* 访问的表：
* 修改的表：
* 输入参数：HASH_TBL + 256 * node
* 输出参数：
* 返 回 值：
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
HASH_ID module_sym_hash_tbl_create(int sizeLog2, FUNCPTR  keyCmpRtn, FUNCPTR keyRtn,int keyArg)
{
    unsigned extra  = (1 << sizeLog2) * sizeof (SL_LIST);
    HASH_ID hashId;
    SL_LIST *pList;

    hashId  = (HASH_ID)malloc(sizeof(HASH_TBL)+extra);
    if (hashId != NULL)
    {
        pList = (SL_LIST *)(hashId+1);
        module_sym_hash_tbl_init(hashId, pList, sizeLog2, keyCmpRtn, keyRtn, keyArg);
    }
    else
    {
        printf("%s line:%d call maloc failed \n",(char * )__func__,__LINE__);
        return NULL;
    }

    return hashId;/* return the hash id */
}
/**********************************************************************
* 函数名称：
* 功能描述：创建符号表
* 访问的表：hashSizeLog2:  size of hash table as a power of 2
* 修改的表：sameNameOk:   allow 2 symbols of same name & type
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：
* 修改日期      版本号  修改人      修改内容
************************************************************************/
SYMTAB_ID module_sym_tbl_create(int hashSizeLog2,bool sameNameOk)
{
    SYMTAB_ID symTblId = (SYMTAB_ID) malloc(sizeof(SYMTAB));

    if (symTblId != NULL)
    {
        symTblId->nameHashId = module_sym_hash_tbl_create (hashSizeLog2,
                                                     (FUNCPTR) sym_key_cmp_name,
                                                     (FUNCPTR) sym_hFunc_name,
                                                     SYM_HFUNC_SEED);

        if (symTblId->nameHashId == NULL)
        {
            printf("%s line:%d  maloc failed \n",(char * )__func__,__LINE__);
            FREE((char *) symTblId);
            return NULL;
        }
        else
        {
            symTblId->sameNameOk = sameNameOk;/* name clash policy */
            symTblId->nsymbols   = 0;/* initial number of syms */
        }
    }
    else
    {
        printf("%s line:%d  maloc failed \n",(char * )__func__,__LINE__);
        return NULL;
    }
    return symTblId;/* return the symbol table ID */
}
/******************************************************************************
* 函数名称：
* 功能描述：
* 访问的表：无
* 修改的表：无
* 输入参数：
* 输出参数：无
* 返 回 值：               
* 其它说明：
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------------
******************************************************************************/
T_ModuleSYMInfo *  find_module_ptr_by_path(CHAR * LibPath)
{
    T_ModuleSYMInfo * pT_ModuleSYMInfo= NULL;
    T_ModuleSYMInfo * ptemp = NULL;
        
    if(NULL == LibPath)
    {
        printf("%s line:%d LibPath is NULL \n",(char * )__func__,__LINE__);
        return NULL;
    }
    else
    {
        printf("%s line:%d LibPath:%s \n",(char * )__func__,__LINE__,LibPath);
    }

    if(NULL == g_pT_ModuleSYMInfo_Head)
    {
        printf("There is no module load \n");
        return NULL;
    }
    pT_ModuleSYMInfo = g_pT_ModuleSYMInfo_Head;
    do
    {   
        if(0 == strcmp(pT_ModuleSYMInfo->pcModulePath,LibPath))
            return pT_ModuleSYMInfo;

        pT_ModuleSYMInfo = pT_ModuleSYMInfo->pModuleSYMNext;
        
    }while(pT_ModuleSYMInfo != g_pT_ModuleSYMInfo_Head);
    
    return ptemp;
}
/**********************************************************************
* 函数名称：
* 功能描述：添加到模块双向链表中
* 访问的表：无
* 修改的表：无
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
* 2011/07/25    V1.0    陈林海    创建
************************************************************************/
bool add_to_module_table(T_ModuleSYMInfo * pT_ModuleSYMInfo)
{
    T_ModuleSYMInfo * pLast = NULL;
    
    if(NULL == pT_ModuleSYMInfo)
    {
        printf("%s line:%d pT_ModuleSYMInfo is null  \n",(char * )__func__,__LINE__);
        return false;
    }
    pT_ModuleSYMInfo->pModuleSYMNext = NULL;
    pT_ModuleSYMInfo->pModuleSYMPrev = NULL;
    
    if(NULL == g_pT_ModuleSYMInfo_Head)
    {
        pT_ModuleSYMInfo->pModuleSYMNext = pT_ModuleSYMInfo;
        pT_ModuleSYMInfo->pModuleSYMPrev = pT_ModuleSYMInfo;
        g_pT_ModuleSYMInfo_Head = pT_ModuleSYMInfo;
    }
    else
    {   
        pLast = g_pT_ModuleSYMInfo_Head->pModuleSYMPrev;
        pT_ModuleSYMInfo->pModuleSYMPrev = pLast;
        pT_ModuleSYMInfo->pModuleSYMNext = pLast->pModuleSYMNext;
        pLast->pModuleSYMNext->pModuleSYMPrev = pT_ModuleSYMInfo;
        pLast->pModuleSYMNext = pT_ModuleSYMInfo;
    }
    
    return true;
}

#define ADDR_64_BIT_DATA_LEN 16
/******************************************************************************
* 函数名称：
* 功能描述：从MAPS文件中获取模块路径和加载地址
* 访问的表：无
* 修改的表：无
* 输入参数：
* 输出参数：无
* 返 回 值：               
* 其它说明：
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------------
******************************************************************************/
int parse_maps()
{   
    int ipid;
    CHAR achPath[60];
    CHAR achPid[10];
    CHAR achLine[200];
    CHAR achAddr[ADDR_64_BIT_DATA_LEN+2];
    char * s ="r-xp";
    T_ModuleSYMInfo * pT_ModuleSYMInfo = NULL;

    FILE *fd;
    char * puctemp = NULL;
    
    memset(achPath, 0, 60);
    memset(achPid, 0, 10);
    memset(achLine, EOS, sizeof(achLine));
    memset(achAddr, 0, sizeof(achAddr));

    ipid = g_dwCurProcessId;

    sprintf(achPid, "%ld", ipid);
    strcpy(achPath, "/proc/");
    strcat(achPath, achPid);
    strcat(achPath, "/maps");
    
    fd = fopen(achPath, "r");
    if(NULL == fd)
    {
        printf("%s line:%d fd is NULL achPath:%s \n",(char * )__func__,__LINE__,achPath);
        return ERROR_UNKNOWN;
    }
    /*循环读取proc/pid/maps文件内容*/
    while(fgets(achLine, sizeof(achLine),fd)!=NULL)
    {
         printf("%s line:%d achLine:%s \n",(char * )__func__,__LINE__,achLine);
        /*代码段*/
        if(strstr(achLine,s) != NULL)
        {
            pT_ModuleSYMInfo = (T_ModuleSYMInfo *)malloc(sizeof(T_ModuleSYMInfo));
            if(NULL == pT_ModuleSYMInfo)
            {
                printf("%s line:%d malloc failed \n",(char * )__func__,__LINE__);
                fclose(fd);
                return ERROR_UNKNOWN;
            }
            memset(pT_ModuleSYMInfo,0,sizeof(T_ModuleSYMInfo));
            memset(pT_ModuleSYMInfo->pcModulePath, EOS, 120);
            pT_ModuleSYMInfo->pModuleSYMNext = NULL;
            pT_ModuleSYMInfo->pModuleSYMPrev = NULL;
            
            memset(achAddr, 0, sizeof(achAddr));
            strncpy(achAddr, achLine, ADDR_64_BIT_DATA_LEN);
            achAddr[ADDR_64_BIT_DATA_LEN]='\0';
            pT_ModuleSYMInfo->ModuleLoadAddress = strtoul(achAddr, NULL, 16);

            memset(achAddr, 0 , sizeof(achAddr));
            strncpy(achAddr, strchr(achLine,'-') + 1, ADDR_64_BIT_DATA_LEN);
            achAddr[ADDR_64_BIT_DATA_LEN] = '\0';
            
            pT_ModuleSYMInfo->CodeEndAddr = strtoul(achAddr, NULL, 16);
            
            /*查找模块加载路径*/
            if((puctemp = strstr(achLine,"/"))== NULL)
            {
                #ifndef SUPPORT_64BIT
                if((strstr(achLine,"vdso"))== NULL)
                {
                    printf("%s line:%d %s \n",(char * )__func__,__LINE__,achLine);
                    FREE(pT_ModuleSYMInfo);
                    fclose(fd);
                    return ERROR_UNKNOWN;  
                }
                else/*忽略vdso*/
                #endif    
                {
                    FREE(pT_ModuleSYMInfo);
                    memset(achLine, EOS, sizeof(achLine));
                    continue;
                }
            }
            /*过滤路径后面的空格*/
            if(strlen(puctemp)>= MODULE_PATH_LENGTH)
            {
                printf("%s line:%d %s \n",(char * )__func__,__LINE__,achLine);
                FREE(pT_ModuleSYMInfo);
                fclose(fd);
                return ERROR_UNKNOWN;  
            }
            else
            {
                CHAR * cp = puctemp+strlen(puctemp)-1;
                while (*cp == '\n')
                {
                    cp--;
                }
                *(cp+1) = EOS;
                    
                strcpy(pT_ModuleSYMInfo->pcModulePath,puctemp);
            }
            #ifdef SUPPORT_64BIT
            if(find_module_ptr_by_path(pT_ModuleSYMInfo->pcModulePath))
            {
                printf("%s line:%d  Module:%s exist\n",(char * )__func__,__LINE__,pT_ModuleSYMInfo->pcModulePath);
                FREE(pT_ModuleSYMInfo);
                puctemp = NULL;
                memset(achLine, EOS, sizeof(achLine));
                continue;
            }
            #endif    
            /*把模块信息插入到全局表中*/
            if(false == add_to_module_table(pT_ModuleSYMInfo))
            {
                printf("%s line:%d call add_to_module_table failed \n",(char * )__func__,__LINE__);
                FREE(pT_ModuleSYMInfo);
                fclose(fd);
                return ERROR_UNKNOWN;  
            }
            
            printf("%s line:%d  Module:%s LoadAddress:0x%lx\n",
                                      (char * )__func__,__LINE__,
                                      pT_ModuleSYMInfo->pcModulePath,
                                      pT_ModuleSYMInfo->ModuleLoadAddress);
            puctemp = NULL;
            memset(achLine, EOS, sizeof(achLine));
        } 
        if(feof(fd))
        {
            break;
        }
    }
    fclose(fd);

    return SUCCESS;
}
/**********************************************************************
* 函数名称：
* 功能描述：添加一个模块
* 访问的表：无
* 修改的表：无
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
int deal_one_module_add(T_ModuleSYMInfo * pT_ModuleSYMInfo)
{
    int fd;
#ifdef SUPPORT_64BIT
     Elf64_Ehdr elfHdr;
#else
     Elf32_Ehdr elfHdr;
#endif
    if(NULL == pT_ModuleSYMInfo)
    {
        printf("%s line:%d arg is null \n",(char * )__func__,__LINE__);
        return ERROR;
    }
    fd = open(pT_ModuleSYMInfo->pcModulePath, S_IRUSR);
    if (fd < 0)
    {
        printf("%s line:%d open :%s failed %d %s \n",(char * )__func__,__LINE__,pT_ModuleSYMInfo->pcModulePath,errno,strerror(errno));
        return ERROR;
    }
    else
    {
        printf("%s line:%d open :%s success \n",(char * )__func__,__LINE__,pT_ModuleSYMInfo->pcModulePath);
    }

    if (OK != verify_elf_header (fd, &elfHdr))
    {
        printf("%s line:%d verify_elf_header fail \n",(char * )__func__,__LINE__);
        close(fd);
        return ERROR;
    }

    B2L2 (elfHdr.e_type);
    B2L2 (elfHdr.e_machine);
	
    if(0 == g_cpu_Family)
    {
        g_cpu_Family = elfHdr.e_machine;
    }
    
#ifdef SUPPORT_64BIT
    B2L8 (elfHdr.e_shoff);
#else
    B2L4 (elfHdr.e_shoff);
#endif
    B2L2 (elfHdr.e_shentsize);
    B2L2 (elfHdr.e_shnum); 
    B2L2 (elfHdr.e_shstrndx);
    
    if ((elfHdr.e_type != ET_DYN) && (elfHdr.e_type != ET_EXEC))
    {
        printf("%s line:%d file:%s format error \n",(char * )__func__,__LINE__,pT_ModuleSYMInfo->pcModulePath);
        close(fd);
        return (ERROR);
    }
    pT_ModuleSYMInfo->ModuleType = elfHdr.e_type;

    if (OK != add_one_module_sym(&elfHdr, fd,pT_ModuleSYMInfo))
    {
        printf("%s line:%d add_one_module_sym fail \n",(char * )__func__,__LINE__);
        close(fd);
        return ERROR;
    }
    
    close(fd);
    return OK;
}

/**********************************************************************
* 函数名称：
* 功能描述：模块初始化
* 访问的表：
* 修改的表：
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：无
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
bool module_sym_init(VOID)
{
    T_ModuleSYMInfo * pT_ModuleSYMInfo= NULL;
    
    /*初始化符号表，初始化后，当前符号表为空表，后续通过ADD添加*/
    g_ModuleSymTbl = module_sym_tbl_create (SYM_TBL_HASH_SIZE_LOG2, true);
    if(NULL == g_ModuleSymTbl)
    {
        printf("%s line:%d g_ModuleSymTbl is null  \n",(char * )__func__,__LINE__);
        return false;
    }
    /*从maps文件中获取已经加载的模块路径、起始地址*/
    if(ERROR_UNKNOWN == parse_maps())
    {
        printf("%s line:%d call parse_maps error \n",(char * )__func__,__LINE__);
        return false;
    }
    if(NULL == g_pT_ModuleSYMInfo_Head)
    {
        printf("%s line:%d There is no module load \n",(char * )__func__,__LINE__);
        return true;
    }
    /* 初始化已经加载的模块符号添加到符号表中*/
    pT_ModuleSYMInfo = g_pT_ModuleSYMInfo_Head;
    do
    {   
        if(ERROR == deal_one_module_add(pT_ModuleSYMInfo))
        {
            printf("%s line:%d call deal_one_module_add failed load address :0x%lx path:%s\n",
                     (char * )__func__,__LINE__,
                     pT_ModuleSYMInfo->ModuleLoadAddress,
                     pT_ModuleSYMInfo->pcModulePath);
        }
        pT_ModuleSYMInfo = pT_ModuleSYMInfo->pModuleSYMNext;
    }while(pT_ModuleSYMInfo != g_pT_ModuleSYMInfo_Head);
    
    return true;
}
/**********************************************************************
* 函数名称：
* 功能描述：
* 访问的表：symTblId : symbol table ID
* 修改的表：name : name to search for 
* 输入参数：value : value of symbol to search for
* 输出参数：type : symbol type
* 返 回 值：mask : type bits that matter
* 其它说明：pSymbolId : where to return id of matching symbol
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
int symFindSymbol(SYMTAB_ID symTblId, char * name,void * value,BYTE type,BYTE mask,SYMBOL_ID * pSymbolId)
{
    HASH_NODE *         pNode;      /* node in symbol hash table */
    SYMBOL              keySymbol;  /* dummy symbol for search by name */
    int                 index;      /* counter for search by value */
    SYMBOL *            pSymbol;    /* current symbol, search by value */
    SYMBOL *            pBestSymbol = NULL; 
    /* symbol with lower value, matching type */
    char *      pUnder;     /* string for _text, etc., check */
    void *      bestValue = NULL; 
    /* current value of symbol with matching type */ 

    if (NULL == symTblId  || pSymbolId == NULL)
    {
        printf("%s line:%d symTblId is NULL  \n",(char * )__func__,__LINE__);
        return ERROR; 
    }

    if (name != NULL) 
    {
        /* Search by name or by name and type: */
        /* fill in keySymbol */
        keySymbol.name = name;/* match this name */
        keySymbol.type = type;/* match this type */

        pNode = hashTblFind (symTblId->nameHashId, &keySymbol.nameHNode, (int)mask);
        
        if (pNode == NULL)
        {
            printf("%s line:%d SYMBOL_NOT_FOUND :%s \n",(char * )__func__,__LINE__,name);
            return ERROR;
        }
        *pSymbolId = (SYMBOL_ID) pNode;
    }
    else 
    {
        /* Search by value or by value and type: */
        for (index = 0; index < symTblId->nameHashId->elements; index++)
        {
            pSymbol = (SYMBOL *) SLL_FIRST(&symTblId->nameHashId->pHashTbl [index]);
            char *str = ".o";
            while (pSymbol != NULL)/* list empty */
            {
                if ( ((pSymbol->type & mask) == (type & mask)) 
                    &&(pSymbol->value == value) 
                    &&(((pUnder = rindex (pSymbol->name, '_')) == NULL)
                        ||((strcmp (pUnder, "_text") != 0) 
                            &&(strcmp (pUnder, "_data") != 0) 
                            &&(strcmp (pUnder, "_bss") != 0) 
                            &&(strcmp(pUnder, "_opd") != 0)
                            &&(strcmp (pUnder, "_compiled.") != 0))) 
                    &&(((pUnder = rindex (pSymbol->name, '.')) == NULL)
                        ||((strcmp (pUnder, str) != 0))))
                {
                    /* We've found the entry.  Return it. */
                    *pSymbolId = pSymbol;
                    printf("%s line:%d SYMBOL_FOUND :%s \n",(char * )__func__,__LINE__,pSymbol->name);
                    return OK;
                }
                else if (((pSymbol->type & mask) == (type & mask)) &&
            #if defined SUPPORT_64BIT
                    ((*(ULONG*)pSymbol->value <= (ULONG)value) &&
                    (*(ULONG*)pSymbol->value > (ULONG)bestValue)))
                {
                    /* this symbol is of correct type and closer than last one */
                    bestValue = (void*)(*(ULONG*)pSymbol->value);
                    pBestSymbol = pSymbol;
                }
            #else
                    ((pSymbol->value <= value) &&
                    (pSymbol->value > bestValue)))
                {
                    /* this symbol is of correct type and closer than last one */
                    bestValue   = pSymbol->value;
                    pBestSymbol = pSymbol;
                }
            #endif

                pSymbol = (SYMBOL *) SLL_NEXT (&pSymbol->nameHNode);
            }
        }

        if (bestValue == NULL || pBestSymbol == NULL)	/* any closer symbol? */
        {
            printf("%s line:%d SYMBOL_NOT_FOUND :%s \n",(char * )__func__,__LINE__,name);
            return (ERROR);
        }
        *pSymbolId = pBestSymbol;
    }

    return OK;
}
/**********************************************************************
* 函数名称：
* 功能描述：通过名称找地址
* 访问的表：无
* 修改的表：无
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
WORD32 symFindByName(CHAR *name, ULONG *pValue, WORD32 *size, WORD32 *pType)
{
    SYMBOL *pSymbol = NULL;
    
    if(NULL == name)
    {
        printf("%s line:%d name is null \n",(char * )__func__,__LINE__);
        return ERROR;
    }
    
    if(ERROR == symFindSymbol (g_ModuleSymTbl, name, NULL, SYM_MASK_ANY_TYPE, SYM_MASK_ANY_TYPE,&pSymbol))
    {
        printf("%s line:%d call symFindSymbol fail \n",(char * )__func__,__LINE__);
        return ERROR;
    }

    if(NULL == pSymbol)
    {
        printf("%s line:%d pSymbol is NULL \n",(char * )__func__,__LINE__);
        return ERROR; 
    }
        
    if (pValue)
    {
        *pValue = (unsigned long)pSymbol->value;
    }
    if (pType)
    {
        *pType =  (WORD32)ELF32_ST_TYPE (pSymbol->type);
    }
    if (size)
    {
        *size =   (WORD32)pSymbol->size;
    }
    return OK;
}
/**********************************************************************
* 函数名称：
* 功能描述：通过地址找符号名，
* 访问的表：无
* 修改的表：无
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：已有接口，要保持原有定义
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
WORD32 symFindAttrByValue(ULONG value, CHAR *name, ULONG *pValue,  WORD32 *pType, WORD32 *size)
{
    SYMBOL * pSymbol = NULL;

    if(NULL == name)
    {
        printf("%s line:%d name is null \n",(char * )__func__,__LINE__);
        return ERROR;
    }
    if (symFindSymbol (g_ModuleSymTbl, NULL, (char *) value, SYM_MASK_ANY_TYPE, SYM_MASK_ANY_TYPE, &pSymbol) != OK)
    {
        printf("%s line:%d symFindSymbol fail \n",(char * )__func__,__LINE__);
        return ERROR;
    }

    if(NULL == pSymbol)
    {
        printf("%s line:%d pSymbol is NULL \n",(char * )__func__,__LINE__);
        return ERROR; 
    }
    
    if((NULL != name)&&(NULL != pSymbol->name))
    {
        strncpy (name, pSymbol->name, 128);
    }

    if (pValue)
    {
        *pValue = (ULONG)pSymbol->value;
    }
    if (pType)
    {
        *pType = (WORD32)ELF32_ST_TYPE(pSymbol->type);
    }

    if(size)
    {
        *size = pSymbol->size;
    }
    return OK;
}

/**********************************************************************
* 函数名称：
* 功能描述：判断输入的命令是否地址，如果是地址是否可以找到函数
* 访问的表：无
* 修改的表：无
* 输入参数：
* 输出参数：
* 返 回 值：
* 其它说明：
* 修改日期      版本号  修改人      修改内容
* ---------------------------------------------------------------------
************************************************************************/
bool symFindByAddress(CHAR *command, CHAR* name, ULONG *pValue, WORD32 *pSize, WORD32 *ptSymType)
{
    ULONG   wSymValue;

    if(NULL == command || NULL == name || NULL == pValue || 
       NULL == pSize || NULL == ptSymType)
    {
        printf("symFindByAddress param error");
        return false;
    }

    if(command[0] == '0' && (command[1] == 'x' || command[1] == 'X'))
    {
        sscanf(command,"0x%x",pValue);
    }
    if(OK == symFindAttrByValue((ULONG)*pValue,name,&wSymValue,ptSymType, pSize))
    {
        /*如果该地址是函数入口地址*/
        if (STT_FUNC == *ptSymType && (*pValue) == wSymValue)
        {
            return true;
        }
    }
    
    return false;
}

