/*
 * Copyright (C)  2015 Guillaume Duteil <g.duteil@alsim.com>
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stlink-common.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <uglylogging.h>

#define FREERTOS_LIST_SIZE		20
#define FREERTOS_TASK_NAME_OFFSET	52
#define FREERTOS_LOWER_VALID_ADDRESS	0x10000000
#define FREERTOS_HIGHER_VALID_ADDRESS	0x2001FFFF

#define NB_FREERTOS_SYMBOLS	10

typedef enum {
    FREERTOS_SCHEDULER_RUNNING = 0,
    FREERTOS_CURRENT_TCB,
    FREERTOS_NUMBER_OF_TASKS,
    FREERTOS_TOP_READY_PRIORITY,
    FREERTOS_READY_TASKS_LIST,
    FREERTOS_DELAYED_TASK_LIST1,
    FREERTOS_DELAYED_TASK_LIST2,
    FREERTOS_PENDING_READY_TASK_LIST,
    FREERTOS_SUSPENDED_TASK_LIST,
    FREERTOS_WAITING_TERM_LIST
} FreeRTOSSymbols;


const char szFreeRTOSSymbolNames[NB_FREERTOS_SYMBOLS][32] ={
    "xSchedulerRunning",
    "pxCurrentTCB",
    "uxCurrentNumberOfTasks",
    "uxTopReadyPriority",
    "pxReadyTasksLists",
    "xDelayedTaskList1",
    "xDelayedTaskList2",
    "xPendingReadyList",
    "xSuspendedTaskList",
    "xTasksWaitingTermination"
};

static uint32_t FreeRTOSSymbolsAddresses[NB_FREERTOS_SYMBOLS] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

void FreeRTOSUpdate(stlink_t* sl);
char *FreeRTOSGetCurrentThread(stlink_t* sl);
char *FreeRTOSSetCurrentThread(char *query);
char *FreeRTOSThreadInfo(stlink_t* sl, bool bFirst);
char *FreeRTOSThreadExtraInfo(char *query);
char *FreeRTOSReadRegs(stlink_t* sl);
char *FreeRTOSCheckThreadAlive(char *query);
char *FreeRTOSSymbol(char *query);
char *FreeRTOSSymbolRequest();
uint8_t FreeRTOSUpdateTaskFromList(stlink_t* sl, uint8_t listSymbol, uint8_t listTabNum, uint8_t numFirstTaskFound);

typedef struct _STask {
    uint32_t TCBAddress;
    char szName[32];
} STask;

typedef struct _SFreeRTOSInfos {
    uint32_t nbTasks;
    uint32_t currentTask;
    uint32_t currentTaskGDB;
    STask *tasks;
} SFreeRTOSInfos;

static SFreeRTOSInfos sFreeRTOS = {0, 0, 0xFFFFFFFF, NULL};

// bin2hex : encode to ascii-hex representation
int bin2hex(const char *bin, char *hex, int bin_size, int hex_maxlen) 
{
    int i, hex_len = 0;
    for (i=0;i<bin_size;i++)
    {
        hex_len += snprintf(hex+hex_len, hex_maxlen-hex_len, "%02x", bin[i]&0xff);
    }
    return hex_len;
}

// hex2bin : decode ascii-hex representation
int hex2bin(const char *hex, char *bin, int bin_size) 
{
    int i, tmp;
    memset(bin, 0, bin_size);
    for (i=0;i<bin_size;i++) 
    {
        if (sscanf(hex+(2*i), "%02x", &tmp) != 1)
            return i;
        bin[i] = tmp;
    }
    return i;
}

// Read an UINT32 from memory
uint32_t ReadUINT32(stlink_t* sl, uint32_t address) 
{
    stlink_read_mem32(sl, address, 4);
    return (uint32_t)(sl->q_buf[0] | (sl->q_buf[1] <<  8) | (sl->q_buf[2] << 16) | (sl->q_buf[3] << 24));
}

// Read an string from memory
uint32_t ReadString(stlink_t* sl, uint32_t address, char *pBuf, uint32_t bufLen) 
{
    memset(pBuf, 0, bufLen);
    uint32_t ret = 0;
    bool bEndOfStringFound = false;
    while (!bEndOfStringFound) {
        stlink_read_mem32(sl, address + ret, 4);
        for (int i = 0; i < 4; i++) {
            if (ret < bufLen) {
                *(pBuf + ret) = sl->q_buf[i];
                ret++;
                if (sl->q_buf[i] == '\0')
                    bEndOfStringFound = true;
            } else {
                *(pBuf + bufLen - 1) = '\0';
                bEndOfStringFound = true;
            }
        }
    }
    return ret;
}

// FreeRTOS packet handler
char *FreeRTOSPacket(stlink_t* sl, char *packet) 
{
    DLOG("FreeRTOS : %s\n", packet);

    if (strncmp(packet, "qfThreadInfo", 12) == 0) {
        return FreeRTOSThreadInfo(sl, true);
    } else if (strncmp(packet, "qsThreadInfo", 12) == 0) {
        return FreeRTOSThreadInfo(sl, false);
    } else if (strncmp(packet, "qSymbol:", 8) == 0) {
        return FreeRTOSSymbol(packet + 8);
    } else if (strncmp(packet, "qThreadExtraInfo,", 17) == 0) {
        return FreeRTOSThreadExtraInfo(packet + 17);
    } else if (strncmp(packet, "qC", 2) == 0) {
        return FreeRTOSGetCurrentThread(sl);
    } else if (strncmp(packet, "Hg", 2) == 0) {
        return FreeRTOSSetCurrentThread(packet + 2);
    } else if (packet[0] == 'g') {
        return FreeRTOSReadRegs(sl);
    } else if (packet[0] == 'T') {
        return FreeRTOSCheckThreadAlive(packet + 1);
    } else {
        return strdup("");
    }
}

// Update FreeRTOS infos
void FreeRTOSUpdate(stlink_t* sl) 
{
    // Free old memory
    if (sFreeRTOS.tasks != NULL) {
        free(sFreeRTOS.tasks);
        sFreeRTOS.tasks = NULL;
        sFreeRTOS.nbTasks = 0;
    }

    // Check if we have all addresses for symbols
    for (uint32_t i = 0; i < NB_FREERTOS_SYMBOLS; i++) {
        if (FreeRTOSSymbolsAddresses[i] == 0) {
            return;
        }
    }

    // Is the scheduler running ?
    int32_t IsRunning = (int32_t) ReadUINT32(sl, FreeRTOSSymbolsAddresses[FREERTOS_SCHEDULER_RUNNING]);
    if (IsRunning != 1) 
    {
        WLOG("FreeRTOS scheduler is not running\n");
        return;
    }
    // Number of tasks
    sFreeRTOS.nbTasks = ReadUINT32(sl, FreeRTOSSymbolsAddresses[FREERTOS_NUMBER_OF_TASKS]);
    sFreeRTOS.tasks = (STask *) malloc(sFreeRTOS.nbTasks * sizeof (STask));
    memset(sFreeRTOS.tasks, 0, sFreeRTOS.nbTasks * sizeof (STask));

    // Fill tasks infos
    uint32_t numTask = 0;
    for (uint32_t i = 0; i < ReadUINT32(sl, FreeRTOSSymbolsAddresses[FREERTOS_TOP_READY_PRIORITY]); i++) 
    {
        numTask += FreeRTOSUpdateTaskFromList(sl, FREERTOS_READY_TASKS_LIST, i, numTask);
    }
    numTask += FreeRTOSUpdateTaskFromList(sl, FREERTOS_DELAYED_TASK_LIST1, 0, numTask);
    numTask += FreeRTOSUpdateTaskFromList(sl, FREERTOS_DELAYED_TASK_LIST2, 0, numTask);
    numTask += FreeRTOSUpdateTaskFromList(sl, FREERTOS_PENDING_READY_TASK_LIST, 0, numTask);
    numTask += FreeRTOSUpdateTaskFromList(sl, FREERTOS_SUSPENDED_TASK_LIST, 0, numTask);
    numTask += FreeRTOSUpdateTaskFromList(sl, FREERTOS_WAITING_TERM_LIST, 0, numTask);

    // Get current task
    uint32_t pxCurrentTCB = ReadUINT32(sl, FreeRTOSSymbolsAddresses[FREERTOS_CURRENT_TCB]);
    for (uint32_t i = 0; i < sFreeRTOS.nbTasks; i++) {
        if (sFreeRTOS.tasks[i].TCBAddress == pxCurrentTCB) {
            sFreeRTOS.currentTask = i;
            break;
        }
    }
}

// Fill task infos for a specified list
uint8_t FreeRTOSUpdateTaskFromList(stlink_t* sl, uint8_t listSymbol, uint8_t listTabNum, uint8_t numFirstTaskFound) {
    // Did we find all task we needed ?
    if (numFirstTaskFound >= sFreeRTOS.nbTasks)
        return 0;

    // Get number of elements in the list
    uint32_t nbElements = ReadUINT32(sl, FreeRTOSSymbolsAddresses[listSymbol] + FREERTOS_LIST_SIZE * listTabNum);
    if (nbElements == 0 || nbElements > sFreeRTOS.nbTasks)
        return 0;

    // Fill list infos
    uint8_t ret = 0;
    uint32_t elementAddr = ReadUINT32(sl, FreeRTOSSymbolsAddresses[listSymbol] + FREERTOS_LIST_SIZE * listTabNum + 4);
    for (uint32_t i = 0; i < nbElements + 1; i++) 
    {
        uint32_t pvOwnerAddr = ReadUINT32(sl, elementAddr + 12);
        if (pvOwnerAddr >= FREERTOS_LOWER_VALID_ADDRESS && pvOwnerAddr <= FREERTOS_HIGHER_VALID_ADDRESS && numFirstTaskFound+ret < sFreeRTOS.nbTasks) 
        {
            // TCB Address
            sFreeRTOS.tasks[numFirstTaskFound + ret].TCBAddress = pvOwnerAddr;

            // Task name
            ReadString(sl, pvOwnerAddr + FREERTOS_TASK_NAME_OFFSET, sFreeRTOS.tasks[numFirstTaskFound + ret].szName, sizeof (sFreeRTOS.tasks[numFirstTaskFound + ret].szName));
            DLOG("Found task in list %s:%d at address 0x%08X (%s)\n", szFreeRTOSSymbolNames[listSymbol], listTabNum, pvOwnerAddr, sFreeRTOS.tasks[numFirstTaskFound + ret].szName);
            ret++;

        }
        elementAddr = ReadUINT32(sl, elementAddr + 4);
    }
    return ret;
}

// Return current thread id
char *FreeRTOSGetCurrentThread(stlink_t* sl) 
{
    // Update FreeRTOS infos
    FreeRTOSUpdate(sl);

    if (sFreeRTOS.nbTasks == 0) 
    {
        return strdup("");
    }

    char *szTmp = (char *) malloc(20);
    snprintf(szTmp, 20, "QC %016x", sFreeRTOS.tasks[sFreeRTOS.currentTask].TCBAddress);
    return szTmp;
}

// Set current thread id
char *FreeRTOSSetCurrentThread(char *query) 
{
    uint32_t TCBAddress = 0;
    if (sscanf(query, "%08X", &TCBAddress) == 1) 
    {
        if (TCBAddress == 0) 
        {
            sFreeRTOS.currentTaskGDB = 0;
        } else {
            for (uint32_t i = 0; i < sFreeRTOS.nbTasks; i++) 
            {
                if (sFreeRTOS.tasks[i].TCBAddress == TCBAddress) 
                {
                    sFreeRTOS.currentTaskGDB = i;
                    break;
                }
            }
        }
        return strdup("OK");
    } else {
        sFreeRTOS.currentTaskGDB = 0xFFFFFFFF;
        return strdup("");
    }
}

// Return list of FreeRTOS tasks
char *FreeRTOSThreadInfo(stlink_t* sl, bool bFirst) 
{
    if (!bFirst)
        return strdup("l");

    // Update FreeRTOS infos
    FreeRTOSUpdate(sl);

    // Prepare reply
    int replySize = (sFreeRTOS.nbTasks * 17) + 1;
    char *pReply = (char *) malloc(replySize);
    char *ptr = pReply;
    for (uint32_t i = 0; i < sFreeRTOS.nbTasks; i++) 
    {
        if (i == 0)
            ptr += sprintf(ptr, "m%016x", sFreeRTOS.tasks[i].TCBAddress);
        else
            ptr += sprintf(ptr, ",%016x", sFreeRTOS.tasks[i].TCBAddress);
    }

    return pReply;
}

// Return thread extra info
char *FreeRTOSThreadExtraInfo(char *query) 
{
    uint32_t taskAddress = 0;
    if (sscanf(query, "%08X", &taskAddress) == 1) 
    {
        for (uint32_t i = 0; i < sFreeRTOS.nbTasks; i++) 
        {
            if (sFreeRTOS.tasks[i].TCBAddress == taskAddress) 
            {
                char *szTmp = (char *) malloc(64);
                bin2hex(sFreeRTOS.tasks[i].szName, szTmp, strlen(sFreeRTOS.tasks[i].szName), 64);
                return strdup(szTmp);
            }
        }
    }
    return strdup("");
}

// Read regs for current thread id
char *FreeRTOSReadRegs(stlink_t* sl) 
{
    FreeRTOSUpdate(sl);
    if (sFreeRTOS.currentTaskGDB > sFreeRTOS.nbTasks || sFreeRTOS.currentTaskGDB == 0)
        return NULL;

    // Get stack pointer
    uint32_t topOfStack = ReadUINT32(sl, sFreeRTOS.tasks[sFreeRTOS.currentTaskGDB].TCBAddress);

    // Read stack
    uint8_t stack[64];
    stlink_read_mem32(sl, topOfStack, sizeof (stack));
    memcpy(stack, sl->q_buf, sizeof (stack));

    uint8_t nbRegisters = 17;
    char *regs_list = (char *) malloc(nbRegisters * 4 * 2 + 1);
    memset(regs_list, 0, nbRegisters * 4 * 2 + 1);

    char *p = regs_list;

    int i = 0;

    // Registers R0->R3
    for (i = 0; i < 4; i++) {
        p += sprintf(p, "%08x", htonl(*(uint32_t *) (stack + 0x24 + i * 4)));
    }

    // Registers R4->R11
    for (i = 0; i < 8; i++) {
        p += sprintf(p, "%08x", htonl(*(uint32_t *) (stack + i * 4)));
    }

    // Registers R12
    p += sprintf(p, "%08x", htonl(*(uint32_t *) (stack + 0x34)));

    // Register sp
    uint32_t sp = ((topOfStack + 64)&(~((uint32_t) 7))) + 8;
    p += sprintf(p, "%08x", htonl(sp));

    // Registers lr, pc and xPSR
    for (i = 0; i < 2; i++) {
        p += sprintf(p, "%08x", htonl(*(uint32_t *) (stack + 0x38 + i * 4)));
    }

    DLOG("Stack : %s\n", regs_list);
    return regs_list;
}

// Check is a thread is alive
char *FreeRTOSCheckThreadAlive(char *query) {
    uint32_t TCBAddress = 0;
    if (sscanf(query, "%08X", &TCBAddress) == 1) 
    {
        for (uint32_t i = 0; i < sFreeRTOS.nbTasks; i++) 
        {
            if (sFreeRTOS.tasks[i].TCBAddress == TCBAddress) 
            {
                return strdup("OK");
            }
        }
    }
    return strdup("");
}

// Handle symbol messages
char *FreeRTOSSymbol(char *msg) 
{
    if (msg[0] == ':') {
        // Ready to resolve symbols
        memset(FreeRTOSSymbolsAddresses, 0, sizeof (FreeRTOSSymbolsAddresses));
        return FreeRTOSSymbolRequest();
    }

    // Parse message
    char szSymbolHex[64];
    char szAddress[16];
    char *ptr = strtok(msg, ":");
    uint8_t bError = 0;
    if (ptr != NULL) {
        strncpy(szAddress, ptr, sizeof (szAddress) - 1);
        ptr = strtok(NULL, ":");
        if (ptr != NULL)
            strncpy(szSymbolHex, ptr, sizeof (szSymbolHex) - 1);
        else
            bError = 1;
    } else {
        bError = 1;
    }

    if (bError) {
        ELOG("Error parsing %s\n", msg);
        return strdup("");
    }
    char szSymbolName[32];
    hex2bin(szSymbolHex, szSymbolName, sizeof(szSymbolName));
    DLOG("Reply %s\n", szSymbolName);
    // Update our symbol address list
    for (int i = 0; i < NB_FREERTOS_SYMBOLS; i++) {
        if (strcmp(szFreeRTOSSymbolNames[i], szSymbolName) == 0) {
            if (sscanf(szAddress, "%08X", &FreeRTOSSymbolsAddresses[i]) == 1) {
                DLOG("Updated %s to 0x%08x\n", szFreeRTOSSymbolNames[i], FreeRTOSSymbolsAddresses[i]);
            }
            break;
        }
    }

    return FreeRTOSSymbolRequest();
}

// Request symbol
char *FreeRTOSSymbolRequest() 
{
    for (int i = 0; i < NB_FREERTOS_SYMBOLS; i++) 
    {
        if (FreeRTOSSymbolsAddresses[i] == 0) {
            DLOG("Query : %s\n", szFreeRTOSSymbolNames[i]);
            char *szTmp = (char *) malloc(64);
            strncpy(szTmp, "qSymbol:", 64);
            bin2hex(szFreeRTOSSymbolNames[i], szTmp + strlen(szTmp), strlen(szFreeRTOSSymbolNames[i]), 64 - strlen(szTmp));
            return szTmp;
        }
    }
    return strdup("OK");
}
