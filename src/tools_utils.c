#include "main.h"

// FIXME: Make this configurable to run more than just python scripts.
void execute_tool(char** output, char *tool_engine, char* tool_name, char* parameters, fio_lock_i tool_call_lock)
{
    char *cmd_str = malloc(CMD_LEN);
    log_debug("%s %s %s", tool_engine, tool_name, parameters);
    snprintf(cmd_str, CMD_LEN, "bash -c \"%s %s %s\"", tool_engine, tool_name, parameters);
    FILE *fp;
    fp = popen(cmd_str, "r");
    if (fp == NULL)
    {
        log_error("TOOL-EXEC-FAIL\n");
        return;
    }
    // FIXME: Should find another way round without using malloc with hardcoded, probably should not even use malloc?
    char* l = malloc(OUTPUT_SINGLE_L);
    char* result = malloc(16384);
    memset(result, 0, 16384);
    while (fgets(l, OUTPUT_SINGLE_L, fp) != NULL)
    {
        strcat(result, l);
    }
    pclose(fp);
    free(l);
    free(cmd_str);
    fio_unlock(&tool_call_lock);
    log_info("Await lock freed for: %s", tool_name);
    strncpy(*output, result, strlen(result));
    free(result);
    log_debug("TOOL-OUTPUT: %s", *output);
}