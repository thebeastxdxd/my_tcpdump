#ifndef __ERROR_H__
#define __ERROR_H__
#include <stdio.h>
#include <errno.h>

#define TRUE (1)
#define FALSE (0)

typedef enum {
    SUCCESS_STATUS,
    GENERIC_FAILED_STATUS
} error_status_t;

#define PERROR_STRING "FAILED AT"
#define CHECK_PERROR  (perror(PERROR_STRING))
#define PRINT_FILE_LINE_NUM (printf("\n\tat file: %s, line: %d\n", __FILE__, __LINE__))

#define CHECK_ERR(OP, ERR_VAL) do { if (!(OP)) { CHECK_PERROR; PRINT_FILE_LINE_NUM; ret_status = ERR_VAL; goto cleanup; }; } while(0);
#define CHECK(OP) do { if (!(OP)) { CHECK_PERROR; PRINT_FILE_LINE_NUM; ret_status = GENERIC_FAILED_STATUS; goto cleanup; }; } while(0);

#endif //__ERROR_H__
