#ifndef __ERROR_H__
#define __ERROR_H__
#include <stdio.h>
#include <errno.h>

typedef enum {
    STATUS_SUCCESS,
    STATUS_GENERIC_FAILED
} error_status_t;

#define PERROR_STRING ("FAILED AT")
#define PRINT_FILE_LINE_NUM() (printf("\n\tat file: %s, line: %d\n", __FILE__, __LINE__))

#define CHECK_ERR(OP, ERR_VAL) do { \
	if (!(OP)) { \
		perror(PERROR_STRING); \
		PRINT_FILE_LINE_NUM(); \
		ret_status = ERR_VAL;  \
		goto cleanup; \
	} \
} while(0)

// can't put surrounding parenthesis, doesn't compile, thinks there needs to be an expression before.
// #define CHECK(OP) (CHECK_ERR(OP, STATUS_GENERIC_FAILED))
#define CHECK(OP) CHECK_ERR(OP, STATUS_GENERIC_FAILED)
#define CHECK_FUNC(RET_VAL) CHECK(RET_VAL == STATUS_SUCCESS)

// is this better?
//#define CHECK(OP) do { CHECK_ERR(OP, STATUS_GENERIC_FAILED) } while(0)
//#define CHECK_FUNC(RET_VAL) do { CHECK(RET_VAL == STATUS_SUCCESS) } while(0)
#endif //__ERROR_H__
