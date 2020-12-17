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

#define CHECK_ERR(EXP, ERR_VAL, ERR_STR) do { \
	if (!(EXP)) { \
		perror(ERR_STR); \
		PRINT_FILE_LINE_NUM(); \
		ret_status = (ERR_VAL); \
		goto cleanup; \
	} \
} while(0)

#define CHECK(EXP) CHECK_ERR((EXP), STATUS_GENERIC_FAILED, PERROR_STRING)
#define CHECK_STR(EXP, ERR_STR) CHECK_ERR((EXP), STATUS_GENERIC_FAILED, (ERR_STR))
#define CHECK_FUNC(RET_VAL) CHECK((RET_VAL) == STATUS_SUCCESS)
#define CHECK_FUNC_STR(RET_VAL, ERR_STR) CHECK_STR((RET_VAL) == STATUS_SUCCESS, (ERR_STR))

#endif //__ERROR_H__
