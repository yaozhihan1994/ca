

/***********************************************
* @addtogroup Nebula
* @{
* @file  : CommonError.h
* @brief :
* @date  : 2019-04-25
***********************************************/

//--------------------------------------------------
// Copyright (c) Beijing Nebula Link Technology Co.,Ltd
//--------------------------------------------------


#ifndef COMMON_ERROR_H_
#define COMMON_ERROR_H_

#ifdef __cplusplus
extern "C"
{
#endif

/* Return Value */
typedef enum CommonError
{
	COMMON_SUCCESS = 0,
	COMMON_ERROR = -1,
	COMMON_INVALID_PARAMS = -2,
	COMMON_NULL_POINT = -3,

} e_CommonError;


#ifdef __cplusplus
}
#endif

#endif

/**
* @}
**/



