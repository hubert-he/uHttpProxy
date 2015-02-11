/*
**  Author: hubert_he@realsil.com.cn
**  3rdParty: tinyProxy: https://banu.com/tinyproxy/
** Http Proxy: asynchronous and non-block socket implementation
** 
*/
#ifndef __MYTIME_H__
#define __MYTIME_H__
#include "time.h"
int proxy_difftime(time_t time1, time_t time0);
time_t proxy_time(time_t* t);
#endif
