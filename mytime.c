/*
**  Author: hubert_he@realsil.com.cn
**  3rdParty: tinyProxy: https://banu.com/tinyproxy/
** Http Proxy: asynchronous and non-block socket implementation
** 
*/
#include "mytime.h"
time_t proxy_time(time_t* t)
{
	return oskTimerGetSecs();
}

int proxy_difftime(time_t time1, time_t time0)
{
	return (time1-time0);		
}

