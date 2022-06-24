#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <HttpFilt.h>
#include <stdio.h>

BOOL WINAPI GetFilterVersion(PHTTP_FILTER_VERSION pVer)
{
	OutputDebugStringA("GetFilterVersion ran\r\n");
	FILE* file = fopen("C:\\logs\\log.log", "a");
	if (file) {
		fprintf(file, "FILTER STARTED\r\n");
		fclose(file);
	}
	pVer->dwFlags &= ~SF_NOTIFY_ORDER_MASK;

	// Set the flags we are interested in
	pVer->dwFlags |= SF_NOTIFY_SECURE_PORT
		| SF_NOTIFY_NONSECURE_PORT
		| SF_NOTIFY_AUTHENTICATION
		| SF_NOTIFY_PREPROC_HEADERS
		| SF_NOTIFY_URL_MAP
		| SF_NOTIFY_SEND_RAW_DATA
		| SF_NOTIFY_SEND_RESPONSE
		| SF_NOTIFY_READ_RAW_DATA 
		| SF_NOTIFY_LOG
		| SF_NOTIFY_END_OF_NET_SESSION
		| SF_NOTIFY_END_OF_REQUEST;

	// Set Priority
	pVer->dwFlags |= SF_NOTIFY_ORDER_LOW; //SF_NOTIFY_ORDER_MEDIUM;
	strcpy(pVer->lpszFilterDesc, "AdsFilter from Bilawal Ahmed");
  return TRUE;
}

DWORD WINAPI HttpFilterProc(PHTTP_FILTER_CONTEXT pfc, DWORD notificationType, LPVOID pvNotification)
{
	switch (notificationType)
	{
	case SF_NOTIFY_READ_RAW_DATA:
	{
		HTTP_FILTER_RAW_DATA* structure = (HTTP_FILTER_RAW_DATA*)pvNotification;
		structure->cbInData = 0;
		structure->cbInBuffer = 0;
		break;
	}
	case SF_NOTIFY_SEND_RAW_DATA:
	{
		HTTP_FILTER_RAW_DATA* structure = (HTTP_FILTER_RAW_DATA*)pvNotification;
		structure->cbInData = 0;
		structure->cbInBuffer = 0;
		break;
	}
	default:
		break;
	}

	if ((notificationType & SF_NOTIFY_READ_RAW_DATA) != 0)
	{
		HTTP_FILTER_RAW_DATA* structure = (HTTP_FILTER_RAW_DATA*)pvNotification;
		structure->cbInData = 0;
		structure->cbInBuffer = 0;
	}

	if ((notificationType & SF_NOTIFY_SEND_RAW_DATA) != 0)
	{
		HTTP_FILTER_RAW_DATA* structure = (HTTP_FILTER_RAW_DATA*)pvNotification;
		structure->cbInData = 0;
		structure->cbInBuffer = 0;
	}
  return SF_STATUS_REQ_NEXT_NOTIFICATION;
}
