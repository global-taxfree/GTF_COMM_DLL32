#include <process.h>
#include <direct.h>

#define YYYYMMDD                 1
#define YYYY_MM_DD_hh_mm_ss      2
#define YYYYMMDDhhmmss			 3

void GetCurDtTm(char *targetbuf, int type);
int PrintLog(const char *fmt, ...);
int WriteLog(const char *fmt, int len);
int StringFind(char *buf, int chk, int cnt);
void traceDebug(char *szFormat, ...);
void HexDump(unsigned char *pDcs, int len);
