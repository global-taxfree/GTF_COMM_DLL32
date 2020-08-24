#include "StdAfx.h"
#include "DateTimeT.h"
#include <ctime>

#define	MIN_VAL(a,b)	a>b?b:a
// DateTimeT.cpp : 구현 파일입니다.
//
// DateTimeT
int daysInMonths[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

bool IsLeapYear(int year) 
{
	if (year % 4 != 0) return false;
	if (year % 400 == 0) return true;
	if (year % 100 == 0) return false;
	return true;
}


int GetDaysInMonth(int year, int month)
{
	if(month < 0 || month > 11) return 31;

	int days = daysInMonths[month];

	if (month == 1 && IsLeapYear(year)) // February of a leap year
		days += 1;

	return days;
}

tm AddMonths_tm(const tm &d, int months)
{
	bool isLastDayInMonth = d.tm_mday == GetDaysInMonth(d.tm_year, d.tm_mon);

	int year = d.tm_year + months / 12;
	int month = d.tm_mon + months % 12;

	if (month > 11)
	{
		year += 1;
		month -= 12;
	}

	int day;

	// 5월 30 + 3개월 --> 8월 31일을 만드는 부분
	if (isLastDayInMonth)
		day = GetDaysInMonth(year, month); // Last day of month maps to last day of result month
	else 	// 11월 30 + 3개월 --> 2월 28일을 만드는 부분
		day = MIN_VAL(d.tm_mday, GetDaysInMonth(year, month));

	tm result = tm();

	result.tm_year = year;
	result.tm_mon = month;
	result.tm_mday = day;

	result.tm_hour = d.tm_hour;
	result.tm_min = d.tm_min;
	result.tm_sec = d.tm_sec;

	return result;
}

time_t AddMonths_T(const time_t &date, int months)
{
	tm d = tm();

	localtime_s(&d, &date);
	tm result = AddMonths_tm(d, months);

	return mktime(&result);
}

tm AddMonths_tm2(const tm &d, int months)
{
	bool isLastDayInMonth = d.tm_mday == GetDaysInMonth(d.tm_year, d.tm_mon);

	int year = d.tm_year + months / 12;
	int month = d.tm_mon + months % 12;

	if (month > 11)
	{
		year += 1;
		month -= 12;
	}

	int day;
	
	// 11월 30 + 3개월 --> 2월 28일을 만드는 부분
	day = MIN_VAL(d.tm_mday, GetDaysInMonth(year, month));

	tm result = tm();

	result.tm_year = year;
	result.tm_mon = month;
	result.tm_mday = day;

	result.tm_hour = d.tm_hour;
	result.tm_min = d.tm_min;
	result.tm_sec = d.tm_sec;

	return result;
}

time_t AddMonths_T2(const time_t &date, int months)
{
	tm d = tm();

	localtime_s(&d, &date);
	tm result = AddMonths_tm2(d, months);

	return mktime(&result);
}

// time_t date로 입력된 일자의 months달 후 직전일을 time_t로 return
time_t AddMonths_T2bT(const time_t &date, int months)
{
	// 입력된 time_t date를 struct tm d로 변환
	tm d = tm();
	localtime_s(&d, &date);

	bool isLastDayInMonth = d.tm_mday == GetDaysInMonth(d.tm_year, d.tm_mon);

	int year = d.tm_year + months / 12;
	int month = d.tm_mon + months % 12;

	if (month > 11)
	{
		year += 1;
		month -= 12;
	}

	int day;

	// 11월 30 + 3개월 --> 2월 28일을 만드는 부분
	day = MIN_VAL(d.tm_mday, GetDaysInMonth(year, month));

	tm result = tm();

	result.tm_year = year;
	result.tm_mon = month;
	result.tm_mday = day;

	result.tm_hour = d.tm_hour;
	result.tm_min = d.tm_min;
	result.tm_sec = d.tm_sec;

	time_t res_t = mktime(&result);

	// 3개월 후 일자가 말일보다 작거나 같으면, 전일로 day -1, 
	if( d.tm_mday <= GetDaysInMonth(year, month) ) {
		res_t -= 24*60*60;
	}
	// 3개월 후 일자가 말일보다 크면 말일로 완료

	return res_t;
}

// Oracle Style 5월30일 + 3개월 --> 8월 31일
void Add_Months(char *inDate, int iDiff, char *outDate)
{
	int iYear,iMonth, iDay;
	char buff[10];
	
	strncpy_s(buff,inDate,4);buff[4]=0;
	iYear = atoi(buff);
	strncpy_s(buff,inDate+4,2);buff[2]=0;
	iMonth = atoi(buff);
	strncpy_s(buff,inDate+6,2);buff[2]=0;
	iDay = atoi(buff);

	tm now_tm, res_tm;

	time_t	now_t, res_t;

	now_t = time(NULL);
	localtime_s(&now_tm, &now_t); 

	now_tm.tm_year = iYear - 1900;
	now_tm.tm_mon = iMonth - 1;
	now_tm.tm_mday = iDay;

	now_t = mktime(&now_tm);
	//localtime_s(&now_tm, &now_t);
	
	res_t = AddMonths_T( now_t, iDiff);
	localtime_s(&res_tm, &res_t);
	//Log.println("[%04d%02d%02d]==[%d]==>[%04d%02d%02d]", now_tm.tm_year+1900, now_tm.tm_mon+1, now_tm.tm_mday, iDiff,res_tm.tm_year+1900, res_tm.tm_mon+1, res_tm.tm_mday);
	sprintf( outDate, "%04d%02d%02d", res_tm.tm_year+1900, res_tm.tm_mon+1, res_tm.tm_mday );
	memcpy(outDate, buff, 8);

}

// Not Oracle Style 5월30일 + 3개월 --> 8월 30일
void Add_Months2(char *inDate, int iDiff, char *outDate)
{
	int iYear,iMonth, iDay;
	char buff[100];
	
	strncpy_s(buff,inDate,4);buff[4]=0;
	iYear = atoi(buff);
	strncpy_s(buff,inDate+4,2);buff[2]=0;
	iMonth = atoi(buff);
	strncpy_s(buff,inDate+6,2);buff[2]=0;
	iDay = atoi(buff);

	tm now_tm, res_tm;

	time_t	now_t, res_t;

	now_t = time(NULL);
	localtime_s(&now_tm, &now_t); 

	now_tm.tm_year = iYear - 1900;
	now_tm.tm_mon = iMonth - 1;
	now_tm.tm_mday = iDay;

	now_t = mktime(&now_tm);
	//localtime_s(&now_tm, &now_t);
	
	res_t = AddMonths_T2( now_t, iDiff);
	localtime_s(&res_tm, &res_t);
	//Log.println("Add_Months2,%04d%02d%02d,%d,%04d%02d%02d", now_tm.tm_year+1900, now_tm.tm_mon+1, now_tm.tm_mday, iDiff,res_tm.tm_year+1900, res_tm.tm_mon+1, res_tm.tm_mday);
	sprintf( buff, "%04d%02d%02d", res_tm.tm_year+1900, res_tm.tm_mon+1, res_tm.tm_mday );
	memcpy(outDate, buff, 8);

}

// Not Oracle Style 5월30일 + 3개월 --> 8월 30일의 직전일
void Add_Months2b(char *inDate, int iDiff, char *outDate)
{
	int iYear,iMonth, iDay;
	char buff[10];
	
	strncpy_s(buff,inDate,4);buff[4]=0;
	iYear = atoi(buff);
	strncpy_s(buff,inDate+4,2);buff[2]=0;
	iMonth = atoi(buff);
	strncpy_s(buff,inDate+6,2);buff[2]=0;
	iDay = atoi(buff);

	tm now_tm, res_tm;

	time_t	now_t, res_t;

	now_t = time(NULL);
	localtime_s(&now_tm, &now_t); 

	now_tm.tm_year = iYear - 1900;
	now_tm.tm_mon = iMonth - 1;
	now_tm.tm_mday = iDay;

	now_t = mktime(&now_tm);
	//localtime_s(&now_tm, &now_t);
	
	res_t = AddMonths_T2bT( now_t, iDiff);
	localtime_s(&res_tm, &res_t);
	//Log.println("Add_Months2b,%04d%02d%02d,%d,%04d%02d%02d", now_tm.tm_year+1900, now_tm.tm_mon+1, now_tm.tm_mday, iDiff,res_tm.tm_year+1900, res_tm.tm_mon+1, res_tm.tm_mday);
	sprintf( buff, "%04d%02d%02d", res_tm.tm_year+1900, res_tm.tm_mon+1, res_tm.tm_mday );
	memcpy(outDate, buff, 8);

}