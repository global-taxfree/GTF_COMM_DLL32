#pragma once
#include <ctime>


bool IsLeapYear(int year) ;
int GetDaysInMonth(int year, int month);
tm AddMonths_tm(const tm &d, int months);
time_t AddMonths_T(const time_t &date, int months);
void Add_Months(char *inDate, int iDiff, char *outDate);
tm AddMonths_tm2(const tm &d, int months);
time_t AddMonths_T2(const time_t &date, int months);
void Add_Months2(char *inDate, int iDiff, char *outDate);
time_t AddMonths_T2bT(const time_t &date, int months);
void Add_Months2b(char *inDate, int iDiff, char *outDate);


