#pragma once

// TaxCalc.h : 부가세 구간에 따른 환급액 계산용 Table
typedef struct VAT_Table {
	int	MinAmt;	// 최소금액
	int	MaxAmt;	// 최대금액
	int	Refund;	// 환급금액
} VAT_TABLE_T;

// 부가세로 환급액을 조회
int	getRefundAmt( int SellAmt );

// 220만원 이상 부가세로 환급액을 조회
int	getRefundAmt220( int SellAmt );
