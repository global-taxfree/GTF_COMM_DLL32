// GTF_COMM_DLL32.cpp : Defines the initialization routines for the DLL.
//

#include "stdafx.h"
#include "GTF_COMM_DLL32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <time.h>
#include <mbstring.h>
#include "Util.h"
#include "com_code.h"
#include <Winsock2.h>
#include <openssl/des.h>
#include "base64.h"
#include "DateTimeT.h"
#include "TaxCalc.h"

// Recv from POS 수신전문 for 오프라인 전문 Make
//refund_slip_t	gsRecvData;
int	gnOffLineMode = 0;

// 통신 장애시 오프라인 전표를 수신 데이터로 만들어 주는 함수
int	MakeOfflineSlip(char *inbuff, char *outbuff);
// 오프라인 리턴 에러코드,에러메세지, 패킷사이즈 셋팅함수 
void MakeOfflineError(char *pErrCode, char *pErrMsg, char *RequestMsg, char *RetMsg);


#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

//
//	Note!
//
//		If this DLL is dynamically linked against the MFC
//		DLLs, any functions exported from this DLL which
//		call into MFC must have the AFX_MANAGE_STATE macro
//		added at the very beginning of the function.
//
//		For example:
//
//		extern "C" BOOL PASCAL EXPORT ExportedFunction()
//		{
//			AFX_MANAGE_STATE(AfxGetStaticModuleState());
//			// normal function body here
//		}
//
//		It is very important that this macro appear in each
//		function, prior to any calls into MFC.  This means that
//		it must appear as the first statement within the 
//		function, even before any object variable declarations
//		as their constructors may generate calls into the MFC
//		DLL.
//
//		Please see MFC Technical Notes 33 and 58 for additional
//		details.
//

/////////////////////////////////////////////////////////////////////////////
// CGTF_COMM_DLL32App

BEGIN_MESSAGE_MAP(CGTF_COMM_DLL32App, CWinApp)
	//{{AFX_MSG_MAP(CGTF_COMM_DLL32App)
		// NOTE - the ClassWizard will add and remove mapping macros here.
		//    DO NOT EDIT what you see in these blocks of generated code!
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CGTF_COMM_DLL32App construction

CGTF_COMM_DLL32App::CGTF_COMM_DLL32App()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}

/////////////////////////////////////////////////////////////////////////////
// The one and only CGTF_COMM_DLL32App object

CGTF_COMM_DLL32App theApp;

// OffLine Mode Set 
extern "C" __declspec(dllexport) void __stdcall GTF_SetOffLineMode( int Mode );

extern "C" __declspec(dllexport) int __stdcall GTF_RequestApproval(char *P_Addr, 
																   int P_Port, 
																   char *RequestMsg, 
																   int RequestLen,
																   char *RecvMsg,
																   int ReadTimeOut);
/*
extern "C" __declspec(dllexport) int __stdcall GTF_EncryptData(char *Input, 
																   char *Output);

extern "C" __declspec(dllexport) int __stdcall GTF_DecryptData(char *Input, 
																	char *Output);
*/

#define DEBUG_HEX			0

extern "C" __declspec(dllexport) int __stdcall GTF_RequestApproval(char *P_Addr, 
																   int P_Port, 
																   char *RequestMsg, 
																   int RequestLen,
																   char *RecvMsg,
																   int ReadTimeOut)
{
	SOCKET sockfd = INVALID_SOCKET;
	int rtn_flag = 1;
	int ResponseLen = 0;

	char sndMsg[BUFFER_SIZE];
	char rcvMsg[BUFFER_SIZE];

	// OffLine Mode Process	
	if( gnOffLineMode ) {
		int	nRLen, nLength;
		char	tbuff[100];
		refund_slip_t	 *pReqMsg;

		pReqMsg = ( refund_slip_t *)RequestMsg;

		PrintLog("OffLine Service Start - RequestMsg[%.5s]\n", RequestMsg);
		memcpy( tbuff, RequestMsg, 5 );
		tbuff[5] =0;
		nLength = atoi(tbuff);

		// 최소 전문사이즈 물품 1건 기준 보다 작은 패킷은 Return Error
		if( RequestLen < sizeof(refund_slip_t)-sizeof(buy_detail_t)*(MAX_BUY_CNT-1) ) {
			PrintLog("Minimum Packet Size Error RequestLenR[%d]<M[%d]\n", RequestLen, sizeof(refund_slip_t)-sizeof(buy_detail_t)*(MAX_BUY_CNT-1));
			return -1;
		}
		// length 필드의 크기와, RequestLen이 다르면 
		else if( nLength != RequestLen ) {
			PrintLog("Packet Length not match RequestLen Error[%d != %d]\n",nLength, RequestLen);
			return -1;
		}

		// 판매금액 추출
		memcpy( tbuff, pReqMsg->sell_sum_money, sizeof(pReqMsg->sell_sum_money) );
		tbuff[sizeof(pReqMsg->sell_sum_money)] = 0;
		nLength = atoi(tbuff);

		// 판매금액이 100만원 미만인 경우만 오프라인전표 발급, 100만원 이상이면 fail
		if( nLength >= 1000000 ) {
			PrintLog("SellAmtLimit[1000000Won] Exceeded Error[%d]\n",nLength);
			MakeOfflineError("906", "오프라인 환급한도(1백만원미만) 초과", RequestMsg, RecvMsg); // 환급 건당한도 초과
			return ERR_PKT_SIZE;
		}

		nRLen = MakeOfflineSlip( RequestMsg, rcvMsg);
		memcpy( RecvMsg, rcvMsg, nRLen );

		PrintLog("OffLine Service End - rtn[%d]\n", nRLen);

		return nRLen;
	}


	if(ReadTimeOut == 0)
		ReadTimeOut = READ_TIMEOUT;

	PrintLog("Service Start - (Ip = [%s], Port = [%d])\n", P_Addr, P_Port);
	
	if((sockfd = ConnectServer(P_Addr, P_Port, ReadTimeOut)) == INVALID_SOCKET)
	{
		rtn_flag = ERR_CONNECT_SERV;
		goto END;
	}

#if DEBUG_HEX
HexDump((unsigned char*)RequestMsg, RequestLen);
#endif

	memset(sndMsg,	0x00,	sizeof(sndMsg));
	memset(rcvMsg,	0x00,	sizeof(rcvMsg));

	memcpy(sndMsg,	RequestMsg,		RequestLen);


	PrintLog("SEND [%d][%s]\n", RequestLen, sndMsg);
	if(Write_Line(sockfd, sndMsg, RequestLen) < 0)
	{	
		PrintLog("ERROR : 요청전문 송신 오류!\n");
		rtn_flag = ERR_SEND_MSG;
		goto END;
	}

	ResponseLen = SockReceiveTimeOut(sockfd, rcvMsg, ReadTimeOut, RequestLen);
	
	PrintLog("RECV [%d][%s]\n", ResponseLen, rcvMsg);

	memcpy(RecvMsg, rcvMsg, ResponseLen);

#if DEBUG_HEX
HexDump((unsigned char*)rcvMsg, ResponseLen);
#endif

END:
	closesocket(sockfd);
	WSACleanup();

	if(rtn_flag > 0) rtn_flag = ResponseLen;

	PrintLog("Service End - rtn[%d]\n", rtn_flag);

	return rtn_flag;
}

extern "C" __declspec(dllexport) void __stdcall GTF_SetOffLineMode( int Mode )
{
	PrintLog("GTF_SetOffLineMode [%d]\n", Mode);
	gnOffLineMode = Mode;
}


int ConnectServer(char *P_Addr, int P_Port, int ReadTimeOut)
{
	WSADATA				wsaData;
	SOCKET				sockfd;
	SOCKADDR_IN			addr;
	int					nCTimeOut, ErrNo, ret;
	unsigned long		ulNonBlockingState;
	WSAEVENT			hEvent;
	BOOL				retflag = FALSE;
	DWORD				dwret;
	WSANETWORKEVENTS	events;

	WORD wVersion = MAKEWORD(2, 2);
	if(WSAStartup(wVersion, &wsaData) != 0) return -1;

	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		ErrNo = WSAGetLastError();
		PrintLog("ERROR : Socket Open Error (ERRNO = %d)\n", ErrNo);
		return INVALID_SOCKET;
	}

	memset(&addr, 0x00, sizeof(addr));
	addr.sin_family				= AF_INET;
	addr.sin_port				= htons(P_Port);
	addr.sin_addr.S_un.S_addr	= inet_addr(P_Addr);	

	hEvent = WSACreateEvent();
	if(hEvent == WSA_INVALID_EVENT)
	{
		PrintLog("ERROR : Socket Open Error (WSA_INVALID_EVENT)\n");
		return INVALID_SOCKET;
	}

	ret = WSAEventSelect(sockfd, hEvent, FD_CONNECT);
	if(ret == SOCKET_ERROR)
	{
		ErrNo = WSAGetLastError();
		PrintLog("ERROR : Socket Open Error (ERRNO = %d)\n", ErrNo);
		WSACloseEvent(hEvent);
		return INVALID_SOCKET;
	}

	if(connect(sockfd, (LPSOCKADDR)&addr, sizeof(addr)) == SOCKET_ERROR)
	{
		ErrNo = WSAGetLastError();
		if(ErrNo != WSAEWOULDBLOCK) goto END;
	}

	dwret = WSAWaitForMultipleEvents(1, &hEvent, FALSE, CONNECT_TIMEOUT * 1000, FALSE);
	if(dwret != WSA_WAIT_EVENT_0) goto END;

	ret = WSAEnumNetworkEvents(sockfd, hEvent, &events);
	if(ret == SOCKET_ERROR) goto END;

	if((events.lNetworkEvents & FD_CONNECT) && events.iErrorCode[FD_CONNECT_BIT]==0)
	{
		retflag = TRUE;
	}

END:
	WSAEventSelect(sockfd, NULL, 0);
	WSACloseEvent(hEvent);

	if(retflag != TRUE)
	{
		ErrNo = WSAGetLastError();
		PrintLog("ERROR : Connect Error (ERRNO = %d)\n", ErrNo);
		return INVALID_SOCKET;
	}

	ulNonBlockingState = 0L;
	ioctlsocket(sockfd, FIONBIO, (unsigned long far *)&ulNonBlockingState);

	nCTimeOut = ReadTimeOut * 1000;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&nCTimeOut, sizeof(nCTimeOut));

	return sockfd;
}

int Write_Line(SOCKET fd, char *sendbuf, int len)
{
	int	slen, wlen, spt = 0;
	int	ErrNo;

	slen = len;

	while(1)
	{
		if((wlen = send(fd, &sendbuf[spt], slen, 0)) < 0)
		{
			ErrNo = WSAGetLastError();
			PrintLog("ERROR : Write Error (ERRNO = %d)\n", ErrNo);
			return -1;
		}

		slen = slen - wlen;
		spt = spt + wlen;

		if(slen == 0) break;
	}

	return 1;
}

int Read_Line(SOCKET fd, char *recvbuf, int len)
{
	int 	restlen, readlen, rtnlen;
	int		ErrNo;

	restlen = len;
	readlen = 0;

	while(1)
	{
		if((rtnlen = recv(fd, &recvbuf[readlen], restlen, 0)) < 0)
		{
			ErrNo = WSAGetLastError();
			PrintLog("ERROR : Read Error (ERRNO = %d)\n", ErrNo);
			return -1;
		}

		if(rtnlen == 0)
		{
			PrintLog("ERROR : Read Error (EOF 수신)\n");
			return -1;
		}

		readlen = readlen + rtnlen;
		restlen = restlen - rtnlen;
	
		if(restlen == 0) break;
	}

	return 1;
}

int SockReceiveTimeOut(SOCKET fd, char *recvdata, int timeout, int readsize)
{
	int nRet = 0;

	char buff[BUFFER_SIZE];

	fd_set rset;
	struct timeval tm;

	tm.tv_usec	= 0;
	tm.tv_sec	= timeout;

	FD_ZERO(&rset);
	FD_SET((u_int)fd, &rset);

	nRet = select(fd + 1, &rset, NULL, NULL, &tm);

	if (FD_ISSET(fd, &rset))
	{
		if(readsize < 400){

			memset(buff, 0x00, sizeof(buff));
			nRet = recv(fd, buff, sizeof(buff), 0);
			memcpy(recvdata, buff, strlen(buff));
			return nRet;

		}else{
			if(Read_Line(fd, buff, readsize) <= 0)
			{
				return 0;
			}else{
				memcpy(recvdata, buff, readsize);
				return readsize;
			}
		}
	}
	return 0;
}

void GetCurDtTm(char *targetbuf, int type)
{
	time_t tmt;
	struct tm *calptr;

	time(&tmt);
	calptr = (struct tm *)localtime(&tmt);

	switch(type)
	{	
		case YYYYMMDD:
			strftime(targetbuf, 16, "%Y%m%d", calptr);
			break;
		case YYYY_MM_DD_hh_mm_ss:
			strftime(targetbuf, 32, "%Y/%m/%d %H:%M:%S", calptr);
			break;	
		case YYYYMMDDhhmmss:
			strftime(targetbuf, 32, "%Y%m%d%H%M%S", calptr);
			break;	
	}
	return;
}

void traceDebug(char *szFormat, ...)
{
	/*
	char s[2048];
	va_list vlMarker;

	va_start(vlMarker, szFormat);
	vsprintf(s, szFormat, vlMarker);
	va_end(vlMarker);

	OutputDebugString((LPCWSTR)s);
	*/
}

int PrintLog(const char *fmt, ...)
{
	va_list	ap;
	char curdttm[32];
	FILE *fp;
	char logfilename[100] = {0x00 , };
		
	memset(curdttm, 0x00, sizeof(curdttm)); 
	GetCurDtTm(curdttm, YYYYMMDD);
	_mkdir("gtf_log");

	sprintf(logfilename, ".\\gtf_log\\gtf%s.log", curdttm);
		
	fp = fopen(logfilename, "a+");
	if(fp == NULL) return -1;
		
	memset(curdttm, 0x00, sizeof(curdttm)); GetCurDtTm(curdttm, YYYY_MM_DD_hh_mm_ss);
	fprintf(fp, "[%s][%d] ▷ ", curdttm, getpid());
		
	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);
		
	fflush(fp);
	fclose(fp);
	return TRUE;
}

int WriteLog(const char *fmt, int len)
{
	char curdttm[32];
	FILE *fp;
	char logfilename[100] = {0x00 , };

	memset(curdttm, 0x00, sizeof(curdttm)); 
	GetCurDtTm(curdttm, YYYYMMDD);
	sprintf(logfilename, ".\\gtf_log\\gtf%s.log", curdttm);

	_mkdir("gtf_log");
	fp = fopen(logfilename, "a+");
	if(fp == NULL) return -1;

	memset(curdttm, 0x00, sizeof(curdttm)); GetCurDtTm(curdttm, YYYY_MM_DD_hh_mm_ss);
	fprintf(fp, "[%s][%d] ▷ ", curdttm, getpid());
	
	fwrite(fmt, len, 1, fp);

	fflush(fp);
	fclose(fp);

	return TRUE;
}

int StringFind(char *buf, int chk, int cnt)
{
	int i=0, tmp=0, cntchk=0;

	for(i=0;i<=(int)strlen(buf);i++)
	{
		tmp = (int)buf[i];

		if(tmp == chk)
		{
			cntchk ++;
			if(cntchk == cnt) return i;
		}
	}
	return -1;
}

void HexDump(unsigned char *pDcs, int len)
{
    char        pDisp[BUFFER_SIZE], tbuf[9], asc;
    int         line, col, dummy;

    //PrintMessage("Dump Data> total length = %d", len);
    //PrintMessage("%s", "|    | 0  1  2  3  4  5  6  7  | 8  9  A  B  C  D  E  F  | |0123456789ABCDEF|");
    //PrintMessage("%s", "|====|=========================|=========================| |================|");

    for ( line = 0; line <= (len/16); line++) {
        memset( pDisp, 0x00, sizeof(pDisp));
        sprintf( pDisp, "|%04d| ", line*16);   /* offset number. */

        for ( col = 0; (col < 8) && ((line*16+col) < len); col++) {
            sprintf(&tbuf[0], "%02x ", (unsigned char) *(pDcs+((line*16)+col)));
            strncat(pDisp, &tbuf[0], 3);
        }

        if (col < 8) {
            for (dummy=0; dummy < (8 - col); dummy++) {
                sprintf( &tbuf[0], "   ");
                strncat( pDisp, &tbuf[0], 3);
            }
        }

        sprintf( &tbuf[0], "| ");
        strncat( pDisp, &tbuf[0], 2);

        for (col = 8; (col <16) && ((line*16+col) < len); col++) {
            sprintf(&tbuf[0], "%02x ", (unsigned char) *(pDcs+((line*16)+col)));
            strncat( pDisp, &tbuf[0], 3);
        }

        if ( col < 16 ) {
            for (dummy = 0; dummy < (16 - col); dummy++) {
                sprintf( &tbuf[0], "   ");
                strncat( pDisp, &tbuf[0], 3);
            }
        }

        sprintf( &tbuf[0], "| |");
        strncat( pDisp, &tbuf[0], 4);   /* separator */

        for (col = 0; (col < 16) && ((line*16+col) < len); col++) {
            asc = *(pDcs+((line*16)+col));
            //sprintf( &tbuf[0], "%c", (isprint(asc) ? asc : '.'));
			sprintf( &tbuf[0], "%c", (0x21 <= asc && asc <= 0x80) ? asc : '.');
            strncat( pDisp, &tbuf[0], 1);
        }

        if (col < 16) {
            for (dummy = 0; dummy < (16 - col); dummy++) {
                sprintf( &tbuf[0], " ");
                strncat( pDisp, &tbuf[0], 1);
            }
        }

        sprintf( &tbuf[0], "|");
        strncat( pDisp, &tbuf[0], 2);   /* separator */

        PrintLog("%s\n", pDisp);
    }

    PrintLog("%s\n", "|====|=========================|=========================| |================|");
}


// 통신 장애시 오프라인 전표를 수신 데이터로 만들어 주는 함수
int	MakeOfflineSlip(char *inbuff, char *outbuff)
{
	refund_slip_t	 *pRcvData, *pOffSlip;
	char	temp[100],buff[100];

	pRcvData = ( refund_slip_t *)inbuff;
	pOffSlip = ( refund_slip_t *)outbuff;
	SYSTEMTIME	LocalTime;
	PrintLog("pRcvData[%.100s]\n", inbuff+326 );
	GetLocalTime(&LocalTime);

	// 오프라인 전문 데이터 영역 공백으로 초기화
	memset(pOffSlip, 0x20, sizeof(refund_slip_t)-sizeof(buy_detail_t)*(MAX_BUY_CNT-1));

	// 전문길이 -- 물품내역 1레코드만
	sprintf( buff, "%05d", sizeof(refund_slip_t)-sizeof(buy_detail_t)*(MAX_BUY_CNT-1) );;
	memcpy( pOffSlip->length, buff, sizeof(pOffSlip->length));
	// 업무구분
	memcpy( pOffSlip->EDI, pRcvData->EDI, sizeof(pOffSlip->EDI));

	// 전문버전
	memcpy( pOffSlip->version, pRcvData->version, sizeof(pOffSlip->version));

	// 문서코드
	memcpy( pOffSlip->document_cd, "100", 3);

	// 구매일련번호 규칙: 209(3)+terminalID(5)+YYMMDD(6)+HHMMSS(6) = size(20)
	sprintf( buff, "209%5.5s%6.6s%02d%02d%02d", pRcvData->terminal_id, pRcvData->sell_time+2,LocalTime.wHour,LocalTime.wMinute,LocalTime.wSecond );
	PrintLog("==>HHMMSS[%02d%02d%02d]\n", LocalTime.wHour,LocalTime.wMinute,LocalTime.wSecond);
	memcpy( pOffSlip->buy_serial_num, buff, 20 );
    // 101 구매취소여부 판매
	memcpy( pOffSlip->buyer_cancel_chk, "N", 1);
	// 거래승인번호 (올리브영DLL)
	memcpy( pOffSlip->trade_approval_num, pRcvData->trade_approval_num, sizeof(pOffSlip->trade_approval_num));
	// 사업자등록번호
	memcpy( pOffSlip->seller_busi_regist_num, pRcvData->seller_busi_regist_num, sizeof(pOffSlip->seller_busi_regist_num));
	// 단말기ID
	memcpy( pOffSlip->terminal_id, pRcvData->terminal_id, sizeof(pOffSlip->terminal_id));
	// 판매 년월일시
	memcpy( pOffSlip->sell_time, pRcvData->sell_time, sizeof(pOffSlip->sell_time));
	// 판매수량
	memcpy( pOffSlip->sell_sum_total, pRcvData->sell_sum_total, sizeof(pOffSlip->sell_sum_total));
	// 판매금액
	memcpy( pOffSlip->sell_sum_money, pRcvData->sell_sum_money, sizeof(pOffSlip->sell_sum_money));
	// 환급총액 / 총부가세
	//memcpy( pOffSlip->refund_amount, pRcvData->refund_amount, sizeof(pOffSlip->refund_amount));
	// 결제유형
	memcpy( pOffSlip->payment_type, pRcvData->payment_type, sizeof(pOffSlip->payment_type));
	// 비고
	memcpy( pOffSlip->extra, pRcvData->extra, sizeof(pOffSlip->extra));
	//card_num(공통 POS전문에는 없는 데이타여서 미포함)
	//dom_yn(공통 POS전문에는 없는 데이타여서 미포함)
	//여권암호화여부
	memcpy( pOffSlip->passport_enc_yn, pRcvData->passport_enc_yn, sizeof(pOffSlip->passport_enc_yn));
	//여권영문이름
	memcpy( pOffSlip->passport_name, pRcvData->passport_name, sizeof(pOffSlip->passport_name));
	//여권번호
	memcpy( pOffSlip->passport_num, pRcvData->passport_num, sizeof(pOffSlip->passport_num));
	//여권국가
	memcpy( pOffSlip->passport_nation, pRcvData->passport_nation, sizeof(pOffSlip->passport_nation));
	//여권성별
	memcpy( pOffSlip->passport_sex, pRcvData->passport_sex, sizeof(pOffSlip->passport_sex));
	//여권생년월일
	memcpy( pOffSlip->passport_birth, pRcvData->passport_birth, sizeof(pOffSlip->passport_birth));
	//여권만료일
	memcpy( pOffSlip->passport_expire, pRcvData->passport_expire, sizeof(pOffSlip->passport_expire));
	// 응답코드 - 정상
	memcpy( pOffSlip->response_cd, "100", sizeof(pOffSlip->response_cd));
	// 응답메시지 
	//memcpy( pOffSlip->response_message, "정상", 4);
	// 매장명
	memcpy( pOffSlip->shop_name, pRcvData->shop_name, sizeof(pOffSlip->shop_name));
	//물품반복횟수 - 수신한 물품을 합하여, 잡화(13) 으로 처리 하므로, 1건으로 고정
	memcpy( pOffSlip->sequence_count, "0001", 4);
	// 반출유효기간 3개월 후일의 직전일
	Add_Months2( pOffSlip->sell_time, 3, pOffSlip->export_expiry_date );

	PrintLog("==>반출만료일[%.8s]\n",pOffSlip->export_expiry_date);

	// 영수증번호
	memcpy( pOffSlip->rct_no, pRcvData->rct_no, sizeof(pOffSlip->rct_no));
	// 즉시환급여부
	memcpy( pOffSlip->before_refund_yn, pRcvData->before_refund_yn, sizeof(pOffSlip->before_refund_yn));
	// 결제금액
	//memcpy( pOffSlip->payment_amount, pRcvData->payment_amount, sizeof(pOffSlip->payment_amount));
	// 반출승인번호
	//memcpy( pOffSlip->export_approval_num, pRcvData->export_approval_num, sizeof(pOffSlip->export_approval_num));
	// 즉시환급한도액
	//memcpy( pOffSlip->before_limit_amount, pRcvData->before_limit_amount, sizeof(pOffSlip->before_limit_amount));
	// 고유번호
	memcpy( pOffSlip->unique_num, pRcvData->unique_num, sizeof(pOffSlip->unique_num));
	// 비고
	memcpy( pOffSlip->extra2, pRcvData->extra2, sizeof(pOffSlip->extra2));


	// 물품건수
	memcpy( temp, pRcvData->sequence_count, sizeof(pRcvData->sequence_count));
	temp[sizeof(pRcvData->sequence_count)] = 0;
	int	nItemCnt = atoi(temp);
	PrintLog("==>pRcvData->sequence_count[%.*s]nItemCnt[%d]\n",sizeof(pRcvData->sequence_count),inbuff+326,nItemCnt);


	// 물품내역 시작(1 레코드만 입력 )
	// 물품 일련번호
	memcpy(pOffSlip->buy_detail[0].commodity_num,"001", 3);
	// 개별소비세구분 -- 1:부가세로 고정
	memcpy(pOffSlip->buy_detail[0].sct_div,"1", 1);
	//품목코드 -- 잡화(13)로 고정
	memcpy(pOffSlip->buy_detail[0].commodity_cd,"13", 2);
	//물품 내용
	memcpy( temp, pRcvData->buy_detail[0].commodity_cont, sizeof(pRcvData->buy_detail[0].commodity_cont));
	temp[sizeof(pRcvData->buy_detail[0].commodity_cont)] = 0;
	CString strProdName = CString(temp).Trim();
	CString strContents = "";
	if( nItemCnt == 1 )
		strContents.Format(_T("%s"), strProdName);
	else
		strContents.Format(_T("%s외%d건"), strProdName, nItemCnt-1);
	sprintf(buff, "%-*.*s", sizeof(pRcvData->buy_detail[0].commodity_cont),sizeof(pRcvData->buy_detail[0].commodity_cont),LPSTR(LPCTSTR(strContents)));
	PrintLog("==>commodity_cont[%s]\n", buff);
	//물품 내용 -- "1st 물품내용 외 n건" 으로
	memcpy(pOffSlip->buy_detail[0].commodity_cont, buff, sizeof(pOffSlip->buy_detail[0].commodity_cont));

	int		nVolumeSum=0;				//수량누적용			(–2,147,483,648 to 2,147,483,647	)
	int		nVolume=0;					//수량					
	int		nUnitPriceAmt=0;			//단가*수량 누적용		
	int		nSellPriceAmt=0;			//판매가격*수량 누적용	
	int		nVatSum=0;					//부가가치세누적용	
	int		nSctSum=0;					//개별소비세누적용	
	int		nEdtSum=0;					//교육세누적용		
	int		nFfvSum=0;					//농어촌특별세누적용
	int		nPrice=0;					//평균가

	// 개별소비세구분 4인경우 처리 구현 하지 않음 - 2016.09.07 손충희 차장
	/*
	int		nVolumeS=0;					//수량누적용			
	int		nUnitPriceAmtS=0;			//단가*수량 누적용		
	int		nSellPriceAmtS=0;			//판매가격*수량 누적용	
	int		lVatS=0;					//부가가치세누적용	
	int		lSctS=0;					//개별소비세누적용	
	int		lEdtS=0;					//교육세누적용		
	int		lFfvS=0;					//농어촌특별세누적용
	*/
	// int(–2,147,483,648 to 2,147,483,647), long(–2,147,483,648 to 2,147,483,647), long long(–9,223,372,036,854,775,808 to 9,223,372,036,854,775,807)


	for (int i=0; i< nItemCnt; i++ ) {
		//수량 누적
		memcpy( temp, pRcvData->buy_detail[i].volume, sizeof(pRcvData->buy_detail[i].volume));
		temp[sizeof(pRcvData->buy_detail[i].volume)] = 0;
		nVolume = atoi(temp);
		nVolumeSum += nVolume;

		//단가누적
		memcpy( temp, pRcvData->buy_detail[i].unit_price, sizeof(pRcvData->buy_detail[i].unit_price));
		temp[sizeof(pRcvData->buy_detail[i].unit_price)] = 0;
		nUnitPriceAmt += atoi(temp)*nVolume;

		//판매금액누적
		memcpy( temp, pRcvData->buy_detail[i].sell_price, sizeof(pRcvData->buy_detail[i].sell_price));
		temp[sizeof(pRcvData->buy_detail[i].sell_price)] = 0;
		nSellPriceAmt += atoi(temp);

		//부가가치세 누적
		memcpy( temp, pRcvData->buy_detail[i].vat, sizeof(pRcvData->buy_detail[i].vat));
		temp[sizeof(pRcvData->buy_detail[i].vat)] = 0;
		nVatSum += atoi(temp);

		//개별소비세 누적
		memcpy( temp, pRcvData->buy_detail[i].sct, sizeof(pRcvData->buy_detail[i].sct));
		temp[sizeof(pRcvData->buy_detail[i].sct)] = 0;
		nSctSum += atoi(temp);

		//교육세 누적
		memcpy( temp, pRcvData->buy_detail[i].et, sizeof(pRcvData->buy_detail[i].et));
		temp[sizeof(pRcvData->buy_detail[i].et)] = 0;
		nEdtSum += atoi(temp);

		//농어촌특별세 누적
		memcpy( temp, pRcvData->buy_detail[i].ffvst, sizeof(pRcvData->buy_detail[i].ffvst));
		temp[sizeof(pRcvData->buy_detail[i].ffvst)] = 0;
		nFfvSum += atoi(temp);
	}
	
	// 수량합계
	sprintf(buff, "%0*d", sizeof(pOffSlip->buy_detail[0].volume),nVolumeSum);
	PrintLog("==>volume[%s]\n", buff);
	memcpy(pOffSlip->buy_detail[0].volume, buff, sizeof(pOffSlip->buy_detail[0].volume));

	// 단가 평균으로 입력
	
	nPrice = nVolumeSum==0?0:nUnitPriceAmt/nVolumeSum;
	sprintf(buff, "%0*d", sizeof(pOffSlip->buy_detail[0].unit_price),nPrice);
	PrintLog("==>unit_price[%s]\n",buff);
	memcpy(pOffSlip->buy_detail[0].unit_price, buff, sizeof(pOffSlip->buy_detail[0].unit_price));

	// 판매금액 누적으로 입력 
	//nPrice = nVolumeSum==0?0:nSellPriceAmt/nVolumeSum; // 원래 판매금액 평균이었음
	sprintf(buff, "%0*d", sizeof(pOffSlip->buy_detail[0].sell_price),nSellPriceAmt);
	PrintLog("==>sell_price[%s]\n",buff);
	memcpy(pOffSlip->buy_detail[0].sell_price, buff, sizeof(pOffSlip->buy_detail[0].sell_price));

	// 부가가치세 누적
	sprintf(buff, "%0*d", sizeof(pOffSlip->buy_detail[0].vat),nVatSum);
	PrintLog("==>부가가치세[%s]\n",buff);
	memcpy(pOffSlip->buy_detail[0].vat, buff, sizeof(pOffSlip->buy_detail[0].vat));

	// 개별소비세 누적
	sprintf(buff, "%0*d", sizeof(pOffSlip->buy_detail[0].sct),nSctSum);
	PrintLog("==>개별소비세[%s]\n",buff);
	memcpy(pOffSlip->buy_detail[0].sct, buff, sizeof(pOffSlip->buy_detail[0].sct));

	// 교육세 누적
	sprintf(buff, "%0*d", sizeof(pOffSlip->buy_detail[0].et),nEdtSum);
	PrintLog("==>교육세[%s]\n",buff);
	memcpy(pOffSlip->buy_detail[0].et, buff, sizeof(pOffSlip->buy_detail[0].et));

	// 농어촌특별세 누적
	sprintf(buff, "%0*d", sizeof(pOffSlip->buy_detail[0].ffvst),nFfvSum);
	PrintLog("==>농어촌특별세[%s]\n",buff);
	memcpy(pOffSlip->buy_detail[0].ffvst, buff, sizeof(pOffSlip->buy_detail[0].ffvst));

	// 판매금액으로 부가세 환급 금액을 산출
	memcpy( temp, pRcvData->sell_sum_money, sizeof(pRcvData->sell_sum_money));
	temp[sizeof(pRcvData->sell_sum_money)] = 0;
	// 물품판매금액 합계와 헤더판매금액 불일치 검사
	if( nSellPriceAmt != atoi(temp) ) {
		PrintLog("SellAmt is not equal to SellAmtSum Error[%d<>%d]\n",nSellPriceAmt,atoi(temp) );
		MakeOfflineError("902", "물품판매금액합계가 헤더판매금액과 상이합니다.", inbuff, outbuff); // 환급 금액오류
		return ERR_PKT_SIZE;
	}
	nSellPriceAmt = atoi(temp);

	// 환급총액 / 총부가세
	sprintf(buff, "%0*d", sizeof(pOffSlip->refund_amount),getRefundAmt(nSellPriceAmt));
	PrintLog("==>판매금액[%d]-환급총액[%s]\n",nSellPriceAmt,buff);
	memcpy( pOffSlip->refund_amount, buff, sizeof(pOffSlip->refund_amount));

	return sizeof(refund_slip_t)-sizeof(buy_detail_t)*(MAX_BUY_CNT-1);
}

// 리턴 에러코드,에러메세지, 패킷사이즈 셋팅함수 
void	MakeOfflineError(char *pErrCode, char *pErrMsg, char *RequestMsg, char *RetMsg) 
{
	char	tbuff[100];
	refund_slip_t	 *pRetMsg;

	pRetMsg = ( refund_slip_t *)RetMsg;

	memcpy( RetMsg, RequestMsg, ERR_PKT_SIZE);

	memcpy( pRetMsg->response_cd, pErrCode, sizeof(pRetMsg->response_cd)); 
	strcpy_s( tbuff, sizeof(tbuff), pErrMsg );
	memcpy( pRetMsg->response_message, tbuff, strlen(tbuff) );
	sprintf_s( tbuff, "%0*d", sizeof(pRetMsg->sequence_count),0 );
	memcpy( pRetMsg->sequence_count, tbuff, strlen(tbuff) );
	sprintf_s( tbuff, "%0*d", sizeof(pRetMsg->length),ERR_PKT_SIZE );
	memcpy( pRetMsg->length, tbuff, strlen(tbuff) );
}


/*
DES_key_schedule keyschedc1;
DES_key_schedule keyschedc2;
DES_key_schedule keyschedc3;

void initKey()
{
	DES_set_key((DES_cblock *)"55CF39FF", &keyschedc1);
	DES_set_key((DES_cblock *)"886B50AE", &keyschedc2);
	DES_set_key((DES_cblock *)"9A0DCD57", &keyschedc3); 
}

extern "C" __declspec(dllexport) int __stdcall GTF_EncryptData(char *Input, 
															   char *Output)
{
	unsigned char intext[256], outtext[256];

	memset(intext,	0x07,	sizeof(intext)); //PKCS#5 padding (See documentation)
	memset(outtext,	0x00,	sizeof(outtext));

	initKey();
	
	memcpy(intext,	Input,	strlen(Input));

	for (int i=0; i<16; i += 8)
	{
		DES_ecb3_encrypt((DES_cblock *)(intext + i),
						(DES_cblock *)(outtext + i), 
						&keyschedc1, 
						&keyschedc2, 
						&keyschedc3,
						DES_ENCRYPT);
	}

	unsigned char *enc_str;

	int enc_size = Base64Encode((unsigned char *)outtext,	enc_str,	strlen((char *)outtext));	

	memcpy(Output,	enc_str,		enc_size);
	free(enc_str);

	return 1;
}

extern "C" __declspec(dllexport) int __stdcall GTF_DecryptData(char *Input, 
															   char *Output)
{
	unsigned char intext[256], outtext[256];
	unsigned char *dec_str;

	int dec_size = Base64Decode((unsigned char*)Input,	dec_str,	strlen(Input));

	memset(intext,	0x00,	sizeof(intext));
	memset(outtext,	0x00,	sizeof(outtext));

	memcpy(intext,		dec_str,	dec_size);

	free(dec_str);

	initKey();

	for (int i=0; i<16; i += 8)
	{
		DES_ecb3_encrypt((DES_cblock *)(intext + i),
						(DES_cblock *)(outtext + i), 
						&keyschedc1, 
						&keyschedc2, 
						&keyschedc3,
						DES_DECRYPT);
	}

	strcpy(Output,	(char *)outtext);

	return 1;
}
*/