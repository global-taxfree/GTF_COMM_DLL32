#include <Winsock2.h>

#define STX						0x02
#define ETX						0x03
#define ACK						0x06
#define NAK						0x15
#define ESC						0x1B
#define EOT						0x04
#define DLE						0x10
#define FS						0x1C
#define CR						0x0D

#define	BUFFER_SIZE				8192

#define ERR_VENDOR_INFO			-2001
#define ERR_VANOPTION_INFO		-2002
#define ERR_CRYPT_CARD_INFO		-2003
#define ERR_CRYPTO_ERRCODE		-2004
#define ERR_RSA_ENCRYPT			-2005
#define ERR_SEED_ENCRYPT		-2006
#define ERR_SEED_DECRYPT		-2007

#define ERR_REQ_MSG_NO_LENGTH	-3301
#define ERR_REQ_MSG_LENGTH		-3302
#define ERR_REQ_MSG_CMD			-3303
#define ERR_CONNECT_SERV		-3401
#define ERR_SEND_MSG			-3402
#define ERR_RECV_MSG			-3403
#define ERR_RES_MSG_NO_LENGTH	-3304
#define ERR_RECV_EOT			-3405

#define CONNECT_TIMEOUT			6
#define READ_TIMEOUT			17

int ConnectServer(char *P_Addr, int P_Port, int ReadTimeOut);
int Write_Line(SOCKET fd, char *sendbuf, int len);
int Read_Line(SOCKET fd, char *recvbuf, int len);
int SockReceiveTimeOut(SOCKET fd, char *recvdata, int timeout, int readsize);

// 구매내역건수 최대
#define	MAX_BUY_CNT	50

// refund slip 구매내역(반복)
typedef struct buy_detail {
	char commodity_num			[3];	// 물품 일련번호
	char sct_div                [1];	// 개별소비세구분
	char commodity_cd           [2];	// 물품코드
	char commodity_cont         [50];	// 물품 내용
	char volume                 [4];	// 수량
	char unit_price             [9];	// 단가
	char sell_price             [9];	// 판매금액
	char vat                    [8];	// 부가가치세
	char sct                    [8];	// 개별소비세
	char et                     [8];	// 교육세
	char ffvst                  [8];	// 농어촌특별세
	char extra                  [16];	// 비고

} buy_detail_t;

// refund slip 공통헤더
typedef struct refund_slip {
	char length					[5];	// 전문길이
	char EDI                    [2];	// 업무구분
	char version                [10];	// 전문버전
	char document_cd            [3];	// 문서코드
	char buy_serial_num         [20];	// 구매 일련번호
	char buyer_cancel_chk       [1];	// 구매 취소여부
	char trade_approval_num     [10];	// 거래 승인번호
	char seller_busi_regist_num [10];	// 판매자 사업자등록번호
	char terminal_id            [10];	// 단말기ID
	char sell_time              [14];	// 판매 년월일시
	char sell_sum_total         [4];	// 판매 총수량
	char sell_sum_money         [9];	// 판매 총금액
	char refund_amount          [8];	// 환급총액 / 총부가세
	char payment_type           [1];	// 결제 유형
	char extra                  [35];	// 비고
	char passport_enc_yn        [1];	// 여권암호화여부
	char passport_name          [40];	// 여권영문이름
	char passport_num           [24];	// 여권번호
	char passport_nation        [3];	// 여권국가코드
	char passport_sex           [1];	// 여권성별
	char passport_birth         [6];	// 여권생년월일
	char passport_expire        [6];	// 여권만료일
	char response_cd            [3];	// 응답코드
	char response_message       [60];	// 응답메시지
	char shop_name              [40];	// 매장명
	char sequence_count         [4];	// 물품부반복횟수
	char export_expiry_date     [8];	// 반출유효기간
	char rct_no                 [30];	// 영수증번호
	char before_refund_yn       [1];	// 즉시환급여부
	char payment_amount         [9];	// 결제금액
	char export_approval_num    [30];	// 반출승인번호
	char before_limit_amount    [10];	// 즉시환급한도액
	char unique_num             [20];	// 고유번호
	char extra2                 [80];	// 비고
	buy_detail_t buy_detail[MAX_BUY_CNT];	// 구매내역
	
} refund_slip_t;

#define	ERR_PKT_SIZE	sizeof(refund_slip_t)-sizeof(buy_detail_t)*MAX_BUY_CNT