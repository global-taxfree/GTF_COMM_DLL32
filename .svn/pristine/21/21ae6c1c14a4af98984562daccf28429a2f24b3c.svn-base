const unsigned char table[64] = { 
     'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 
     'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 
     'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 
     'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 
     'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 
     'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 
     'w', 'x', 'y', 'z', '0', '1', '2', '3', 
     '4', '5', '6', '7', '8', '9', '+', '/' 
 }; 

 unsigned char GetIdx(unsigned char _data); 


 /**
 @param[in]  _szIn   Base64 를 적용할 문자열(\0 미포함 문자열을 의미)
 @param[out] _szOut  결과값을 저장할 버퍼의 포인터 (해당함수내에서 메모리 할당함)
 @param[in]  _nSize  _szIn 의 길이 (\0 를 제외한 길이)
 @result     성공시 _szOut 의 길이 (\0 를 제외한 길이)
 */ 
int Base64Encode(unsigned char * _szIn, unsigned char * &_szOutPtr, int _nSize) 
 { 
     // 입력오류 
    if(_szIn == NULL) 
     { 
         return -1; 
     } 

     if(_nSize <= 0) 
     { 
         return -1; 
     } 

     // 3 바이트 -> 4바이트로 변환하기 위해 메모리 계산 
    int p = _nSize / 3; 
     int q = _nSize % 3; 
     

     q = (3 - q); 

     unsigned char * szTemp = NULL; 
     szTemp = (unsigned char *) malloc (_nSize + q); 

     // 메모리 할당시 오류 
    if(szTemp == NULL) 
     { 
         return -1; 
     } 

     if(q) p++; 

     int ret = 4 * p; 
     _szOutPtr = (unsigned char*) malloc (ret + 1); 
     if(_szOutPtr == NULL) 
     { 
         return -1; 
     } 

     memset(szTemp, 0, _nSize + q); 
     memcpy(szTemp, _szIn, _nSize); 


     unsigned char * szOutsp = _szOutPtr, *ptr = NULL; 
     unsigned char b1, b2, b3, b4; 
     int i = 0; 


     while(i < (_nSize + q)) 
     { 
         b1 = (szTemp[i] & 0xFC) >> 2; 
         b2 = (((szTemp[i] & 0x03) << 4) | ((szTemp[i+1] & 0xF0) >> 4)); 
         b3 = (((szTemp[i+1] & 0xF) << 2) | ((szTemp[i+2] & 0xC0) >> 6)); 
         b4 = (szTemp[i+2] & 0x3F); 


 #ifdef _DEBUG 
         /*printf("%c %c %c %c\n", table[b1], table[b2], table[b3], table[b4]);  */
 #endif 

         ptr = szOutsp; 
         *szOutsp++ = table[b1]; 
         *szOutsp++ = table[b2]; 
         *szOutsp++ = table[b3]; 
         *szOutsp++ = table[b4]; 


         // 마지막 문자 3바이트 중 패딩문자는 = 로 치환 
        if(i == ((_nSize + q) - 3)) 
         { 
             if(q) 
             { 
                 if(q == 2) 
                 { 
                     *(ptr+2) = '='; 
                 } 
                 *(ptr+3) = '='; 
             } 

             break; 
         } 

         i += 3; 
     } 

     *(ptr+4) = '\0'; 

     free(szTemp);

     return (ret); 
 } 


 /**
 @param[in]  _szIn   디코딩할 문자열(\0 미포함 문자열을 의미)
 @param[out] _szOut  결과값을 저장할 버퍼의 포인터 (해당함수내에서 메모리 할당함)
 @param[in]  _nSize  _szIn 의 길이 (\0 를 제외한 길이)
 @result     성공시 _szOut 의 길이 (\0 를 제외한 길이)
 */ 
int Base64Decode(unsigned char * _szIn, unsigned char* &_szOutPtr, int _nSize) 
 { 
     if(_szIn == NULL) 
     { 
         return -1; 
     } 

     if(_nSize <= 0) 
     { 
         return -1; 
     } 

     int p = _nSize / 4; 
     int q = 0; 

     int i = 1; 
     while(_szIn[_nSize - i] == '=') 
     { 
         q++; 
         i++; 
     } 

     int ret = 3 * p + q; 
     _szOutPtr = (unsigned char *) malloc(ret + 1); 

     if(_szOutPtr == NULL) 
     { 
         return -1; 
     } 

     unsigned char * ptr = _szIn, *szOutTemp = _szOutPtr; 
     unsigned char i1, i2, i3, i4; 
     unsigned char o1, o2, o3; 

     i = 0; 

     while(i < _nSize) 
     { 
         i1 = GetIdx(ptr[i]); 
         i2 = GetIdx(ptr[i+1]); 
         i3 = GetIdx(ptr[i+2]); 
         i4 = GetIdx(ptr[i+3]); 

         if(i == (_nSize - 4)) 
         { 
             if(q) 
             { 
                 /*if(ptr[i+1] == '=') i2 = 0;*/ 
                 if(ptr[i+2] == '=') i3 = 0; 
                 if(ptr[i+3] == '=') i4 = 0; 
             } 
         } 

         o1 = (i1 << 2) | ((i2 & 0x30) >> 4); 
         o2 = ((i2 & 0xF) << 4) | ((i3 & 0x3C) >> 2); 
         o3 = ((i3 & 0x3) << 6) | i4; 

 #ifdef  _DEBUG 
       
 #endif 

         *szOutTemp++ = o1; 
         *szOutTemp++ = o2; 
         *szOutTemp++ = o3; 

         i += 4; 
     } 

     *szOutTemp = '\0'; 


     return (ret); 
 } 

 unsigned char GetIdx(unsigned char _data) 
 { 
     if(isupper(_data)) 
     { 
         // 대문자 0-25 
         return (_data - 65); 
     } 
     else if(islower(_data)) 
     { 
         // 소문자 26-51 
         return (_data - 71); 
     } 
     else if(_data >= '0' && _data <= '9') 
     { 
         // 숫자 52-61 
         return (_data - '0' + 52); 
     } 
     else 
     { 
         if(_data == '+') return 62; 
         if(_data == '/') return 63; 
     } 

     return (-1); 
 } 