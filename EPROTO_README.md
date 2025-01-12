### NestJS API Server에서 발생했던 TLS/SSL 이슈 정리

1. 이슈 내용
   - Node.js v.16 API Server에서 특정 외부 API와의 통신에서 아래와 같은 에러가 발생함
     ~~~
     ApiRequestException: Error: write EPROTO 140011552446400:error:14094438:SSL routines:ssl3_read_bytes:tlsv1 alert internal error:../deps/openssl/openssl/ssl/record/rec_layer_s3.c:1565:SSL alert number 80
     ~~~
   - 위에 에러를 잘 살펴보면, `TLS/SSL 핸드셰이크 중 발생한 오류`임을 확인할 수 있으며, 자세하게 다시 설명하면 아래와 같음
     - TLS/SSL 핸드셰이크 실패 :
       - TLS 프로토콜 경고 ( internal_error ) 또는 핸드셰이크 중 서버 내부 문제
     - EPROTO 프로토콜 오류 :
       - TLS 핸드셰이크 중 프로토콜 위반으로 인해 연결이 중단됨
     - TLS Alert Internal Error ( SSL Alert 80 ) :
       - 서버에서 발생한 내부 TLS/SSL 설정 문제 또는 리소스 제한
       

2. 예상 원인
   - 서버 내부 오류 :
     - EX) 리소스 부족, 잘못된 TLS 설정
   - 클라이언트와 서버 간 호환성 문제 :
     - EX) TLS 버전, 암호화 스위트, 인증서 등


3. 에러 재현 및 원인 분석
   1) 테스트 환경 구성 ( Local ) 후 TLS 버전 변경해가며 테스트 진행
      - OpenSSL 다운로드 및 환경변수 설정
        - Download : https://slproweb.com/products/Win32OpenSSL.html
        - 참고 사이트 : https://chris1108.tistory.com/36 
      - NestJS API 생성
        - Node 설치와 @nestjs/cli 패키지 글로벌 설치는 되어 있다고 가정하고 진행
        - NestJS Project 생성
          ~~~
          $ cd 프로젝트 생성할 위치
          $ nest new test-project
          $ npm i
          ~~~
      - HTTPS 서버 설정을 위해 인증서와 키 생성
        ~~~
        $ cd 프로젝트 생성한 위치

        # 아래 명령어 실행 후에는 key.pem, cert.pem 파일이 현재 위치에 생성됨
        $ openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365
        ~~~
      - HTTPS 설정 추가/변경 ( main.ts 파일 )
        ~~~
        import { NestFactory } from '@nestjs/core';
        import { AppModule } from './app.module';
        import * as fs from 'fs';

        async function bootstrap() {
          const httpsOptions = {
            key: fs.readFileSync('./key.pem'),
            cert: fs.readFileSync('./cert.pem'),
            secureOptions: require('constants').SSL_OP_NO_TLSv1_3, // TLS 1.3 비활성화 - 이 부분에서 버전을 변경해가며 테스트 진행
          };

          const app = await NestFactory.create(AppModule, { httpsOptions });
          await app.listen(443);
        }
        bootstrap();
        ~~~
      - CURL 명령어로 TLS 협상 테스트 ( 다양한 TLS 버전으로 테스트 진행 )

        | **TLS 요청 버전** | **결과 TLS 버전** | **암호화 스위트**              | **결과**                                                                                                             | **사용 명령어**                                              |
        |---------|---------|--------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------|----------------------------------|
        | TLS 1.1 | TLS 1.2 | ECDHE-RSA-AES128-GCM-SHA256      | TLS 1.2로 업그레이드 협상 완료                                                                                               | `$ curl https://localhost -k --tlsv1.1 -v --trace-time` |
        | TLS 1.2 | TLS 1.2 | ECDHE-RSA-AES128-GCM-SHA256      | TLS 1.2로 정상 협상 완료                                                                                                  | `$ curl https://localhost -k --tlsv1.2 -v --trace-time`   |
        | TLS 1.3 | 실패     | -                                | 서버에 TLS 1.3 비활성화 설정한 부분으로 협상 실패 에러 발생 ( error:1409442E:SSL routines:ssl3_read_bytes:tlsv1 alert protocol version ) | `$ curl https://localhost -k --tlsv1.3 -v --trace-time`   |
      - 결과 : 동일한 에러 재현 불가
      
   2) openssl s_client 명령어를 통해 TLS 협상 확인 ( 운영서버에서 진행 )
   
      | **TLS 요청 버전** | **결과 TLS 버전** | **암호화 스위트**              | **결과**                                 | **사용 명령어**                                                                 |
      |-------------------|-------------------|----------------------------------------|-----------------------------------------------------------|--------------------------------------------------------------------------------|
      | TLS 1.1           | 실패             | -                             | 서버에서 지원하지 않아 협상 실패 ( alert number 70 ) | `openssl s_client -connect [서버 주소]:[포트] -tls1_1 -msg`                    |
      | TLS 1.2           | TLS 1.2          | ECDHE-RSA-AES256-GCM-SHA384   | 정상 협상 완료                              | `openssl s_client -connect [서버 주소]:[포트] -tls1_2 -msg`                    |
      | TLS 1.3           | TLS 1.3          | TLS_AES_256_GCM_SHA384        | 정상 협상 완료                              | `openssl s_client -connect [서버 주소]:[포트] -tls1_3 -msg`                    |
      
   3) Docker Swarm 환경에서 TLS 디버깅 활성화 ( 운영서버에서 진행 )
     - Docker Swarm 서비스 업데이트 명령어에 TLS 디버깅 모드 환경변수 추가하여 진행
       ~~~
       $ env-add NODE_DEBUG=tls # TLS 디버깅 모드 환경변수 추가
       $ env-rm NODE_DEBUG # 추가한 디버깅 모드 환경변수 제거
    
       EX) docker service update --env-add NODE_DEBUG=tls --image [AWS 계정 ID].dkr.ecr.ap-northeast-2.amazonaws.com/dev_portal_out_api:${배포할 이미지 태그} --with-registry-auth [Docker Swarm 서비스 이름]
       EX) docker service update --env-rm NODE_DEBUG --image [AWS 계정 ID].dkr.ecr.ap-northeast-2.amazonaws.com/dev_portal_out_api:${배포할 이미지 태그} --with-registry-auth [Docker Swarm 서비스 이름]
       ~~~
     - 결과 : 별다른 로그 확인할 수 없었음
   4) 암호화 스위트 및 TLS 버전 테스트 ( 운영서버에서 진행 )
     - $ openssl ciphers -v 명령어를 통해 서버에서 사용가능한 Cipher 목록 파악
     - TLS 버전과 사용가능한 Cipher 목록을 조합하여 별도의 테스트 코드 작성 후 진행
       ~~~
       # 사용 가능한 Cipher 목록
       
       TLS_AES_256_GCM_SHA384              TLSv1.3 Kx=any      Au=any  Enc=AESGCM(256) Mac=AEAD
       TLS_CHACHA20_POLY1305_SHA256        TLSv1.3 Kx=any      Au=any  Enc=CHACHA20/POLY1305(256) Mac=AEAD
       TLS_AES_128_GCM_SHA256              TLSv1.3 Kx=any      Au=any  Enc=AESGCM(128) Mac=AEAD
       ECDHE-ECDSA-AES256-GCM-SHA384       TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AESGCM(256) Mac=AEAD
       ECDHE-RSA-AES256-GCM-SHA384         TLSv1.2 Kx=ECDH     Au=RSA  Enc=AESGCM(256) Mac=AEAD
       DHE-RSA-AES256-GCM-SHA384           TLSv1.2 Kx=DH       Au=RSA  Enc=AESGCM(256) Mac=AEAD
       ECDHE-ECDSA-CHACHA20-POLY1305       TLSv1.2 Kx=ECDH     Au=ECDSA Enc=CHACHA20/POLY1305(256) Mac=AEAD
       ECDHE-RSA-CHACHA20-POLY1305         TLSv1.2 Kx=ECDH     Au=RSA  Enc=CHACHA20/POLY1305(256) Mac=AEAD
       DHE-RSA-CHACHA20-POLY1305           TLSv1.2 Kx=DH       Au=RSA  Enc=CHACHA20/POLY1305(256) Mac=AEAD
       ECDHE-ECDSA-AES128-GCM-SHA256       TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AESGCM(128) Mac=AEAD
       ECDHE-RSA-AES128-GCM-SHA256         TLSv1.2 Kx=ECDH     Au=RSA  Enc=AESGCM(128) Mac=AEAD
       DHE-RSA-AES128-GCM-SHA256           TLSv1.2 Kx=DH       Au=RSA  Enc=AESGCM(128) Mac=AEAD
       ECDHE-ECDSA-AES256-SHA384           TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AES(256)  Mac=SHA384
       ECDHE-RSA-AES256-SHA384             TLSv1.2 Kx=ECDH     Au=RSA  Enc=AES(256)  Mac=SHA384
       DHE-RSA-AES256-SHA256               TLSv1.2 Kx=DH       Au=RSA  Enc=AES(256)  Mac=SHA256
       ECDHE-ECDSA-AES128-SHA256           TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AES(128)  Mac=SHA256
       ECDHE-RSA-AES128-SHA256             TLSv1.2 Kx=ECDH     Au=RSA  Enc=AES(128)  Mac=SHA256
       DHE-RSA-AES128-SHA256               TLSv1.2 Kx=DH       Au=RSA  Enc=AES(128)  Mac=SHA256
       ECDHE-ECDSA-AES256-SHA              TLSv1 Kx=ECDH       Au=ECDSA Enc=AES(256)  Mac=SHA1
       ECDHE-RSA-AES256-SHA                TLSv1 Kx=ECDH       Au=RSA  Enc=AES(256)  Mac=SHA1
       DHE-RSA-AES256-SHA                  SSLv3 Kx=DH         Au=RSA  Enc=AES(256)  Mac=SHA1
       ECDHE-ECDSA-AES128-SHA              TLSv1 Kx=ECDH       Au=ECDSA Enc=AES(128)  Mac=SHA1
       ECDHE-RSA-AES128-SHA                TLSv1 Kx=ECDH       Au=RSA  Enc=AES(128)  Mac=SHA1
       DHE-RSA-AES128-SHA                  SSLv3 Kx=DH         Au=RSA  Enc=AES(128)  Mac=SHA1
       AES256-GCM-SHA384                   TLSv1.2 Kx=RSA      Au=RSA  Enc=AESGCM(256) Mac=AEAD
       AES128-GCM-SHA256                   TLSv1.2 Kx=RSA      Au=RSA  Enc=AESGCM(128) Mac=AEAD
       AES256-SHA256                       TLSv1.2 Kx=RSA      Au=RSA  Enc=AES(256)  Mac=SHA256
       AES128-SHA256                       TLSv1.2 Kx=RSA      Au=RSA  Enc=AES(128)  Mac=SHA256
       AES256-SHA                          SSLv3 Kx=RSA        Au=RSA  Enc=AES(256)  Mac=SHA1
       AES128-SHA                          SSLv3 Kx=RSA        Au=RSA  Enc=AES(128)  Mac=SHA1
       ~~~
       ~~~
       import { Injectable } from '@nestjs/common';
       import { HttpService } from '@nestjs/axios';
       import * as https from 'https';
       import { lastValueFrom } from 'rxjs';
       import axios, { AxiosResponse, Method } from 'axios';
       import { ApiRequestException } from '@src/exception/api-request.exception';

       @Injectable()
       export class TestService {
         constructor(private readonly httpService: HttpService) {}

         // TLS 버전과 Cipher Suite가 모두 협상할 수 없는 상태인 경우에만 SSL alert number 에러가 발생함
         async fetchWithTlsDebug(url: string): Promise<void> {
           const httpsAgent = new https.Agent({
             rejectUnauthorized: false, // 테스트용 (인증서 검증 비활성화)
             minVersion: 'TLSv1.2', // (최소) TLS 버전
             maxVersion: 'TLSv1.2', // (최대) TLS 버전
             ciphers: 'AES128-SHA', // 약한 암호화 방식
             //ciphers: 'DHE-RSA-AES128-SHA', // 일부 서버에서 비활성화된 DHE 기반 Suite
           });

           try {
             const response: AxiosResponse = await lastValueFrom(
                 this.httpService.request({
                     url,
                     method: 'get',
                     httpsAgent
                 })
             );

             const { socket } = response.request;

             // TLS 관련 정보 출력
             console.log('TLS Protocol : ', socket.getProtocol());
             console.log('Cipher Suite : ', socket.getCipher());
             console.log('Peer Certificate : ', socket.getPeerCertificate());
       
           } catch (error: any) {
             if (axios.isAxiosError(error)) {
                 throw new ApiRequestException(error);
             } else {
                 throw error;
             }
           }
         }
       }
       ~~~
     - 결과 :
       - alert number 70 ( TLS 버전 불일치 ), alert number 30 ( 암호화 키 교환 실패 또는 데이터 손상 ) 에러는 발생시킬 수 있었지만 alert number 80 ( 범용적인 TLS 실패 ) 에러는 재현 불가
       - 다만, 실제 합의는 TLS 1.3 버전으로 되고 있다는 점을 확인함
         ~~~
         # TLS 관련 정보 출력한 내용
         
         | TLS Protocol :  TLSv1.3
         | Cipher Suite :  {
         |   name: 'TLS_AES_256_GCM_SHA384',
         |   standardName: 'TLS_AES_256_GCM_SHA384',
         |   version: 'TLSv1.3'
         | }
         | Peer Certificate :  {}
         | https:
         ~~~


4. WireShark 툴을 활용하여 패킷 분석
  - 네트워크 패킷 캡처
     - tcpdump 명령어 사용 ( 운영 서버에서 실행 )
       ~~~
       $ tcpdump -i eth0 host [타겟 Host] and port 443 -c 100 -w /tmp/[파일명].pcap
       ~~~
     - 로컬로 패킷 파일 복사
       ~~~
       # 로컬에서 실행 : 원격지(운영 Host Server) → 로컬 파일 복사
       $ scp -P [원격지 포트] [원격지 사용자 계정]@[원격지 아이피]:/tmp/[파일명].pcap "C:\Users\[Windows 사용자 계정]" 
       ~~~
  - WireShark로 패킷 분석 ( Local에서 진행 )
     - WireShark 다운로드 : https://www.wireshark.org/download.html
     - 패킷 파일 불러오기
       - Local에서 복사한 .pcap 파일을 WireShark로 열어 분석
       - TLS 핸드셰이크 및 알림 ( alert ) 메시지 확인
  - 분석 결과
    - TLSv1.2 : 
      - TLSv1.2로 요청 시 10건 중 2~3건에서 핸드셰이크 실패 ( alert number 80 ) 가 불규칙적으로 발생
      - 서버 또는 클라이언트의 TLS 협상 과정에서 암호화 스위트 호환성 문제 또는 리소스 부족 가능성 확인
    - TLSv1.3 :
      - TLSv1.3 요청 시 핸드셰이크 실패 발생하지 않음
      - TLSv1.3에서는 협상 과정 및 암호화 스위트 설정이 안정적으로 동작
      

5. 개선 조치
  - 클라이언트 측 TLS 버전을 1.3으로 고정하여 테스트 진행
  - 결과적으로 TLSv1.2에서 발생하던 불규칙적인 핸드셰이크 실패가 일 평균 1~2건으로 감소하며 안정성 개선 확인
  - 핸드셰이크 시간이 단축되며, 전체 요청 처리 속도가 20~30% 개선됨