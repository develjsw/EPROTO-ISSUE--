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
   

3. 이슈와 유사한 환경 구현 ( Local - Windows 기준 )
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
   - HTTPS 설정 추가 ( main.ts 파일 )
     ~~~
     import { NestFactory } from '@nestjs/core';
     import { AppModule } from './app.module';
     import * as fs from 'fs';

     async function bootstrap() {
       const httpsOptions = {
         key: fs.readFileSync('./key.pem'),
         cert: fs.readFileSync('./cert.pem'),
       };

       const app = await NestFactory.create(AppModule, { httpsOptions });
       await app.listen(443);
     }
     bootstrap();
     ~~~
   - HTTPS 설정 변경 ( main.ts 파일 )
     ~~~
     import { NestFactory } from '@nestjs/core';
     import { AppModule } from './app.module';
     import * as fs from 'fs';
    
     async function bootstrap() {
       const httpsOptions = {
         key: fs.readFileSync('./key.pem'),
         cert: fs.readFileSync('./cert.pem'),
         secureOptions: require('constants').SSL_OP_NO_TLSv1_3, // TLS 1.3 비활성화
       };
    
       const app = await NestFactory.create(AppModule, { httpsOptions });
       await app.listen(443);
     }
     bootstrap();
     ~~~
   - CURL 명령어로 TLS 특정 버전 설정 및 API 요청 테스트
     ~~~
     # tls 1.1 버전으로 협상 요청 - tls 1.2/ECDHE-RSA-AES128-GCM-SHA256 암호화 스위트로 협상 완료 ( SSL connection using TLSv1.2 / ECDHE-RSA-AES128-GCM-SHA256 )
     $ curl https://localhost -k --tlsv1.1 -v --trace-time
     
     # tls 1.2 버전으로 협상 요청 - tls 1.2/ECDHE-RSA-AES128-GCM-SHA256 암호화 스위트로 협상 완료 ( SSL connection using TLSv1.2 / ECDHE-RSA-AES128-GCM-SHA256 )
     $ curl https://localhost -k --tlsv1.2 -v --trace-time
     
     # tls 1.3 버전으로 협상 요청 - 위에서 Server측에 설정된 TLS 1.3 비활성화로 협상 실패 ( error:1409442E:SSL routines:ssl3_read_bytes:tlsv1 alert protocol version )
     $ curl https://localhost -k --tlsv1.3 -v --trace-time
     ~~~

   - ~~OpenSSL 설정파일 수정 ( 서버 - TLS 설정 제한 )~~
     - ~~OpenSSL 설정파일 위치 확인~~
       - ~~$ openssl version -d # EX) OPENSSLDIR: "/mingw64/ssl"~~
     - ~~설정파일 수정~~
       - ~~notepad++ 관리자 모드로 아래 경로 파일 열기~~
       - ~~path : C:\Program Files\Git\mingw64\ssl\openssl.cnf~~
     - ~~아래 내용 추가 후 저장~~
         ~~<br>[ default_conf ]<br>~~
         ~~ssl_conf = ssl_sect<br><br>~~
    
         ~~[ssl_sect]<br>~~
         ~~system_default = ssl_default_sect<br><br>~~
    
         ~~[ssl_default_sect]<br>~~
         ~~MinProtocol = TLSv1.2<br>~~
         ~~CipherString = DEFAULT:@SECLEVEL=2~~
