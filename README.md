# Secure Coding - Tiny Secondhand Shopping Platform

Flask 기반의 간단한 중고거래 플랫폼입니다.

기존 애플리케이션의 보안 취약점을 분석하고, 인증·인가·입력 검증·CSRF 방어·송금 무결성·파일 업로드 검증·실시간 채팅 보안·감사 로그 등의 보안 기능을 적용하였습니다.

## 주요 기능

- 회원가입 및 로그인
- 사용자 프로필 관리
- 상품 등록 / 조회 / 수정 / 삭제
- 상품 이미지 업로드
- 사용자 및 상품 신고
- 사용자 간 송금
- Socket.IO 기반 실시간 채팅
- 주요 보안 이벤트 감사 로그

## 주요 보안 기능

### 인증 및 계정 보호

- Argon2id 기반 비밀번호 해싱
- 로그인 실패 횟수 제한
- 반복 로그인 실패 시 계정 일시 잠금
- 세션 기반 사용자 인증
- HttpOnly / SameSite 세션 쿠키 적용

### 접근 제어

- 로그인 여부에 따른 기능 접근 제한
- 프로필 수정 시 세션의 사용자 ID 사용
- 상품 수정 및 삭제 시 소유권 검증
- 송금 및 신고 대상에 대한 서버 측 검증

### CSRF 방어

Flask-WTF의 CSRFProtect를 적용하여 상태를 변경하는 POST 요청에 CSRF 토큰을 검증합니다.

### 입력값 및 XSS 방어

- 상품명, 설명, 가격 등 서버 측 입력값 검증
- 프로필 및 신고 사유 길이 제한
- 채팅 메시지 길이 제한
- Jinja2 autoescape 및 안전한 DOM API 사용
- Content Security Policy 적용

### 송금 보안

- 송금액 서버 측 검증
- 잔액 초과 송금 방지
- 자기 자신에게 송금 방지
- DB 트랜잭션을 이용한 잔액 변경 및 송금 기록의 원자성 보장
- idempotency key를 이용한 중복 송금 방지

### 채팅 보안

- 클라이언트가 전달한 사용자명을 신뢰하지 않고 세션을 통해 송신자 확인
- 메시지 DB 저장
- 채팅 내역 재조회
- 메시지 길이 검증
- Rate Limit을 이용한 채팅 도배 방지
- textContent 기반 메시지 출력으로 DOM XSS 방지

### 파일 업로드 보안

- 업로드 요청 크기 제한
- Pillow를 이용한 실제 이미지 검증
- 이미지 크기 및 해상도 제한
- 서버에서 JPEG로 재인코딩
- UUID 기반 서버 파일명 생성
- 원본 파일명을 저장 경로로 사용하지 않음
- 상품 삭제 시 관련 이미지 파일 삭제

### HTTP 보안 헤더

다음과 같은 HTTP 보안 헤더를 적용합니다.

- Content-Security-Policy
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy

### 감사 로그

다음과 같은 주요 보안 이벤트를 `audit_log` 테이블에 기록합니다.

- 회원가입
- 로그인 성공 / 실패
- 계정 잠금
- 상품 생성 / 수정 / 삭제
- 송금
- 신고

비밀번호, 세션 ID, CSRF 토큰 등의 민감정보는 감사 로그에 기록하지 않습니다.

## 실행 환경

개발 및 테스트 환경:

- Python 3.14
- Flask 3.1
- SQLite
- Flask-SocketIO
- Flask-WTF
- Flask-Limiter
- Argon2
- Pillow

## 설치 및 실행

### 1. 저장소 복제

```bash
git clone <repository-url>
cd secure_coding
```

### 2. 가상환경 생성

```bash
python -m venv .venv
```

Bash / Zsh:

```bash
source .venv/bin/activate
```

Fish:

```fish
source .venv/bin/activate.fish
```

### 3. 의존성 설치

```bash
pip install -r requirements.txt
```

### 4. 환경변수 설정

예제 파일을 복사합니다.

```bash
cp .env.example .env
```

`.env`의 `SECRET_KEY`를 안전한 랜덤 값으로 변경합니다.

예를 들어 Python을 이용해 생성할 수 있습니다.

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

생성된 값을 `.env`에 설정합니다.

```env
SECRET_KEY=<generated-secret-key>
FLASK_DEBUG=false
```

`.env` 파일에는 실제 비밀값이 포함되므로 Git 저장소에 커밋하지 않습니다.

### 5. 서버 실행

```bash
python app.py
```

실행 후 브라우저에서 다음 주소로 접속합니다.

```text
http://127.0.0.1:5000
```

## 데이터베이스

SQLite를 사용하며 최초 실행 시 `market.db`가 자동으로 생성됩니다.

다음 테이블이 생성됩니다.

- `user`
- `product`
- `report`
- `message`
- `transfer`
- `audit_log`

개발 과정에서 기존 DB를 제거한 상태에서도 애플리케이션을 실행하여 전체 스키마가 정상적으로 재생성되는 것을 확인하였습니다.

## 테스트

신규 데이터베이스 환경에서 다음 기능을 직접 검증하였습니다.

- 회원가입 및 로그인
- Argon2id 비밀번호 저장
- 로그인 실패 및 계정 잠금
- 프로필 수정
- CSRF 요청 차단
- 상품 등록 / 수정 / 삭제
- 이미지 업로드 및 위장 파일 차단
- 사용자 / 상품 신고
- 정상 송금 및 잔액 초과 송금 차단
- 실시간 채팅 및 채팅 내역 저장
- XSS 문자열의 비실행 확인
- 채팅 Rate Limit
- 상품 삭제 시 이미지 파일 제거
- 감사 로그 생성
- 신규 DB 자동 생성

## 주의사항

이 프로젝트는 교육 목적의 개발 서버를 기준으로 작성되었습니다.

Flask 내장 개발 서버는 운영 환경용 서버가 아니므로 실제 서비스 배포 시에는 별도의 WSGI 서버, HTTPS, 운영 환경에 맞는 비밀정보 관리 및 추가적인 보안 설정이 필요합니다.
