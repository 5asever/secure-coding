# Secure Coding

## Tiny Secondhand Shopping Platform

이 리포지토리는 Flask 기반의 중고거래 플랫폼 예제입니다.

---

## 📋 사전 준비

- Python 3.8 이상  
- MySQL
- (선택) 외부 접속 테스트를 위한 ngrok
- 가상환경 venv 만들기
- 

---

## 가상 환경 설정 (venv)

1. 리포지토리 클론  
git clone https://github.com/ugonfor/secure-coding.git
cd secure-coding

2. 가상 환경 생성 및 활성화
python3 -m venv venv
(Linux/macOS) source venv/bin/activate
(Windows) venv\Scripts\activate.bat

3. 의존성 패키지 설치
pip install --upgrade pip
pip install -r requirements.txt

4. 실행
python app.py


(선택)
# ngrok 설치 (Snap)
sudo snap install ngrok

# HTTP 5000 포트 공개
ngrok http 5000

