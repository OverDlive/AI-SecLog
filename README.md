![header](https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=10&height=200&text=AI%20SECLOG&fontSize=50&animation=twinkling&fontAlign=68&fontAlignY=36)
## 프로젝트 개요
AI-SecLog는 GPT 모델을 활용하여 웹 로그 데이터를 자동으로 분석하고, 보안 위협에 대한 요약, 위험 등급 평가 및 대응 권장사항을 제공하는 도구입니다. 이 프로젝트는 보안 전문가뿐 아니라 일반 사용자도 로그를 쉽게 해석하고 신속하게 대응할 수 있도록 설계되었습니다.

## 주요 특징
- 자동 로그 분석
AI가 웹 로그를 분석하여 공격 유형 및 특징을 요약합니다.
- 위험 등급 평가
로그 분석 결과를 기반으로 위험도를 높음/중간/낮음으로 분류합니다.
- 대응 권장사항 제공
분석 결과에 따른 대응 권장사항(예: 추가 모니터링, IP 차단 등)을 제공합니다.
- 사용자 친화적 대시보드
Streamlit을 활용한 직관적인 웹 인터페이스로 결과를 확인할 수 있습니다.

## 프로젝트 구조
```plant
.
├── app.py
├── image
│   └── logo.png
├── LICENSE
├── logfile
│   ├── access_log
│   ├── access_log.1
│   ├── access_log.10
│   ├── access_log.11
│   ├── access_log.12
│   ├── access_log.2
│   ├── access_log.3
│   ├── access_log.4
│   ├── access_log.5
│   ├── access_log.6
│   ├── access_log.7
│   ├── access_log.8
│   ├── access_log.9
│   ├── agent_log.1
│   ├── audit_log
│   ├── error_log.2
│   ├── referer_log.1
│   └── ssl_error_log.1
├── modules
│   ├── __pycache__
│   │   └── analyzer.cpython-312.pyc
│   ├── analysis_results.json
│   ├── analyzer.py
│   ├── json.py
│   └── testlog
├── README.md
├── requirements.txt
└── sample attack logs.txt
```
---
## 설치 및 설정
1. 클론 및 가상환경 설정
```bash
git clone https://github.com/OverDlive/AI-SecLog.git
cd AI-SecLog
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
```
## 의존성 설치
```bash
pip install -r requirements.txt
```

## 환경 변수 설정
프로젝트 루트에 .env 파일을 생성하고 아래와 같이 API 키를 입력합니다.
```
OPENAI_API_KEY='api-key'
```
---
## 사용방법
1. 애플리케이션 실행
    ```bash
    streamlit run app.py
    ```
2. 웹 브라우저에서 접속
기본적으로 http://localhost:8501 주소에서 애플리케이션을 확인할 수 있습니다.
3.	로그 입력 및 분석
	•	텍스트 입력란에 분석할 보안 로그를 입력합니다.
	•	“분석하기” 버튼을 클릭하면, AI가 로그를 분석하여 요약 결과, 위험 등급, 대응 권장사항을 화면에 출력합니다.

## 개발 방식
- 프론트엔드:
Streamlit을 사용하여 간단한 웹 대시보드를 구축하고, 사용자 입력 및 결과 표시를 담당합니다.
- 백엔드:
Python 기반 모듈(modules/analyzer.py)에서 GPT API를 호출하여 로그 데이터를 분석합니다.
- AI 연동:
OpenAI의 ChatCompletion API를 사용하여 GPT-4 모델로 로그 요약 및 보안 분석을 수행합니다.

## 기여 방법
1.	Fork & Clone
본 레포지토리를 fork한 후, 로컬 환경에 클론합니다.
2.	새로운 브랜치 생성
    ```bash
    git checkout -b feature/새로운기능
    ```
3. 코드 수정 및 테스트
변경 사항을 추가한 후, 충분히 테스트합니다.
4. Pull Request 제출
변경 사항을 main브랜치에 반영할 수 있도록 PR을 제출합니다.
## 라이선스

이 프로젝트는 MIT License 하에 배포됩니다.


## 참고 자료
- OpenAI ChatCompletion API 문서
- Streamlit Documentation
