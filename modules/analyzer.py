from dotenv import load_dotenv
load_dotenv() 

import openai
import os

# .env 파일에서 OPENAI_API_KEY 불러오기
API_KEY = os.getenv("OPENAI_API_KEY")
openai.api_key = API_KEY

def analyze_logs(log_text: str):
    """
    보안 로그 텍스트를 GPT에 전달하고,
    요약 결과와 위험도, 대응 방안을 반환
    """
    # 1) GPT 프롬프트 구성
    prompt = f"""
    다음 보안 로그를 분석하고,
    1) 공격 유형 / 특징 요약
    2) 위험도 (높음/중간/낮음)
    3) 대응 권장사항을 한국어로 간단히 알려줘.

    보안 로그:
    {log_text}
    """

    # 2) GPT API 호출 (ChatCompletion 사용)
    response = openai.ChatCompletion.create(
        model="gpt-4",  # 올바른 모델 이름
        messages=[
            {"role": "system", "content": "너는 웹 로그를 분석하는 도움이야."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=300,
        temperature=0.7
    )

    # 응답에서 결과 추출
    gpt_output = response["choices"][0]["message"]["content"].strip()

    # 예시: GPT 응답 파싱 (실제 응답 형식에 따라 파싱 로직 조정 필요)
    summary = gpt_output
    risk_level = "중간"            # 예시 값 (실제 위험도 분석 로직 필요)
    recommendation = "추가 모니터링 및 IP 차단 검토"  # 예시 값

    return summary, risk_level, recommendation
