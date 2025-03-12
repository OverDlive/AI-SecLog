from dotenv import load_dotenv
load_dotenv() 

import openai
import os

# .env 파일에서 OPENAI_API_KEY 불러오기
openai.api_key = os.getenv("OPENAI_API_KEY")

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
    3) 대응 권장사항
    를 한국어로 간단히 알려줘.

    보안 로그:
    {log_text}
    """

    # 2) GPT API 호출
    response = openai.Completion.create(
        engine="gpt-4o",
        prompt=prompt,
        max_tokens=300,
        temperature=0.7
    )

    gpt_output = response["choices"][0]["text"].strip()

    # 예시: GPT 응답 파싱(단순 가정)
    # 실제로는 gpt_output에서 '위험도: ...' 같은 패턴 추출
    summary = gpt_output
    risk_level = "중간"  # 일단 하드코딩 예시
    recommendation = "추가 모니터링 및 IP 차단 검토"

    return summary, risk_level, recommendation