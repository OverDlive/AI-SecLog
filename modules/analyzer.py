import re
import json
from openai import OpenAI
from typing import List, Dict, Any

class WebAttackAnalyzer:
    """웹 로그에서 공격 패턴을 탐지하고 분석하는 클래스"""
    
    # 공격 패턴 정규식 목록
    ATTACK_PATTERNS = [
        # SQL 인젝션 패턴
        r"(?i)(\b(select|insert|update|delete|drop|alter|union|exec|declare|cast)\b.*\b(from|into|where|table|database)\b)|(\b(waitfor|delay|sleep)\b.*\d+)|('(''|[^'])*'(''|'|[^'])*')|(--[^\r\n]*)|(/\*[^*]*\*/)",
        # XSS 패턴
        r"(?i)(<script[^>]*>.*</script>|<iframe[^>]*>.*</iframe>|javascript:|alert\(|onmouseover=|onclick=|onerror=)",
        # 디렉토리 탐색 패턴
        r"(?i)((\.\./|\.\./\./|\.\.\\|\.\.\\\.\.\\|/etc/passwd|/etc/shadow|/proc/self/environ|/proc/\d+/fd/\d+))",
        # 명령어 인젝션 패턴
        r"(?i)(\||;|`|\$\(|\$\{|&&|\|\||ping -c|wget |curl |nc |netcat |ncat |bash -|sh -|python -c|chmod |chown |killall |/bin/|/dev/)",
        # 파일 업로드 시도 패턴
        r"(?i)(\.php|\.jsp|\.asp|\.aspx|\.exe|\.sh|\.pl|\.cgi|\.bat)(\s|$)",
        # LFI/RFI 패턴
        r"(?i)((\?|&)(file|page|url|path|include|dir|location|folder|doc|document|site|view|content)=)",
        # 기본 웹 공격 패턴(비정상적 요청)
        r"(?i)(\.htaccess|\.git/|\.svn/|\/config\.php|\?XDEBUG_SESSION_START=|acunetix|appscan)"
    ]
    
    def __init__(self, openai_api_key: str):
        """
        초기화 함수
        
        Args:
            openai_api_key (str): OpenAI API 키
        """
        self.client = OpenAI(api_key=openai_api_key)
        
        # 각 패턴을 개별적으로 컴파일
        self.COMPILED_PATTERNS = [re.compile(pattern) for pattern in self.ATTACK_PATTERNS]
    
    def filter_attack_logs(self, log_content: str) -> List[str]:
        """
        로그 내용에서 공격 패턴이 포함된 로그만 필터링
        
        Args:
            log_content (str): 웹 로그 내용
            
        Returns:
            List[str]: 공격 패턴이 탐지된 로그 리스트
        """
        attack_logs = []
        
        try:
            # 로그를 줄 단위로 분할
            lines = log_content.split('\n')
            
            for line in lines:
                line = line.strip()
                if not line:  # 빈 줄 건너뛰기
                    continue
                    
                # 모든 패턴을 순차적으로 검사
                for pattern in self.COMPILED_PATTERNS:
                    if pattern.search(line):
                        attack_logs.append(line)
                        break  # 하나의 패턴이라도 매칭되면 추가하고 다음 라인으로
        except Exception as e:
            print(f"로그 내용 처리 오류: {e}")
        
        return attack_logs
    
    def analyze_attack_logs(self, attack_logs: List[str], max_logs_per_batch: int = 5) -> List[Dict[str, Any]]:
        """
        필터링된 공격 로그를 GPT를 통해 분석
        
        Args:
            attack_logs (List[str]): 공격이 탐지된 로그 리스트
            max_logs_per_batch (int): 한 번에 분석할 최대 로그 수
            
        Returns:
            List[Dict[str, Any]]: 분석 결과 리스트 (JSON 형식)
        """
        results = []
        
        # 로그가 없는 경우
        if not attack_logs:
            return results
        
        # 배치로 나누어 처리
        for i in range(0, len(attack_logs), max_logs_per_batch):
            batch_logs = attack_logs[i:i+max_logs_per_batch]
            
            prompt = self._create_analysis_prompt(batch_logs)
            
            try:
                response = self.client.chat.completions.create(
                    model="gpt-4o-mini",  # 모델은 필요에 따라 변경 가능
                    messages=[
                        {"role": "system", "content": "웹 로그에서 발견된 공격 패턴을 분석하여 공격 종류, 위험도, 대응방안을 JSON 형식으로 제공해주세요."},
                        {"role": "user", "content": prompt}
                    ],
                    response_format={"type": "json_object"}
                )
                
                # JSON 응답 파싱
                analysis_result = json.loads(response.choices[0].message.content)
                
                if isinstance(analysis_result, dict) and "analyses" in analysis_result:
                    results.extend(analysis_result["analyses"])
                else:
                    results.append({"error": "응답 형식이 잘못되었습니다", "raw_response": analysis_result})
                
            except Exception as e:
                print(f"GPT API 호출 오류: {e}")
                results.append({"error": str(e), "logs": batch_logs})
        
        return results
    
    def _create_analysis_prompt(self, logs: List[str]) -> str:
        """
        GPT에 전송할 프롬프트 생성
        
        Args:
            logs (List[str]): 분석할 로그 리스트
            
        Returns:
            str: 완성된 프롬프트
        """
        prompt = """다음 웹 로그에서 발견된 보안 공격 패턴을 분석해주세요. 
각 로그에 대해 다음 정보를 포함하는 JSON 형식으로 응답해주세요:

1. payload_info: HTTP 요청 정보 요약
2. attack_type: 공격의 유형 (SQL 인젝션, XSS, 디렉토리 탐색 등)
3. risk_level: "낮음", "중간", "높음" 중 하나
4. mitigation: 이 공격을 방어하기 위한 간단한 권장 조치
5. attack_description: 공격 유형 상세 설명
6. risk_assessment: 위험도 평가 상세 설명
7. detailed_mitigation: 대응 방안 상세 설명

응답은 다음 JSON 형식을 따라주세요:
```
{
  "analyses": [
    {
      "payload_info": "HTTP 요청 정보",
      "attack_type": "XSS",
      "risk_level": "중간",
      "mitigation": "해당 페이로드 차단",
      "attack_description": "XSS란...",
      "risk_assessment": "위험도는...",
      "detailed_mitigation": "현재로서는..."
    },
    ...
  ]
}
```

분석할 로그:
"""
        
        for i, log in enumerate(logs, 1):
            prompt += f"\n{i}. {log}"
        
        return prompt
    
    def save_results(self, results: List[Dict[str, Any]], output_file_path: str) -> None:
        """
        분석 결과를 JSON 파일로 저장
        
        Args:
            results (List[Dict[str, Any]]): 분석 결과 리스트
            output_file_path (str): 저장할 파일 경로
        """
        output = {
            "total_attacks_found": len(results),
            "analyses": results
        }
        
        try:
            with open(output_file_path, 'w', encoding='utf-8') as file:
                json.dump(output, file, ensure_ascii=False, indent=2)
            print(f"분석 결과가 {output_file_path}에 저장되었습니다.")
        except Exception as e:
            print(f"결과 저장 오류: {e}")
