import re
import json
import argparse
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
    
    # 컴파일된 정규식 패턴 목록
    COMPILED_PATTERNS = None
    
    def __init__(self, openai_api_key: str):
        """
        초기화 함수
        
        Args:
            openai_api_key (str): OpenAI API 키
        """
        self.client = OpenAI(api_key=openai_api_key)
        
        # 각 패턴을 개별적으로 컴파일
        self.COMPILED_PATTERNS = [re.compile(pattern) for pattern in self.ATTACK_PATTERNS]
    
    def filter_attack_logs(self, log_file_path: str) -> List[str]:
        """
        로그 파일에서 공격 패턴이 포함된 로그만 필터링
        
        Args:
            log_file_path (str): 웹 로그 파일 경로
            
        Returns:
            List[str]: 공격 패턴이 탐지된 로그 리스트
        """
        attack_logs = []
        
        try:
            with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as file:
                for line in file:
                    # 모든 패턴을 순차적으로 검사
                    for pattern in self.COMPILED_PATTERNS:
                        if pattern.search(line):
                            attack_logs.append(line.strip())
                            break  # 하나의 패턴이라도 매칭되면 추가하고 다음 라인으로
        except Exception as e:
            print(f"로그 파일 읽기 오류: {e}")
        
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
                    model="gpt-4-turbo",  # 모델은 필요에 따라 변경 가능
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

1. 공격 종류 (type): 공격의 유형 (SQL 인젝션, XSS, 디렉토리 탐색 등)
2. 위험도 (risk_level): "낮음", "중간", "높음" 중 하나
3. 대응방안 (mitigation): 이 공격을 방어하기 위한 권장 조치

응답은 다음 JSON 형식을 따라주세요:
```
{
  "analyses": [
    {
    attack_description = "XSS란~" # 공격 유형 설명
    risk_assessment = "위험도는 ~" # 위험도 평가
    detailed_mitigation = "현재로서는 ~" # 대응 권장 사항
    payload_info = "HTTP~"
    attack_type = "XSS"
    risk_level = "중간 (Medium)"
    mitigation = "해당 페이로드 차단"
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

def main():
    """메인 함수"""
    # 파일 경로와 API 키를 코드에 직접 설정
    log_file_path = "testlog"  # 분석할 웹 로그 파일 경로
    output_file_path = "attack_analysis.json"  # 결과를 저장할 파일 경로
    openai_api_key = ""  # OpenAI API 키
    
    analyzer = WebAttackAnalyzer(openai_api_key)
    
    print(f"로그 파일 {log_file_path}에서 공격 패턴 탐색 중...")
    attack_logs = analyzer.filter_attack_logs(log_file_path)
    
    print(f"총 {len(attack_logs)}개의 의심스러운 로그가 발견되었습니다.")
    
    if attack_logs:
        print("GPT를 사용하여 로그 분석 중...")
        results = analyzer.analyze_attack_logs(attack_logs)
        analyzer.save_results(results, output_file_path)
    else:
        print("공격 패턴이 발견되지 않았습니다.")

if __name__ == "__main__":
    main()
