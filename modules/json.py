import json
from collections import Counter

def analyze_attack_logs(logs, output_file):
    attack_patterns = {
        "SQL Injection": ["' OR 1=1 --", "UNION SELECT", "SELECT * FROM"],
        "XSS": ["<script>", "onerror=alert(1)", "javascript:"],
        "Brute Force": ["failed login", "invalid password", "401 Unauthorized"],
        "Directory Traversal": ["../etc/passwd", "../../windows/system32"],
        "RFI/LFI": ["http://malicious.com/shell.php", "../../../../../var/log"]
    }
    
    attack_counts = Counter()
    time_distribution = Counter()
    source_ips = Counter()
    target_urls = Counter()
    severity_levels = {"SQL Injection": "높음", "XSS": "중간", "Brute Force": "낮음", "Directory Traversal": "높음", "RFI/LFI": "중간"}
    
    for log in logs:
        for attack, patterns in attack_patterns.items():
            if any(pattern in log["request"] for pattern in patterns):
                attack_counts[attack] += 1
                time_distribution[log["time"][:2] + ":00-" + log["time"][:2] + ":59"] += 1
                source_ips[log["ip"]] += 1
                target_urls[log["url"]] += 1
                break
    
    total_attacks = sum(attack_counts.values())
    attack_types = [{
        "type": attack,
        "count": count,
        "percentage": round((count / total_attacks) * 100, 2),
        "severity": severity_levels[attack],
        "examples": attack_patterns[attack]
    } for attack, count in attack_counts.items()]
    
    severity_distribution = Counter({sev: 0 for sev in ["높음", "중간", "낮음"]})
    for attack in attack_types:
        severity_distribution[attack["severity"]] += attack["count"]
    
    visualization_data = {
        "time_distribution": [{"hour": k, "count": v} for k, v in time_distribution.items()],
        "top_source_ips": [{"ip": k, "count": v} for k, v in source_ips.most_common(5)],
        "top_target_urls": [{"url": k, "count": v} for k, v in target_urls.most_common(5)]
    }
    
    summary = f"공격 유형 중 가장 빈도가 높은 것은 {max(attack_counts, key=attack_counts.get)}이며, " \
              f"가장 심각한 위협은 {max(severity_distribution, key=severity_distribution.get)}입니다. " \
              f"공격자들은 주로 {max(target_urls, key=target_urls.get)}을 대상으로 하고 있으며, " \
              f"{max(time_distribution, key=time_distribution.get)}에 공격이 집중되었습니다."
    
    security_recommendations = [
        "웹 애플리케이션 방화벽(WAF) 설정 강화",
        "SQL Injection 및 XSS 방지를 위한 입력값 검증 강화",
        "비밀번호 보호 강화를 위한 로그인 제한 정책 적용"
    ]
    
    result = {
        "attack_analysis": {
            "total_attacks": total_attacks,
            "attack_types": attack_types,
            "severity_distribution": severity_distribution
        },
        "visualization_data": visualization_data,
        "summary": summary,
        "security_recommendations": security_recommendations
    }
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4, ensure_ascii=False)
    
    return f"분석 결과가 {output_file} 파일에 저장되었습니다."

# 예제 로그 데이터
logs = [
    {"time": "12:34:56", "ip": "192.168.1.1", "url": "/login.php", "request": "' OR 1=1 --"},
    {"time": "13:22:10", "ip": "10.0.0.2", "url": "/search.php", "request": "<script>alert(1)</script>"},
    {"time": "14:55:32", "ip": "172.16.0.3", "url": "/admin.php", "request": "../../etc/passwd"},
]

output_file = "attack_analysis.json"
print(analyze_attack_logs(logs, output_file))
