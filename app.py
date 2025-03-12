import streamlit as st
import json
import os
import re
from modules.analyzer import WebAttackAnalyzer

# OpenAI API 키 환경 변수에서 가져오기 (실제 사용 시 환경 변수 설정 필요)
openai_api_key = os.environ.get("OPENAI_API_KEY", "")

# 분석기 인스턴스 생성
analyzer = WebAttackAnalyzer(openai_api_key)

# Streamlit 페이지 설정
st.set_page_config(page_title="AI 기반 보안 로그 분석기", layout="wide")

# 다크 모드 및 UI 스타일
st.markdown("""
    <style>
        /* 다크 모드 스타일 */
        body, .stApp { background-color: #121212; color: white; }
        .stTextArea textarea, .stTextInput input, .stFileUploader { background-color: #1E1E1E; color: white; border-radius: 8px; }
        .stButton>button { background-color: #BB86FC; color: white; border-radius: 10px; width: 100%; text-align: center; }
        .stRadio label { color: white; }

        /* 이미지 중앙 정렬 */
        .stImage img { display: block; margin: auto; }

        /* 버튼 가운데 정렬 */
        .stButton { display: flex; justify-content: center; }
    </style>
""", unsafe_allow_html=True)

# 위협 수준 색상 매핑
risk_color_map = {
    "낮음": "🟢 낮음 (Low)",
    "중간": "🟡 중간 (Medium)",
    "높음": "🔴 높음 (High)"
}

# 공격 유형 라벨 - 정규식 순서와 일치
ATTACK_TYPES = [
    "SQL 인젝션",
    "XSS(크로스 사이트 스크립팅)",
    "디렉토리 탐색",
    "명령어 인젝션",
    "악성 파일 업로드 시도",
    "LFI/RFI(로컬/원격 파일 인클루전)",
    "기본 웹 공격(비정상적 요청)",
    "cmd.exe 실행 시도",
    "경로 우회 시도",
    "시스템 디렉토리 접근 시도",
    "웹 취약점 스캐닝(root.exe)",
    "버퍼 오버플로우 공격",
    "OpenWebMail 취약점 탐색",
    "허용되지 않은 HTTP 메서드",
    "프록시 하이재킹 시도",
    "FrontPage/SharePoint 취약점 탐색"
]

# 세션 상태 초기화
if "page" not in st.session_state:
    st.session_state["page"] = "main"

if "analysis_result" not in st.session_state:
    st.session_state["analysis_result"] = None
    
if "all_detected_attacks" not in st.session_state:
    st.session_state["all_detected_attacks"] = {}

def analyze_logs(log_content):
    """로그 분석 함수"""
    try:
        # 로그 문자열로부터 공격 패턴 탐색
        attack_logs_by_type = {}  # 공격 유형별로 로그를 저장할 딕셔너리
        detected_patterns = []  # 감지된 패턴 인덱스
        
        for line in log_content.split('\n'):
            if not line.strip():  # 빈 줄 건너뛰기
                continue
                
            # 모든 패턴을 순차적으로 검사
            for i, pattern in enumerate(analyzer.COMPILED_PATTERNS):
                if pattern.search(line):
                    # 해당 인덱스의 공격 유형 가져오기
                    attack_type = ATTACK_TYPES[i] if i < len(ATTACK_TYPES) else f"Unknown_{i}"
                    
                    # 공격 유형별로 로그 저장
                    if attack_type not in attack_logs_by_type:
                        attack_logs_by_type[attack_type] = []
                    
                    attack_logs_by_type[attack_type].append(line.strip())
                    detected_patterns.append(i)  # 감지된 패턴 인덱스 저장
                    break  # 하나의 패턴이라도 매칭되면 다음 라인으로
        
        # 모든 공격 로그 저장 (UI에서 표시용)
        st.session_state["all_detected_attacks"] = attack_logs_by_type
        
        # 공격 패턴이 없으면 기본 응답 반환
        if not attack_logs_by_type:
            return {
                "payload_info": "공격 패턴이 발견되지 않았습니다.",
                "attack_type": "없음",
                "risk_level": "낮음",
                "mitigation": "모니터링을 계속하세요.",
                "attack_description": "로그에서 알려진 공격 패턴이 발견되지 않았습니다.",
                "risk_assessment": "현재 위험 수준은 낮습니다.",
                "detailed_mitigation": "일반적인 보안 모니터링을 계속하고 정기적인 보안 업데이트를 유지하세요."
            }
        
        # 공격 유형별로 대표 샘플 하나씩만 선택
        sample_logs = []
        for attack_type, logs in attack_logs_by_type.items():
            sample_logs.append(logs[0])  # 각 유형의 첫 번째 로그만 선택
        
        # GPT 분석 실행 (선택된 샘플 로그만 전송)
        results = analyzer.analyze_attack_logs(sample_logs)
        
        # 결과가 있으면 상위 5개를 선택, 없으면 기본 응답
        if results and len(results) > 0:
            # 위험도 순으로 정렬 (높음 > 중간 > 낮음)
            risk_order = {"높음": 3, "중간": 2, "낮음": 1, "알 수 없음": 0}
            sorted_results = sorted(results, key=lambda x: risk_order.get(x.get("risk_level", "알 수 없음"), 0), reverse=True)
            
            # 상위 5개까지 선택
            top_results = sorted_results[:min(5, len(sorted_results))]
            return top_results
        else:
            return {
                "payload_info": "분석 중 오류가 발생했습니다.",
                "attack_type": "알 수 없음",
                "risk_level": "중간",
                "mitigation": "보안 전문가의 검토가 필요합니다.",
                "attack_description": "로그에서 의심스러운 패턴이 발견되었으나 정확한 분석에 실패했습니다.",
                "risk_assessment": "정확한 평가를 위해 추가 조사가 필요합니다.",
                "detailed_mitigation": "로그를 보안 전문가에게 전달하여 자세한 분석을 의뢰하세요."
            }
            
    except Exception as e:
        st.error(f"분석 중 오류 발생: {str(e)}")
        return {
            "payload_info": f"오류: {str(e)}",
            "attack_type": "오류 발생",
            "risk_level": "알 수 없음",
            "mitigation": "시스템 관리자에게 문의하세요.",
            "attack_description": "로그 분석 중 오류가 발생했습니다.",
            "risk_assessment": "오류로 인해 위험 평가를 수행할 수 없습니다.",
            "detailed_mitigation": "시스템 로그를 확인하고 애플리케이션을 재시작해 보세요."
        }

def main():
    """로그 입력 및 분석 페이지"""
    col1, col2, col3 = st.columns([1.5, 1, 1])  
    with col2:
        st.image("./image/logo.png", width=200)  # 로고 이미지 중앙 정렬

    st.markdown("<p style='text-align: center;'>보안 로그를 입력하거나 파일을 업로드하면 AI가 위협 수준을 분석하고 대응 방법을 제안합니다.</p>", unsafe_allow_html=True)

    # 입력 방식 선택
    input_method = st.radio("로그 입력 방식 선택", ("파일 업로드", "직접 입력"))

    user_input = ""
    uploaded_file = None

    if input_method == "파일 업로드":
        uploaded_file = st.file_uploader("📂 JSON 또는 로그 파일을 업로드하세요", type=["json", "csv", "log", "txt"])
    elif input_method == "직접 입력":
        user_input = st.text_area("🔍 보안 로그 입력", height=200)

    # 분석 버튼 
    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        if st.button("🚀 분석하기"):
            if uploaded_file:
                try:
                    # 파일 확장자 확인
                    file_ext = uploaded_file.name.split('.')[-1].lower()
                    
                    if file_ext == 'json':
                        # JSON 파일인 경우
                        user_input = json.dumps(json.load(uploaded_file), indent=2)
                    else:
                        # 텍스트 파일인 경우
                        user_input = uploaded_file.getvalue().decode('utf-8', errors='ignore')
                except Exception as e:
                    st.error(f"🚨 파일을 읽을 수 없습니다: {str(e)}")
                    return

            if user_input.strip():
                with st.spinner("🔍 AI가 로그를 분석 중입니다..."):
                    result = analyze_logs(user_input)

                # 분석 결과를 세션 상태에 저장
                st.session_state["analysis_result"] = result

                # 결과 페이지로 이동
                st.session_state["page"] = "result"
                st.rerun()
            else:
                st.warning("⚠️ 로그를 입력하거나 파일을 업로드하세요.")


def result_page():
    """분석 결과 페이지"""
    col1, col2, col3 = st.columns([1.5, 1, 1])  
    with col2:
        st.image("./image/logo.png", width=200)  # 로고 이미지 유지

    results = st.session_state.get("analysis_result", None)
    all_attacks = st.session_state.get("all_detected_attacks", {})
    
    # 전체 탐지된 공격 요약 출력
    total_attack_types = len(all_attacks)
    total_attacks = sum(len(logs) for logs in all_attacks.values())
    
    if total_attack_types > 0:
        st.markdown(f"## 🔍 탐지 결과 요약")
        st.markdown(f"총 {total_attack_types}개 유형의 공격 패턴에서 {total_attacks}개의 공격 시도가 발견되었습니다.")
        
        if st.checkbox("전체 탐지 결과 보기"):
            for attack_type, logs in all_attacks.items():
                with st.expander(f"{attack_type} ({len(logs)}개)"):
                    for i, log in enumerate(logs, 1):
                        st.text(f"{i}. {log}")

    # AI 분석 결과
    if results:
        st.markdown("## 🧠 AI 분석 결과")
        
        if isinstance(results, list):
            # 여러 결과가 있는 경우
            st.markdown(f"### 가장 위험한 상위 {len(results)}개 공격 패턴에 대한 분석")
            
            # 탭 인터페이스를 사용하여 여러 결과 표시
            tab_labels = [f"위협 #{i+1} ({result.get('attack_type', 'N/A')})" for i, result in enumerate(results)]
            tabs = st.tabs(tab_labels)
            
            for i, (tab, result) in enumerate(zip(tabs, results)):
                with tab:
                    st.markdown("### 🔎 분석 결과 요약")
                    st.markdown(f"**📌 페이로드 정보:** {result.get('payload_info', 'N/A')}")
                    st.markdown(f"**💀 공격 유형:** {result.get('attack_type', 'N/A')}")
                    st.markdown(f"**⚠️ 위험 등급:** {risk_color_map.get(result.get('risk_level', '알 수 없음'), '알 수 없음')}")
                    st.markdown(f"**🚨 권장 대응:** {result.get('mitigation', 'N/A')}")
                    
                    st.markdown("---")
                    st.markdown("### 📖 상세 설명")
                    st.markdown(f"**📝 공격 설명:** {result.get('attack_description', 'N/A')}")
                    st.markdown(f"**📊 위험 평가:** {result.get('risk_assessment', 'N/A')}")
                    st.markdown(f"**🔧 대응 상세 설명:** {result.get('detailed_mitigation', 'N/A')}")
        else:
            # 단일 결과인 경우 (기존 코드)
            result = results
            st.markdown("---")
            st.markdown("### 🔎 분석 결과 요약")
            
            st.markdown(f"**📌 페이로드 정보:** {result.get('payload_info', 'N/A')}")
            st.markdown(f"**💀 공격 유형:** {result.get('attack_type', 'N/A')}")
            st.markdown(f"**⚠️ 위험 등급:** {risk_color_map.get(result.get('risk_level', '알 수 없음'), '알 수 없음')}")
            st.markdown(f"**🚨 권장 대응:** {result.get('mitigation', 'N/A')}")
            
            st.markdown("---")
            st.markdown("### 📖 상세 설명")
            st.markdown(f"**📝 공격 설명:** {result.get('attack_description', 'N/A')}")
            st.markdown(f"**📊 위험 평가:** {result.get('risk_assessment', 'N/A')}")
            st.markdown(f"**🔧 대응 상세 설명:** {result.get('detailed_mitigation', 'N/A')}")

        # 돌아가기 버튼
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            if st.button("🔙 메인 페이지로 돌아가기"):
                st.session_state["page"] = "main"
                st.rerun()
    else:
        st.warning("⚠️ 분석 결과가 없습니다. 로그를 입력 후 다시 시도하세요.")
        col1, col2, col3 = st.columns([1, 1, 1])
        with col2:
            if st.button("🔙 메인 페이지로 이동"):
                st.session_state["page"] = "main"
                st.rerun()


# 페이지 전환 로직
if st.session_state["page"] == "main":
    main()
elif st.session_state["page"] == "result":
    result_page()