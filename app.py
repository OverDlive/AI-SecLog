import streamlit as st
import json
import os
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

# 세션 상태 초기화
if "page" not in st.session_state:
    st.session_state["page"] = "main"

if "analysis_result" not in st.session_state:
    st.session_state["analysis_result"] = None

def analyze_logs(log_content):
    """로그 분석 함수"""
    try:
        # 로그 문자열로부터 공격 패턴 탐색
        attack_logs = []
        for line in log_content.split('\n'):
            # 모든 패턴을 순차적으로 검사
            for pattern in analyzer.COMPILED_PATTERNS:
                if pattern.search(line):
                    attack_logs.append(line.strip())
                    break  # 하나의 패턴이라도 매칭되면 추가하고 다음 라인으로

        # 공격 패턴이 없으면 기본 응답 반환
        if not attack_logs:
            return {
                "payload_info": "공격 패턴이 발견되지 않았습니다.",
                "attack_type": "없음",
                "risk_level": "낮음",
                "mitigation": "모니터링을 계속하세요.",
                "attack_description": "로그에서 알려진 공격 패턴이 발견되지 않았습니다.",
                "risk_assessment": "현재 위험 수준은 낮습니다.",
                "detailed_mitigation": "일반적인 보안 모니터링을 계속하고 정기적인 보안 업데이트를 유지하세요."
            }

        # GPT 분석 실행
        results = analyzer.analyze_attack_logs(attack_logs)
        
        # 결과가 있으면 첫 번째 결과 반환, 없으면 기본 응답
        if results and len(results) > 0:
            return results
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

    if results:
        if isinstance(results, list):
            # 여러 결과가 있는 경우
            st.markdown("## 🔎 분석 결과")
            st.markdown(f"총 {len(results)}개의 위협이 탐지되었습니다.")
            
            # 탭 인터페이스를 사용하여 여러 결과 표시
            tab_labels = [f"위협 #{i+1}" for i in range(len(results))]
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
