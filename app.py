import streamlit as st
import json
from modules.analyzer import analyze_logs  

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
        uploaded_file = st.file_uploader("📂 JSON 형식 로그 파일을 업로드하세요", type=["json", ".csv"])
    elif input_method == "직접 입력":
        user_input = st.text_area("🔍 보안 로그 입력", height=200)

    # 분석 버튼 
    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        if st.button("🚀 분석하기"):
            if uploaded_file:
                try:
                    user_input = json.dumps(json.load(uploaded_file), indent=2)
                except json.JSONDecodeError:
                    st.error("🚨 JSON 파일을 읽을 수 없습니다.")
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

    result = st.session_state.get("analysis_result", None)

    if result:
        # 분석 결과 요약
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
