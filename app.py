import streamlit as st
import json
import os
import re
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
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
        body, .stApp { background-color: #121212; color: white !important; }
        .stTextArea textarea, .stTextInput input, .stFileUploader { background-color: #1E1E1E; color: white; border-radius: 8px; }
        .stButton>button { background-color: #BB86FC; color: white; border-radius: 10px; width: 100%; text-align: center; }
        .stRadio label, .stCheckbox label, .stSelectbox label { color: white !important; }
        
        /* 모든 텍스트 요소에 하얀색 적용 */
        p, span, label, div, h1, h2, h3, h4, h5, h6, li, td, th { color: white !important; }
        .stMarkdown, .stText { color: white !important; }
        
        /* 탭 텍스트 색상 */
        .stTabs [data-baseweb="tab"] { color: white !important; }
        
        /* 확장자 헤더 색상 */
        .streamlit-expanderHeader { color: white !important; }
        
        /* 이미지 중앙 정렬 */
        .stImage img { display: block; margin: auto; }

        /* 버튼 가운데 정렬 */
        .stButton { display: flex; justify-content: center; }
        
        /* 코드 블록 스타일 완전 재정의 */
        pre {
            background-color: #2B2B2B !important;
            padding: 12px !important;
            border-radius: 5px !important;
            border-left: 5px solid #BB86FC !important;
            margin-bottom: 20px !important;
            white-space: pre-wrap !important;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace !important;
        }
        
        /* 코드 블록 내부 텍스트 색상 강제 지정 */
        code, pre code, .stCode code, pre span {
            color: #11F945 !important; /* 밝은 녹색으로 변경 */
            font-size: 14px !important;
            line-height: 1.5 !important;
        }
        
        /* 코드 블록 색상이 override 되지 않도록 최대 우선순위 지정 */
        .language-python, .language-apache, .language-bash, .language-html, .language-javascript {
            color: #11F945 !important;
        }
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
            return [{
                "payload_info": "분석 중 오류가 발생했습니다.",
                "attack_type": "알 수 없음",
                "risk_level": "중간",
                "mitigation": "보안 전문가의 검토가 필요합니다.",
                "attack_description": "로그에서 의심스러운 패턴이 발견되었으나 정확한 분석에 실패했습니다.",
                "risk_assessment": "정확한 평가를 위해 추가 조사가 필요합니다.",
                "detailed_mitigation": "로그를 보안 전문가에게 전달하여 자세한 분석을 의뢰하세요."
            }]
            
    except Exception as e:
        st.error(f"분석 중 오류 발생: {str(e)}")
        return [{
            "payload_info": f"오류: {str(e)}",
            "attack_type": "오류 발생",
            "risk_level": "알 수 없음",
            "mitigation": "시스템 관리자에게 문의하세요.",
            "attack_description": "로그 분석 중 오류가 발생했습니다.",
            "risk_assessment": "오류로 인해 위험 평가를 수행할 수 없습니다.",
            "detailed_mitigation": "시스템 로그를 확인하고 애플리케이션을 재시작해 보세요."
        }]

def main():
    """로그 입력 및 분석 페이지"""
    col1, col2, col3 = st.columns([1.5, 1, 1])  
    with col2:
        try:
            st.image("./image/logo.png", width=200)  # 로고 이미지 중앙 정렬
        except:
            st.title("AI 기반 보안 로그 분석기")  # 이미지가 없는 경우 대체 텍스트

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


def get_font_path():
    """운영체제에 맞는 한글 폰트 경로 자동 탐색"""
    try:
        if os.name == "nt":  # Windows
            font_path = "C:/Windows/Fonts/malgun.ttf"  # 맑은 고딕
            if os.path.exists(font_path):
                return font_path
        
        # macOS
        mac_font_paths = [
            "/System/Library/Fonts/AppleSDGothicNeo.ttc",
            "/Library/Fonts/AppleGothic.ttf"
        ]
        for path in mac_font_paths:
            if os.path.exists(path):
                return path
                
        # Linux
        linux_font_paths = [
            "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
            "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc"
        ]
        for path in linux_font_paths:
            if os.path.exists(path):
                return path
    except:
        pass
    
    return None  # 적절한 폰트를 찾지 못한 경우


def result_page():
    """분석 결과 페이지"""
    col1, col2, col3 = st.columns([1.5, 1, 1])  
    with col2:
        try:
            st.image("./image/logo.png", width=200)
        except:
            st.title("AI 기반 보안 로그 분석기")  # 이미지가 없는 경우 대체 텍스트

    results = st.session_state.get("analysis_result", None)

    if results and isinstance(results, list) and len(results) > 0:
        total_threats = len(results)  # 총 위협 개수 계산
        risk_counts = {"높음": 0, "중간": 0, "낮음": 0, "알 수 없음": 0}

        for result in results:
            risk_level = result.get('risk_level', '알 수 없음')
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1
            else:
                risk_counts["알 수 없음"] += 1

        # 🚨 총 위협 개수 강조 카드 (크기 조정)
        st.markdown(
            f"""
            <div style="background-color: #BB86FC; padding: 10px; border-radius: 8px; text-align: center; color: white; font-size:16px;">
                <h3>🚨 총 {total_threats}개의 위협 탐지</h3>
            </div>
            """,
            unsafe_allow_html=True
        )

        # 📊 위험 등급별 개수 그래프와 카드 높이 맞추기
        col1, col2 = st.columns([1, 1])  # 그래프 크기 축소, 카드 크기 맞춤

        with col1:
            try:
                # 🔹 한글 폰트 설정 (한글 깨짐 방지)
                font_path = get_font_path()
                
                # 그래프 스타일 설정 - 다크 모드
                plt.style.use('dark_background')
                
                # 그래프 그리기 - 높이를 정확히 설정하여 카드와 일치시킴
                fig, ax = plt.subplots(figsize=(4, 2.8))  # 높이를 약간 늘려 190px에 맞춤
                fig.patch.set_facecolor('#121212')  # 배경색 설정
                ax.set_facecolor('#1E1E1E')  # 차트 영역 배경색
                
                # 데이터 필터링 - '알 수 없음' 제외하고 그래프 작성
                plot_data = {k: v for k, v in risk_counts.items() if k != "알 수 없음"}
                
                # 색상 매핑
                colors = {'높음': 'red', '중간': 'yellow', '낮음': 'green'}
                
                # 그래프 그리기
                bars = ax.bar(plot_data.keys(), plot_data.values(), color=[colors[k] for k in plot_data.keys()])
                
                # 그리드 설정
                ax.grid(color='#333333', linestyle='--', linewidth=0.5, alpha=0.7)
                
                # 텍스트 색상 설정 - 모든 텍스트 하얀색으로
                text_color = 'white'
                
                # 한글 폰트 설정
                if font_path:
                    font_prop = fm.FontProperties(fname=font_path, size=9)
                    ax.set_title("위험 등급별 위협 개수", fontproperties=font_prop, fontsize=10, color=text_color)
                    ax.set_ylabel("위협 개수", fontproperties=font_prop, fontsize=8, color=text_color)
                    plt.xticks(fontproperties=font_prop, fontsize=8, color=text_color)
                else:
                    # 폰트가 없는 경우 영문으로 대체
                    ax.set_title("Threats by Risk Level", fontsize=10, color=text_color)
                    ax.set_ylabel("Count", fontsize=8, color=text_color)
                    plt.xticks(fontsize=8, color=text_color)
                
                plt.yticks(fontsize=8, color=text_color)
                
                # 테두리 색상 설정
                for spine in ax.spines.values():
                    spine.set_color('#555555')
                
                # 그래프 출력
                st.pyplot(fig)
                
            except Exception as e:
                st.error(f"그래프 생성 중 오류 발생: {str(e)}")
                st.text(f"위험 등급별 개수: 높음 {risk_counts['높음']}, 중간 {risk_counts['중간']}, 낮음 {risk_counts['낮음']}")

        with col2:
            # 카드 컨테이너를 그래프 높이에 맞추기 (약 190px)
            container_style = "display: flex; flex-direction: column; justify-content: space-between; height: 190px;"
            
            # 개별 카드 스타일 (컨테이너 내에서 균등하게 분배)
            card_style = "padding: 8px; border-radius: 8px; text-align: center; font-size:18px; font-weight:bold; display: flex; align-items: center; justify-content: center; margin-bottom: 0px; flex: 1;"
            
            # 카드 컨테이너 시작
            st.markdown(
                f"""
                <div style="{container_style}">
                """, 
                unsafe_allow_html=True
            )
            
            # 높은 위험 카드
            st.markdown(
                f"""
                <div style="background-color: #FF4C4C; {card_style} color: white;">
                    🔴 높은 위험 <span style="font-size:18px; margin-left:8px;">{risk_counts["높음"]}</span>
                </div>
                """,
                unsafe_allow_html=True
            )
            
            # 중간 위험 카드
            st.markdown(
                f"""
                <div style="background-color: #FFB74D; {card_style} color: white;">
                    🟡 중간 위험 <span style="font-size:18px; margin-left:8px;">{risk_counts["중간"]}</span>
                </div>
                """,
                unsafe_allow_html=True
            )
            
            # 낮은 위험 카드
            st.markdown(
                f"""
                <div style="background-color: #66BB6A; {card_style} color: white;">
                    🟢 낮은 위험 <span style="font-size:18px; margin-left:8px;">{risk_counts["낮음"]}</span>
                </div>
                """,
                unsafe_allow_html=True
            )
            
            # 알 수 없음 카드 (필요한 경우)
            if risk_counts["알 수 없음"] > 0:
                st.markdown(
                    f"""
                    <div style="background-color: #9E9E9E; {card_style} color: white;">
                        ⚪ 알 수 없음 <span style="font-size:18px; margin-left:8px;">{risk_counts["알 수 없음"]}</span>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            
            # 카드 컨테이너 종료
            st.markdown("</div>", unsafe_allow_html=True)

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
        
        if isinstance(results, list) and len(results) > 0:
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
                    
                    # 대응 방안 섹션을 확장자(expander)로 표시하여 더 많은 공간 확보
                    with st.expander("**🔧 상세 대응 방안**", expanded=True):
                        st.markdown(f"**즉시 조치사항:** {result.get('immediate_actions', '상세 대응 방안 참조')}")
                        st.markdown(f"**기술적 대응:** {result.get('technical_mitigation', result.get('detailed_mitigation', 'N/A'))}")
                        
                        # 코드 예시가 있는 경우 표시
                        if result.get('mitigation_examples'):
                            st.markdown("**구현 예시:**")
                            
                            # 코드 블록 직접 HTML로 삽입
                            code_html = f"""
                            <pre style="background-color: #2B2B2B; color: #11F945; padding: 12px; border-radius: 5px; border-left: 5px solid #BB86FC;">
                            <code style="color: #11F945; font-family: monospace;">{result.get('mitigation_examples').replace('<', '&lt;').replace('>', '&gt;')}</code>
                            </pre>
                            """
                            st.markdown(code_html, unsafe_allow_html=True)
                        
                        # 보안 구성 예시가 있는 경우 표시
                        if result.get('security_config'):
                            st.markdown("**보안 구성 예시:**")
                            
                            # 코드 블록 직접 HTML로 삽입
                            config_html = f"""
                            <pre style="background-color: #2B2B2B; color: #11F945; padding: 12px; border-radius: 5px; border-left: 5px solid #BB86FC;">
                            <code style="color: #11F945; font-family: monospace;">{result.get('security_config').replace('<', '&lt;').replace('>', '&gt;')}</code>
                            </pre>
                            """
                            st.markdown(config_html, unsafe_allow_html=True)
                            
                        st.markdown(f"**장기적 대응:** {result.get('long_term_actions', '추가적인 보안 강화 방안을 검토하세요.')}")
        elif isinstance(results, dict):
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
        else:
            st.warning("⚠️ 결과 데이터가 예상 형식과 다릅니다.")

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