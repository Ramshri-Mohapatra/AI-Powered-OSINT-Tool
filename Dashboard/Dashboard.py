import os
os.environ["TRANSFORMERS_NO_TF"] = "1"
import streamlit as st
import altair as alt
import json
import random
import re
import pandas as pd
from transformers import AutoTokenizer, AutoModelForTokenClassification, pipeline
from collections import defaultdict
import pymongo
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import textwrap
import base64
import os


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


BG_IMAGE_PATH = os.path.join(BASE_DIR, "illustration-rain-futuristic-city.jpg")
# MongoDB connection
client = pymongo.MongoClient("mongodb+srv://rskissan:HZIXkw1D5XOUxaS2@osintunctruc.p5itk5s.mongodb.net/?retryWrites=true&w=majority")
db = client["osint_db"]
feeds = {
    "Reddit": db["reddit_data"],
    "News": db["newsapi_data"],
}

# Sidebar navigation
page = st.sidebar.radio("Go to:", ["📝 Dashboard", "🌐 Live Insights"])

def set_background_with_overlay(image_path):
    with open(image_path, "rb") as img_file:
        encoded_string = base64.b64encode(img_file.read()).decode()

    custom_css = f"""
    <style>
    /* Main background */
    .stApp {{
        background: transparent;
        color: #ffffff;
    }}

    /* Blurred background image with dark overlay */
    .stApp::before {{
        content: "";
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: -1;
        background-image: url("data:image/jpeg;base64,{encoded_string}");
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
        filter: blur(6px) brightness(0.6); /* Blur + darken for contrast */
    }}

    /* Translucent sidebar */
    section[data-testid="stSidebar"] {{
        background-color: rgba(0, 0, 0, 0.5);
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        color: white;
        border-right: 1px solid rgba(255, 255, 255, 0.1);
    }}

    /* Translucent UI elements */
    .stTextArea, .stTextInput, .stFileUploader, .stButton button {{
        background-color: rgba(0, 0, 0, 0.5) !important;
        border: 1px solid rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(8px);
        -webkit-backdrop-filter: blur(8px);
        color: white !important;
    }}

    .stTextArea textarea, .stTextInput input {{
        color: white !important;
    }}

    .stButton button {{
        color: white !important;
        font-weight: bold;
        border-radius: 6px;
    }}
    </style>
    """
    st.markdown(custom_css, unsafe_allow_html=True)




set_background_with_overlay(BG_IMAGE_PATH)

cfg = {
    "regex_patterns": {
        "dashes": "[–—−‑]",
        "obfuscated_dot": r"\[\.\]",
        "multi_space": r"\s{2,}",
        "cve": r"\bCVE-\d{4}-\d{4,5}\b",
        "url": r"\bhttps?://[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]+\b",
        "email": r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",
        "hash": r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b",
        "ip_port": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d):(?!0)(?:[1-9]\d{0,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])\b"
    },
    "alias_map": {
        "Heartbleed":      "CVE-2014-0160",
        "Shellshock":      "CVE-2014-6271",
        "EternalBlue":     "CVE-2017-0144",
        "BlueKeep":        "CVE-2019-0708",
        "Meltdown":        "CVE-2017-5754",
        "Spectre":         "CVE-2017-5753",
        "KRACK":           "CVE-2017-13077",
        "DROWN":           "CVE-2016-0800",
        "FREAK":           "CVE-2015-0204",
        "POODLE":          "CVE-2014-3566",
        "Log4Shell":       "CVE-2021-44228",
        "LogJam":          "CVE-2021-44228",
        "Follina":         "CVE-2022-30190",
        "PrintNightmare":  "CVE-2021-34527",
        "ProxyLogon":      "CVE-2021-26855",
        "ProxyShell":      "CVE-2021-34473",
        "ZeroLogon":       "CVE-2020-1472",
        "Dirty COW":       "CVE-2016-5195",
        "Dirty Pipe":      "CVE-2022-0847"
    }
}

# Now compile all your regexes directly:
DASH_RE           = re.compile(cfg["regex_patterns"]["dashes"])
OBFUSCATED_DOT_RE = re.compile(cfg["regex_patterns"]["obfuscated_dot"])
MULTI_SPACE_RE    = re.compile(cfg["regex_patterns"]["multi_space"])
CVE_RE            = re.compile(cfg["regex_patterns"]["cve"])
URL_RE            = re.compile(cfg["regex_patterns"]["url"], flags=re.IGNORECASE)
EMAIL_RE          = re.compile(cfg["regex_patterns"]["email"])
HASH_RE           = re.compile(cfg["regex_patterns"]["hash"])
IP_PORT_RE        = re.compile(cfg["regex_patterns"]["ip_port"])



# Alias map (some cves can have nick name)
ALIAS_MAP = cfg["alias_map"]

# Entity colors
ENTITY_COLORS = {
    "Malware": "#ff6b6b",
    "Vulnerability": "#1e90ff",
    "Indicator": "#2ed573",
    "Organization": "#ffa502",
    "System": "#a29bfe"
}

# Helper functions
def apply_aliases(text: str) -> str:
    for nick, cve in ALIAS_MAP.items():
        pattern = re.compile(rf"(?<![A-Za-z0-9]){re.escape(nick)}(?![A-Za-z0-9])", re.IGNORECASE)
        text = pattern.sub(cve, text)
    return text

def normalize_cve_format(text: str) -> str:
    text = DASH_RE.sub("-", text)
    text = re.sub(
        r"CVE[\s:_\-]+(\d{4})[\s:._\-]*(\d{4,5})",
        r"CVE-\1-\2",
        text,
        flags=re.IGNORECASE
    )
    text = re.sub(
        r"(?<!CVE-)(?<!CVE)(?<![A-Za-z0-9])(\d{4})\.(\d{4,5})(?!\d)",
        r"CVE-\1-\2",
        text,
        flags=re.IGNORECASE
    )
    text = re.sub(
        r"CVE[.\-_:]+(CVE-\d{4}-\d{4,5})",
        r"\1",
        text,
        flags=re.IGNORECASE
    )
    text = re.sub(
        r'[\s$$  $$$$  $$\{\}\uFF08\uFF09\uFF3B\uFF3D\uFF5B\uFF5D"\']*'
        r'(CVE[‑—−–-]\d{4}[‑—−–-]\d{4,5})'
        r'[\s$$  $$$$  $$\{\}\uFF08\uFF09\uFF3B\uFF3D\uFF5B\uFF5D"\']*',
        r' \1 ',
        text,
        flags=re.IGNORECASE
    )
    text = re.sub(r'\s{2,}', ' ', text).strip()
    text = re.sub(
        r'([A-Za-z0-9])(CVE[‑—−–-]\d{4}[‑—−–-]\d{4,5})',
        r'\1 \2',
        text,
        flags=re.IGNORECASE
    )
    return text

def normalize_obfuscated_urls(text: str) -> str:
    text = re.sub(r'\bhxxp(s?)://', r'http\1://', text, flags=re.IGNORECASE)
    text = OBFUSCATED_DOT_RE.sub(".", text)
    return re.sub(r'\.{2,}', '.', text)

def extract_url_indicators(text: str, min_score=0.6, max_score=0.9):
    hits = []
    for m in URL_RE.finditer(text):
        score = round(random.uniform(min_score, max_score), 4)
        hits.append({
            "entity_group": "Indicator",
            "word": m.group(0),
            "start": m.start(),
            "end": m.end(),
            "score": score
        })
    return hits

def extract_email_indicators(text: str, min_score=0.6, max_score=0.9):
    hits = []
    for m in EMAIL_RE.finditer(text):
        score = round(random.uniform(min_score, max_score), 4)
        hits.append({
            "entity_group": "Indicator",
            "word": m.group(0),
            "start": m.start(),
            "end": m.end(),
            "score": score
        })
    return hits

def extract_hash_indicators(text: str, min_score=0.6, max_score=0.9):
    hits = []
    for m in HASH_RE.finditer(text):
        score = round(random.uniform(min_score, max_score), 4)
        hits.append({
            "entity_group": "Indicator",
            "word": m.group(0),
            "start": m.start(),
            "end": m.end(),
            "score": score
        })
    return hits

def extract_ipport_indicators(text: str, min_score=0.6, max_score=0.9):
    hits = []
    for m in IP_PORT_RE.finditer(text):
        score = round(random.uniform(min_score, max_score), 4)
        hits.append({
            "entity_group": "Indicator",
            "word": m.group(0),
            "start": m.start(),
            "end": m.end(),
            "score": score
        })
    return hits

def fix_spacing(results: list, original_text: str) -> list:
    for ent in results:
        ent["word"] = original_text[ent["start"]:ent["end"]]
    return results

def merge_adjacent_entities(results):
    merged = []
    for ent in sorted(results, key=lambda e: e["start"]):
        if merged and ent["entity_group"] == merged[-1]["entity_group"] \
           and ent["start"] <= merged[-1]["end"] + 1:
            prev = merged[-1]
            prev["end"] = ent["end"]
            prev["word"] = prev["word"] + ent["word"][ent["start"]-prev["start"]:]
            prev["score"] = max(prev["score"], ent["score"])
        else:
            merged.append(ent.copy())
    return merged

def get_highlighted_text(text: str, entities: list) -> str:
    from collections import defaultdict

    offset_map = defaultdict(list)
    for ent in entities:
        offset_map[ent["start"]].append(("start", ent))
        offset_map[ent["end"]].append(("end", ent))

    html_out = []
    open_spans = []

    for i, ch in enumerate(text):
        if i in offset_map:
            # Close existing spans first
            for action, ent in sorted(offset_map[i], key=lambda x: x[0] == "end"):
                if action == "end":
                    html_out.append("</span>")
                    if open_spans:
                        open_spans.pop()

            # Then open new ones
            for action, ent in sorted(offset_map[i], key=lambda x: x[0] != "start"):
                if action == "start":
                    color = ENTITY_COLORS.get(ent["entity_group"], "#e0e0e0")
                    html_out.append(
                            f"<span style='"
                            f"background-color:{color}; "
                            f"padding:1px 3px; "
                            f"border-radius:3px; "
                            f"font-weight:600; "
                            f"display:inline; "
                            f"line-height:1.2; "
                            f"word-break:break-word;' "
                            f"title='{ent['entity_group']}'>"
                        )
                    open_spans.append(ent["entity_group"])

        # Escape HTML characters
        if ch == "<":
            html_out.append("&lt;")
        elif ch == ">":
            html_out.append("&gt;")
        elif ch == "&":
            html_out.append("&amp;")
        else:
            html_out.append(ch)

    # Close any remaining open spans
    while open_spans:
        html_out.append("</span>")
        open_spans.pop()

    return "".join(html_out)

# Load NER pipeline
@st.cache_resource
def load_ner():
    # Pull your token from Streamlit secrets
    hf_token = st.secrets["HF_TOKEN"]

    # Load your fine‑tuned model from the Hub, authenticating with that token
    tokenizer = AutoTokenizer.from_pretrained(
        "Rkdon11/Cybersecurity_ner_model",
        use_auth_token=hf_token
    )
    model = AutoModelForTokenClassification.from_pretrained(
        "Rkdon11/Cybersecurity_ner_model",
        use_auth_token=hf_token
    )
    return pipeline("ner", model=model, tokenizer=tokenizer, aggregation_strategy="first")

# Then elsewhere in your code:
ner_pipeline = load_ner()

# Process article function for parallel processing
def process_article(feed_name, text, ner_pipeline):
    cleaned = normalize_cve_format(normalize_obfuscated_urls(apply_aliases(text)))[:5000]
    ents = ner_pipeline(cleaned)
    ents = fix_spacing(ents, cleaned)

    for extractor in (
        extract_url_indicators,
        extract_email_indicators,
        extract_hash_indicators,
        extract_ipport_indicators
    ):
        for hit in extractor(cleaned):
            if not any(
                r["start"] == hit["start"] and r["end"] == hit["end"]
                for r in ents if r["entity_group"] == "Indicator"
            ):
                ents.append(hit)

    df = (
        pd.DataFrame(ents)
        .reindex(columns=["entity_group", "word", "score", "start", "end"])
        .dropna(subset=["entity_group", "word"])
        .sort_values("score", ascending=False)
        .drop_duplicates(subset=["entity_group", "word"], keep="first")
        .reset_index(drop=True)
    )
    df["feed"] = feed_name
    return df, (feed_name, cleaned, df.to_dict("records"))

# Functios For rendering two different pages
def render_dashboard():

    st.title("🕵️ AI-Powered-OSINT-Tool")
    st.markdown("Enter threat intel text or upload a .txt to extract malware, CVEs, URLs, etc.")

    with st.sidebar:
        st.header("🔎 Filters")
        min_score = st.slider(
            "Minimum confidence score",
            min_value=0.0,
            max_value=1.0,
            value=0.7,
            step=0.01
        )
        st.markdown("**Entity types to include:**")
        selected_groups = []
        for entity, color in ENTITY_COLORS.items():
            swatch, checkbox = st.columns([0.1, 0.9])
            swatch.markdown(
                f"<div style='width:12px; height:12px; background:{color}; "
                "border-radius:2px; margin-top:13.5px;'></div>",
                unsafe_allow_html=True
            )
            if checkbox.checkbox(entity, value=True):
                selected_groups.append(entity)
        st.markdown("---")
        st.header("📘 About the Model")
        st.markdown("""
        - Fine‑tuned: microsoft/deberta-v3-large  
        - Data: Reddit, NewsAPI, Twitter  
        - Entities: Org, Malware, Vulnerability, Indicator, System
        """)

    raw = st.text_area("Paste your threat intel text here:", height=150)
    uploaded = st.file_uploader("…or upload a .txt file", type="txt")
    if uploaded:
        raw = uploaded.read().decode("utf-8")

    if st.button("Extract Entities"):
        if not raw.strip():
            st.warning("Please enter some text!")
        else:
            with st.spinner("Processing…"):
                aliased = apply_aliases(raw)
                deobf = normalize_obfuscated_urls(aliased)
                cleaned = normalize_cve_format(deobf)

                st.markdown("### 🧼 Preprocessed Input Text")
                st.code(cleaned, language="text")

                ents = ner_pipeline(cleaned)
                ents = fix_spacing(ents, cleaned)

                if "Indicator" in selected_groups:
                    for h in extract_url_indicators(cleaned, 0.7, 0.8):
                        if h["score"] >= min_score and not any(
                            r["start"] == h["start"] and r["end"] == h["end"]
                            for r in ents if r["entity_group"] == "Indicator"
                        ):
                            ents.append(h)
                    for h in extract_email_indicators(cleaned, 0.8, 0.9):
                        if h["score"] >= min_score and not any(
                            r["start"] == h["start"] and r["end"] == h["end"]
                            for r in ents if r["entity_group"] == "Indicator"
                        ):
                            ents.append(h)
                    for h in extract_hash_indicators(cleaned, 0.8, 0.9):
                        if h["score"] >= min_score and not any(
                            r["start"] == h["start"] and r["end"] == h["end"]
                            for r in ents if r["entity_group"] == "Indicator"
                        ):
                            ents.append(h)
                    for h in extract_ipport_indicators(cleaned, 0.7, 0.8):
                        if h["score"] >= min_score and not any(
                            r["start"] == h["start"] and r["end"] == h["end"]
                            for r in ents if r["entity_group"] == "Indicator"
                        ):
                            ents.append(h)

                ents = [
                    e for e in ents
                    if e["entity_group"] in selected_groups and e["score"] >= min_score
                ]

                df = (
                    pd.DataFrame(ents)[["entity_group", "word", "score", "start", "end"]]
                    .sort_values("score", ascending=False)
                    .drop_duplicates(subset=["entity_group", "word"], keep="first")
                    .reset_index(drop=True)
                )

                filtered_df = df

                count_df = (
                    filtered_df["entity_group"]
                    .value_counts()
                    .rename_axis("entity_group")
                    .reset_index(name="count")
                )
                color_scale = alt.Scale(
                    domain=list(ENTITY_COLORS.keys()),
                    range=list(ENTITY_COLORS.values())
                )
                chart = (
                    alt.Chart(count_df)
                    .mark_bar(size=50)
                    .encode(
                        x=alt.X("entity_group:N", title="Entity Type"),
                        y=alt.Y("count:Q", title="Count"),
                        color=alt.Color(
                            "entity_group:N",
                            scale=color_scale,
                            legend=None
                        )
                    )
                    .properties(width=600, height=300, title="Entity Graph")
                )

                records = filtered_df.to_dict("records")
                html_container = f"""
                <div style="
                    white-space: normal;
                    word-wrap: break-word;
                    overflow-wrap: break-word;
                    padding: 1em;
                    background: rgba(30,30,30,0.85);
                    border-radius: 8px;
                    backdrop-filter: blur(4px);
                    -webkit-backdrop-filter: blur(4px);
                    font-size: 1rem;
                    line-height:1.4;
                    color: white;
                ">
                {get_highlighted_text(cleaned, records)}
                </div>
                """
                st.markdown("### ✨ Highlighted Entities in Text")
                st.markdown(html_container, unsafe_allow_html=True)

                st.markdown("### 🧾 Extracted Entities")
                st.dataframe(filtered_df[["entity_group", "word", "score"]])
                st.altair_chart(chart, use_container_width=True)

                csv = filtered_df[["entity_group", "word", "score"]].to_csv(index=False).encode("utf-8")
                st.download_button("📥 Download CSV", csv, "entities.csv", "text/csv")

def render_live_insights():
    st.title("🌐 Live Insights")
    st.markdown("Fetch the most recent articles from each feed and run NER + regex fallbacks.")

    source = st.sidebar.selectbox("Feed type", ["All"] + list(feeds.keys()))
    max_articles = st.sidebar.slider("How many per feed?", 1, 50, 5)
    
    if st.button("Clear Cache"):
        st.cache_data.clear()
        st.success("Cache cleared! Please refresh the page.")

    @st.cache_data(show_spinner=True, ttl=600)
    def load_docs(src, limit):
        docs = []
        for name, col in feeds.items():
            if src != "All" and name != src:
                continue
            cursor = (
                col.find({"text": {"$exists": True}}, {"text": 1, "timestamp": 1})
                   .sort("timestamp", pymongo.DESCENDING)
                   .limit(limit)
            )
            for d in cursor:
                docs.append((name, d["text"]))
        return docs
    try:
        with st.spinner("📡 Fetching and processing articles…"):
            docs = load_docs(source, max_articles)
            if not docs:
                st.info("No articles found.")
                return
            #Display raw articles in a dropdown
            with st.expander("Raw Articles", expanded=False):
                for feed_name, text in docs:
                    st.markdown(f"**Feed: {feed_name}**")
                    st.code(text[:500], language="text")

            all_entities = []
            previews = []
            with ThreadPoolExecutor(max_workers=4) as executor:
                results = executor.map(lambda x: process_article(x[0], x[1], ner_pipeline), docs)
                for df, preview in results:
                    all_entities.append(df)
                    previews.append(preview)

            all_entities = pd.concat(all_entities, ignore_index=True)

            # Display all extracted entities in a dropdown
            with st.expander("All Extracted Entities", expanded=False):
                st.dataframe(all_entities)

            # Show counts of entities by type in a dropdown
            with st.expander("Entity Counts by Type", expanded=False):
                entity_counts = all_entities["entity_group"].value_counts().reset_index()
                entity_counts.columns = ["Entity Type", "Count"]
                st.dataframe(entity_counts)

            # Initialize session state for chart_group
            if "chart_group" not in st.session_state:
                st.session_state.chart_group = None

            
            if all_entities.empty:
                st.warning("No entities found to display in the chart.")
                return

            available_entities = all_entities["entity_group"].unique()
            default_chart_group = "Indicator" if "Indicator" in available_entities else available_entities[0] if len(available_entities) > 0 else None

            if default_chart_group:
                chart_group = st.sidebar.selectbox(
                    "Chart entity type",
                    available_entities,
                    index=list(available_entities).index(default_chart_group),
                    key="chart_group_select"
                )
                st.session_state.chart_group = chart_group
            else:
                st.warning("No entity types available to chart.")
                return

            chart_group = st.session_state.chart_group

            # Prepare the  DataFrame for Chhart
            all_feeds = list(feeds.keys()) if source == "All" else [source]
            chart_df = (
                all_entities[all_entities["entity_group"] == chart_group]
                .groupby("feed")["word"]
                .nunique()
                .reset_index(name="unique_count")
            )

            # Ensure all feeds are represented, even with zero counts
            chart_df = pd.DataFrame({"feed": all_feeds}).merge(
                chart_df, on="feed", how="left"
            ).fillna({"unique_count": 0})

            
            with st.expander("Chart Data", expanded=False):
                st.dataframe(chart_df)

            # Define color scale for feeds
            feed_color_scale = alt.Scale(
                domain=all_feeds,
                range=["#ff6b6b", "#1e90ff", "#2ed573"]  
            )

            chart = (
                alt.Chart(chart_df)
                .mark_bar()
                .encode(
                    x=alt.X("feed:N", title="Feed"),
                    y=alt.Y("unique_count:Q", title=f"Unique “{chart_group}” Count"),
                    color=alt.Color("feed:N", scale=feed_color_scale, legend=None),
                )
                .properties(width=600, height=300, title=f"Unique {chart_group} by Feed")
            )
            st.altair_chart(chart, use_container_width=True)

            st.sidebar.markdown("---")
            st.sidebar.markdown("#### Entity Legend")
            for entity, color in ENTITY_COLORS.items():
                st.sidebar.markdown(
                    f"""
                    <div style="display: flex; align-items: center; margin-bottom: 0.5em;">
                        <div style="width: 18px; height: 18px; border-radius: 4px; background: {color}; margin-right: 0.6em; border: 1.5px solid #fff;"></div>
                        <span style="font-size: 1rem; color: #fff;">{entity}</span>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            st.markdown("---")
            st.markdown("### Latest articles preview with highlights")
            for feed_name, cleaned, recs in previews:
                st.subheader(feed_name)
                highlighted = get_highlighted_text(cleaned, recs)
                st.markdown(
                    f"<div style='padding:0.5em; background:#1e1e1e;'>{highlighted}</div>",
                    unsafe_allow_html=True
                )
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")


# Main page logic
if page == "📝 Dashboard":
    render_dashboard()
elif page == "🌐 Live Insights":
    render_live_insights()