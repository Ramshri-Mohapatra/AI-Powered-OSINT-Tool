# AI-Powered OSINT Tool for Cybersecurity Threat Intelligence

**Author:** Ramshri Mohapatra  
**Degree:** BSc(Hons) Computer Science – 2025  
**Supervisor:** Dr. Mohammad Saedi  
**Final Project Submission**

---
link To One drive - https://cityuni-my.sharepoint.com/:f:/r/personal/ramshri_mohapatra_city_ac_uk/Documents/AI-Powered-OSINT-Tool?csf=1&web=1&e=hwZgqE

## Project Summary

This project provides a streamlined OSINT pipeline that collects cybersecurity data from open sources like Reddit, NewsAPI, RSS feeds, and more. It uses a fine-tuned DeBERTa v3 NER model to extract cybersecurity indicators such as malware names, vulnerabilities (CVEs), and threat actors. The results are then visualized through an interactive Streamlit dashboard.

---

## Key Files to Review

| File                          | Purpose                                                |
|-------------------------------|--------------------------------------------------------|
| Dashboard.py                 | ✅ Main tool – interactive dashboard (run with Streamlit) |
| DataCollectionPipeline.py    | Script for gathering OSINT using APIs like and from NewsAPI, Reddit, and RSS |
| Deberta_V3_Large_Model.ipynb | Jupyter Notebook for training large DeBERTa model, code was run on google collab with A100 gpus |
| FineTunedDistilBERTBaseCased.ipynb | This is one of the earlier models trained when not access to A100 GPUs |
| test_input.txt               | Sample input file to test Page 1 of the dashboard |

---

## Getting Started

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. API Keys and Environment Setup

⚠️ For the marker’s ease of testing, **API keys are hardcoded** into the provided version.  
However, for proper deployments, a `.env` file (example included in github repo) should be used:

```
NEWSAPI_KEY=your_newsapi_key
REDDIT_CLIENT_ID=your_client_id
REDDIT_CLIENT_SECRET=your_secret
MONGO_URI=your_mongo_connection_string
RAPIDAPI_KEY=your_rapidapi_key
```

---

## Model and Training Details

- The final model used in this tool is trained and shown in:
  **`Deberta_V3_Large_Model.ipynb `**
- Model: `microsoft/deberta-v3-large` fine-tuned using a custom NER dataset
- Training done using **Google Colab A100 GPU**
- Dataset stored and managed via **MongoDB**, collected from Reddit, RSS, and NewsAPI

---

## Tool Functionality

### Page 1: Dashboard
- Input: Paste or upload raw cybersecurity-related text
- Output:
  - NER performed using Hugging Face model
  - Post-processed using regex for extra precision
  - Entities tagged: **Organization, Malware, System, Indicator, Vulnerability**
  - Results shown with:
    - Highlighted text
    - Downloadable CSV
    - Entity frequency bar chart

### Page 2: Live Insights
- Pulls top recent posts (stored in MongoDB)
- Data sources:
  - NewsAPI (every 24 hours, up to 100 news articles)
  - RSS feeds (hourly)
  - Reddit (hourly)
- Script is scheduled and runs on a **Google Cloud VM**

---

## Pretrained Model

👉 [Hugging Face Model Used](https://huggingface.co/Rkdon11/Cybersecurity_ner_model)  
- Base: `microsoft/deberta-v3-large`  
- Fine-tuned on cybersecurity NER tasks  
- I have made it available on HuggingFace Hub. Please have a look through the link on the files and version section

---

## How to Run

```bash
cd to folder with Dashboard.py
pip install streamlit
streamlit run Dashboard.py
```

---

## Testing the Tool

Use `test_input.txt`(I have provided in the Dashboard directory) on Page 1 to test functionality quickly.  
The tool also supports custom input and real-time exploration on Page 2.

---

## Evaluation Highlights

- ✅ Automated and modular OSINT data collection
- ✅ Fine-tuned transformer with regex fallback
- ✅ Visual NER insights with entity filters
- ✅ Scheduled data ingestion via a cloud VM

---

## Legal & Ethical Notes

- Only public data is collected
- No PII is used or stored
- Complies with GDPR, API terms, and City University ethical review
- Tool is marked and used **only for academic research**

