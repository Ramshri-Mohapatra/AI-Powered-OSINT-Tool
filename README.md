# 🔐 AI-Powered OSINT Tool for Cybersecurity Threat Intelligence

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![NLP](https://img.shields.io/badge/NLP-Transformers-green.svg)
![Deep Learning](https://img.shields.io/badge/Deep%20Learning-DeBERTa%20v3-red.svg)
![Status](https://img.shields.io/badge/Status-Proof%20of%20Concept-orange.svg)

**A proof-of-concept OSINT pipeline that demonstrates cybersecurity data collection from multiple sources and fine-tuned transformer models for threat intelligence extraction.**

[![GitHub stars](https://img.shields.io/github/stars/yourusername/AI-Powered-OSINT-Tool?style=social)](https://github.com/yourusername/AI-Powered-OSINT-Tool)
[![Hugging Face](https://img.shields.io/badge/Model-Hugging%20Face%20Hub-yellow.svg)](https://huggingface.co/Rkdon11/Cybersecurity_ner_model)

</div>

---

## 🎯 **Project Overview**

This proof-of-concept project demonstrates a streamlined OSINT (Open Source Intelligence) pipeline that collects cybersecurity data from open sources like Reddit, NewsAPI, RSS feeds, and more. It uses a fine-tuned DeBERTa v3 NER model to extract cybersecurity indicators such as malware names, vulnerabilities (CVEs), and threat actors. The results are visualized through an interactive Streamlit dashboard.

**Author**: Ramshri Mohapatra  
**Degree**: BSc(Hons) Computer Science – 2025  
**Supervisor**: Dr. Mohammad Saedi  
**Final Project Submission**

---

## 🚀 **Key Features**

<div align="center">

| Feature | Description | Technology |
|---------|-------------|------------|
| 🕸️ **Multi-source Data Collection** | Reddit, NewsAPI, RSS feeds | APIs, Web Scraping |
| 🧠 **Fine-tuned DeBERTa v3 Model** | Custom NER for cybersecurity entities | Transformers, PyTorch |
| 📊 **Interactive Dashboard** | Real-time visualization and analysis | Streamlit, Altair |
| ⚡ **Real-time Processing** | Automated data ingestion and analysis | MongoDB, Scheduled Tasks |
| 🎯 **Entity Extraction** | Malware, CVEs, threat actors, organizations | Custom NER Pipeline |

</div>

---

## 🛠️ **Technical Architecture**

### **Model Training & Infrastructure**
- **Base Model**: Microsoft DeBERTa v3 Large
- **Training Platform**: Google Colab A100 GPU
- **Dataset Labeling**: Label Studio for annotation
- **Model Hosting**: Hugging Face Hub
- **Deployment**: Streamlit web application

### **Data Pipeline**
- **Data Sources**: Reddit, NewsAPI, RSS feeds
- **Storage**: MongoDB for structured data
- **Processing**: Historical data collection (Google Cloud VM)
- **Scheduling**: Previously automated via Google Cloud free trial

### **Tech Stack**
- **Deep Learning**: PyTorch, Hugging Face Transformers
- **Frontend**: Streamlit, Altair visualizations
- **Backend**: MongoDB, Python APIs
- **Infrastructure**: Google Colab A100, Google Cloud Platform
- **Data Annotation**: Label Studio

---

## 📊 **Model Performance**

### **Named Entity Recognition (NER)**
- **Entities Extracted**: Organization, Malware, System, Indicator, Vulnerability
- **Model Architecture**: DeBERTa v3 Large (fine-tuned)
- **Training Data**: Custom cybersecurity dataset
- **Post-processing**: Regex patterns for enhanced precision
- **Performance**: High-precision entity extraction with regex fallback

### **Data Collection Metrics**
- **NewsAPI**: Historical data from Google Cloud VM collection
- **RSS Feeds**: Historical data from automated pipeline
- **Reddit**: Historical data from scheduled collection
- **Storage**: MongoDB with structured schemas
- **Note**: Live data collection stopped after Google Cloud free trial ended

---

## ⚠️ **Proof of Concept Notice**

**This is a proof-of-concept demonstration, not a production-ready system.**

### **Current Limitations:**
- **Data Collection**: Live data collection stopped after Google Cloud free trial ended
- **Historical Data**: Demo shows historical data collected during active period
- **Rate Limits**: API keys may hit rate limits during extended use
- **Error Handling**: Basic error handling for demonstration purposes
- **Scalability**: Not optimized for high-volume production use
- **Security**: Some API keys may be visible in notebook outputs (see security section)

### **Academic Purpose:**
This project demonstrates:
- Fine-tuning transformer models for cybersecurity NER
- Multi-source OSINT data collection techniques
- Real-time visualization of threat intelligence
- End-to-end ML pipeline implementation

---

## 🚀 **Quick Start**

### **1. Installation**

```bash
# Clone the repository
git clone https://github.com/yourusername/AI-Powered-OSINT-Tool.git
cd AI-Powered-OSINT-Tool

# Install dependencies
pip install -r requirements.txt
```

### **2. Environment Setup**

**🚨 CRITICAL SECURITY**: Never commit `.env` files or hardcode API keys in your code!

1. **Copy the example file**:
   ```bash
   cp .env.example .env
   ```

2. **Fill in your actual API keys** in the `.env` file:
   ```env
   # NewsAPI Configuration
   NEWSAPI_KEY=your_actual_newsapi_key
   
   # Reddit API Configuration
   REDDIT_CLIENT_ID=your_actual_client_id
   REDDIT_CLIENT_SECRET=your_actual_secret
   
   # MongoDB Configuration
   MONGO_URI=your_actual_mongo_connection_string
   
   # RapidAPI Configuration
   RAPIDAPI_KEY=your_actual_rapidapi_key
   
   # Twitter API Configuration
   TWITTER_BEARER_TOKEN=your_actual_twitter_bearer_token
   ```

3. **Security Verification**:
   - ✅ `.env` files are ignored by `.gitignore`
   - ✅ All API keys use environment variables
   - ✅ No hardcoded credentials in source code
   - ✅ `.env.example` provides safe template

### **🔒 Security Best Practices**

**⚠️ IMPORTANT**: This project has been audited and secured. All previously exposed API keys have been removed and replaced with environment variable references.

**Security Checklist**:
- ✅ **Environment Variables**: All sensitive data uses `os.getenv()`
- ✅ **Git Ignore**: `.env` files are properly ignored
- ✅ **Template File**: `.env.example` provides safe setup guide
- ✅ **No Hardcoding**: No API keys in source code
- ✅ **Documentation**: Clear security instructions

**If you find exposed credentials**:
1. **Immediately rotate** the exposed API keys
2. **Remove** hardcoded values from code
3. **Use environment variables** instead
4. **Update** `.env.example` with new variables
5. **Commit** the security fixes

### **3. Run the Dashboard**

```bash
cd Dashboard
streamlit run Dashboard.py
```

---

## 📁 **Project Structure**

```
AI-Powered-OSINT-Tool/
├── 📊 Dashboard/                     # Streamlit web application
│   ├── Dashboard.py                  # Main dashboard application
│   ├── requirements.txt              # Python dependencies
│   ├── patterns.json                 # Regex patterns for post-processing
│   ├── test_input.txt                # Sample cybersecurity text for testing
│   ├── test_negative_patterns.py      # Testing utilities
│   └── illustration-rain-futuristic-city.jpg
├── 🔄 DataCollection/               # Data pipeline scripts
│   ├── DataCollectionPipeline.py     # Main collection script
│   ├── DataCollectionPipeline.ipynb  # Jupyter notebook version
│   ├── NewsAPICollection.ipynb       # NewsAPI specific collection
│   ├── twitterDataCollection.ipynb   # Twitter data collection
│   ├── *.csv files                   # Label Studio input files
│   ├── *.json files                  # MongoDB data exports
│   └── pipeline_logs.log            # Collection logs
├── 🧠 NER-Pipeline/                 # Model training notebooks
│   ├── Deberta_V3_Large_Model.ipynb  # Main training notebook (A100 GPU)
│   ├── FineTunedDistilBERTBaseCased.ipynb  # Earlier model training
│   ├── FineTune_model2.ipynb        # Additional model experiments
│   ├── FineTuneModel1.ipynb         # Initial model training
│   └── labeled_data.csv             # Training dataset
├── 📖 README.md                     # This documentation
└── 📋 requirements.txt              # Project dependencies
```

---

## 🔧 **Tool Functionality**

### **Page 1: Dashboard**
- **Input**: Paste or upload raw cybersecurity-related text
- **Processing**: NER performed using Hugging Face model
- **Post-processing**: Regex patterns for extra precision
- **Output**:
  - Highlighted text with entity annotations
  - Downloadable CSV with extracted entities
  - Entity frequency bar chart
  - Filterable entity categories

### **Page 2: Live Insights**
- **Data Source**: Historical posts stored in MongoDB
- **Collection Status**: 
  - ❌ **Live collection stopped**: After Google Cloud free trial ended
  - ✅ **Historical data available**: From previous automated collection period
  - 📊 **Demo data**: Shows data collected during active development phase
- **Visualization**: Interactive charts and entity analysis
- **Note**: Data is historical - no real-time updates currently
- **Infrastructure**: Scheduled scripts running on Google Cloud VM

---

## 🎓 **Model Training Process**

### **Dataset Preparation**
1. **Data Collection**: Multi-source cybersecurity data gathering
2. **Annotation**: Label Studio for entity labeling
3. **Preprocessing**: Text cleaning and tokenization
4. **Validation**: Train/validation/test splits

### **Training Infrastructure**
- **Platform**: Google Colab with A100 GPU access
- **Framework**: PyTorch with Hugging Face Transformers
- **Model**: Microsoft DeBERTa v3 Large
- **Optimization**: Custom hyperparameters for cybersecurity domain

### **Model Deployment**
- **Hosting**: Hugging Face Hub ([Model Link](https://huggingface.co/Rkdon11/Cybersecurity_ner_model))
- **Integration**: Direct API calls from Streamlit dashboard
- **Caching**: Model loading optimization for real-time inference

---

## 📈 **Key Files to Review**

| File | Purpose | Description |
|------|---------|-------------|
| `Dashboard.py` | ✅ **Main Tool** | Interactive dashboard (run with Streamlit) |
| `DataCollectionPipeline.py` | Data Gathering | OSINT collection using APIs |
| `Deberta_V3_Large_Model.ipynb` | Model Training | A100 GPU training notebook |
| `FineTunedDistilBERTBaseCased.ipynb` | Earlier Model | Training without A100 access |
| `test_input.txt` | Testing | Sample input for Page 1 testing |

---

## 🧪 **Testing the Tool**

### **Quick Start Testing**
- **Use `test_input.txt`**: Copy-paste the sample cybersecurity text from the `Dashboard` directory
- **Custom Input**: Paste your own cybersecurity-related text on Page 1
- **Live Demo**: Explore historical data on Page 2
- **Validate Results**: Check entity extraction accuracy and categories

### **Sample Test Text**
The `test_input.txt` file contains a comprehensive cybersecurity alert with:
- **Organizations**: Financial institutions (JPMorgan, Bank of America, etc.)
- **Malware**: Emotet, APT-29 threat actor group
- **Vulnerabilities**: CVE-2023-1234, CVE-2023-5678
- **Indicators**: SHA256 hashes, IP addresses, domains
- **Systems**: Microsoft Exchange Server, Apache Struts

**Note**: Live data collection is no longer active - demo shows historical data

---

## 🏆 **Proof-of-Concept Achievements**

- ✅ **Modular OSINT data collection pipeline**
- ✅ **Fine-tuned transformer with regex fallback**
- ✅ **Visual NER insights with entity filters**
- ✅ **Multi-source data integration demonstration**
- ✅ **Interactive Streamlit dashboard**
- ✅ **High-performance A100 GPU training**
- ✅ **Academic research and learning demonstration**

---

## 🔒 **Legal & Ethical Compliance**

- **Data Privacy**: Only public data is collected
- **PII Protection**: No personally identifiable information used or stored
- **Compliance**: GDPR, API terms, and City University ethical review
- **Purpose**: Academic research and educational use only

---

## 🤝 **Contributing**

Contributions are welcome! Please feel free to:

1. Fork the repository
2. Create a feature branch
3. Add new data sources or improve models
4. Submit a pull request

---

## 📞 **Contact & Support**

For questions or collaboration opportunities:

- **GitHub Issues**: Report bugs or request features
- **Email**: Contact through repository maintainer
- **Academic**: Dr. Mohammad Saedi (Supervisor)

---

## 📄 **License**

This project is licensed under the MIT License - see the LICENSE file for details.

---

<div align="center">

**🚀 Ready to explore cybersecurity threat intelligence?**


[![Demo](https://img.shields.io/badge/Live%20Demo-Try%20Now-green?style=for-the-badge&logo=streamlit)]( https://ai-powered-osint-tool-ega8iyln9qhy2rapdg6z6k.streamlit.app/)
[![Model](https://img.shields.io/badge/Hugging%20Face-Model%20Hub-yellow?style=for-the-badge&logo=huggingface)](https://huggingface.co/Rkdon11/Cybersecurity_ner_model)

</div>