# 🧠 NLP Portfolio Repository

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![NLP](https://img.shields.io/badge/NLP-Transformers-green.svg)
![ML](https://img.shields.io/badge/ML-Scikit--learn-orange.svg)
![Deep Learning](https://img.shields.io/badge/Deep%20Learning-PyTorch-red.svg)

**A comprehensive showcase of Natural Language Processing expertise, featuring advanced transformer models, real-world applications, and production-ready systems.**

[![GitHub stars](https://img.shields.io/github/stars/yourusername/NLP?style=social)](https://github.com/yourusername/NLP)
[![GitHub forks](https://img.shields.io/github/forks/yourusername/NLP?style=social)](https://github.com/yourusername/NLP)

</div>

---

## 🎯 **About This Portfolio**

This repository demonstrates my journey in **Natural Language Processing**, showcasing projects that span from fundamental text processing techniques to cutting-edge transformer-based models. Each project represents practical applications of NLP in real-world scenarios including **cybersecurity threat intelligence**, **financial sentiment analysis**, and **automated content classification**.

### 🚀 **Key Technical Achievements**
- ✅ **Fine-tuned DeBERTa v3 Large** model for cybersecurity NER
- ✅ **Production-ready Streamlit dashboard** with real-time data processing
- ✅ **Multi-source data pipeline** (Reddit, NewsAPI, RSS feeds)
- ✅ **Ensemble ML models** achieving 56.3% accuracy in stock prediction
- ✅ **End-to-end NLP pipeline** from data collection to model deployment

### 🛠️ **Technologies Mastered**
- **Deep Learning**: PyTorch, Transformers, Hugging Face
- **ML Frameworks**: Scikit-learn, XGBoost, Ensemble Methods
- **NLP Libraries**: NLTK, spaCy, Gensim, TextBlob
- **Data Processing**: Pandas, NumPy, MongoDB
- **Deployment**: Streamlit, Docker, Google Cloud Platform
- **APIs**: REST APIs, Web Scraping, Real-time Data Integration

## 🚀 **Featured Projects**

<div align="center">

| Project | Technology | Domain | Status |
|---------|------------|--------|--------|
| [🔐 OSINT Tool](#-ai-powered-osint-tool) | DeBERTa v3, Streamlit | Cybersecurity | ✅ Production |
| [📈 Stock Analysis](#-stock-sentiment-analysis) | Ensemble ML, TF-IDF | Finance | ✅ Complete |
| [📰 Fake News](#-fake-news-classifier) | Traditional ML | Media | ✅ Complete |
| [📧 Spam Detection](#-spam-classifier) | Scikit-learn | Communication | ✅ Complete |

</div>

---

### 🔐 **AI-Powered OSINT Tool for Cybersecurity Threat Intelligence**

<div align="center">

![OSINT Tool](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)
![Model](https://img.shields.io/badge/Model-DeBERTa%20v3%20Large-blue.svg)
![Accuracy](https://img.shields.io/badge/Performance-High%20Precision-green.svg)

</div>

**🎯 Project Overview**: A sophisticated OSINT (Open Source Intelligence) pipeline that collects cybersecurity data from multiple sources and uses fine-tuned transformer models for threat intelligence extraction.

**📍 Location**: `AI-Powered-OSINT-Tool/`

**🔥 Key Features**:
- 🕸️ **Multi-source Data Collection**: Reddit, NewsAPI, RSS feeds
- 🧠 **Fine-tuned DeBERTa v3 Model**: Custom NER for cybersecurity entities
- 📊 **Interactive Dashboard**: Streamlit-based visualization tool
- ⚡ **Real-time Processing**: Automated data ingestion and analysis
- 🎯 **Entity Extraction**: Malware names, CVEs, threat actors, organizations

**🛠️ Tech Stack**:
- **Deep Learning**: Microsoft DeBERTa v3 Large, Hugging Face Transformers
- **Frontend**: Streamlit, Altair for visualizations
- **Backend**: MongoDB, Python APIs
- **Infrastructure**: Google Colab A100 GPU, Google Cloud Platform
- **Deployment**: Hugging Face Hub model hosting

**🚀 Quick Start**:
```bash
cd AI-Powered-OSINT-Tool/Dashboard
pip install -r requirements.txt
streamlit run Dashboard.py
```

**📈 Performance**: High-precision entity extraction with regex post-processing for cybersecurity threat intelligence.

---

### 📈 **Stock Sentiment Analysis & Movement Prediction**

<div align="center">

![Stock Analysis](https://img.shields.io/badge/Status-Complete-brightgreen.svg)
![Accuracy](https://img.shields.io/badge/Best%20Accuracy-56.3%25-blue.svg)
![Models](https://img.shields.io/badge/Models-Ensemble%20Learning-orange.svg)

</div>

**🎯 Project Overview**: Financial news sentiment analysis for stock movement prediction using ensemble machine learning techniques.

**📍 Location**: `Stock-Sentiment-Analysis/`

**🔥 Model Performance**:
- **Model 1**: Random Forest + CountVectorizer → **54.2% accuracy**
- **Model 2**: Logistic Regression + TF-IDF + Sentiment → **56.3% accuracy**
- **Model 3**: Voting Ensemble (LogReg + Random Forest + SVM) → **56.3% accuracy**

**🛠️ Tech Stack**:
- **ML Libraries**: Scikit-learn, NLTK, TextBlob
- **Feature Engineering**: TF-IDF, Sentiment Analysis, Lemmatization
- **Models**: Random Forest, Logistic Regression, SVM, Ensemble Methods
- **Data Processing**: Pandas, NumPy

**🚀 Future Enhancements**:
- VADER sentiment analysis for financial context
- Named Entity Recognition for market entities
- Topic modeling with LDA/NMF
- XGBoost/LightGBM implementation
- Transformer embeddings (FinBERT)

---

### 📰 **Fake News Classifier**

<div align="center">

![Fake News](https://img.shields.io/badge/Status-Complete-brightgreen.svg)
![Domain](https://img.shields.io/badge/Domain-Media%20Analysis-purple.svg)

</div>

**🎯 Project Overview**: Machine learning system for detecting fake news using various classification techniques and feature engineering approaches.

**📍 Location**: `Fake-News-Classifier/`

**🔥 Features**:
- Multiple model implementations and comparison
- Advanced text preprocessing and feature engineering
- Performance evaluation across different approaches
- Scalable classification pipeline

---

### 📧 **Spam Classifier**

<div align="center">

![Spam Detection](https://img.shields.io/badge/Status-Complete-brightgreen.svg)
![Domain](https://img.shields.io/badge/Domain-Communication-red.svg)

</div>

**🎯 Project Overview**: SMS spam detection system using traditional machine learning techniques with focus on text preprocessing and feature extraction.

**📍 Location**: `Spam-Classifier/`

**🔥 Features**:
- SMS text preprocessing pipeline
- Multiple classification algorithms
- Comprehensive performance evaluation metrics
- Real-world SMS dataset processing

---

## 📚 **Learning & Development Journey**

<div align="center">

| Notebook | Technique | Skill Level | Purpose |
|----------|-----------|-------------|---------|
| `BagOfWords.ipynb` | Text Representation | Beginner | BoW implementation |
| `TfIdfVectorizer.ipynb` | Feature Engineering | Intermediate | TF-IDF techniques |
| `Word2VecPractice.ipynb` | Word Embeddings | Intermediate | Word2Vec embeddings |
| `Lemmatization.ipynb` | Text Preprocessing | Beginner | Text normalization |
| `Scrapping.ipynb` | Data Collection | Intermediate | Web scraping & APIs |

</div>

**🎓 Learning Progression**: This repository demonstrates a structured learning path from fundamental text processing to advanced transformer models, showcasing continuous skill development in NLP.

---

## 🛠️ **Technical Setup**

### 📋 **Prerequisites**
- Python 3.8+
- pip package manager
- Git for version control

### 🔧 **Quick Installation**

```bash
# Clone the repository
git clone https://github.com/yourusername/NLP.git
cd NLP

# Install core dependencies
pip install nltk pandas numpy scikit-learn matplotlib seaborn
pip install transformers torch
pip install streamlit altair pymongo python-dotenv

# For specific projects
cd AI-Powered-OSINT-Tool && pip install -r requirements.txt
cd ../Stock-Sentiment-Analysis && pip install -r requirements.txt
```

### 🔑 **Environment Configuration**

Create a `.env` file for API access:

```env
NEWSAPI_KEY=your_newsapi_key
REDDIT_CLIENT_ID=your_client_id
REDDIT_CLIENT_SECRET=your_secret
MONGO_URI=your_mongo_connection_string
RAPIDAPI_KEY=your_rapidapi_key
```

### 🚀 **Quick Start Commands**

```bash
# Run the main OSINT dashboard
cd AI-Powered-OSINT-Tool/Dashboard
streamlit run Dashboard.py

# Explore learning notebooks
jupyter notebook

# Test individual components
python -c "import transformers; print('Transformers ready!')"
```

---

## 📁 **Repository Structure**

```
NLP/
├── 🔐 AI-Powered-OSINT-Tool/          # Production cybersecurity system
│   ├── Dashboard/                     # Streamlit web application
│   ├── DataCollection/                # Multi-source data pipeline
│   ├── NER-Pipeline/                  # Transformer model training
│   └── README.md
├── 📈 Stock-Sentiment-Analysis/       # Financial ML models
├── 📰 Fake-News-Classifier/           # Media classification
├── 📧 Spam-Classifier/                # Communication filtering
├── 🧠 Cybersecurity_ner_model/        # Pre-trained transformer
├── 📚 fine_tuned_model_*/             # Additional model variants
├── 📓 Learning Notebooks/             # Skill development materials
│   ├── BagOfWords.ipynb              # Text representation
│   ├── TfIdfVectorizer.ipynb         # Feature engineering
│   ├── Word2VecPractice.ipynb        # Word embeddings
│   ├── Lemmatization.ipynb           # Text preprocessing
│   └── Scrapping.ipynb               # Data collection
├── 📊 cyber_news_dataset.csv         # Collected dataset
└── 📖 README.md                      # This documentation
```

---

## 🎯 **Professional Skills Demonstrated**

<div align="center">

| Skill Category | Technologies | Projects |
|----------------|---------------|----------|
| **Deep Learning** | PyTorch, Transformers, DeBERTa | OSINT Tool, NER Pipeline |
| **Machine Learning** | Scikit-learn, Ensemble Methods | Stock Analysis, Spam Detection |
| **NLP Processing** | NLTK, spaCy, TextBlob | All Projects |
| **Data Engineering** | MongoDB, APIs, Web Scraping | Data Collection Pipeline |
| **Web Development** | Streamlit, Altair | Interactive Dashboard |
| **Cloud Computing** | Google Colab, GCP | Model Training & Deployment |

</div>

---

## 🏆 **Key Achievements**

- ✅ **Production-Ready System**: Deployed OSINT tool with real-time processing
- ✅ **Advanced Model Training**: Fine-tuned DeBERTa v3 on custom cybersecurity dataset
- ✅ **Full-Stack Development**: End-to-end pipeline from data collection to visualization
- ✅ **Performance Optimization**: Achieved high accuracy across multiple domains
- ✅ **Scalable Architecture**: Modular design supporting multiple data sources

---

## 🤝 **Collaboration & Contact**

<div align="center">

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=for-the-badge&logo=linkedin)](https://linkedin.com/in/yourprofile)
[![Email](https://img.shields.io/badge/Email-Contact-red?style=for-the-badge&logo=gmail)](mailto:your.email@example.com)
[![Portfolio](https://img.shields.io/badge/Portfolio-Visit-green?style=for-the-badge&logo=github)](https://github.com/yourusername)

</div>

**💼 Open to Opportunities**: I'm actively seeking roles in **Machine Learning Engineering**, **NLP Research**, and **Data Science** positions where I can apply these skills to solve real-world problems.

**🤝 Contributing**: Contributions, suggestions, and collaboration opportunities are welcome! Feel free to:
- Fork the repository
- Submit issues and feature requests
- Create pull requests for improvements
- Connect for professional networking

---

## 📄 **License & Usage**

This repository is licensed under the **MIT License** - see individual project directories for specific licensing information.

**⚠️ Important Note**: This repository is designed for **educational and research purposes**. When using external data sources, please ensure compliance with API terms of service and data usage policies.

---

<div align="center">

**🚀 Ready to explore the future of Natural Language Processing?**

[![GitHub](https://img.shields.io/badge/GitHub-View%20Code-black?style=for-the-badge&logo=github)](https://github.com/yourusername/NLP)
[![Demo](https://img.shields.io/badge/Live%20Demo-Try%20Now-green?style=for-the-badge&logo=streamlit)](https://your-demo-link.com)

</div>
