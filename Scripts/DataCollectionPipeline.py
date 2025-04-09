#!/usr/bin/env python
# coding: utf-8

# In[10]:


#Required Libraries
import requests
import feedparser
from pymongo import MongoClient
from datetime import datetime
import time
import schedule


# In[11]:


# ==== MongoDB Setup ====
try:
    client = MongoClient("mongodb+srv://rskissan:HZIXkw1D5XOUxaS2@osintunctruc.p5itk5s.mongodb.net/?retryWrites=true&w=majority")
    db = client["osint_db"]
    
    # Collections for each source
    newsapi_collection = db["newsapi_data"]
    reddit_collection = db["reddit_data"]
    rss_collection = db["rss_data"]
    rapidapi_collection = db["rapidapi_data"]
    
    print(" Connected to MongoDB successfully")
except Exception as e:
    print(f" Error connecting to MongoDB: {e}")


# In[12]:


keywords = [
    "cybersecurity", "infosec", "threat intelligence", "vulnerability", "exploit", "zero-day", "APT",
    "penetration testing", "network security", "firewall breach", "incident response",
    "ransomware", "phishing", "DDoS", "SQL injection", "man-in-the-middle attack",
    "social engineering", "supply chain attack", "malvertising", "brute force attack", 
    "credential stuffing", "malware", "spyware", "adware", "trojan", "worm", "rootkit", 
    "keylogger", "RAT", "ICS malware", "botnet", "backdoor", "CVE", "Indicators of Compromise", 
    "IOC", "MD5 hash", "SHA256 hash", "IP address blacklist", "malicious domains", "malicious URLs",
    "threat actor", "hacker group", "APT group", "state-sponsored attack", "hacktivist", 
    "cyber espionage", "black hat", "white hat", "grey hat", "deepfake", 
    "AI-generated malware", "zero-trust architecture", "cloud security breach", "IoT security", 
    "blockchain security", "quantum computing threat", "Metasploit", "Burp Suite", "Nmap", 
    "Wireshark", "Cobalt Strike", "Shodan", "VirusTotal", "AbuseIPDB", "ThreatCrowd"
]


# In[13]:


NEWSAPI_KEY = "a287317e0ca94d568dd9fb178361187d"

def fetch_and_store_news(keyword):
    try:
        logging.info(f"Starting NewsAPI collection for keyword: {keyword}")
        url = f"https://newsapi.org/v2/everything?q={keyword}&apiKey={NEWSAPI_KEY}&pageSize=100"
        
        response = requests.get(url)
        response.raise_for_status()
        
        articles = response.json().get("articles", [])
        new_records = 0
        
        for article in articles:
            doc = {
                "source": "newsapi",
                "timestamp": article.get("publishedAt"),
                "text": article.get("title", "") + ". " + (article.get("description", "") or ""),
                "meta": {
                    "author": article.get("author"),
                    "source_name": article.get("source", {}).get("name"),
                    "url": article.get("url"),
                    "query_used": keyword
                },
                "fetched_at": datetime.utcnow().isoformat()
            }
            
            # Check for duplicate entries using URL
            if newsapi_collection.count_documents({"meta.url": article.get("url")}) == 0:
                newsapi_collection.insert_one(doc)
                new_records += 1
        
        logging.info(f" Successfully collected {new_records} new articles for keyword: {keyword}")

    except Exception as e:
        logging.error(f" Error collecting data from NewsAPI for keyword '{keyword}': {e}")


# In[14]:


import praw
from datetime import datetime

# ==== PRAW Reddit API Authentication ====
try:
    reddit = praw.Reddit(
        client_id="6abqWObNapOZUTboI38SMA",
        client_secret="jvqQN0e285EOhw3pFWRkMsV7BN_lZA",
        user_agent="osint_tool_v1"
    )
    print(" Connected to Reddit successfully")
except Exception as e:
    print(f" Error connecting to Reddit: {e}")

# ==== Reddit Subreddits to Monitor ====
subreddits_to_monitor = ["netsec", "cybersecurity", "hacking", "blueteamsec", "malware"]

# ==== PRAW Data Collection ====
def collect_from_praw():
    try:
        for subreddit_name in subreddits_to_monitor:
            subreddit = reddit.subreddit(subreddit_name)
            for post in subreddit.new(limit=100):  # Fetch latest 100 posts per subreddit
                doc = {
                    "source": "reddit_praw",
                    "timestamp": datetime.utcfromtimestamp(post.created_utc).isoformat(),
                    "text": post.title + ". " + (post.selftext or ""),
                    "meta": {
                        "author": post.author.name if post.author else "N/A",
                        "url": post.url,
                        "subreddit": post.subreddit.display_name,
                        "score": post.score,
                        "num_comments": post.num_comments,
                        "post_id": post.id
                    },
                    "fetched_at": datetime.utcnow().isoformat()
                }

                # Check if the post already exists in the collection
                if reddit_collection.count_documents({"meta.post_id": post.id}) == 0:
                    reddit_collection.insert_one(doc)
                    print(f" New post saved from subreddit: {subreddit_name}")

    except Exception as e:
        print(f" Error collecting data from PRAW: {e}")

#collect_from_praw()


# In[15]:


rss_urls = ["https://krebsonsecurity.com/feed/", "https://threatpost.com/feed/"]

def collect_from_rss():
    try:
        for url in rss_urls:
            feed = feedparser.parse(url)
            for entry in feed.entries:
                doc = {
                    "source": "rss",
                    "timestamp": entry.published,
                    "text": entry.title + ". " + entry.summary,
                    "meta": {
                        "author": entry.get("author", "N/A"),
                        "url": entry.link
                    },
                    "fetched_at": datetime.utcnow().isoformat()
                }
                rss_collection.insert_one(doc)
        
        print(" RSS data collection successful")
        
    except Exception as e:
        print(f" Error collecting data from RSS feeds: {e}")

#collect_from_rss()


# In[16]:


# ==== RapidAPI Request Function ====
def collect_from_rapidapi(ioc_type, ioc_value):
    try:
        # Determine the correct endpoint based on IOC type
        url_map = {
            "ip": f"https://ioc-search.p.rapidapi.com/rapid/v1/ioc/search/ip",
            "domain": f"https://ioc-search.p.rapidapi.com/rapid/v1/ioc/search/domain",
            "url": f"https://ioc-search.p.rapidapi.com/rapid/v1/ioc/search/url",
            "hash": f"https://ioc-search.p.rapidapi.com/rapid/v1/ioc/search/hash"
        }

        url = url_map.get(ioc_type)
        
        if not url:
            print(f" Invalid IOC type: {ioc_type}")
            return
        
        querystring = {"query": ioc_value}

        headers = {
            "x-rapidapi-key": "0ea5fe4d7fmsh0b2b8346715525cp1263f3jsn707750ed0fb2",
            "x-rapidapi-host": "ioc-search.p.rapidapi.com"
        }

        response = requests.get(url, headers=headers, params=querystring)
        response.raise_for_status()  # Ensure request was successful
        
        data = response.json()
        
        # Check if the API returned data successfully
        if not data.get("data"):
            print(f" No data returned for {ioc_type}: {ioc_value}")
            return
        
        # Print the response to verify
        print(f" Full Response for {ioc_type} '{ioc_value}': {data}")

        # Prepare the document for MongoDB
        doc = {
            "source": "rapidapi",
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data,  # Save the entire data object
            "fetched_at": datetime.utcnow().isoformat()
        }
        
        # Insert data into MongoDB
        rapidapi_collection.insert_one(doc)
        
        print(f" Data successfully saved for {ioc_type}: {ioc_value}")
        
    except Exception as e:
        print(f" Error collecting data from RapidAPI for {ioc_type} '{ioc_value}': {e}")

# Test the function with an IP address
#collect_from_rapidapi("ip", "117.131.215.118")


# In[ ]:


import schedule
import time
import logging
from datetime import datetime
import os

# ==== Setting Up Logging Properly ====

# Clear previous handlers if they exist
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)

# Define the log file path
log_file_path = os.path.join(os.getcwd(), 'pipeline_logs.log')

# Apply logging configuration with proper flushing
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file_path, mode='a'),
        logging.StreamHandler()  # Outputs to console too
    ]
)

def log_start(function_name):
    logging.info(f"Starting function: {function_name}")
    print(f"🚀 Starting function: {function_name} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def log_end(function_name):
    logging.info(f"Finished function: {function_name}")
    print(f"✅ Finished function: {function_name} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# === List of IOC Types and Values to Collect ===
ioc_indicators = [
    ("ip", "117.131.215.118"),
    ("domain", "example.com"),
    ("url", "https://malicious-site.com"),
    ("hash", "44d88612fea8a8f36de82e1278abb02f")
]

def run_newsapi_fetch():
    try:
        log_start("NewsAPI Daily Fetch")
        for keyword in news_keywords:
            fetch_and_store_news(keyword)
        log_end("NewsAPI Daily Fetch")
    except Exception as e:
        logging.error(f" Error in run_newsapi_fetch: {e}")

# === IOC Collection - Hourly Job
def run_others():
    try:
        log_start("others Hourly Collection")

        log_start("collect_from_praw")
        collect_from_praw()
        log_end("collect_from_praw")

        log_start("collect_from_rss")
        collect_from_rss()
        log_end("collect_from_rss")

        for ioc_type, ioc_value in ioc_indicators:
            log_start(f"collect_from_rapidapi ({ioc_type}: {ioc_value})")
            collect_from_rapidapi(ioc_type, ioc_value)
            log_end(f"collect_from_rapidapi ({ioc_type}: {ioc_value})")

        log_end("others Hourly Collection")
    except Exception as e:
        logging.error(f" Error in other_collection: {e}")

# === Scheduler Rules
schedule.every().day.at("00:00").do(run_newsapi_fetch)  # Daily at midnight
schedule.every().hour.do(run_others)             # ⏱Hourly

# === Start Loop
while True:
    try:
        schedule.run_pending()
        time.sleep(60)
    except Exception as e:
        logging.error(f"Error in scheduler loop: {e}")
        print(f" Error in scheduler loop: {e}")

