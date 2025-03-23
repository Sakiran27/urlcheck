from flask import Flask, render_template, request
import joblib
import pandas as pd
from urllib.parse import urlparse

app = Flask(__name__)


model = joblib.load("url_classifier_model.pkl")


def extract_features(url):
   
    parsed_url = urlparse(url)
    
   
    url_length = len(url)
    
   
    special_chars = sum(1 for char in url if char in ["/", ":", "?", "=", "@", "&", ".", "-"])
    
  
    domain_age = 10 
    

    https = 1 if parsed_url.scheme == "https" else 0
    
  
    subdomains = parsed_url.netloc.count(".")
    

    phishing_keywords = ["login", "secure", "account", "verify", "banking"]
    keyword_count = sum(1 for keyword in phishing_keywords if keyword in url.lower())

    features = {
        "url_length": url_length,
        "special_chars": special_chars,
        "domain_age": domain_age,
        "https": https,
        "subdomains": subdomains,
        "keyword_count": keyword_count,
    }
    
    return pd.DataFrame([features])

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            features = extract_features(url)
            prediction = model.predict(features)
            result = "Legitimate" if prediction[0] == 0 else "Malicious"
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)