# %%
# Step 1: Import libraries
import pandas as pd
import re
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score


# %%
# Step 2: Load the two datasets
df1 = pd.read_csv(r'C:\Users\kakul\OneDrive\Desktop\PBL\Phishing URLs.csv')
df2 = pd.read_csv(r'C:\Users\kakul\OneDrive\Desktop\PBL\URL dataset.csv')

# Step 3: Normalize column names
df1.columns = [col.strip().lower() for col in df1.columns]
df2.columns = [col.strip().lower() for col in df2.columns]

# Identify relevant columns
url_col_1 = df1.columns[0]
label_col_1 = df1.columns[1]
url_col_2 = df2.columns[0]
label_col_2 = df2.columns[1]


# %%
# Step 4: Clean labels and combine datasets
def clean_label(val):
    val = str(val).lower()
    return 1 if val in ['1', 'phishing', 'bad'] else 0

df1_clean = df1[[url_col_1, label_col_1]].copy()
df1_clean.columns = ['url', 'label']
df1_clean['label'] = df1_clean['label'].apply(clean_label)

df2_clean = df2[[url_col_2, label_col_2]].copy()
df2_clean.columns = ['url', 'label']
df2_clean['label'] = df2_clean['label'].apply(clean_label)

df = pd.concat([df1_clean, df2_clean], ignore_index=True).dropna().drop_duplicates()
print(f"Combined dataset shape: {df.shape}")
df.head()


# %%
import re
from urllib.parse import urlparse

# Define feature detectors
def has_spoofed_brand(url, brand="paypal"):
    try:
        return int(brand in url.lower() or brand.replace("l", "1") in url.lower())
    except:
        return 0

def has_suspicious_keywords(url):
    keywords = ['login', 'verify', 'account', 'update', 'secure']
    try:
        return int(any(k in url.lower() for k in keywords))
    except:
        return 0

def has_leetspeak(url):
    try:
        return int(any(char in url.lower() for char in ['1', '0', '3', '@']))
    except:
        return 0

def has_suspicious_tld(url):
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
    try:
        return int(any(url.lower().endswith(tld) for tld in suspicious_tlds))
    except:
        return 0

# Safe feature extraction
def extract_features(url):
    try:
        cleaned_url = str(url).replace('[.]', '.')  # handle obfuscation
        parsed = urlparse(cleaned_url)
        domain = parsed.netloc

        return {
            'url_length': len(cleaned_url),
            'num_dots': cleaned_url.count('.'),
            'num_hyphens': cleaned_url.count('-'),
            'num_at': cleaned_url.count('@'),
            'has_https': int(cleaned_url.lower().startswith('https')),
            'num_subdomains': max(0, len(domain.split('.')) - 2),
            'contains_ip': int(bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain))),  # only match full IPs
            'has_spoofed_brand': has_spoofed_brand(cleaned_url),
            'has_leetspeak': has_leetspeak(cleaned_url),
            'has_suspicious_keywords': has_suspicious_keywords(cleaned_url),
            'has_suspicious_tld': has_suspicious_tld(cleaned_url)
        }
    except Exception as e:
        print(f"Error in URL: {url} — {e}")
        return {
            'url_length': 0,
            'num_dots': 0,
            'num_hyphens': 0,
            'num_at': 0,
            'has_https': 0,
            'num_subdomains': 0,
            'contains_ip': 0,
            'has_spoofed_brand': 0,
            'has_leetspeak': 0,
            'has_suspicious_keywords': 0,
            'has_suspicious_tld': 0
        }



# %%
features = df['url'].apply(extract_features)
features_df = pd.DataFrame(features.tolist())
features_df['label'] = df['label']
features_df.head()

# %%
# Step 7: Split the dataset
X = features_df.drop('label', axis=1)
y = features_df['label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
# Step: Check for NaNs or non-numeric values
print("X_train shape:", X_train.shape)
print("y_train shape:", y_train.shape)

print("\nChecking for NaNs in X_train:", X_train.isnull().sum().sum())
print("Checking for NaNs in y_train:", y_train.isnull().sum())

print("\nX_train dtypes:\n", X_train.dtypes)
# Replace or drop NaNs
X_train = X_train.fillna(0)
y_train = y_train.fillna(0)

# Ensure all features are numeric
X_train = X_train.astype(float)



# %%
# Step 8: Train Random Forest model
model = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)
model.fit(X_train, y_train)



# %%
from sklearn.metrics import accuracy_score, classification_report

# Ensure labels are numeric and properly typed
y_test = pd.to_numeric(y_test, errors='coerce').fillna(0).astype(int)
y_pred = model.predict(X_test)
y_pred = pd.Series(y_pred).astype(int)

# Step 9: Evaluate the model
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Classification Report:\n", classification_report(y_test, y_pred))


# %%
# Step 10: Predict on a custom URL
def predict_url(url):
    feats = extract_features(url)
    df_feat = pd.DataFrame([feats])
    pred = model.predict(df_feat)[0]
    return "Phishing" if pred == 1 else "Legitimate"

predict_url("https://microsoft-support.com")
    


