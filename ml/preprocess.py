import sqlite3
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
import os

def load_data():
    # conn = sqlite3.connect("../data/cves.db")
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), "../data/cves.db"))
    df = pd.read_sql_query("SELECT * FROM cves WHERE severity != 'UNKNOWN'", conn)
    conn.close()
    return df

def prepare_features(df):
    tfidf = TfidfVectorizer(max_features=500)
    X = tfidf.fit_transform(df["description"])
    y = df["severity"]
    return X, y, tfidf

if __name__ == "__main__":
    df = load_data()
    print(df.head())
    X, y, tfidf = prepare_features(df)
    print("Feature matrix shape:", X.shape)
