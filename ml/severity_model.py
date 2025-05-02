from preprocess import load_data, prepare_features
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

def train_and_evaluate():
    df = load_data()
    X, y, tfidf = prepare_features(df)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = LogisticRegression(max_iter=1000, class_weight='balanced')
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))

    # ✅ Save model and vectorizer
    joblib.dump(model, "ml/severity_model.pkl")
    joblib.dump(tfidf, "ml/tfidf_vectorizer.pkl")
    print("Model and vectorizer saved.")

if __name__ == "__main__":
    train_and_evaluate()
