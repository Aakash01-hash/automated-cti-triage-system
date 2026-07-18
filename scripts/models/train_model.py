import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os
import sys

# Fix path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from feature_engineering.feature_extractor import extract_features

DATA_PATH = "D:/CTI/data/processed/final_cti_dataset.csv"
MODEL_PATH = "D:/CTI/models/cti_model.pkl"

def train():
    print("Loading dataset...")
    df = pd.read_csv(DATA_PATH)
    df = df.dropna(subset=['text', 'label'])

    print("Extracting features (this may take a minute)...")
    # Apply our feature extractor to the dataset
    X = list(df['text'].apply(extract_features))
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced")
    model.fit(X_train, y_train)

    print("\nModel Evaluation:")
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"✅ Model successfully saved to {MODEL_PATH}")

if __name__ == "__main__":
    train()