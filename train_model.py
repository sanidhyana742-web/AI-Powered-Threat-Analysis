import os
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor, RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import mean_squared_error, accuracy_score

def train_and_save_models():
    project_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(project_dir, 'dataset', 'national_critical_infrastructure_risk_dataset_10000.csv')
    models_dir = os.path.join(project_dir, 'models')
    
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset file '{dataset_path}' not found.")
        return

    print("Loading dataset...")
    df = pd.read_csv(dataset_path)

    # Feature selection
    feature_cols = [
        'sector', 'attack_type', 'severity', 'cvss_score', 
        'exploitability_score', 'known_exploited', 'threat_active', 
        'threat_confidence', 'sector_criticality', 'asset_criticality', 'exposure_score'
    ]

    X = df[feature_cols].copy()
    y_score = df['risk_score']
    y_level = df['risk_level']

    # Convert Boolean columns to integers
    X['known_exploited'] = X['known_exploited'].astype(int)
    X['threat_active'] = X['threat_active'].astype(int)

    # Encode Categorical features
    label_encoders = {}
    categorical_cols = ['sector', 'attack_type', 'severity']

    for col in categorical_cols:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col])
        label_encoders[col] = le

    # Create models output directory
    os.makedirs(models_dir, exist_ok=True)

    # 1. Train Risk Score Regressor Model
    print("Training Risk Score Regressor...")
    X_train_r, X_test_r, y_train_r, y_test_r = train_test_split(X, y_score, test_size=0.2, random_state=42)
    
    regressor = RandomForestRegressor(n_estimators=100, random_state=42)
    regressor.fit(X_train_r, y_train_r)
    
    r2_score = regressor.score(X_test_r, y_test_r)
    print(f"Risk Score Regressor R² Accuracy: {r2_score * 100:.2f}%")

    # 2. Train Risk Level Classifier Model
    print("Training Risk Level Classifier...")
    X_train_c, X_test_c, y_train_c, y_test_c = train_test_split(X, y_level, test_size=0.2, random_state=42)
    
    classifier = RandomForestClassifier(n_estimators=100, random_state=42)
    classifier.fit(X_train_c, y_train_c)
    
    clf_acc = accuracy_score(y_test_c, classifier.predict(X_test_c))
    print(f"Risk Level Classifier Accuracy: {clf_acc * 100:.2f}%")

    # Save Models and Encoders locally
    print("Saving models to 'models' directory...")
    joblib.dump(regressor, os.path.join(models_dir, 'risk_score_regressor.pkl'))
    joblib.dump(classifier, os.path.join(models_dir, 'risk_level_classifier.pkl'))
    joblib.dump(label_encoders, os.path.join(models_dir, 'label_encoders.pkl'))
    joblib.dump(feature_cols, os.path.join(models_dir, 'feature_names.pkl'))

    print("Model training complete! Saved artifacts to directory 'models/'.")

if __name__ == '__main__':
    train_and_save_models()