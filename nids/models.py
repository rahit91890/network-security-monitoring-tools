# ML Models for Network Intrusion Detection

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

class AnomalyDetector:
    """ML-based anomaly detection for network traffic"""
    
    def __init__(self, contamination=0.1):
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_trained = False
    
    def train(self, X_train):
        """Train the anomaly detection model"""
        X_scaled = self.scaler.fit_transform(X_train)
        self.model.fit(X_scaled)
        self.is_trained = True
        print(f"Anomaly detector trained on {len(X_train)} samples")
    
    def predict(self, X):
        """Predict anomalies (-1 for anomaly, 1 for normal)"""
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)
    
    def save_model(self, path='models/anomaly_detector.pkl'):
        """Save trained model to disk"""
        joblib.dump({'model': self.model, 'scaler': self.scaler}, path)
        print(f"Model saved to {path}")
    
    def load_model(self, path='models/anomaly_detector.pkl'):
        """Load trained model from disk"""
        data = joblib.load(path)
        self.model = data['model']
        self.scaler = data['scaler']
        self.is_trained = True
        print(f"Model loaded from {path}")

class SignatureDetector:
    """Signature-based intrusion detection using Random Forest"""
    
    def __init__(self, n_estimators=100):
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            random_state=42,
            max_depth=20
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.classes_ = None
    
    def train(self, X_train, y_train):
        """Train the signature detection model"""
        X_scaled = self.scaler.fit_transform(X_train)
        self.model.fit(X_scaled, y_train)
        self.is_trained = True
        self.classes_ = self.model.classes_
        print(f"Signature detector trained on {len(X_train)} samples")
        print(f"Detected attack types: {self.classes_}")
    
    def predict(self, X):
        """Predict attack type"""
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)
    
    def predict_proba(self, X):
        """Get prediction probabilities"""
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")
        X_scaled = self.scaler.transform(X)
        return self.model.predict_proba(X_scaled)
    
    def get_feature_importance(self):
        """Get feature importance scores"""
        if not self.is_trained:
            raise ValueError("Model must be trained first")
        return self.model.feature_importances_
    
    def save_model(self, path='models/signature_detector.pkl'):
        """Save trained model to disk"""
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'classes': self.classes_
        }, path)
        print(f"Model saved to {path}")
    
    def load_model(self, path='models/signature_detector.pkl'):
        """Load trained model from disk"""
        data = joblib.load(path)
        self.model = data['model']
        self.scaler = data['scaler']
        self.classes_ = data['classes']
        self.is_trained = True
        print(f"Model loaded from {path}")
