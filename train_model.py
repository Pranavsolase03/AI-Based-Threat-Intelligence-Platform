import os
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use('Agg') # For headless environments
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_curve, auc
from sklearn.preprocessing import label_binarize
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout

def train_and_evaluate():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    processed_dir = os.path.join(base_dir, "processed_data")
    models_dir = os.path.join(base_dir, "models")
    plots_dir = os.path.join(base_dir, "plots")
    os.makedirs(plots_dir, exist_ok=True)
    
    # Load data
    print("Loading preprocessed data...")
    try:
        X_train = np.load(os.path.join(processed_dir, 'X_train.npy'))
        X_test = np.load(os.path.join(processed_dir, 'X_test.npy'))
        y_train = np.load(os.path.join(processed_dir, 'y_train.npy'))
        y_test = np.load(os.path.join(processed_dir, 'y_test.npy'))
    except FileNotFoundError:
        print("Preprocessed data not found. Run preprocessing.py first.")
        return
        
    num_classes = len(np.unique(y_train))
    
    metrics = {}
    
    # 1. Random Forest
    print("Training Random Forest...")
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_model.fit(X_train, y_train)
    joblib.dump(rf_model, os.path.join(models_dir, 'rf_model.pkl'))
    y_pred_rf = rf_model.predict(X_test)
    y_proba_rf = rf_model.predict_proba(X_test)
    
    # 2. XGBoost
    print("Training XGBoost...")
    xgb_model = XGBClassifier(use_label_encoder=False, eval_metric='mlogloss', random_state=42)
    xgb_model.fit(X_train, y_train)
    joblib.dump(xgb_model, os.path.join(models_dir, 'xgb_model.pkl'))
    y_pred_xgb = xgb_model.predict(X_test)
    y_proba_xgb = xgb_model.predict_proba(X_test)
    
    # 3. Isolation Forest (Anomaly Detection)
    print("Training Isolation Forest...")
    iso_model = IsolationForest(contamination=0.1, random_state=42)
    iso_model.fit(X_train)
    joblib.dump(iso_model, os.path.join(models_dir, 'isolation_model.pkl'))
    # Iso forest returns 1 for inliers, -1 for outliers. We don't calculate traditional metrics for it.
    
    # 4. Neural Network
    print("Training Neural Network...")
    y_train_cat = tf.keras.utils.to_categorical(y_train, num_classes)
    y_test_cat = tf.keras.utils.to_categorical(y_test, num_classes)
    
    nn_model = Sequential([
        Dense(64, activation='relu', input_shape=(X_train.shape[1],)),
        Dropout(0.2),
        Dense(32, activation='relu'),
        Dropout(0.2),
        Dense(num_classes, activation='softmax')
    ])
    
    nn_model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    history = nn_model.fit(X_train, y_train_cat, epochs=10, batch_size=32, validation_split=0.2, verbose=0)
    nn_model.save(os.path.join(models_dir, 'nn_model.h5'))
    
    y_pred_nn = np.argmax(nn_model.predict(X_test), axis=1)
    y_proba_nn = nn_model.predict(X_test)
    
    # Calculate metrics
    def calculate_metrics(y_true, y_pred, name):
        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, average='weighted', zero_division=0)
        rec = recall_score(y_true, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(y_true, y_pred, average='weighted', zero_division=0)
        metrics[name] = {'Accuracy': acc, 'Precision': prec, 'Recall': rec, 'F1 Score': f1}
        return acc
        
    calculate_metrics(y_test, y_pred_rf, 'Random Forest')
    calculate_metrics(y_test, y_pred_xgb, 'XGBoost')
    calculate_metrics(y_test, y_pred_nn, 'Neural Network')
    
    # Generate Plots
    
    # 1. Accuracy Comparison Plot
    plt.figure(figsize=(10, 6))
    model_names = list(metrics.keys())
    accuracies = [metrics[m]['Accuracy'] for m in model_names]
    sns.barplot(x=model_names, y=accuracies)
    plt.title('Model Accuracy Comparison')
    plt.ylim(0, 1.1)
    plt.ylabel('Accuracy')
    plt.savefig(os.path.join(plots_dir, 'accuracy_comparison.png'))
    plt.close()
    
    # 2. Confusion Matrix (XGBoost as best generally)
    plt.figure(figsize=(8, 6))
    cm = confusion_matrix(y_test, y_pred_xgb)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title('Confusion Matrix (XGBoost)')
    plt.ylabel('Actual')
    plt.xlabel('Predicted')
    plt.savefig(os.path.join(plots_dir, 'confusion_matrix.png'))
    plt.close()
    
    # 3. ROC Curve
    plt.figure(figsize=(10, 8))
    y_test_bin = label_binarize(y_test, classes=np.unique(y_test))
    for i in range(num_classes):
        fpr, tpr, _ = roc_curve(y_test_bin[:, i], y_proba_xgb[:, i])
        plt.plot(fpr, tpr, label=f'Class {i} (area = {auc(fpr, tpr):.2f})')
    plt.plot([0, 1], [0, 1], 'k--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curve (XGBoost)')
    plt.legend(loc="lower right")
    plt.savefig(os.path.join(plots_dir, 'roc_curve.png'))
    plt.close()
    
    # 4. Feature Importance (Random Forest)
    plt.figure(figsize=(12, 8))
    importances = rf_model.feature_importances_
    indices = np.argsort(importances)[::-1]
    # We don't have feature names directly here easily, so we just plot top 20 indices
    top_indices = indices[:20]
    plt.bar(range(20), importances[top_indices], align="center")
    plt.xticks(range(20), top_indices, rotation=90)
    plt.title("Top 20 Feature Importances (Random Forest)")
    plt.savefig(os.path.join(plots_dir, 'feature_importance.png'))
    plt.close()
    
    # 5. Loss Curve (Neural Network)
    plt.figure(figsize=(10, 6))
    plt.plot(history.history['loss'], label='Train Loss')
    plt.plot(history.history['val_loss'], label='Validation Loss')
    plt.title('Model Loss (Neural Network)')
    plt.ylabel('Loss')
    plt.xlabel('Epoch')
    plt.legend()
    plt.savefig(os.path.join(plots_dir, 'loss_curve.png'))
    plt.close()
    
    # Save metrics
    metrics_df = pd.DataFrame(metrics).T
    metrics_df.to_csv(os.path.join(base_dir, 'model_metrics.csv'))
    print("Training completed. Models and plots saved.")
    
if __name__ == "__main__":
    train_and_evaluate()
