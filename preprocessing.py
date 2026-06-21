import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
import joblib

# NSL-KDD column names
COLUMNS = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
           'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
           'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count',
           'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
           'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
           'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
           'label', 'difficulty']

CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']

def get_threat_category(label):
    # Mapping NSL-KDD specific attacks to broader categories
    dos_attacks = ['apache2', 'back', 'land', 'neptune', 'mailbomb', 'pod', 'processtable', 'smurf', 'teardrop', 'udpstorm']
    probe_attacks = ['ipsweep', 'mscan', 'nmap', 'portsweep', 'saint', 'satan']
    privilege_attacks = ['buffer_overflow', 'loadmodule', 'perl', 'ps', 'rootkit', 'sqlattack', 'xterm']
    access_attacks = ['ftp_write', 'guess_passwd', 'httptunnel', 'imap', 'multihop', 'named', 'phf', 'sendmail', 'snmpgetattack', 'snmpguess', 'spy', 'warezclient', 'warezmaster', 'xlock', 'xsnoop']

    if label == 'normal':
        return 'Normal'
    elif label in dos_attacks:
        return 'DDoS'
    elif label in probe_attacks:
        return 'Port Scan'
    elif label in access_attacks:
        return 'Brute Force'
    elif label in privilege_attacks:
        return 'Insider Threat'
    else:
        # Fallback for others to fit dashboard
        return 'Malware'

def preprocess_data():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_dir = os.path.join(base_dir, "datasets", "NSL-KDD")
    train_file = os.path.join(dataset_dir, "KDDTrain+.txt")
    
    if not os.path.exists(train_file):
        print("Dataset not found. Please run dataset_download.py first.")
        return False
        
    print("Loading dataset...")
    df = pd.read_csv(train_file, names=COLUMNS)
    
    # Drop difficulty as it's not a real feature
    df = df.drop('difficulty', axis=1)
    
    # Map labels to threat categories
    df['threat_category'] = df['label'].apply(get_threat_category)
    df = df.drop('label', axis=1)
    
    # Label encoding for categorical columns
    label_encoders = {}
    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        label_encoders[col] = le
        
    # Also encode the target
    target_le = LabelEncoder()
    df['threat_category_encoded'] = target_le.fit_transform(df['threat_category'])
    
    X = df.drop(['threat_category', 'threat_category_encoded'], axis=1)
    y = df['threat_category_encoded']
    
    # Feature Scaling
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
    
    # Save processed data and encoders
    processed_dir = os.path.join(base_dir, "processed_data")
    os.makedirs(processed_dir, exist_ok=True)
    models_dir = os.path.join(base_dir, "models")
    os.makedirs(models_dir, exist_ok=True)
    
    np.save(os.path.join(processed_dir, 'X_train.npy'), X_train)
    np.save(os.path.join(processed_dir, 'X_test.npy'), X_test)
    np.save(os.path.join(processed_dir, 'y_train.npy'), y_train)
    np.save(os.path.join(processed_dir, 'y_test.npy'), y_test)
    
    # Save encoders and scaler
    joblib.dump(scaler, os.path.join(models_dir, 'scaler.pkl'))
    joblib.dump(target_le, os.path.join(models_dir, 'target_encoder.pkl'))
    for col, le in label_encoders.items():
        joblib.dump(le, os.path.join(models_dir, f'encoder_{col}.pkl'))
        
    print("Preprocessing completed. Data saved to processed_data/ and encoders to models/")
    return True

if __name__ == "__main__":
    preprocess_data()
