import os
import pandas as pd

def create_demo_files():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_dir = os.path.join(base_dir, "datasets", "NSL-KDD")
    test_file = os.path.join(dataset_dir, "KDDTest+.txt")
    
    if not os.path.exists(test_file):
        print("Dataset not found. Cannot create demo files.")
        return
        
    COLUMNS = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
       'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
       'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count',
       'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
       'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
       'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
       'label', 'difficulty']

    df = pd.read_csv(test_file, names=COLUMNS)
    
    # Create a malicious demo file (mostly anomalies)
    malicious_df = df[df['label'] != 'normal'].head(15)
    # We can drop label and difficulty to simulate raw logs, or keep them as our backend drops them anyway
    malicious_df.to_csv(os.path.join(base_dir, 'demo_malicious_logs.csv'), index=False, header=False)
    
    # Create a normal demo file (mostly benign)
    normal_df = df[df['label'] == 'normal'].head(15)
    normal_df.to_csv(os.path.join(base_dir, 'demo_normal_logs.csv'), index=False, header=False)
    
    # Create a mixed demo file
    mixed_df = pd.concat([df[df['label'] == 'normal'].head(10), df[df['label'] != 'normal'].head(10)])
    mixed_df = mixed_df.sample(frac=1).reset_index(drop=True) # Shuffle
    mixed_df.to_csv(os.path.join(base_dir, 'demo_mixed_logs.csv'), index=False, header=False)
    
    print("Demo files created: demo_malicious_logs.csv, demo_normal_logs.csv, demo_mixed_logs.csv")

if __name__ == "__main__":
    create_demo_files()
