import kagglehub
import os
import shutil

def download_and_extract_datasets():
    print("Downloading NSL-KDD dataset using kagglehub...")
    try:
        # Download latest version of NSL-KDD
        path = kagglehub.dataset_download("hassan06/nslkdd")
        print("Downloaded dataset to:", path)
        
        # Define destination in the workspace
        base_dir = os.path.dirname(os.path.abspath(__file__))
        dest_dir = os.path.join(base_dir, "datasets", "NSL-KDD")
        os.makedirs(dest_dir, exist_ok=True)
        
        # Copy files from kagglehub cache to our workspace
        for item in os.listdir(path):
            s = os.path.join(path, item)
            d = os.path.join(dest_dir, item)
            if os.path.isdir(s):
                shutil.copytree(s, d, dirs_exist_ok=True)
            else:
                shutil.copy2(s, d)
                
        print(f"Dataset successfully copied to {dest_dir}")
        return dest_dir
    except Exception as e:
        print(f"Error downloading dataset: {e}")
        return None

if __name__ == "__main__":
    download_and_extract_datasets()
