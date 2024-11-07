import pandas as pd
import hashlib
import os


import requests
from tqdm import tqdm

proxy = ""
os.environ['HTTP_PROXY'] = proxy
os.environ['HTTPS_PROXY'] = proxy
# url = "https://www.virustotal.com/api/v3/files"

print("HTTP_PROXY:", os.getenv("HTTP_PROXY"))
print("HTTPS_PROXY:", os.getenv("HTTPS_PROXY"))


apikey = ""

def get_folder_files(folder: str) -> list:
    out_files = []
    files = [os.path.join(folder, f) for f in os.listdir(folder) ]
    for file in files:
        if os.path.isfile(file):
            out_files.append(file)
        elif os.path.isdir(file):
            out_files.extend(get_folder_files(file))
    return out_files

def get_file_sha256(file_path: str) -> str:
    with open(file_path, "rb") as f:
        file_data = f.read()
        sha256 = hashlib.sha256(file_data).hexdigest()
    return sha256

def upload_file(file_path: str) -> str:
    url = "https://www.virustotal.com/api/v3/files"
    files = { "file": (os.path.basename(file_path), open(file_path, "rb"), "application/x-msdownload") }
    headers = {
        "accept": "application/json",
        "x-apikey": apikey,
    }
    response = requests.post(url, files=files, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return data["data"]["id"]
    else:
        return None

csv_file = "malware_example.csv"

adversarial_example_csv = "adversarial_example.csv"
adversarial_example_df = pd.read_csv(adversarial_example_csv)
files_id = []
for file in tqdm( adversarial_example_df["file_path"].values,desc="upload"):
    file_id = upload_file(file)
    if file_id:
        files_id.append(file_id)
    else:
        print(f"upload {file} failed")
# adversarial_example_df["file_id"] = files_id
adversarial_example_df.to_csv(adversarial_example_csv, index=False)