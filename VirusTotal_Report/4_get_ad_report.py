import requests
import os
import hashlib
import random
import json
import pandas as pd
from tqdm import tqdm

proxy = ""
os.environ['HTTP_PROXY'] = proxy
os.environ['HTTPS_PROXY'] = proxy
# url = "https://www.virustotal.com/api/v3/files"

print("HTTP_PROXY:", os.getenv("HTTP_PROXY"))
print("HTTPS_PROXY:", os.getenv("HTTPS_PROXY"))
url = "https://www.virustotal.com/api/v3/files"

# apikey
apikey = ""

def get_file_sha256(file_path: str) -> str:
    with open(file_path, "rb") as f:
        file_data = f.read()
        sha256 = hashlib.sha256(file_data).hexdigest()
    return sha256


def get_file_report(file_sha256: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/files/{file_sha256}"

    headers = {
        "accept": "application/json",
        "x-apikey": apikey
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"get VT report error : {response.text}")
        return None

def get_csv_files_report(adversarial_example_csv:str,json_folder:str):
    adversarial_example_df = pd.read_csv(adversarial_example_csv)
    # add malicious, suspicious, undetected, last_submission_date columns
    adversarial_example_df["malicious"] = [None] * len(adversarial_example_df)
    adversarial_example_df["suspicious"] = [None] * len(adversarial_example_df)
    adversarial_example_df["undetected"] = [None] * len(adversarial_example_df)
    adversarial_example_df["last_submission_date"] = [None] * len(adversarial_example_df)
    print(f'adversarial_example_df 5: {adversarial_example_df.head()}')
    for index, row in tqdm(adversarial_example_df.iterrows(),desc=f"get_file_report,total:{len(adversarial_example_df)}"):
        sha256 = row["sha256"]
        resport_dict = get_file_report(sha256)
        if resport_dict != None:
            adversarial_example_df.at[index, "malicious"] = resport_dict["data"]["attributes"]["last_analysis_stats"]["malicious"]
            adversarial_example_df.at[index, "suspicious"] = resport_dict["data"]["attributes"]["last_analysis_stats"]["suspicious"]
            adversarial_example_df.at[index, "undetected"] = resport_dict["data"]["attributes"]["last_analysis_stats"]["undetected"]
            adversarial_example_df.at[index, "last_submission_date"] = resport_dict["data"]["attributes"]["last_submission_date"]
            # write report_dict to json file, named by sha256
            if json_folder is not None:
                if not os.path.exists(json_folder):
                    os.makedirs(json_folder)
                with open(os.path.join(json_folder,f"{sha256}.json"), "w", encoding="utf-8") as f:
                    json.dump(resport_dict, f, ensure_ascii=False, indent=4)

    adversarial_example_df.to_csv(adversarial_example_csv, index=False)



if __name__ == "__main__":
    adversarial_example_csv = "adversarial_example.csv"
    out_json_folder = "adversarial_example_json"
    get_csv_files_report(adversarial_example_csv,out_json_folder)
