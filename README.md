# OSEAF: A Robust One-Shot Environment-Aware Framework for Malware Detection Evasion
Code framework and Partial experimental data of paper: OSEAF: A Robust One-Shot Environment-Aware Framework for Malware Detection Evasion





The folders are described as follows:

## 1 OSEAF_Code_Framework

This folder contains the code framework for OSEAF：

* `\ExeBypass.py` is a OSEAF framework interface，`\call_ExeBypass.py` is Call examples for interfaces。



To prevent abuse of the attack framework, we will retain some code.

* The Anti-Sandbox function needs to be built by itself.
  * The Anti-Sandbox code in `\SourceCodeFile\checkSandBox.h` needs to be added on its own

* The encryption and decryption function needs to be built by itself.
  * The `encrypt` function in `NeedEncry.py` needs to be added by itself, corresponding to `\SourceCodeFile\decrypt.h`
  * The `decrypt` function in `\SourceCodeFile\decrypt.h` needs to be added by itself, corresponding to `NeedEncry.py`


* The compilation command needs to be built by itself
  * `\SourceCodeFile\building_cl.bat` and `\SourceCodeFile\building_link.bat` represent compile and link commands, respectively, and need to **choose one compiler** to add compile and link commands




## 2 VirusTotal_Report

This folder records **[VirusTotal](https://www.virustotal.com/gui/home/upload) report results ** and **related python scripts **.

* The VT test results contain the VT report report (json format) for 140 samples, and the csv file 、`malware_adversarial_result.csv` that summarizes the results.
* The VT key `apikey` and proxy URL `proxy` in the code need to be set by themselves



## 3 Datasets

csv file containing 3500 malicious sample data sets, containing malicious sample information `mal_type`, `sha256`, `size_kb`, from [VirusShare](https://virusshare.com/)

