# BAFMA-Dynamic-and-Static-Black-box-Adversarial-Attack-Framework-Based-on-Malware-Architecture
Code framework and Partial experimental data of paper: BAFMA:Dynamic and Static Black-box Adversarial Attack Framework Based on Malware Architecture





The folders are described as follows:

## 1 BAFMA_Code_Framework

This folder contains the code framework for BAFMA：

* `\ExeBypass.py` is a BAFMA framework interface，`\call_ExeBypass.py` is Call examples for interfaces。



To prevent abuse of the attack framework, we will retain some code.

* The Anti-Sandbox function needs to be built by itself.
  * The Anti-Sandbox code in `\SourceCodeFile\checkSandBox.h` needs to be added on its own

* The encryption and decryption function needs to be built by itself.
  * The `encrypt` function in `NeedEncry.py` needs to be added by itself, corresponding to `\SourceCodeFile\decrypt.h`
  * The `decrypt` function in `\SourceCodeFile\decrypt.h` needs to be added by itself, corresponding to `NeedEncry.py`


* The compilation command needs to be built by itself
  * `\SourceCodeFile\building_cl.bat` and `\SourceCodeFile\building_link.bat` represent compile and link commands, respectively, and need to **choose one compiler** to add compile and link commands




## 2 VirusTotal_Report

This folder records **VT test results ** and **related python scripts **.

* The VT test results contain the VT report report (json format) for 140 samples, and the csv file 、`malware_adversarial_result.csv` that summarizes the results.
* The VT key `apikey` and proxy URL `proxy` in the code need to be set by themselves
