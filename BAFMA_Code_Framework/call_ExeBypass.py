import sys
import os
import subprocess
import ctypes
import time


def system_call_ExeBypass(in_exe_path:str,SourceCodeDirectoryPath:str,OutExeDirectoryPath:str):
    '''
        function: call ExeBypass.py file in command line to generate evasion exe
        Usage: python ExeBypass.py in_exe_path SourceCodeDirectoryPath OutExeDirectoryPath
        parameter specification:
            in_exe_path: str, the path of input exe file
            SourceCodeDirectoryPath: str, the path of SourceCodeDirectory
            OutExeDirectoryPath: str, the path of output exe file
        return specification:
            ret: int, the return value of system call
    '''

    cmd = f"python ExeBypass.py {in_exe_path} {SourceCodeDirectoryPath} {OutExeDirectoryPath}"
    ret = os.system(cmd)
    return ret



def bypass_dir_exe(src_dir,SourceCodeDirectoryPath,des_dir):
    """
    function: bypass all exe files in the directory
    parameter specification:
        src_dir: str, the path of source directory
        SourceCodeDirectoryPath: str, the path of SourceCodeDirectory
        des_dir: str, the path of destination directory
    return specification:
        None
    """

    directories = [d for d in os.listdir(src_dir)]

    for file in directories:
        file_path = os.path.join(src_dir,file)

        if os.path.isdir(file_path):
            src_dir_child = file_path #os.path.join(directories,file)
            target_dir_child = os.path.join(des_dir,file+'_evasion')

            os.makedirs(target_dir_child, exist_ok=True)
            # Recursively traverse the folder, deep search, dfs
            bypass_dir_exe(src_dir_child,SourceCodeDirectoryPath,target_dir_child)


        elif os.path.isfile(file_path):
            system_call_ExeBypass(file_path,SourceCodeDirectoryPath,des_dir)




def Bypass_dir(dir_path,SourceCodeDirectoryPath,target_dir_path):
    """
    function: bypass all exe files in the directory
    parameter specification:
        dir_path: str, the path of source directory
        SourceCodeDirectoryPath: str, the path of SourceCodeDirectory
        target_dir_path: str, the path of destination directory
    return specification:
        None
    """
    if dir_path.endswith(os.path.sep):
        dir_path = dir_path[:-1]
    folder_name = os.path.basename(dir_path)    
    new_dir_path = os.path.join(target_dir_path,folder_name+'_evasion')
    if not os.path.exists(new_dir_path):
        os.makedirs(new_dir_path, exist_ok=True)
    bypass_dir_exe(dir_path,SourceCodeDirectoryPath,new_dir_path)


if __name__ == '__main__':

    # call the bypass of a single exe file
    # in_exe_path = "path\\to\\in_exe"
    # SourceCodeDirectoryPath = "path\\to\\SourceCodeFile"
    # OutExeDirectoryPath = "path\\to\\out_exe" 
    # system_call_ExeBypass(in_exe_path,SourceCodeDirectoryPath,OutExeDirectoryPath)


    # call the bypass of a directory of exe files
    SourceCodeDirectoryPath = "path\\to\\SourceCodeFile"
    dir_path = "path\\to\\in_exe\\dir"
    target_dir_path = "path\\to\\out_exe\\dir" 
    if not os.path.exists(target_dir_path):
        os.makedirs(target_dir_path)
    Bypass_dir(dir_path,SourceCodeDirectoryPath,target_dir_path)
