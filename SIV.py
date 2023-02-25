import argparse as ap   # for commandline parameters
import os               # for interacting with the os
import traceback        # for printing the traceback of an exception
import csv              # for writing to csv files (verification file)
import pwd              # for getting the name of the owner of a file/directory
import grp              # for getting the name of the group owning a file/directory
import datetime         # for managing dates and time in a human-readable format
import hashlib          # for hashing files

def check_if_file_is_inside_folder(filePath : str, dirPath : str):
    if os.path.commonprefix([filePath, dirPath]) == dirPath:
        return True
    else:
        return False

def calculate_hash(filepath, hasher):
    with open(filepath, "rb") as f:
        while True:
            data = f.read(4096)
            if not data:
                break
            hasher.update(data)
    return hasher.hexdigest()

def scan_folder(root_folder, csv_writer):
    num_files = 0
    num_dirs = 0
    for filename in os.listdir(root_folder):
        path = os.path.join(root_folder, filename)
        if os.path.isdir(path):
            num_dirs += 1
            #--------------writing phase for directories-----------------
            # Save only the name of the directory
            name = os.path.basename(os.path.dirname(path))
            size = None # The instructions say that only the size of files should be saved. This is for dirs.
            # get the owner name
            dir_owner_uid = os.stat(path).st_uid
            dir_owner_name = pwd.getpwuid(dir_owner_uid).pw_name
            # get the group name
            dir_group_uid = os.stat(path).st_gid
            dir_group_name = grp.getgrgid(dir_group_uid).gr_name
            # get the directory permissions
            permissions = oct(os.stat(path).st_mode & 0o777)
            # Assumption: the last modification datetime of a folder can be ambiguous (some might say it's the
            # same of the last modified file, some might say it doesn't make sense). I decided to follow the latter.
            date_time = None
            # hash: None
            hashed_value = None
            # save all the values in a list before writing to the csv file
            toBeWritten = [name, size, dir_owner_name, dir_group_name, permissions, date_time, hashed_value, root_folder]
            # writes to the csv
            csv_writer.writerow(toBeWritten)
            # next folder
            sub_files, sub_dirs = scan_folder(path, csv_writer)
            num_files += sub_files
            num_dirs += sub_dirs
        else:
            num_files += 1
            #--------------writing phase for files-----------------
            # get the size
            size = os.path.getsize(path)
            # get the owner name
            file_owner_uid = os.stat(path).st_uid
            file_owner_name = pwd.getpwuid(file_owner_uid).pw_name
            # get the group id
            file_group_gid = os.stat(path).st_gid
            file_group_name = grp.getgrgid(file_group_gid).gr_name
            # permissions
            permissions = oct(os.stat(path).st_mode & 0o777)
            # calculate last modification date
            modification_time_since_epoch = os.path.getmtime(path)
            modification_datetime = datetime.datetime.fromtimestamp(modification_time_since_epoch)
            formatted_datetime = modification_datetime.strftime("%d/%m/%Y %H:%M:%S GMT+1")
            # calculate hash
            if args.hash_function == "md5":
                computed_message_digest = calculate_hash(path, hashlib.md5())
            elif args.hash_function == "sha1":
                computed_message_digest = calculate_hash(path, hashlib.sha1())
            # save all the values in a list before writing to the csv file
            toBeWritten = [filename, size, file_owner_name, file_group_name, permissions, formatted_datetime, computed_message_digest, path]
            # writes to the csv
            csv_writer.writerow(toBeWritten)

    return num_files, num_dirs

if __name__ == "__main__":
    
    parser = ap.ArgumentParser(add_help=False)
    #parser.usage = 'This is a simple System Integrity Verifier (SIV) for a Linux system. Its goal is to detect file system\
    #modifications occurring within a directory tree. The SIV outputs statistics and warnings about changes\
    #to a report file specified by the user.'

    #------------ List of all the arguments------------------
    group1 = parser.add_mutually_exclusive_group()

    group1.add_argument('-h', '--help', action='help')
    group1.add_argument('-i', '--initialization-mode', action='store_true', help='Specifies that the script should be run in \"initialization mode\"')
    group1.add_argument('-v', '--verification-mode', action='store_true', help='Specifies that the script should be run in \"verification mode\"')

    parser.add_argument('-D', '--directory', action='store', type=str, required=True, help="Path to the directory that you want to monitor")
    parser.add_argument('-R', '--report-file', action='store', type=str, required=True, help='Name of the report file (must be a .txt)')
    parser.add_argument('-V', '--verification-file', action='store', type=str, required=True, help='Name of the verification file')
    parser.add_argument('-H', '--hash-function', action='store', type=str, choices=['sha1', 'md5'], help='Specifies the algorithm for the hash function')
 

    #------------ Parse all the received arguments
    args = parser.parse_args() # Namespace for all the arguments

    if args.verification_mode:
        if args.hash_function is not None and args.verification_file is not None:
            raise Exception("In verification mode the hash function cannot be specified")

    if args.initialization_mode == True:
        print("Starting initialization mode...")
        dirPath = args.directory
        verFilePath = args.verification_file
        reportFilePath = args.report_file
        hashFun = args.hash_function
        #-------Temporary hardcoding for testing purposes--------
        #dirPath = "/home/accazeta/Scrivania/Test Folder"
        #verFilePath = "/home/accazeta/Scrivania/Test Folder/verification_file.txt"
        #reportFilePath = "/home/accazeta/Scrivania/Test Folder/report_file.txt"
        #hashFun = "md5"
        #-------End of programming malpractice-----------

        try:
            if not os.path.isdir(dirPath):
                raise Exception(f"\"{dirPath}\" is not a directory")
            elif not os.path.exists(dirPath):
                raise Exception(f" {dirPath} doesn't exist")
            elif not os.path.isfile(verFilePath):
                raise Exception(f" {verFilePath} doesn't exist")
            elif not os.path.isfile(reportFilePath):
                raise Exception(f" {reportFilePath} doesn't exist")
            else:
                if check_if_file_is_inside_folder(verFilePath, dirPath): # if true, file location is inside
                    raise Exception(f"The verification file specified by {verFilePath} cannot be inside the root folder {dirPath}")
                elif check_if_file_is_inside_folder(reportFilePath, dirPath): # if true, file location is inside
                    raise Exception(f"The report file specified by {reportFilePath} cannot be inside the folder {dirPath}")
                else:
                    if hashFun != "md5" and hashFun != "sha1":
                        raise Exception(f"The hashing function \"{hashFun}\" is not supported.\nType \'siv --help\' for available hashing functions")
                    else:
                        with open(verFilePath + ".csv", "w", newline="") as csv_file:
                            writer = csv.writer(csv_file)
                            writer.writerow(['Name', 'Size (Kb)', 'Owner', 'Group', 'Permission levels', 'Last modification date time', 'Hash', 'Path'])
                            num_files, num_dirs = scan_folder(dirPath, writer)
                            print(f"In total {num_files} files and {num_dirs} directories have been scanned!")
            
        except Exception as e:
            print(str(e) + "\n")
            traceback.print_exc()
    elif args.verification_mode:
        print("Starting verification mode...")


