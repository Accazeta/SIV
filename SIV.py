#!/usr/bin/env python3

import argparse as ap   # for commandline parameters
import os               # for interacting with the os
import traceback        # for printing the traceback of an exception
import csv              # for writing to csv files (verification file)
import pwd              # for getting the name of the owner of a file/directory
import grp              # for getting the name of the group owning a file/directory
import datetime         # for managing dates and time in a human-readable format
import hashlib          # for hashing files
import time             # for calculating the total amount of time that a certain mode takes

def check_if_file_is_inside_folder(filePath : str, dirPath : str) -> bool:
    '''Takes the path to a file and the path to a directory and returns True if the file
       is inside the folder, False otherwise'''
    if os.path.commonprefix([filePath, dirPath]) == dirPath:
        return True
    else:
        return False

def calculate_hash(filepath : str, hasher : hashlib._hashlib.HASH) -> str:
    '''Takes the path to a file and the hashing function in input and returns the hashed digest of said file'''
    with open(filepath, "rb") as f:
        while True:
            data = f.read(4096)
            if not data:
                break
            hasher.update(data)
    return hasher.hexdigest()

def scan_folder(root_folder : str, csv_writer : csv.writer):
    '''Method that recursively scans the parsed root folder and everyone of its subfolder, up to any depth.
    The csv.writer argument is used for writing all the necessary informations to a csv file.
    It returns the number of files and folder (in this order) that have been scanned'''
    num_files = 0
    num_dirs = 0
    # create a list of all the directories followed by all the files
    dirList = [x for x in os.listdir(root_folder) if os.path.isdir(os.path.join(root_folder, x))]
    filesList = [x for x in os.listdir(root_folder) if not os.path.isdir(os.path.join(root_folder, x))]
    if dirList: # if this list is not empty, sort it
        dirList.sort()
    if filesList: # if this list is not empty, sort it
        filesList.sort()
    for filename in dirList + filesList:
        path = os.path.join(root_folder, filename)
        if os.path.isdir(path):
            num_dirs += 1
            #--------------writing phase for directories-----------------
            # Save only the name of the directory
            name = filename
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
            toBeWritten = [name, size, dir_owner_name, dir_group_name, permissions, date_time, hashed_value, path]
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
            if hashFun == "md5":
                computed_message_digest = calculate_hash(path, hashlib.md5())
            elif hashFun == "sha1":
                computed_message_digest = calculate_hash(path, hashlib.sha1())
            # save all the values in a list before writing to the csv file
            toBeWritten = [filename, size, file_owner_name, file_group_name, permissions, formatted_datetime, computed_message_digest, path]
            # writes to the csv
            csv_writer.writerow(toBeWritten)
    return num_files, num_dirs

def copy_csv_and_remove_unwanted_lines(inputCsvFile : str, outputCsvFile : str, unwantedItems : set):
    '''Opens the inputCsvFile and copies all the rows where the last column item doesn't belong\
        to the set of unwantedItems into the the outputCsvFile.
        Returns a FileIOWrapper of a csv file.
    '''
    with open(inputCsvFile, 'r') as inputCsv, open(outputCsvFile, "w", newline="") as outputCsv:
        reader = csv.reader(inputCsv)
        writer = csv.writer(outputCsv)
        for row in reader:
            if row[-1] not in unwantedItems:
                writer.writerow(row)
    return outputCsv

if __name__ == "__main__":
    
    parser = ap.ArgumentParser(add_help=False)
    parser.usage = 'This is a simple System Integrity Verifier (SIV) for a Linux system. Its goal is to detect file system\
    modifications occurring within a directory tree. The SIV outputs statistics and warnings about changes\
    to a report file specified by the user.'

    #------------ List of all the arguments ------------
    group1 = parser.add_mutually_exclusive_group(required=True)

    group1.add_argument('-h', '--help', action='help')
    group1.add_argument('-i', '--initialization-mode', action='store_true', help='Specifies that the script should be run in \"initialization mode\"')
    group1.add_argument('-v', '--verification-mode', action='store_true', help='Specifies that the script should be run in \"verification mode\"')

    parser.add_argument('-D', '--directory', action='store', type=str, required=True, help="Path to the directory that you want to monitor")
    parser.add_argument('-R', '--report-file', action='store', type=str, required=True, help='Name of the report file (must be a .txt)')
    parser.add_argument('-V', '--verification-file', action='store', type=str, required=True, help='Name of the verification file')
    parser.add_argument('-H', '--hash-function', action='store', type=str, choices=['sha1', 'md5'], help='Specifies the algorithm for the hash function')
 
    #------------ Parse all the received arguments ------------
    args = parser.parse_args() # Namespace for all the arguments

    #------------ Start of initialization mode ------------
    if args.initialization_mode == True:
        start_time = time.time() # start counting time  
        print("Starting initialization mode...")
        dirPath = args.directory
        verFilePath = args.verification_file
        reportFilePath = args.report_file
        hashFun = args.hash_function

        #------------ Check that the requirements are met ------------
        try:
            if not os.path.isdir(dirPath):
                raise NotADirectoryError(f"\"{dirPath}\" is not a directory")
            elif not os.path.exists(dirPath):
                raise FileNotFoundError(f" {dirPath} doesn't exist")
            elif not reportFilePath.endswith(".txt"):
                reportFilePath + ".txt"
            else:
                if check_if_file_is_inside_folder(verFilePath, dirPath): # if true, file location is inside
                    raise Exception(f"The verification file specified by {verFilePath} cannot be inside the root folder {dirPath}")
                elif check_if_file_is_inside_folder(reportFilePath, dirPath): # if true, file location is inside
                    raise Exception(f"The report file specified by {reportFilePath} cannot be inside the folder {dirPath}")
                else:
                    if hashFun != "md5" and hashFun != "sha1":
                        raise Exception(f"The hashing function \"{hashFun}\" is not supported.\nType \'siv --help\' for available hashing functions")
                    else:
                        #------------ If everything is fine, write to the verification file ------------
                        with open(verFilePath + ".csv", "w", newline="") as csv_file:
                            writer = csv.writer(csv_file)
                            writer.writerow(['Name', 'Size (B)', 'Owner', 'Group', 'Permission levels', 'Last modification date time', 'Hash ('+hashFun+')', 'Path'])
                            num_files, num_dirs = scan_folder(dirPath, writer)
                            print(f"In total {num_files} files and {num_dirs} directories have been scanned!")
                            end_time = time.time()
                            total_time_initialization_mode = end_time - start_time
                        #------------ Write the report file ------------
                        with open(reportFilePath, "w") as reportFile:
                            reportFile.write(f"The full path of the monitored directory is {dirPath}\n")
                            reportFile.write(f"The full path of the verification file is {verFilePath}.csv\n")
                            reportFile.write(f"Overall, {num_dirs} directories containing a total of {num_files} files have been scanned\n")
                            reportFile.write(f"The total time spent in initialization mode is {total_time_initialization_mode} (seconds)\n")

        except Exception as e:
            print(str(e) + "\n")
            traceback.print_exc()

    #------------ Start of verification mode ------------
    elif args.verification_mode:
        start_time = time.time() # start counting time  
        
        print("Starting verification mode...")
        dirPath = args.directory
        verFilePath = args.verification_file + ".csv"
        reportFilePath = args.report_file   
        hashFun = ""

        # retrieves the 7th element of the first row of the csv file, which contains the name of the 
        # hash function (inside brackets)
        with open(verFilePath, "r") as f:
            temp_reader = csv.reader(f)
            hashFun = next(temp_reader)[6]
            hashFun = hashFun[hashFun.find("(") + 1 : hashFun.find(")")]

        try:
            if args.hash_function is not None:
                raise Exception("In verification mode the hash function cannot be specified")
            elif not os.path.isdir(dirPath):
                raise NotADirectoryError(f"\n\"{dirPath}\" is not a directory")
            elif not os.path.exists(dirPath):
                raise FileNotFoundError(f"\n {dirPath} doesn't exist")
            elif not os.path.isfile(verFilePath):
                raise FileNotFoundError(f"\n {verFilePath} doesn't exist")
            elif not str(reportFilePath).endswith(".txt"):
                raise ValueError(f"\n {reportFilePath} must be a .txt file")
            elif check_if_file_is_inside_folder(verFilePath, dirPath): # if true, file location is inside
                raise Exception(f"The verification file specified by {verFilePath} cannot be inside the root folder {dirPath}")
            elif check_if_file_is_inside_folder(reportFilePath, dirPath): # if true, file location is inside
                raise Exception(f"The report file specified by {reportFilePath} cannot be inside the folder {dirPath}")
            else:
                # create a new csv file that is going to be compared with the old one to see if something has changed
                with open("new_csv_file.csv", "w", newline="") as new_csv_file:
                    new_writer = csv.writer(new_csv_file)
                    new_writer.writerow(['Name', 'Size (B)', 'Owner', 'Group', 'Permission levels', 'Last modification date time', 'Hash ('+hashFun+')', 'Path'])
                    num_files, num_dirs = scan_folder(dirPath, new_writer)
                #------------ Check if something has been deleted ------------ 
                # from the old csv file remove all the entries that are in the new csv.
                # If there's something left in the old csv, then it means that it was deleted
                #
                # Import the paths from the original csv
                original_csv_files = set()
                with open(verFilePath, "r") as original_csv:
                    reader = csv.reader(original_csv)
                    for row in reader:
                        original_csv_files.add(row[-1])
                # Import the paths from the new csv
                new_csv_files = set()
                with open("new_csv_file.csv", "r") as temp:
                    reader = csv.reader(temp)
                    for row in reader:
                        new_csv_files.add(row[-1]) 
                deleted_paths = set()
                deleted_paths = original_csv_files - new_csv_files
                print("------------ Scanning for deleted files or directories ------------")
                if bool(deleted_paths): # if the set is not empty, it means that something has been deleted afterwards
                    print("Warning: the following file/s or directory/ies has/have been deleted!")
                    for index, deleted_file in enumerate(sorted(deleted_paths)):
                        print(f"{index+1} - {deleted_file}")
                else:
                    print("Nothing was deleted!")
                #------------ Check if something new was added ------------
                # This is achieved by doing the opposite set subtraction from above
                # From the new files remove all the old files. If there's something left, then it was added afterward
                print("------------ Scanning for new files or directories ------------")
                new_paths = new_csv_files - original_csv_files
                if bool(new_paths):
                    print("Warning: the following file/s or directory/ies has/have been added")
                    for index, added_file in enumerate(sorted(new_paths)):
                        print(f"{index+1} - {added_file}")
                else:
                    print("Nothing was added!")
                #------------ Look for all the remaing stuff to find ------------
                # 1) take the original verification file and create a new one withoout the deleted items
                # 2) take the second verification file and create a new one without the added items
                # 3) The resulting csv files will have the same amount of rows, thus making it possible to scan them "in parallel".
                #    Furthermore, given the fact that they were created using the same function, the order of the item is the same.
                
                # 1)
                filesInfoBefore = copy_csv_and_remove_unwanted_lines(inputCsvFile=verFilePath, outputCsvFile="ver_file_copy.csv", unwantedItems=deleted_paths)
                
                # 2)
                filesInfoAfter = copy_csv_and_remove_unwanted_lines(inputCsvFile="new_csv_file.csv", outputCsvFile="second_ver_file_copy.csv", unwantedItems=new_paths)

                # 3)
                print("------------ Scanning for details ------------")
                with open(filesInfoBefore.name, 'r') as fileA, open(filesInfoAfter.name, 'r') as fileB:
                    readerA = csv.reader(fileA)
                    readerB = csv.reader(fileB)
                    
                    list_of_changes = []
                    # scans both copied csv files in parallel
                    for rowA, rowB in zip(readerA, readerB):
                        flag = False
                        changes = {"Path" : rowA[-1],
                               "Size" : None, 
                               "Owner" : None, 
                               "Group" : None, 
                               "Permission Levels" : None, 
                               "Last Modification Date" : None, 
                               "Hash" : None,
                               }
                        
                        if rowA[1] != rowB[1]:
                            changes["size"] = [rowA[1], rowB[1]]
                            flag = True
                        if rowA[2] != rowB[2]:
                            changes["Owner"] = [rowA[2], rowB[2]]
                            flag = True
                        if rowA[3] != rowB[3]:
                            changes["Group"] = [rowA[3], rowB[3]]
                            flag = True
                        if rowA[4] != rowB[4]:
                            changes["Permission Levels"] = [rowA[4], rowB[4]]
                            flag = True
                        if rowA[5] != rowB[5]:
                            changes["Last Modification Date"] = [rowA[5], rowB[5]]
                            flag = True
                        if rowA[6] != rowB[6]:
                            changes["Hash"] = [rowA[6], rowB[6]]
                            flag = True
                            
                        
                        if flag: # If something has changed, print it
                            list_of_changes.append(changes)
                
                if list_of_changes:
                    for index, changes in enumerate(list_of_changes):
                        file_path = changes["Path"]
                        print(f"{index+1} - The file/folder {file_path} has undergone the following modifications:")
                        for key, item in changes.items():
                            if item is not None and key is not "Path":
                                print(f"\t{key}:\t|{item[0]}| --> |{item[1]}|")
                else:
                    print("No file or directory was modified!") 

                # When everything is done, clean up all the csv files left behind
                os.remove("new_csv_file.csv")
                os.remove("second_ver_file_copy.csv")
                os.remove("ver_file_copy.csv")

                # Stop counting time
                end_time = time.time()
                total_time_verification_mode = end_time - start_time

                # Write to the report file
                with open(reportFilePath, "w") as rf:
                    rf.write(f"The full path of the monitored directory is {dirPath}\n")
                    rf.write(f"The full path of the verification file is {verFilePath}\n")
                    rf.write(f"The full path of this report file is {reportFilePath}\n")
                    rf.write(f"Overall, {num_dirs} directories containing a total of {num_files} files have been scanned\n")
                    rf.write(f"Overall, {len(deleted_paths) + len(new_paths) + len(list_of_changes)} warnings have been issued\n")
                    rf.write(f"The total time spent in initialization mode is {total_time_verification_mode} (seconds)\n")
               
        except Exception as e:
            print("\n" + str(e) + "\n")
            traceback.print_exc()
