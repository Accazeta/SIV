import argparse as ap
import os
import traceback


def check_if_file_is_inside_folder(filePath : str, dirPath : str):
    if os.path.commonprefix([filePath, dirPath]) == dirPath:
        return True
    else:
        return False




if __name__ == "__main__":

    parser = ap.ArgumentParser(add_help=False)
    parser.usage = 'This is a simple System Integrity Verifier (SIV) for a Linux system. Its goal is to detect file system\
    modifications occurring within a directory tree. The SIV outputs statistics and warnings about changes\
    to a report file specified by the user.'

    #------------ List of all the arguments------------------
    group1 = parser.add_mutually_exclusive_group()

    group1.add_argument('-h', '--help', action='help')
    group1.add_argument('-i', '--initialization-mode', action='store_true', help='Specifies that the script should be run in \"initialization mode\"')
    group1.add_argument('-v', '--verification-mode', action='store_true', help='Specifies that the script should be run in \"verification mode\"')

    parser.add_argument('-D', '--directory', action='store', type=str, help="Path to the directory that you want to monitor")

    group2 = parser.add_mutually_exclusive_group()
    group2.add_argument('-V', '--verification-file', action='store',  type=str, help='Name of the verification file')

    parser.add_argument('-R', '--report-file', action='store', type=str, help='Name of the report file (must be a .txt)')

    group2.add_argument('-H', '--hash-function', action='store', type=str, choices=['sha1', 'md5'], help='Specifies the algorithm for the hash function')

    #------------ Parse all the received arguments
    args = parser.parse_args() # Namespace for all the arguments

    if args.initialization_mode:
        print("Starting initialization mode...")
        dirPath = args.directory
        verFilePath = args.verification_file
        reportFilePath = args.report_file
        hashFun = args.hash_function
        #-------Temporary hardcoding for testing purposes--------
        dirPath = "/home/accazeta/Scrivania/Test Folder"
        verFilePath = "/home/accazeta/Scrivania/Test Folde/verification_file.txt"
        reportFilePath = "/home/accazeta/Scrivania/Test Folde/report_file.txt"
        hashFun = "md5"
        #-------End of programming malpractice-----------

        

        try:
            if not os.path.isdir(dirPath):
                raise Exception(f"{dirPath}\nis not a directory")
            elif not os.path.exists(dirPath):
                raise Exception(f"{dirPath}\ndoesn't exist")
            else:
                if check_if_file_is_inside_folder(verFilePath, dirPath): # if true, file location is inside
                    raise Exception(f"The verification file specified by\n{verFilePath}\ncannot be inside the folder\n{dirPath}")
                elif check_if_file_is_inside_folder(reportFilePath, dirPath): # if true, file location is inside
                    raise Exception(f"The verification file specified by\n{reportFilePath}\ncannot be inside the folder\n{dirPath}")
                else:
                    if hashFun != "md5" or hashFun != "sha1":
                        raise Exception(f"The hashing function \"{hashFun}\n is not supported.\nType \'siv --help\' for available hashing functions")
                    else:
                        pass # Here starts the main part of the program
            
        except Exception as e:
            print(str(e) + "\n")
            traceback.print_exc()
    elif args.verification_mode:
        print("Starting verification mode...")


