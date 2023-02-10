import argparse as ap

parser = ap.ArgumentParser(add_help=False)
parser.usage = 'This is a simple System Integrity Verifier (SIV) for a Linux system. Its goal is to detect file system\
modifications occurring within a directory tree. The SIV outputs statistics and warnings about changes\
to a report file specified by the user.'

#------------ List of all the arguments------------------
group1 = parser.add_mutually_exclusive_group()

group1.add_argument('-h', '--help', action='help')
group1.add_argument('-i', '--initialization_mode', action='store_true', help='Specifies that the script should be run in \"initialization mode\"')
group1.add_argument('-v', '--verification_mode', action='store_true', help='Specifies that the script should be run in \"verification mode\"')

parser.add_argument('-D', '--directory', action='store', type=str, help="Path to the directory that you want to monitor")

group2 = parser.add_mutually_exclusive_group()
group2.add_argument('-V', '--verification_file', action='store',  type=str, help='Name of the verification file')

parser.add_argument('-R', '--report_file', action='store', type=str, help='Name of the report file (must be a .txt)')

group2.add_argument('-H', '--hash_function', action='store', type=str, choices=['sha1', 'md5'], help='Specifies the algorithm for the hash function')



#------------ Parse all the received arguments
args = parser.parse_args() # Namespace for all the arguments

print(args.initialization_mode)
print(args.verification_mode)





