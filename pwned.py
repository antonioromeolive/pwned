# PWNED - ver 1.0 - 08/05/2021
# PWNED - ver 1.3 - 08/12/2021 Added -z switch (only support single password so far...)
# PWNED - ver 2.0 - 13/04/2023 Added -b switch for "binary_search" if the password file is sorted
# PWNED - ver 2.1 - 14/04/2023 added info at exit (printstats improvements)
# Author: Antonio Romeo - Cinquefrondi (RC)
# email: antonioromeoNO_SPAM@live.it
# This software is free of charge for personal usage. Since it may use an online service (to check if a pwd has been "pwned")
# the number of queries to the service may be subject to policy/licensing. I am not affiliated nor sponsored nor associated in any way 
# with the provider of the service. You need to get the owner permission (https://haveibeenpwned.com) for any "extensive" usage.
# My suggestion, if you have lot of pwd to check, is to download the hacked pwd DB from the same site and use it locally.
# But anyway you are on your own.
# Notes: when checking the password online, the pwd itself is NOT sent to anybody... checks are done against HASHED passwords 
#        in a way to anonymize the pwd itself.
# Feel free to send me any bug/improvement request. I will try to respond to anyone.
"""
MIT License

Copyright (c) [2024] [Antonio Romeo]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
import os
import sys
import datetime
import hashlib
import getopt
import time
import threading
import zipfile
import requests

import pwned_stats as pstat

my_stats = pstat.PwnedStats()
my_stats.start_timer()

HASH_PREFIX_LENGHT  = 5
BASE_PWD_SEARCH_URL = 'https://api.pwnedpasswords.com/range/'

#type of expected inputs for the scrypt
IM_UNKNOWN_MODE     = 0
IM_SINGLE_PASSOWRD  = 1 #a single password provided in the command line - can be plain text or sha1 hash depending on OPERATION_MODE
IM_PASSWORD_FILE    = 2 #a file containing password (one per line)
IM_TEXT_FILE        = 3 #a text file containing words that will be extracted as password (with some filter explained in command line help)

#work with plain text or SHA1 passwords (-s flag)
OM_PLAIN            = 1 #all password are provided to the script as plain text ... input password may be logged or showed on screen beware where you use this...
OM_HASH             = 2 #all password are provided to the script as SHA1.... and also logged or written as such (i.e. no passwords present anywhere...)

#work with the web service or with local file
DB_UNKNOWN          = 0
DB_WEB              = 1
DB_LOCAL            = 2
DB_LOCAL_SORTED     = 3
DB_LOCAL_ZIP        = 4

INPUT_MODES: list[int]     = [IM_SINGLE_PASSOWRD, IM_PASSWORD_FILE, IM_TEXT_FILE]
OPERATION_MODES: list[int] = [OM_PLAIN, OM_HASH]
DATABASE_MODES: list[int]  = [DB_WEB, DB_LOCAL, DB_LOCAL_SORTED, DB_LOCAL_ZIP]

ERR_NO_ERROR         = 0
ERR_WRONG_PARAMETERS = 1
ERR_OTHERS           = 2
ERR_OPMODE_UNKNOWN   = 3
ERR_NO_HASH_PASSWORD = 4


#Constants for the -f implementation....
#lines starting with the below will be excluded
LINES_TO_EXCLUDE = ["http", "https", "***", "---", "___", "#", "//", "/*"] 
#following chars will be changed to spaces
SPLIT_CHARS      = [":", "/", "=", "\t"]
#words longer than 5 will be excluded
MIN_WORD_LENGTH=5

#A line_tocheck with ANY of the words in "excluding_list" will return TRUE (so to be excluded)
def lineToBeExcluded(line_tocheck, excluding_list):
    result=False
    for word_to_exclude in excluding_list:
        if line_tocheck.startswith(word_to_exclude):
            result = True
            break
    return result

def wordToBeExcluded(word_tocheck, min_word_length):
    result = (len(word_tocheck) < min_word_length)
    return result

def printColor(text: str, color:str="white") -> None:
    #used by printcolor....
    RU_COLOR_RED:str    = "\033[91m {}\033[00m"
    RU_COLOR_GREEN:str  = "\033[92m {}\033[00m"
    RU_COLOR_BLUE:str   = "\033[94m {}\033[00m"
    RU_COLOR_YELLOW:str = "\033[93m {}\033[00m"
    RU_COLOR_PINK:str   = "\033[95m {}\033[00m"
    RU_COLOR_CYAN:str   = "\033[96m {}\033[00m"
    RU_COLOR_WHITE:str  = "\033[97m {}\033[00m"
    RU_COLOR_BLACK:str  = "\033[98m {}\033[00m"
    RU_COLOR_GRAY:str   = "\033[99m {}\033[00m"

    """ print a text in the defined color """
    if color.strip().lower() == "red":
        print(RU_COLOR_RED .format(text))
    elif color.strip().lower() == "green":
        print(RU_COLOR_GREEN .format(text))
    elif color.strip().lower() == "blue":
        print(RU_COLOR_BLUE .format(text))
    elif color.strip().lower() == "yellow":
        print(RU_COLOR_YELLOW .format(text))
    elif color.strip().lower() == "pink":
        print(RU_COLOR_PINK .format(text))
    elif color.strip().lower() == "cyan":
        print(RU_COLOR_CYAN .format(text))
    elif color.strip().lower() == "white":
        print(RU_COLOR_WHITE .format(text))
    elif color.strip().lower() == "black":
        print(RU_COLOR_BLACK .format(text))
    elif color.strip().lower() == "gray":
        print(RU_COLOR_GRAY .format(text))
    else:
        print(text)

    return


def getPasswordList(filename):
    # def __init__(self, src_password, src_hash, found_filename, found_linenumber, ispwned=False):
    # with context manager assures us the
    # file will be closed when leaving the scope
    file = open(filename, 'r', errors='ignore', encoding='utf-8')
    lines = file.readlines()
   
    cleaned_word_list = []
    file_line:int=0
    for the_line in lines:
        file_line=file_line+1
        remove_unwanted: str=the_line.strip()

        if not lineToBeExcluded(remove_unwanted, LINES_TO_EXCLUDE):
            for chartoremove in SPLIT_CHARS:
                remove_unwanted = remove_unwanted.replace(chartoremove, " ")
        
            newline=remove_unwanted.split(" ")
            #assert " " not in newline
            for word in newline:
                if not wordToBeExcluded(word, MIN_WORD_LENGTH):
                    the_hash = hashlib.sha1()
                    the_hash.update(str(word).strip().encode('utf-8'))
                    new_rec= password_record(word, the_hash.hexdigest().upper(), filename, file_line, False)
                    cleaned_word_list.append(new_rec)
        
    return cleaned_word_list


class password_record:
    def __init__(self, src_password, src_hash, found_filename, found_linenumber, ispwned=False):
        self.src_password = src_password    # instance variable unique to each instance
        self.src_hash = src_hash
        self.found_filename = found_filename
        self.found_linenumber = found_linenumber
        self.ispwned = ispwned


def printStats() -> None:

    loc_stats = pstat.PwnedStats()
    loc_stats.stop_timer()
    loc_stats.elapsed_time = loc_stats.elapsed_time 

    print("\n")
    print("---------------------------------------------------------------")
    print("Total number of passwords/hash read.......: " + "{:,}".format(loc_stats.number_of_password_read))
    print("Total number of passwords/hash pwned......: " + "{:,}".format(loc_stats.pwned_passwords_found))
    print("Total number of passwords/hash safe.......: " + "{:,}".format(loc_stats.safe_passwords_found))
    print("Total number of passwords/hash read.......: " + "{:,}".format(loc_stats.number_of_password_read))
    print("Total number of lines scanned in local db : " + "{:,}".format(loc_stats.scanned_lines_in_db))
    print("Total elapsed time (sec)..................: " + "{0:.4f}".format(loc_stats.elapsed_time) + " (" + str(datetime.timedelta(seconds=loc_stats.elapsed_time)) + ")")
    print("---------------------------------------------------------------")
    print("PWNED - ver. " + loc_stats.PROGRAM_VERSION + " from A.R.")
    return 


def debugLog(any_variable, color: str = "gray", calling_function:str="") -> None:
    """ 
    print a stringin color if DEBUG_MODE=True. Also write on file if DEBUG_ON_FILE is True
    """
    loc_stats = pstat.PwnedStats()
    l_DEBUG_MODE: bool = loc_stats.DEBUG_MODE
    DEBUG_ON_FILE: bool = loc_stats.DEBUG_ON_FILE
    DEBUG_FILENAME: str = loc_stats.DEBUG_FILENAME

    timestamp: str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    debug_string:str = timestamp + " - " + calling_function + " - " + str(any_variable)
    if l_DEBUG_MODE:
        #print('DEBUG: ', end='')  
        printColor(debug_string, color)
    
    if DEBUG_ON_FILE:
        
        with open(DEBUG_FILENAME, "a", encoding="utf-8") as file:
            file.write(debug_string + "\n")

    return


def alwaysLog(string_variable):
    print(string_variable)
    return

    
def readTextPasswordFromTextFile(l_cli_password_file, l_inputmode=OM_PLAIN):
    result = []
    file = open(l_cli_password_file, 'r', encoding='utf-8', errors='ignore')
    lines = file.readlines()
    file_line:int=0
    if l_inputmode==OM_PLAIN:
        debugLog("readTextPasswordFromTextFile - Reading in plain text mode (i.e. expecting plain passwords)")
        for the_line in lines:
            the_word: str=the_line.strip()
            file_line =file_line+1
            if the_word != "":
                the_hash = hashlib.sha1()
                try:
                    the_hash.update(the_word.encode('utf-8'))  
                except Exception as e:
                    debugLog(f"readTextPasswordFromTextFile(OM_PLAIN): Error processing line {file_line}: " + str(e))
                    the_hash.update(''.encode('utf-8'))
        
                rec = password_record(the_word, the_hash.hexdigest().upper(), l_cli_password_file, file_line, False )
  
                result.append(rec)
            else:
                debugLog("readTextPasswordFromTextFile(OM_PLAIN):Skipping empty line")
    else:
        debugLog("readTextPasswordFromTextFile - Reading in Sha1 mode (i.e. expecting sha1 digests of passwords)")
        for the_line in lines:
            the_hash: str=the_line.strip()
            file_line=file_line+1
            if the_hash != "":
                rec = password_record("unknown", the_hash, l_cli_password_file, file_line, False )
                result.append(rec)
            else:
                debugLog("readTextPasswordFromTextFile(OM_HASH):Skipping empty line")

    return result

def writeListOfRecords(l_outputfilename, l_list_of_records):
    for new_current_record in l_list_of_records:
        writeOneRecord(l_outputfilename, new_current_record)
    return

def writeOneRecord(l_outputfilename, l_myrecord):
    writeOnePassword(l_outputfilename, l_myrecord.found_filename, l_myrecord.src_password, l_myrecord.src_hash, l_myrecord.found_linenumber, l_myrecord.ispwned   )
    return


def writeOnePassword(l_outputfilename, found_filename, src_password, src_hash, found_linenumber, i_ispwned ):
    debugLog("writeOnePassword("+ l_outputfilename + ", " + found_filename + "," + src_password + ", " + src_hash + ", " + str(found_linenumber) + "," + str(i_ispwned)+ ")")

    if (l_outputfilename != ""):
        line_output=found_filename + ", " + str(found_linenumber) + "," + src_password + ", " + src_hash  + "," + str(i_ispwned) + "\n"
        l_outfile = open(l_outputfilename, 'a', encoding='utf-8', newline='\n')
        
        l_outfile.writelines(line_output)
        l_outfile.close()
    else:
        debugLog("writeOnePassword: No filename provided.")

    return

# press any key to continue function
def pressAnyKey(theprompt="Press any key to continue...", failChars='qQ'):
    '''
    Displays a prompt to the user, then waits for the user to press a key.
    Accepts a string for prompt, and a string containing all characters for which it should return False.
    Returns False if the char pressed was in the failChars string, True otherwise.
    Exit on Ctrl + C'''
    exit_char_pressed=False
    from msvcrt import getch, kbhit
    print(theprompt)
    ch = getch()
    while kbhit():
        getch()
    if ch == '\x03':
        os._exit(1)
    else:
        exit_char_pressed = (str(ch) in failChars)
    return exit_char_pressed

def showHelpShort():
    print("-----------------------------------------------------------------------------------------------------------------------")
    print("Sample usage:")
    print("pwned -p password123 -l sha1_pwned_pwd_file.txt")
    print("pwned -p B0399D2029F64D445BD131FFAA399A42D2F8E7DC -s -o thisiswhativefound.txt")
    print("pwned -f file_with_passwords.txt -o thisiswhativefound.txt")
    print("pwned -f file_with_passwords_insha1_format.txt -s -o thisiswhativefound.txt")
    print("pwned --help")

def showHelp():
    print("Usage: pwned [-p password_to_check]|[-f pwds_filename]|[-t text_filename] [-s] [-l sha1_pwned_pwd_file] -d secs| [-h]")
    print("       pwned [--password password_to_check]|[-password_file pwds_filename]|[-text_file text_filename] [--sha1_format] [--local_sha1_db sha1_pwned_pwd_file] --delay secs | [--help]")
    print("-----------------------------------------------------------------------------------------------------------------------")    
    print("\nCheck a password or a list of password against a DB of breaches maintained at https://haveibeenpwned.com/Passwords")
    print("By default uses api at: " + BASE_PWD_SEARCH_URL)
    print("Using the -l parameter you can check a local file downloadable from the site above")
    print("No clear passwords are transmitted on the network.")
    print("Each pasword is hashed with SHA1 hash function and 5 chars of the hash hex representaion are used to query the remote db")
    #pressAnyKey()
    print(" -p password_to_check (--password)      - password to check")
    print(" -f pwds_filename     (--password_file) - read a text file containing a list of 1 passwords per line (ending in \\n)") 
    print("                                          Each line must contain a plain text password or a SHA1 hash (if -s is used")
    print(" -t text_filename     (--text_file)     - read a text file continaing words. The idea is to implement a pwd parser...") 
    print("                                          -t is NOT YET IMPLEMENTED, same as -f option so far") 
    print(" -s                   (--sha1_format)   - inputs (from command line or files) is expected to be a SHA1 hex string")
    print("                                         lines beginning with # are skipped  - NOT IMPLEMENTED YET") 
    print("                                         lines containing *** # are skipped  - NOT IMPLEMENTED YET")
    print("                                         lines containing ___ # are skipped  - NOT IMPLEMENTED YET")
    print("                                         lines containing http # are skipped - NOT IMPLEMENTED YET")
    print(" -l sha1_filename     (--local_sha1_db )- A local text file containing the list of SHA1 hex string passwords")
    print("                                          Tested with the list of SHA1 passwords obtained from:")
    print("                                          https://haveibeenpwned.com/Passwords")
    print(" -z zip_filename      (--zipped)        - if the text file defined with -l is contained in the zip_filename")
    print(" -w secs_number       (--wait)          - when using the web server (i.e. if -l NOT used) requests are delayed waiting secs_number between requests")
    print("                                          (throtthled) by secs_number seconds. Ignored with -l")
    print(" -h                   (--help)          - print this message... override all other parameters")
    print(" -o out_filename      (--output_file )  - Write all passwords and the search result in the file named out_filename.")
    print("                                          If -s is used no passwords will be in the file")
    print(" -b                   (--binary_search) - The file containing password hashes (if -l is used) sorted alphabetically. Cannot be used with -z")
    print(" -d                   (--debug)         - Start in debug mode (lot of logs)")
    print("-----------------------------------------------------------------------------------------------------------------------")
    print("Output file (if used) is a csv file containing:")
    print("       source_file_name, line_number_in_src_file, plain_text_pwd_if_available, Sha1-version_of_the_pwd, True|False")
    print("-----------------------------------------------------------------------------------------------------------------------")

    showHelpShort()
    return


def hashMeThis(l_password):
    the_hashed_pwd = hashlib.sha1()
    the_hashed_pwd.update(str(l_password).strip().encode('utf-8'))
    the_hashed_pwd_string = the_hashed_pwd.hexdigest().upper()
    return the_hashed_pwd_string

def checkSinglePassword(l_password, l_current_input_mode, l_current_db_mode, l_cli_local_db_file, l_cli_local_zip, l_cli_output_file):

    debugLog("checkSinglePassword(" + l_password + "," + str(l_current_input_mode) + "," + str(l_current_db_mode) + "," + l_cli_local_db_file + "," + l_cli_local_zip + "," + l_cli_output_file + ")")

    password_in_text_format = ""
    password_in_hash_format = ""

    if (l_current_input_mode == OM_HASH):
        password_in_text_format = "no_pwd"
        password_in_hash_format = l_password
        if len(password_in_hash_format) != 40:
            print(password_in_hash_format + " does NOT look as a SHA1 format...proceding as it was plaintext instead...")
            
            password_in_text_format = l_password
            password_in_hash_format = hashMeThis(l_password)
    else:
        password_in_text_format = l_password
        password_in_hash_format = hashMeThis(l_password)
    
    is_pwned = False
    if (l_current_db_mode == DB_WEB):
        is_pwned=isHashPwnedRemoteWithPwd(password_in_hash_format, l_password)
    elif (l_current_db_mode == DB_LOCAL_ZIP):
        is_pwned=isHashPwnedLocalZip(password_in_hash_format, l_cli_local_db_file, l_cli_local_zip)
    elif (l_current_db_mode == DB_LOCAL_SORTED):
        is_pwned=isHashPwnedLocalBinary(password_in_hash_format, l_cli_local_db_file)
    else:
        is_pwned=isHashPwnedLocal(password_in_hash_format, l_cli_local_db_file)
    
    writeOnePassword(l_cli_output_file, "cli", password_in_text_format, password_in_hash_format, 0, is_pwned )
   
    return

def checkPlainPasswordFile(l_cli_password_file, l_current_db_mode, l_cli_local_db_file, l_cli_output_file, l_inputmode=OM_PLAIN, l_delay_secs=0):
    debugLog("checkPlainPasswordFile(" + l_cli_password_file + "," + str(l_current_db_mode) + "," +l_cli_local_db_file + "," + l_cli_output_file +","+ str(l_inputmode) + "," + str(l_delay_secs)+")")

    loc_stats = pstat.PwnedStats()
    
    list_to_check = []  
    list_to_check = readTextPasswordFromTextFile(l_cli_password_file, l_inputmode)
    loc_stats.number_of_password_read = len(list_to_check)
    if (l_current_db_mode == DB_WEB):
        for current in list_to_check:
            current.ispwned=isHashPwnedRemoteWithPwd(current.src_hash, current.src_password)
            writeOneRecord(l_cli_output_file, current)
            time.sleep(l_delay_secs)
            debugLog("Throttling requests by secs:" + str(l_delay_secs))
    elif (l_current_db_mode == DB_LOCAL_SORTED):
        isHashListPwnedLocalBinary(list_to_check, l_cli_local_db_file, l_cli_output_file, OM_PLAIN)
    else:
        #isHashListPwnedLocalMT(list_to_check, l_cli_local_db_file, l_cli_output_file, OM_PLAIN)
        #below  is the working version...
        isHashListPwnedLocal(list_to_check, l_cli_local_db_file, l_cli_output_file, OM_PLAIN)
    return 

def checkTextFile(l_word_list, l_current_db_mode, l_cli_local_db_file, l_cli_output_file, l_delay_secs):
    debugLog("checkTextFile(l_word_list, " + str(l_current_db_mode) + "," + l_cli_local_db_file + "," + l_cli_output_file + ")")
    
    list_to_check = l_word_list
    loc_stats = pstat.PwnedStats()
    loc_stats.number_of_password_read = len(list_to_check)
    if (l_current_db_mode == DB_WEB):
        for current in list_to_check:
            current.ispwned=isHashPwnedRemoteWithPwd(current.src_hash, current.src_password)
            writeOneRecord(l_cli_output_file, current)
            time.sleep(l_delay_secs)
            debugLog("Throttling requests by secs:" + str(l_delay_secs))
    elif (l_current_db_mode == DB_LOCAL_SORTED):
        isHashListPwnedLocalBinary(list_to_check, l_cli_local_db_file, l_cli_output_file, OM_PLAIN)
    else:
        isHashListPwnedLocal(list_to_check, l_cli_local_db_file, l_cli_output_file, OM_PLAIN)
    return 

#added on 2021/12/27 to read from a zipped file....
def isHashPwnedLocalZip(l_hash, l_local_db_file, l_local_zip_file):
    debugLog("isHashPwnedLocalZip(" + l_hash + "," + l_local_db_file + ", " + l_local_zip_file + ")")
    result= False
    line_number=0
    loc_stats = pstat.PwnedStats()

    with zipfile.ZipFile(l_local_zip_file) as z:
        #surround with try catch
        try:
            with z.open(l_local_db_file) as f:
                debugLog("isHashPwnedLocalZip-zip file is now open...:" + l_local_zip_file + ")")
                for the_line in f:
                    line_number = line_number + 1
                    if (l_hash.encode() in the_line):
                        loc_stats.number_of_password_read = 1
                        loc_stats.pwned_passwords_found   = 1
                        loc_stats.safe_passwords_found    = loc_stats.number_of_password_read - loc_stats.pwned_passwords_found 
                        loc_stats.scanned_lines_in_db     = line_number 
                        result=True
                        print(l_hash + " FOUND on line " + str(line_number) + " of file " + l_local_db_file)
                        debugLog("isHashPwnedLocalZip result=" + str(result))
                        return result
                    if (line_number % 100000) == 0:
                        #last_digit = (last_digit+1) % 10
                        #print(str(last_digit), end='', flush= True)
                        print("Scanned lines:", "{:,}".format(line_number), end="\r") 
        except Exception as e:  
            # Code to handle the exception  
            debugLog("isHashPwnedLocalZip: Exception: " + str(e))
            print("\nERROR: " + l_local_db_file + " file NOT FOUND inside " + l_local_zip_file + ". Exiting...") 
    
    loc_stats.number_of_password_read = 1
    loc_stats.pwned_passwords_found   = 0
    loc_stats.safe_passwords_found    = loc_stats.number_of_password_read - loc_stats.pwned_passwords_found
    loc_stats.scanned_lines_in_db     = line_number                 
    return result


def isHashPwnedLocal(l_hash, l_local_db_file):
    debugLog("isHashPwnedLocal(" + l_hash + "," + l_local_db_file + ")")
    
    result= False
    line_number=0
    loc_stats = pstat.PwnedStats()

    with open(l_local_db_file, 'r', encoding='utf-8') as read_obj:
        for the_line in read_obj:
            line_number = line_number + 1
            if (l_hash in the_line):
                loc_stats.number_of_password_read = 1
                loc_stats.pwned_passwords_found   = 1
                loc_stats.safe_passwords_found    = loc_stats.number_of_password_read - loc_stats.pwned_passwords_found
                loc_stats.scanned_lines_in_db     = line_number 
                result=True
                print("")
                print(l_hash + " FOUND on line " + str(line_number) + " of file " + l_local_db_file)
                return result

            if (line_number % 100000) == 0:
                #last_digit = (last_digit+1) % 10
                #print(str(last_digit), end='', flush= True)
                print("Scanned lines:", "{:,}".format(line_number), end="\r") 
                
    loc_stats.number_of_password_read = 1
    loc_stats.pwned_passwords_found   = 0
    loc_stats.safe_passwords_found    = loc_stats.number_of_password_read - loc_stats.pwned_passwords_found
    loc_stats.scanned_lines_in_db     = line_number                 
    return result

#write a function like isHashPwnedLocal but using binary search in the l_local_db_file
def isHashPwnedLocalBinary(l_hash, l_local_db_file):
    debugLog("isHashPwnedLocalBinary(" + l_hash + "," + l_local_db_file + ")")
    loc_stats = pstat.PwnedStats()

    #binary search of l_hash in l_local_db_file
    
    loc_stats.scanned_lines_in_db = 0
    mid = 0
    with open(l_local_db_file, 'r', encoding='utf-8') as f:
        left = 0
        right = f.seek(0, 2) # Seek to end of file
        while left <= right:
            loc_stats.scanned_lines_in_db = loc_stats.scanned_lines_in_db + 1
            #print(str(g_scanned_lines_in_db), end='', flush= True)
            print("Lines scanned:", loc_stats.scanned_lines_in_db, end="\r") 
            mid = (left + right) // 2
            f.seek(mid)
            f.readline() # Discard the partial line
            line = f.readline().strip()
            if line.startswith(l_hash):
                loc_stats.number_of_password_read = 1
                loc_stats.pwned_passwords_found   = 1
                loc_stats.safe_passwords_found    = 0
                return True
            elif line < l_hash:
                left = mid + 1
            else:
                right = mid - len(line) - 1

    loc_stats.number_of_password_read = 1
    loc_stats.pwned_passwords_found   = 0
    loc_stats.safe_passwords_found    = 1
    loc_stats.scanned_lines_in_db     = mid                 
    return False 
  

#isHashListPwnedLocalBinary(list_records, l_local_db_file, l_outputfilename, l_input_mode)
def isHashListPwnedLocalBinary(list_records, l_local_db_file, l_outputfilename, l_input_mode):
    debugLog("isHashListPwnedLocalBinary(" + "list_records" + "," + l_local_db_file + "," + l_outputfilename + "," + str(l_input_mode) + ")")
    result= False #True if at least one password is found
    line_number=0
    local_result = False
    total_records = len(list_records)
    true_records  = 0

    loc_stats = pstat.PwnedStats()    

    loc_stats.number_of_password_read = 0
    #for all objects in list_records call isHashPwnedLocalBinary
    for current_record in list_records:
        loc_stats.number_of_password_read = loc_stats.number_of_password_read +1
        local_result = isHashPwnedLocalBinary(current_record.src_hash, l_local_db_file)
        result = result or local_result
        if (local_result):
            true_records = true_records + 1

            current_record.ispwned=True
            result=result or True
            print("\n" + current_record.found_filename + "(" + str(current_record.found_linenumber) + ") -" +
            current_record.src_password + " -" + current_record.src_hash + " FOUND on line " + str(line_number) +
            " of file " + l_local_db_file + " - " + str(total_records-true_records) + " pwds to check...")
        else:
            loc_stats.safe_passwords_found = loc_stats.safe_passwords_found + 1
            current_record.ispwned=False

    loc_stats.number_of_password_read = total_records
    loc_stats.pwned_passwords_found   = true_records
    loc_stats.safe_passwords_found    = loc_stats.number_of_password_read - loc_stats.pwned_passwords_found
    loc_stats.scanned_lines_in_db     = line_number
    writeListOfRecords(l_outputfilename, list_records)
    return result


def isHashListPwnedLocal(list_records, l_local_db_file, l_outputfilename, l_input_mode):
    debugLog("isHashListPwnedLocal(" + "list_records" + "," + l_local_db_file + "," + l_outputfilename + "," + str(l_input_mode) + ")")
    result= False #True if at least one password is found
    line_number=0
    
    total_records = len(list_records)
    true_records  = 0
    loc_stats = pstat.PwnedStats()    

    with open(l_local_db_file, 'r', encoding='utf-8') as read_obj:
        for the_line in read_obj:
            line_number = line_number + 1
            for current_record in list_records:
                if (true_records < total_records):
                    if current_record.ispwned is False:
                        if (current_record.src_hash in the_line):
                            result=result or True
                            true_records = true_records + 1
                            current_record.ispwned = True
                            print("\n" + current_record.found_filename + "(" + str(current_record.found_linenumber) + ") -" +
                                current_record.src_password + " -" + current_record.src_hash + " FOUND on line " + str(line_number) +
                                " of file " + l_local_db_file + " - " + str(total_records-true_records) + " pwds to check...")
                else:
                    debugLog("isHashListPwnedLocal: exit and return... no more passwords to check. Total scanned lines: " + str(line_number))
                    writeListOfRecords(l_outputfilename, list_records)
                    loc_stats.number_of_password_read = total_records
                    loc_stats.pwned_passwords_found   = true_records
                    loc_stats.safe_passwords_found    = loc_stats.number_of_password_read - loc_stats.pwned_passwords_found
                    loc_stats.scanned_lines_in_db     = line_number #if local db option used
                    return
            if (line_number % 100000) == 0:
                #last_digit = (last_digit+1) % 10
                #print(str(last_digit), end='', flush= True)
                print("Scanned lines:", "{:,}".format(line_number), end="\r") 
        print("isHashListPwnedLocal - All passwords checked. Total scanned lines: " + str(line_number))
    writeListOfRecords(l_outputfilename, list_records)
    loc_stats.number_of_password_read = total_records
    loc_stats.pwned_passwords_found   = true_records
    loc_stats.safe_passwords_found    = loc_stats.number_of_password_read - loc_stats.pwned_passwords_found
    loc_stats.scanned_lines_in_db     = line_number #if local db option used
    return result

def checkListAgainstLineMT(list_records, l_line, thread_name):
    debugLog("checkListAgainstLineMT(" + "list_records" + "," + l_line+ "," + thread_name)
    number_of_true_records_found = 0

    for current_record in list_records:
        if current_record.ispwned is False:
            if (current_record.src_hash in l_line):
                #result=result or True
                number_of_true_records_found = number_of_true_records_found + 1
                current_record.ispwned = True
                print("\n" + thread_name + ": " + current_record.found_filename + "(" + str(current_record.found_linenumber) + ") -"
                    + current_record.src_password + " -" + current_record.src_hash + " FOUND")
    
    return number_of_true_records_found

#Same as before but multi-threaded
def isHashListPwnedLocalMT(list_records, l_local_db_file, l_outputfilename, l_input_mode):
    debugLog("isHashListPwnedLocalMT(" + "list_records" + "," + l_local_db_file + "," + l_outputfilename + "," + str(l_input_mode) + ")")
    result= False #True if at least one password is found
    line_number=0
    
    total_records = len(list_records)
    true_records  = 0
    list_of_threads = []
    loc_stats = pstat.PwnedStats()    

    with open(l_local_db_file, 'r', encoding='utf-8') as read_obj:
        for the_line in read_obj:
            line_number = line_number + 1
            #here I would like to spin a thread and move on...
            t = threading.Thread(target=checkListAgainstLineMT, args=(list_records, the_line, str(line_number)))
            t.start()
            list_of_threads.append(t)

            if (line_number % 100000) == 0:
                #last_digit = (last_digit+1) % 10
                #print(str(last_digit), end='', flush= True)
                print("Scanned lines:", "{:,}".format(line_number), end="\r") 

        for ttt in list_of_threads:
            ttt.join()

        print("isHashListPwnedLocalMT - All passwords checked. Total scanned lines: " + str(line_number))
    
    writeListOfRecords(l_outputfilename, list_records)
    loc_stats.number_of_password_read = total_records
    loc_stats.pwned_passwords_found   = true_records
    loc_stats.safe_passwords_found    = loc_stats.number_of_password_read - loc_stats.pwned_passwords_found
    loc_stats.scanned_lines_in_db     = line_number #if local db option used
    return result

def isHashPwnedRemote(l_hash):
    return isHashPwnedRemoteWithPwd(l_hash, "test_pwd") 

def isHashPwnedRemoteWithPwd(l_hash, l_password):
    debugLog("isHashPwnedRemote(" + l_hash + ")")
    result = False
    the_hashed_prefix = l_hash[0:(HASH_PREFIX_LENGHT)]
    the_hashed_suffix = l_hash[HASH_PREFIX_LENGHT:len(l_hash)]
    loc_stats = pstat.PwnedStats()

    final_url = BASE_PWD_SEARCH_URL + the_hashed_prefix

    #WARNING_ verify=false added only on this local copy to avoid checking ssl certificate
    response = requests.get(final_url, timeout=10, verify=loc_stats.SSL_CHECK)

    if response.status_code == 200:
        print('Web service returned success status 200')
        #debugLog(response.text + "\n")
        if (the_hashed_suffix in response.text):
            print(l_password + " (Hash = " + l_hash + ") FOUND! This password is PWNED")
            result = True
            loc_stats.pwned_passwords_found    = loc_stats.pwned_passwords_found + 1
        else:
            print(l_password + " (Hash = " + l_hash + ") NOT FOUND! This password is SAFE")
            result = False
            loc_stats.safe_passwords_found    = loc_stats.safe_passwords_found + 1 
    elif response.status_code == 404:
        print('ERROR 404 - Page not Found.')
        loc_stats.safe_passwords_invalid = loc_stats.safe_passwords_invalid+1
    elif response.status_code == 429:
        print('ERROR 429 - rate limit exceeded. No Retry')
        loc_stats.safe_passwords_invalid = loc_stats.safe_passwords_invalid+1
    elif response.status_code == 400:
        print('ERROR 400 - The hash prefix was not valid hexadecimal')
        loc_stats.safe_passwords_invalid = loc_stats.safe_passwords_invalid+1
    else:
        print('ERROR Unknown: ' + str(response.status_code) + ' ' + response.text)
    
    return result



def isPasswordPwned(password_to_check):
    result = False
    the_hashed_pwd = hashlib.sha1()
    the_hashed_pwd.update(str(password_to_check).strip().encode('utf-8'))
    the_hashed_pwd_string = the_hashed_pwd.hexdigest().upper()

    the_hashed_prefix = the_hashed_pwd_string[0:(HASH_PREFIX_LENGHT)]
    the_hashed_suffix = the_hashed_pwd_string[HASH_PREFIX_LENGHT:len(the_hashed_pwd_string)]

    final_url: str = BASE_PWD_SEARCH_URL + the_hashed_prefix

    response: requests.Response = requests.get(final_url, timeout=5)
        
    if response.status_code == 200:
        print('You got the success!')
        print(response.text)
        if (the_hashed_suffix in response.text):
            print("Password ***" + password_to_check + "*** with hash " + the_hashed_pwd_string + " FOUND! Is PWNED")
            result = True
    elif response.status_code == 404:
        print('Page not Found.')
    elif response.status_code == 404:
        print('Rate limit exceeded.')
    else:
        #print('Unknown Error: ' + str(response.status_code) + ' ' + response.message)
        print('Unknown Error: ' + str(response.status_code) + ' ' + response.reason)
    
    return result


#*********************************************
#          MAIN is HERE
#*********************************************
g_start_time:float = my_stats.start_time
debugLog(str(g_start_time) + 'This program is now in DEBUG mode. To change put DEBUG_MODE = False at the beginning of the file.')
print("PWNED - ver. " + my_stats.PROGRAM_VERSION + " from A.R. is starting...")
debugLog("WARNING - SSL Check is now " + str(my_stats.SSL_CHECK) + ". To change update value on SSL_CHECK variable")

#Global operation modes and variables - by default the WEB service is used and input assumed in PLAIN TEXT mode
current_operation_mode  = IM_UNKNOWN_MODE
cli_password       = ""
cli_password_file  = ""
cli_text_file      = ""

cli_input_mode = OM_PLAIN

cli_db_mode    = DB_WEB
cli_local_db_file  = ""
cli_local_zip      = ""

cli_output_file    = ""
cli_delay_secs     = 0
# Remove 1st argument from the list of command line arguments
argumentList = sys.argv[1:]
# Options
options = "p:f:t:l:o:w:z:sbdh"
# Long options
long_options = ["password", "password_file", "text_file", "local_sha1_file", "output_file", "delay", "sha1_format","zipped", "binary_search", "debug", "help"]

try:
    debugLog("Parsing command line arguments....\n" + str(argumentList))
    # Parsing argument
    arguments, values = getopt.getopt(argumentList, options, long_options)
    local_hashfile_name_found = False
    # checking each argument
    for currentArgument, currentValue in arguments:
        if currentArgument in ("-p", "--password"):   
            debugLog("-p " + currentValue + " found")
            if current_operation_mode == IM_TEXT_FILE:
                debugLog("-p " + currentValue + " found - Ignoring due to -t parameter found first....")
                alwaysLog("WARNING: -p parameter found after -t parameter. Ignoring -p parameter....")
            elif current_operation_mode == IM_PASSWORD_FILE:
                debugLog("-p " + currentValue + " found - Ignoring due to -f parameter found first....")
                alwaysLog("WARNING: -p parameter found after -f parameter. Ignoring -p parameter....")
            else:
                cli_password   = currentValue.strip()
                current_operation_mode = IM_SINGLE_PASSOWRD
                if cli_password == "":
                    alwaysLog("WARNING: -p parameter found but NO password provided...Exiting")
                    os._exit(ERR_WRONG_PARAMETERS)

        elif currentArgument in ("-f", "--password_file"):
            debugLog("-f " + currentValue + " found")
            if current_operation_mode == IM_SINGLE_PASSOWRD:
                debugLog("-f " + currentValue + " found - Ignoring due to -p parameter found first....")
                alwaysLog("WARNING: -f parameter found after -p parameter. Ignoring -f parameter....")
            elif current_operation_mode == IM_PASSWORD_FILE:
                debugLog("-f " + currentValue + " found - Ignoring due to -t parameter found first....")
                alwaysLog("WARNING: -f parameter found after -t parameter. Ignoring -f parameter....")
            else:
                cli_password           = ""
                current_operation_mode = IM_PASSWORD_FILE
                cli_password_file      = currentValue.strip()
                if (not os.path.isfile(cli_password_file)):
                    alwaysLog("ERROR: -f " + cli_password_file + " not found. Exiting...")
                    os._exit(ERR_WRONG_PARAMETERS)

        elif currentArgument in ("-t", "--text_file"):
            debugLog("-t " + currentValue + " found")
            if current_operation_mode == IM_SINGLE_PASSOWRD:
                debugLog("-t " + currentValue + " found - Ignoring due to -p parameter found first....")
                alwaysLog("WARNING: -t parameter found after -p parameter. Ignoring -t parameter....")
            elif current_operation_mode == IM_PASSWORD_FILE:
                debugLog("-t " + currentValue + " found - Ignoring due to -f parameter found first....")
                alwaysLog("WARNING: -t parameter found after -f parameter. Ignoring -t parameter....")
            else:
                cli_password           = ""
                current_operation_mode = IM_TEXT_FILE  
                cli_text_file          = currentValue.strip()
                if (not os.path.isfile(cli_text_file)):
                    alwaysLog("ERROR: -t " + cli_text_file + " not found. Exiting...")
                    os._exit(ERR_WRONG_PARAMETERS)

        elif currentArgument in ("-s", "--sha1_format"):
            debugLog("-s found... assuming everyhing in SHA1 mode from now on...")
            cli_input_mode = OM_HASH

        elif currentArgument in ("-w", "--wait"):
            debugLog("-w secs_number found... each web request will be throttled by " + str(currentValue) + "seconds")
            cli_delay_secs = int(currentValue.strip())
             
        elif currentArgument in ("-l", "--local_sha1_file"):
            debugLog("-l " + currentValue + " found")
            if (cli_db_mode != DB_LOCAL_ZIP) and (cli_db_mode != DB_LOCAL_SORTED):
                cli_db_mode    = DB_LOCAL
            cli_local_db_file  = currentValue.strip()
            if cli_local_db_file:
                local_hashfile_name_found = True


        elif currentArgument in ("-z", "--zipped"):
            debugLog("-z " + currentValue + " found. Using zipped file")
            cli_local_zip  = currentValue.strip()
            if (cli_db_mode != DB_LOCAL_SORTED):
                cli_db_mode  = DB_LOCAL_ZIP
            else:
                debugLog("-z " + cli_local_zip + " found - Ignoring due to -b parameter found first....")
                alwaysLog("WARNING: -z parameter found after -b parameter. Ignoring -z...")
                
        elif currentArgument in ("-b", "--binary_search"):
            debugLog("-b " + currentValue + " found. Using binary search")
            if (cli_db_mode != DB_LOCAL_ZIP):
                cli_db_mode  = DB_LOCAL_SORTED
            else:
                debugLog("-b " + currentValue + " found - Ignoring due to -z parameter found first....")
                alwaysLog("WARNING: -b parameter found after -z parameter. Ignoring -b...")
            
        elif currentArgument in ("-o", "--output_file"):
            debugLog("-o " + currentValue + " found")
            cli_output_file  = currentValue.strip()
            if cli_output_file != "": #erase the file if it exists
                outfile = open(cli_output_file, 'w', encoding='utf-8', newline='\n')
                outfile.close()

        elif currentArgument in ("-d", "--debug"):
            DEBUG_MODE = True
            debugLog("-d " + currentValue + " found. continuing in DEBUG MODE")

        elif currentArgument in ("-h", "--help"):
            showHelp()
            alwaysLog("-h or --help found - Ignoring other parameters...")
            print("PWNED - ver. " + my_stats.PROGRAM_VERSION + " from A.R.")
            os._exit(ERR_NO_ERROR)
        
        else:
            print("Unknow parameter")
            showHelp()
            print("PWNED - ver. " + my_stats.PROGRAM_VERSION + " from A.R.")
            os._exit(ERR_WRONG_PARAMETERS)
        debugLog("cli_input_mode="+ str(cli_input_mode) + " - cli_db_mode=" + str(cli_db_mode) + " - current_operation_mode=" + str(current_operation_mode))

except getopt.error as err:
    # output error, and return with an error code
    print("Argument parsing error: " + str(err))
    #showHelp()
    print("PWNED - ver. " + my_stats.PROGRAM_VERSION + " from A.R.")
    os._exit(ERR_WRONG_PARAMETERS)

#anykey("Press 'q' or Ctrl-C to quit or anything else to continue....")

#all local db options require a filename to be specified. check if cli_local_db_file is not empty and existing
if (cli_db_mode == DB_LOCAL) or (cli_db_mode == DB_LOCAL_SORTED):
    if (cli_local_db_file == ""):
        alwaysLog("ERROR: -l parameter not found or local_password_file name not provided. Exiting...")
        os._exit(ERR_WRONG_PARAMETERS)
    elif (not os.path.isfile(cli_local_db_file)):
        alwaysLog("ERROR: " + cli_local_db_file + " not found. Exiting...")
        os._exit(ERR_WRONG_PARAMETERS)

#if -z provided then check if cli_local_zip is not empty and existig
if (cli_db_mode == DB_LOCAL_ZIP):
    if (cli_local_zip == ""):
        alwaysLog("ERROR: -z parameter provided but with no zip file name. Exiting...")
        os._exit(ERR_WRONG_PARAMETERS)
    elif (not os.path.isfile(cli_local_zip)):
        alwaysLog("ERROR: " + cli_local_zip + " not found. Exiting...")
        os._exit(ERR_WRONG_PARAMETERS)  


#here we really start....

if current_operation_mode == IM_SINGLE_PASSOWRD:
    # We are in single password mode
    assert not cli_password==""
    print("Searching for a single password...: " + cli_password)
    my_stats.number_of_password_read = 1
    checkSinglePassword(cli_password, cli_input_mode, cli_db_mode, cli_local_db_file, cli_local_zip, cli_output_file)
    printStats()

elif current_operation_mode == IM_PASSWORD_FILE:
    assert cli_password_file!=""
    if (not os.path.isfile(cli_text_file)):
        alwaysLog("ERROR: -l " + cli_local_db_file + " not found. Exiting...")
        os._exit(ERR_WRONG_PARAMETERS)

    print("Searching for password file: " + cli_password_file)
    checkPlainPasswordFile(cli_password_file, cli_db_mode, cli_local_db_file, cli_output_file, cli_input_mode, cli_delay_secs)
    printStats()

elif current_operation_mode == IM_TEXT_FILE: 
    assert cli_text_file!=""
    if (not os.path.isfile(cli_local_db_file)):
        alwaysLog("ERROR: -l " + cli_local_db_file + " not found. Exiting...")
        os._exit(ERR_WRONG_PARAMETERS)

    print("Searching for text file: " + cli_text_file)
    word_to_check_list=getPasswordList(cli_text_file)
    checkTextFile(word_to_check_list, cli_db_mode, cli_local_db_file, cli_output_file, cli_delay_secs)
    printStats()
else:
    print("UNKNOWN operation mode. this should NEVER happen. Need one of -p -f -t parameters. Use -h or --help to see usage")
    print("current arguments: "+ str(argumentList))
    printStats()
    showHelpShort()
    os._exit(ERR_OPMODE_UNKNOWN)

if cli_output_file != "":
    print("Passwords and status are recorded to: " + cli_output_file)
    print("Remember to REMOVE THIS FILE!!!!!!!! it MAY contains your passwords.... ")
else:
    debugLog("Password not recorded. To record use the cli option: -o outputfilename")
os._exit(ERR_NO_ERROR)

