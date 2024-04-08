set LOG_FILE=pwnedtest.log
echo Running pwned.py tests...
echo ******************* Single password tests... ******************************************
echo FROM THE WEB **************************************************************************
python pwned.py -p password123
PAUSE
echo FROM THE WEB with empty password ------------------------------------------------------ 
python pwned.py -p ""
PAUSE
echo FROM THE WEB with NO password    ------------------------------------------------------
python pwned.py -p
PAUSE
echo FROM LOCAL FILE                  ------------------------------------------------------
python pwned.py -p password123 -l pwned-passwords-sha1-top100kSORTED.txt 
PAUSE
echo FROM LOCAL FILE with empty filename ---------------------------------------------------
python pwned.py -p password123 -l ""
PAUSE
echo FROM LOCAL FILE with no filename ------------------------------------------------------
python pwned.py -p password123 -l 
PAUSE
echo FROM LOCAL FILE with non existing filename --------------------------------------------
python pwned.py -p password123 -l "44gattiinfilaper3.txt"
PAUSE
echo FROM LOCAL FILE inside a zip file -----------------------------------------------------
python pwned.py -p password123 -l pwned-passwords-sha1-top100kSORTED.txt -z pwned-passwords-sha1-top100kSORTED.zip
PAUSE
echo FROM LOCAL FILE inside a zip file with empty zip filename -----------------------------
python pwned.py -p password123 -l pwned-passwords-sha1-top100kSORTED.txt -z ""
PAUSE
echo FROM LOCAL FILE inside a zip file with no filename ------------------------------------
python pwned.py -p password123 -l pwned-passwords-sha1-top100kSORTED.txt -z 
PAUSE
echo FROM LOCAL FILE inside a zip file with non existing ZIP -------------------------------
python pwned.py -p password123 -l pwned-passwords-sha1-top100kSORTED.txt -z 44gattiinfilaper3.txt
PAUSE
echo FROM LOCAL FILE inside a zip file with local file NOT inside the zip ------------------
python pwned.py -p password123 -l 44gattiinfilaper3.txt -z pwned-passwords-sha1-top100kSORTED.zip
PAUSE
echo FROM LOCAL FILE inside a zip file with -b option -------------------------------------- 
python pwned.py -p password123 -l pwned-passwords-sha1-top100kSORTED.txt -z pwned-passwords-sha1-top100kSORTED.zip -b
PAUSE

echo ******************* passwords from text file ******************************************
echo FROM THE WEB WITH LOCAL PASSWORD FILE PROVIDED ----------------------------------------
python pwned.py -t test.plainpasswords.txt
PAUSE
echo FROM THE WEB with empty password file -------------------------------------------------
python pwned.py -t "test.emptyfile.txt"
PAUSE
echo FROM THE WEB with NO existing password file password ----------------------------------
python pwned.py -t 44gattiinfilaper3.txt
PAUSE
echo FROM LOCAL FILE ------------------------------------------------------------------------
python pwned.py -t test.plainpasswords.txt -l pwned-passwords-sha1-top100kSORTED.txt 
PAUSE
echo FROM LOCAL FILE with empty filename -------------------------------------------------
python pwned.py -t test.plainpasswords.txt -l ""
PAUSE
echo FROM LOCAL FILE with no filename -------------------------------------------------
python pwned.py -t test.plainpasswords.txt -l 
PAUSE
echo FROM LOCAL FILE with non existing filename -------------------------------------------------
python pwned.py -t test.plainpasswords.txt -l "44gattiinfilaper3.txt"
PAUSE
echo FROM LOCAL FILE inside a zip file -------------------------------------------------
python pwned.py -t test.plainpasswords.txt -l pwned-passwords-sha1-top100kSORTED.txt -z pwned-passwords-sha1-top100kSORTED.zip
PAUSE
echo FROM LOCAL FILE inside a zip file with empty zip filename -------------------------------------------------
python pwned.py -t test.plainpasswords.txt -l pwned-passwords-sha1-top100kSORTED.txt -z ""
PAUSE
echo FROM LOCAL FILE inside a zip file with no filename -------------------------------------------------
python pwned.py -t test.plainpasswords.txt -l pwned-passwords-sha1-top100kSORTED.txt -z 
PAUSE
echo FROM LOCAL FILE inside a zip file with non existing ZIP -------------------------------------------------
python pwned.py -t test.plainpasswords.txt -l pwned-passwords-sha1-top100kSORTED.txt -z 44gattiinfilaper3.txt
PAUSE
echo FROM LOCAL FILE inside a zip file with local file NOT inside the zip -------------------------------------------------
python pwned.py -f test.plainpasswords.txt -l 44gattiinfilaper3.txt -z pwned-passwords-sha1-top100kSORTED.zip
PAUSE
echo FROM LOCAL FILE inside a zip file with local file NOT inside the zip -------------------------------------------------
python pwned.py -t test.plainpasswords.txt -l 44gattiinfilaper3.txt -z pwned-passwords-sha1-top100kSORTED.zip
PAUSE
echo FROM LOCAL FILE inside a zip file with -b option  -------------------------------------------------
python pwned.py -t test.plainpasswords.txt -l pwned-passwords-sha1-top100kSORTED.txt -z pwned-passwords-sha1-top100kSORTED.zip -b
PAUSE
