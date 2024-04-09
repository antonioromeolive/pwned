echo off
set /a good_tests = 0
set /a bad_tests = 0
set /a total_tests = 0

set LOG_FILE=pwnedtest.log
echo Running pwned.py tests...
echo ******************* Single password tests... ******************************************
echo 1. FROM THE WEB **************************************************************************
set /a total_tests = %total_tests% + 1

python pwned.py -p password123
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
) ELSE (
    set /a good_tests = %good_tests% + 1
    echo OK
)

echo 2.FROM THE WEB with empty password ------------------------------------------------------ 
set /a total_tests = %total_tests% + 1
python pwned.py -p ""
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred as expected! Everthing OK
    set /a good_tests = %good_tests% + 1
) ELSE (
    echo This should NOT Happen!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
)

echo 3. FROM THE WEB with NO password    ------------------------------------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -p
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred as expected! Everthing OK
    set /a good_tests = %good_tests% + 1
) ELSE (
    echo This should NOT Happen!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
)

echo 4. FROM LOCAL FILE                  ------------------------------------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -p password123 -l pwned-passwords-sha1-top100kSORTED.txt 
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
) ELSE (
    set /a good_tests = %good_tests% + 1
    echo OK
)


echo 5. FROM LOCAL FILE with empty filename ---------------------------------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -p password123 -l ""
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred as expected! Everthing OK
    set /a good_tests = %good_tests% + 1
) ELSE (
    echo This should NOT Happen!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
)

echo 6. FROM LOCAL FILE with no filename ------------------------------------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -p password123 -l 
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred as expected! Everthing OK
    set /a good_tests = %good_tests% + 1
) ELSE (
    echo This should NOT Happen!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
)

echo 7. FROM LOCAL FILE with non existing file --------------------------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -p password123 -l "44gattiinfilaper3.txt"
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred as expected! Everthing OK
    set /a good_tests = %good_tests% + 1
) ELSE (
    echo This should NOT Happen!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
)

echo 8. FROM LOCAL FILE inside a zip file -----------------------------------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -p password123 -l pwned-passwords-sha1-top100kSORTED.txt -z pwned-passwords-sha1-top100kSORTED.zip
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND

) ELSE (
    set /a good_tests = %good_tests% + 1
    echo OK
)

echo 9. FROM LOCAL FILE inside a zip file with empty zip filename -----------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -p password123 -l pwned-passwords-sha1-top100kSORTED.txt -z ""
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred as expected! Everthing OK
    set /a good_tests = %good_tests% + 1
) ELSE (
    echo This should NOT Happen!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
)

echo 10. FROM LOCAL FILE inside a zip file with no filename ------------------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -p password123 -l pwned-passwords-sha1-top100kSORTED.txt -z 
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred as expected! Everthing OK
    set /a good_tests = %good_tests% + 1
) ELSE (
    echo This should NOT Happen!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
)

echo 11. FROM LOCAL FILE inside a zip file with non existing ZIP -------------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -p password123 -l pwned-passwords-sha1-top100kSORTED.txt -z 44gattiinfilaper3.txt
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred as expected! Everthing OK
    set /a good_tests = %good_tests% + 1
) ELSE (
    echo This should NOT Happen!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
)


echo 12. FROM LOCAL FILE inside a zip file with local file NOT inside the zip ------------------
set /a total_tests = %total_tests% + 1
python pwned.py -p password123 -l 44gattiinfilaper3.txt -z pwned-passwords-sha1-top100kSORTED.zip
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred as expected! K
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
) ELSE (
    echo OK
    set /a good_tests = %good_tests% + 1

)

echo 13. FROM LOCAL FILE inside a zip file with -b option -------------------------------------- 
set /a total_tests = %total_tests% + 1
python pwned.py -p password123 -l pwned-passwords-sha1-top100kSORTED.txt -z pwned-passwords-sha1-top100kSORTED.zip -b
IF %ERRORLEVEL% NEQ 0 (
    set /a bad_tests = %bad_tests% + 1
    echo Error occurred!
    goto THEEND
) ELSE (
    set /a good_tests = %good_tests% + 1
    echo OK
)

echo ******************* passwords from text file ******************************************
echo 14. FROM THE WEB WITH LOCAL PASSWORD FILE PROVIDED ----------------------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -t test.plainpasswords.txt
IF %ERRORLEVEL% NEQ 0 (
    set /a bad_tests = %bad_tests% + 1
    echo Error occurred!
    goto THEEND
) ELSE (
    set /a good_tests = %good_tests% + 1
    echo OK
)

echo 15. FROM THE WEB with empty password file -------------------------------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -t "test.emptyfile.txt"
IF %ERRORLEVEL% NEQ 0 (
    echo This should NOT Happen!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
) ELSE (
    echo Error occurred as expected! Everthing OK
    set /a good_tests = %good_tests% + 1
)

echo 16. FROM THE WEB with NO existing password file password ----------------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -t 44gattiinfilaper3.txt
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred as expected! Everthing OK
    set /a good_tests = %good_tests% + 1
) ELSE (
    echo This should NOT Happen!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
)

echo 17. FROM LOCAL FILE ------------------------------------------------------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -t test.plainpasswords.txt -l pwned-passwords-sha1-top100kSORTED.txt 
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
) ELSE (
    set /a good_tests = %good_tests% + 1
    echo OK
)


echo 18. FROM LOCAL FILE with empty filename -------------------------------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -t test.plainpasswords.txt -l ""
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred as expected! Everthing OK
    set /a good_tests = %good_tests% + 1
) ELSE (
    echo This should NOT Happen!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
)

echo 19. FROM LOCAL FILE with no filename -------------------------------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -t test.plainpasswords.txt -l 
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred as expected! Everthing OK
    set /a good_tests = %good_tests% + 1
) ELSE (
    echo This should NOT Happen!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
)

echo 20. FROM LOCAL FILE with non existing filename -------------------------------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -t test.plainpasswords.txt -l "44gattiinfilaper3.txt"
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred as expected! Everthing OK
    set /a good_tests = %good_tests% + 1
) ELSE (
    echo This should NOT Happen!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
)

echo 21. FROM LOCAL FILE inside a zip file -------------------------------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -t test.plainpasswords.txt -l pwned-passwords-sha1-top100kSORTED.txt -z pwned-passwords-sha1-top100kSORTED.zip
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
) ELSE (
    set /a good_tests = %good_tests% + 1
    echo OK
)


echo 22. FROM LOCAL FILE inside a zip file with empty zip filename -------------------------------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -t test.plainpasswords.txt -l pwned-passwords-sha1-top100kSORTED.txt -z ""
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred as expected! Everthing OK
    set /a good_tests = %good_tests% + 1
) ELSE (
    echo This should NOT Happen!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
)

echo 23. FROM LOCAL FILE inside a zip file with no filename -------------------------------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -t test.plainpasswords.txt -l pwned-passwords-sha1-top100kSORTED.txt -z 
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred as expected! Everthing OK
    set /a good_tests = %good_tests% + 1
) ELSE (
    echo This should NOT Happen!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
)

echo 24. FROM LOCAL FILE inside a zip file with non existing ZIP -------------------------------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -t test.plainpasswords.txt -l pwned-passwords-sha1-top100kSORTED.txt -z 44gattiinfilaper3.txt
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred as expected! Everthing OK
    set /a good_tests = %good_tests% + 1
) ELSE (
    echo This should NOT Happen!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
)

echo 25. FROM LOCAL FILE inside a zip file with local file NOT inside the zip -------------------------------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -f test.plainpasswords.txt -l 44gattiinfilaper3.txt -z pwned-passwords-sha1-top100kSORTED.zip
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred as expected! Everthing OK
    set /a good_tests = %good_tests% + 1
) ELSE (
    echo This should NOT Happen!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
)

echo 26. FROM LOCAL FILE inside a zip file with local file NOT inside the zip -------------------------------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -t test.plainpasswords.txt -l 44gattiinfilaper3.txt -z pwned-passwords-sha1-top100kSORTED.zip
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred as expected! Everthing OK
    set /a good_tests = %good_tests% + 1
) ELSE (
    echo This should NOT Happen!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
)

echo 27. FROM LOCAL FILE inside a zip file with -b option  -------------------------------------------------
set /a total_tests = %total_tests% + 1
python pwned.py -t test.plainpasswords.txt -l pwned-passwords-sha1-top100kSORTED.txt -z pwned-passwords-sha1-top100kSORTED.zip -b
IF %ERRORLEVEL% NEQ 0 (
    echo Error occurred!
    set /a bad_tests = %bad_tests% + 1
    goto THEEND
) ELSE (
    set /a good_tests = %good_tests% + 1
    echo OK
)

:THEEND
echo Good tests: %good_tests%
echo Bad tests: %bad_tests%
echo Total tests: %total_tests%






