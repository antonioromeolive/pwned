# PWNED

A Python command-line tool to check if passwords have appeared in known data breaches, using the [Have I Been Pwned](https://haveibeenpwned.com/Passwords) database. **Not affiliated with haveibeenpwned.com.**

No plain-text passwords are ever transmitted over the network. The tool uses a [k-anonymity](https://en.wikipedia.org/wiki/K-anonymity) approach: only the first 5 characters of the SHA1 hash are sent to the API, keeping your passwords private.

## Features

- Check a **single password** from the command line
- Check **multiple passwords** from a file (one per line)
- **Extract words** from a text file and check them as passwords
- **Online mode** (default): queries the Have I Been Pwned API
- **Offline mode**: search a local copy of the breach database (plain text, sorted with binary search, or zipped)
- Accepts passwords as **plain text** or **SHA1 hashes**
- Optional **CSV output** of results
- Configurable **request throttling** for the web API
- **Debug mode** for verbose logging

## Requirements

- Python 3.8+
- `requests` library

```
pip install -r requirements.txt
```

## Usage

```
pwned [-p password] | [-f file] | [-t text_file]
      [-s]                  Input is in SHA1 format
      [-l local_db_file]    Use a local hash database file
      [-b]                  Use binary search (requires sorted local file)
      [-z zip_file]         Use a zipped local database
      [-w seconds]          Delay between web API requests
      [-o output_file]      Write results to a CSV file
      [-d]                  Enable debug mode
      [-h]                  Show help
```

## Examples

### Check a single password against the web API

```
python pwned.py -p mypassword123
```

### Check a single SHA1 hash against the web API

```
python pwned.py -p 7C4A8D09CA3762AF61E59520943DC26494F8941B -s
```

### Check a file of plain-text passwords

```
python pwned.py -f passwords.txt
```

The file should contain one password per line.

### Check a file of SHA1 hashes

```
python pwned.py -f hashed_passwords.txt -s
```

### Check passwords against a local database

Download the SHA1 hash list from [haveibeenpwned.com/Passwords](https://haveibeenpwned.com/Passwords), then:

```
python pwned.py -p mypassword123 -l pwned-passwords-sha1-ordered.txt
```

### Use binary search with a sorted local database (faster)

```
python pwned.py -f passwords.txt -l pwned-passwords-sha1-ordered.txt -b
```

### Use a zipped local database

```
python pwned.py -p mypassword123 -l pwned-passwords-sha1-ordered.txt -z pwned-passwords-sha1-ordered.zip
```

### Save results to a CSV file

```
python pwned.py -f passwords.txt -o results.csv
```

The output CSV contains: `source_filename, line_number, plain_password, sha1_hash, is_pwned`

### Throttle web requests (1 second between each)

```
python pwned.py -f passwords.txt -w 1
```

### Extract words from a text file and check them

```
python pwned.py -t document.txt -l pwned-passwords-sha1-ordered.txt -b
```

Words shorter than 5 characters are excluded. Lines starting with `http`, `#`, `//`, `/*`, `---`, `***`, or `___` are skipped. Characters `:`, `/`, `=`, and tabs are treated as word separators.

## How It Works

1. Each password is hashed with SHA1
2. **Online mode**: the first 5 hex characters of the hash are sent to the API, which returns all matching hash suffixes. The tool checks locally whether the full hash appears in the response. Your password never leaves your machine.
3. **Offline mode**: the full SHA1 hash is compared against a local copy of the breach database, either sequentially or using binary search for sorted files.

## Output

At the end of each run, a summary is printed:

```
---------------------------------------------------------------
Total number of passwords/hash read.......: 10
Total number of passwords/hash pwned......: 3
Total number of passwords/hash safe.......: 7
Total number of passwords/hash invalid....: 0
Total number of lines scanned in local db : 100,000
Total elapsed time (sec)..................: 1.2345
---------------------------------------------------------------
PWNED - ver. 2.2 from A.R.
```

## Security Note

When using the `-o` option, the output file **may contain your plain-text passwords**. Delete it after use.

## License

MIT License - Copyright (c) 2024 Antonio Romeo

## Author

Antonio Romeo
