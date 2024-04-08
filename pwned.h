#ifndef PWNED_H
#define PWNED_H
#include <time.h><

#define PROGRAM_VERSION "2.1"
#define DEBUG_MODE false
#define SSL_CHECK true

#define HASH_PREFIX_LENGHT 5
#define BASE_PWD_SEARCH_URL "https://api.pwnedpasswords.com/range/"

#define IM_UNKNOWN_MODE 0
#define IM_SINGLE_PASSOWRD 1
#define IM_PASSWORD_FILE 2
#define IM_TEXT_FILE 3

#define OM_PLAIN 1
#define OM_HASH 2

#define DB_UNKNOWN 0
#define DB_WEB 1
#define DB_LOCAL 2
#define DB_LOCAL_SORTED 3
#define DB_LOCAL_ZIP 4

#define ERR_NO_ERROR 0
#define ERR_WRONG_PARAMETERS 1
#define ERR_OTHERS 2
#define ERR_OPMODE_UNKNOWN 3
#define ERR_NO_HASH_PASSWORD 4

#define LINES_TO_EXCLUDE {"http", "https", "***", "---", "___", "#", "//", "/*"}
#define SPLIT_CHARS {":", "/", "=", "\t"}
#define MIN_WORD_LENGTH 5

struct Record {
    bool ispwned;
    char src_password[256];
    char src_hash[41];
    char found_filename[256];
    int found_linenumber;
};

struct GlobalStatistics {
    int number_of_password_read;
    int pwned_passwords_found;
    int safe_passwords_found;
    int scanned_lines_in_db;
    int safe_passwords_invalid;
    time_t start_time;
    time_t stop_time;
    double elapsed_time;
};



#endif // PWNED_H
