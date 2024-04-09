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
import time

class PwnedStats:
    """ Utility class for pwned.py to store statistics. This is a SINGLETON class.
    """
    _instance = None
    _initialized = False

    def __new__(cls):
        if not cls._instance:
            cls._instance = super(PwnedStats, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self.start_time:float       = 0
            self.stop_time:float        = 0
            self.elapsed_time:float     = 0
            self.PROGRAM_VERSION:str    = "2.2"
            self.DEBUG_MODE:bool        = False
            self.DEBUG_ON_FILE:bool     = False
            self.DEBUG_FILENAME:str     = "pwned.log"
            self.SSL_CHECK:bool         = True
            
            self.number_of_password_read:int = 0   #1 if from command 
            self.pwned_passwords_found:int   = 0
            self.safe_passwords_found:int    = 0
            self.scanned_lines_in_db:int     = 0  #if local db option used
            self.safe_passwords_invalid:int  = 0

            self._initialized = True
            
    def start_timer(self):
        self.start_time = time.time()

    def stop_timer(self):
        self.stop_time = time.time()
        self.elapsed_time = self.stop_time - self.start_time

    def get_elapsed_time(self) -> float:
        return self.elapsed_time
    
    def get_elapsed_time_str(self) -> str:
        return f"{self.elapsed_time:.2f} seconds"

    def increment_number_of_password_read(self) -> None:
        self.number_of_password_read += 1

    def increment_pwned_passwords_found(self) -> None:
        self.pwned_passwords_found += 1
    
    def increment_safe_passwords_found(self):
        self.safe_passwords_found += 1

    def increment_scanned_lines_in_db(self):
        self.scanned_lines_in_db += 1

    def increment_safe_passwords_invalid(self):
        self.safe_passwords_invalid  += 1



"""
# Usage example
stats = PwnedStats()
stats.start_timer()
# Perform some operations
stats.stop_timer()
print(f"Elapsed time: {stats.elapsed_time} seconds")
"""