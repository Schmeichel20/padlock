# padlock
Simple Python digital padlock for encrypting/decrypting short texts (texts, supposedly).
Written with (a lot of) help from OpenAI ChatGPT-3.5, though it f***s up very often too.

## Usage
padlock.py [-h] [-l] [-u] [-s STRING] [-f FILE] [-o OUTPUT] [-p PASSWORD] [-d]

AES encryption and decryption tool.

options:
  -h, --help            show this help message and exit
  -l, --lock            Encrypt the input
  -u, --unlock          Decrypt the input
  -s STRING, --string STRING
                        Input string to be encrypted or decrypted
  -f FILE, --file FILE  Input file to be encrypted or decrypted
  -o OUTPUT, --output OUTPUT
                        Output file for encrypted or decrypted data
                        If you do not specify an output... things will happen
                        Might elaborate but it's too much hassle
  -p PASSWORD, --password PASSWORD
                        Password for encryption/decryption
  -d, --direct          Directly display the decrypted data via command line.
                        When you use this option when encrypting, you'll get a warning
                        and nothing will be displayed.
                        
## Known bugs
- Cannot encrypt binary files.
