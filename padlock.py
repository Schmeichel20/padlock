import argparse
import os
import getpass
import sys
import base64
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import warnings

def derive_key(password, salt):
    """Derives the encryption key from the password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def encrypt_data(password, data):
    """Encrypts the data using AES-CBC with a random initialization vector."""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(base64.urlsafe_b64encode(key))
    encrypted_data = f.encrypt(data)
    return salt + encrypted_data

def decrypt_data(password, data):
    """Decrypts the data using AES-CBC with the initialization vector."""
    salt = data[:16]
    encrypted_data = data[16:]
    key = derive_key(password, salt)
    f = Fernet(base64.urlsafe_b64encode(key))
    try:
        decrypted_data = f.decrypt(encrypted_data).decode()
        return decrypted_data
    
    except InvalidToken:
        sys.exit('Error: wrong password')


def process_string_input(args, password):
    data = args.string
    if not isinstance(data, bytes):
        data = data.encode()


    if args.lock:
        encrypted_data = encrypt_data(password, data)

        if args.output:
            with open(args.output, 'wb') as f:
                f.write(encrypted_data)
    # elif args.unlock:
    #     decrypted_data = decrypt_data(password, data)

    #     if args.output:
    #         with open(args.output, 'wb') as f:
    #             f.write(decrypted_data)
    #     if args.direct:
    #         print('Decrypted data:', decrypted_data.decode())

def process_file_input(args, password):
    """Encrypts or decrypts the input file based on the input arguments."""
    # Determine input and output filenames
    input_filename = args.file
    input_basename, input_ext = os.path.splitext(input_filename)

    if args.output:
        output_filename = args.output
    else:
        # Default output filename based on input filename and mode
        if args.lock:
            output_filename = f'{input_basename}_encrypted{input_ext}'
        else:
            output_filename = f'{input_basename}_decrypted{input_ext}'

    # Read input data from file
    with open(input_filename, 'rb') as input_file:
        input_data = input_file.read()

    # Process input data
    if args.lock:
        output_data = encrypt_data(password, input_data)
    else:
        output_data = decrypt_data(password, input_data)
    
    # Write output data to file
    if args.lock:
        # works in lock mode, so the output is encrypted, and should be bytes
        with open(output_filename, 'wb') as output_file:
            output_file.write(output_data)

        print(f'Output written to {output_filename}')
        
    elif args.unlock:
        # works in unlock mode, so presumably the output is a string
        # but we got to check
        if isinstance(output_data, str):
            # print on CLI if required
            if args.direct:
                print(output_data)

            # just write
            with open(output_filename, 'w') as output_file:
                output_file.write(output_data)
            
            print(f'Output written to {output_filename}')
            
        
        # for anything that is not a string, convert to bytes
        elif (not isinstance(output_data, bytes)) and (output_data is not None):
            output_data = output_data.encode()
            with open(output_filename, 'wb') as output_file:
                output_file.write(output_data)

            if args.direct:
                # who would want to see bytes in the terminal?
                warnings.warn('The output is in bytes, so no fancy display here')

def main():
    parser = argparse.ArgumentParser(description='AES encryption and decryption tool.')
    parser.add_argument('-l', '--lock', action='store_true', help='Encrypt the input')
    parser.add_argument('-u', '--unlock', action='store_true', help='Decrypt the input')
    parser.add_argument('-s', '--string', help='Input string to be encrypted or decrypted')
    parser.add_argument('-f', '--file', help='Input file to be encrypted or decrypted')
    parser.add_argument('-o', '--output', help='Output file for encrypted or decrypted data')
    parser.add_argument('-p', '--password', help='Password for encryption/decryption')
    parser.add_argument('-d', '--direct', action='store_true', help='Directly display the decrypted data via command line.')

    args = parser.parse_args()

    if not args.lock and not args.unlock:
        parser.error('At least one of -l or -u must be specified')
    elif args.lock and args.unlock:
        parser.error('-l and -u cannot be specified together')
    elif args.string and args.file:
        parser.error('-s and -f cannot be specified together')
    elif args.unlock and args.string:
        parser.error('Cannot decrypt a string input')
    elif args.lock and args.string and (not args.output):
        parser.error('-o or --output is required when encrypting a string')
    elif args.file and not os.path.exists(args.file):
        parser.error('Input file does not exist')
    elif args.output and not args.lock and not args.unlock:
        parser.error('-o can only be used with -l or -u')

    if args.lock and args.direct:
        warnings.warn('No thing will be displayed because the encrypted content will be binary!')

    password = args.password or getpass.getpass(prompt='Enter the password: ', stream=None)
    
    # Process input data
    if args.string:
        process_string_input(args, password)
    elif args.file:
        process_file_input(args, password)
    else:
        parser.error('Either -s or -f must be specified')

if __name__ == '__main__':
    main()



# api_key = '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'