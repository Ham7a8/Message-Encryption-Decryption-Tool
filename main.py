import base64

def encode_message(message):
    encoded_bytes = base64.b64encode(message.encode('utf-8'))
    encoded_message = encoded_bytes.decode('utf-8')
    return encoded_message

def decode_message(encoded_message):
    decoded_bytes = base64.b64decode(encoded_message.encode('utf-8'))
    decoded_message = decoded_bytes.decode('utf-8')
    return decoded_message

def caesar_cipher_encrypt(message, shift):
    encrypted_message = ''
    for char in message:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            encrypted_message += chr(shifted)
        else:
            encrypted_message += char
    return encrypted_message

def caesar_cipher_decrypt(encrypted_message, shift):
    return caesar_cipher_encrypt(encrypted_message, -shift)

def main():
    choice = input("Do you want to encrypt or decrypt a message? (encrypt/decrypt): ").lower()
    
    if choice == 'encrypt':
        method = input("Choose the encryption method (base64/caesar): ").lower()
        message = input("Enter the message to encrypt: ")
        
        if method == 'base64':
            encoded = encode_message(message)
            print("Encoded:", encoded)
        elif method == 'caesar':
            shift = int(input("Enter the shift for Caesar cipher: "))
            encrypted = caesar_cipher_encrypt(message, shift)
            print("Encrypted:", encrypted)
        else:
            print("Invalid encryption method!")
    
    elif choice == 'decrypt':
        method = input("Choose the decryption method (base64/caesar): ").lower()
        encrypted_message = input("Enter the message to decrypt: ")
        
        if method == 'base64':
            decoded = decode_message(encrypted_message)
            print("Decoded:", decoded)
        elif method == 'caesar':
            shift = int(input("Enter the shift for Caesar cipher: "))
            decrypted = caesar_cipher_decrypt(encrypted_message, shift)
            print("Decrypted:", decrypted)
        else:
            print("Invalid decryption method!")
    
    else:
        print("Invalid choice!")

if __name__ == "__main__":
    main()
