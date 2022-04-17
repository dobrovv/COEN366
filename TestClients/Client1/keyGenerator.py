class EncryptionDecryption:

    eol = '\n'
    char = '"'
    encryption = "abcdefghijklmnopqrstuvwxyz0123456789!/$%?&*()_-=+^¨'><:,.[]{}ABCDEFGHIJKLMNOPQRSTUVWXYZ " + eol + char             # Predefined data to update the message
    message = ""
    #message = input ("Enter the message to encrypt: ")     # Ask the user to enter the message
    key = 15    

    def encryptionMessage(message,encryption,key):
        encrypt = ""
        for i in message:
            new_position = (encryption.find(i) + key) % len(encryption)
            encrypt += encryption[new_position]
            #print("Encrypted message:" + encryption[new_position])
        return encrypt

    def decryptionMessage(encrypt,encryption,key):
        decrypt = ""
        for i in encrypt:
            new_position = (encryption.find(i) - key) % len(encryption)
            decrypt += encryption[new_position]
            #print("Decrypted message:" + decrypt)
        return decrypt

    #encryptionMessage(message,encryption,key)
    #decryptionMessage(message,encryption,key,encryptionMessage(message,encryption,key))
    #print("Encrypted message:" + encryptionMessage(message,encryption,key))
    #print("Decrypted message:" + decryptionMessage(message,encryption,key,encryptionMessage(message,encryption,key)))
