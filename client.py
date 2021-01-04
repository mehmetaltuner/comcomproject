import socket
import time 
import random as rd
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random

def pad(s):
    #return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
    return s + (16 - len(s) % 16) * bytes([(16 - len(s) % 16)])
def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

# Represents integers from 0-255 in one byte
def toByte(s):
    #return chr(s).encode('utf-8')
    return bytes([s]) 
    #return bytes("\x{:02x}".format(s).encode('utf-8'))


# Returns 0-255 byte to integer
def fromByte(s):
    return ord(s)

def unreliableSend(packet, sock, user, errRate):
    if errRate < rd.randint(0,100):
        sock.sendto(packet, user)
        
print(toByte(4),toByte(160), toByte(250))
print(fromByte(toByte(4)),fromByte(toByte(160)),fromByte(toByte(250)))

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server
user = (HOST, PORT)
status = "Start"

errRate = 10 # Average Error rate of the unreliable channel
TIMEOUT = 0.01 # Timeout value
N = 1 # Go-back-N N

filename = b'crime-and-punishment.txt'

passwd = Random.get_random_bytes(32)                        # AES256 must be 32 bytes
secretWord = b"This word is secret"                         # The word that will be encrypted.  
AEScipher = AES.new(passwd, AES.MODE_ECB)                   # Create AES cipher with given key. 
phrase= AEScipher.encrypt(pad(secretWord))                  # The words that will be encrypted
                                                            # Must have length multiple of 16.
print(phrase)
print(AEScipher.decrypt(phrase).decode('utf-8'))

rsaKey = RSA.generate(1024)                                 # Generate RSA public and Private keys
private_key = rsaKey.export_key()                           # Export private key.
public_key = rsaKey.publickey().export_key('OpenSSH')       # Export public key. 
                                                            # Public key will be shared.
publicKey = RSA.import_key(public_key)                      # Convert RSA keys to be usable by 
privateKey = RSA.import_key(private_key)                    # Encryptors

rsaEncryptor = PKCS1_OAEP.new(publicKey)                    # RSA has separate decoder and encoders
rsaDecryptor = PKCS1_OAEP.new(privateKey)                   # Which have different keys

enc = rsaEncryptor.encrypt(secretWord)#.encode('utf-8'))
dec = rsaDecryptor.decrypt(enc)
print(enc, dec)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)     # Create UDP socket
sock.settimeout(TIMEOUT)                                    # If no packets came after TIMEOUT
                                                            # Then throw exception
while True:
    try:
        if status == "Start":
            # Create payload
            length = toByte(len(filename) + len(public_key))
            print(public_key)
            print(len(filename) + len(public_key), length)  
            pType = toByte(0)
            packet = pType + length
            packet += filename + public_key
            # Send to the server
            unreliableSend(packet, sock, user, errRate)
            status = "Handshaking"

        else:
            data, user = sock.recvfrom(1024)
            #print('Received:', data)
            if status == "Handshaking":
                data = rsaDecryptor.decrypt(data)
                if data[0] == 0:
                    packetLength = data[1]
                    sessionKey = data[2:2+packetLength]
                    print("sessionKey =", sessionKey, packetLength)

                    # ACK segment 00
                    packet = toByte(1) + toByte(0) 
                    packet = pad(packet)
                    print(packet)
                    #print(bytes(packet))
                    AEScipher = AES.new(sessionKey, AES.MODE_ECB)
                    packet = AEScipher.encrypt(packet)
                    unreliableSend(packet, sock, user, errRate)
                    nextSeqNum = 0

                    status = "DataTransfer"
                else:
                    print("SERVER SENT WRONG PACKET")
                    exit(1)
            
            elif status == "DataTransfer":
                data = AEScipher.decrypt(data)
                data = unpad(data)
                packetType = data[0]
                if packetType == 2:
                    packetLenght = data[1]
                    sequenceNumber = data[2]

                    packet = toByte(1) + toByte(sequenceNumber)
                    print("Getted seq num", sequenceNumber)
                    packet = pad(packet)
                    packet = AEScipher.encrypt(packet)
                    unreliableSend(packet, sock, user, errRate)

                    if sequenceNumber == nextSeqNum: 
                        payload = data[3:3+packetLenght].decode('utf-8')
                        print(sequenceNumber, payload[:-1])
                        nextSeqNum = (nextSeqNum + 1) % 256
                        
                    else:
                        print("Discarding packet", sequenceNumber, "expected", nextSeqNum)
                        pass # if it is not expected discard the packet

                elif packetType == 3:
                    print("Transmission Complete")
                    packet = toByte(1) + toByte(0)
                    packet = pad(packet)
                    packet = AEScipher.encrypt(packet)
                    unreliableSend(packet, sock, user, errRate)
                    status = "Ending"
                    exit(0)
                else:
                    print("SERVER SENT WRONG PACKET")
                    exit(1)
    except Exception as ex:         
        #print(ex)
        if status == "Handshaking" or status == "Ending":
            unreliableSend(packet, sock, user, errRate)

