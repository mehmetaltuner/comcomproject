import socket
import time 
import random as rd
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
import os.path

def pad(s):
    return s + (16 - len(s)%16)*bytes([(16-len(s)%16)])

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

def toByte(s):
    return bytes([s])

def fromByte(s):
    return ord(s)

class Error(Exception):
    pass


class WrongPacketType(Error):
    def __init__(self, expression):
        self.expression = expression

class Server(object):

    def __init__(self, PORT = 65432, erRate = 0, TIMEOUT=0.01, N = 10):
        self.PORT = PORT
        self.session_key = Random.get_random_bytes(32)
        self.AESchiper = AES.new(self.session_key, AES.MODE_ECB)
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.erRate = erRate
        self.serverSocket.bind(('', PORT))
        self.status = None
        self.filename = None
        self.ptypes = ['Handshake', 'Ack', 'Data', 'FIN']
        self.RSAkey = None
        self.TIMEOUT = TIMEOUT
        self.serverSocket.settimeout(self.TIMEOUT)
        self.status = 'Start'
        self.N =  N
        self.last_packets = []
        self.send_base = 0
        self.next_seq = 0
        self.partition = 64
        self.row = 0


    def unreliable_send(self, packet, client):
        if self.erRate < rd.randint(0,100):
            self.serverSocket.sendto(packet, client)

    def decrypt(self, packet):
        return self.AESchiper.decrypt(packet)
    
    def encrypt(self, packet):
        return self.AESchiper.encrypt(packet)

    def receive_handshake_message(self, packet):
        ptype = packet[0]
        if ptype != 0:
            expr = 'Expected handshake message but got ' + self.ptypes[ptype] + ' message type'
            raise WrongPacketType(expr)
        length = packet[1]
        data = packet[2:2+length].decode('UTF-8')
        ts = data.find('.txt')
        #should look if the file exist.
        self.filename = data[:ts+4]
        file_exist = os.path.isfile(self.filename)
        self.RSAkey = data[ts+4:]
        return file_exist
        


    def receive_ack_message(self, packet):
        packet = self.decrypt(packet)
        packet = unpad(packet)
        ptype = packet[0]
        if(ptype != 1):
            expr = 'Expected ack message but got ' + self.ptypes[ptype] + ' message type'
            raise WrongPacketType(expr)
        seqnum = packet[1]
        return seqnum

    def receive_data_packet(self, packet):
        pass

    def send_handshake_message(self, client):
        ### This code Excepts to receive handshake message beforehand 
        ### and to already have a public RSA key so it can encrypt 
        ### it's session key
        ptype = toByte(0)
        publicKey = RSA.import_key(self.RSAkey)
        rsaEncryptor = PKCS1_OAEP.new(publicKey)
        length = toByte(len(self.session_key))
        
        packet = ptype + length + self.session_key
        
        encpted_packet = rsaEncryptor.encrypt(packet)
        #This will be replaced later, this is for development stage.
        self.unreliable_send(encpted_packet, client)
        return encpted_packet

    def send_ack_message(self):
        pass

    def send_data_message(self, data, seq_num, client):
        ptype = toByte(2)
        seq_num = toByte(seq_num)

        if type(data) != bytes:
            try:
                data = bytes(data, "utf-8")
            except Exception as err:
                print("Error while converting data to bytes: ", err)
                raise err

        length = toByte(len(data))

        packet = ptype + length + seq_num + data
        packet = pad(packet)
        #print('RSA', self.RSAkey)
        #print('Senden Packet', packet, unpad(packet))
        encpted_packet = self.AESchiper.encrypt(packet)
        #print('Session KEy', self.session_key)
        #print('decrypted packet: ', self.decrypt(encpted_packet))
        self.unreliable_send(encpted_packet, client)
        return encpted_packet

    def send_fin_message(self, client):
        pType = toByte(3)
        packet = pType
        packet = pad(packet)
        encpted_packet = self.AESchiper.encrypt(packet)
        self.unreliable_send(encpted_packet, client)

    def send_raw_enc_packet(self, enc_packet, client):
        self.unreliable_send(enc_packet, client)
        
    

mob = Server()
yolla = True
client = None
data_to_send = None
last_recvd_ack = -1


while True:
    try:
        if mob.status == 'Start':
            packet, client = mob.serverSocket.recvfrom(1024)
            print('Getting start message')
            file_recv = mob.receive_handshake_message(packet)
            print('message received ', mob.filename)
            if not file_recv:
                print('No file with filename: ', mob.filename)
                time.sleep(mob.TIMEOUT)
            else:
                print('Message is received Status is changed to handshaking')
                mob.status = 'Handshaking'

        elif mob.status == 'Handshaking':
            
            mob.send_handshake_message(client)
        
            packet, client = mob.serverSocket.recvfrom(1024)
            print('Sending Handshake Message')
            print('Getting ack for handshake message')
            if(packet[0] == 0):
                continue
            packet = mob.decrypt(packet)
            packet = unpad(packet)
            print('Decrypting Message')
            print('Packet = ', packet)
            print('Packet Type ', packet[0])
            if (packet[0] == 1):
                mob.status = 'DataTransfer'
                

        elif mob.status == 'DataTransfer':
            if not data_to_send:
                with open("crime-and-punishment.txt", "r") as file_stream:
                    data_to_send = file_stream.read()
                data_to_send = data_to_send.split("\n")

            if mob.row >= len(data_to_send) and len(mob.last_packets) == 0:
                print("Done sending packets to the client, closing the socket")
                mob.send_fin_message(client)
                try:
                    packet, _ = mob.serverSocket.recvfrom(1024)
                except WrongPacketType as err:
                   pass
                mob.serverSocket.close()
                exit(0)

            while mob.next_seq < mob.send_base + mob.N and mob.row < len(data_to_send):
                print("SENDING SEG ", mob.next_seq)
                raw_enc_packet = mob.send_data_message(data_to_send[mob.row], mob.next_seq, client)
                mob.row += 1
                mob.next_seq = (mob.next_seq+1) % 256
                mob.last_packets.append(raw_enc_packet)

            try:
                packet, _ = mob.serverSocket.recvfrom(1024)
                ack_seq_num = mob.receive_ack_message(packet)
                mob.send_base = ack_seq_num
                print("ACK RECVD, send base: ", mob.send_base)
                if ack_seq_num != last_recvd_ack:
                    mob.last_packets.pop(0)
                    last_recvd_ack = ack_seq_num

            except WrongPacketType:
                pass

            except socket.timeout:
                print("UN-ACKED PACKETS LIST SIZE: ", len(mob.last_packets))
                print("SEND BASE PTR: ", mob.send_base, "\n NEXT SEQ PTR: ", mob.next_seq)
                if mob.send_base == mob.next_seq:
                    continue
                for packet in mob.last_packets:
                    mob.send_raw_enc_packet(packet, client)

    except Exception as ex:
        print(ex)
        continue
    
# 
# print('asdsad')
# mob.receive_handshake_message(packet)
# mob.send_handshake_message(client)
# mob.serverSocket.close()
