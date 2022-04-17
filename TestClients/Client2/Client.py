import os, socket, threading, time, random
from MessageParser import *
from ipaddress import getIpTcpAddress
from keyGenerator import *

GoogleSocket = getIpTcpAddress()
CL_ADDRESS   = GoogleSocket[0]
CL_UDP_PORT   = 5001+2
CL_TCP_PORT   = 6001+2
CL_NAME = "My Client 2"
CL_PASSWORD = "P2P pass"
DIR = "Published2"
DOWNLOADS = "Downloads"
udpBufferSize = 1024*4
tcpBufferSize = 1024*4

#Server parameters (fixed port, user-input IP address)
print("Initializing client...")
serverIP = input("Please enter the IP address of the server: ")
while serverIP is None:
    print("No or invalid IP address specified.")
    serverIP = input("Please enter the IP address of the server: ")
UDP_IP = serverIP;
UDP_PORT = 3000

print("UDP target IP:", UDP_IP)
print("UDP target port:", UDP_PORT)
print("UDP source IP:", CL_ADDRESS)
print("UDP source port:", CL_UDP_PORT)

# Create a UDP socket at client side
# UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
# UDPClientSocket.bind((clientAddress, clientUdpPort))

# Send to server using created UDP socket
# UDPClientSocket.sendto(bytesToSend, serverAddressPort)
# msgFromServer = UDPClientSocket.recvfrom(bufferSize)

class Client:
    def __init__(self, Name:str, ipaddress:str, udp:int, tcp:int, password="pass1234", filesDirectoryPath:str = "Published", filesDownloadPath:str = "Downloads" ):
        self.Name = Name
        self.ipaddress = ipaddress
        self.udp = udp
        self.tcp = tcp
        self.filesInPubDir = []
        self.filesInDlDir = []
        self.password = password
        
        self.filesDir = filesDirectoryPath
        self.downloadDIR = filesDownloadPath
        self.isRegistered = False
        self.isAuthenticated = False
        self.isDownloading = False
        self.isUploading = False

        self.svsock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
        for i in range(32):
            try:
                self.svsock.bind(('', self.udp)) # only the port number is set
                break
            except Exception as e:
                print(f"Can't bind server udp socket to {(self.ipaddress, self.tcp)} retrying...")
                self.udp = self.udp + 1

        #Reads file names in the transfer folder
        #self._read_files_from_dir()
    
    def start_listening_for_uploads(self,):
        upserver = threading.Thread(target=self.p2p_listening_thread)
        upserver.start()

    def p2p_listening_thread(self):
        
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        for i in range(32):
            try:
                server.bind((self.ipaddress, self.tcp))
                break
            except Exception as e:
                print(f"Can't bind to {(self.ipaddress, self.tcp)} retrying...")
                self.tcp = self.tcp + 1
        
        server.listen(5)
        print (f"The client is up and listens at {self.ipaddress}:{self.tcp} for upload requests")

        while True:
            client, addr = server.accept()
            print(f"[*] Accepted connection from: {addr[0]}:{addr[1]}")
            servercl = threading.Thread(target=self.client_handler, args=(client,))
            
            servercl.start()

    def read_file(self, fileName):
        f = open(self.filesDir + '/' + fileName, "r")
        data = f.readlines()
        f.close()
        data = "".join(data)
        #split file into chunks of size 200
        chunk_size=200
        chunks = [data[y-chunk_size:y] for y in range(chunk_size, len(data)+chunk_size,chunk_size)]
        return chunks

    def chunk(self, fileName):
        pass

    def client_handler(self, client_socket):
        msg = client_socket.recv(tcpBufferSize)
        print ("[*] Received request: ", msg)
        
         # bytes to string conversion
        msg = msg.decode("utf-8")  
    
        # convert the string to an array of fields
        # it uses comma as the delimeter 
        cmd = msg.split(',')
        
        #strip spaces in fields " RQ " -> "RQ"
        cmd = [field.strip() for field in cmd]

        #|DOWNLOAD| RQ# |File-name
        if len(cmd) != 3:
            try:
                reply = f"DOWNLOAD-ERROR, 0, Invalid command format"
                client_socket.sendall(reply.encode('utf-8'))
            except Exception as e:
                print('[exception]', e)
            return

        if cmd[0] == "DOWNLOAD":
            #|FILE |RQ# |File-name |Chunk# |Text
            fileName = cmd[2]
            try:
                chunks = self.read_file(fileName)

            except Exception as e:
                reply = f"DOWNLOAD-ERROR, 0, Filename {fileName} not present on client"
                client_socket.sendall(reply.encode('utf-8'))
                return
            ci = 0
            try:
                for chunk in chunks:
                    encryptedMSG=EncryptionDecryption.encryptionMessage(chunk,EncryptionDecryption.encryption,EncryptionDecryption.key)
                    if (ci+1 == len(chunks)):
                        #FILE-END|RQ# |File-name |Chunk# |Text
                        reply = f"FILE-END, 0, {fileName},{ci},{encryptedMSG}"
                    else:
                        reply = f"FILE, 0, {fileName},{ci},{encryptedMSG}"
                    client_socket.sendall(reply.encode('latin-1'))
                    read_or_timeout(client_socket, 'latin-1')
                    ci = ci + 1
            except Exception as e:
                reply = f"DOWNLOAD-ERROR, 0, Unknown Socket error"
                print("[exception-dl-155]", e)
                #client_socket.sendall(reply.encode('utf-8'))
        else:
            # |DOWNLOAD-ERROR|RQ#|Reason
            reply = f"DOWNLOAD-ERROR, 0, Unknown Invalid Command"
            client_socket.sendall(reply.encode('utf-8'))

        client_socket.close()

    def _read_files_from_dir(self, path):
        filesInPubDir = []
        with os.scandir(path=path) as i:
            for entry in i:
                if entry.is_file():
                    filesInPubDir.append(entry.name)
        return filesInPubDir
    

    def execServerCommand(self, cmd: list):
        client = self
        sock = self.svsock
        
        print(f"Executing sv:{cmd}")
        
        resp = None
        command = cmd[0]
        rq = cmd[1]

        if command == "REGISTER":
            resp = sendServerCommand(cmd, sock)
            if resp is None or len(resp) < 2:
                print('Invalid Responce', resp)
                return
            
            if resp[0] == "REGISTERED":
                client.isRegistered = True
                client.isAuthenticated = True
            else:
                client.isRegistered = False
        
        elif command == "AUTHENTICATE":
            resp = sendServerCommand(cmd, sock)
            if resp is None or len(resp) < 2:
                print('Invalid Responce', resp)
                return
            
            if resp[0] == "AUTHENTICATED":
                client.isAuthenticated = True
                client.isRegistered = True
            else:
                client.isAuthenticated = False

        elif command == "DE-REGISTER":
            resp = sendServerCommand(cmd, sock)
            client.isRegistered = False
        
        elif command == 'PUBLISH':
            resp = sendServerCommand(cmd, sock)
            if resp is None or len(resp) < 2:
                print('Invalid Responce', resp)
                return
            
            if resp[0] == "PUBLISHED":
                client.isPublished = True
            else:
                client.isPublished = False
        elif command in ["RETRIEVE", "RETRIEVE-INFOT", "SEARCH-FILE"]:
            resp = sendServerCommandEx(cmd, sock)
        else:
            resp = sendServerCommand(cmd, sock)
        
        return resp


    def searchFile(self, filename):
        
        resp = self.execServerCommand(['SEARCH-FILE', '0', filename])
        #['SEARCH-FILE', '0', ['Pub', '127.0.0.4', '6002', 'User Name', '127.0.0.0.1', '6001']]
        #or ['NOT-AUTHENTICATED', '0']
        
        if resp[0] == "NOT-AUTHENTICATED":
            print ("Download Error, Client not authenticated on the server")
            return (None, None, None)
        elif resp[0] == "SEARCH-ERROR":
            print (f"Download Error, File name {filename} not present on the server")
            return (None, None, None)
        try:
            #select random user from the search list
            user = random.randint(0, len(resp[2])/3-1)
            user = 0

            username = resp[2][user+0]
            ipaddress = resp[2][user+1]
            tcp = int(resp[2][user+2])

            return (ipaddress, tcp, username)
        except:
            return (None, None, None)


    def execDownloadCommand(self, cmd: list):
        client = self 
        svsock = self.svsock
        #DOWNLOAD, 0, Filename, (optional) ip, (optional) tcp
        print("Executing cl:", cmd)

        if cmd[0] == 'DOWNLOAD':
            filename = cmd[2]
            fileEnd = False
            
            try:
                # ip tcp params are in the command
                if len(cmd) == 5:
                    ipaddress = cmd[3]
                    tcp = int(cmd[4])
                    username = ""
                else:
                    #get the tcp port with a file search
                    ipaddress, tcp, username = self.searchFile(filename)

                dsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dsock.connect((ipaddress, tcp))            
            except Exception as e:
                print ("[exception-dl] Connection to remote,", e)
                return False

            print('DOWNLOADING', filename, f" at {ipaddress}:{tcp} from client {username}")
            f = open(client.downloadDIR+"/"+filename, 'w')
            try:
                request = f"DOWNLOAD, 0, {cmd[2]}"
                dsock.sendall(request.encode('utf-8'))
                while not fileEnd:
                    chunkresp = read_or_timeout(dsock, "latin-1")

                    chunk = chunkresp.decode("latin-1").split(',', 4)

                    print(chunk)
                    if chunk[0] == "DOWNLOAD-ERROR":
                        print ("download error", chunk)
                        break
                    if chunk[0] == "FILE-END":
                        fileEnd = True
                    dsock.sendall(f"File Chunk ACK {filename}".encode('latin-1'))
                    #FILE, 0, Common.txt, 0, text
                    text = chunk[4]
                    decryptedMSG=EncryptionDecryption.decryptionMessage(text,EncryptionDecryption.encryption,EncryptionDecryption.key)
                    f.write(decryptedMSG)

            except Exception as e:
                print("[download-dl]", e)
            
            dsock.close()        
            f.close()
        
        return fileEnd

#sends an sv command to the server address
# awaits the reply
# return a serialised response
def sendServerCommand(cmd: list, sock):
    msg = serializeCommand(cmd)

    print(f"Sending sv ({UDP_IP}:{UDP_PORT}):", msg)
    MESSAGE = str.encode(msg, 'utf-8') # str -> to bytes
    sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))
    resp = read_or_timeout(sock)
    if resp:
        resp = resp.decode('utf-8')
        print('Server responce:', resp)
        resp = parseServerMessage(resp)
        print('Server responce deserialized', resp)

    return resp

#RETRIEVE-ALL special case, possibly fragmented into multiple messages, terminated by \r\n control sequence
def sendServerCommandEx(cmd:list, sock):
    msg = serializeCommand(cmd)
    print(f"Sending sv ({UDP_IP}:{UDP_PORT}):", msg)
    MESSAGE = str.encode(msg, 'utf-8') # str -> to bytes
    sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))
    
    hasEndSeq = False #"\r\n"
    respAll = ""
    
    while not hasEndSeq:
        resp = read_or_timeout(sock)
        if resp:
            resp = resp.decode('utf-8')
            print('Server responce ex:', resp)
            if "\r\n" in resp:
                hasEndSeq = True
            respAll += resp
        else:
            hasEndSeq = True

    resp = parseServerMessage(respAll)
    print('Server responce deserialized', resp)

    return resp

#cl = Client()

cl = Client(CL_NAME, CL_ADDRESS, CL_UDP_PORT, CL_TCP_PORT, CL_PASSWORD, DIR, DOWNLOADS)
cl.start_listening_for_uploads()

def read_or_timeout(sock, codec="utf-8"):
    try:
        sock.settimeout(3.0)
        data = sock.recv(udpBufferSize)
        sock.settimeout(None)
        print('socket rx:', data.decode(codec))
        return data
    except Exception as e:
        print("[exception]", e)
        return None


if True:
    
    cl.execServerCommand(['AUTHENTICATE', '0', cl.Name, cl.password])
    #cl.execServerCommand(['DE-REGISTER', '0', cl.Name])
    
    if cl.isAuthenticated == False:
        cl.execServerCommand(['REGISTER', '1', cl.Name, cl.ipaddress, cl.udp, cl.tcp, cl.password])
 
    cl.execServerCommand(['UPDATE-CONTACT', '2', cl.Name, cl.password, cl.password, cl.ipaddress, cl.udp, cl.tcp])
    
    #retrieve files from download, published directories
    cl.filesInPubDir = cl._read_files_from_dir(cl.filesDir)
    cl.filesInDlDir = cl._read_files_from_dir(cl.downloadDIR)

    #publish files in the published directory
    cl.execServerCommand(['PUBLISH', '3', cl.Name, cl.filesInPubDir])
    resp = cl.execServerCommand(['RETRIEVE-INFOT', '4', cl.Name])
    
    try:
        publishedFiles = resp[5]
    except:
        publishedFiles = []

    print("Files in Publish Directory:", cl.filesInPubDir, "Client Files published on the sever:", publishedFiles)
    #['RETRIEVE', '0', [['Rain', '127.0.0.2', '6001', ['Rain1.txt', 'Rain2.txt']], ['Pub', '127.0.0.1', '6001', ['Pub1.txt', 'Common.txt', 'Pub2.txt']], ['User Name', '127.0.0.1', '6001', ['Common.txt', 'File name 1.txt', 'File name 3.txt', 'File name 2.txt']]]]
    
    try:
        publisedOnSvNotCl = list(set(publishedFiles)-set(cl.filesInPubDir)-set(['']))
        if (len(publisedOnSvNotCl)):
            print(f"Remove Files published but not on client: {publisedOnSvNotCl}")
            cl.execServerCommand(['REMOVE', '6', cl.Name, publisedOnSvNotCl])
    except:
        pass

    
    time.sleep(15)

    #DOWNLOAD ALL FILES PUBLISHED ON THE SERVER
    if True:
        resp = cl.execServerCommand(['RETRIEVE-ALL', '5'])
        if resp:
            for user in resp[2]:
                userName = user[0]
                ipaddress = user[1]
                tcp = user[2]
                for file in user[3]:
                    if file not in cl.filesInDlDir:
                        cl.execDownloadCommand(['DOWNLOAD', '0', file])#, ipaddress, tcp])
                        cl.filesInDlDir = cl._read_files_from_dir(cl.downloadDIR)
                    else:
                        print(f"The file {file} is already downloaed")

if False:
    #AUTHENTICATE A REGISTERED USER, fail if user is not registered
    cl.execServerCommand(['AUTHENTICATE', '0', 'Pub', 'pass1'])
    cl.execServerCommand(['DE-REGISTER', '0', 'Pub'])
    cl.execServerCommand(['REGISTER', '0', 'Pub', '127.0.0.1', '5001', '6001', 'pass1'])
    cl.execServerCommand(['PUBLISH', '0', 'Pub', ('Pub1.txt', 'Pub2.txt', "Common.txt")])
    
    cl.execServerCommand(['AUTHENTICATE', '0', 'Rain', 'pass2'])
    cl.execServerCommand(['DE-REGISTER', '0', 'Rain'])
    cl.execServerCommand(['REGISTER', '0', 'Rain', '127.0.0.2', '5001', '6001', 'pass2'])
    cl.execServerCommand(['PUBLISH', '0', 'Rain', ('Rain1.txt', 'Rain2.txt')])
    
    cl.execServerCommand(['AUTHENTICATE', '0', 'User Name', 'pass3'])
    cl.execServerCommand(['DE-REGISTER', '0', 'User Name'])
    cl.execServerCommand(['REGISTER', '0', 'User Name', '127.0.0.1', '5001', '6001', 'pass3'])
    cl.execServerCommand(['PUBLISH', '0', 'User Name', ('User name 1.txt', 'User name 2.txt', "Common.txt")])
    cl.execServerCommand(['PUBLISH', '0', 'User Name', ('User name 3.txt',)])
    
    
    #bigFileList = ["Filex "+str(x) for x in range(100)]
    #cl.execServerCommand(['PUBLISH', '0', 'Pub', bigFileList])
    #cl.execServerCommand(['REMOVE', '0', 'Pub', bigFileList])

    cl.execServerCommand(['UPDATE-CONTACT', '0', 'Pub', 'pass1', 'pass1', '127.0.0.1', '5001', '6001',])
    cl.execServerCommand(['UPDATE-CONTACT', '0', 'Rain', 'pass2', 'pass2', '127.0.0.2', '5001', '6001',])
    cl.execServerCommand(['UPDATE-CONTACT', '0', 'User Name', 'pass3', 'pass3', '127.0.0.3', '5001', '6001',])

    cl.execServerCommand(['RETRIEVE-ALL', '0'])
    cl.execServerCommand(['RETRIEVE-INFOT', '0', 'User Name'])
    #resp = cl.execServerCommand(['SEARCH-FILE', '0', 'Common.txt'])

    cl.execServerCommand(['REMOVE', '0', 'Pub', ("Common.txt",)])

    cl.execServerCommand(['SEARCH-FILE', '0', 'Common.txt'])
    #cl.execDownloadCommand(['DOWNLOAD', '0', 'Common.txt', '192.168.43.202', '6001'])
    cl.execDownloadCommand(['DOWNLOAD', '0', 'Common.txt'])
    
    cl.execServerCommand(['AUTHENTICATE', '0', cl.Name, cl.password])

while True:
    line = input(">>>")
    
    cmd = parseUserMessage(line)
    
    if cmd is None or len(cmd) < 2:
        print("Invalid command", cmd)
        continue
    elif cmd[0] == "DOWNLOAD":
        cl.execDownloadCommand(cmd)
    else:
        cl.execServerCommand(cmd)
    
    #MESSAGE = str.encode(line, 'utf-8') # str -> to bytes
    #sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))
    #read_or_timeout(sock)
