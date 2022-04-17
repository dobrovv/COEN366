import os, socket, threading, time, random
from MessageParser import *
from ipaddress import getIPAddress
from inputChecker import *
from keyGenerator import *

print("Initializing client...")
CL_ADDRESS = getIPAddress()
CL_NAME = "P2P Client"
CL_PASSWORD = "P2P pass"
DIR = "Published"
DOWNLOADS = "Downloads"
udpBufferSize = 1024*4
tcpBufferSize = 1024*4 
requestNum = 0

#Server parameters (fixed port, user-input IP address)
serverIP = input("Please enter the IP address of the server: ")
while not inputChecker.checkIPAddress(serverIP):
    serverIP = input("Please enter the IP address of the server: ")
UDP_PORT = 3000
client_UDP = input("Please enter the desired UDP port [4000, 5999]: ")
while not inputChecker.checkUDP(client_UDP):
    client_UDP = input("Please enter the desired UDP port: ")
client_TCP = input("Please enter the desired TCP port [6000, 7999]: ")
while not inputChecker.checkTCP(client_TCP):
    client_TCP = input("Please enter the desired TCP port: ")

#CL_NAME = input("Please enter the name of the client: ")
#while not inputChecker.checkName(CL_NAME):
#    CL_NAME = input("Please enter the name of the client: ")

print("\nUDP target IP:", serverIP)
print("UDP target port:", UDP_PORT)
print("\nUDP source IP:", CL_ADDRESS)
print("UDP source port:", client_UDP)
print(" ")

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
                print(f"Can't bind server udp socket to {(self.ipaddress, self.udp)} retrying...")
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
        print (f"The client is up and listens at {self.ipaddress}:{self.tcp} for upload requests\n")

        while True:
            client, addr = server.accept()
            print(f"[*] Accepted connection from: {addr[0]}:{addr[1]}")
            servercl = threading.Thread(target=self.client_handler, args=(client,))
            
            servercl.start()
    
    def get_client_IP_address(self,):
        return self.ipaddress
    
    def set_client_UDP_port(self, udp):
        self.udp = int(udp)
        self.svsock.close()
        self.svsock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
        for i in range(32):
            try:
                self.svsock.bind(('', self.udp)) # only the port number is set
                break
            except Exception as e:
                print(f"Can't bind server udp socket to {(self.ipaddress, self.udp)} retrying...")
                self.udp = self.udp + 1
    
    def get_client_UDP_port(self,):
        return self.udp
    
    def get_client_TCP_port(self,):
        return self.tcp

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

        #Obtain request number from command 1
        rq = cmd[1]

        #|DOWNLOAD| RQ# |File-name
        if len(cmd) != 3:
            try:
                reply = f"DOWNLOAD-ERROR, {rq}, Invalid command format"
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
                reply = f"DOWNLOAD-ERROR, {rq}, Filename {fileName} not present on client"
                client_socket.sendall(reply.encode('utf-8'))
                return
            ci = 0
            try:
                for chunk in chunks:
                    encryptedMSG=EncryptionDecryption.encryptionMessage(chunk,EncryptionDecryption.encryption,EncryptionDecryption.key)
                    if (ci+1 == len(chunks)):
                        #FILE-END|RQ# |File-name |Chunk# |Text
                        reply = f"FILE-END, {rq}, {fileName},{ci},{encryptedMSG}"
                    else:
                        reply = f"FILE, {rq}, {fileName},{ci},{encryptedMSG}"
                    client_socket.sendall(reply.encode('latin-1'))
                    read_or_timeout(client_socket, 'latin-1')
                    ci = ci + 1
            except Exception as e:
                reply = f"DOWNLOAD-ERROR, {rq}, Unknown Socket error"
                print("[exception-dl-155]", e)
                #client_socket.sendall(reply.encode('utf-8'))
        else:
            # |DOWNLOAD-ERROR|RQ#|Reason
            reply = f"DOWNLOAD-ERROR, {rq}, Unknown Invalid Command"
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
                print('Invalid response', resp)
                return
            
            if resp[0] == "REGISTERED":
                client.isRegistered = True
                client.isAuthenticated = True
                client.Name = cmd[2]
            else:
                client.isRegistered = False
                client.isAuthenticated = False
        
        elif command == "AUTHENTICATE":
            resp = sendServerCommand(cmd, sock)
            if resp is None or len(resp) < 2:
                print('Invalid response', resp)
                return
            
            if resp[0] == "AUTHENTICATED":
                client.isAuthenticated = True
                client.isRegistered = True
                client.Name = cmd[2]
            else:
                client.isAuthenticated = False
                
        elif command == "UPDATE-CONTACT":
            resp = sendServerCommand(cmd, sock)
            if resp is None or len(resp) < 2:
                print('Invalid response', resp)
                return
            
            if resp[0] == "UPDATE-CONFIRMED":
                client.set_client_UDP_port(cmd[6])
        
        elif command == "CHECK-NAME":
            resp = sendServerCommand(cmd, sock)
            if resp is None or len(resp) < 2:
                print('CHECK-NAME : Invalid response', resp)
                return
            
            if resp[0] == "NAME-CONFIRM":
                print("Name confirmed")
            else:
                print("Name error")

        elif command == "CHECK-IP":
            resp = sendServerCommand(cmd, sock)
            if resp is None or len(resp) < 2:
                print('CHECK-IP : Invalid response', resp)
                return
            
            if resp[0] == "IP-CONFIRM":
                print("IP confirmed")
            else:
                print("IP error")

        elif command == "CHECK-UDP":
            resp = sendServerCommand(cmd, sock)
            if resp is None or len(resp) < 2:
                print('CHECK-UDP : Invalid response', resp)
                return
            
            if resp[0] == "UDP-CONFIRM":
                print("UDP confirmed")
            else:
                print("UDP error")

        elif command == "CHECK-TCP":
            resp = sendServerCommand(cmd, sock)
            if resp is None or len(resp) < 2:
                print('CHECK-TCP : Invalid response', resp)
                return
            
            if resp[0] == "TCP-CONFIRM":
                print("TCP confirmed")
            else:
                print("TCP error")

        else:
            if command == "DE-REGISTER":
                resp = sendServerCommand(cmd, sock)
                if(resp[0] == "DE-REGISTERED"):
                    client.Name = CL_NAME
                    client.isRegistered = False
                    client.isAuthenticated = False

            elif command == 'PUBLISH':
                try:
                    for i in range(0, len(cmd[3])):
                        file = open(client.filesDir+"/"+cmd[3][i])
                    resp = sendServerCommand(cmd, sock)
                    if resp is None or len(resp) < 2:
                        print('Invalid response', resp)
                        return

                    if resp[0] == "PUBLISHED":
                        client.isPublished = True
                    else:
                        client.isPublished = False
                except IOError:
                    print("ERROR: One or more files specified does not exist on the local PC.")

            elif command in ["RETRIEVE", "RETRIEVE-INFOT", "SEARCH-FILE"]:
                resp = sendServerCommandEx(cmd, sock)
            else:
                resp = sendServerCommand(cmd, sock)
        
        return resp


    def searchFile(self, filename):
        
        resp = self.execServerCommand(['SEARCH-FILE', f'{requestNum}', filename])
        #['SEARCH-FILE', '0', ['Pub', '127.0.0.4', '6002', 'User Name', '127.0.0.0.1', '6001']]
        #or ['NOT-AUTHENTICATED', '0']
        
        if resp[0] == "NOT-AUTHENTICATED":
            print ("Download Error, Client not authenticated on the server")
            return (None, None, None, False)
        elif resp[0] == "SEARCH-ERROR":
            print (f"Download Error, File name {filename} not present on the server")
            return (None, None, None, False)
        try:
            #select random user from the search list
            user = random.randint(0, len(resp[2])/3-1)
            user = 0

            username = resp[2][user+0]
            ipaddress = resp[2][user+1]
            tcp = int(resp[2][user+2])

            return (ipaddress, tcp, username, True)
        except:
            return (None, None, None, False)


    def execDownloadCommand(self, cmd: list):
        client = self 
        svsock = self.svsock
        fileEnd = False
        downloadAuthorized = False
        clUsername = ""
        clPassword = ""
        #DOWNLOAD, 0, Filename, (optional) ip, (optional) tcp
        print("Executing cl:", cmd)

        if cmd[0] == 'DOWNLOAD':
            filename = cmd[2]
            if filename is not None:
                try:
                    # ip tcp params are in the command
                    if len(cmd) == 7:
                        ipaddress = cmd[3]
                        tcp = int(cmd[4])
                        username = ""
                        clUsername = cmd[5]
                        clPassword = cmd[6]
                        auth = self.execServerCommand(['AUTHENTICATE', f'{requestNum}', clUsername, clPassword])
                        if auth[0] == "AUTHENTICATED":
                            downloadAuthorized = True
                        else:
                            downloadAuthorized = False
                    else:
                        #get the tcp port with a file search
                        ipaddress, tcp, username, auth = self.searchFile(filename)
                        if auth:
                            downloadAuthorized = True
                        else:
                            downloadAuthorized = False

                    if ipaddress != self.ipaddress and downloadAuthorized:
                        dsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        dsock.connect((ipaddress, tcp))            
                except Exception as e:
                    print ("[exception-dl] Connection to remote,", e)
                    return False
                
                if downloadAuthorized:
                    if ipaddress != self.ipaddress:
                        print('DOWNLOADING', filename, f" at {ipaddress} : {tcp} from client {username}")
                        f = open(client.downloadDIR+"/"+filename, 'w')
                        try:
                            request = f"DOWNLOAD, {requestNum}, {cmd[2]}"
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
                    else:
                        print(f"DOWNLOAD-ERROR, {requestNum}, Source and destination clients are the same.")
                else:
                    print(f"DOWNLOAD-ERROR, {requestNum}, Incorrect username/password or unauthorized to download files.")
            else:
                print(f"DOWNLOAD-ERROR, {requestNum}, Incorrect username/password or unauthorized to download files.")
        return fileEnd

#sends an sv command to the server address
# awaits the reply
# return a serialised response
def sendServerCommand(cmd: list, sock):
    msg = serializeCommand(cmd)

    print(f"Sending sv ({serverIP}:{UDP_PORT}):", msg)
    MESSAGE = str.encode(msg, 'utf-8') # str -> to bytes
    sock.sendto(MESSAGE, (serverIP, UDP_PORT))
    resp = read_or_timeout(sock)
    if resp:
        resp = resp.decode('utf-8')
        print('Server response:', resp)
        resp = parseServerMessage(resp)
        print('Server response deserialized', resp)

    return resp

#RETRIEVE-ALL special case, possibly fragmented into multiple messages, terminated by \r\n control sequence
def sendServerCommandEx(cmd:list, sock):
    msg = serializeCommand(cmd)
    print(f"Sending sv ({serverIP}:{UDP_PORT}):", msg)
    MESSAGE = str.encode(msg, 'utf-8') # str -> to bytes
    sock.sendto(MESSAGE, (serverIP, UDP_PORT))
    
    hasEndSeq = False #"\r\n"
    respAll = ""
    
    while not hasEndSeq:
        resp = read_or_timeout(sock)
        if resp:
            resp = resp.decode('utf-8')
            print('Server response ex:', resp)
            if "\r\n" in resp:
                hasEndSeq = True
            respAll += resp
        else:
            hasEndSeq = True

    resp = parseServerMessage(respAll)
    print('Server response deserialized', resp)

    return resp

#cl = Client()

cl = Client(CL_NAME, CL_ADDRESS, int(client_UDP), int(client_TCP), CL_PASSWORD, DIR, DOWNLOADS)
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

#Debug code for automated testing
if False:
    
    cl.execServerCommand(['AUTHENTICATE', '0', cl.Name, cl.password])
    #cl.execServerCommand(['DE-REGISTER', '0', cl.Name])
    
    if cl.isAuthenticated == False:
        cl.execServerCommand(['REGISTER', '1', cl.Name, cl.password, cl.ipaddress, cl.udp, cl.tcp, ])
 
    cl.execServerCommand(['UPDATE-CONTACT', '2', cl.Name, cl.password, cl.password, cl.ipaddress, cl.udp, cl.tcp])
    cl.execServerCommand(['AUTHENTICATE', '0', cl.Name, cl.password])
    
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
    if False:
        resp = cl.execServerCommand(['RETRIEVE-ALL', '5'])
        if resp:
            for user in resp[2]:
                userName = user[0]
                ipaddress = user[1]
                tcp = user[2]
                for file in user[3]:
                    if file not in cl.filesInDlDir and cl.Name != userName:
                        cl.execDownloadCommand(['DOWNLOAD', '0', file])#, ipaddress, tcp])
                        cl.filesInDlDir = cl._read_files_from_dir(cl.downloadDIR)
                    else:
                        print(f"The file {file} is already downloaded")

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
#End debug code

while True:
    
    if cl.isRegistered:
        line = input(f"\n[{cl.Name}]>>>")
    else:
        line = input("\n>>>")
    
    cmd = parseUserMessage(line, True)
    
    if cmd is None or len(cmd) < 1 or cmd[0] == "RETRIEVE":
        print("Invalid command", cmd)
        continue
    elif cmd[0] == "REGISTER": #Insert IP address, UDP port and TCP port directly
        cmd.insert(1, f'{requestNum}')
        cmd.insert(4, f'{cl.get_client_IP_address()}')
        cmd.insert(5, f'{cl.get_client_UDP_port()}')
        cmd.insert(6, f'{cl.get_client_TCP_port()}')
        cl.execServerCommand(cmd)
        requestNum = requestNum + 1
    elif cmd[0] == "UPDATE-CONTACT": #Insert client IP address for verifictation with the server
        cmd.insert(1, f'{requestNum}')
        cmd.insert(8, f'{cl.get_client_IP_address()}')
        cl.execServerCommand(cmd)
        requestNum = requestNum + 1
    elif cmd[0] == "DOWNLOAD":
        cmd.insert(1, f'{requestNum}')
        if len(cmd) < 3: #Special case to deal with accidental inputs of a plain DOWNLOAD command
            cmd.insert(2, "")
        cl.execDownloadCommand(cmd)
        requestNum = requestNum + 1
    elif cmd[0] == "PUBLISH" or cmd[0] == "REMOVE":
        cmd.insert(1, f'{requestNum}')
        cmd.insert(2, f'{cl.Name}')
        cl.execServerCommand(cmd)
        requestNum = requestNum + 1
    else:
        cmd.insert(1, f'{requestNum}')
        if cmd[0] == "RETRIEVE" and len(cmd) < 3: #Special case to deal with accidental inputs of a plain RETRIEVE command
            cmd.insert(2, "")
        cl.execServerCommand(cmd)
        requestNum = requestNum + 1
    
    #MESSAGE = str.encode(line, 'utf-8') # str -> to bytes
    #sock.sendto(MESSAGE, (serverIP, UDP_PORT))
    #read_or_timeout(sock)
