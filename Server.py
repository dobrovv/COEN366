#https://pythontic.com/modules/socket/udp-client-server-example
#https://stackoverflow.com/questions/31350267/python-server-only-working-on-local-wifi
import socket
from ServerClientsStore import *
from MessageParser import *
from ipaddress import getIPAddress
from inputChecker import *

print("\nInitializing server...")
serverIP     = getIPAddress()
serverPort   = 3000
bufferSize   = 1024*4

print("\nServer initialization complete. IP Address is ", serverIP)
print("UDP port: ", serverPort)
print("")
serverClients = ServerClientsStore()
print("")

def serverResponse(reply, address):
    print("[Response >>>]", reply.encode('utf-8'))
    #UDPServerSocket.sendto(reply.encode('utf-8'), address)

def executeClientCommand(cmd:list, address:tuple):
    print("[Checking >>>]", cmd, "from", address)

    if len(cmd) < 1:
        return
    command = cmd[0] # command is always the first field
    try: # get the RQ number
        RQ = cmd[1]
    except:
        RQ = 0    
    rqUserName = "Unknown"

    if inputChecker.checkClientMessage(cmd):

        if command not in ["AUTHENTICATE", "REGISTER", "CHECK-NAME", "CHECK-PASS", "CHECK-IP", "CHECK-UDP", "CHECK-TCP"]:
            status = serverClients.isAuthenticated(ipaddress=address[0], udp=address[1])        
            if not status.valid:
                print("[Not Authenticated] ", cmd, "address", address)
                reply = f"NOT-AUTHENTICATED, {RQ}, Address Not Authenticated"
                serverResponse(reply,address)
                UDPServerSocket.sendto(reply.encode('utf-8'), address)  
                return
        
            rqUserName = status.error # fetch the client name from the auth
            print("[Authenticated] address", address, "as", rqUserName)
    
        #Special commands to check for existing usernames, passwords, IP addresses, UDP ports and TCP ports during registration
        if command in ["CHECK-NAME", "CHECK-PASS", "CHECK-IP", "CHECK-UDP", "CHECK-TCP"]:
            try:
                param = cmd[2]
                if command == "CHECK-NAME":
                    if serverClients.isRegistered(param):
                        print("[ERROR] ", cmd, "address", address, f"The name {param} is already in use by another client.")
                        reply = f"NAME-ERROR, The name {param} is already in use by another client."
                        serverResponse(reply,address)
                        UDPServerSocket.sendto(reply.encode('utf-8'), address)
                        return
                    else:
                        print("[NAME-CONFIRM] ", cmd, "address", address, f"Name {param} is available.")
                        reply = f"NAME-CONFIRM, Name {param} is available."
                        serverResponse(reply,address)
                        UDPServerSocket.sendto(reply.encode('utf-8'), address)
                        return
                elif command == "CHECK-IP":
                    if serverClients.checkIPAddress(param):
                        print("[ERROR] ", cmd, "address", address, f"The IP address {param} is already in use by another client.")
                        reply = f"IP-ERROR, The IP address {param} is already in use by another client."
                        serverResponse(reply,address)
                        UDPServerSocket.sendto(reply.encode('utf-8'), address)
                        return
                    else:
                        print("[IP-CONFIRM] ", cmd, "address", address, f"IP address {param} is available.")
                        reply = f"IP-CONFIRM, IP address {param} is available."
                        serverResponse(reply,address)
                        UDPServerSocket.sendto(reply.encode('utf-8'), address)
                        return
                elif command == "CHECK-PASS":
                    if serverClients.checkPassword(param):
                        print("[ERROR] ", cmd, "address", address, f"The password entered is already in use by another client.")
                        reply = f"PASSWORD-ERROR, The password entered is already in use by another client."
                        serverResponse(reply,address)
                        UDPServerSocket.sendto(reply.encode('utf-8'), address)
                        return
                    else:
                        print("[PASSWORD-CONFIRM] ", cmd, "address", address, f"The provided password is available.")
                        reply = f"PASSWORD-CONFIRM, The provided password is available."
                        serverResponse(reply,address)
                        UDPServerSocket.sendto(reply.encode('utf-8'), address)
                        return
                elif command == "CHECK-UDP":
                    if serverClients.checkUDPPort(param):
                        print("[ERROR] ", cmd, "address", address, f"UDP port {param} is already in use by another client.")
                        reply = f"UDP-ERROR, UDP port {param} is already in use by another client."
                        serverResponse(reply,address)
                        UDPServerSocket.sendto(reply.encode('utf-8'), address)
                        return
                    else:
                        print("[UDP-CONFIRM] ", cmd, "address", address, f"UDP port {param} is available.")
                        reply = f"UDP-CONFIRM, UDP port {param} is available."
                        serverResponse(reply,address)
                        UDPServerSocket.sendto(reply.encode('utf-8'), address)
                        return
                else:
                    if serverClients.checkTCPPort(param):
                        print("[ERROR] ", cmd, "address", address, f"TCP port {param} is already in use by another client.")
                        reply = f"TCP-ERROR, TCP port {param} is already in use by another client."
                        serverResponse(reply,address)
                        UDPServerSocket.sendto(reply.encode('utf-8'), address)
                        return
                    else:
                        print("[TCP-CONFIRM] ", cmd, "address", address, f"TCP port {param} is available.")
                        reply = f"TCP-CONFIRM, TCP port {param} is available."
                        serverResponse(reply,address)
                        UDPServerSocket.sendto(reply.encode('utf-8'), address)
                        return
            except Exception as e:
                print("exception-64", e)
    
        # check the name of the request is the name of the authenticated user
        if command in ["PUBLISH", "REMOVE", "DE-REGISTER"]:
            try:
                Name = cmd[2]
                if Name != rqUserName:
                    print("[Not Authenticated] ", cmd, "address", address, f"The name in the request {Name} doesn't match the autheticated user {rqUserName}")
                    reply = f"NOT-AUTHENTICATED, {RQ}, The name in the request {Name} doesn't match the autheticated user {rqUserName}"
                    serverResponse(reply,address)
                    UDPServerSocket.sendto(reply.encode('utf-8'), address)
                    return
            except Exception as e:
                print("exception-64", e)

        if command == "AUTHENTICATE":
        # |AUTHENTICATE|RQ#|Name|password|
            if len(cmd) == 4:
                status = serverClients.authenticate(Name=cmd[2], password=cmd[3], ipaddress=address[0], udp=str(address[1]))
                if status.valid:
                    reply = f"AUTHENTICATED, {RQ}"
                else:
                    reply = f"NOT-AUTHENTICATED, {RQ}, {status.error}"
            else:
                reply = f"NOT-AUTHENTICATED, {RQ}, Incorrect number of parameters specified."
            serverResponse(reply,address)
            UDPServerSocket.sendto(reply.encode('utf-8'), address)

        elif command == "REGISTER":
        # |REGISTER|RQ#|Name|password|IP Address|UDP socket#|TCP socket#
            if len(cmd) == 7:
                status = serverClients.register(Name=cmd[2], ipaddress=cmd[4], udp=cmd[5], tcp=cmd[6], password=cmd[3])
                if status.valid:
                    reply = f"REGISTERED, {RQ}"
                    statusAuth = serverClients.authenticate(Name=cmd[2], password=cmd[3], ipaddress=address[0], udp=str(address[1]))
                    if not statusAuth.valid:
                        reply = f"REGISTER-DENIED, {RQ}, Not Authenticated"
                else:
                    reply = f"REGISTER-DENIED, {RQ}, {status.error}"
            else:
                reply = f"REGISTER-DENIED, {RQ}, Incorrect number of parameters specified."
            serverResponse(reply,address)
            UDPServerSocket.sendto(reply.encode('utf-8'), address)
    
        elif command == "UPDATE-CONTACT":
            if len(cmd) == 9:
                status = serverClients.update_contact(Name=cmd[2], old_pwd=cmd[3], password=cmd[4], ipaddress=cmd[5], udp=cmd[6], tcp=cmd[7], clientIP=cmd[8])
                if status.valid:
                    reply = f"UPDATE-CONFIRMED, {RQ}, {cmd[2]}, {cmd[5]}, {cmd[6]}, {cmd[7]} "
                else:
                    reply = f"UPDATE-DENIED, {RQ}, {cmd[2]}, {status.error}"
            else:
                reply = f"UPDATE-DENIED, {RQ}, Incorrect number of parameters specified."
            serverResponse(reply,address)
            UDPServerSocket.sendto(reply.encode('utf-8'), address)
    
        elif command == "PUBLISH":
        # |PUBLISH|RQ#|Name|List of files|
        
            if len(cmd) > 3:
                print("List of files:", cmd[3])
                status = serverClients.publish(Name=cmd[2], listOfFiles=cmd[3])

                if status.valid:
                    reply = f"PUBLISHED, {RQ}"
                else:
                    reply = f"PUBLISH-DENIED, {RQ}, {status.error}"
            elif len(cmd) == 3:
                reply = f"PUBLISH-DENIED, {RQ}, No list of files specified."
            else:
                reply = f"PUBLISH-DENIED, {RQ}, Incorrect number of parameters specified."
            serverResponse(reply,address)
            UDPServerSocket.sendto(reply.encode('utf-8'), address)
    
        elif command == "REMOVE":
        # |REMOVE|RQ#|Name|List of files|
        
            if len(cmd) > 3:
                print("List of files:", cmd[3])
                status = serverClients.remove(Name=cmd[2], listOfFiles=cmd[3])

                if status.valid:
                    reply = f"REMOVED, {RQ}"
                else:
                    reply = f"REMOVE-DENIED, {RQ}, {status.error}"
            elif len(cmd) == 3:
                reply = f"REMOVE-DENIED, {RQ}, No list of files specified."
            else:
                reply = f"REMOVE-DENIED, {RQ}, Incorrect number of parameters specified."
            serverResponse(reply,address)
            UDPServerSocket.sendto(reply.encode('utf-8'), address)
    
        elif command == "RETRIEVE-ALL":
        # |RETRIEVE-ALL|RQ#|
        
        # check if request is coming from a registered address
            if True: #serverClients.isRegisteredAddress(address):
                listRetrieved = serverClients.retrieve_all()
                reply = serializeCommand(["RETRIEVE", f"{RQ}", listRetrieved])
                #reply += "\r\n"
                serverResponse(reply,address)
                UDPServerSocket.sendto(reply.encode('utf-8'), address)
            else:
                print(f"warning {address} is not the address of any registered client")
                reply = f"Warning: This client is not registered on the server."
                UDPServerSocket.sendto(reply.encode('utf-8'), address)
     
        elif command == "RETRIEVE-INFOT":
        # |RETRIEVE-INFO|RQ#|NAME|
            if len(cmd) != 3:
                reply = f"RETRIEVE-ERROR, {RQ}, Incorrect number of parameters specified."
                serverResponse(reply,address)
                UDPServerSocket.sendto(reply.encode('utf-8'), address)
            else:
                info = serverClients.retrieve_infot(cmd[2])
                if info is None:
                    reply = f"RETRIEVE-ERROR, {RQ}, The requested username does not exist."
                    serverResponse(reply,address)
                    UDPServerSocket.sendto(reply.encode('utf-8'), address)
                else:
                    reply = serializeCommand(["RETRIEVE-INFOT", f"{RQ}", info[0], info[1], info[2], info[3]])
                    reply += "\r\n"
                    serverResponse(reply,address)
                    UDPServerSocket.sendto(reply.encode('utf-8'), address)

        elif command == "DE-REGISTER":
        # |DE-REGISTER|RQ#|Name|
            status = serverClients.deregister(Name=cmd[2])
            if status.valid:
                reply = f"DE-REGISTERED, {RQ}"
                serverResponse(reply,address)
                UDPServerSocket.sendto(reply.encode('utf-8'), address)
            else:
                print(f"warning: deregister name={cmd[2]} doesn't exist")
    
        elif command == "SEARCH-FILE":
        # |SEARCH-FILE|RQ#|FILENAME|
            if len(cmd) != 3:
                reply = f"SEARCH-ERROR, {RQ}, Incorrect number of parameters specified."
                serverResponse(reply,address)
                UDPServerSocket.sendto(reply.encode('utf-8'), address)
            else:
                info = serverClients.search(cmd[2])
                if info is None or len(info) == 0:
                    reply = f"SEARCH-ERROR, {RQ}, The requested file is not registered to any clients."
                    serverResponse(reply,address)
                    UDPServerSocket.sendto(reply.encode('utf-8'), address)
                else:
                    reply = serializeCommand(["SEARCH-FILE", f"{RQ}", list(chain.from_iterable(info))])
                    reply += "\r\n"
                    serverResponse(reply,address)
                    UDPServerSocket.sendto(reply.encode('utf-8'), address)
        
        else:
            reply= f"ERROR, {RQ}, Unknown/Invalid Command {cmd}"
            print(f"Unknown/invalid command: {cmd}")
            serverResponse(reply,address)
            UDPServerSocket.sendto(reply.encode('utf-8'), address)
    else:
        reply= f"ERROR, {RQ}, Command error: {cmd} Validation: {inputChecker.lastErrorMessage}"
        print(f"Command error: {cmd}, Validation: {inputChecker.lastErrorMessage}")
        serverResponse(reply,address)
        UDPServerSocket.sendto(reply.encode('utf-8'), address)


# Create a UDP datagram socket
UDPServerSocket = socket.socket(
    family=socket.AF_INET, # Internet
    type=socket.SOCK_DGRAM # UDP
)

# Bind to address and ip
bindSuccess = 0
retries = 3
while bindSuccess == 0:
    try:
        UDPServerSocket.bind( (serverIP, serverPort) )
        serverIP = UDPServerSocket.getsockname()[0]
        serverPort = UDPServerSocket.getsockname()[1]
        bindSuccess = 1
    except Exception as e:
        print("Exception: ", e)
        if retries > 0:
            tryAgain = input(f"Press Enter key to try again. Retries remaining : {retries}")
            retries = retries - 1
        else:
            print("Unable to bind UDP server socket. Exiting...")
            quit()

# Listen and process incoming datagrams
while(True):
    #read a message from the socket when availabla
    try:
        bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
        message = bytesAddressPair[0]
        address = bytesAddressPair[1]
    except Exception as e:
        print("Message Rx Exception ", e)
        continue
    
    print(f"\n[>>>] ({address[0]}:{address[1]}) msg: {message}")
    
    serverClients.resync_authentication_times()

    #cmd = decodeClientMessage(message)
    
    # bytes to string conversion
    message = message.decode('utf-8')
    
    #converts a raw message into an array of fields, cmd = (field1, field2, field3, ...)
    cmd = parseUserMessage(message, False)

    if cmd is None:
        reply= f"ERROR, 0, Unknown/Invalid Command"
        print(f"Invalid/Unknown Command:", message)
        UDPServerSocket.sendto(reply.encode('utf-8'), address)
        continue
    
    # processes the received command cmd at the ip address 
    executeClientCommand(cmd, address)
