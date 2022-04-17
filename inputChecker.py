
def setError(msg):
    inputChecker.lastErrorMessage = msg

class inputChecker:
    lastErrorMessage=""

    def checkRQ(RQnumber):
        
        validatedRQnum = ""
        check = False
        if RQnumber.isnumeric():
            validatedRQnum = RQnumber
            check = True
        else:
            print("RQ number should contain only digits.")
            setError("RQ number should contain only digits.")
            check = False
        return check

    def checkName(name):
        
        validatedName = ""
        check = False

        if len(name) < 3:
            print(" Username is too short (minimum 3 characters)")
            setError("Username is too short (minimum 3 characters)")
            return check

        if all(x.isalnum() or x.isspace() for x in name):
            validatedName = name
            check = True
        else:
            print("NAME should contain only alphanumeric characters.")
            setError("NAME should contain only alphanumeric characters.")
            check = False
        return check
    
    def checkPassword(password):
        check = False
        
        if len(password) < 8:
            print("Password is too short (minimum 8 characters)")
            setError("Password is too short (minimum 8 characters)")
            return check

        if all(x.isalnum() for x in password):
            validatedName = password
            check = True
        else:
            print("PASSWORD should contain only alphanumeric characters.")
            setError("PASSWORD should contain only alphanumeric characters.")
            check = False
        return check

    def checkIPAddress(ipAddress):
       
        checkIP = ipAddress.split(".")
        validatedIP = ""
        check = False
            
        if len(checkIP) == 4:
            i = 0
            while i < 4:

                if checkIP[i].isnumeric():
                    num = checkIP[i]
                    
                    if (0 <= int(num) <= 255):
                        check = True
                    else:
                        print("IP address is out of range.")
                        setError("IP address is out of range.")
                        check = False
                        break
                else:
                    print("IP address should contain only digits.")
                    setError("IP address should contain only digits.")
                    check = False
                    break
                i += 1
        else:
            print("IP address format is incorrect.")
            setError("IP address format is incorrect.")
            check = False
        if check:
            validatedIP = ipAddress
        
        return check

    def checkUDP(UDPsocket):
        
        validatedUDP = ""
        check = False

        if UDPsocket.isnumeric():
    
            if (4000 <= int(UDPsocket) <= 5999):
                    validatedUDP = UDPsocket
                    check = True
            else:
                print("UDP socket number is out of range. [4000, 5999]")
                setError("UDP socket number is out of range. [4000, 5999]")
                check = False
        else:
            print("UDP socket number should contain only digits.")
            setError("UDP socket number should contain only digits.")
            check = False
        return check

    def checkTCP(TCPsocket):
        
        validatedTCP = ""
        check = False

        if TCPsocket.isnumeric():

            if (6000 <= int(TCPsocket) <= 7999):
                validatedTCP = TCPsocket
                check = True
            else:
                print("TCP socket number is out of range. [6000, 7999]")
                setError("TCP socket number is out of range. [6000, 7999]")
                check = False
        else:
            print("TCP socket number should contain only digits.")
            setError("TCP socket number is out of range. [6000, 7999]")
            check = False
        return check

    def checkClientMessage(msg:bytes):
        #msg = msg.decode("utf-8")

        #msg = msg.replace(" ","")
        #msg = msg.split(',')

        check = False
        validatedMSG = ""
        
        if msg[0]=="REGISTER":
            if len(msg) == 7:
                if inputChecker.checkRQ(msg[1]):
                    #print(msg[1])
                    #print(inputChecker.checkRQ(msg[1]))
                    #print("RG checked")
                    check = True
                    if inputChecker.checkName(msg[2]):
                        #print("NAME checked")
                        check = True
                        if inputChecker.checkIPAddress(msg[4]):
                            #print("IP ADDRESS checked")
                            check = True
                            if inputChecker.checkUDP(msg[5]):
                                #print("UDP checked")
                                check = True
                                if inputChecker.checkTCP(msg[6]):
                                    #print("TCP checked")
                                    check = True
                                    if inputChecker.checkPassword(msg[3]):
                                        #print("pass checked")
                                        check = True
                                    else:
                                        check = False
                                else:
                                    check = False
                            else:
                                check = False
                        else:
                            check = False
                    else:
                        check = False
                else:
                    check = False
            
            else:
                validatedMSG = "Wrong format"
                setError(validatedMSG)
                check = False
            
            if check:
                #print(msg)
                validatedMSG = msg
        
        elif msg[0]=="UPDATE-CONTACT":
            if len(msg) == 9:
                if inputChecker.checkRQ(msg[1]):
                    #print(msg[1])
                    #print(inputChecker.checkRQ(msg[1]))
                    #print("RG checked")
                    check = True
                    if inputChecker.checkName(msg[2]):
                        #print("NAME checked")
                        check = True
                        if inputChecker.checkIPAddress(msg[5]):
                            #print("IP ADDRESS checked")
                            check = True
                            if inputChecker.checkUDP(msg[6]):
                                #print("UDP checked")
                                check = True
                                if inputChecker.checkTCP(msg[7]):
                                    #print("TCP checked")
                                    check = True
                                    if inputChecker.checkIPAddress(msg[8]):
                                        check = True
                                    else:
                                        check = False
                                else:
                                    check = False
                            else:
                                check = False
                        else:
                            check = False
                    else:
                        check = False
                else:
                    check = False
                
                if inputChecker.checkPassword(msg[4]):
                    check = True
                else:
                    check = False

            else:
                validatedMSG = "Wrong format"
                setError(validatedMSG)
                check = False
            if check:
                #print(msg)
                validatedMSG = msg

        elif msg[0]=="DE-REGISTER" or msg[0]=="RETRIEVE-INFOT":
            if len(msg) == 3:
                if inputChecker.checkRQ(msg[1]):
                    #print(msg[1])
                    #print(inputChecker.checkRQ(msg[1]))
                    #print("RG checked")
                    check = True
                    if inputChecker.checkName(msg[2]):
                        #print("NAME checked")
                        check = True
                    else:
                        check = False
                else:
                    check = False
            else:
                validatedMSG = "Wrong format"
                setError(validatedMSG)
                check = False
            if check:
                #print(msg)
                validatedMSG = msg
        
        elif msg[0]=="AUTHENTICATE":
            if len(msg) == 4:
                if inputChecker.checkRQ(msg[1]):
                    #print(msg[1])
                    #print(inputChecker.checkRQ(msg[1]))
                    #print("RG checked")
                    check = True
                    if inputChecker.checkName(msg[2]):
                        #print("NAME checked")
                        check = True
                    else:
                        check = False
                else:
                    check = False
            else:
                validatedMSG = "Wrong format"
                setError(validatedMSG)
                check = False
            if check:
                #print(msg)
                validatedMSG = msg

        elif msg[0]=="PUBLISH" or msg[0]=="REMOVE":
            if len(msg) == 4:
                if inputChecker.checkRQ(msg[1]):
                    #print(msg[1])
                    #print(inputChecker.checkRQ(msg[1]))
                    #print("RG checked")
                    check = True
                    if inputChecker.checkName(msg[2]):
                        #print("NAME checked")
                        check = True
                    else:
                        check = False
                else:
                    check = False
            else:
                validatedMSG = "Wrong format"
                setError(validatedMSG)
                check = False
            if check:
                #print(msg)
                validatedMSG = msg

        elif msg[0]=="CHECK-NAME":
            if len(msg) == 3:
                if inputChecker.checkRQ(msg[1]):
                    #print(msg[1])
                    #print(inputChecker.checkRQ(msg[1]))
                    #print("RG checked")
                    check = True
                    if inputChecker.checkName(msg[2]):
                        #print("NAME checked")
                        check = True
                    else:
                        check = False
                else:
                    check = False
            else:
                validatedMSG = "Wrong format"
                setError(validatedMSG)
                check = False
            if check:
                #print(msg)
                validatedMSG = msg

        elif msg[0]=="CHECK-PASS":
            if len(msg) == 3:
                if inputChecker.checkRQ(msg[1]):
                    check = True
                else:
                    check = False
            else:
                validatedMSG = "Wrong format"
                setError(validatedMSG)
                check = False
            if check:
                #print(msg)
                validatedMSG = msg

        elif msg[0]=="CHECK-IP":
            if len(msg) == 3:
                if inputChecker.checkRQ(msg[1]):
                    #print(msg[1])
                    #print(inputChecker.checkRQ(msg[1]))
                    #print("RG checked")
                    check = True
                    if inputChecker.checkIPAddress(msg[2]):
                        #print("NAME checked")
                        check = True
                    else:
                        check = False
                else:
                    check = False
            else:
                validatedMSG = "Wrong format"
                setError(validatedMSG)
                check = False
            if check:
                #print(msg)
                validatedMSG = msg

        elif msg[0]=="CHECK-UDP":
            if len(msg) == 3:
                if inputChecker.checkRQ(msg[1]):
                    #print(msg[1])
                    #print(inputChecker.checkRQ(msg[1]))
                    #print("RG checked")
                    check = True
                    if inputChecker.checkUDP(msg[2]):
                        #print("NAME checked")
                        check = True
                    else:
                        check = False
                else:
                    check = False
            else:
                validatedMSG = "Wrong format"
                setError(validatedMSG)
                check = False
            if check:
                #print(msg)
                validatedMSG = msg

        elif msg[0]=="CHECK-TCP":
            if len(msg) == 3:
                if inputChecker.checkRQ(msg[1]):
                    #print(msg[1])
                    #print(inputChecker.checkRQ(msg[1]))
                    #print("RG checked")
                    check = True
                    if inputChecker.checkTCP(msg[2]):
                        #print("NAME checked")
                        check = True
                    else:
                        check = False
                else:
                    check = False
            else:
                validatedMSG = "Wrong format"
                setError(validatedMSG)
                check = False
            if check:
                #print(msg)
                validatedMSG = msg

        elif msg[0]=="RETRIEVE-ALL":
            if len(msg) == 2:
                if inputChecker.checkRQ(msg[1]):
                    #print(msg[1])
                    #print(inputChecker.checkRQ(msg[1]))
                    #print("RG checked")
                    check = True
                else:
                    check = False
            else:
                validatedMSG = "Wrong format"
                setError(validatedMSG)
                check = False
            if check:
                #print(msg)
                validatedMSG = msg

        elif msg[0]=="DOWNLOAD":

            if len(msg) == 3:
                if inputChecker.checkRQ(msg[1]):
                    #print(msg[1])
                    #print(inputChecker.checkRQ(msg[1]))
                    #print("RG checked")
                    check = True
                    if inputChecker.checkName(msg[2]):
                        #print("NAME checked")
                        check = True
                    else:
                        check = False
                else:
                    check = False
            else:
                validatedMSG = "Wrong format"
                setError(validatedMSG)
                check = False
            if check:
                print(msg)
                validatedMSG = msg

        elif msg[0]=="SEARCH-FILE":

            if len(msg) == 3:
                if inputChecker.checkRQ(msg[1]):
                    check = True
                else:
                    check = False
            else:
                validatedMSG = "Wrong format"
                setError(validatedMSG)
                check = False
            if check:
                print(msg)
                validatedMSG = msg
        else:
            validatedMSG = "COMMAND NOT FOUND."
            setError(validatedMSG)
        return check

        

        


#RQnumber = "o"
#print("\nRQ number : " + RQnumber)
#print(inputChecker.checkRQ(RQnumber))

#name = "Hello"
#print("\nName : " + name)
#print(inputChecker.checkName(name))

#ipAddress = "231.0.3.0"
#print("\nIP Address : " + ipAddress)
#print(inputChecker.checkIPAddress(ipAddress))
   
#UDPsocket = "5000"
##print("\nUDP Socket Number : " + UDPsocket)
#print(inputChecker.checkUDP(UDPsocket))

#TCPsocket = "6600"
#print("\nTCP Socket Number : " + TCPsocket)
#print(inputChecker.checkTCP(TCPsocket))

"""""
msg = "REGISTER, 0, CHAMA, 123.4.5.6, 5000, 6000, psw"
print("\nUser input : " + msg)
print(inputChecker.checkClientMessage(msg))

msg = "DE-REGISTER, 0, CHAMA, 123.4.5.6, 5000, 6000, psw"
print("\nUser input : " + msg)
print(inputChecker.checkClientMessage(msg))

msg = "AUTHENTICATE, 0, CHAMA, 123.4.5.6, 5000, 6000, psw"
print("\nUser input : " + msg)
print(inputChecker.checkClientMessage(msg))

msg = "PUBLISH, 0, CHAMA, 123.4.5.6, 5000, 6000, psw"
print("\nUser input : " + msg)
print(inputChecker.checkClientMessage(msg))

msg = "REMOVE, 0, CHAMA, 123.4.5.6, 5000, 6000, psw"
print("\nUser input : " + msg)
print(inputChecker.checkClientMessage(msg))

msg = "RETRIEVE-ALL, 0, CHAMA, 123.4.5.6, 5000, 6000, psw"
print("\nUser input : " + msg)
print(inputChecker.checkClientMessage(msg))

msg = "RETRIEVE-INFOT, 0, CHAMA, 123.4.5.6, 5000, 6000, psw"
print("\nUser input : " + msg)
print(inputChecker.checkClientMessage(msg))

msg = "SEARCH-FILE, 0, CHAMA, 123.4.5.6, 5000, 6000, psw"
print("\nUser input : " + msg)
print(inputChecker.checkClientMessage(msg))

msg = "DOWNLOAD, 0, CHAMA, 123.4.5.6, 5000, 6000, psw"
print("\nUser input : " + msg)
print(inputChecker.checkClientMessage(msg))

msg = "UPDATE-CONTACT, 0, CHAMA, 123.4.5.6, 5000, 6000, psw"
print("\nUser input : " + msg)
print(inputChecker.checkClientMessage(msg))

msg = "HelloT, 0, CHAMA, 123.4.5.6, 5000, 6000, psw"
print("\nUser input : " + msg)
print(inputChecker.checkClientMessage(msg))
"""""
