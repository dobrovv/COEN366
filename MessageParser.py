import re
from itertools import chain
    
#List of available files
def parseFileNameList(l:str):
    
    reg = r"([\w\. ]+)\s*,?" #a filename followed by an optional comma
    matches = re.findall(reg, l)
    
    #remove surrounding spaces from filenames
    matches = [filename.strip() for filename in matches]
    
    return matches

def parseDoubleList(l:str):
    #List of [Name, IP address, TCP socket#, list of available files]
    reg = r"([\w ]*)\s*,\s*([\d\.]*)\s*,\s*(\d+)\s*,\s*(\(.*?\)),?"
    matches = re.findall(reg, l)
    matches = [list(e) for e in matches]
    
    #each element is (Name, IP address, TCP socket#, list of available files)
    for e in matches:
        e[0] = e[0].strip() # remove surrounding spaces from names
        e[3] = parseFileNameList(e[3]) #parse inner filename list

    return matches

# Helper function, it parses the input data of the socket
# deserialises the command message recieved from the client 
# returns the command as the list (field1, field2 filed3 ...)
def parseUserMessage(msg:str, isClient:bool):
    #"Obtain the command by slplitng the message to the first comma,"
    cmd = msg.split(',', maxsplit=1)
    command = cmd[0]
    
    #parse commands contatining a list of names/filenames using regexps
    if command in ["PUBLISH", "REMOVE"]:
        if isClient:
            if command == "PUBLISH": # PUBLISH RQ# Name List of files
                #reg = r"(PUBLISH)\s*,\s*([\w\. ]*)\s*,\s*(\(.*?\))"
                reg = r"(PUBLISH)\s*,\s*(\(.*?\))"
                match = re.match(reg, msg)
            
                if match:
                    cmd = list(match.groups())
                    #deserialize the file list, 1st arg
                    cmd[1] = parseFileNameList(cmd[1])
                else:
                    cmd = None
        
            elif command == "REMOVE": # REMOVE RQ# Name List of files to remove
                #reg = r"(REMOVE)\s*,\s*(\(.*?\))"
                reg = r"(REMOVE)\s*,\s*(\(.*?\))"
                match = re.match(reg, msg)
            
                if match:
                    cmd = list(match.groups())
                    #deserialize the file list, 1st arg
                    cmd[1] = parseFileNameList(cmd[1])
                else:
                    cmd = None
        else:
            if command == "PUBLISH": # PUBLISH RQ# Name List of files
                reg = r"(PUBLISH)\s*,\s*(\d+)\s*,\s*([\w\. ]*)\s*,\s*(\(.*?\))"
                match = re.match(reg, msg)
            
                if match:
                    cmd = list(match.groups())
                    #deserialize the file list, 4th arg
                    cmd[3] = parseFileNameList(cmd[3])
                else:
                    cmd = None
        
            elif command == "REMOVE": # REMOVE RQ# Name List of files to remove
                reg = r"(REMOVE)\s*,\s*(\d+)\s*,\s*([\w\. ]*)\s*,\s*(\(.*?\))"
                match = re.match(reg, msg)
            
                if match:
                    cmd = list(match.groups())
                    #deserialize the file list, 4th arg
                    cmd[3] = parseFileNameList(cmd[3])
                else:
                    cmd = None

    else: #
        #split message into fields
        cmd = list(msg.split(','))
        #strip spaces in fields " RQ " -> "RQ"
        cmd = [field.strip() for field in cmd]

    return cmd

# Helper function, it parses the input data of the socket
# deserialises the command message recieved from the server 
# returns the command as the list (field1, field2 filed3 ...)
def parseServerMessage(msg:str):
    #"Obtain the command by slplitng the message to the first comma,"
    cmd = msg.split(',', maxsplit=1)
    command = cmd[0]
    
    #parse commands contatining a list of names/filenames using regexps
    if command in ["RETRIEVE", "RETRIEVE-INFOT", "SEARCH-FILE"]:
        if command == "RETRIEVE": #RETRIEVE RQ# List of (Name, IP address, TCP socket#, list of available files)
            reg = r"(RETRIEVE)\s*,\s*(\d+)\s*,\s*(\[.*?\])"
            match = re.match(reg, msg)
            
            if match:
                cmd = list(match.groups())
                #deserialize the file list, 3rd arg
                cmd[2] = parseDoubleList(cmd[2])
            else:
                cmd = None
        
        elif command == "RETRIEVE-INFOT": #RETRIEVE-INFOT RQ# Name IP Address TCP socket# List of available files
            reg = r"(RETRIEVE-INFOT)\s*,\s*(\d+)\s*,\s*([\w ]*)\s*,\s*([\d\.]*)\s*,\s*(\d+)\s*,\s*(\(.*?\))"
            match = re.match(reg, msg)
            
            if match:
                cmd = list(match.groups())
                #deserialize the file list, 6th arg
                cmd[5] = parseFileNameList(cmd[5])
            else:
                cmd = None
        
        elif command=="SEARCH-FILE": #SEARCH-FILE RQ# List of (Name, IP address, TCP socket#)
            reg = r"(SEARCH-FILE)\s*,\s*(\d+)\s*,\s*(\(.*?\))"
            match = re.match(reg, msg)
            
            if match:
                cmd = list(match.groups())
                #deserialize the file list, 3d arg
                cmd[2] = parseFileNameList(cmd[2])
            else:
                cmd = None

    else: #
        #split message into fields
        cmd = list(msg.split(','))
        #strip spaces in fields " RQ " -> "RQ"
        cmd = [field.strip() for field in cmd]

    return cmd

def serializeCommand(cmd:list):
    # check if the command contains double arrays
    if cmd[0] == "RETRIEVE":
        res = ", ".join(cmd[0:2]) + ", ["
        
        for item in cmd[2]:
            itemStr = ", ".join(item[0:3]) + ", ("+", ".join(item[3]) + ")"
            if item != cmd[2][-1]:
                itemStr += ", "
            res += itemStr
        res += "]" 
    else:
        #flatten the arrays
        res = [ "("+", ".join(e)+")" if isinstance(e, (list,tuple)) else e for e in cmd ]
        res = [str(elem) for elem in res]
        res = ", ".join(res)
    return res
        
def mp_tests():
    cmd = parseDoubleList("RETRIEVE, 0, [Alex L, 127.0.0.1, 6001, (A Long Journey, Mechanics,  Economics 101 ), Michael, 127.0.0.1, 6001, (File 1, File 2, File 3), Leonard, 127.0.0.1, 6001, (File 1, File 2, File 3)]")
    cmd = parseServerMessage("RETRIEVE, 0, [Alex L, 127.0.0.1, 6001, (A Long Journey, Mechanics,  Economics 101 ), Michael, 127.0.0.1, 6001, (File 1, File 2, File 3), Leonard, 127.0.0.1, 6001, (File 1, File 2, File 3)]")
    print()
    print(cmd)
    print()
    print("Serialized:", serializeCommand(cmd))
    print()
    cmd = parseServerMessage("RETRIEVE-INFOT, 3, Alex L, 127.0.0.1, 6001, (A Long Journey, Mechanics,  Economics 101)")
    print(cmd)
    print()
    print("Serialized:", serializeCommand(cmd))



if __name__ == "__main__":
    mp_tests()
