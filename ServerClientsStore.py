import sqlite3, datetime

#Time before revoking authentication in minutes
AUTH_MINUTES = 15

#ServerClient constructor
class ServerClient:
    def __init__(self, Name:str, ipaddress:str, udp:int, tcp:int):
        self.Name = Name
        self.ipaddress = ipaddress
        self.udp = udp
        self.tcp = tcp
        self.files = []

#Status flags for the various functions of the ServerClientsStore
class Status:
    def __init__(self, valid:bool, error:str=""):
        self.valid = valid
        self.error = error 

#Information about the clients on the server is stored by the ServerClientsStore class
class ServerClientsStore:
    #Create two SQLite3 databases on the server, one listing the users registered on the server, the other listing which users are authenticated and authorized
    #to use the server, and store it in a database.db file
    def __init__(self):
        self.clients  = dict()  # dictionary (Name, ServerClient) pairs
        self.con = sqlite3.connect('database.db')
        self.cur = self.con.cursor()
        
        try:
            self.cur.execute('''CREATE TABLE Users (username text unique, password text, ipaddress text, udp text, tcp text, filenames text)''')
        except Exception as e :
            print(e)
            pass

        try:
            self.cur.execute('''CREATE TABLE UsersAuth (username text, ipaddress text, udp text, LastModified timestamp)''')
        except Exception as e :
            print(e)
            pass

    #Keep track of how long a client has been authenticated and revoke authentication after a certain amount of minutes has elapsed.
    def resync_authentication_times(self):
        time = datetime.datetime.now()
        timeDiff = datetime.timedelta(minutes = AUTH_MINUTES)
        delta = time - timeDiff
        self.cur.execute(f"DELETE FROM UsersAuth WHERE LastModified < ?", (delta,))
        self.con.commit()
    
    #Authenticate the user based on the provided name, password, IP address and UDP port - authenticate if the username and password
    #match, otherwise refuse authentication
    def authenticate(self, Name:str, password:int, ipaddress:str, udp:str):
        try:
            if self.matchPassword(Name, password) and self.matchIPAddress(Name, ipaddress):
                self.cur.execute(f"DELETE FROM UsersAuth WHERE ipaddress=? AND udp=?", (ipaddress, udp))
                self.cur.execute(f"INSERT INTO UsersAuth VALUES (?,?,?,?)", (Name, ipaddress, udp, datetime.datetime.now()))
                self.cur.execute("UPDATE Users SET ipaddress=?, udp=? WHERE username=?", (ipaddress, udp, Name) )
                self.con.commit()
                return Status(valid=True)
            else:
                #self.cur.execute(f"DELETE FROM UsersAuth WHERE username=? AND ipaddress=? AND udp=?", (Name, ipaddress, udp))
                #self.con.commit()
                return Status(valid=False, error="Incorrect Username/Password")
        except Exception as e:
                print("Authentication exception", e)
                return Status(valid=False, error=str(e))
    
    #Check if the provided user is authenticated on the server
    def isAuthenticated(self, ipaddress:str, udp:str):
        #sql = 'SELECT UsersAuth.username FROM UsersAuth WHERE ipaddress=? AND udp=?;'
        sql = 'SELECT UsersAuth.username FROM Users, UsersAuth WHERE UsersAuth.ipaddress=? AND UsersAuth.udp=? AND Users.ipaddress=UsersAuth.ipaddress AND Users.udp=UsersAuth.udp'
        res = self.cur.execute(sql, (ipaddress, udp))
        res = res.fetchone()
        if res:
            return Status(valid=True, error=res[0])
        else:
            return Status(valid=False, error="Not authenticated.")
    
    #Register a client on the server and store their information in the database
    def register(self, Name:str, ipaddress:str, udp:int, tcp:int, password:str=""):
        if self.isRegistered(Name):
            return Status(valid=False, error=f"Name {Name} already in use.")
        elif self.checkIPAddress(ipaddress):
            return Status(valid=False, error=f"User already registered at IP address {ipaddress}.")
        elif self.checkUDPPort(udp):
            return Status(valid=False, error=f"UDP port {udp} already in use.")
        elif self.checkTCPPort(tcp):
            return Status(valid=False, error=f"TCP port {tcp} already in use.")
        else:
            try:
                self.cur.execute(f"INSERT INTO Users VALUES ('{Name}', '{password}','{ipaddress}','{udp}', '{tcp}', '')")
                self.con.commit()
            except Exception as e:
                return Status(valid=False, error=str(e))
            return Status(valid=True)
    
    #Remove the given client and all associated files, IP address and ports from the database
    def deregister(self, Name:str):
        if self.isRegistered(Name):
            self.cur.execute(f"DELETE FROM Users WHERE username=\'{Name}\'")
            self.cur.execute(f"DELETE FROM UsersAuth WHERE username=?", (Name,))
            self.con.commit()
            return Status(valid=True)
        else:
            return Status(valid=False, error="Name doesn't exist")
    
    #Publish a list of files to the server, associate them to a particular client and store them in the database
    def publish(self, Name:str, listOfFiles:list):
        if self.isRegistered(Name):

            #add the list of files to the published files
            info = self.retrieve_infot(Name)
            if info is not None:
                listOfFiles = list(set(info[3]+listOfFiles)-set(['']))
            else:
                listOfFiles = list(set(listOfFiles))

            sql = "UPDATE Users SET filenames=? WHERE username=?"
            try:
                self.cur.execute(sql, (",".join(listOfFiles), Name) )
                self.con.commit()
            except Exception as e:
                return Status(valid=False, error=str(e))
            return Status(valid=True)
        else:
            return Status(valid=False, error="Name doesn't exist")
    
    #Remove the given list of files belonging to a particular client from the database
    def remove(self, Name:str, listOfFiles:list):
        if self.isRegistered(Name):
            
            #remove list of files from the published files
            info = self.retrieve_infot(Name)
            if info is not None:
                listOfFiles = list(set(info[3])-set(listOfFiles)-set(['']))
            else:
                listOfFiles = []
            
            sql = "UPDATE Users SET filenames=? WHERE username=?"
            try:
                self.cur.execute(sql, (",".join(listOfFiles), Name) )
                self.con.commit()
            except Exception as e:
                return Status(valid=False, error=str(e))
            return Status(valid=True)
        else:
            return Status(valid=False, error="Name doesn't exist")

    #Retrieve all the files published on the server from all registered clients
    def retrieve_all(self):
        clientsList = [] # List of (Name, IP address, TCP socket#, list of available files)
        
        for row in self.cur.execute('SELECT username,ipaddress,tcp,filenames FROM Users'):
            entry = list(row)
            entry[3] = entry[3].split(',') #split filename list str -> list
            clientsList.append(entry)
        
        print("ClientsList:", clientsList)
        return clientsList
    
    #Retrieve the files published by a single user
    def retrieve_infot(self, Name):
        if not self.isRegistered(Name):
            return None

        sql = "SELECT username,ipaddress,tcp,filenames FROM Users WHERE username=?"
        entry = None
        try:
            row = self.cur.execute(sql, (Name,)).fetchone()
            entry = list(row)
            entry[3] = entry[3].split(',') #split filename list str -> list
        except Exception as e:
            print("[exception]", e)
            return None
        return entry
    
    #Search for a specific file and retrieve which client has the file in question
    def search(self, filename):
        sql = "SELECT username,ipaddress,tcp FROM Users WHERE filenames LIKE ?"
        searchList = [] # SEARCH-FILE RQ# List of (Name, IP address, TCP socket#)

        for row in self.cur.execute(sql, ("%"+filename+"%",)):
            searchList.append(list(row))
        
        print("SearchList:", searchList)
        return searchList
    
    #Update client IP address, ports and password (deny update if the old password doesn't match the one currently in the database)
    def update_contact(self, Name:str, old_pwd:str, password:str, ipaddress:str, udp:int, tcp:int, clientIP:str):
        if self.isRegistered(Name):
            if self.matchIPAddress(Name, clientIP):
                if self.matchPassword(Name, old_pwd):

                    if self.checkIPAddress(ipaddress, Name):
                        return Status(valid=False, error=f"User already registered at IP address {ipaddress}.")
                
                    if self.checkUDPPort(udp, Name):
                        return Status(valid=False, error=f"UDP port {udp} already in use.")
                
                    if self.checkTCPPort(tcp, Name):
                        return Status(valid=False, error=f"TCP port {tcp} already in use.")

                    sql = "UPDATE Users SET ipaddress=?, password=?, udp=?, tcp=? WHERE username=?"
                    try:
                        self.cur.execute(f"DELETE FROM UsersAuth WHERE username=?", (Name,))
                        self.cur.execute(sql, (ipaddress, password, udp, tcp, Name) )
                        self.con.commit()
                    except Exception as e:
                        return Status(valid=False, error=str(e))
                    return Status(valid=True)
                else:
                    return Status(valid=False, error="Old password mismatch.")
            else:
                return Status(valid=False, error="The given name is not registered at this address.")
        else:
            return Status(valid=False, error="Name doesn't exist")
    
    #Check if the given user is already registered on the server
    def isRegistered(self, Name:str):
        
        res = self.cur.execute(f'SELECT * FROM Users WHERE username=\'{Name}\';')
        res = res.fetchone()
        if res:
            return True
        else:
            return False
    
    #Check if the given IP address is already registered on the server
    def checkIPAddress(self, ipaddress:str, Name:str="NaU"):
        res = self.cur.execute(f'SELECT * FROM Users WHERE ipaddress=\'{ipaddress}\' and username!=\'{Name}\';')
        res = res.fetchone()
        if res:
            return True
        else:
            return False
    
    #Check if the given password is already in use by another user registered on the server
    def checkPassword(self, password:str, Name:str="NaU"):
        res = self.cur.execute(f'SELECT * FROM Users WHERE password=\'{password}\' and username!=\'{Name}\';')
        res = res.fetchone()
        if res:
            return True
        else:
            return False
    
    #Check if the given UDP port is already in use from another user
    def checkUDPPort(self, udp:int, Name:str="NaU"):
        res = self.cur.execute(f'SELECT * FROM Users WHERE udp=\'{udp}\' and username!=\'{Name}\';')
        res = res.fetchone()
        if res:
            return True
        else:
            return False
    
    #Check if the given TCP port is already in use from another user
    def checkTCPPort(self, tcp:int, Name="NaU"):
        res = self.cur.execute(f'SELECT * FROM Users WHERE tcp=\'{tcp}\' and username!=\'{Name}\';')
        res = res.fetchone()
        if res:
            return True
        else:
            return False
    
    #Check if the password of a particular client stored in the database matches the one provided
    def matchPassword(self, Name:str, password:str):
        res = self.cur.execute(f'SELECT * FROM Users WHERE username=? AND password=?;', (Name, password))
        res = res.fetchone()
        if res:
            return True
        else:
            return False
            
    #Check if the IP address of a particular client stored in the database matches the one provided
    def matchIPAddress(self, Name:str, ipaddress:str):
        res = self.cur.execute(f'SELECT * FROM Users WHERE username=? AND ipaddress=?;', (Name, ipaddress))
        res = res.fetchone()
        if res:
            return True
        else:
            return False

    #Check if the given user is registered on the server
    def isRegistered(self, Name:str):
        res = self.cur.execute(f'SELECT * FROM Users WHERE username=\'{Name}\';')
        res = res.fetchone()
        if res:
            return True
        else:
            return False
    
    def isRegisteredAddress(self, address:tuple):
        ipaddress = f"{address[0]}:{address[1]}"
        sql = 'SELECT * FROM Users WHERE ipaddress=?;'
        res = self.cur.execute(sql, (ipaddress,))
        res = res.fetchone()
        if res:
            return True
        else:
            return False

        #for client in self.clients.values():
        #    print(client.ipaddress, client.udp, address)
        #    if client.ipaddress == address[0] and int(client.udp) == int(address[1]):
        #        return True
        #return False
