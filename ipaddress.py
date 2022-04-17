import socket

def getIPAddress():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Obtaining IP address...")
    try:
        #s.connect(('8.8.8.8', 53))
        s.connect(('172.217.13.110', 80)) # google.com website
        IP = s.getsockname()[0]
        s.close()
        print("Done.")
    except Exception:
        print("Failed to detect IP address.")
        IP = input("Please use ipconfig in Windows or ip a in Linux and enter the IP address manually: ")
        while IP is None:
            print("No or invalid IP address specified.")
            IP = input("Please use ipconfig in Windows or ip a in Linux and enter the IP address manually: ")
        s.close()
    return IP
    
if __name__ == "__main__":
    print("Computer IP Address is ", IP)