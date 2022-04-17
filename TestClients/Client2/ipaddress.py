import socket

def getIpTcpAddress():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 53))
        IP = s.getsockname()[0]
        TCP = s.getsockname()[1]
    except Exception:
        IP = '127.0.0.1'
        TCP = 6001
    finally:
        s.close()
    return (IP, TCP)

if __name__ == "__main__":
    print("Computer IP Address is ", getIpTcpAddress()[0], "tcp:", getIpTcpAddress()[1])
