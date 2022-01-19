import socket
import sockets

# # ----- Client --------------
# s = socket.socket()        
# port = 12345               
# s.connect(('127.0.0.1', port))
# # receive data from the server and decoding to get the string.
# print(s.recv(1024).decode("utf-8")) # receive 1024 bytes
# # close the connection
# s.close()

if __name__=="__main__":
    connection = sockets.Connection(port=1237,wait=False)
    connection.emit_connection(host="localhost",port=12367)