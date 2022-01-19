import client1

if __name__=="__main__":
    connection = client1.Connection(port=1237,wait=False)
    connection.emit_connection(host="localhost",port=12367)