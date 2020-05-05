import socket
import ssl
import sys
import nacl.utils
from nacl.public import PrivateKey, Box

class Client:
    def login(self,connection):
        connection.send((2).to_bytes(1,byteorder='big'))
        user = input("Enter your username.")
        password = input("Enter your password.")
        sizeofuser = sys.getsizeof(user)
        sizeofpword = sys.getsizeof(password)
        connection.send((sizeofuser).to_bytes(3,byteorder='big'))
        connection.send(user.encode())
        connection.send((sizeofpword).to_bytes(3,byteorder='big'))
        connection.send(password.encode())
        response = int.from_bytes(connection.recv(28),byteorder='big')
        while response >0:
            password = input("You entered the wrong password. Please re-enter your password.")
            sizeofpword = sys.getsizeof(password)
            connection.send((sizeofpword).to_bytes(3,byteorder='big'))
            connection.send(password.encode())
            response = int.from_bytes(conn.recv(28),byteorder='big')
        skclient = PrivateKey.generate()
        pkclient = skclient.public_key
        sizeofpkclient = sys.getsizeof(pkclient)
        connection.send((sizeofpkclient).to_bytes(3,byteorder='big'))
        connection.send(pkclient)

    def createAccount(self,connection):
        connection.send((1).to_bytes(1,byteorder='big'))
        user = input("Enter the user name.")
        sizeofuser = sys.getsizeof(user)
        connection.send((sizeofuser).to_bytes(3,byteorder='big'))
        connection.send(user.encode())
        response = int.from_bytes(connection.recv(28),byteorder='big')
        while response >0:
            user = input("That user name is already taken. Please enter a new one.")
            sizeofuser = sys.getsizeof(user)
            connection.send((sizeofuser).to_bytes(3,byteorder='big'))
            connection.send(user.encode())
            response = int.from_bytes(connection.recv(28),byteorder='big')
        password = input("Enter your password.")
        confirm = input("Confirm the password by entering it again.")
        while confirm != password:
            print('password is '+password+'confirm is '+confirm)
            confirm = input("That did not match the password entered. Please re-enter the password.")

        sizeofpword = sys.getsizeof(password)
        connection.send((sizeofpword).to_bytes(3,byteorder='big'))
        connection.send(password.encode())
        print("You have created an account.")

    def connectToServer(self,hostname,port,ca_name,ca_file):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_verify_locations(ca_file)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        #with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        try:
            sock.settimeout(10)
            sock.connect((hostname,port))
            ssock = context.wrap_socket(sock,server_hostname = ca_name)
            #with context.wrap_socket(sock,server_hostname = ca_name) as ssock:
            try:
                print(ssock.server_hostname)
                print(ssock.version())
                cert = ssock.getpeercert()
                #print(cert)
                #print(ca_name)
                ssl.match_hostname(cert,ca_name)
                return ssock
            except:
                print('something broke')#ssock.unwrap()
        except:
            sock.close()

    def printOnlineList(self,connection):
        print("The users online are :")


    def connectionPrompt(self,hostname,port,ca_name,ca_file):
        connection = self.connectToServer(hostname,port,ca_name,ca_file)
        while connection == None:
            again = input('Failed to connect. Try again? Y/N')
            if again.lower() == 'y':
                connection = self.connectToServer(hostname,port,'NADGE','certificate.pem')
            elif again.lower() == 'n':
                #quit = True
                break
            else:
                print("Invalid input.")
        return connection

    def loginOrCreateAccountPrompt(self,connection):
        quit = False
        option = input("Press l to log in, r to create an account, or q to quit.")
        while not quit:
            if option.lower() == 'l':
                self.login(connection)
                break
            elif option.lower() == 'r':
                self.createAccount(connection)
                option = input("Press l to log in, r to create an account, or q to quit.")
            elif option.lower() == 'q':
                quit = True
            else:
                option = input("That is not a valid input. Please press l to log in, r to create an account, or q to quit.")
        return quit

    def messagePrompt(self,connection):
        option = input("To print a list of users online press l, to send a user a message enter their username followed by the message inside quotes (eg. USERNAME 'MESSAGE'), to quit press q.")
        while not quit:
            if option == 'l':
                self.printOnlineList(connection)
                option = input("To print a list of users online press l, to start chatting with a user online enter their user name, to quit press q.")
            elif option == 'q':
                quit = True
            else:
                print(option)

    def __init__(self):
        quit = False
        hostname = '192.168.1.157'
        #hostname = '71.255.90.82'
        port = 8443

        connection = self.connectionPrompt(hostname,port,'NADGE','certificate.pem')
        if(connection == None)
            quit = True

        if not quit:
            quit = self.loginOrCreateAccountPrompt(connection)

        if not quit:
            self.messagePrompt(connection)
Client()
