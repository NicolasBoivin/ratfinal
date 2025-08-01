#!/usr/bin/env python3
"""
Serveur RAT - Version 1.2 
Commit: "Add basic error handling and message loop"
"""
import socket

class BasicServer:
    def __init__(self, host="0.0.0.0", port=4444):
        self.host = host
        self.port = port
        
    def start(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((self.host, self.port))
            sock.listen(5)
            
            print(f"[*] Serveur démarré sur {self.host}:{self.port}")
            
            while True:
                client_sock, addr = sock.accept()
                print(f"[+] Client connecté: {addr}")
                
                # Amélioration: boucle de messages
                while True:
                    try:
                        data = client_sock.recv(1024)
                        if not data:
                            break
                        print(f"[*] Reçu: {data.decode('utf-8')}")
                        # Echo simple
                        client_sock.send(b"Message recu")
                    except Exception as e:
                        print(f"[-] Erreur: {e}")
                        break
                        
                client_sock.close()
                print(f"[-] Client {addr} déconnecté")
                
        except Exception as e:
            print(f"[-] Erreur serveur: {e}")

def main():
    server = BasicServer()
    server.start()

if __name__ == "__main__":
    main()