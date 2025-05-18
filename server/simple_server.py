#!/usr/bin/env python3
"""
Serveur RAT - Version 1.1 - Première tentative de socket
Commit: "Initial socket implementation - basic server"
"""
import socket

class BasicServer:
    def __init__(self, host="0.0.0.0", port=4444):
        self.host = host
        self.port = port
        
    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # BUG: pas de gestion d'erreur
        sock.bind((self.host, self.port))
        sock.listen(1)  # Seulement 1 client
        
        print(f"Serveur démarré sur {self.host}:{self.port}")
        
        while True:
            client_sock, addr = sock.accept()
            print(f"Client connecté: {addr}")
            
            # BUG: boucle infinie basique
            data = client_sock.recv(1024)
            print(f"Reçu: {data}")
            client_sock.close()

def main():
    server = BasicServer()
    server.start()

if __name__ == "__main__":
    main()