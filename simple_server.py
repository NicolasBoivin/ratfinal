#!/usr/bin/env python3
"""
Serveur RAT - Version 1.4
Commit: "Add threading support (buggy implementation)"
"""
import socket
import json
import threading

class BasicServer:
    def __init__(self, host="0.0.0.0", port=4444):
        self.host = host
        self.port = port
        self.clients = {}  # Dictionnaire maintenant
        self.client_counter = 0
        
    def start(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((self.host, self.port))
            sock.listen(5)
            
            print(f"[*] Serveur démarré sur {self.host}:{self.port}")
            
            while True:
                client_sock, addr = sock.accept()
                self.client_counter += 1
                client_id = self.client_counter
                
                print(f"[+] Client {client_id} connecté: {addr}")
                
                # BUG: pas de daemon=True
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_sock, client_id, addr)
                )
                client_thread.start()
                
        except Exception as e:
            print(f"[-] Erreur serveur: {e}")
    
    def handle_client(self, client_sock, client_id, addr):
        """Gère un client avec threading"""
        try:
            # Stockage client
            self.clients[client_id] = {
                "socket": client_sock,
                "addr": addr
            }
            
            while True:
                # BUG: toujours recv(1024) fixe
                data = client_sock.recv(1024)
                if not data:
                    break
                
                try:
                    message = json.loads(data.decode('utf-8'))
                    print(f"[*] Client {client_id}: {message}")
                    
                    # BUG: pas de vrai traitement
                    response = {"status": "ok", "client_id": client_id}
                    client_sock.send(json.dumps(response).encode('utf-8'))
                    
                except json.JSONDecodeError:
                    print(f"[-] Client {client_id}: JSON invalide")
                    break
                    
        except Exception as e:
            print(f"[-] Erreur client {client_id}: {e}")
        finally:
            # Nettoie le client
            if client_id in self.clients:
                del self.clients[client_id]
            client_sock.close()
            print(f"[-] Client {client_id} déconnecté")

def main():
    server = BasicServer()
    server.start()

if __name__ == "__main__":
    main()