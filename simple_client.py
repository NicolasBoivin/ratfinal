#!/usr/bin/env python3
"""
Client RAT - Version initiale basique
"""
import socket
import json
import time

class RATClient:
    def __init__(self, server_host, server_port):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.running = False
        
    def connect(self):
        """Se connecte au serveur"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            print(f"[+] Connecté au serveur")
            return True
        except Exception as e:
            print(f"[-] Erreur de connexion: {e}")
            return False
    
    def start(self):
        """Démarre le client"""
        if not self.connect():
            return
        
        self.running = True
        print("[*] Client démarré")
        
        while self.running:
            try:
                # Version basique - pas de protocol robuste
                data = self.socket.recv(1024)
                if not data:
                    break
                
                # Parse JSON sans sécurité
                command_data = json.loads(data.decode('utf-8'))
                command = command_data.get('command')
                
                if command == "help":
                    response = {'output': 'Client basique - commandes limitées'}
                else:
                    response = {'output': f'Commande non supportée: {command}'}
                
                # Envoie réponse simple
                self.socket.send(json.dumps(response).encode('utf-8'))
                
            except Exception as e:
                print(f"[-] Erreur: {e}")
                break
        
        self.cleanup()
    
    def cleanup(self):
        """Nettoage"""
        self.running = False
        if self.socket:
            self.socket.close()
        print("[*] Client arrêté")

def main():
    import sys
    if len(sys.argv) != 3:
        print("Usage: python client.py <host> <port>")
        return
    
    client = RATClient(sys.argv[1], int(sys.argv[2]))
    client.start()

if __name__ == "__main__":
    main()