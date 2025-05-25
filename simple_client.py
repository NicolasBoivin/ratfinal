#!/usr/bin/env python3
"""
Client RAT - Version 2 avec chiffrement buggué
"""
import socket
import json
import time
import base64
from cryptography.fernet import Fernet

class RATClient:
    def __init__(self, server_host, server_port):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.running = False
        
        # Clé de chiffrement fixe
        self.key = b'ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg='
        self.cipher = Fernet(self.key)
        
    def connect(self):
        """Se connecte au serveur"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            
            # Envoie info basique (sans handshake proper)
            client_info = {
                'hostname': socket.gethostname(),
                'timestamp': time.time()
            }
            
            # ERREUR: pas de gestion de taille
            encrypted_data = self.cipher.encrypt(json.dumps(client_info).encode('utf-8'))
            self.socket.send(encrypted_data)
            
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
                # PROBLÈME: recv taille fixe ne fonctionne pas toujours
                data = self.socket.recv(4096)  
                if not data:
                    break
                
                # Déchiffre
                try:
                    decrypted_data = self.cipher.decrypt(data)
                    command_data = json.loads(decrypted_data.decode('utf-8'))
                except:
                    print("[-] Erreur déchiffrement")
                    continue
                
                command = command_data.get('command')
                
                if command == "help":
                    response = {'output': 'Commandes: help\nVersion avec chiffrement basique'}
                elif command == "test":
                    response = {'output': 'Test OK'}
                else:
                    response = {'output': f'Commande inconnue: {command}'}
                
                # Chiffre et envoie
                encrypted_response = self.cipher.encrypt(json.dumps(response).encode('utf-8'))
                # ERREUR: pas de gestion de taille côté serveur
                self.socket.send(encrypted_response)
                
            except Exception as e:
                print(f"[-] Erreur traitement: {e}")
                break
        
        self.cleanup()
    
    def cleanup(self):
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