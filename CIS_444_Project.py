# === Imports ===
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64
import tkinter as tk
from tkinter import scrolledtext
import threading
import time
import queue

# === Utility Functions ===

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

def rsa_encrypt(public_key, data):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)

def rsa_decrypt(private_key, encrypted_data):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_data)

def generate_aes_key():
    return get_random_bytes(16)  # AES-128

def aes_encrypt(aes_key, plaintext):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return cipher.nonce, ciphertext, tag

def aes_decrypt(aes_key, nonce, ciphertext, tag):
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# === Message System Setup ===

class Party:
    def __init__(self, name):
        self.name = name
        self.private_key, self.public_key = generate_rsa_keys()
        self.aes_key = None

class Attacker:
    def __init__(self):
        self.name = "Attacker"
        self.a_aes_key = None
        self.b_aes_key = None

# === GUI Setup ===

class SecureChatGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure Two-Party Chat with Attacks")

        self.message_log = scrolledtext.ScrolledText(self.root, width=80, height=20)
        self.message_log.pack()

        self.input_a = tk.Entry(self.root, width=40)
        self.input_a.pack()
        self.frame_a = tk.Frame(self.root)
        self.frame_a.pack()
        tk.Button(self.frame_a, text="Send A ➜ B", command=self.send_a_to_b).pack(side=tk.LEFT)
        tk.Button(self.frame_a, text="Send public key to B", command=self.send_a_key_to_b).pack(side=tk.LEFT)


        self.input_b = tk.Entry(self.root, width=40)
        self.input_b.pack()
        self.frame_b = tk.Frame(self.root)
        self.frame_b.pack()
        tk.Button(self.frame_b, text="Send B ➜ A", command=self.send_b_to_a).pack(side=tk.LEFT)
        tk.Button(self.frame_b, text="Send public key to A", command=self.send_b_key_to_a).pack(side=tk.LEFT)

        tk.Button(self.root, text="Launch Eavesdrop", command=self.eavesdrop).pack()

        self.input_atk = tk.Entry(self.root, width=40)
        self.input_atk.pack()
        self.frame_atk = tk.Frame(self.root)
        self.frame_atk.pack()
        tk.Button(self.frame_atk, text="Send Attacker ➜ B", fg="red", command=self.attacker_send_to_b).pack(side=tk.LEFT)
        tk.Button(self.frame_atk, text="Send Attacker ➜ A", fg="red", command=self.attacker_send_to_a).pack(side=tk.LEFT)
        
        tk.Button(self.root, text="Launch DoS Attack", command=self.dos_attack).pack()

        # so that i dont have to worry about sifting through i bajillion text logs when i am debugging
        self.frame_log = tk.Frame(self.root)
        self.frame_log.pack()
        tk.Button(self.frame_log, text="Clear log file [debug]", bg="red", fg="white", command=self.clear_log_file).pack(side=tk.LEFT)
        tk.Button(self.frame_log, text="Clear attacker log file [debug]", bg="red", fg="white", command=self.clear_attacker_log_file).pack(side=tk.LEFT)


        # Parties
        self.user_a = Party("User A")
        self.user_b = Party("User B")
        self.attacker = Attacker()
        self.attacker_log = []

        # initialization variables
        self.eavesdrop_toggle = False
        self.integrity_toggle = False

        # Communication channel
        self.message_queue = queue.Queue()

        # Start receiver threads
        threading.Thread(target=self.process_messages, daemon=True).start()

    # === Core Messaging Functions ===

    def send_a_to_b(self):
        text = self.input_a.get()
        if not self.user_b.aes_key:
            self.message_queue.put(("A", "PLAINTEXT", (text)))
            # self.message_queue.put(("A", "KEY", self.user_a.public_key.export_key()))
        else:
            nonce, ct, tag = aes_encrypt(self.user_b.aes_key, text)
            self.message_queue.put(("A", "MSG", (nonce, ct, tag)))

    def send_a_key_to_b(self):
        self.message_queue.put(("A", "KEY", self.user_a.public_key.export_key()))

    def send_b_to_a(self):
        text = self.input_b.get()
        if not self.user_a.aes_key:
            self.message_queue.put(("B", "PLAINTEXT", text))
            # self.message_queue.put(("B", "KEY", self.user_b.public_key.export_key()))
        else:
            nonce, ct, tag = aes_encrypt(self.user_a.aes_key, text)
            self.message_queue.put(("B", "MSG", (nonce, ct, tag)))

    def send_b_key_to_a(self):
        self.message_queue.put(("B", "KEY", self.user_b.public_key.export_key()))

    def attacker_send_to_b(self):
        text = self.input_atk.get()
        self.integrity_toggle = True
        if not self.attacker.b_aes_key:
            self.message_queue.put(("A", "PLAINTEXT", (text)))
            # self.message_queue.put(("A", "KEY", self.user_a.public_key.export_key()))
        else:
            nonce, ct, tag = aes_encrypt(self.attacker.b_aes_key, text)
            self.message_queue.put(("A", "MSG", (nonce, ct, tag)))

    def attacker_send_to_a(self):
        text = self.input_atk.get()
        self.integrity_toggle = True
        if not self.attacker.a_aes_key:
            self.message_queue.put(("B", "PLAINTEXT", text))
            # self.message_queue.put(("B", "KEY", self.user_b.public_key.export_key()))
        else:
            nonce, ct, tag = aes_encrypt(self.attacker.a_aes_key, text)
            self.message_queue.put(("B", "MSG", (nonce, ct, tag)))

    def process_messages(self):
        while True:
            if not self.message_queue.empty():
                sender, msg_type, content = self.message_queue.get()

                if msg_type == "KEY":
                    print(msg_type)
                    self.log(f"{sender} sent public key.")
                    if sender == "A":
                        aes_key = generate_aes_key()
                        enc_key = rsa_encrypt(RSA.import_key(content), aes_key)
                        self.user_b.aes_key = aes_key
                        if self.eavesdrop_toggle == True:
                            self.attacker.b_aes_key = aes_key
                        self.message_queue.put(("B", "AES_KEY", enc_key))
                    elif sender == "B":
                        aes_key = generate_aes_key()
                        enc_key = rsa_encrypt(RSA.import_key(content), aes_key)
                        self.user_a.aes_key = aes_key
                        if self.eavesdrop_toggle == True:
                            self.attacker.a_aes_key = aes_key
                        self.message_queue.put(("A", "AES_KEY", enc_key))

                elif msg_type == "AES_KEY":
                    print(msg_type)
                    # Determine who the recipient is (not the sender)
                    recipient = self.user_b if sender == "A" else self.user_a
                    try:
                        decrypted_key = rsa_decrypt(recipient.private_key, content)
                        recipient.aes_key = decrypted_key
                        self.log(f"{recipient.name} received and decrypted AES key.")
                    except ValueError:
                        self.log(f"{recipient.name} failed to decrypt AES key. Possible key mismatch.")

                elif msg_type == "MSG":
                    nonce, ct, tag = content
                    try:
                        plaintext = aes_decrypt(
                            self.user_b.aes_key if sender == "A" else self.user_a.aes_key,
                            nonce, ct, tag
                        )
                        self.log(f"{sender} ➜ {'B' if sender == 'A' else 'A'}(Encrypted): {plaintext}")
                    except Exception:
                        self.log("Decryption failed. Possible integrity issue.")
                
                elif msg_type == "PLAINTEXT":
                    self.log(f"{sender} ➜ {'B' if sender == 'A' else 'A'}(Un-encrypted): {content}")

            time.sleep(0.1)

    # === Attack Simulations ===
    

    def eavesdrop(self):    
        if not self.eavesdrop_toggle:
            self.log("[EAVESDROP] Attacker is listening.")
            self.eavesdrop_toggle = True
        else:   
            self.log("[EAVESDROP] Attacker is no longer listening.")
            self.eavesdrop_toggle = False



    def dos_attack(self):
        def flood():
            for _ in range(50):
                self.message_queue.put(("Attacker", "MSG", aes_encrypt(get_random_bytes(16), "FLOOD")[0:3]))
                time.sleep(0.05)
            self.log("[DoS] Flooding complete.")

        threading.Thread(target=flood).start()

    # === UI Logging ===

    def log(self, text):
        # display the messages in the GUI
        self.message_log.insert(tk.END, text + "\n")
        self.message_log.see(tk.END)

        # log the messages in a file
        with open("chat_log.txt", "a", encoding="utf-8") as f:
            if self.integrity_toggle:
                f.write("Attacker tampered with this message ➜ ")
                self.integrity_toggle = False
            f.write(text + "\n")

        if self.eavesdrop_toggle:
            with open("attacker_log.txt", "a", encoding="utf-8") as atk:
                if self.integrity_toggle:
                    f.write("I tampered with this message ➜ ")
                atk.write(text + "\n")


    def clear_log_file(self):
        with open("chat_log.txt", "w",) as f:
            pass

    def clear_attacker_log_file(self):
        with open("attacker_log.txt", "w",) as f:
            pass

    def run(self):
        self.root.mainloop()


# === Main Launch ===

if __name__ == "__main__":
    gui = SecureChatGUI()
    gui.run()
