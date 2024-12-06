import tkinter as tk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from tkinter import ttk, filedialog, messagebox
from tkinter import ttk, messagebox
import smtplib
from email.mime.text import MIMEText
from cryptography.hazmat.primitives import padding
import tkinter.font as tkFont
import time  # Import time module

# Font-related functions
def increase_font_size():
    app_font.config(size=app_font.actual()['size'] + 2)

def decrease_font_size():
    app_font.config(size=max(8, app_font.actual()['size'] - 2))




# Encryption and Decryption Functions
def encrypt(text, key, iv, mode):
    plaintext_bytes = text.encode('utf-8')
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext_bytes) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted.hex()


def decrypt(data, key, iv, mode):
    encrypted_bytes = bytes.fromhex(data)
    cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode('utf-8')


def generate_key(bits):
    return os.urandom(bits // 8)

# Perform Encryption with Timer
def perform_encryption():
    try:
        start_time = time.time()  # Start timer

        selected_key_size = int(key_size_combo.get())
        user_key = key_entry.get().strip()

        if not user_key:
            key = generate_key(selected_key_size)
            key_entry.delete(0, tk.END)
            key_entry.insert(0, key.hex())
        elif len(user_key) == selected_key_size // 4:  # Key length in hex characters
            key = bytes.fromhex(user_key)
        else:
            raise ValueError(f"Key must be exactly {selected_key_size // 4} hex characters ({selected_key_size} bits).")

        iv = os.urandom(16) if selected_mode.get() in ["CBC", "CFB"] else None
        if iv:
            iv_entry.delete(0, tk.END)
            iv_entry.insert(0, iv.hex())

        plaintext = plaintext_entry.get("1.0", tk.END).strip()
        mode = get_mode(iv)
        encrypted = encrypt(plaintext, key, iv, mode)
        encrypted_entry.delete("1.0", tk.END)
        encrypted_entry.insert("1.0", encrypted)

        elapsed_time = time.time() - start_time  # Calculate elapsed time
        encryption_time_label.config(text=f"Encryption Time: {elapsed_time:.4f} seconds")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Perform Decryption with Timer
def perform_decryption():
    try:
        start_time = time.time()  # Start timer

        selected_key_size = int(key_size_combo.get())
        user_key = key_entry.get().strip()

        if not user_key or len(user_key) != selected_key_size // 4:
            raise ValueError(f"Key must be exactly {selected_key_size // 4} hex characters ({selected_key_size} bits).")
        key = bytes.fromhex(user_key)

        iv = bytes.fromhex(iv_entry.get().strip()) if selected_mode.get() in ["CBC", "CFB"] else None
        encrypted_text = encrypted_entry.get("1.0", tk.END).strip()
        if not encrypted_text:
            raise ValueError("No encrypted text provided for decryption.")

        mode = get_mode(iv)
        decrypted = decrypt(encrypted_text, key, iv, mode)
        decrypted_entry.delete("1.0", tk.END)
        decrypted_entry.insert("1.0", decrypted)

        elapsed_time = time.time() - start_time  # Calculate elapsed time
        decryption_time_label.config(text=f"Decryption Time: {elapsed_time:.4f} seconds")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Get Mode Based on Selection
def get_mode(iv):
    mode = selected_mode.get()
    if mode == "ECB":
        return modes.ECB()
    elif mode == "CBC":
        return modes.CBC(iv)
    elif mode == "CFB":
        return modes.CFB(iv)
    else:
        raise ValueError("Invalid mode selected!")

def generate_key_iv():
    key_size = int(key_size_combo.get())
    key = os.urandom(key_size // 8)
    iv = os.urandom(16) if mode_var.get() == "CBC" else b""
    key_entry.delete(0, tk.END)
    key_entry.insert(0, key.hex())
    iv_entry.delete(0, tk.END)
    iv_entry.insert(0, iv.hex())


#############################################################################################
# Image Encryption decriptin Start
###############################################################################################




def encrypt_image(file_path, key, iv, mode):
    try:
        with open(file_path, "rb") as img_file:
            image_data = img_file.read()

        cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())
        encryptor = cipher.encryptor()
        padded_data = image_data + b'\x00' * (16 - len(image_data) % 16)  # Pad image data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        save_path = filedialog.asksaveasfilename(
            title="Save Encrypted Image",
            defaultextension=".enc",
            filetypes=[("Encrypted Files", "*.enc")]
        )
        if save_path:
            with open(save_path, "wb") as enc_file:
                enc_file.write(encrypted_data)
            messagebox.showinfo("Success", "Image encrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to encrypt image: {e}")

def decrypt_image(file_path, key, iv, mode):
    try:
        with open(file_path, "rb") as enc_file:
            encrypted_data = enc_file.read()

        cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        decrypted_data = decrypted_data.rstrip(b'\x00')  # Remove padding

        save_path = filedialog.asksaveasfilename(
            title="Save Decrypted Image",
            defaultextension=".png",
            filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")]
        )
        if save_path:
            with open(save_path, "wb") as img_file:
                img_file.write(decrypted_data)
            messagebox.showinfo("Success", "Image decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt image: {e}")

# GUI callbacks
def handle_image_encryption():
    file_path = filedialog.askopenfilename(
        title="Select an Image to Encrypt",
        filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif")]
    )
    if not file_path:
        return
    try:
        key = bytes.fromhex(key_entry.get())
        iv = bytes.fromhex(iv_entry.get()) if mode_var.get() == "CBC" else None
        mode = modes.CBC(iv) if mode_var.get() == "CBC" else modes.ECB()
        encrypt_image(file_path, key, iv, mode)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def handle_image_decryption():
    file_path = filedialog.askopenfilename(
        title="Select an Encrypted File",
        filetypes=[("Encrypted Files", "*.enc")]
    )
    if not file_path:
        return
    try:
        key = bytes.fromhex(key_entry.get())
        iv = bytes.fromhex(iv_entry.get()) if mode_var.get() == "CBC" else None
        mode = modes.CBC(iv) if mode_var.get() == "CBC" else modes.ECB()
        decrypt_image(file_path, key, iv, mode)
    except Exception as e:
        messagebox.showerror("Error", str(e))

####################################################################################################
# end Image Encryption/Decryption section
#####################################################################################################



#######################################################################################
#Email Start
#####################################################################################


# Send email function
def send_email(subject, body, sender, recipient, password):
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = recipient
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
            smtp_server.login(sender, password)
            smtp_server.sendmail(sender, recipient, msg.as_string())
        messagebox.showinfo("Success", "Encrypted data sent via email!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send email: {e}")

# Perform encryption and send email
def perform_encryption_and_send_email():
    try:
        # Encrypt data
        user_key = key_entry.get().strip()
        if len(user_key) != 64:  # For 256-bit key in hex
            raise ValueError("Key must be 256 bits (64 hex characters).")
        key = bytes.fromhex(user_key)
        iv = os.urandom(16)  # Generate random IV for CBC mode
        plaintext = plaintext_entry.get("1.0", tk.END).strip()
        mode = modes.CBC(iv)
        encrypted = encrypt(plaintext, key, iv, mode)

        # Prepare email details
        recipient_email = recipient_email_entry.get().strip()
        sender_email = sender_email_entry.get().strip()
        sender_password = sender_password_entry.get().strip()
        if not recipient_email or not sender_email or not sender_password:
            raise ValueError("Email details cannot be empty.")

        subject = "Encrypted Data"
        body = f"Encrypted Data: {encrypted}\n\nIV: {iv.hex()}"

        # Send email
        send_email(subject, body, sender_email, recipient_email, sender_password)
    except Exception as e:
        messagebox.showerror("Error", str(e))


###################################################################################################
#Email END
##################################################################################################



#############################################################################################
#Clean Form
###############################################################################################

# Clear Fields
def clear_fields():
    key_entry.delete(0, tk.END)
    iv_entry.delete(0, tk.END)
    plaintext_entry.delete("1.0", tk.END)
    encrypted_entry.delete("1.0", tk.END)
    decrypted_entry.delete("1.0", tk.END)


#############################################################################################
#Clean End
############################################################################################





############################################################################################
#GUI START
############################################################################################

# GUI Application
root = tk.Tk()
root.title("AES Encryption and Decryption Tool By Yashan ")
app_font = tkFont.Font(family="Times", size=12)

# Font Resizing Section
font_resize_frame = tk.Frame(root)
font_resize_frame.pack()
tk.Label(font_resize_frame, text="Font Resizer", font=app_font).pack(side=tk.LEFT)
tk.Button(font_resize_frame, text="Increase Font Size", command=increase_font_size).pack(side=tk.LEFT)
tk.Button(font_resize_frame, text="Decrease Font Size", command=decrease_font_size).pack(side=tk.LEFT)


# Add Timer Labels in the GUI
encryption_time_label = tk.Label(root, text="Encryption Time: N/A", font=app_font)
encryption_time_label.pack()

decryption_time_label = tk.Label(root, text="Decryption Time: N/A", font=app_font)
decryption_time_label.pack()



# Key Size Selection
key_size_label = tk.Label(root, text="Select key size:",font=app_font)
key_size_label.pack()
key_size_combo = ttk.Combobox(root, values=["128", "192", "256"], state="readonly")
key_size_combo.set("256")  # Default selection
key_size_combo.pack()

# Key Input
key_label = tk.Label(root, text="Enter a key (hex):",font=app_font)
key_label.pack()
key_entry = tk.Entry(root, width=70)
key_entry.pack()

# IV Input
iv_label = tk.Label(root, text="IV (for CBC and CFB modes):",font=app_font)
iv_label.pack()
iv_entry = tk.Entry(root, width=70)
iv_entry.pack()

# Mode Selection
mode_label = tk.Label(root, text="Select AES mode:",font=app_font)
mode_label.pack()
selected_mode = tk.StringVar(value="ECB")  # Default mode
modes_frame = tk.Frame(root)
modes_frame.pack()
mode_var = tk.StringVar(value="CBC")
tk.Radiobutton(modes_frame, text="ECB", variable=selected_mode, value="ECB").pack(side=tk.LEFT)
tk.Radiobutton(modes_frame, text="CBC", variable=selected_mode, value="CBC").pack(side=tk.LEFT)
tk.Radiobutton(modes_frame, text="CFB", variable=selected_mode, value="CFB").pack(side=tk.LEFT)

# Plaintext Input
plaintext_label = tk.Label(root, text="Enter plaintext to encrypt:",font=app_font)
plaintext_label.pack()
plaintext_entry = tk.Text(root, height=5, width=70)
plaintext_entry.pack()

# Encrypt Button
encrypt_button = tk.Button(root, text="Encrypt", command=perform_encryption,font=app_font)
encrypt_button.pack()

# Encrypted Output
encrypted_label = tk.Label(root, text="Encrypted Text (Hex):",font=app_font)
encrypted_label.pack()
encrypted_entry = tk.Text(root, height=5, width=70)
encrypted_entry.pack()

# Decrypt Button
decrypt_button = tk.Button(root, text="Decrypt", command=perform_decryption,font=app_font)
decrypt_button.pack()

# Decrypted Output
decrypted_label = tk.Label(root, text="Decrypted Text:",font=app_font)
decrypted_label.pack()
decrypted_entry = tk.Text(root, height=5, width=70)
decrypted_entry.pack()

# Clear Button
clear_button = tk.Button(root, text="Clear", command=clear_fields,font=app_font)
clear_button.pack()

# Image Encrypt/Decrypt buttons
image_encrypt_button = tk.Button(root, text="Encrypt Image", command=handle_image_encryption,font=app_font)
image_encrypt_button.pack()

image_decrypt_button = tk.Button(root, text="Decrypt Image", command=handle_image_decryption,font=app_font)
image_decrypt_button.pack()

generate_button = tk.Button(root, text="Generate Key & IV", command=generate_key_iv,font=app_font)
generate_button.pack()

# Email Details
recipient_email_label = tk.Label(root, text="Recipient Email:",font=app_font)
recipient_email_label.pack()
recipient_email_entry = tk.Entry(root, width=70)
recipient_email_entry.pack()

sender_email_label = tk.Label(root, text="Your Email:",font=app_font)
sender_email_label.pack()
sender_email_entry = tk.Entry(root, width=70)
sender_email_entry.pack()

sender_password_label = tk.Label(root, text="Your Email Password:",font=app_font)
sender_password_label.pack()
sender_password_entry = tk.Entry(root, show="*", width=70)
sender_password_entry.pack()

# Encrypt and Send Button
encrypt_send_button = tk.Button(root, text="Encrypt and Send Email", command=perform_encryption_and_send_email,font=app_font)
encrypt_send_button.pack()




# Run Application
root.mainloop()
