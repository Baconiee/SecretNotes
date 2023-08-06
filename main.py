import tkinter.messagebox
from tkinter import *
from PIL import ImageTk, Image
import base64
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def button_save_encrypt():
    title = entry.get()
    secret = text.get("1.0", END)
    key = entry1.get()
    if title == "" or secret == "" or key == "":
        tkinter.messagebox.showwarning(title="Error", message="Please Enter All Information")
    else:
        message_encrypted = encode(key, secret)

        try:
            with open("/Users/albus/PycharmProjects/SecretNotes/secrets.txt", mode="a") as my_file:
                my_file.write(f"\n{title}\n{message_encrypted}")
                my_file.close()
        except:
            pass
        finally:
            entry.delete(0, END)
            entry1.delete(0, END)
            text.delete("1.0", END)
def button_decrypt():
    secret = text.get("1.0", END)
    key = entry1.get()


    if len(secret) == 0 or len(key) == 0:
       tkinter. messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        try:
            decrypted_message = decode(key, secret)
            text.delete("1.0", END)
            text.insert("1.0", decrypted_message)
        except:
            tkinter.messagebox.showinfo(title="Error!", message="Please make sure of encrypted info.")



window = Tk()
window.title("Secret Notes")
window.geometry("400x550")

my_picture = ImageTk.PhotoImage(file="topsecret.jpg")
my_picture = Image.open("topsecret.jpg")
resized = my_picture.resize((50, 50), Image.Resampling.LANCZOS)
new_picture = ImageTk.PhotoImage(resized)

my_label = Label(window, image=new_picture, height=70, width=50)
my_label.pack()

label_for_entry = Label(text="Enter Your Title", font=('Arial', 13, "bold"))
label_for_entry.pack()
entry = Entry(width=40)
entry.pack()

label_for_text = Label(text="Enter Your Secret", font=('Arial', 13, "bold"))
label_for_text.pack()
text = Text(height=15, width=30)
text.pack()
label_for_entry1 = Label(text="Enter Master Key", font=('Arial', 13, "bold"))
label_for_entry1.pack()
entry1 = Entry(width=40)
entry1.pack()

button_save_encrypt = Button(text="Save and Encrypt", command=button_save_encrypt)
button_save_encrypt.pack()
button_decrypt = Button(text="Decrypt", command=button_decrypt)
button_decrypt.pack()



window.mainloop()