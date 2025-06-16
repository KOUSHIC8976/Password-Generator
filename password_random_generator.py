import tkinter as tk
import random
import string

def generate_password():
    password_length = int(length_entry.get())
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(password_length))
    result_label.config(text="Generated Password: " + password)

window = tk.Tk()
window.title("Random Password Characters Generator")

length_label = tk.Label(window, text="Length of password to be generated:")
length_label.pack()
length_entry = tk.Entry(window)
length_entry.pack()

generate_button = tk.Button(window, text="Generate Random Password", command=generate_password)
generate_button.pack()

result_label = tk.Label(window, text="")
result_label.pack()

window.mainloop()
