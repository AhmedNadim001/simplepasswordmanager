
import random
from cryptography.fernet import Fernet
import json
import os
import hashlib
import base64
masteruser_password_dict ={}
local_username_password_dict = {}
key_info_dict = {}
#
# Text File Initialization
def textfile_dict_init(textfilename,relevantdictionary):
    # checks if file is empty, if yes, populates with an empty dict --> so that json.load() can always work
    file = open(textfilename, "a+")
    file.close()
    if os.path.getsize(textfilename) == 0:
        with open(textfilename, "w") as f:
            json.dump({}, f)
    # loads information from text file to the dictionary
    with open(textfilename, 'r') as f:
        relevantdictionary.update(json.load(f))

# USER MANAGEMENT
def add_user():
    username = input("Please enter a username: ")
    if username not in masteruser_password_dict:
        password = input("Please enter a password: ")
        question1 = input("In which city were you born? ").lower()
        question2 = input("What is the last name of your mother? ").lower()
        key_str = username + question1 + question2
        encrypted_password, key_encrypted = encrypt_password(key_str, password)
        key_info_dict[username] = key_encrypted
        masteruser_password_dict[username] = encrypted_password
        with open("masterinfo.txt", "w") as f:
            json.dump(masteruser_password_dict, f)
        with open("key_info.txt", "w") as g:
            json.dump(key_info_dict, g)

def login_user(masterusrname, masterpasswd):
    username = masterusrname
    password = masterpasswd
    if check_password(username, password):
        textfile_dict_init(username + ".txt", local_username_password_dict)
        return True

def forgot_password():
    username = input("Please input your username")
    if username in masteruser_password_dict.keys():
        question1 = input("In which city were you born? ").lower()
        question2 = input("What is the last name of your mother? ").lower()
        key_str = username + question1 + question2
        _, key_encrypted = encrypt_password(key_str, "_")
        if key_info_dict[username] == key_encrypted:
            password = input("Input new password")
            encrypted_password, _ = encrypt_password(key_str, password)
            masteruser_password_dict[username] = encrypted_password
            with open("masterinfo.txt", "w") as f:
                json.dump(masteruser_password_dict, f)


# PASSWORD ENCRYPTION AND DECRYPTION

def encrypt_password(key_info, password):
    salt= b"password"
    key = hashlib.pbkdf2_hmac('sha256', key_info.encode(), salt, 100000)
    key = base64.urlsafe_b64encode(key)
    f = Fernet(key)
    encrypted_passwd = f.encrypt(password.encode())
    encrypted_passwd_str = base64.b64encode(encrypted_passwd).decode()
    key_string = base64.b64encode(key).decode()
    return encrypted_passwd_str, key_string

def decrypt_password(masterusername, encrypted_password):
    salt = b"password"
    key = masteruser_password_dict[masterusername]
    key = hashlib.pbkdf2_hmac('sha256', key.encode(), salt, 100000)
    key = base64.urlsafe_b64encode(key)
    f = Fernet(key)
    decrypted_password = base64.b64decode(encrypted_password)
    decrypted_password = f.decrypt(decrypted_password).decode()
    return decrypted_password


#LOCAL PASSWORD MANAGEMENT
def boolean_comparison(input_string):
    if input_string.lower == "yes":
        return True

def add_password_username(master_username):
    website_add = input('Website: ')
    if website_add not in local_username_password_dict.keys():
        username_add = input('Type the username: ')
        generate_pass_bool = input("Do you want to generate a password? Yes or No: ")
        if boolean_comparison(generate_pass_bool):
            generate_password()
        password_add = input('Type your password: ')
        encrypted_password_add, key_not_important = encrypt_password(masteruser_password_dict[master_username], password_add)
        local_username_password_dict[website_add] = [username_add,encrypted_password_add]
        with open(master_username + ".txt", "w") as f:
            json.dump(local_username_password_dict,f)
    else:
        print("There is already an entry for this website. Please use update password to update it")

def update_password(master_username):
    website_update = input("Website: ")
    if website_update in local_username_password_dict.keys():
        username_update = input("What is the new username? ")
        generate_pass_bool = input("Do you want to generate a password? Yes or No: ")
        if boolean_comparison(generate_pass_bool):
            generate_password()
        password_update = input("What is the new password?  ")
        encrypted_password_update, key_not_important = encrypt_password(masteruser_password_dict[master_username], password_update)
        local_username_password_dict[website_update] = [username_update, encrypted_password_update]
        with open(master_username + ".txt", "w") as f:
            json.dump(local_username_password_dict,f)
    else:
        print("Entry not found. Please use the add password feature")

def check_password(user_input_username, user_input_password):
    #retrieves key from dict and again encodes it into 32 byte URL safe bytes
    key = key_info_dict[user_input_username]
    key = base64.b64decode(key.encode())
    f= Fernet(key)
    #decryptes the password and converts it into string for comparison
    decrypted_password = base64.b64decode(masteruser_password_dict[user_input_username])
    decrypted_password = f.decrypt(decrypted_password).decode()
    if user_input_password == decrypted_password:
        # print("Password Matched")
        return True
    else:
        print("Password Not Matched")

def generate_password():
    password_generation_char_choice = ""
    characters = int(input("How many characters do you want? "))
    specialcharacterbool = input("Do you want special characters in your password? Yes or No: ")
    normal_alphabets_numbers = "abcdefghijklmnopqrstuvwxyzABCDEFGHIZKLMNOPQRSTUVWXYZ123456789"
    specialcharacter = "!@#$%^&*()_=+[{]}&#60&#62/?"
    if boolean_comparison(specialcharacterbool):
        password_generation_char_choice = normal_alphabets_numbers + specialcharacter
    else:
        password_generation_char_choice = normal_alphabets_numbers

        #Generates three sets of password using characters from password_generation_char_choice
    for x in range(1,4):
        generated_password = "".join(random.choice(password_generation_char_choice) for i in range(characters))
        print(f"{x}. {generated_password}")

def show_username_password(master_username):
    iteration_number = 1
    for key in local_username_password_dict:
        print("--------------------------------------------------")
        print(f"{iteration_number}. ")
        print(f"Website: {key} ")
        print(f"Username: {local_username_password_dict[key][0]} ")
        print(f"Password: {decrypt_password(master_username, local_username_password_dict[key][1])} \n")
        iteration_number +=1
        print("--------------------------------------------------")



# Console
textfile_dict_init("masterinfo.txt",masteruser_password_dict)
textfile_dict_init("key_info.txt", key_info_dict)

option_global = input(f" 1. Login \n 2. Sign up \n 3. Forgot Password \n 4. Quit \n")
if option_global == "1":
    is_password_verified = False
    masterusername_global = input("Please enter your masterusername: ")
    masterpassword_global = input("Please enter your masterpassword: ")
    is_password_verified = login_user(masterusername_global, masterpassword_global)
    while is_password_verified:
        print(f"1.Add Password \n"
              f"2.Update Password \n"
              f"3.Generate Password \n"
              f"4.Show username and password \n"
              f"5.Quit \n")
        option = input("Please enter a option: ")

        if option == '1':
            add_password_username(masterusername_global)
        elif option == '2':
            update_password(masterusername_global)
        elif option == '3':
            generate_password()
        elif option == '4':
            show_username_password(masterusername_global)
        elif option == "5":
            break
        else:
            option_status = True

elif option_global =="2":
    add_user()
elif option_global == "3":
    forgot_password()
elif option_global =="4":
    pass
else:
    pass









