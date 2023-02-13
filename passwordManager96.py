import sys, os
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from stat import S_IREAD, S_IRGRP, S_IROTH, S_IWUSR
try:
    import configparser
except:
    from six.moves import configparser
# from passlib.context import CryptContext
from passlib.hash import pbkdf2_sha256
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from readme import getReadme

def resource_path(relative_path):
    # print(os.path.join(os.path.abspath("."), relative_path))
    return os.path.join(os.path.abspath("."), relative_path)


passwords_file = 'passwords.info'
user_file = 'user.info'
name_file = 'pbkdf2-sha256$29000$2JsTAsC4N4bQWkupVSqFkA$niBmSmVygLWtEf.Cot7rr0forqMpJxmPK8Hdw8Mw9Ts'
USER = ""

window = tk.Tk()
window.geometry("350x350")
window.title("Password Manager")
window.resizable(False, False)
frame = tk.Frame(window)
frame.pack()
framegrid = tk.Frame(window)


#--------------------------------------------------------------------------

# pwd_context = CryptContext(
#         schemes=["pbkdf2_sha256"],
#         default="pbkdf2_sha256",
#         pbkdf2_sha256__default_rounds=30000
# )

def hash_password(password):
    custom_pbkdf2 = pbkdf2_sha256.using(salt='123456'.encode())
    return pbkdf2_sha256.hash(password)

def read_password():
    passw = '...'
    if not os.path.isfile(resource_path(user_file)): #if there's no pass file, it creates it
        messagebox.showerror("Error", "COULDN'T FIND THE USER FILE.")
    else:
        f = open(resource_path(user_file), 'r')
        passw = f.readline()
        if passw[-1] == '\n':
            passw = passw[:-1]
        f.close()
    return passw

def check_hash_password(password):
    hashed = read_password()
    # return pwd_context.verify(password, hashed)
    return pbkdf2_sha256.verify(password, hashed)

def encrypt_password(message, password):
    key = get_key(password)
    f = Fernet(key)
    encrypted = f.encrypt(message.encode())
    return encrypted.decode()

def deencrypt_password(message, password):
    key = get_key(password)
    f = Fernet(key)
    decrypted = f.decrypt(message.encode())
    return decrypted.decode()

def get_key(password_provided):
    password = password_provided.encode() # Convert to type bytes
    salt = str(password_provided+'1296@@3dasf!##sdf').encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password)) # Can only use kdf once
    return key

#------------------------------------------------------------------------------
#cleanX : removes all elements from that page
#startX : packs all elements of that page

def checkPassword():
    global password_global
    pass_input = input0_pass.get()

    if(check_hash_password(pass_input)):
        clean(0)
        start(1)
        password_global = pass_input
        if not os.path.isfile(resource_path(passwords_file)): #if there's no pass file, it creates it
            open(resource_path(passwords_file), 'w').close()
            deny_modifying(resource_path(passwords_file))
    else:
        messagebox.showerror("Error", "PLEASE ENTER THE CORRECT PASSWORD")


def get_treeview():
    global filter_sel, flist, password_global
    treeview2.delete(*treeview2.get_children())

    try:
        f = open(resource_path(passwords_file), "r")
        for line in f:
            line_split = line.split('@@&&')
            name = deencrypt_password(line_split[0], password_global)
            user = deencrypt_password(line_split[1], password_global)
            passw = deencrypt_password(line_split[2], password_global)
            filter = deencrypt_password(line_split[3], password_global)

            if(filter_sel == filter or filter_sel == 'None'):
                father = treeview2.insert("", 0, text=name)
                treeview2.insert(father, tk.END, text='user: '+user)
                treeview2.insert(father, tk.END, text='pass: '+passw)
                treeview2.insert(father, tk.END, text='tag: '+filter)
        f.close()
    except Exception as e:
        print(e)
        messagebox.showerror("Error", "IT SEEMS YOUR PASSWORD FILE IS NOT ASSOCIATED TO YOUR USER")
        go_back('2to0')


def add2list():
    global password_global
    alreadyexists = False

    n = input3_newtag.get()

    try:
        f = open(resource_path(passwords_file), "r")
        #if there's already an element with that name
        for line in f:
            line_split = line.split('@@&&')
            name = deencrypt_password(line_split[0], password_global)
            if n == name:
                alreadyexists = True
                messagebox.showerror("Error", "ALREADY EXISTING ELEMENT")

        if alreadyexists == False:
            ne = encrypt_password(n, password_global)
            u = encrypt_password(input3_newuser.get(), password_global)
            p = encrypt_password(input3_newpass.get(), password_global)
            filt = encrypt_password(input3_newfilter.get(), password_global)
            allow_modifying(resource_path(passwords_file))
            f = open(resource_path(passwords_file), "a")
            f.write(ne+'@@&&'+u+'@@&&'+p+'@@&&'+filt+'\n')
            f.close()
            deny_modifying(resource_path(passwords_file))

            go_back("3to1correct")
    except:
        messagebox.showerror("Error", "IT SEEMS YOUR PASSWORD FILE IS NOT ASSOCIATED TO YOUR USER")
        go_back('3to0')

def edit_pass_search():
    global name_found, password_global

    list_of_lines = []
    try:
        f = open(resource_path(passwords_file), "r")
        for line in f:
            line_split = line.split('@@&&')
            name = line_split[0]
            name_de = deencrypt_password(name, password_global)
            if(name_found==name_de):
                user = encrypt_password(input4_user.get(), password_global)
                passw = encrypt_password(input4_pass.get(), password_global)
                filter = encrypt_password(input4_filter.get(), password_global)
                list_of_lines.append(name+'@@&&'+user+'@@&&'+passw+'@@&&'+filter+'\n')
            else:
                list_of_lines.append(line)

        allow_modifying(resource_path(passwords_file))
        f = open(resource_path(passwords_file), "w")
        f.writelines(list_of_lines)
        f.close()
        deny_modifying(resource_path(passwords_file))

        go_back("41to1")

    except:
        messagebox.showerror("Error", "IT SEEMS YOUR PASSWORD FILE IS NOT ASSOCIATED TO YOUR USER")
        go_back('41to0')

def edit_sameuser():
    global user_found, var4_assignuser, var4_sameuser
    if var4_sameuser:
        var4_assignuser.set("")
        input4_user.configure(state='normal')
    else:
        var4_assignuser.set(user_found)
        input4_user.configure(state='disabled')
    var4_sameuser = not var4_sameuser


def edit_samepass():
    global pass_found, var4_assignpass, var4_samepass
    if var4_samepass:
        var4_assignpass.set("")
        input4_pass.configure(state='normal')
    else:
        var4_assignpass.set(pass_found)
        input4_pass.configure(state='disabled')
    var4_samepass = not var4_samepass


def edit_samefilter():
    global filter_found, var4_assignfilter, var4_samefilter
    if var4_samefilter:
        var4_assignfilter.set("")
        input4_filter.configure(state='normal')
    else:
        var4_assignfilter.set(filter_found)
        input4_filter.configure(state='disabled')
    var4_samefilter = not var4_samefilter


def search_name():
    namefound = False
    global name_found, user_found, pass_found, filter_found, password_global

    name_input = input4_name.get()

    try:
        f = open(resource_path(passwords_file), "r")
        for line in f:
            line_split = line.split('@@&&')
            name_e = line_split[0]
            name_de = deencrypt_password(name_e, password_global)
            if(name_input==name_de):
                name_found = name_input
                user_found = deencrypt_password(line_split[1], password_global)
                pass_found = deencrypt_password(line_split[2], password_global)
                filter_found = deencrypt_password(line_split[3], password_global)
                namefound=True
    except:
        messagebox.showerror("Error", "IT SEEMS YOUR PASSWORD FILE IS NOT ASSOCIATED TO YOUR USER")
        go_back('4to0')


    if namefound == False:
        messagebox.showerror("Error", "NO PASSWORD ASSOCIATED")
    elif namefound == True:
        clean(4)
        start(41)


def user_created_blank():
    newuser_input = input51_newuser.get()
    newpass_input = input51_newpass.get()

    hash_pass = hash_password(newpass_input)
    f = open(resource_path(user_file), 'w')
    f.write(hash_pass+'\n'+newuser_input+'\n')
    f.close()
    deny_modifying(resource_path(user_file))

    if os.path.isfile(resource_path(passwords_file)): # if there's a pass file, it clears it
        allow_modifying(resource_path(passwords_file))
        open(resource_path(passwords_file), 'w').close()
        deny_modifying(resource_path(passwords_file))

    go_back('51to0')

def allow_modifying(filename):
    os.chmod(filename, S_IWUSR|S_IREAD)
def deny_modifying(filename):
    os.chmod(filename, S_IREAD|S_IRGRP|S_IROTH)


def user_created():
    prevpass_input = input5_previouspass.get()

    if(check_hash_password(prevpass_input)):
        response_warn = messagebox.askokcancel("Warning", "WITH THIS YOU WILL TO REMOVE ALL PREVIOUS PASSWORDS YOU HAD SAVED. \n (IF YOU PRESS 'NO', THE PASSWORD WILL CHANGE BUT THE FILE WITH THEM WILL NOT BE DELETED. Although it will be useless)")
        if(response_warn==1):
            allow_modifying(resource_path(passwords_file))
            open(resource_path(passwords_file), 'w').close()
            deny_modifying(resource_path(passwords_file))

        newuser_input = input5_newuser.get()
        newpass_input = input5_newpass.get()

        hash_pass = hash_password(newpass_input)
        allow_modifying(resource_path(user_file))
        f = open(resource_path(user_file), 'w')
        f.write(hash_pass+'\n'+newuser_input)
        f.close()
        deny_modifying(resource_path(user_file))

        go_back('5to0')
    else:
        messagebox.showerror("Error", "THE PREVIOUS PASSWORD WAS INCORRECT")


def getFilters():
    global password_global
    filters = []
    filters.append("None")
    f = open(resource_path(passwords_file), "r")
    for line in f:
        line_split = line.split('@@&&')
        filter = deencrypt_password(line_split[3], password_global)
        if filter not in filters:
            filters.append(filter)
    return filters

def filter_selected(event):
    global filter_sel
    filter_sel = combo2_filter.get()
    get_treeview()

def deletePassword():
    global password_global
    namefound = False
    name_input = input6_name.get()
    list_of_lines = []

    f = open(resource_path(passwords_file), "r")
    for line in f:
        line_split = line.split('@@&&')
        name_e = line_split[0]
        name_de = deencrypt_password(name_e, password_global)
        if(name_input==name_de):
            namefound=True
            name_found = name_de
            user_found = deencrypt_password(line_split[1], password_global)
            pass_found = deencrypt_password(line_split[2], password_global)
            filter_found = deencrypt_password(line_split[3], password_global)
        else:
            list_of_lines.append(line)
    f.close()

    if namefound == False:
        messagebox.showerror("Error", "NO PASSWORD ASSOCIATED")
    elif namefound == True:
        response_warn = messagebox.askokcancel("Warning", "ARE YOU SURE YOU WANT TO DELETE THE FOLLOWING PASSWORD? \n \
                                                                Name: "+name_found+"\n \
                                                                User: "+user_found+"\n \
                                                                Password: "+pass_found+"\n \
                                                                Tag: "+filter_found+"\n")
        if(response_warn==1):
            allow_modifying(resource_path(passwords_file))
            f = open(resource_path(passwords_file), "w")
            f.writelines(list_of_lines)
            f.close()
            deny_modifying(resource_path(passwords_file))

            go_back('6to1')

def register_user():
    newuser_input = input53_name.get()
    newpass_input = input53_pass.get()

    hash_pass = hash_password(newpass_input)
    f = open(resource_path(user_file), 'w')
    f.write(hash_pass+'\n'+newuser_input+'\n')
    f.close()
    deny_modifying(resource_path(user_file))

    go_back('53to0')
#-------------------------------------------------------------------------
def start(page):
    global USER
    if page == 0:

        f = open(resource_path(user_file), 'r')
        f.readline()
        USER = f.readline()
        f.close()
        if USER[-1] == '\n':
            USER = USER[:-1]
        text1_hello.configure(text="Hello "+USER)

        text0_welcome.pack(pady=(50,10))
        input0_pass.pack(ipadx=10, ipady=4, pady=(40,10))
        but0_pass.pack(pady=10, ipady=7, ipadx=12)
        but0_newuser.pack(padx=(200,10),pady=(60, 0), ipady=2, ipadx=2)
    elif page == 1:
        text1_hello.pack(pady=10)
        but1_show.pack(pady=10)
        but1_add.pack(pady=10)
        but1_edit.pack(pady=10)
        but1_delete.pack(pady=10)
    elif page == 2:
        text2_inside.pack(pady=(10,5), padx=5)
        global flist, filter_sel
        try:
            flist = getFilters()
            combo2_filter.configure(value = flist)
            combo2_filter.current(0)
            filter_sel = combo2_filter.get()
            combo2_filter.pack(pady=5, padx=5)
            treeview2.pack(pady=1)
            get_treeview()
            but2_back.pack(padx=10, ipadx=5, pady=5)
        except Exception as e:
            print(e)
    elif page == 3:
        text3_tag.pack(pady=(10,2))
        input3_newtag.pack(pady=2, ipady=2)
        text3_user.pack(pady=2)
        input3_newuser.pack(pady=2, ipady=2)
        text3_pass.pack(pady=2)
        input3_newpass.pack(pady=2, ipady=2)
        text3_filter.pack(pady=2)
        input3_newfilter.pack(pady=2, ipady=2)
        # but3_add.pack(padx=(200,5), pady=(10,0), ipady=5, ipadx=20)
        but3_add.pack(pady=10, ipady=6, ipadx=20)
        but3_back.pack(padx=(5,200), pady=(15,0), ipady=2)
    elif page == 4:
        text4_ask.pack(pady=(30,10))
        text4_name.pack(pady=(30,5))
        input4_name.pack(pady=5, ipady=3, ipadx=5)
        but4_search.pack(pady=10, ipadx=10, ipady=5)
        but4_back.pack(padx=(5,200), pady=(60,0), ipady=2, ipadx=2)
    elif page == 41:
        frame.pack_forget()
        framegrid.pack()
        text4_user.grid(row=0, column=0, pady=(15,5), padx=(40,25))
        input4_user.grid(row=1, column=0, ipady=5, ipadx=10, pady=5, padx=(40,25))
        but4_sameuser.grid(row=1, column=1, padx=15)
        text4_pass.grid(row=2, column=0, pady=(10,5), padx=(40,25))
        input4_pass.grid(row=3, column=0, ipady=5, ipadx=10, pady=5, padx=(40,25))
        but4_samepass.grid(row=3, column=1, padx=15)
        text4_filter.grid(row=4, column=0, pady=(10,5), padx=(40,25))
        input4_filter.grid(row=5, column=0, ipady=5, ipadx=10, pady=5, padx=(40,25))
        but4_samefilter.grid(row=5, column=1, padx=15)
        but4_edit.grid(row=6, column=1, ipady=10, ipadx=22, pady=(30,5), padx=(10,60), rowspan=2)
        but4_searchagain.grid(row=6, column=0, ipady=2, ipadx=5, pady=10)
        but41_back.grid(row=7, column=0, ipady=3, ipadx=5)
    elif page == 5:
        text5_previouspass.pack()
        input5_previouspass.pack()
        text5_newuser.pack()
        input5_newuser.pack()
        text5_newpass.pack()
        input5_newpass.pack()
        but5_create.pack()
        but5_goback.pack()
    elif page == 51:
        text51_newuser.pack(pady=(30,5))
        input51_newuser.pack(pady=5, ipady=2)
        text51_newpass.pack(pady=(10,5))
        input51_newpass.pack(pady=5, ipady=2)
        but51_create.pack(ipadx=10, ipady=5, pady=10)
        but51_help.pack(ipady=2, ipadx=5, padx=(200,5))
        text51_alreadyexist.pack(pady=(25,2))
        but51_alreadyexist.pack(pady=5, ipady=3, ipadx=5)
    elif page == 52:
        window.geometry("600x450")
        text52_title.pack(pady=(15,5), padx=10)
        text52_readme.pack(pady=5, padx=10)
        but52_return.pack(pady=10, ipady=5, ipadx=10)
    elif page == 53:
        text53_name.pack(pady=(25,5))
        input53_name.pack(ipady=2, pady=5)
        text53_pass.pack(pady=(10,5))
        input53_pass.pack(ipady=2, pady=5)
        but53_check.pack(ipady=2, ipadx=5, pady=(10,2))
        text53_disclaimer.pack()
        but53_back.pack(ipady=2, ipadx=3, pady=(40,5))
    elif page == 6:
        text6_ask.pack(pady=(30,10))
        text6_name.pack(pady=(30,5))
        input6_name.pack(pady=5, ipady=3, ipadx=5)
        but6_delete.pack(pady=10, ipadx=10, ipady=5)
        but6_goback.pack(padx=(5,200), pady=(60,0), ipady=2, ipadx=2)


def clean(page):
    if page == 0:
        text0_welcome.pack_forget()
        input0_pass.pack_forget()
        input0_pass.delete(0, 'end')
        but0_pass.pack_forget()
        but0_newuser.pack_forget()
    elif page == 1:
        text1_hello.pack_forget()
        but1_show.pack_forget()
        but1_add.pack_forget()
        but1_edit.pack_forget()
        but1_delete.pack_forget()
        text1_added.pack_forget()
        text1_edited.pack_forget()
    elif page == 2:
        text2_inside.pack_forget()
        but2_back.pack_forget()
        treeview2.pack_forget()
        combo2_filter.pack_forget()
    elif page == 3:
        text3_tag.pack_forget()
        input3_newtag.pack_forget()
        input3_newtag.delete(0, 'end')
        text3_user.pack_forget()
        input3_newuser.pack_forget()
        input3_newuser.delete(0, 'end')
        text3_pass.pack_forget()
        input3_newpass.pack_forget()
        input3_newpass.delete(0, 'end')
        text3_filter.pack_forget()
        input3_newfilter.pack_forget()
        input3_newfilter.delete(0, 'end')
        but3_add.pack_forget()
        but3_back.pack_forget()
    elif page == 4:
        text4_ask.pack_forget()
        text4_name.pack_forget()
        input4_name.delete(0, 'end')
        input4_name.pack_forget()
        but4_search.pack_forget()
        but4_back.pack_forget()
    elif page == 41:
        text4_user.pack_forget()
        input4_user.pack_forget()
        input4_user.delete(0, 'end')
        but4_sameuser.pack_forget()
        text4_pass.pack_forget()
        input4_pass.pack_forget()
        input4_pass.delete(0, 'end')
        but4_samepass.pack_forget()
        text4_filter.pack_forget()
        input4_filter.pack_forget()
        input4_filter.delete(0, 'end')
        but4_samefilter.pack_forget()
        but4_edit.pack_forget()
        but4_searchagain.pack_forget()
        but41_back.pack_forget()
        framegrid.pack_forget()
        frame.pack()
    elif page == 5:
        text5_previouspass.pack_forget()
        input5_previouspass.pack_forget()
        input5_previouspass.delete(0, 'end')
        text5_newuser.pack_forget()
        input5_newuser.pack_forget()
        input5_newuser.delete(0, 'end')
        text5_newpass.pack_forget()
        input5_newpass.pack_forget()
        input5_newpass.delete(0, 'end')
        but5_create.pack_forget()
        but5_goback.pack_forget()
    elif page == 51:
        text51_newuser.pack_forget()
        input51_newuser.pack_forget()
        input51_newuser.delete(0, 'end')
        text51_newpass.pack_forget()
        input51_newpass.pack_forget()
        input51_newpass.delete(0, 'end')
        but51_create.pack_forget()
        but51_help.pack_forget()
        text51_alreadyexist.pack_forget()
        but51_alreadyexist.pack_forget()
    elif page == 52:
        window.geometry("350x350")
        text52_title.pack_forget()
        text52_readme.pack_forget()
        but52_return.pack_forget()
    elif page == 53:
        text53_name.pack_forget()
        input53_name.pack_forget()
        text53_pass.pack_forget()
        input53_pass.pack_forget()
        but53_check.pack_forget()
        but53_back.pack_forget()
        text53_disclaimer.pack_forget()
    elif page == 6:
        text6_ask.pack_forget()
        text6_name.pack_forget()
        input6_name.pack_forget()
        input6_name.delete(0, 'end')
        but6_goback.pack_forget()
        but6_delete.pack_forget()

def go_back(from_where):
    if from_where == '0to5':
        clean(0)
        start(5)
    elif from_where == '2to0':
        clean(2)
        start(0)
    elif from_where == '3to0':
        clean(3)
        start(0)
    elif from_where == '4to0':
        clean(4)
        start(0)
    elif from_where == '41to0':
        clean(41)
        start(0)
    elif from_where == '1to2':
        clean(1)
        start(2)
    elif from_where == '1to3':
        clean(1)
        start(3)
    elif from_where == '1to4':
        clean(1)
        start(4)
    elif from_where == '1to6':
        clean(1)
        start(6)
    elif from_where == '2to1':
        clean(2)
        start(1)
    elif from_where == '3to1':
        clean(3)
        start(1)
    elif from_where == '3to1correct':
        clean(3)
        start(1)
        text1_added.pack(pady=5)
    elif from_where == '4to1':
        clean(4)
        start(1)
    elif from_where == '4to1':
        clean(41)
        start(1)
    elif from_where == '41to4':
        clean(41)
        start(4)
    elif from_where == '41to1':
        clean(41)
        start(1)
        text1_edited.pack(pady=5)
    elif from_where == '5to0':
        clean(5)
        start(0)
    elif from_where == '51to0':
        clean(51)
        start(0)
    elif from_where == '53to0':
        clean(53)
        start(0)
    elif from_where == '6to1':
        clean(6)
        start(1)
    elif from_where == '51to52':
        clean(51)
        start(52)
    elif from_where == '52to51':
        clean(52)
        start(51)
    elif from_where == '51to53':
        clean(51)
        start(53)
    elif from_where == '53to51':
        clean(53)
        start(51)

#------------------------------------------------------------------------------


#CREATE A NEW USER from blank PAGE 5.1 -------------------------------------
text51_newuser = tk.Label(frame, text="New Username:")
input51_newuser = tk.Entry(frame)
text51_newpass = tk.Label(frame, text="New Password:")
input51_newpass = tk.Entry(frame)
but51_create = tk.Button(frame, text="Register", command=user_created_blank, activebackground="black")
but51_help = tk.Button(frame, text = "Help", command=lambda: go_back("51to52"), bg="cyan", activebackground="black")
text51_alreadyexist = tk.Label(frame, text="Do you have the password file and a previous account?")
but51_alreadyexist = tk.Button(frame, text = "Login", command=lambda: go_back("51to53"), activebackground="black")

# HELP PAGE 5.2 ---------------------------------------------------
[titl, readme] = getReadme()
text52_title = tk.Label(frame, text=titl)
text52_readme = tk.Label(frame, text=readme, anchor='e')
but52_return = tk.Button(frame, text = "Okay", command=lambda: go_back("52to51"), activebackground="black")

# ALREADY EXISTING ACCOUNT 5.3 -----------------------------------
text53_name = tk.Label(frame, text='Previous name')
input53_name = tk.Entry(frame)
text53_pass = tk.Label(frame, text='Previous password')
input53_pass = tk.Entry(frame)
but53_check = tk.Button(frame, text = "Check", command=register_user, activebackground="black")
but53_back = tk.Button(frame, text = "Go Back", command=lambda: go_back("53to51"), activebackground="black")
text53_disclaimer = tk.Label(frame, text='Warning: Here the password will not be checked.\nIf the password is different from the previous, \nthe passwords will be not retrieved correctly')

#STARTING PAGE 0 ---------------------------------------
password_global = ""
text0_welcome = tk.Label(frame, text="Write your password")
input0_pass = tk.Entry(frame)
but0_pass = tk.Button(frame, text="Login", command=checkPassword, activebackground="black")
but0_newuser = tk.Button(frame, text="new user", command=lambda: go_back("0to5"), activebackground="black")

#MENU OPTIONS PAGE 1 -------------------------------------
text1_hello = tk.Label(frame)
but1_show = tk.Button(frame, text="Show", command=lambda: go_back("1to2"), activebackground="black", width=15, height=2)
but1_add = tk.Button(frame, text="Add", command=lambda: go_back("1to3"), activebackground="black", width=15, height=2)
but1_edit = tk.Button(frame, text="Modify", command=lambda: go_back("1to4"), activebackground="black", width=15, height=2)
but1_delete = tk.Button(frame, text="Delete", command=lambda: go_back("1to6"), activebackground="black", width=15, height=2)
text1_added = tk.Label(frame, text="Password Added Correctly") #if the password is added correctly
text1_edited = tk.Label(frame, text="Password Edited Correctly") #if the password is edited correctly

#SHOW PASSWORDS PAGE 2 -------------------------------------
text2_inside = tk.Label(frame, text="Here are your passwords:")
treeview2 = ttk.Treeview()
flist = [""]
filter_sel = ""
combo2_filter = ttk.Combobox(frame)
combo2_filter.bind("<<ComboboxSelected>>", filter_selected)
but2_back = tk.Button(frame, text="Go back", command=lambda: go_back("2to1"), activebackground="black")

#NEW PASSWORD PAGE 3 --------------------------------------
text3_tag = tk.Label(frame, text="Name:")
input3_newtag = tk.Entry(frame)
text3_user = tk.Label(frame, text="Username:")
input3_newuser = tk.Entry(frame)
text3_pass = tk.Label(frame, text="Password")
input3_newpass = tk.Entry(frame)
text3_filter = tk.Label(frame, text="Tag")
input3_newfilter = tk.Entry(frame)
but3_add = tk.Button(frame, text="Add", command=add2list, activebackground="black")
but3_back = tk.Button(frame, text="Go back", command=lambda: go_back("3to1"), activebackground="black")

#EDIT PASSWORD search PAGE 4 -------------------------------------
name_found = tk.StringVar()
text4_ask = tk.Label(frame, text="Which password would you like to change?")
text4_name = tk.Label(frame, text="Name:")
input4_name = tk.Entry(frame)
but4_search = tk.Button(frame, text="Search", command=search_name, activebackground="black")
but4_back = tk.Button(frame, text="Go back", command=lambda: go_back("4to1"), activebackground="black")

#EDIT PASSWORD edit PAGE 4.1 -------------------------------------
user_found = ""
pass_found = ""
filter_found = ""
var4_assignuser  = tk.StringVar() #where the name will be saved, if the user wants to user the previous one
var4_assignpass = tk.StringVar() #where the password will be saved, if the user wants to user the previous one
var4_assignfilter = tk.StringVar() #where the password will be saved, if the user wants to user the previous one
var4_sameuser = False
var4_samepass = False
var4_samefilter = False

text4_user = tk.Label(framegrid, text="New username")
input4_user = tk.Entry(framegrid, textvariable=var4_assignuser)
but4_sameuser = tk.Button(framegrid, text="previous\nuser", width=10, command=edit_sameuser, activebackground="black")
text4_pass = tk.Label(framegrid, text="New password")
input4_pass = tk.Entry(framegrid, textvariable=var4_assignpass)
but4_samepass = tk.Button(framegrid, text="previous\npassw", width=10, command=edit_samepass, activebackground="black")
text4_filter = tk.Label(framegrid, text="New filter")
input4_filter = tk.Entry(framegrid, textvariable=var4_assignfilter)
but4_samefilter = tk.Button(framegrid, text="previous\ntag", width=10, command=edit_samefilter, activebackground="black")
but4_edit = tk.Button(framegrid, text="Edit", command=edit_pass_search, activebackground="black")
but4_searchagain = tk.Button(framegrid, text="Search Again", command=lambda: go_back("41to4"), activebackground="black")
but41_back = tk.Button(framegrid, text="Go back", command=lambda: go_back("41to1"), activebackground="black")

#CREATE A NEW USER PAGE 5 -------------------------------------
text5_previouspass = tk.Label(frame, text="Previous Password:")
input5_previouspass = tk.Entry(frame)
text5_newuser = tk.Label(frame, text="New Username:")
input5_newuser = tk.Entry(frame)
text5_newpass = tk.Label(frame, text="New Password:")
input5_newpass = tk.Entry(frame)
but5_goback = tk.Button(frame, text="Go Back", command=lambda: go_back('5to0'), activebackground="black")
but5_create = tk.Button(frame, text="Create", command=user_created, activebackground="black")

#DELETE A PASSWORD 6 --------------------------------------------------------
text6_ask = tk.Label(frame, text="Which password do you want to delete?")
text6_name = tk.Label(frame, text="Name")
input6_name = tk.Entry(frame)
but6_goback = tk.Button(frame, text="Go Back", command=lambda: go_back('6to1'), activebackground="black")
but6_delete = tk.Button(frame, text="Delete", command=deletePassword, activebackground="black")


# START RUNNING--------------------------------------------------------------
if(os.path.isfile(resource_path(user_file))):
    start(0)
else:
    start(51)
window.mainloop()
