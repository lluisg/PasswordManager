from tkinter import *
from tkinter import ttk

PASSWORD = "1w"
USER = "Lluis"

window = Tk()
window.geometry("800x800")
window.title("Password Manager")
window.iconbitmap("pass_icon.ico")
frame = Frame(window)
frame.pack()

def checkPassword():
    pass_input = input0_pass.get()

    #hashing password and check
    if(pass_input == PASSWORD):
        text0_welcome.pack_forget()
        input0_pass.pack_forget()
        but0_pass.pack_forget()
        text0_wrong.pack_forget()

        text1_inside.pack()
        but1_show.pack()
        but1_add.pack()
        but1_modify.pack()
    else:
        text0_wrong.pack()

def show_passwords():
    text1_inside.pack_forget()
    but1_show.pack_forget()
    but1_add.pack_forget()
    but1_modify.pack_forget()

    text2_inside.pack()
    treeview2.pack()

    f = open("passwords.txt", "r")
    for line in f:
        line_split = line.split('-')
        name = line_split[0]
        user = line_split[1]
        passw = line_split[2]
        #uncoding the passowrds etc to be readable
        father = treeview2.insert("", 0, text=name)
        treeview2.insert(father, END, text=user)
        treeview2.insert(father, END, text=passw)
    f.close()

    but_back2.pack()



def add_password():
    text1_inside.pack_forget()
    but1_show.pack_forget()
    but1_add.pack_forget()
    but1_modify.pack_forget()

    but_back3.pack()
    text3_tag.pack()
    input3_newname.pack()
    text3_user.pack()
    input3_newuser.pack()
    text3_password.pack()
    input3_newpassw.pack()
    but3_add2list.pack()

def add2list():
    n = input3_newname.get()

    f = open("passwords.txt", "r")
    #if there's already an element with that name
    for line in f:
        line_split = line.split('-')
        name = line_split[0]
        if n == name:
            go_back("from_add_wrong")

    u = input3_newuser.get()
    p = input3_newpassw.get()
    # codification of password etc
    f = open("passwords.txt", "a")
    f.write('\n'+n+'-'+u+'-'+p)
    f.close()

    go_back("from_add_correctlyadd")


def edit_passwords():
    text1_inside.pack_forget()
    but1_show.pack_forget()
    but1_add.pack_forget()
    but1_modify.pack_forget()

    but_back4.pack()
    text4_ask.pack()
    input4_searchname.pack()
    but4_search.configure(text="Search")
    but4_search.pack()

def search_name():
    name_input = input4_searchname.get()
    namefound = False

    f = open("passwords.txt", "r")
    for line in f:
        line_split = line.split('-')
        name = line_split[0]
        # print('input: '+name_input+' - line name: '+name)
        if(name_input==name):
            namefound = True
            global user_found, passw_found
            user_found.set(line_split[1])
            passw_found.set(line_split[2])

            but4_search.configure(text="Search Again")
            text4_notfound.pack_forget()
            text4_edituser.pack()
            input4_edituser.pack()
            input4_edituser.configure(state='normal', text="a")
            # input4_edituser.delete(1.0,END)
            but4_sameuser.pack()
            text4_editpass.pack()
            input4_editpass.configure(state='normal', text="a")

            # input4_editpass.delete(1.0,END)
            input4_editpass.pack()
            but4_samepass.pack()
            but4_editpass.pack()

    if(namefound==False):
        text4_edituser.pack_forget()
        input4_edituser.pack_forget()
        but4_sameuser.pack_forget()
        text4_editpass.pack_forget()
        input4_editpass.pack_forget()
        but4_samepass.pack_forget()
        but4_editpass.pack_forget()
        text4_notfound.pack()

def previous_user():
    input4_edituser.configure(state='disabled', text=user_found)

def previous_pass():
    input4_editpass.configure(state='disabled', text=passw_found)

def edit_passw():
    list_of_lines = []
    name_input = input4_searchname.get()
    f = open("passwords.txt", "r")
    for line in f:
        line_split = line.split('-')
        name = line_split[0]
        if(name_input==name):
            list_of_lines.append(name+'-'+input4_edituser.get()+'-'+input4_editpass.get())
        else:
            list_of_lines.append(line)

    f = open("passwords.txt", "w")
    f.writelines(list_of_lines)
    f.close()

    go_back("from_edit")

def go_back(from_where):
    but_back2.pack_forget()
    but_back3.pack_forget()
    but_back4.pack_forget()

    text2_inside.pack_forget()
    treeview2.pack_forget()
    for elem in treeview2.get_children():
        treeview2.delete(elem)

    text3_tag.pack_forget()
    input3_newname.pack_forget()
    text3_user.pack_forget()
    input3_newuser.pack_forget()
    text3_password.pack_forget()
    input3_newpassw.pack_forget()
    but3_add2list.pack_forget()

    text3_added.pack_forget()
    text3_notadded.pack_forget()


    text4_ask.pack_forget()
    input4_searchname.pack_forget()
    but4_search.pack_forget()
    text4_notfound.pack_forget()
    text4_edituser.pack_forget()
    input4_edituser.pack_forget()
    but4_sameuser.pack_forget()
    text4_editpass.pack_forget()
    input4_editpass.pack_forget()
    but4_samepass.pack_forget()
    but4_editpass.pack_forget()

    text1_inside.pack()
    but1_show.pack()
    but1_add.pack()
    but1_modify.pack()
    if from_where == "from_add_correctly":
        text3_added.pack()
    elif from_where == "from_add_wrong":
        text3_notadded.pack()



#STARTING PAGE 0 ---------------------------------------
text0_welcome = Label(frame, text="Write your password")
input0_pass = Entry(frame)
but0_pass = Button(frame, text="Enter", command=checkPassword, activebackground="black")

text0_wrong = Label(frame, text="ARE YOU TRYING TO STEAL??", background = 'red')

#MENU OPTIONS PAGE 1 -------------------------------------
text1_inside = Label(frame, text="Hello "+USER)
but1_show = Button(frame, text="Show", command=show_passwords, activebackground="black")
but1_add = Button(frame, text="New", command=add_password, activebackground="black")
but1_modify = Button(frame, text="Modify", command=edit_passwords, activebackground="black")

#SHOW PASSWORDS PAGE 2 -------------------------------------
text2_inside = Label(frame, text="Here are your passwords")
but_back2 = Button(frame, text="Go back", command=lambda: go_back("from_2"), activebackground="black")
treeview2 = ttk.Treeview()

#NEW PASSWORD PAGE 3 --------------------------------------
text3_tag = Label(frame, text="Tag:")
input3_newname = Entry(frame)
text3_user = Label(frame, text="User:")
input3_newuser = Entry(frame)
text3_password = Label(frame, text="Password")
input3_newpassw = Entry(frame)
but3_add2list = Button(frame, text="Add Password", command=add2list, activebackground="black")
text3_added = Label(frame, text="New password added") #if the password is added correctly
text3_notadded = Label(frame, text="There was already a matching element")
but_back3 = Button(frame, text="Go back", command=lambda: go_back("from_3"), activebackground="black")

#EDIT PASSWORD PAGE 4 -------------------------------------
text4_ask = Label(frame, text="Which password would you like to change?")
input4_searchname = Entry(frame)
but4_search = Button(frame, text="Search", command=search_name, activebackground="black")
text4_notfound = Label(frame, text="No passwords with this element", foreground="red")
but_back4 = Button(frame, text="Go back", command=lambda: go_back("from_4"), activebackground="black")

user_found = StringVar() #where the name will be saved, if the user wants to user the previous one
passw_found = StringVar() #where the password will be saved, if the user wants to user the previous one
text4_edituser = Label(frame, text="New username")
input4_edituser = Entry(frame)
but4_sameuser = Button(frame, text="Same as previous user", command=previous_user, activebackground="black")
text4_editpass = Label(frame, text="New password")
input4_editpass = Entry(frame)
but4_samepass = Button(frame, text="Same as previous password", command=previous_pass, activebackground="black")
but4_editpass = Button(frame, text="Modify Password", command=edit_passw, activebackground="black")


# AFEGIR LA OPCIO DE SELECCIONAR SI TIPUS WEBS - JOCS - IMPORTANTS
# (INCLOURE UN ELEMENT MES A EL TXT)








# START RUNNING--------------------------------------------------------------
text0_welcome.pack(fill = X)
input0_pass.pack()
but0_pass.pack()


window.mainloop()
