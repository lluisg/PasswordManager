import os
from stat import S_IREAD, S_IRGRP, S_IROTH, S_IWUSR
# import hashlib
from security import hash_password, check_hash_password

filename1 = "passwords.txt"
filename2 = "principal.txt"
password = '1w'
username = 'lluis'

option = input("Select option: \n 1-Make passwords readable \n 2-Make passwords unreadable \
                    \n 3-Reestart password \n 4-Make principal readable \
                    \n 5-Make principal unreadable \n")
if option == '1':
    os.chmod(filename1, S_IWUSR|S_IREAD) # wathever
elif option == '2':
    os.chmod(filename1, S_IREAD|S_IRGRP|S_IROTH) #makes it read only
elif option == '3':
    os.chmod(filename2, S_IWUSR|S_IREAD) # wathever

    # hasher = hashlib.sha256()
    # hasher.update(password.encode('utf8'))
    # hashed_element = hasher.hexdigest()

    f = open(filename2, 'w')
    # f.write(hashed_element+'\n'+username)
    f.write(encrypt_password(password)+'\n'+username)
    f.close()

    os.chmod(filename2, S_IREAD|S_IRGRP|S_IROTH) #makes it read only

elif option == '4':
    os.chmod(filename2, S_IWUSR|S_IREAD) # wathever

elif option == '5':
    os.chmod(filename2, S_IREAD|S_IRGRP|S_IROTH) #makes it read only
else:
    print('WRONG OPTION')

#
# os.chmod(filename, S_IWUSR|S_IREAD) # wathever
#
# # hasher = hashlib.sha256()
# # hasher.update(password.encode('utf8'))
# # hashed_element = hasher.hexdigest()
#
# f = open(filename, 'w')
# # f.write(hashed_element+'\n'+username)
# f.write(encrypt_password(password)+'\n'+username)
# f.close()
#
# os.chmod(filename, S_IREAD|S_IRGRP|S_IROTH) #makes it read only
