from security_file import hash_password2

passw = 'made by lluis guardia'
passc = hash_password2(passw)
print(type(passc))
print(passc)
# passde = deencrypt_password(passc)
# print(type(passde))
# print(passde)

# hash1 = hash(passw)
# hash2 = hash(passw+'1')
# print(hash1)
# print(hash2)
# print(hash1 == hash2)
