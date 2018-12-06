from Cryptodome.PublicKey import RSA

for usr in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
    key = RSA.generate(2048)
    keystr_priv = key.exportKey()
    with open("./keys/" + usr + "_priv.pem", "w") as prv_file:
        print("{}".format(keystr_priv.decode()), file=prv_file)

    keystr_pub = key.publickey().exportKey()
    with open("./keys/" + usr + "_pub.pem", "w") as pub_file:
        print("{}".format(keystr_pub.decode()), file=pub_file)
