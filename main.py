# Python program implementing Image Steganography
 
# PIL module is used to extract
# pixels of image and modify it
from PIL import Image
import rsa
import os
import base64

# Generate public and private key:
# Public key to encrypt, private key to decrypt
# 1024
def generateKeys(keyLength):
    if(keyLength >= int(1024)):
        (publicKey, privateKey) = rsa.newkeys(keyLength)
        # os.mkdir('./keys')
        # puKey = open("keys/publcKey.pem", "w")
        # puKey.write(str(publicKey.save_pkcs1('PEM')))
        # puKey.close()

        # prKey = open("keys/privateKey.pem", "w")
        # prKey.write(str(privateKey.save_pkcs1('PEM')))
        # prKey.close()

        with open('publicKey.pem', 'wb') as p:
            p.write(publicKey.save_pkcs1('PEM'))
        with open('privateKey.pem', 'wb') as p:
            p.write(privateKey.save_pkcs1('PEM'))
    else:
        print("Key length should not be less than 1024")
        genK()
 
# Convert encoding data into 8-bit binary
# form using ASCII value of characters
def genData(data):
 
        # list of binary codes
        # of given data
        newd = []
 
        for i in data:
            newd.append(format(ord(i), '08b'))
        return newd
 
# Pixels are modified according to the
# 8-bit binary data and finally returned
def modPix(pix, data):
 
    datalist = genData(data)
    lendata = len(datalist)
    imdata = iter(pix)
 
    for i in range(lendata):
 
        # Extracting 3 pixels at a time
        pix = [value for value in imdata.__next__()[:3] +
                                imdata.__next__()[:3] +
                                imdata.__next__()[:3]]
 
        # Pixel value should be made
        # odd for 1 and even for 0
        for j in range(0, 8):
            if (datalist[i][j] == '0' and pix[j]% 2 != 0):
                pix[j] -= 1
 
            elif (datalist[i][j] == '1' and pix[j] % 2 == 0):
                if(pix[j] != 0):
                    pix[j] -= 1
                else:
                    pix[j] += 1
                # pix[j] -= 1
 
        # Eighth pixel of every set tells
        # whether to stop ot read further.
        # 0 means keep reading; 1 means thec
        # message is over.
        if (i == lendata - 1):
            if (pix[-1] % 2 == 0):
                if(pix[-1] != 0):
                    pix[-1] -= 1
                else:
                    pix[-1] += 1
 
        else:
            if (pix[-1] % 2 != 0):
                pix[-1] -= 1
 
        pix = tuple(pix)
        yield pix[0:3]
        yield pix[3:6]
        yield pix[6:9]
 
def encode_enc(newimg, data):
    w = newimg.size[0]
    (x, y) = (0, 0)
 
    for pixel in modPix(newimg.getdata(), data):
 
        # Putting modified pixels in the new image
        newimg.putpixel((x, y), pixel)
        if (x == w - 1):
            x = 0
            y += 1
        else:
            x += 1
 
# Encode data into image
def encode():
    img = input("Enter image name(with extension) : ")
    image = Image.open(img, 'r')
 
    data = input("Enter data to be encoded : ")
    print("Plain data::", data)

    with open('publicKey.pem', 'rb') as pub:
        publicKey = rsa.PublicKey.load_pkcs1(pub.read())

    # with open('privateKey.pem', 'rb') as pri:
    #     privateKey = rsa.PrivateKey.load_pkcs1(pri.read())

    encD = rsa.encrypt(data.encode('utf-8') , publicKey)
    encData = base64.urlsafe_b64encode(encD)

    # signedData = rsa.sign(data.encode('utf8'), privateKey, 'SHA-1')


    print("Encrypted Data:: ", base64.urlsafe_b64encode(encData).decode('utf-8'))
    

    if (len(encData) == 0):
        raise ValueError('Data is empty')
 
    newimg = image.copy()
    encode_enc(newimg, encData.decode('utf-8'))
 
    new_img_name = input("Enter the name of new image(with extension) : ")
    newimg.save(new_img_name, str(new_img_name.split(".")[1].upper()))
 
# Decode the data in the image
def decode():
    img = input("Enter image name(with extension) : ")
    image = Image.open(img, 'r')
 
    data = ''
    imgdata = iter(image.getdata())
 
    while (True):
        pixels = [value for value in imgdata.__next__()[:3] +
                                imgdata.__next__()[:3] +
                                imgdata.__next__()[:3]]
 
        # string of binary data
        binstr = ''
 
        for i in pixels[:8]:
            if (i % 2 == 0):
                binstr += '0'
            else:
                binstr += '1'
 
        data += chr(int(binstr, 2))
        if (pixels[-1] % 2 != 0):
            
            # print(base64.urlsafe_b64decode(data).decode('utf-8'))
            # print(base64.urlsafe_b64decode(data))
            # return
            
            with open('privateKey.pem', 'rb') as pri:
                privateKey = rsa.PrivateKey.load_pkcs1(pri.read())

            outData = rsa.decrypt(base64.urlsafe_b64decode(data), privateKey)

            print("Encrypted data:: ")
            print(outData.decode('utf-8'))
            return outData.decode('utf-8')

def genK():
    keyLength = int(input("Enter Key Length\n"))
    generateKeys(keyLength)

# Main Function
def main():
    a = int(input(":: Welcome to Steganography ::\n"
                        "1. Generate Key \n2. Encode\n3. Decode\n"))
    if (a == 1):
        genK()
    elif (a==2):
        encode()
    elif (a == 3):
        print("Decoded Word :  " + decode())
    else:
        raise Exception("Enter correct input")
 
# Driver Code
if __name__ == '__main__' :
 
    # Calling main function
    main()