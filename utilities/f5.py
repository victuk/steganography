from ntpath import join
import random
import textwrap

def generateKey():
    f5Key = []
    email = 'victorp3tr@gmail.com'
    list1 = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    for i in range(24):
        f5Key.append(random.choice(list1))
    print(''.join(f5Key))
    joinedKey = ''.join(f5Key)
    print(textwrap.wrap(joinedKey, 4))
    print(len(f5Key))
    fileName = email[:-4]
    with open("./static/files" + fileName + '.txt', 'w') as f:
        f.write(joinedKey)

        
generateKey()
