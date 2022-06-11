from ast import Try
import jwt

jwtSecret = '1592e2945cc2e8153171e692c44ceeffd98128be9a79b2d6'

def check(token):
    try:
         decoded = jwt.decode(token, jwtSecret, algorithms="HS256")
         return decoded
    except:
        return None