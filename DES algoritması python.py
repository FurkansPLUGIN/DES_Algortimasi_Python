# -*- coding: utf-8 -*-


#DES Algoritması

#Gerekli paketlerin eklenmesi
from Crypto.Cipher import DES
from secrets import token_bytes


#Anahtarın değişkeninin byte tipinde tanımlanması
anahtar=token_bytes(8)

#Şifreleme 
def sifrele(metin):
    cipher = DES.new(anahtar, DES.MODE_EAX)
    nonce = cipher.nonce
    sifreliMetin, tag = cipher.encrypt_and_digest(metin.encode('ascii'))
    return nonce, sifreliMetin, tag

#Şifreli metini çözme
def sifreyiCoz(nonce, sifreliMetin, tag):
    cipher = DES.new(anahtar, DES.MODE_EAX, nonce=nonce)
    cozulenMetin = cipher.decrypt(sifreliMetin)
    try:
        cipher.verify(tag)
        return cozulenMetin.decode('ascii')
    except:
        return False

nonce, sifreliMetin, tag = sifrele(input('Bir metin girin: '))
cozulenMetin = sifreyiCoz(nonce, sifreliMetin, tag)

print(f'Şifreli metin: {sifreliMetin}')

if not cozulenMetin:
    print('Hatalı metin')
else:
    print(f'Çözülmüş metin: {cozulenMetin}')
    
