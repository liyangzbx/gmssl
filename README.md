# gmssl

GmSSL是一个开源的加密包的python实现，支持SM2/SM3/SM4等国密(国家商用密码)算法、项目采用对商业应用友好的类BSD开源许可证，开源且可以用于闭源的商业应用。


## SM2算法

### 1. 生成随机SM2密钥
``` python
from gmssl import sm2, func
sm2_crypt = sm2.CryptSM2(private_key="", public_key="")
# 产生私钥
pri_key = func.random_hex(sm2_crypt.para_len).upper()
k = int(pri_key, 16)
# 通过私钥计算公钥
pub_key = sm2_crypt._kg(k, sm2_crypt.ecc_table['g'])
pubX = pub_key[0:64].upper()
pubY = pub_key[64:len(pub_key)].upper()
```

### 2. encrypt 
``` python
#数据和加密后数据为hex类型 ,后述均为hex
plaintext = "31"
sm2_crypt = sm2.CryptSM2(private_key="", public_key=public_key)
enc_data = sm2_crypt.encrypt(bytes.fromhex(plaintext))
enc_data = bytes.hex(enc_data).upper()
C1 = enc_data[0:128]
C3 = enc_data[128:192]
C2 = enc_data[192:]
```

### 3. decrypt  
 ``` python
sm2_crypt = sm2.CryptSM2(private_key=pri_key, public_key="")
enc_data = bytes.fromhex(C1 + C3 + C2)
dec_data = sm2_crypt.decrypt(enc_data)
dec_result = bytes(dec_data).hex().upper()
```
### 4. sign
``` python
# 签名userId参与数据哈希 ，所有输入均为hex
msg = '31"
userId = "31323334353637383132333435363738"
sm2_crypt = sm2.CryptSM2(private_key="", public_key="")
k = int(pri_key, 16)
pub_key = sm2_crypt._kg(k, sm2_crypt.ecc_table['g'])  # 通过输入的私钥计算出公钥
pubX = pub_key[0:64].upper()
pubY = pub_key[64:len(pub_key)].upper()
public_key = pubX + pubY
sm2_crypt = sm2.CryptSM2(private_key="", public_key=public_key)  # 用私钥计算出的公钥参与计算明文的哈希
e_hash = sm2_crypt.sm2_get_e(userId, msg).upper()

random_hex_str = func.random_hex(sm2_crypt.para_len)  # 生成签名需要的随机数
sm2_crypt = sm2.CryptSM2(private_key=pri_key, public_key="")
sign = sm2_crypt.sign(bytes.fromhex(e_hash), random_hex_str).upper()  # 私钥签名
sign_R = sign[0:64]
sign_S = sign[64:]
```

### 5. verify
``` python
sm2_crypt = sm2.CryptSM2(private_key="", public_key=public_key)  # 公钥参与计算明文的哈希
e_hash = sm2_crypt.sm2_get_e(userId, msg).upper()
public_key = pubX + pubY
sm2_crypt = sm2.CryptSM2(private_key="", public_key=public_key)
sign = sign_R + sign_S
verify = sm2_crypt.verify(sign, bytes().fromhex(e_hash))
if verify:
    return True
else:
    return False
```    
    
## SM4算法
国密SM4, 分组算法， 分组长度为128bit， 密钥长度为128bit， 算法具体内容参照SM4算法。

gmssl是包含国密SM4算法的Python实现， 提供了 encrypt_ecb、 decrypt_ecb、 encrypt_cbc、 decrypt_cbc 、encrypt_cfb 、encrypt_ofb、encrypt_ctr、decrypt_cfb、decrypt_ofb、decrypt_ctr等函数用于加密解密， 用法如下：

### 1. 初始化CryptSM4
``` python
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT

Key = "977F945E5BF4A7B0AB61B0CD49AE04E5"
plaintext = "11111111111111111111111111111111"
iv = "31313131313131313131313131313131"
crypt_sm4 = CryptSM4()
```

### 2、encrypt_ecb和decrypt_ecb
``` python
crypt_sm4.set_key(bytes.fromhex(Key), SM4_ENCRYPT) #加密
en = crypt_sm4.crypt_ecb(bytes.fromhex(plaintext))
ciper = bytes.hex(en).decode().upper()

crypt_sm4.set_keybytes.fromhex(Key), SM4_DECRYPT)  #解密
de = crypt_sm4.crypt_ecb(bytes.fromhex(ciper))
decrypt_value = bytes.hex(de).decode().upper()
assert plaintext == decrypt_value
```

### 3、encrypt_cbc和decrypt_cbc
``` python
crypt_sm4.set_key(bytes.fromhex(Key), SM4_ENCRYPT) #加密
en = crypt_sm4.crypt_cbc(bytes.fromhex(iv), bytes.fromhex(plaintext))
ciper = bytes.hex(en).decode().upper()

crypt_sm4.set_keybytes.fromhex(Key), SM4_DECRYPT)  #解密
de = crypt_sm4.crypt_cbc(bytes.fromhex(iv), bytes.fromhex(ciper))
decrypt_value = bytes.hex(de).decode().upper()
assert plaintext == decrypt_value
```
### 4、encrypt_cfb和decrypt_cfb
``` python
crypt_sm4.set_key(bytes.fromhex(Key), SM4_ENCRYPT) #加密
en = crypt_sm4.crypt_cfb_encrypt(bytes.fromhex(iv), bytes.fromhex(plaintext))
ciper = bytes.hex(en).decode().upper()

crypt_sm4.set_keybytes.fromhex(Key), SM4_DECRYPT)  #解密
de = crypt_sm4.crypt_cfb_decrypt(bytes.fromhex(iv), bytes.fromhex(ciper))
decrypt_value = bytes.hex(de).decode().upper()
assert plaintext == decrypt_value
```

### 5、encrypt_ofb和decrypt_ofb
``` python
crypt_sm4.set_key(bytes.fromhex(Key), SM4_ENCRYPT)
en = crypt_sm4.crypt_ofb(bytes.fromhex(iv), bytes.fromhex(ciper))
# ofb模式加解密实际是一样的，解密也是用加密，可参见相关算法说明。
```

### 6、encrypt_ctr和decrypt_ctr
``` python
crypt_sm4.set_key(bytes.fromhex(Key), SM4_ENCRYPT) #加密
en = crypt_sm4.crypt_ctr(bytes.fromhex(iv), bytes.fromhex(plaintext))
ciper = bytes.hex(en).decode().upper()

crypt_sm4.set_keybytes.fromhex(Key), SM4_DECRYPT)  #解密
de = crypt_sm4.crypt_ctr(bytes.fromhex(iv), bytes.fromhex(ciper))
decrypt_value = bytes.hex(de).decode().upper()
assert plaintext == decrypt_value
```
