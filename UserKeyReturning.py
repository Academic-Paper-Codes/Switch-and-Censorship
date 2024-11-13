from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.hazmat.backends import default_backend
import os

class UserKeyReturning:
    def __init__(self, censor_private_key, user_public_key):
        self.censor_private_key = censor_private_key
        self.user_public_key = user_public_key

    def encrypt_key_data(self, block_number, sk_s, sk_ch):
        # 准备待加密的数据 (B, sk_s, sk_ch)
        data_to_encrypt = f"{block_number}|{sk_s}|{sk_ch}".encode()

        # 生成一个 AES 密钥
        aes_key = os.urandom(32)
        iv = os.urandom(16)

        # 使用 AES 加密数据
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data_to_encrypt) + encryptor.finalize()

        # 使用 RSA 公钥加密 AES 密钥
        encrypted_aes_key = self.user_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 生成签名 s_u (使用 ECDSA)
        s_u = self.censor_private_key.sign(
            data_to_encrypt,
            ec.ECDSA(hashes.SHA256())
        )

        return encrypted_data, encrypted_aes_key, iv, s_u

    def decrypt_and_verify(self, encrypted_data, encrypted_aes_key, iv, user_private_key, s_u):
        # 使用用户的私钥解密 AES 密钥
        aes_key = user_private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 使用 AES 解密数据
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # 解析解密后的数据
        data_parts = decrypted_data.decode().split('|')
        block_number = data_parts[0]
        sk_s = data_parts[1]
        sk_ch = data_parts[2]

        # 准备验证数据的消息
        message = f"{block_number}|{sk_s}|{sk_ch}".encode()

        # 验证签名 (使用 ECDSA)
        try:
            self.censor_private_key.public_key().verify(
                s_u,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            print("Signature verified successfully.")
            return {
                "block_number": block_number,
                "sk_s": sk_s,
                "sk_ch": sk_ch
            }
        except Exception as e:
            print("Signature verification failed:", e)
            return None

# Example usage
if __name__ == "__main__":
    # Generate example private and public keys for censor and user
    censor_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    user_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    user_public_key = user_private_key.public_key()

    # Initialize the UserKeyReturning class
    user_key_returning = UserKeyReturning(censor_private_key, user_public_key)

    # Sample data for encryption
    block_number = 1
    sk_s = "secret_key_s"
    sk_ch = "secret_key_ch"

    # Encrypt key data
    encrypted_data, encrypted_aes_key, iv, s_u = user_key_returning.encrypt_key_data(block_number, sk_s, sk_ch)

    # Decrypt and verify the data
    decrypted_data = user_key_returning.decrypt_and_verify(encrypted_data, encrypted_aes_key, iv, user_private_key, s_u)

    print("Decrypted Data:", decrypted_data)
