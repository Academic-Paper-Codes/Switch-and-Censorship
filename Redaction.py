# Redaction.py

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.backends import default_backend

class Redaction:
    def __init__(self):
        pass

    def censor_redact(self, message, block_number, censor_private_key, chameleon_random):
        """
        审查者编辑方法，生成新的交易来表示消息被审查者编辑。
        """
        # 生成新的变色龙哈希值并签名
        redacted_message = f"Censored: {message}"
        switch_m = self.hash_gen(message, chameleon_random)
        transaction_data = f"Censor|{redacted_message}|{block_number}|{switch_m}|{chameleon_random}".encode()

        # 使用审查者的私钥生成签名
        if isinstance(censor_private_key, rsa.RSAPrivateKey):
            signature = censor_private_key.sign(
                transaction_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif isinstance(censor_private_key, ec.EllipticCurvePrivateKey):
            signature = censor_private_key.sign(
                transaction_data,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            raise ValueError("Unsupported private key type")

        transaction = {
            "redactor": "Censor",
            "message": redacted_message,
            "block_number": block_number,
            "switch": switch_m,
            "chameleon_random": chameleon_random,
            "signature": signature.hex()
        }

        return transaction

    def user_redact(self, message, block_number, user_private_key, chameleon_random):
        """
        用户编辑方法，生成新的交易来表示消息被用户编辑。
        """
        # 生成新的变色龙哈希值并签名
        redacted_message = f"User Redacted: {message}"
        switch_m = self.hash_gen(message, chameleon_random)
        transaction_data = f"User|{redacted_message}|{block_number}|{switch_m}|{chameleon_random}".encode()

        # 使用用户的私钥生成签名
        if isinstance(user_private_key, rsa.RSAPrivateKey):
            signature = user_private_key.sign(
                transaction_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif isinstance(user_private_key, ec.EllipticCurvePrivateKey):
            signature = user_private_key.sign(
                transaction_data,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            raise ValueError("Unsupported private key type")

        transaction = {
            "redactor": "User",
            "message": redacted_message,
            "block_number": block_number,
            "switch": switch_m,
            "chameleon_random": chameleon_random,
            "signature": signature.hex()
        }

        return transaction

    def hash_gen(self, message, secret_key):
        """
        用于生成变色龙哈希值的辅助方法
        """
        hash_function = hashes.Hash(hashes.SHA256())
        hash_function.update(message.encode())
        hash_function.update(secret_key.encode())
        return hash_function.finalize().hex()

if __name__ == "__main__":
    # 示例使用 Redaction 类
    redaction = Redaction()

    # 假设用户和审查者的私钥已经准备好
    # 示例参数
    message = "This is a secret message"
    block_number = 1
    chameleon_random = "random_value"

    # 模拟审查者编辑
    censor_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    censored_transaction = redaction.censor_redact(message, block_number, censor_private_key, chameleon_random)
    print(f"Censored Transaction: {censored_transaction}")

    # 模拟用户编辑
    user_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    user_redacted_transaction = redaction.user_redact(message, block_number, user_private_key, chameleon_random)
    print(f"User Redacted Transaction: {user_redacted_transaction}")
