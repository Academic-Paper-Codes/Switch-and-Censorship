# TransactionPool.py

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.backends import default_backend


class TransactionPool:
    def __init__(self):
        self.transactions = []

    def hash_gen(self, message, secret_key):
        # 生成变色龙哈希值（Switch）
        hash_function = hashes.Hash(hashes.SHA256())
        hash_function.update(message.encode())
        hash_function.update(secret_key.encode())
        return hash_function.finalize().hex()

    def generate_transaction(self, message, block_number, user_private_key, chameleon_random):
        # Step 1: 生成变色龙哈希值
        switch_m = self.hash_gen(message, chameleon_random)

        # Step 2: 使用用户的私钥对交易数据签名
        message_data = f"{message}|{switch_m}|{block_number}|{chameleon_random}".encode()

        # 检查密钥类型并使用相应的签名算法
        if isinstance(user_private_key, rsa.RSAPrivateKey):
            # 如果是 RSA 密钥，使用 PSS 填充
            signature = user_private_key.sign(
                message_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif isinstance(user_private_key, ec.EllipticCurvePrivateKey):
            # 如果是椭圆曲线密钥，使用 ECDSA
            signature = user_private_key.sign(
                message_data,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            raise ValueError("Unsupported private key type")

        # Step 3: 创建交易
        transaction = {
            "message": message,
            "switch": switch_m,
            "block_number": block_number,
            "chameleon_random": chameleon_random,
            "signature": signature.hex()
        }

        return transaction

    def add_transaction(self, transaction):
        # 将交易添加到交易池
        self.transactions.append(transaction)

    def display_transactions(self):
        for i, tx in enumerate(self.transactions):
            print(f"Transaction {i + 1}:")
            for key, value in tx.items():
                print(f"  {key}: {value}")
            print("\n")

    def get_transactions(self):
        return self.transactions


if __name__ == "__main__":
    # 示例：创建交易池并生成一些交易
    transaction_pool = TransactionPool()

    # 假设我们有一些交易数据和用户密钥
    message = "Sample message"
    block_number = 1
    chameleon_random = "random_string"

    # 假设用户有一个私钥，这里我们使用一个模拟私钥
    # 请替换为实际的密钥
    user_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # 生成交易
    transaction = transaction_pool.generate_transaction(message, block_number, user_private_key, chameleon_random)

    # 添加交易到交易池
    transaction_pool.add_transaction(transaction)

    # 显示所有交易
    transaction_pool.display_transactions()