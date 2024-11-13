# # Miner.py
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import serialization


class Miner:
    def __init__(self, blockchain, transaction_pool, verbose=False):
        self.blockchain = blockchain
        self.transaction_pool = transaction_pool
        self.verbose = verbose  # 控制是否显示详细输出

    def verify_signature(self, transaction, public_key):
        try:
            # 确保消息内容的格式和编码一致
            message_data = f"{transaction['message']}|{transaction['switch']}|{transaction['block_number']}|{transaction['chameleon_random']}".encode('utf-8')
            signature = bytes.fromhex(transaction['signature'])

            # 输出调试信息，查看消息和签名是否一致
            if self.verbose:
                print("Message to verify:", message_data.decode('utf-8'))
                print("Signature (hex):", signature.hex())

            # 使用 ECDSA 验证签名
            if isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(signature, message_data, ec.ECDSA(hashes.SHA256()))
            else:
                if self.verbose:
                    print("Unsupported public key type for verification.")
                return False
            return True
        except Exception as e:
            if self.verbose:
                print("Signature verification failed:", e)
            return False

    def hash_gen(self, message, secret_key):
        """
        计算变色龙哈希的辅助方法
        """
        hash_function = hashlib.sha256()
        hash_function.update(message.encode())
        hash_function.update(secret_key.encode())
        return hash_function.hexdigest()

    def hash_ver(self, transaction, secret_key):
        """
        验证变色龙哈希值的对应关系
        """
        hash_function = hashlib.sha256()
        hash_function.update(transaction["message"].encode())
        hash_function.update(secret_key.encode())
        computed_hash = hash_function.hexdigest()
        return computed_hash == transaction["switch"]

    def finalize_transactions(self, public_key, secret_key):
        verified_transactions = []

        for transaction in self.transaction_pool.transactions:
            if not self.verify_signature(transaction, public_key):
                if self.verbose:
                    print(f"Transaction {transaction} has invalid signature and will be discarded.")
                continue

            # if not self.hash_ver(transaction, secret_key):
            #     if self.verbose:
            #         print(f"Transaction {transaction} has invalid chameleon hash and will be discarded.")
            #     continue

            verified_transactions.append(transaction)

        if verified_transactions:
            merkle_root = self.build_merkle_tree([tx["switch"] for tx in verified_transactions])
            block_data = {
                "transactions": verified_transactions,
                "merkle_root": merkle_root
            }
            self.blockchain.add_block(block_data)  # 创建一个新块并添加到区块链
            print("Block finalized and added to blockchain with merkle root:", merkle_root)
            return block_data
        else:
            print("No valid transactions to finalize.")

        # if not verified_transactions:
        #     return
        #
        # merkle_root = self.build_merkle_tree([tx["switch"] for tx in verified_transactions])
        # block_data = {
        #     "transactions": verified_transactions,
        #     "merkle_root": merkle_root
        # }
        # self.blockchain.add_block(block_data)
        # print("Block finalized and added to blockchain with merkle root:", merkle_root)

    def build_merkle_tree(self, hash_list):
        if not hash_list:
            return None

        while len(hash_list) > 1:
            if len(hash_list) % 2 != 0:
                hash_list.append(hash_list[-1])

            new_level = []
            for i in range(0, len(hash_list), 2):
                combined_hash = hashlib.sha256((hash_list[i] + hash_list[i + 1]).encode()).hexdigest()
                new_level.append(combined_hash)

            hash_list = new_level

        return hash_list[0]

    def encrypt_data(self, data, rsa_public_key):
        """
        使用RSA加密数据
        """
        encrypted_data = rsa_public_key.encrypt(
            data.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_data

    def decrypt_data(self, encrypted_data, rsa_private_key):
        """
        使用RSA解密数据
        """
        decrypted_data = rsa_private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_data.decode()


# 以下是补充的 if __name__ == "__main__": 内容
if __name__ == "__main__":
    # 示例使用 Miner 类
    miner = Miner(blockchain=None, transaction_pool=None, verbose=True)

    # 假设用户的公钥和私钥已经准备好
    # 示例参数
    message = "This is a sample message"
    block_number = 1
    chameleon_random = "random_value"

    # 计算变色龙哈希
    calculated_switch_hash = miner.hash_gen(message, chameleon_random)

    # RSA 公钥和私钥生成示例
    rsa_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    rsa_public_key = rsa_private_key.public_key()

    # ECDSA 公钥和私钥生成示例
    ecdsa_private_key = ec.generate_private_key(ec.SECP256R1())
    ecdsa_public_key = ecdsa_private_key.public_key()

    # 示例交易数据
    transaction = {
        "message": message,
        "switch": calculated_switch_hash,
        "block_number": block_number,
        "chameleon_random": chameleon_random,
        "signature": ""  # 这里我们稍后再签名
    }

    # 使用 ECDSA 签名
    message_to_sign = f"{message}|{calculated_switch_hash}|{block_number}|{chameleon_random}"
    print("Message to sign:", message_to_sign)  # 输出要签名的消息，确保格式正确

    signature = ecdsa_private_key.sign(
        message_to_sign.encode('utf-8'),
        ec.ECDSA(hashes.SHA256())
    )
    transaction["signature"] = signature.hex()

    # 使用矿工的 verify_signature 方法验证签名
    is_verified = miner.verify_signature(transaction, ecdsa_public_key)
    print("Signature verified:", is_verified)

    # RSA 加密与解密示例
    encrypted_message = miner.encrypt_data(message, rsa_public_key)
    print("Encrypted Message:", encrypted_message.hex())

    decrypted_message = miner.decrypt_data(encrypted_message, rsa_private_key)
    print("Decrypted Message:", decrypted_message)


