# # Registration.py
# 单个执行文件
# import os
# from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
# from cryptography.hazmat.primitives import hashes, serialization
# import Setup  # 导入 Setup 模块
# from UserKeyReturning import UserKeyReturning  # 导入 UserKeyReturning 模块
# from TransactionPool import TransactionPool  # 导入 TransactionPool 模块
#
# # 初始化区块链、密钥和交易池
# blockchain = Setup.Blockchain()
# private_key_c, public_key_c = Setup.generate_communication_keys()  # 从 Setup 中生成通信密钥
# private_key_s, public_key_s = Setup.generate_signature_keys()  # 从 Setup 中生成签名密钥
# transaction_pool = TransactionPool()  # 初始化交易池
#
#
# # 定义用户注册类
# class UserRegistration:
#     def __init__(self, censor_public_key, censor_private_key):
#         self.censor_public_key = censor_public_key
#         self.censor_private_key = censor_private_key
#
#     def register_user(self, user_id, user_credentials, user_public_key):
#         # 使用审查者的公钥加密用户ID和凭证
#         message = f"{user_id}|{user_credentials}".encode()
#         encrypted_data = self.censor_public_key.encrypt(
#             message,
#             padding.OAEP(
#                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
#                 algorithm=hashes.SHA256(),
#                 label=None
#             )
#         )
#
#         # 使用审查者的私钥解密数据
#         decrypted_data = self.censor_private_key.decrypt(
#             encrypted_data,
#             padding.OAEP(
#                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
#                 algorithm=hashes.SHA256(),
#                 label=None
#             )
#         )
#
#         # 验证用户ID
#         decrypted_id, decrypted_credentials = decrypted_data.decode().split('|')
#         if decrypted_id != user_id:
#             print("Authentication failed. User cannot join the Web 3.0 system.")
#             return None
#
#         print("Authentication successful. User registered in the Web 3.0 system.")
#
#         # 生成变色龙哈希密钥和签名密钥
#         sk_ch = os.urandom(32).hex()
#         pk_ch = os.urandom(32).hex()
#         sk_s = private_key_s.private_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PrivateFormat.TraditionalOpenSSL,
#             encryption_algorithm=serialization.NoEncryption()
#         ).decode()
#
#         pk_s = public_key_s.public_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo
#         ).decode()
#
#         # 为用户数据生成签名
#         message = f"{user_id}|{pk_ch}|{pk_s}".encode()
#         s_r = private_key_s.sign(
#             message,
#             ec.ECDSA(hashes.SHA256())
#         )
#
#         # 返回注册数据和签名
#         return {
#             "user_id": user_id,
#             "pk_ch": pk_ch,
#             "pk_s": pk_s,
#             "sk_s": sk_s,
#             "s_r": s_r
#         }
#
#
# # 实例化用户注册系统
# user_registration = UserRegistration(public_key_c, private_key_c)
#
# # 模拟多个用户注册并添加到用户数据列表中
# registered_users = []
# for i in range(10):  # 注册多个用户
#     user_id = f"user_{i}"
#     user_credentials = f"credentials_{i}"
#     user_public_key = f"user_public_key_placeholder_{i}"
#     user_data = user_registration.register_user(user_id, user_credentials, user_public_key)
#
#     if user_data:
#         registered_users.append(user_data)
#
# # 将用户数据传递给 Record 模块的矿工
# from Record import record_users_to_blockchain  # 假设 Record.py 中有这个函数
#
# block_numbers = record_users_to_blockchain(blockchain, registered_users, public_key_s)
#
# # 初始化 UserKeyReturning 模块，模拟密钥返回过程
# for user_data, block_number in zip(registered_users, block_numbers):
#     # 设置用户的公钥和私钥
#     user_key_returning = UserKeyReturning(private_key_s, public_key_c)
#
#     # 加密返回的密钥数据 (B, sk_s, sk_ch, s_u)
#     encrypted_data, encrypted_aes_key, iv, s_u = user_key_returning.encrypt_key_data(
#         block_number,
#         user_data["sk_s"],
#         user_data["pk_ch"]
#     )
#
#     # 模拟用户使用私钥解密和验证
#     user_private_key = private_key_c  # 使用用户的私钥解密
#     decrypted_data = user_key_returning.decrypt_and_verify(
#         encrypted_data,
#         encrypted_aes_key,
#         iv,
#         user_private_key,
#         s_u
#     )
#     print(f"Decrypted data for user {user_data['user_id']} in block number {block_number}:")
#     print("  Decrypted data:", decrypted_data)
#
#     # 生成交易并添加到交易池
#     transaction = transaction_pool.generate_transaction(
#         message="m1",  # 示例消息内容
#         block_number=block_number,
#         user_private_key=private_key_s,
#         chameleon_random=user_data["pk_ch"]  # 使用用户的 pk_ch 作为随机数
#     )
#     print(f"Transaction for user {user_data['user_id']}: {transaction}")
#
# # 显示所有交易
# transaction_pool.display_transactions()
#
#
# # 打印区块内容
# def print_block_content(block):
#     print(f"Block Index: {block.index}")
#     print(f"Timestamp: {block.timestamp}")
#     print(f"Previous Hash: {block.previous_hash}")
#     print(f"Hash: {block.hash}")
#     print("Data:")
#     if isinstance(block.data, dict):
#         for key, value in block.data.items():
#             print(f"  {key}: {value}")
#     else:
#         print(f"  Data: {block.data}")
#     print("\n")
#
#
# # 显示所有区块的内容
# for i in range(len(blockchain.chain)):
#     block = blockchain.get_block(i)
#     print_block_content(block)
#
#
#
import os
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.hazmat.primitives import hashes, serialization

# 从 Setup 模块导入生成密钥的函数
import Setup


# 定义用户注册类
class UserRegistration:
    def __init__(self, rsa_public_key, rsa_private_key, censor_private_key):
        self.rsa_public_key = rsa_public_key
        self.rsa_private_key = rsa_private_key
        self.censor_private_key = censor_private_key

    def register_user(self, user_id, user_credentials, user_public_key):
        # 使用审查者的公钥加密用户ID和凭证
        message = f"{user_id}|{user_credentials}".encode()
        encrypted_data = self.rsa_public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 使用审查者的私钥解密数据
        decrypted_data = self.rsa_private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 验证用户ID
        decrypted_id, decrypted_credentials = decrypted_data.decode().split('|')
        if decrypted_id != user_id:
            print("Authentication failed. User cannot join the Web 3.0 system.")
            return None

        print("Authentication successful. User registered in the Web 3.0 system.")
        private_key_s, public_key_s = Setup.generate_signature_keys()
        sk_ch, pk_ch = Setup.generate_communication_keys()
        # 生成变色龙哈希密钥和签名密钥
        sk_ch = os.urandom(32).hex()
        pk_ch = os.urandom(32).hex()
        sk_s = private_key_s.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        pk_s = public_key_s.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        # 为用户数据生成签名
        message = f"{user_id}|{pk_ch}|{pk_s}".encode()
        s_r = private_key_s.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )

        # 返回注册数据和签名
        return {
            "user_id": user_id,
            "sk_ch": sk_ch,
            "pk_ch": pk_ch,
            "pk_s": pk_s,
            "sk_s": sk_s,
            "s_r": s_r
        }


# 用于生成多个用户的注册信息
def register_multiple_users(num_users, rsa_public_key, rsa_private_key, censor_private_key):
    user_registration = UserRegistration(rsa_public_key, rsa_private_key, censor_private_key)
    registered_users = []
    for i in range(num_users):
        user_id = f"user_{i}"
        user_credentials = f"credentials_{i}"
        user_public_key = f"user_public_key_placeholder_{i}"
        user_data = user_registration.register_user(user_id, user_credentials, user_public_key)
        if user_data:
            registered_users.append(user_data)
    return registered_users


# 仅在直接运行此文件时执行以下代码
if __name__ == "__main__":
    # 示例：用户注册
    num_users = 10
    private_key_c, public_key_c = Setup.generate_communication_keys()  # 从 Setup 中生成通信密钥
    private_key_s, public_key_s = Setup.generate_signature_keys()  # 从 Setup 中生成签名密钥

    # 执行注册过程
    registered_users = register_multiple_users(num_users, public_key_c, private_key_c, private_key_s)

    # 打印注册的用户信息
    for user_data in registered_users:
        print(user_data)

