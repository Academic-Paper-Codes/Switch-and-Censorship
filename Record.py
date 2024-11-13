# # Record.py
#
# import Setup  # 导入 Setup 模块，用于访问区块链和密钥生成功能
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import ec
#
# class Miner:
#     def __init__(self, blockchain, censor_public_key):
#         self.blockchain = blockchain
#         self.censor_public_key = censor_public_key
#
#     def verify_and_record(self, user_data):
#         # 提取签名和消息内容
#         s_r = user_data["s_r"]
#         message = f"{user_data['user_id']}|{user_data['pk_ch']}|{user_data['pk_s']}".encode()
#
#         # 验证签名
#         try:
#             self.censor_public_key.verify(
#                 s_r,
#                 message,
#                 ec.ECDSA(hashes.SHA256())
#             )
#             print("Signature verified successfully.")
#         except Exception as e:
#             print("Signature verification failed:", e)
#             return None
#
#         # 添加记录到区块链
#         record_data = {
#             "user_id": user_data["user_id"],
#             "pk_ch": user_data["pk_ch"],
#             "pk_s": user_data["pk_s"],
#             "s_r": s_r.hex()
#         }
#         self.blockchain.add_block(record_data)
#
#         # 返回区块编号
#         return len(self.blockchain.chain) - 1  # 当前区块的编号
#
# def record_users_to_blockchain(blockchain, users_data, censor_public_key):
#     miner = Miner(blockchain, censor_public_key)
#     block_numbers = []
#
#     for user_data in users_data:
#         block_number = miner.verify_and_record(user_data)
#         if block_number is not None:
#             block_numbers.append(block_number)
#
#     return block_numbers
import Setup  # 导入 Setup 模块，用于访问区块链和密钥生成功能
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

class UserRecordMiner:
    def __init__(self, blockchain, censor_public_key):
        self.blockchain = blockchain
        self.censor_public_key = censor_public_key

    def verify_and_record(self, user_data):
        # 提取签名和消息内容
        s_r = user_data["s_r"]
        message = f"{user_data['user_id']}|{user_data['pk_ch']}|{user_data['pk_s']}".encode()

        # 验证签名
        try:
            self.censor_public_key.verify(
                s_r,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            print("Signature verified successfully.")
        except Exception as e:
            print("Signature verification failed:", e)
            return None

        # 添加记录到区块链
        record_data = {
            "user_id": user_data["user_id"],
            "pk_ch": user_data["pk_ch"],
            "pk_s": user_data["pk_s"],
            "s_r": s_r.hex()
        }
        self.blockchain.add_block(record_data)

        # 返回区块编号
        return len(self.blockchain.chain) - 1  # 当前区块的编号

def record_users_to_blockchain(blockchain, users_data, censor_public_key):
    user_record_miner = UserRecordMiner(blockchain, censor_public_key)
    block_numbers = []

    for user_data in users_data:
        block_number = user_record_miner.verify_and_record(user_data)
        if block_number is not None:
            block_numbers.append(block_number)

    return block_numbers

# 在直接运行此文件时执行以下代码
if __name__ == "__main__":
    # 示例设置：初始化区块链和生成公私钥对
    blockchain = Setup.Blockchain()
    private_key, public_key = Setup.generate_communication_keys()

    # 模拟用户数据
    sample_user_data = {
        "user_id": "user_1",
        "pk_ch": "sample_pk_ch",
        "pk_s": "sample_pk_s",
        "s_r": b"sample_signature"  # 假设已经生成签名数据
    }

    # 创建矿工实例并将用户数据记录到区块链中
    user_record_miner = UserRecordMiner(blockchain, public_key)
    block_number = user_record_miner.verify_and_record(sample_user_data)

    if block_number is not None:
        print(f"User data recorded in block number: {block_number}")

    # 显示区块链中所有区块的数据
    for block in blockchain.chain:
        print(f"Block {block.index}:")
        print(f"  Timestamp: {block.timestamp}")
        print(f"  Data: {block.data}")
        print(f"  Hash: {block.hash}")
        print(f"  Previous Hash: {block.previous_hash}")
        print("\n")
