import uuid
from Setup import Blockchain
from TransactionPool import TransactionPool
from Miner import Miner
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes

# 初始化区块链和交易池
blockchain = Blockchain()
transaction_pool = TransactionPool()

# 生成用户公私钥对
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# 创建 3 笔交易，每笔交易使用唯一的 chameleon_random 值
for i in range(3):
    chameleon_random = str(uuid.uuid4())  # 使用 UUID 生成唯一的 chameleon_random
    message = f"test_message_{i+1}"       # 每笔交易不同的消息内容
    block_number = i + 1                  # 假设每笔交易在不同的区块中

    # 创建交易并添加到交易池
    transaction = transaction_pool.generate_transaction(
        message=message,
        block_number=block_number,
        user_private_key=private_key,
        chameleon_random=chameleon_random
    )

    transaction_pool.add_transaction(transaction)

# 打印交易池中的所有交易
print("Transactions in the transaction pool:")
transaction_pool.display_transactions()

# 矿工执行验证和打包操作
miner = Miner(blockchain, transaction_pool)
for transaction in transaction_pool.get_transactions():
    chameleon_random = transaction["chameleon_random"]
    miner.finalize_transactions(public_key, chameleon_random)

# 显示区块链中打包的交易
print("Finalized blocks in the blockchain:")
for block in blockchain.chain:
    print(block)

# main_copy.py

# import uuid
# from Setup import Blockchain, generate_communication_keys, generate_signature_keys
# from TransactionPool import TransactionPool
# from Miner import Miner
# from Record import Record
# from Redaction import Redaction
# from Registration import Registration
# from UserKeyReturning import UserKeyReturning
# from cryptography.hazmat.primitives.asymmetric import rsa
#
# # 初始化区块链和密钥生成
# blockchain = Blockchain()
# private_key_c, public_key_c = generate_communication_keys()  # 通信密钥
# private_key_s, public_key_s = generate_signature_keys()  # 签名密钥
#
# # 初始化交易池和矿工
# transaction_pool = TransactionPool()
# miner = Miner(blockchain, transaction_pool)
#
# # 初始化记录和编辑模块
# record = Record()
# redactor = Redaction()
#
# # 初始化用户注册和密钥返回模块
# registration = Registration(transaction_pool, private_key_c, public_key_c)
# user_key_returning = UserKeyReturning()
#
# # 用户注册并生成交易
# for i in range(3):  # 示例生成3笔交易
#     chameleon_random = str(uuid.uuid4())
#     message = f"test_message_{i + 1}"
#     block_number = i + 1
#
#     # 使用注册模块创建交易
#     transaction = registration.register_user(
#         user_id=f"user_{i + 1}",
#         user_credentials=f"credentials_{i + 1}",
#         message=message,
#         block_number=block_number,
#         chameleon_random=chameleon_random
#     )
#     transaction_pool.add_transaction(transaction)
#
# # 显示交易池中的所有交易
# print("Transactions in the transaction pool:")
# transaction_pool.display_transactions()
#
# # 矿工验证并打包交易
# miner.finalize_transactions(public_key_s)
#
# # 显示区块链中的所有区块
# print("Finalized blocks in the blockchain:")
# for block in blockchain.chain:
#     print(block)
#
# # 编辑交易示例
# redacted_transaction = redactor.censor_redact(
#     message="test_message_1",
#     block_number=1,
#     censor_private_key=private_key_s,
#     chameleon_random="random_value"
# )
# transaction_pool.add_transaction(redacted_transaction)
#
# # 记录查询示例
# print("Querying records:")
# record_data = record.query_transaction("test_message_1")
# print(record_data)
#
# # 用户密钥返回示例
# encrypted_key_data, user_signature = user_key_returning.encrypt_key_data(
#     block_number=1,
#     secret_key=private_key_c,
#     public_key=public_key_c
# )
# print("Encrypted user key data:", encrypted_key_data)
# print("User signature:", user_signature)

