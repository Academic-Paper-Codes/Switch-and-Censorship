# main.py
import os
import time
import json
import secrets
import string
import base64
import hashlib
from Record import UserRecordMiner
from Regisration import UserRegistration  # 假设 Registration.py 中实现了 UserRegistration 类
from Setup import Blockchain, generate_communication_keys, generate_signature_keys
from cryptography.hazmat.primitives import hashes  # 添加此行
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from UserKeyReturning import UserKeyReturning
from TransactionPool import TransactionPool
from Miner import Miner
from Redaction import Redaction
from cryptography.hazmat.primitives import serialization


MAX_TRANSACTIONS_PER_BLOCK = 5
USER_DATA_FILE = "user_data.json"  # 用户数据文件名
TRANSACTION_DATA_FILE = "transaction_data.json"

# 审查者密钥对
# censor_private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048,
#     backend=default_backend()
# )
censor_private_key, censor_public_key = generate_signature_keys()

rsa_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

def generate_random_number(length=16):
    """Generate a secure random number of specified digit length."""
    return secrets.randbelow(10 ** length)

def generate_random_string(length=16):
    """Generate a secure random string of specified length."""
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

rsa_public_key = rsa_private_key.public_key()
blockchain = Blockchain()  # 创建区块链实例
transaction_pool = TransactionPool()
redaction = Redaction()
miner = Miner(blockchain, transaction_pool, verbose=True)

# 创建一个用户注册系统实例
user_registration = UserRegistration(rsa_public_key, rsa_private_key, censor_private_key)
user_record_miner = UserRecordMiner(blockchain, censor_public_key)
# 用户数据库
user_database = {}
is_logged_in = False  # 标记用户是否已登录

def initialize_blocks(num_blocks=10):
    """
    初始化区块链，并添加指定数量的空区块
    """
    print(f"Initializing blockchain with {num_blocks} blocks...")
    for i in range(num_blocks - 1):  # -1 是因为创世区块已经被创建
        blockchain.add_block([])  # 每个区块的数据初始化为空列表
    print(f"Blockchain initialized with {len(blockchain.chain)} blocks.")

def load_user_data():
    """
    从 JSON 文件加载用户数据
    """
    global user_database
    if os.path.exists(USER_DATA_FILE):
        try:
            with open(USER_DATA_FILE, "r") as f:
                content = f.read().strip()
                if content:  # 检查文件是否非空
                    user_database = json.loads(content)
                    print("User data loaded successfully.")
                else:
                    print("User data file is empty. Starting with an empty user database.")
        except json.JSONDecodeError:
            print("User data file is corrupted or not in JSON format. Starting with an empty user database.")
    else:
        print("No user data file found. Starting with an empty user database.")


def save_user_data():
    """
    将用户数据保存到 JSON 文件
    """
    with open(USER_DATA_FILE, "w") as f:
        json.dump(user_database, f)
    print("User data saved successfully.")

def load_transactions():
    """
    从 JSON 文件加载交易池
    """
    if os.path.exists(TRANSACTION_DATA_FILE):
        try:
            with open(TRANSACTION_DATA_FILE, "r") as f:
                transactions = json.load(f)
                transaction_pool.transactions = transactions
                print("Transaction data loaded successfully.")
        except json.JSONDecodeError:
            print("Transaction data file is corrupted.")
    else:
        print("No transaction data file found. Starting with an empty transaction pool.")

def save_transactions():
    """
    将交易池中的交易保存到 JSON 文件
    """
    with open(TRANSACTION_DATA_FILE, "w") as f:
        json.dump(transaction_pool.transactions, f)
    print("Transaction data saved successfully.")

def generate_signature(user_id, pk_ch, pk_s):
    """
    使用审查者的私钥对注册信息生成签名 s_r
    """
    message = f"{user_id}|{pk_ch}|{pk_s}".encode()
    signature = censor_private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature

def register_user():
    """
    用户注册函数，通过调用 Registration 模块中的注册方法。
    """
    user_id = input("Enter your ID: ")
    user_credentials = input("Enter your credentials: ")
    credentials_hash = hashlib.sha256(user_credentials.encode()).hexdigest()
    if user_id in user_database:
        print("User already registered. Please log in.")
        return
    # 调用 Registration 模块中的注册方法
    user_data = user_registration.register_user(user_id, user_credentials, user_public_key="Temporary_Public_Key")

    if user_data:
        s_r = generate_signature(user_id, user_data['pk_ch'], user_data['pk_s'])
        pk_ch_str = base64.b64encode(user_data['pk_ch'].encode('utf-8')).decode('utf-8')
        sk_s_str = base64.b64encode(user_data['sk_s'].encode('utf-8')).decode('utf-8')
        pk_s_str = base64.b64encode(user_data['pk_s'].encode('utf-8')).decode('utf-8')
        user_data["s_r"] = s_r
        user_database[user_id] = {
            "credentials_hash": credentials_hash,
            "pk_ch": pk_ch_str,
            "sk_s": sk_s_str,
            "pk_s": pk_s_str
        }
        print(f"User {user_id} registered successfully!")
        print("Generated Keys:")

        print(f"Chameleon Hash Private Key (sk_ch): {user_data['sk_ch']}")
        print(f"Chameleon Hash Public Key (pk_ch): {user_data['pk_ch']}")
        print(f"Signature Private Key (sk_s): {user_data['sk_s']}")
        print(f"Signature Public Key (pk_s): {user_data['pk_s']}")
        save_user_data()
        block_number = user_record_miner.verify_and_record(user_data)
        # 将注册信息作为一笔交易
        transaction_data = {
            "user_id": user_id,
            "pk_ch": user_data['pk_ch'],
            "pk_s": user_data['pk_s'],
            "registration_time": time.ctime(),
            "s_r": s_r.hex(),
            "action": "Registration"
        }

        # 检查最后一个区块的交易数量，决定是否添加到现有区块或创建新区块
        last_block = blockchain.chain[-1]
        if isinstance(last_block.data, list) and len(last_block.data) < MAX_TRANSACTIONS_PER_BLOCK:
            # 如果当前区块未满，添加交易到当前区块
            last_block.data.append(transaction_data)
            print("Transaction added to current block:", last_block.index)
        else:
            # 如果当前区块已满，创建新块并添加交易
            blockchain.add_block([transaction_data])
            print("Transaction added to new block.")

            # 设置注册状态为 True
            is_logged_in = True
    else:
        print("Registration failed. Authentication error.")

def login_user():
    """
    已注册用户登录
    """
    global is_logged_in
    user_id = input("Enter your ID: ")
    user_credentials = input("Enter your credentials: ")

    # 生成凭证的哈希值
    credentials_hash = hashlib.sha256(user_credentials.encode()).hexdigest()

    # 验证用户是否存在且凭证匹配
    if user_id in user_database and user_database[user_id]["credentials_hash"] == credentials_hash:
        print(f"User {user_id} logged in successfully!")
        is_logged_in = True
    else:
        print("Invalid ID or credentials. Access denied.")


def view_blockchain_info():
    """
    查看区块链的区块数量和每个区块的交易信息
    """
    if not is_logged_in:
        print("Access denied. Please log in first.")
        return

    print(f"\nCurrent number of blocks: {len(blockchain.chain)}")
    for i, block in enumerate(blockchain.chain):
        print(f"\nBlock {i}:")
        print(f"  Index: {block.index}")
        print(f"  Timestamp: {time.ctime(block.timestamp)}")
        print(f"  Previous Hash: {block.previous_hash}")
        print(f"  Hash: {block.hash}")
        print("  Transactions:")
        if isinstance(block.data, list):  # 假设每个区块的数据是一个列表
            for transaction in block.data:
                for key, value in transaction.items():
                    print(f"    {key}: {value}")
        else:
            print(f"    {block.data}")

def generate_transaction():
    """
    生成并添加交易到交易池
    """
    message = input("Enter the transaction message: ")
    block_number = len(blockchain.chain) - 1  # 假设使用当前块号
    chameleon_random = generate_random_string()  # 示例随机数，替换为实际生成的值

    # 获取用户的私钥
    user_private_key = censor_private_key  # 假设使用 ECDSA 私钥签名

    # 生成交易并添加到交易池
    transaction = transaction_pool.generate_transaction(message, block_number, user_private_key, chameleon_random)
    transaction_pool.add_transaction(transaction)
    print("Transaction added to the transaction pool.")

    # 永久保存交易到文件
    save_transactions()



def finalize_transactions():
    """
    使用矿工将交易池中的交易进行验证和打包
    """
    print("Finalizing transactions...")
    # block_data = miner.finalize_transactions(censor_public_key, "secret_key")
    miner.finalize_transactions(censor_public_key, "secret_key")
    save_transactions()

    # if block_data:
    #     print("\n--- Recently Finalized Block ---")
    #     print("Merkle Root:", block_data["merkle_root"])
    #     print("Transactions:")
    #     for i, transaction in enumerate(block_data["transactions"], 1):
    #         print(f"  Transaction {i}:")
    #         for key, value in transaction.items():
    #             print(f"    {key}: {value}")
    # else:
    #     print("No transactions were finalized into a block.")

def return_user_key(user_id):
    """
    使用 UserKeyReturning 类加密并返回用户密钥数据
    """
    if user_id not in user_database:
        print("User not found.")
        return

    user_data = user_database[user_id]
    pk_ch = base64.b64decode(user_data["pk_ch"].encode('utf-8'))
    sk_s = base64.b64decode(user_data["sk_s"].encode('utf-8'))
    block_number = len(blockchain.chain) - 1  # 当前块号

    # 初始化 UserKeyReturning 类
    user_key_returning = UserKeyReturning(censor_private_key, rsa_public_key)

    # 加密数据
    encrypted_data, encrypted_aes_key, iv, s_u = user_key_returning.encrypt_key_data(block_number, sk_s, pk_ch)

    # 打印加密后的数据
    print("Encrypted key data (AES encrypted):", base64.b64encode(encrypted_data).decode('utf-8'))
    print("Encrypted AES key:", base64.b64encode(encrypted_aes_key).decode('utf-8'))
    print("Initialization Vector (IV):", base64.b64encode(iv).decode('utf-8'))
    print("Digital Signature (s_u):", base64.b64encode(s_u).decode('utf-8'))

# Redaction function
def redact_transaction():
    original_message = input("Enter the original message to redact: ")
    # block_number = int(input("Enter the block number of the transaction to redact: "))

    # New redacted message
    new_message = input("Enter the new redacted message: ")
    block_number = int(input("Enter the block number of the transaction to redact: "))
    redactor_choice = input("Who is redacting? Enter 'c' for Censor or 'u' for User: ").strip().lower()

    # block = blockchain.get_block(block_number)
    # if not block or "transactions" not in block.data:
    #     print("Block or transactions not found.")
    #     return
    #
    # # Locate the transaction with the original message
    # chameleon_random = None
    # for transaction in block.data["transactions"]:
    #     if transaction["message"] == original_message:
    #         chameleon_random = transaction["chameleon_random"]
    #         break
    #
    # if chameleon_random is None:
    #     print("Original transaction not found in the specified block.")
    #     return
    chameleon_random = generate_random_string()
    if redactor_choice == 'c':
        censored_transaction = redaction.censor_redact(new_message, block_number, censor_private_key, chameleon_random)
        print("Censor-redacted transaction:", censored_transaction)
    elif redactor_choice == 'u':
        # user_id = input("Enter your user ID: ")
        # private_key_data = user_database[user_id]["sk_s"]
        user_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        user_redacted_transaction = redaction.user_redact(new_message, block_number, user_private_key, chameleon_random)
        print("User-redacted transaction:", user_redacted_transaction)
    else:
        print("Invalid choice. Please select 'c' or 'u'.")

def main():
    print("Welcome to the Web3.0 System")
    # initialize_blocks(10)  # 初始化 10 个区块
    load_user_data()  # 加载用户数据

    global is_logged_in

    while True:
        print("\nSelect an option:")
        print("1. Register a User")
        print("2. Login")
        print("3. Exit")

        if is_logged_in:
            print("4. View Blockchain Info")
            print("5. Return User Key")
            print("6. Generate Transaction")
            print("7. Finalize Transactions")
            print("8. Redact Transaction")

        choice = input("Enter your choice: ")

        if choice == '1':
            register_user()
        elif choice == '2':
            login_user()
        elif choice == '3':
            print("Exiting the system...")
            break
        elif choice == '4' and is_logged_in:
            view_blockchain_info()
        elif choice == '5' and is_logged_in:
            user_id = input("Enter your user ID: ")
            return_user_key(user_id)
        elif choice == '6' and is_logged_in:
            generate_transaction()
        elif choice == '7' and is_logged_in:
            finalize_transactions()
        elif choice == '8' and is_logged_in:
            redact_transaction()
        elif not is_logged_in and choice in ['4', '5', '6', '7', '8']:
            print("You need to register or log in first.")
        else:
            print("Invalid choice!")


if __name__ == "__main__":
    main()
