# Setup.py
import json
import os
import time
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# 区块类
class Block:
    def __init__(self, index, timestamp, data, previous_hash=''):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = f"{self.index}{self.timestamp}{self.data}{self.previous_hash}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self):
        # 将区块信息和交易列表一起序列化
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,  # 交易信息列表
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }

    @staticmethod
    def from_dict(block_data):
        # 从字典格式反序列化为 Block 对象
        block = Block(
            block_data["index"],
            block_data["timestamp"],
            block_data["data"],  # 加载交易信息列表
            block_data["previous_hash"]
        )
        block.hash = block_data["hash"]
        return block


# 区块链类
class Blockchain:
    def __init__(self):
        self.chain = []
        self.load_blockchain_data()

    def create_genesis_block(self):
        genesis_block = Block(0, time.time(), [], "0")  # 创世区块的交易列表为空
        self.chain.append(genesis_block)
        self.save_blockchain_data()

    def add_block(self, data):
        previous_block = self.chain[-1]
        new_block = Block(len(self.chain), time.time(), data, previous_block.hash)
        self.chain.append(new_block)
        self.save_blockchain_data()

    def load_blockchain_data(self):
        if os.path.exists("blockchain_data.json"):
            with open("blockchain_data.json", "r") as f:
                blockchain_data = json.load(f)
                self.chain = [Block.from_dict(block) for block in blockchain_data]
            print("Blockchain data loaded successfully.")
        else:
            print("No existing blockchain data found. Creating genesis block...")
            self.create_genesis_block()

    def save_blockchain_data(self):
        with open("blockchain_data.json", "w") as f:
            blockchain_data = [block.to_dict() for block in self.chain]
            json.dump(blockchain_data, f, indent=4)
        print("Blockchain data saved successfully.")

    def get_block(self, index):
        if index < len(self.chain):
            return self.chain[index]
        else:
            return None

# 生成通信密钥对
def generate_communication_keys():
    private_key_c = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key_c = private_key_c.public_key()
    return private_key_c, public_key_c

# 生成ECDSA密钥对
def generate_signature_keys():
    private_key_s = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key_s = private_key_s.public_key()
    return private_key_s, public_key_s
