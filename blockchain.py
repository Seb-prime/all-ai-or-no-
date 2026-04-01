import hashlib
import json
from datetime import datetime

def detect_threat(event):
    score = 0

    if event["location"] == "unknown":
        score += 40

    if event["action"] == "multiple_failed_logins":
        score += 50

    if event["device"] == "new_device":
        score += 30

    return min(score, 100)

class Block:
    def __init__(self, index, data, previous_hash="0"):
        self.index = index
        self.timestamp = datetime.utcnow().isoformat()
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }

class Blockchain:
    def __init__(self):
        self.chain = []
        self._create_genesis_block()

    def _create_genesis_block(self):
        genesis = Block(0, {"message": "MoD UEBA Genesis Block"})
        self.chain.append(genesis)

    def get_last_block(self):
        return self.chain[-1]

    def add_threat(self, event):
        threat_score = detect_threat(event)

        threat_data = {
            "event": event,
            "threat_score": threat_score,
            "risk_level": self.get_risk_level(threat_score)
        }

        last = self.get_last_block()

        new_block = Block(
            index=len(self.chain),
            data=threat_data,
            previous_hash=last.hash
        )

        self.chain.append(new_block)

        if threat_score > 70:
            print(f"HIGH THREAT DETECTED: {event['user']} | Score: {threat_score}")

        return new_block

    def get_risk_level(self, score):
        if score > 70:
            return "HIGH"
        elif score > 40:
            return "MEDIUM"
        return "LOW"

    def is_valid(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            if current.hash != current.compute_hash():
                return False

            if current.previous_hash != previous.hash:
                return False

        return True

    def to_list(self):
        return [block.to_dict() for block in self.chain]

def tamper_block(blockchain):
    if len(blockchain.chain) > 1:
        blockchain.chain[1].data["event"]["user"] = "HACKER"
