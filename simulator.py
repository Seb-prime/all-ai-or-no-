import random
import time
from blockchain import Blockchain

bc = Blockchain()

users = ["user1", "user2", "admin"]
actions = ["login", "multiple_failed_logins"]
locations = ["india", "unknown"]
devices = ["known_device", "new_device"]

print(" Starting Threat Simulation...\n")

for _ in range(10):
    event = {
        "user": random.choice(users),
        "action": random.choice(actions),
        "location": random.choice(locations),
        "device": random.choice(devices)
    }

    block = bc.add_threat(event)

    print(f"Block {block.index} Added | Risk: {block.data['risk_level']}")
    time.sleep(1)

print("\n Checking blockchain validity BEFORE tampering:")
print("Valid:", bc.is_valid())

from blockchain import tamper_block
tamper_block(bc)

print("\n AFTER TAMPERING:")
print("Valid:", bc.is_valid())
