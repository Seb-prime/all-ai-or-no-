import json
import os
import numpy as np

from ueba_engine import UEBAEngine
from blockchain import Blockchain

LOG_FILE = "firewallx_audit.json"


class FirewallXBackend:
    def __init__(self):
        self.ueba = UEBAEngine()
        self.blockchain = Blockchain()

    # -------- SAFE JSON --------
    def _safe_json(self, data):
        if isinstance(data, dict):
            return {str(k): self._safe_json(v) for k, v in data.items()}

        elif isinstance(data, list):
            return [self._safe_json(v) for v in data]

        elif isinstance(data, (str, int, float, bool)) or data is None:
            return data

        elif isinstance(data, (np.bool_,)):
            return bool(data)

        elif isinstance(data, (np.integer,)):
            return int(data)

        elif isinstance(data, (np.floating,)):
            return float(data)

        else:
            return str(data)

    # -------- SAVE --------
    def _save_to_disk(self):
        clean_data = self._safe_json(self.blockchain.to_list())

        with open(LOG_FILE, "w") as f:
            json.dump(clean_data, f, indent=2)

    # -------- CORE --------
    def process_event(self, event):
        analysed = self.ueba.analyse(event)

        # 🔥 sanitize ML output
        analysed = self._safe_json(analysed)

        block = self.blockchain.add_threat(analysed)

        # 🔥 save every time
        self._save_to_disk()

        return {
            "analysis": analysed,
            "block": block.to_dict()
        }

    # -------- DATA --------
    def get_logs(self):
        return self.blockchain.to_list()

    def get_stats(self):
        return self.ueba.stats()

    def get_threats(self):
        return self.ueba.get_threats()

    # -------- SECURITY --------
    def is_secure(self):
        return self.blockchain.is_valid()

    def tamper(self):
        if len(self.blockchain.chain) > 1:
            self.blockchain.chain[1].data["tampered"] = True
            self._save_to_disk()

    # -------- RESET --------
    def reset(self):
        self.__init__()
        self._save_to_disk()
