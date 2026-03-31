from flask import Flask, jsonify, request
from flask_cors import CORS

from blockchain import Blockchain
from ueba_engine import UEBAEngine
from simulator import generate_batch, generate_login_event, generate_file_event, generate_network_event

app = Flask(__name__)
CORS(app)

chain = Blockchain()
engine = UEBAEngine()


# ------------------------------------------------------------------ #
#  Helpers                                                             #
# ------------------------------------------------------------------ #

def _ingest(event):
    """Run event through UEBA engine. If threat, write to blockchain."""
    result = engine.analyse(event)
    if result["is_threat"]:
        chain.add_threat({
            "event_type": result.get("type"),
            "user": result.get("user_name"),
            "risk_score": result.get("final_risk"),
            "reasons": result.get("threat_reasons"),
            "timestamp": result.get("timestamp"),
        })
    return result


# ------------------------------------------------------------------ #
#  Routes                                                              #
# ------------------------------------------------------------------ #

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "MoD UEBA Backend"})


@app.route("/api/simulate", methods=["POST"])
def simulate():
    """
    Simulate a batch of events.
    Body (optional): { "count": 10 }
    """
    body = request.get_json(silent=True) or {}
    count = min(int(body.get("count", 10)), 50)
    events = generate_batch(count)
    results = [_ingest(e) for e in events]
    threats = [r for r in results if r["is_threat"]]
    return jsonify({
        "generated": len(results),
        "threats_detected": len(threats),
        "events": results
    })


@app.route("/api/simulate/login", methods=["POST"])
def simulate_login():
    body = request.get_json(silent=True) or {}
    event = generate_login_event(force_anomaly=body.get("force_anomaly", False))
    return jsonify(_ingest(event))


@app.route("/api/simulate/file", methods=["POST"])
def simulate_file():
    body = request.get_json(silent=True) or {}
    event = generate_file_event(force_anomaly=body.get("force_anomaly", False))
    return jsonify(_ingest(event))


@app.route("/api/simulate/network", methods=["POST"])
def simulate_network():
    body = request.get_json(silent=True) or {}
    event = generate_network_event(force_anomaly=body.get("force_anomaly", False))
    return jsonify(_ingest(event))


@app.route("/api/events", methods=["GET"])
def get_events():
    limit = int(request.args.get("limit", 100))
    return jsonify(engine.get_all_events(limit=limit))


@app.route("/api/threats", methods=["GET"])
def get_threats():
    limit = int(request.args.get("limit", 50))
    return jsonify(engine.get_threats(limit=limit))


@app.route("/api/stats", methods=["GET"])
def get_stats():
    s = engine.stats()
    s["blockchain_length"] = len(chain.chain)
    s["blockchain_valid"] = chain.is_valid()
    return jsonify(s)


@app.route("/api/blockchain", methods=["GET"])
def get_blockchain():
    return jsonify({
        "length": len(chain.chain),
        "valid": chain.is_valid(),
        "chain": chain.to_list()
    })


@app.route("/api/blockchain/verify", methods=["GET"])
def verify_chain():
    valid = chain.is_valid()
    return jsonify({
        "valid": valid,
        "message": "Chain integrity verified — no tampering detected." if valid
                   else "CHAIN INTEGRITY VIOLATION — tampering detected!"
    })


if __name__ == "__main__":
    print("MoD UEBA Backend starting on http://localhost:5000")
    print("Seeding initial events...")
    for e in generate_batch(30):
        _ingest(e)
    print("Ready. 30 seed events loaded.")
    app.run(debug=True, port=5000)
