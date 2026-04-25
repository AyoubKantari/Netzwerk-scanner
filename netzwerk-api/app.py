from flask import Flask,request
import scanner
app = Flask(__name__)
@app.route("/health")
def health():
    return {"status": "ok"}
@app.route("/scan")
def scan():
    ip = request.args.get("ip")
    if not ip:
        return {"error": "IP-Adresse erforderlich"}, 400
    if scanner.ping_host(ip):
        ports = scanner.scan_ports(ip)
        return {"ip": ip, "offene_ports": ports}
    else:
        return {"error": "Host nicht erreichbar"}, 404
if __name__ == "__main__":
    app.run(port=5000)