from flask import Flask,request,jsonify
from flask_cors import CORS
from log_analyzer import analyze_lines
app=Flask(__name__);CORS(app)
@app.get("/api/health")
def health(): return jsonify({"status":"online"})
@app.post("/api/analyze")
def analyze():
 if "file" not in request.files:return jsonify({"error":"file field required"}),400
 f=request.files["file"]
 if not f.filename.lower().endswith((".txt",".log")):return jsonify({"error":"Only .txt and .log files"}),400
 return jsonify(analyze_lines(f.read().decode("utf-8",errors="replace").splitlines()))
if __name__=="__main__":app.run(host="127.0.0.1",port=5000,debug=True)
