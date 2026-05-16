import os,re,pickle,chromadb
from flask import Flask,render_template,request
from google import genai
from dotenv import load_dotenv

load_dotenv()
app=Flask(__name__)
GEMINI_API_KEY=os.getenv("GEMINI_API_KEY")

chroma_client=chromadb.Client(settings=chromadb.config.Settings(persist_directory="./chroma_db"))
threat_db=chroma_client.get_or_create_collection(name="threat_intel")
history_db=chroma_client.get_or_create_collection(name="scan_history")

if threat_db.count()==0:
    threat_db.upsert(
        documents=[
            "Phishing links use typos like paypa1 instead of paypal.",
            "OTP/account blocked SMS is a common scam.",
            "Domains like .xyz, .top are risky.",
            "Urgent banking alerts often indicate scams."
        ],
        ids=["t1","t2","t3","t4"]
    )

def load_models():
    try:
        v=pickle.load(open("vectorizer.pkl","rb"))
        m=pickle.load(open("phishing.pkl","rb"))
        return v,m
    except:
        return None,None

vector,model=load_models()

def is_url(t):return bool(re.search(r"\.[a-z]{2,}",t.lower()))
def clean_url(u):return re.sub(r"^https?://(www\.)?","",u)

def safe_query(db,text):
    try:
        r=db.query(query_texts=[text],n_results=1)
        if r and r.get("documents") and r["documents"][0]:
            return r["documents"][0][0]
    except:pass
    return ""

def agent_analysis(text):
    if not GEMINI_API_KEY:
        return "AI_OFFLINE",0
    try:
        intel=safe_query(threat_db,text)
        past=safe_query(history_db,text)
        client=genai.Client(api_key=GEMINI_API_KEY)
        prompt=f"Context:{intel}\nPast:{past}\nInput:{text}\nClassify [DANGER]/[SAFE] and give Risk(0-100)\nFormat:\n[DANGER/SAFE]\nRisk:<num>\nWhy:\nAction:"
        res=client.models.generate_content(model="gemini-2.5-flash",contents=prompt)
        if not res or not hasattr(res,"text"):
            return "AI_OFFLINE",0
        out=res.text.strip()
        m=re.search(r"Risk:\s*(\d+)",out)
        return out,int(m.group(1)) if m else 50
    except Exception as e:
        print("[AI ERROR]:",e)
        return "AI_OFFLINE",0

def compute_risk(inp):
    risk=0
    pred="good"

    if is_url(inp) and vector and model:
        try:
            p=clean_url(inp)
            pred=model.predict(vector.transform([p]))[0]
            risk+=60 if pred=="bad" else 20
        except Exception as e:
            print("[ML ERROR]:",e)

    ai_report,ai_risk=agent_analysis(inp)

    if ai_report!="AI_OFFLINE":
        risk=max(risk,ai_risk)

    return pred,risk,ai_report,(ai_report=="AI_OFFLINE")

def store_history(text,risk):
    try:
        history_db.upsert(
            documents=[f"{text} → Risk {risk}"],
            ids=[str(abs(hash(text)))]
        )
    except:pass

def classify(r):
    if r>=70:
        return "🚨 Phishing Detected","bg-red-900/30","border-red-500","text-red-400"
    if r>=40:
        return "⚠️ Suspicious Content","bg-yellow-900/30","border-yellow-500","text-yellow-400"
    return "✅ Safe Content","bg-green-900/30","border-green-500","text-green-400"

@app.route("/",methods=["GET","POST"])
def index():
    if request.method=="POST":
        inp=request.form.get("input_text","").strip()
        if not inp:
            return render_template("index.html")

        pred,risk,ai_report,ai_down=compute_risk(inp)

        if ai_down:
            ai_report="AI unavailable. Result based on system analysis."

        store_history(inp,risk)

        msg,bg,border,txt=classify(risk)

        return render_template(
            "index.html",
            predict=msg,
            agent_info=ai_report,
            risk=risk,
            bg=bg,
            border=border,
            text=txt
        )

    return render_template("index.html")

if __name__=="__main__":
    app.run(debug=True)