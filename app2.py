import streamlit as st
import pickle
import numpy as np
import re
import tldextract

# Load model
with open("model.pkl", "rb") as f:
    model = pickle.load(f)

FEATURE_ORDER = [
    'having_iphaving_ip_address_',
    'urlurl_length_',
    'shortining_service_',
    'having_at_symbol_',
    'double_slash_redirecting_',
    'prefix_suffix_',
    'having_sub_domain_',
    'sslfinal_state_',
    'domain_registeration_length_',
    'favicon_',
    'port_',
    'https_token_',
    'request_url_',
    'url_of_anchor_',
    'links_in_tags_',
    'sfh_',
    'submitting_to_email_',
    'abnormal_url_',
    'redirect_',
    'on_mouseover_',
    'rightclick_',
    'popupwidnow_',
    'iframe_',
    'age_of_domain_',
    'dnsrecord_',
    'web_traffic_',
    'page_rank_',
    'google_index_',
    'links_pointing_to_page_',
    'statistical_report_'
]

def extract_features(url):
    feats = {}

    # 1. having_ip_address
    feats['having_iphaving_ip_address_'] = -1 if re.search(r"\d{1,3}(\.\d{1,3}){3}", url) else 1

    # 2. url_length
    if len(url) < 54:
        feats['urlurl_length_'] = 1
    elif 54 <= len(url) <= 75:
        feats['urlurl_length_'] = 0
    else:
        feats['urlurl_length_'] = -1

    # 3. shortining_service
    feats['shortining_service_'] = -1 if re.search(r"bit\.ly|goo\.gl|tinyurl|is\.gd|t\.co", url) else 1

    # 4. having_at_symbol
    feats['having_at_symbol_'] = -1 if "@" in url else 1

    # 5. double_slash_redirecting
    feats['double_slash_redirecting_'] = -1 if url.rfind("//") > 7 else 1

    # 6. prefix_suffix
    domain = tldextract.extract(url).domain
    feats['prefix_suffix_'] = -1 if "-" in domain else 1

    # 7. having_sub_domain
    subdomain = tldextract.extract(url).subdomain
    feats['having_sub_domain_'] = -1 if subdomain.count(".") >= 1 else 1

    # 8. sslfinal_state
    feats['sslfinal_state_'] = 1 if url.startswith("https") else -1

    # TEMP defaults for remaining features (improve later)
    defaults = [
        'domain_registeration_length_', 'favicon_', 'port_', 'https_token_',
        'request_url_', 'url_of_anchor_', 'links_in_tags_', 'sfh_',
        'submitting_to_email_', 'abnormal_url_', 'redirect_', 'on_mouseover_',
        'rightclick_', 'popupwidnow_', 'iframe_', 'age_of_domain_', 'dnsrecord_',
        'web_traffic_', 'page_rank_', 'google_index_', 'links_pointing_to_page_',
        'statistical_report_'
    ]
    for k in defaults:
        feats[k] = 0

    # Build array in EXACT training order
    X = np.array([feats[col] for col in FEATURE_ORDER]).reshape(1, -1)
    return X

st.set_page_config(page_title="Phishing URL Detector", page_icon="🔐")
st.title("🔐 Phishing URL Detection System")

url = st.text_input("Enter URL")

if st.button("Check URL"):
    if not url:
        st.warning("Please enter a URL first.")
    else:
        x = extract_features(url)
        pred = model.predict(x)[0]

        if pred == 1:
            st.success("✅ Legitimate Website")
        else:
            st.error("🚨 Phishing Website Detected")