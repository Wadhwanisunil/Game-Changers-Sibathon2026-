import streamlit as st
import pickle  
st.title("Phishing URL Detector")
url_input = st.text_input("Enter a URL to check:")

if st.button("Check URL"):
   
    
    st.write("Prediction: ⚠ Phishing")  