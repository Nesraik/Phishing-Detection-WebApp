import streamlit as st
import requests
import json

st.title('Phishing Website Detection')
option = st.radio('Select the model to use', ['Random Forest', 'LightGBM', 'XGBoost'])

st.write('Enter the URL to check if it is a phishing website or not')

url = st.text_input('URL')

data = {
    "option": option,
    'url': url
}
def get_color(result):
    if result == 'Phishing':
        return 'red'
    else:  
        return 'green'

if url:
    result = requests.post(url = 'http://127.0.0.1:8000/predict', json=data)
    color = get_color(result.json())
    name_colored = f'<p style="color:{color};">{result.json()}!</p>'
    st.write("Type: "+name_colored, unsafe_allow_html=True)
 

