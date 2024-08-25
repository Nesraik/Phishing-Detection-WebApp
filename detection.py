from urllib.parse import urlparse
import pandas as pd
import whois
import ssl
import socket
from functools import lru_cache
from datetime import datetime, date
import dateutil
import pickle

#Obtained from original dataframes
scaler_mean = [2.44813725e-01, 7.49407796e-02, 2.11269830e+00, 1.15338095e+00,
               3.63631469e-01, 2.51597157e-02, 7.45959604e+03, 8.02212350e+03,
               8.14281100e-01, 4.99946163e-01]

scaler_scale = [4.91589065e-01, 2.70423971e-01, 1.21611531e+00, 2.60275875e+00,
                1.15822358e+00, 1.58092662e-01, 3.23601098e+03, 3.43537556e+03, 
                3.88879661e-01, 4.99999997e-01]

#Preprocessed data
data = pd.read_csv('sample_data.csv')

#Trained Model
RF = pickle.load(open('RF.pickle','rb'))
XGB = pickle.load(open('XGB.pickle','rb'))
LGBM = pickle.load(open('LGBM.pickle','rb'))

#Helper Functions
def url_length(url):
  return len(str(url))

def count_question_url(url):
  return url.count('?')

def count_equal_url(url):
  return url.count('=')

def count_http_url(url):
  result = urlparse(url)
  if result.scheme == 'http':
    return 1
  else:
    return 0

def count_https_url(url):
  result = urlparse(url)
  if result.scheme == 'https':
    return 1
  else:
    return 0
def count_tilde(url):
  return url.count('~')
def count_dot_url(url):
  return url.count('.')

def count_hyphen_url(url):
  return url.count('-')

def count_underline_url(url):
  return url.count('_')

def count_question_url(url):
  return url.count('?')

def count_slash_url(url):
  path = str(urlparse(url).path)
  return path.count('/')

@lru_cache(maxsize=None)

def get_domain_info(url):
    return whois.whois(url)

def age_of_domain(url):
    try:
        res = get_domain_info(url)
        current_date = datetime.combine(date.today(), datetime.min.time())
        creation_date = res.creation_date[0] if isinstance(res.creation_date, list) else res.creation_date
        # Calculate the domain age correctly
        domain_age = (current_date - creation_date).days
        return int(domain_age)
    except:
        return 0

def registration_length(url):
    try:
        res = get_domain_info(url)
        creation_date = res.creation_date[0] if isinstance(res.creation_date, list) else res.creation_date
        expiration_date = res.expiration_date[0] if isinstance(res.expiration_date, list) else res.expiration_date
        registration_length = (expiration_date - creation_date).days
        return int(registration_length)
    except:
        return 0

def verify_ssl_certificate(url, timeout=5):
    hostname = urlparse(url).netloc
    context = ssl.create_default_context()
    try:
        # Resolve the hostname first
        address_info = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
        address = address_info[0][4]  # Extract the address tuple

        # Create a socket connection with a timeout
        with socket.create_connection(address, timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.do_handshake()
                cert = ssock.getpeercert()
                return 1
    except Exception as e:
        return 0

def predict_new_url(mode,url):
    url_data = {
        'count_http': count_http_url(url),
        'count_https': count_https_url(url),
        'countdot':count_dot_url(url),
        'count-': count_hyphen_url(url),
        'count_': count_underline_url(url),
        'counttilde': count_tilde(url),
        'domain_age': age_of_domain(url),
        'regis_length': registration_length(url),
        'SSL_certificate': verify_ssl_certificate(url)
    }

    url_df = pd.DataFrame(url_data, index=[0])

    copydf = data.copy()
    mean_dict = {}
    for i, mean_value in enumerate(scaler_mean):
       feature_name = copydf.columns[i]
       mean_dict[feature_name] = mean_value

    std_dict = {}
    for i, std_value in enumerate(scaler_scale):
        feature_name = copydf.columns[i]
        std_dict[feature_name] = std_value

    url_df['domain_age'] = (url_df['domain_age'] - mean_dict[('domain_age')]) / std_dict[('domain_age')]
    url_df['regis_length'] = (url_df['regis_length'] - mean_dict[('regis_length')]) / std_dict[('regis_length')]

    RF_pred = RF.predict(url_df)
    XGB_pred = XGB.predict(url_df)
    LGBM_pred = LGBM.predict(url_df)
   
    if (mode=='Random Forest'):
      return "Phishing" if RF_pred[0] else "Benign"
    elif (mode=='LightGBM'):
      return "Phishing" if LGBM_pred[0] else "Benign"
    elif (mode=='XGBoost'):
      return "Phishing" if XGB_pred[0] else "Benign"

