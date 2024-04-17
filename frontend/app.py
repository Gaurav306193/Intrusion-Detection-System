import numpy as np
import catboost as cbt
import lightgbm as lgb
import xgboost as xgb
import pandas as pd
import streamlit as st 
from sklearn import preprocessing
import pickle

model = pickle.load(open('C:/Users/GAURAV/Intrusion Detection System/lg_model.pkl', 'rb'))
mode1= pickle.load(open('C:/Users/GAURAV/Intrusion Detection System/xg_model.pkl','rb'))
mode2= pickle.load(open('C:/Users/GAURAV/Intrusion Detection System/cb_model.pkl','rb'))
cols=['flow_duration','total_fwd_packets','total_bwd_packets','total_length_fwd_packets','total_length_bwd_packets']    
  
def main(): 
    st.title("Intrusion Detection System")
    html_temp = """
    <div style="background:#025246 ;padding:10px">
    <h2 style="color:white;text-align:center;">Intrusion Detection System </h2>
    </div>
    """
    st.markdown(html_temp, unsafe_allow_html = True)

    uploaded_file = st.file_uploader("Upload CSV file", type=["csv"])

    if uploaded_file is not None:
        st.write("File Uploaded Successfully!")

        # Read the CSV file into a DataFrame
        df = pd.read_csv(uploaded_file)
        df = df.drop(columns=["Label"], errors="ignore")
        last_row = df.iloc[-1]

        # Convert the last row to a dictionary where column names are keys
        last_row_dict = last_row.to_dict()
    
    
    if st.button("Predict"): 

        print(last_row_dict)
        df=pd.DataFrame([list(last_row_dict.values())], columns=['Flow Duration','Total Fwd Packets','Total Backward Packets','Total Length of Fwd Packets','Total Length of Bwd Packets','Fwd Packet Length Max','Fwd Packet Length Min','Fwd Packet Length Mean','Fwd Packet Length Std','Bwd Packet Length Max','Bwd Packet Length Min','Bwd Packet Length Mean','Bwd Packet Length Std','Flow Bytes/s','Flow Packets/s','Flow IAT Mean','Flow IAT Std','Flow IAT Max','Flow IAT Min','Fwd IAT Total','Fwd IAT Mean','Fwd IAT Std','Fwd IAT Max','Fwd IAT Min','Bwd IAT Total','Bwd IAT Mean','Bwd IAT Std','Bwd IAT Max','Bwd IAT Min','Fwd PSH Flags','Bwd PSH Flags','Fwd URG Flags','Bwd URG Flags','Fwd Header Length','Bwd Header Length','Fwd Packets/s','Bwd Packets/s','Min Packet Length','Max Packet Length','Packet Length Mean','Packet Length Std','Packet Length Variance','FIN Flag Count','SYN Flag Count','RST Flag Count','PSH Flag Count','ACK Flag Count','URG Flag Count','CWE Flag Count','ECE Flag Count','Down/Up Ratio','Average Packet Size','Avg Fwd Segment Size','Avg Bwd Segment Size','Fwd Header Length.1','Fwd Avg Bytes/Bulk','Fwd Avg Packets/Bulk','Fwd Avg Bulk Rate','Bwd Avg Bytes/Bulk','Bwd Avg Packets/Bulk','Bwd Avg Bulk Rate','Subflow Fwd Packets','Subflow Fwd Bytes','Subflow Bwd Packets','Subflow Bwd Bytes','Init_Win_bytes_forward','Init_Win_bytes_backward','act_data_pkt_fwd','min_seg_size_forward','Active Mean','Active Std','Active Max','Active Min','Idle Mean','Idle Std','Idle Max','Idle Min'])
                
        features_list = df.values.tolist()      
        prediction = model.predict(features_list)
    
        output = int(prediction[0])
        if output == 1:
            text = "Intrucion Detected"
        else:
            text = "Intrucion not Detected"

        st.success('Result: {}'.format(text))
      
if __name__=='__main__': 
    main()