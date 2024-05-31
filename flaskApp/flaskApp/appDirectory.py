import os
import subprocess
from flask import *
from werkzeug.utils import secure_filename
import shutil
import pandas as pd
import warnings as wr
from sklearn.feature_extraction.text import CountVectorizer
import glob
import numpy as np
import tensorflow as tf
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'csv'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
'''
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
'''

def filterwireshark(input, destination):
    wr.filterwarnings('ignore')
    data = pd.read_csv(input)
    data = data.drop(['Time', 'No.'], axis = 1)
    data = data[~data['Protocol'].str.contains('SSDP', 'NBNS')]
    data = data[~data['Destination'].str.contains('239.255.255.250')]
    data = data[~data['Info'].str.contains('M-SEARCH*HTTP/1.1')]
    data.to_csv(os.path.join(destination,"Wireshark.CSV"))

def filterprocmon(input, destination):
    df = pd.read_csv(input)
    df = df[~(df['Process Name'].str.contains('Procmon64.exe')
                | df['Process Name'].str.contains('Wireshark.exe')
                | df['Process Name'].str.contains('Regshot-x64-Unicode.exe'))]
    df.to_csv(os.path.join(destination,"Procmon.CSV"))

def vectorizer(path, destination):
    labels = [1]
    text = []

    for filename in os.listdir(path):
        if filename == ".DS_Store":
            continue  # Skip the .DS_Store file
        filename = os.path.join(path, filename)
        print(filename)
        
        try:
            with open(filename, encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(filename, encoding='latin1') as f:
                content = f.read()

        content = content.replace(",", " ").replace('"', " ")
        text.append(content) 

    vectorizer = CountVectorizer(stop_words='english', max_features=2500)

    dtm = vectorizer.fit_transform(text)

    df = pd.DataFrame(dtm.toarray(), columns=vectorizer.get_feature_names_out())
    #df.index.name = "labels"
    

    df.to_csv(os.path.join(destination,"Filtered_DynamicMalwareMatrix.csv")) 

def clear_upload_folder():
    folder = app.config['UPLOAD_FOLDER']
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)  # Remove file or symbolic link
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)  # Remove directory and all its contents
        except Exception as e:
            print(f'Failed to delete {file_path}. Reason: {e}')

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/uploadfileprocmon', methods=['POST'])
def uploadfileprocmon():
    if 'procmonfile' not in request.files:
        return redirect(request.url)
    file = request.files['procmonfile']
    if file.filename == '':
        return redirect(request.url)
    
    if file:
        upload_folder = 'uploads/procmon/'
        
        # Create the directory if it does not exist
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
        
        # Save the file
        filename = file.filename
        file.save(os.path.join(upload_folder, filename))
    return redirect(url_for('index'))

@app.route('/uploadfilewireshark', methods=['POST'])
def uploadfilewireshark():
    if 'wiresharkfile' not in request.files:
        return redirect(request.url)
    file = request.files['wiresharkfile']
    if file.filename == '':
        return redirect(request.url)
    
    if file:
        upload_folder = 'uploads/wireshark/'
        
        # Create the directory if it does not exist
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
        
        # Save the file
        filename = file.filename
        file.save(os.path.join(upload_folder, filename))
    return redirect(url_for('index'))

@app.route('/runmodel', methods=['POST'])
def runmodel():
    upload_folder = 'uploads/filtered/'
    if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
    proc_folder_path = "uploads/procmon/"
    if not os.path.exists(proc_folder_path):
            os.makedirs(proc_folder_path)
    wireshark_folder_path = "uploads/wireshark/"
    if not os.path.exists(wireshark_folder_path):
            os.makedirs(wireshark_folder_path)
    final_destination = "uploads/final/"
    if not os.path.exists(final_destination):
            os.makedirs(final_destination)
    procmonfile =  glob.glob(os.path.join(proc_folder_path, '*'))
    wiresharkfile = glob.glob(os.path.join(wireshark_folder_path, '*'))
    filterwireshark(wiresharkfile[0], upload_folder)
    filterprocmon(procmonfile[0], upload_folder)
    vectorizer(upload_folder, final_destination)
    # Load the saved model
    model = tf.keras.models.load_model('deep_learning_model.keras')

# Load the scaler and label encoder
    model_data = joblib.load('scaler_labelencoder.pkl')
    scaler = model_data['scaler']
    label_encoder = model_data['label_encoder']
    # Load new data
    new_data = pd.read_csv('uploads/final/Filtered_DynamicMalwareMatrix.csv', delimiter=',', usecols=range(1, 1001), dtype=int)

# Preprocess new data
    new_data_normalized = scaler.transform(new_data)

# Predict using the loaded model
    y_pred_onehot = model.predict(new_data_normalized)
    y_pred = np.argmax(y_pred_onehot, axis=1)

# Convert predictions back to original labels
    y_pred_labels = label_encoder.inverse_transform(y_pred)

    with open('debug_predictions.py', 'w') as file:
        file.write("import numpy as np\n\n")
        file.write(f"y_pred_onehot = {repr(y_pred_onehot.tolist())}\n\n")
        file.write(f"y_pred = {repr(y_pred.tolist())}\n\n")
        file.write(f"y_pred_labels = {repr(y_pred_labels.tolist())}\n\n")

    if -1 in y_pred_labels:
        return render_template('malware.html')
    else:
        return render_template('nonmalware.html')


@app.route('/go_home')
def go_home():
    clear_upload_folder()
    return redirect(url_for('index'))

'''
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    arr_file = []
    if request.method == 'POST':
        if 'wiresharkfile' not in request.files or 'procmonfile' not in request.files:
            flash("sorry, not all data sent")
            return redirect(request.url)
        wiresharkfile = request.file["wiresharkfile"]
        procmonfile = request.file["procmonfile"]

        if wiresharkfile.filename == "" or procmonfile.filename == "":
            flash("two files needed")
            return redirect(request.url)
        
        if wiresharkfile and procmonfile:
            wiresharkfiles.save('uploads/wireshark' + wiresharkfiles.filename)
            procmonfile.save('uploads/wireshark' + wiresharkfiles.filename)

        procmonfiles = request.files('procmonfile') 
        wiresharkfiles = request.files('wiresharkfile') 
        clear_upload_folder()
        wiresharkfiles.save('uploads/wireshark' + wiresharkfiles.filename)
        procmonfiles.save('uploads/procmon' + procmonfiles.filename) 
        # Iterate for each file in the files List, and Save them 

        for file in files: 
            file.save('uploads/' + file.filename) 
            f = open('test.py', 'w')
            f.write("x")
            f.write(str(file.filename))
            f.close()

        return "<h1>Files Uploaded Successfully.!</h1>"
        

        #for file in files:

            file.save(file.filename)
            files = request.files.getlist("file")
            f = open('test.py', 'w')
            f.write(str(files))
            f.close()
            if 'file' not in request.files:
                return redirect(request.url)
            file = request.files['file']
            if file.filename == '':
                return redirect(request.url)
            if file:
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                arr_file.append(filename)
                f = open('test.py', 'w')
                f.write(str(filename))
                f.close()

'''        
   # return arr_file

@app.route('/logfiles')
def logfiles():
    return render_template("logfiles.html")

if __name__ == "__main__":
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)
