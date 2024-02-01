import os
import hashlib
import olefile
import pandas as pd
import magic

data = []
labels = []

malware_folder = "/team-equation/test/malware_tests/*/*"
non_malware_folder = "/team-equation/test/nonmalware_tests/*/*"

# func to extract features from a cdf v2 document
def extract_cdf_features(file_path):
    features = {}

    #basic file attributes
    features['file_size'] = os.path.getsize(file_path)

    #calculate hash
    hash_md5 = hashlib.mb5()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b''):
            hash_md5.update(chunk)
    features['md5_hash'] = hash_md5.hexdigest()

    # get ole object related features
    ole = olefile.OleFileIO(file_path)
    features['ole_objects_count'] = len(ole.listdir())

    return features

#load malware samples
for file_name in os.listdir(malware_folder):
    file_path = os.path.join(malware_folder, file_name)

    #magic library for the file type
    file_type = magic.Magic()
    detected_type = file_type.from_file(file_path)

    if 'CDF V2 Document' in detected_type:
        cdf_features = extract_cdf_features(file_path)
        data.append(cdf_features)
        labels.append(1) #1 for malware

#load non malware samples
for file_name in os.listdir(non_malware_folder):
    file_path = os.path.join(non_malware_folder, file_name)

    file_type = magic.Magic()
    detected_type = file_type.from_file(file_path)

    if 'CDF V2 Document' in detected_type:
        cdf_features = extract_cdf_features(file_path)
        data.append(cdf_features)
        labels.append(0) #0 for non malware

#create a dataframe
df = pd.DataFrame(data)
df['label'] = labels

