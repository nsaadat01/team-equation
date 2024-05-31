import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import tensorflow as tf
import joblib
import pickle
from numpy import genfromtxt
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

np.random.seed(0)
tf.random.set_seed(0)

learning_rate = 0.001
n_epochs = 5000  

def convertOneHot(data):
    y_onehot = np.zeros((len(data), data.max() + 1))
    for i, j in enumerate(data):
        y_onehot[i][j] = 1
    return y_onehot

feature = genfromtxt('Filtered_DynamicMalwareMatrix.csv', delimiter=',', usecols=range(1, 1001), dtype=int)
target = genfromtxt('Filtered_DynamicMalwareMatrix.csv', delimiter=',', usecols=0, dtype=int)

sc = StandardScaler()
feature_normalized = sc.fit_transform(feature)

target_label = LabelEncoder().fit_transform(target)
target_onehot = convertOneHot(target_label)

x_train, x_test, y_train_onehot, y_test_onehot = train_test_split(feature_normalized, target_onehot, test_size=0.25, random_state=0)

A = x_train.shape[1]
B = y_train_onehot.shape[1]
print(A)  # features
print(B)  # columns
print("Begin:__________________________________")

precision_scores_list = []
accuracy_scores_list = []

def print_stats_metrics(y_test, y_pred):    
    print('Accuracy: %.2f' % accuracy_score(y_test, y_pred))
    accuracy_scores_list.append(accuracy_score(y_test, y_pred))
    confmat = confusion_matrix(y_true=y_test, y_pred=y_pred)
    print("Confusion matrix")
    print(confmat)
    print(pd.crosstab(y_test, y_pred, rownames=['True'], colnames=['Predicted'], margins=True))
    precision_scores_list.append(precision_score(y_true=y_test, y_pred=y_pred, average='weighted'))
    print('Precision: %.3f' % precision_score(y_true=y_test, y_pred=y_pred, average='weighted'))
    print('Recall: %.3f' % recall_score(y_true=y_test, y_pred=y_pred, average='weighted'))
    print('F1-measure: %.3f' % f1_score(y_true=y_test, y_pred=y_pred, average='weighted'))


def plot_metric_per_epoch():
    x_epochs = list(range(len(accuracy_scores_list)))
    y_epochs = accuracy_scores_list

    plt.scatter(x_epochs, y_epochs, s=50, c='lightgreen', marker='s', label='score')
    plt.xlabel('epoch')
    plt.ylabel('score')
    plt.title('Score per epoch')
    plt.legend()
    plt.grid()
    plt.show()

###############################################################
##Deep Learning 
##############################################################

def build_model(input_dim, output_dim):
    model = tf.keras.Sequential([
        tf.keras.layers.Dense(30, activation='relu', input_shape=(input_dim,)),
        tf.keras.layers.Dense(25, activation='relu'),
        tf.keras.layers.Dense(10, activation='relu'),
        tf.keras.layers.Dense(5, activation='relu'),
        tf.keras.layers.Dense(output_dim, activation='softmax')
    ])
    model.compile(optimizer=tf.keras.optimizers.SGD(learning_rate=learning_rate),
                  loss='categorical_crossentropy',
                  metrics=['accuracy'])
    return model

model = build_model(A, B)
history = model.fit(x_train, y_train_onehot, epochs=n_epochs, validation_data=(x_test, y_test_onehot), verbose=1)

y_pred_onehot = model.predict(x_test)
y_pred = np.argmax(y_pred_onehot, axis=1)
y_true = np.argmax(y_test_onehot, axis=1)

print_stats_metrics(y_true, y_pred)

accuracy_scores_list = history.history['val_accuracy']
plot_metric_per_epoch()

# Save the model in keras format
model.save('deep_learning_model.keras')
print("Model saved as 'deep_learning_model.keras'")

# Save the scaler and label encoder using joblib
model_data = {
    'scaler': sc,
    'label_encoder': LabelEncoder().fit(target)  # save the fitted label encoder
}

joblib.dump(model_data, 'scaler_labelencoder.pkl')
print("Scaler and Label Encoder saved as 'scaler_labelencoder.pkl'")

# Serialize the entire setup including the TensorFlow model
with open('full_model.pkl', 'wb') as f:
    pickle.dump({
        'model_file': 'deep_learning_model.h5',
        'scaler_labelencoder': 'scaler_labelencoder.pkl'
    }, f)

print("Full model including scaler and label encoder saved as 'full_model.pkl'")

print("<<<<<DONE>>>>>>")
