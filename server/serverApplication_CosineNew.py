# Defining the imports required
import os
import numpy as np
import pandas as pd
from Pyfhel import Pyfhel, PyCtxt
from Pyfhel.util import ENCODING_t
from flask import Flask, render_template
from math import sqrt

app = Flask(__name__, template_folder='../templates/')

# Defined host and port value for server application
HOST = "127.0.0.1"
PORT = 8081

# Setting variable for database path
database = "../database/"

# Creating an empty Pyfhel object
FHE = Pyfhel()


# The application will decorate to a view function to register route with the given URL
@app.route("/")
def index():
    """
    This method will show server application started
    :return: HTML template for authenticating user's fingerprint
    """
    return render_template('authenticate.html')


# The application will decorate to a view function to register route with the given URL
@app.route("/difference/file1=<file1>&file2=<file2>&threshold=<threshold>")
def get_difference(file1, file2, threshold, return_distance=False):
    """
    This method will restore current context and secret key from the file and calculating the difference between the
    two contexts and then decrypting the computed context
    :return: Matched or Not Matched
    """

    # Initializing an empty PyCtxt ciphertext by providing a pyfhel instance, fileName and an encoding to load the
    # fingerprintData from a saved file
    context1 = PyCtxt(pyfhel=FHE, fileName=database + file1, encoding=ENCODING_t.BATCH)
    context2 = PyCtxt(pyfhel=FHE, fileName=database + file2, encoding=ENCODING_t.BATCH)

    decrypted_context1 = np.array(FHE.decryptBatch(context1))
    decrypted_context2 = np.array(FHE.decryptBatch(context2))

    distance = abs(cosine_similarity(decrypted_context1, decrypted_context2))

    print(distance)

    # Checking the boolean value of return_distance
    if return_distance:
        return distance
    else:
        # Comparing the mean value
        if distance > float(threshold):
            return "Matched"
        else:
            return "Not Matched"


def square_rooted(x):
    """
    Calculating the square root to pass in the calculation of cosine similarity
    :param x: Value to be passed to calculate the square root
    :return: round off of square root unto 3 decimals.
    """
    return round(sqrt(sum([a * a for a in x])), 3)


def cosine_similarity(x, y):
    """
    This method will return the cosine similarity between two given fingerprint feature vectors
    :param x: fingerprint vector-1 to calculate the similarity
    :param y: fingerprint vector-2 to calculate the similarity
    :return: computed similarity between two fingerprint vectors
    """
    numerator = sum(a * b for a, b in zip(x, y))
    denominator = square_rooted(x) * square_rooted(y)
    return round(numerator / float(denominator), 3)


# The application will decorate to a view function to register route with the given URL
@app.route('/difference/all')
def display_table():
    """
    Method to find differences of all the encrypted files present in the database directory
    :return: html view of differences
    """
    # Create an empty list to have all encrypted files
    encrypted_filenames = []

    # Iterate through all file
    for file in os.listdir(database):
        # Check whether file is in text format or not
        if "." in file:
            encrypted_filenames.append(file)

    # Create empty dataframe list to have table
    df_list = []

    # Set threshold value
    threshold = 0.01

    # Initializing true positive, false positive, false negative and true negative
    tp_count = 0
    fp_count = 0
    fn_count = 0
    tn_count = 0

    # Loop for comparing the encrypted file with other encrypted files
    for i in range(0, len(encrypted_filenames)):
        for j in range(i + 1, len(encrypted_filenames)):

            # Calling get_difference method to calculate the difference between two encrypted files
            diff = get_difference(encrypted_filenames[i], encrypted_filenames[j],
                                  threshold=threshold, return_distance=True)

            # Splitting the files on the basis of dot
            filename1 = encrypted_filenames[i].split('.')[0]
            filename2 = encrypted_filenames[j].split('.')[0]

            # Comparing two file names
            # Here expected is considered as predicted
            expected = filename1 == filename2

            # If difference between two encrypted files is less than threshold then actual is true otherwise false
            actual = diff > threshold

            # Calling getResult function to compare between the actual and expected (predicted) value
            result = getResult(actual, expected)

            # Incrementing counter on the basis of conisitions provided
            if result == "TP":
                tp_count += 1
            elif result == "FP":
                fp_count += 1
            elif result == "FN":
                fn_count += 1
            else:
                tn_count += 1

            # Creating the pandas dataframe to put that result values in HTML table
            df = pd.DataFrame(
                {
                    'file1': [filename1],
                    'file2': [filename2],
                    'difference': [diff],
                    'expected': expected,
                    'actual': actual,
                    'error': result
                })

            # Appending the dataframe column value in dataframe list
            df_list.append(df)

    # Calling printMetrics method to print values
    printMetrics(tp_count, fp_count, fn_count, tn_count)

    # Concatenate all dataframes into one
    df_to_display = pd.concat(df_list)

    # Use pandas method to auto generate html
    df_html = df_to_display.to_html(index=False, classes='table table-stripped')

    # Return tabular view
    return render_template('table.html', table_html=df_html)
    # return "tabular view"


def getResult(actual, expected):
    """
    This function is used to get the results such as True Positive, False Positive, False Negative and True Negative
    :param actual: Passing the actual value
    :param expected: Passing the expected (predicted) value
    :return: TP or FP or FN or TN
    """
    if expected and actual:
        return "TP"
    elif expected and (not actual):
        return "FP"
    elif (not expected) and actual:
        return "FN"
    else:
        return "TN"


def printMetrics(tp, fp, fn, tn):
    """
    This function is used to print the metrics such as TP, FP, FN, TN
    :param tp:
    :param fp:
    :param fn:
    :param tn:
    :return: printing the performance scores and metrices
    """
    print("True Positive : ", tp)
    print("False Positive : ", fp)
    print("False Negative : ", fn)
    print("True Negative : ", tn)

    # https://medium.com/analytics-vidhya/what-is-a-confusion-matrix-d1c0f8feda5

    # Calculating the metrics score
    accuracy = (tp + tn) / (tp + tn + fp + fn)
    precision = tp / (tp + fp)
    recall = tp / (tp + fn)
    f1_score = 2 * ((recall * precision) / (recall + precision))

    print("Accuracy : ", accuracy)
    print("Precision : ", precision)
    print("Recall : ", recall)
    print("F1_score : ", f1_score)


if __name__ == "__main__":
    # Restoring current context from the file
    FHE.restoreContext(database + "context")

    # Restoring current secret key from the file
    FHE.restoresecretKey(database + "secretkey")

    # Running the application in local development server
    app.run(host=HOST, port=PORT, debug=True)
