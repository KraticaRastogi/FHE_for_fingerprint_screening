from Pyfhel import Pyfhel, PyCtxt
from Pyfhel.util import ENCODING_t
from flask import Flask, render_template

app = Flask(__name__, template_folder='../templates/')

# Defined host and port value for server application
HOST = "127.0.0.1"
PORT = 8081

# Setting variable for database path
databasePath = "../database/"


@app.route("/")
def index():
    """
    This method will show server application started
    :return:
    """
    # return "Starting server application"
    return render_template('authenticate.html')


@app.route("/difference/file1=<file1>&file2=<file2>&threshold=<threshold>")
def get_difference(file1, file2, threshold):
    """
    This method will restore current context and secret key from the file and calculating the difference between the
    two contexts and then decrypting the computed context
    :return: Matched or Not Matched
    """
    # Creating an empty Pyfhel object
    FHE = Pyfhel()

    # Restoring current context from the file
    FHE.restoreContext(databasePath + "context")

    # Restoring current secret key from the file
    FHE.restoresecretKey(databasePath + "secretkey")

    # Initializing an empty PyCtxt ciphertext by providing a pyfhel instance, fileName and an encoding to load the
    # fingerprintData from a saved file
    context1 = PyCtxt(pyfhel=FHE, fileName=databasePath + file1, encoding=ENCODING_t.BATCH)
    context2 = PyCtxt(pyfhel=FHE, fileName=databasePath + file2, encoding=ENCODING_t.BATCH)

    # Storing the context difference in variable
    difference = context1 - context2

    # Decrypts a PyCtxt ciphertext using the current secret key, based on the current context.If provided an output
    # vector, decrypts the ciphertext inside it.
    decrypted = FHE.decryptBatch(difference)

    # Calculating the mean
    distance = abs(sum(decrypted)/len(decrypted))

    print(distance)

    # Comparing the mean value
    if distance < float(threshold):
        return "Matched"
    else:
        return "Not Matched"


if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=True)
