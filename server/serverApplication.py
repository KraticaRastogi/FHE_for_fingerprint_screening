from Pyfhel import Pyfhel, PyCtxt
from Pyfhel.util import ENCODING_t
from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    """
    This method will show server application started
    :return:
    """
    return "Starting server application"

@app.route("/difference")
def get_difference():
    """
    This method will restore current context and secret key from the file and calculating the difference between the
    two contexts and then decrypting the computed context
    :return: Matched or Not Matched
    """
    # Creating an empty Pyfhel object
    FHE = Pyfhel()

    # restoring current context from the file
    FHE.restoreContext("../database/saveContext")

    # restoring current secret key from the file
    FHE.restoresecretKey("../database/secretkey")

    # Initializing an empty PyCtxt ciphertext by providing a pyfhel instance, fileName and an encoding to load the
    # fingerprintData from a saved file
    context1 = PyCtxt(pyfhel=FHE, fileName="../database/context1.txt", encoding=ENCODING_t.BATCH)
    context2 = PyCtxt(pyfhel=FHE, fileName="../database/context2.txt", encoding=ENCODING_t.BATCH)

    # storing the context difference in variable
    difference = context1 - context2

    # Decrypts a PyCtxt ciphertext using the current secret key, based on the current context.If provided an output
    # vector, decrypts the ciphertext inside it.
    decrypted = FHE.decryptBatch(difference)

    # Calculating the mean
    mean = (sum(decrypted)/len(decrypted))

    # Comparing the mean value
    if mean != 0:
        return "Not matched"
    else:
        return "Matched"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8081, debug=True)
