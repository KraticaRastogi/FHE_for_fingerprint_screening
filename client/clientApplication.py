import cv2
from Pyfhel import Pyfhel
from flask import Flask, render_template
from numpy import asarray
from sklearn.decomposition import PCA

app = Flask(__name__, template_folder='../templates/')

HOST = "127.0.0.1"
PORT = 8080

# Setting variable for user fingerprint images path
userDataPath = "../fingerprintData/"

# Setting variable for database path
databasePath = "../database/"

@app.route('/')
def index():
    """
    This method will show client application started
    :return: message
    """
    return render_template('enroll.html')


@app.route('/enroll/file=<file>')
def enroll(file):
    """
    This method will load preprocessed fingerprintData
    Define fully homomorphic encryption context
    Generate secret/public keys
    Apply fully homomorphic encryption on preprocessed fingerprintData
    :return: message
    """

    # Creating an empty Pyfhel object
    FHE = Pyfhel()

    # Generates Homomorphic Encryption context based on parameters.
    # Here p is defined as plaintext modulo where p is taken as 65537
    # because it is a prime number and p-1 is multiple of 2 * m and m is taken as 2048 which defines
    # the number of integers per ciphertext
    # flagBatching is set to true to enable batching
    FHE.contextGen(p=65537, m=16384, flagBatching=True)

    # Generates a pair of public/secret keys based on the context defined
    FHE.keyGen()

    # Saving the secret key
    FHE.savesecretKey(databasePath + "secretkey")

    # Saving the context in database
    FHE.saveContext(databasePath + "context")

    # Preprocess fingerprintData
    image = preprocessing_data(userDataPath + file)

    # Encryption makes use of the public key
    # Encrypting images using encryptBatch function
    encrypted_img = FHE.encryptBatch(image)

    # Write homomorphic encryption context1 to context1.txt file
    encrypted_img.to_file(databasePath + "encrypted_" + file)

    return "Encryption successful. File saved as : encrypted_" + file


def preprocessing_data(filepath):
    """
    This method will load images from fingerprintData folder
    Resizing an image to 90*90
    Normalize the data by dividing by 255.
    The normalized values will lie between 0 and 1
    We are trying to reduce to n_components
    :param filepath:
    :return:
    """
    # Loading an image from specified filepath and convert to grey scale image
    img = cv2.imread(filepath, cv2.IMREAD_GRAYSCALE)

    # Resizing an image to defined size
    img = cv2.resize(img, (150, 150))

    # Converting image to array
    img_pixels = asarray(img)

    # Converting from integers to floats
    img_pixels = img_pixels.astype('float32')

    # Normalizing to the range 0-1
    img_pixels /= 255.0

    # Applying PCA and defining the parameters. Number of components taken are 90. Randomized svd_solver is used to
    # project data to a lower-dimensional space preserving most of the variance by dropping the singular vector of
    # components associated with lower singular values. Whiten is enabled will ensure uncorrelated outputs with unit
    # component-wise variances.
    pca = PCA(n_components=100, svd_solver='randomized', whiten=True)

    # Fit the model with img_pixels and apply the dimensionality reduction on img_pixels.
    pca_transformed_image = pca.fit_transform(img_pixels)

    return pca_transformed_image.flatten()


if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=True)
