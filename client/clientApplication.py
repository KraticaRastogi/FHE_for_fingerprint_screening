import cv2
from Pyfhel import Pyfhel
from flask import Flask
from numpy import asarray
from sklearn.decomposition import PCA

app = Flask(__name__)


@app.route("/")
def index():
    """
    This method will show client application started
    :return: message
    """
    return "Starting client application"


@app.route("/load")
def load():
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
    FHE.contextGen(p=65537, m=8192, flagBatching=True)

    # Generates a pair of public/secret keys based on the context defined
    FHE.keyGen()

    # Saving the secret key
    FHE.savesecretKey("../database/secretkey")

    # Saving the context in database
    FHE.saveContext("../database/saveContext")

    # preprocess fingerprintData for fingerprint image1
    image1 = preprocessing_data("../fingerprintData/103_1.tif")

    # preprocess fingerprintData for fingerprint image2
    image2 = preprocessing_data("../fingerprintData/103_3.tif")

    # Encryption makes use of the public key
    # For matrix, encryptBatch function is used
    FHE_context1 = FHE.encryptBatch(image1)
    FHE_context2 = FHE.encryptBatch(image2)

    # Write homomorphic encryption context1 to context1.txt file
    FHE_context1.to_file("../database/context1.txt")

    # Write homomorphic encryption context2 to context2.txt file
    FHE_context2.to_file("../database/context2.txt")

    return "client encrypted fingerprintData successfully"


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
    img = cv2.resize(img, (90, 90))

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
    pca = PCA(n_components=90, svd_solver='randomized', whiten=True)

    # Fit the model with img_pixels and apply the dimensionality reduction on img_pixels.
    pca_transformed_image = pca.fit_transform(img_pixels)

    # print(pca_transformed_image.flatten())
    return pca_transformed_image.flatten()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)
