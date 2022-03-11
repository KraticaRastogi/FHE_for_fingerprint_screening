# Defining the imports required
import os
import shutil
import string
from datetime import datetime
import random
import cv2
from Pyfhel import Pyfhel
from flask import Flask, render_template
from numpy import asarray
from sklearn.decomposition import PCA


# Create an instance of flask web application
app = Flask(__name__, template_folder='../templates/')

HOST = "127.0.0.1"
PORT = 8080

# Define the name of the directory to be created
dirPath = '../database/'

# Check if database folder exist
if os.path.exists(dirPath):

    # Recursively remove existing files or folders from the database folder
    shutil.rmtree(dirPath)

# Create directory
os.makedirs(dirPath)

# Creating an empty Pyfhel object which is the base for all operations needs to perform
FHE = Pyfhel()

# The application will decorate to a view function to register route with the given URL
@app.route('/')
def index():
    """
    This method will show client application started
    :return: HTML template for enroll
    """
    return render_template('enroll.html')


# The application will decorate to a view function to register route with the given URL
@app.route('/enroll/file=<file>')
def enroll(file, folder="../dataSet/DB3_B/"):
    """
    This method will encrypt the fingerprint images

    Preprocessed data method is being called and then
    homomorphic encryption is being performed on that using encryptBatch function
    :param folder: Defaults to DB3_B
    :param file: Name of file to encrypt
    :return: Encrypted file
    """
    t1 = datetime.now()

    # Preprocess fingerprintData
    image = preprocessing_data(folder + file)

    # Encryption makes use of the public key
    # Encrypting images using encryptBatch function
    encrypted_img = FHE.encryptBatch(image)

    # Write homomorphic encryption context1 to context1.txt file
    encrypted_img.to_file(dirPath + file + ''.join(random.choices(string.ascii_lowercase + string.digits, k=5)))

    t2 = datetime.now()

    encryptionTime = t2 - t1

    print("Encryption Time Taken:", encryptionTime.microseconds)

    return "Congrats!! The file is now in encrypted format and saved in database."


# The application will decorate to a view function to register route with the given URL
@app.route('/enroll_all/folder=<folder>')
def enroll_all(folder):
    """
    This method will encrypt all the fingerprint images given in the folder that is being passed

    Preprocessed data method is being called and then
    homomorphic encryption is being performed on that using encryptBatch function
    :return: Message
    """

    path = "../dataSet/"+folder+"/"

    for file in os.listdir(path):
        if file.endswith('.tif'):
            enroll(file, folder=path)

    return "Encryption successful. \n All files saved in database."


def preprocessing_data(filepath):
    """
    Pre-processing of data is being done in this method

    This method will load fingerprint images from the folder which includes multiple fingerprint images
    Resizing an image to 150*150
    Normalize the data by dividing by 255.
    The normalized values will lie between 0 and 1
    Applied PCA to reduce to n_components
    :param filepath: Provides image file directory
    :return: Preprocessed image
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
    img_pixels_normalized = img_pixels/255.0

    # Applying PCA and defining the parameters. Number of components taken are 50. svd_solver is Randomized because
    # it projects data to a lower-dimensional space preserving most of the variance by dropping the singular vector
    # of components associated with lower singular values. Whiten is enabled will ensure uncorrelated outputs with
    # unit component-wise variances.
    pca = PCA(n_components=50, svd_solver='randomized', whiten=True)

    # Fit the model and apply the dimensionality reduction
    pca_transformed_image = pca.fit_transform(img_pixels_normalized)

    return pca_transformed_image.flatten()


if __name__ == "__main__":
    k1 = datetime.now()

    # Generates Homomorphic Encryption context based on parameters.
    # Here p is defined as plaintext modulo where p is taken as 65537
    # because it is a prime number and p-1 is multiple of 2 * m and m is taken as 4096 which defines
    # the number of integers per ciphertext
    # flagBatching is set to true to enable batching
    FHE.contextGen(p=65537, m=8192, sec=128, flagBatching=True)

    k2 = datetime.now()

    keyGen_timeTaken = k2 - k1

    print("Time Taken for keygen:", keyGen_timeTaken.microseconds)

    # Generates a pair of public/secret keys based on the context defined
    FHE.keyGen()

    # Saving the secret key
    FHE.savesecretKey(dirPath + "secretkey")

    # Saving the context in database
    FHE.saveContext(dirPath + "context")

    # Running the application in local development server
    app.run(host=HOST, port=PORT, debug=True, use_reloader=False)
