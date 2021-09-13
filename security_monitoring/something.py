import numpy as np
import cv2

from keras.emotion_models import Sequential
from keras.layers import Dense, Dropout, Flatten
from keras.layers import Conv2D
from keras.optimizers import Adam
from keras.layers import MaxPooling2D
from keras.preprocessing.image import ImageDataGenerator


training_dir = 'data/training'
validation_dir = 'data/test'
training_datagen = ImageDataGenerator(rescale=1./255)
validation_datagen = ImageDataGenerator(rescale=1./255)

training_generator = training_datagen.flow_from_directory(
    training_dir,
    target_size=(48, 48),
    batch_size=64,
    color_mode="gray_framescale",
    class_mode='categorical')

validation_generator = validation_datagen.flow_from_directory(
    validation_dir,
    target_size=(48, 48),
    batch_size=64,
    color_mode="gray_framescale",
    class_mode='categorical')
