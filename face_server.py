import os
from flask import Flask, request, jsonify
import face_recognition
from PIL import Image
import numpy as np
from io import BytesIO
from student_db import init_db, add_student

app = Flask(__name__)

REFERENCE_FOLDER = os.path.join(os.path.dirname(__file__), 'reference_images')


init_db()

@app.route('/verify_face', methods=['POST'])
def verify_face():
    print("student_id:", request.form.get('student_id'))
    print("image:", request.files.get('image'))
    student_id = request.form.get('student_id')
    image_file = request.files.get('image')
    if not student_id or not image_file:
        return jsonify({'success': False, 'error': 'Missing student_id or image'}), 400

    reference_path = os.path.join(REFERENCE_FOLDER, f'{student_id}.jpg')
    if not os.path.isfile(reference_path):
        return jsonify({'success': False, 'error': 'Reference image not found'}), 404

    # Load reference image
    reference_image = face_recognition.load_image_file(reference_path)
    reference_encodings = face_recognition.face_encodings(reference_image)
    if not reference_encodings:
        return jsonify({'success': False, 'error': 'No face found in reference image'}), 400
    reference_encoding = reference_encodings[0]

    # Load uploaded image
    image = Image.open(image_file.stream)
    image_np = np.array(image)
    uploaded_encodings = face_recognition.face_encodings(image_np)
    if not uploaded_encodings:
        return jsonify({'success': False, 'error': 'No face found in uploaded image'}), 400
    uploaded_encoding = uploaded_encodings[0]

    # Compare faces
    match = face_recognition.compare_faces([reference_encoding], uploaded_encoding)[0]

    return jsonify({'success': True, 'match': match})

print("Registered routes:")
for rule in app.url_map.iter_rules():
    print(rule)

if __name__ == '__main__':
    os.makedirs(REFERENCE_FOLDER, exist_ok=True)
    app.run(host='0.0.0.0', port=5000, debug=True)
