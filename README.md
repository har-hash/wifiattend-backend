# Face Recognition Backend Server

## Setup Instructions

1. Install Python 3.7 or newer.
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Place reference images in the `reference_images/` folder. Each image should be named as `{student_id}.jpg` (e.g., `12345.jpg`).
4. Run the server:
   ```
   python face_server.py
   ```

## API Usage

### POST /verify_face
- Params (form-data):
  - `student_id`: The student's ID (string)
  - `image`: The captured face image (file)
- Response:
  - `{ "success": true, "match": true/false }`

## Notes
- The server runs on port 5000 by default.
- You can test with Postman or curl.
