from flask import Flask, send_from_directory, request, jsonify

app = Flask(__name__, static_url_path='', static_folder='static')

@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')


@app.route('/calculate', methods=['POST'])
def calculate():
    data = request.get_json()
    expression = data.get('expression', '')

    try:
        result = eval(expression) 
    except Exception as e:
        return jsonify({'error': str(e)}), 400

    return jsonify({'result': result})

if __name__ == '__main__':
    app.run(debug=True)
