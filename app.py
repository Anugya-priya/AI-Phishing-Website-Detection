from flask import Flask, render_template, request
import model  # the model.py file we created

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    url_input = request.form['url']

    result = model.predict_url(url_input)
    return render_template('index.html', result=result, url=url_input)

if __name__ == '__main__':
    app.run(debug=True)
