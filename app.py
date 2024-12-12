from flask import Flask, render_template, request
import numpy as np
import os.path
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
import mason_crypto

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('form.html')





@app.route('/submit', methods=['POST'])
def submit():
    public_key = str(request.form.get('Public Key'))
    message_input = str(request.form.get('Message Input'))
    secret_key = str(request.form.get('Secret Key'))
    ciphertext_input = str(request.form.get('Ciphertext Input'))
    security_param = str(request.form.get('Security Parameter'))
    
    if (len(public_key) != 0) & (len(message_input) != 0):
        ciphertext = mason_crypto.cipher_text_output_reformatter(mason_crypto.string_enc(mason_crypto.public_key_input_reformatter(public_key), message_input))
    else:
        ciphertext = 'n/a'
    
    if (len(security_param) != 0) & (security_param != 0):
        pk,sk = mason_crypto.gen(int(security_param))
        new_secret_key = mason_crypto.secret_key_output_reformatter(sk)
        new_public_key = mason_crypto.public_key_output_reformatter(pk)
    else:
        ciphertext = 'n/a'

    if (len(secret_key) != 0) & (len(ciphertext_input) != 0):
        plaintext = mason_crypto.string_dec(mason_crypto.secret_key_input_reformatter(secret_key), mason_crypto.cipher_text_input_reformatter(ciphertext_input))
    else:
        plaintext = 'n/a'
    
    return render_template('result.html', ciphertext = ciphertext, plaintext = plaintext, new_public_key = new_public_key, new_secret_key = new_secret_key)

if __name__ == '__main__':
    app.run(debug=True)
