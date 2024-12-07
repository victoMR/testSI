import base64
import hashlib
from flask import Flask, render_template, request, jsonify
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

app = Flask(__name__)

# Global variables to simulate session state
symmetric_key = Fernet.generate_key()
rsa_key_pair = None

def generate_rsa_key_pair():
    """Generate a new RSA key pair"""
    global rsa_key_pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    rsa_key_pair = {
        'private': private_key,
        'public': private_key.public_key()
    }

# Initialize RSA key pair
generate_rsa_key_pair()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/symmetric-encryption', methods=['GET', 'POST'])
def symmetric_encryption():
    global symmetric_key
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'encrypt':
            try:
                message = request.form.get('message')
                f = Fernet(symmetric_key)
                encrypted_message = f.encrypt(message.encode())
                return jsonify({
                    'status': 'success', 
                    'encrypted_message': base64.b64encode(encrypted_message).decode()
                })
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)})
        
        elif action == 'decrypt':
            try:
                message = request.form.get('message')
                f = Fernet(symmetric_key)
                # Decode base64 before decrypting
                message_bytes = base64.b64decode(message)
                decrypted_message = f.decrypt(message_bytes)
                return jsonify({
                    'status': 'success', 
                    'decrypted_message': decrypted_message.decode()
                })
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)})
        
        elif action == 'regenerate_key':
            symmetric_key = Fernet.generate_key()
            return jsonify({
                'status': 'success', 
                'symmetric_key': base64.b64encode(symmetric_key).decode()
            })
    
    # GET request
    return render_template('symmetric_encryption.html', 
                           symmetric_key=base64.b64encode(symmetric_key).decode())

@app.route('/asymmetric-encryption', methods=['GET', 'POST'])
def asymmetric_encryption():
    global rsa_key_pair
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'encrypt':
            try:
                message = request.form.get('message')
                # Encrypt with public key using OAEP padding
                mensaje_bytes = message.encode()
                encrypted_message = rsa_key_pair['public'].encrypt(
                    mensaje_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                return jsonify({
                    'status': 'success', 
                    'encrypted_message': base64.b64encode(encrypted_message).decode()
                })
            except ValueError as e:
                return jsonify({'status': 'error', 'message': str(e)})
        
        elif action == 'decrypt':
            try:
                message = request.form.get('message')
                # Decrypt with private key using OAEP padding
                decrypted_message = rsa_key_pair['private'].decrypt(
                    base64.b64decode(message),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                return jsonify({
                    'status': 'success', 
                    'decrypted_message': decrypted_message.decode()
                })
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)})
        
        elif action == 'regenerate_keypair':
            generate_rsa_key_pair()
            # Get public key in PEM format
            public_key_pem = rsa_key_pair['public'].public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return jsonify({
                'status': 'success', 
                'public_key': public_key_pem.decode()
            })
    
    # GET request
    public_key_pem = rsa_key_pair['public'].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return render_template('asymmetric_encryption.html', 
                           public_key=public_key_pem.decode())

@app.route('/hash-functions', methods=['GET', 'POST'])
def hash_functions():
    if request.method == 'POST':
        action = request.form.get('action')
        text = request.form.get('text')
        algorithm = request.form.get('algorithm')
        known_hash = request.form.get('known_hash')
        
        # Hash algorithms
        algoritmos = {
            "SHA-256": hashlib.sha256,
            "MD5": hashlib.md5,
            "SHA-1": hashlib.sha1
        }
        
        if action == 'calculate':
            # Calculate hash
            hash_obj = algoritmos[algorithm]()
            hash_obj.update(text.encode())
            hash_value = hash_obj.hexdigest()
            
            return jsonify({
                'status': 'success', 
                'hash_value': hash_value
            })
        
        elif action == 'verify':
            # Verify hash
            hash_obj = algoritmos[algorithm]()
            hash_obj.update(text.encode())
            hash_calculado = hash_obj.hexdigest()
            
            return jsonify({
                'status': 'success', 
                'is_valid': hash_calculado == known_hash
            })
    
    return render_template('hash_functions.html')

@app.route('/ssl-certificates', methods=['GET', 'POST'])
def ssl_certificates():
    if request.method == 'POST':
        # Certificate generation
        try:
            # Get form data
            pais = request.form.get('pais', 'MX')
            estado = request.form.get('estado', 'Querétaro')
            localidad = request.form.get('localidad', 'Ciudad')
            organizacion = request.form.get('organizacion', 'Mi Organización')
            dominio = request.form.get('dominio', 'localhost')
            dias_validez = int(request.form.get('dias_validez', 365))

            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )

            # Generate self-signed certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, pais),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, estado),
                x509.NameAttribute(NameOID.LOCALITY_NAME, localidad),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organizacion),
                x509.NameAttribute(NameOID.COMMON_NAME, dominio)
            ])

            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=dias_validez)
            ).sign(private_key, hashes.SHA256())

            # Convert certificate to PEM
            pem_cert = cert.public_bytes(serialization.Encoding.PEM)
            
            # Convert private key to PEM
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

            # Prepare certificate details
            cert_details = {
                'issuer': cert.issuer.rfc4514_string(),
                'subject': cert.subject.rfc4514_string(),
                'valid_from': cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S'),
                'valid_to': cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S'),
                'serial_number': str(cert.serial_number),
                'certificate_pem': pem_cert.decode(),
                'private_key_pem': private_key_pem.decode()
            }

            return jsonify({
                'status': 'success', 
                'certificate': cert_details
            })
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)})
    
    if request.method == 'GET':
        return render_template('ssl_certificates.html')

@app.route('/verify-certificate', methods=['POST'])
def verify_certificate():
    cert_pem = request.form.get('certificate')
    
    try:
        # Load the certificate
        cert = x509.load_pem_x509_certificate(cert_pem.encode())

        # Prepare certificate details
        cert_details = {
            'issuer_details': [{'name': attr.oid._name, 'value': attr.value} for attr in cert.issuer],
            'subject_details': [{'name': attr.oid._name, 'value': attr.value} for attr in cert.subject],
            'valid_from': cert.not_valid_before,
            'valid_to': cert.not_valid_after,
            'serial_number': cert.serial_number,
            'signature_algorithm': cert.signature_algorithm_oid._name,
            'sha256_fingerprint': cert.fingerprint(hashes.SHA256()).hex(),
            'sha1_fingerprint': cert.fingerprint(hashes.SHA1()).hex()
        }

        # Check certificate validity
        now = datetime.utcnow()
        if now < cert.not_valid_before:
            cert_details['validity_status'] = 'not_yet_valid'
        elif now > cert.not_valid_after:
            cert_details['validity_status'] = 'expired'
        else:
            cert_details['validity_status'] = 'valid'

        # Public Key Information
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            cert_details['public_key_type'] = 'RSA'
            cert_details['public_key_size'] = public_key.key_size

        return jsonify({
            'status': 'success', 
            'certificate_details': cert_details
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    app.run(debug=True)