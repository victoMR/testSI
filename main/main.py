import streamlit as st
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

class SeguridadApp:
    def __init__(self):
        # Configure page settings
        st.set_page_config(page_title="Portafolio de Seguridad", page_icon="🔒")
        st.title("🔒 Portafolio de Seguridad Informática")

        # Initialize session state
        self._initialize_session_state()

    def _initialize_session_state(self):
        """Initialize or reset session state variables"""
        # Symmetric encryption key
        if 'clave_simetrica' not in st.session_state:
            st.session_state.clave_simetrica = Fernet.generate_key()

        # RSA key pair
        if 'rsa_key_pair' not in st.session_state:
            self._generar_par_claves_rsa()

    def _generar_par_claves_rsa(self):
        """Generate a new RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        st.session_state.rsa_key_pair = {
            'private': private_key,
            'public': private_key.public_key()
        }

    def cifrado_simetrico(self):
        st.subheader("🔑 Cifrado Simétrico con AES")

        col1, col2 = st.columns(2)

        with col1:
            st.write("### Cifrar")
            mensaje_cifrar = st.text_area("Mensaje a Cifrar", key="cifrar_simetrico")

            if st.button("Cifrar", key="btn_cifrar_simetrico"):
                if mensaje_cifrar:
                    try:
                        f = Fernet(st.session_state.clave_simetrica)
                        mensaje_cifrado = f.encrypt(mensaje_cifrar.encode())
                        st.session_state.ultimo_mensaje_cifrado = mensaje_cifrado
                        st.success("Mensaje Cifrado")
                        st.code(base64.b64encode(mensaje_cifrado).decode())
                    except Exception as e:
                        st.error(f"Error al cifrar: {str(e)}")

        with col2:
            st.write("### Descifrar")
            mensaje_descifrar = st.text_area("Mensaje a Descifrar (Base64)", key="descifrar_simetrico")

            if st.button("Descifrar", key="btn_descifrar_simetrico"):
                if mensaje_descifrar:
                    try:
                        f = Fernet(st.session_state.clave_simetrica)
                        # Decodificar el mensaje base64 antes de descifrar
                        mensaje_bytes = base64.b64decode(mensaje_descifrar)
                        mensaje_descifrado = f.decrypt(mensaje_bytes)
                        st.success("Mensaje Descifrado")
                        st.code(mensaje_descifrado.decode())
                    except Exception as e:
                        st.error(f"Error al descifrar: {str(e)}")

        st.write("### Clave Simétrica (Base64)")
        st.code(base64.b64encode(st.session_state.clave_simetrica).decode())

        if st.button("Regenerar Clave Simétrica", key="btn_regenerar_simetrica"):
            # Reset symmetric key and force page rerun
            st.session_state.clave_simetrica = Fernet.generate_key()
            st.rerun()

    def cifrado_asimetrico(self):
        st.subheader("🔐 Cifrado Asimétrico con RSA")

        col1, col2 = st.columns(2)

        with col1:
            st.write("### Cifrar")
            mensaje_cifrar = st.text_area("Mensaje a Cifrar", key="cifrar_asimetrico", max_chars=200)

            if st.button("Cifrar con Clave Pública", key="btn_cifrar_asimetrico"):
                if mensaje_cifrar:
                    try:
                        # Usar OAEP padding para mayor seguridad
                        mensaje_bytes = mensaje_cifrar.encode()
                        mensaje_cifrado = st.session_state.rsa_key_pair['public'].encrypt(
                            mensaje_bytes,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        st.success("Mensaje Cifrado")
                        st.code(base64.b64encode(mensaje_cifrado).decode())
                    except ValueError as e:
                        # Mensaje demasiado largo para cifrar con RSA
                        st.error(f"Error de cifrado: {str(e)}. Intente con un mensaje más corto.")
                    except Exception as e:
                        st.error(f"Error al cifrar: {str(e)}")

        with col2:
            st.write("### Descifrar")
            mensaje_descifrar = st.text_area("Mensaje a Descifrar (Base64)", key="descifrar_asimetrico")

            if st.button("Descifrar con Clave Privada", key="btn_descifrar_asimetrico"):
                if mensaje_descifrar:
                    try:
                        # Usar el mismo OAEP padding para descifrar
                        mensaje_descifrado = st.session_state.rsa_key_pair['private'].decrypt(
                            base64.b64decode(mensaje_descifrar),
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        st.success("Mensaje Descifrado")
                        st.code(mensaje_descifrado.decode())
                    except ValueError as e:
                        st.error(f"Error de descifrado: {str(e)}")
                    except Exception as e:
                        st.error(f"Error al descifrar: {str(e)}")

        # Sección de información de claves
        st.write("### Información de Claves RSA")

        # Display RSA Public Key
        st.write("#### Clave Pública RSA (Base64)")
        public_key_pem = st.session_state.rsa_key_pair['public'].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        st.code(public_key_pem.decode())

        # Display RSA Private Key


        # Regenerate RSA Key Pair Button
        if st.button("Regenerar Par de Claves RSA", key="btn_regenerar_rsa"):
            # Reset RSA key pair and force page rerun
            self._generar_par_claves_rsa()
            st.rerun()

    def funciones_hash(self):
        st.subheader("🔬 Funciones Hash")

        algoritmos = {
            "SHA-256": hashlib.sha256,
            "MD5": hashlib.md5,
            "SHA-1": hashlib.sha1
        }

        # Create two-column layout
        col1, col2 = st.columns(2)

        with col1:
            st.write("### Calcular Hash")
            texto = st.text_input("Texto para calcular Hash", key="hash_calcular")
            algoritmo = st.selectbox("Selecciona Algoritmo", list(algoritmos.keys()), key="hash_algoritmo")

            if st.button("Calcular Hash", key="btn_calcular_hash"):
                if texto:
                    hash_obj = algoritmos[algoritmo]()
                    hash_obj.update(texto.encode())
                    hash_value = hash_obj.hexdigest()

                    st.success(f"Hash {algoritmo}")
                    st.code(hash_value)
                else:
                    st.warning("Introduce un texto")

        with col2:
            st.write("### Verificar Hash")
            texto_verificar = st.text_input("Texto a Verificar", key="hash_verificar")
            hash_conocido = st.text_input("Hash Conocido", key="hash_conocido")
            algoritmo_verificar = st.selectbox(
                "Selecciona Algoritmo",
                list(algoritmos.keys()),
                key="hash_verificar_algoritmo",
                index=0  # Default to SHA-256
            )

            if st.button("Verificar Hash", key="btn_verificar_hash"):
                if texto_verificar and hash_conocido:
                    hash_obj = algoritmos[algoritmo_verificar]()
                    hash_obj.update(texto_verificar.encode())
                    hash_calculado = hash_obj.hexdigest()

                    if hash_calculado == hash_conocido:
                        st.success("✅ Hash coincide. El texto es correcto.")
                    else:
                        st.error("❌ Hash no coincide. El texto es diferente.")
                else:
                    st.warning("Introduce texto y hash para verificar")

        # Explanation section
        st.markdown("### 🔍 Entendiendo Funciones Hash")

        st.markdown("""
        **¿Qué son las Funciones Hash?**
        - Son funciones matemáticas unidireccionales
        - Transforman datos de cualquier tamaño en una cadena de longitud fija
        - No se pueden *descifrar*, solo verificar

        **Características Clave:**
        - Determinísticas: Mismo input siempre genera mismo hash
        - Resistentes a colisiones: Difícil encontrar dos inputs diferentes con el mismo hash
        - Unidireccionales: No se puede reconstruir el input original
        """)

    def certificados_ssl(self):
        st.subheader("🌐 Generación de Certificados SSL")

        # Crear pestañas
        tab1, tab2 = st.tabs(["Generación de Certificados", "Verificador de Certificados"])

        with tab1:
            # Campos editables para el certificado
            col1, col2 = st.columns(2)

            with col1:
                pais = st.text_input("País", value="MX", key="ssl_pais")
                estado = st.text_input("Estado", value="Querétaro", key="ssl_estado")
                localidad = st.text_input("Localidad", value="Ciudad", key="ssl_localidad")

            with col2:
                organizacion = st.text_input("Organización", value="Mi Organización", key="ssl_org")
                dominio = st.text_input("Dominio", value="localhost", key="ssl_dominio")
                dias_validez = st.number_input("Días de Validez", min_value=1, max_value=365, value=365, key="ssl_dias")

            if st.button("Generar Nuevo Certificado", key="btn_generar_cert"):
                # Generar clave privada
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )

                # Generar certificado autofirmado
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

                # Mostrar detalles del certificado
                st.write("### Detalles del Certificado")

                # Información del certificado
                info_cert = {
                    "Emisor": cert.issuer.rfc4514_string(),
                    "Sujeto": cert.subject.rfc4514_string(),
                    "Válido Desde": cert.not_valid_before_utc,
                    "Válido Hasta": cert.not_valid_after_utc,
                    "Número de Serie": cert.serial_number
                }

                for key, value in info_cert.items():
                    st.text(f"{key}: {value}")

                # Visualizar certificado PEM
                st.write("### Certificado en Formato PEM")
                pem_cert = cert.public_bytes(serialization.Encoding.PEM)
                st.code(pem_cert.decode())

                # Descargar certificado
                cert_name = f"{dominio}_cert.pem"
                cert_b64 = base64.b64encode(pem_cert).decode()
                href = f'<a href="data:file/txt;base64,{cert_b64}" download="{cert_name}">Descargar Certificado</a>'
                st.markdown(href, unsafe_allow_html=True)

                # Descargar clave privada
                private_key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
                key_name = f"{dominio}_key.pem"
                key_b64 = base64.b64encode(private_key_pem).decode()

                href = f'<a href="data:file/txt;base64,{key_b64}" download="{key_name}">Descargar Clave Privada</a>'
                st.markdown(href, unsafe_allow_html=True)

        with tab2:
            # Verificador de Certificado en una pestaña separada
            cert_pem = st.text_area("Pega el contenido del Certificado PEM", height=300,
                                    help="Incluye el certificado completo, incluyendo -----BEGIN CERTIFICATE----- y -----END CERTIFICATE-----")

            if st.button("Verificar Certificado", key="verificar_cert_pem_tab"):
                if not cert_pem:
                    st.warning("Por favor, ingrese un certificado PEM")
                    return

                try:
                    # Load the certificate
                    cert = x509.load_pem_x509_certificate(cert_pem.encode())

                    # Create columns for better layout
                    col1, col2 = st.columns(2)

                    with col1:
                        st.write("### Información del Certificado")
                        st.write(f"**Emisor:**")
                        for attr in cert.issuer:
                            st.text(f"{attr.oid._name}: {attr.value}")

                        st.write("\n**Sujeto:**")
                        for attr in cert.subject:
                            st.text(f"{attr.oid._name}: {attr.value}")

                    with col2:
                        st.write("### Detalles de Validez")
                        st.write(f"**Válido Desde:** {cert.not_valid_before}")
                        st.write(f"**Válido Hasta:** {cert.not_valid_after}")

                        # Check certificate validity
                        now = datetime.utcnow()
                        if now < cert.not_valid_before:
                            st.warning("⚠️ Certificado aún no es válido")
                        elif now > cert.not_valid_after:
                            st.error("❌ Certificado ha expirado")
                        else:
                            st.success("✅ Certificado válido")

                        st.write(f"**Número de Serie:** {cert.serial_number}")

                    # Additional Technical Details
                    st.write("### Detalles Técnicos")
                    st.write(f"**Algoritmo de Firma:** {cert.signature_algorithm_oid._name}")

                    # Public Key Information
                    public_key = cert.public_key()
                    if isinstance(public_key, rsa.RSAPublicKey):
                        st.write(f"**Tipo de Clave Pública:** RSA")
                        st.write(f"**Tamaño de Clave:** {public_key.key_size} bits")

                    # Optional: Fingerprints
                    st.write("### Huellas Digitales")
                    st.write(f"**SHA-256 Fingerprint:** {cert.fingerprint(hashes.SHA256()).hex()}")
                    st.write(f"**SHA-1 Fingerprint:** {cert.fingerprint(hashes.SHA1()).hex()}")

                except ValueError as e:
                    st.error(f"Error al decodificar el certificado: {str(e)}")
                except Exception as e:
                    st.error(f"Error al procesar el certificado: {str(e)}")

    def verificador_certificado(self):
        st.subheader("🔍 Verificador de Certificados SSL")

        # Input for PEM certificate
        cert_pem = st.text_area("Pega el contenido del Certificado PEM", height=300,
                                help="Incluye el certificado completo, incluyendo -----BEGIN CERTIFICATE----- y -----END CERTIFICATE-----")

        if st.button("Verificar Certificado", key="verificar_cert_pem"):
            if not cert_pem:
                st.warning("Por favor, ingrese un certificado PEM")
                return

            try:
                # Load the certificate
                cert = x509.load_pem_x509_certificate(cert_pem.encode())

                # Create columns for better layout
                col1, col2 = st.columns(2)

                with col1:
                    st.write("### Información del Certificado")
                    st.write(f"**Emisor:**")
                    for attr in cert.issuer:
                        st.text(f"{attr.oid._name}: {attr.value}")

                    st.write("\n**Sujeto:**")
                    for attr in cert.subject:
                        st.text(f"{attr.oid._name}: {attr.value}")

                with col2:
                    st.write("### Detalles de Validez")
                    st.write(f"**Válido Desde:** {cert.not_valid_before}")
                    st.write(f"**Válido Hasta:** {cert.not_valid_after}")

                    # Check certificate validity
                    now = datetime.utcnow()
                    if now < cert.not_valid_before:
                        st.warning("⚠️ Certificado aún no es válido")
                    elif now > cert.not_valid_after:
                        st.error("❌ Certificado ha expirado")
                    else:
                        st.success("✅ Certificado válido")

                    st.write(f"**Número de Serie:** {cert.serial_number}")

                # Additional Technical Details
                st.write("### Detalles Técnicos")
                st.write(f"**Algoritmo de Firma:** {cert.signature_algorithm_oid._name}")

                # Public Key Information
                public_key = cert.public_key()
                if isinstance(public_key, rsa.RSAPublicKey):
                    st.write(f"**Tipo de Clave Pública:** RSA")
                    st.write(f"**Tamaño de Clave:** {public_key.key_size} bits")

                # Optional: Fingerprints
                st.write("### Huellas Digitales")
                st.write(f"**SHA-256 Fingerprint:** {cert.fingerprint(hashes.SHA256()).hex()}")
                st.write(f"**SHA-1 Fingerprint:** {cert.fingerprint(hashes.SHA1()).hex()}")

            except ValueError as e:
                st.error(f"Error al decodificar el certificado: {str(e)}")
            except Exception as e:
                st.error(f"Error al procesar el certificado: {str(e)}")

    def run(self):
        menu = st.sidebar.radio("Selecciona un Módulo", [
            "Inicio",
            "Cifrado Simétrico",
            "Cifrado Asimétrico",
            "Funciones Hash",
            "Certificados SSL"
        ])

        if menu == "Inicio":
            st.write("# Bienvenido al Portafolio de Seguridad")
            st.write("Explora diferentes técnicas de seguridad informática")

        elif menu == "Cifrado Simétrico":
            self.cifrado_simetrico()

        elif menu == "Cifrado Asimétrico":
            self.cifrado_asimetrico()

        elif menu == "Funciones Hash":
            self.funciones_hash()

        elif menu == "Certificados SSL":
            self.certificados_ssl()

def main():
    app = SeguridadApp()
    app.run()


if __name__ == "__main__":
    main()