import hmac
import hashlib
import base64
import json

def generate_hmac(data, secret):
    """
    Gera a assinatura HMAC SHA-256 com base nos dados e na chave secreta.
    
    :param data: Dados a serem assinados (como JSON ou string).
    :param secret: Chave secreta usada para gerar o HMAC.
    :return: Assinatura HMAC em base64.
    """
    # Converter os dados para string JSON (se não for já uma string)
    if isinstance(data, dict):
        data = json.dumps(data, separators=(',', ':'))

    # Gerar o HMAC SHA-256
    hmac_object = hmac.new(secret.encode(), data.encode(), hashlib.sha256)
    return base64.b64encode(hmac_object.digest()).decode()

# Exemplo de uso
if __name__ == "__main__":
    # Dados do webhook (exemplo)
    data = {
        "evento": "pedido_criado",
        "dados": {
            "id": 12345,
            "status": "processando"
        }
    }

    # Chave secreta da API
    secret = "5173763ae2c4286107e02bfd22df1bb1a9c19898092eddf3"  # Substitua com sua chave secreta

    # Gerar assinatura HMAC
    hmac_signature = generate_hmac(data, secret)
    
    print("Assinatura HMAC gerada:", hmac_signature)
