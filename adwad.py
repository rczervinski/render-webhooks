import hmac
from hashlib import sha256
import base64
import json

def generate_hmac(payload_dict, secret):
    """
    Gera o HMAC-SHA256 com base no payload e no APP_SECRET
    """
    payload_str = json.dumps(payload_dict, separators=(',', ':'), ensure_ascii=False)
    signature = hmac.new(secret.encode('utf-8'), payload_str.encode('utf-8'), sha256)
    return base64.b64encode(signature.digest()).decode('utf-8')


def main():
    print("=== Gerador de HMAC para Webhooks da Nuvemshop ===\n")

    # Seu APP_SECRET (substitua pelo seu segredo real)
    APP_SECRET = input("Digite seu APP_SECRET: ").strip()

    if not APP_SECRET:
        print("❌ APP_SECRET não pode ser vazio.")
        return

    print("\nDigite o payload do webhook (exemplo abaixo):")
    print('''Exemplo:
{
  "store_id": 123,
  "event": "product/created",
  "id": 9876
}''')

    try:
        payload_input = input("\nCole o payload JSON aqui:\n")
        payload = json.loads(payload_input)
    except json.JSONDecodeError as e:
        print(f"❌ Erro ao decodificar o JSON: {e}")
        return

    hmac_value = generate_hmac(payload, APP_SECRET)

    print("\n✅ HMAC gerado (use no cabeçalho x-linkedstore-hmac-sha256):\n")
    print(hmac_value)

    print("\n✅ Payload formatado (para enviar no corpo da requisição):\n")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()