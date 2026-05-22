from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/')
def index():
    return "Servidor de teste SSRF rodando. Acesse /fetch?url=<seu_url>"

@app.route('/fetch', methods=['GET'])
def fetch_url():
    # O aplicativo pega a URL fornecida pelo usuário na query string
    url = request.args.get('url')
    
    if not url:
        return "Por favor, forneça um parâmetro 'url'. Exemplo: /fetch?url=http://example.com", 400

    try:
        # VULNERABILIDADE SSRF: 
        # O servidor faz o download do conteúdo da URL sem NENHUMA validação ou filtro.
        # Um atacante pode forçar o servidor a acessar a rede interna ou localhost.
        resposta = requests.get(url, timeout=5)
        
        # Retorna o conteúdo da página acessada para o usuário
        return resposta.text, resposta.status_code
        
    except requests.exceptions.RequestException as e:
        return f"Erro ao acessar a URL: {e}", 500

if __name__ == '__main__':
    # Roda em localhost na porta 5000
    app.run(host='127.0.0.1', port=5000)