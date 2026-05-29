import pickle
import base64
from flask import Flask, request

app = Flask(__name__)

@app.route('/carregar_perfil', methods=['POST'])
def carregar_perfil():
    # FONTE: Dado vindo do usuário via corpo da requisição (não confiável)
    dados_base64 = request.form.get('dados_perfil')
    
    if not dados_base64:
        return "Nenhum dado de perfil fornecido.", 400

    try:
        # Decodifica a string Base64 de volta para bytes
        dados_serializados = base64.b64decode(dados_base64)
        
        # VULNERABILIDADE / DESTINO PERIGOSO: 
        # O OpenGrep vai disparar um alerta crítico aqui.
        # pickle.loads() nunca deve ser usado com dados que podem ter sido alterados pelo usuário.
        perfil = pickle.loads(dados_serializados)
        
        return f"Bem-vindo de volta, {perfil.get('nome', 'Usuário')}!"
        
    except Exception as e:
        # Retornar o erro exato não é uma boa prática, mas comum em códigos vulneráveis
        return f"Erro ao processar o perfil: {str(e)}", 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)