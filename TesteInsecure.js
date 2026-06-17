const express = require('express');
const app = express();
const port = 3000;

// Middleware para processar JSON
app.use(express.json());

app.post('/calcular', (req, res) => {
    // FONTE: O usuário envia a expressão no corpo da requisição
    // Exemplo esperado: { "expressao": "2 + 2 * 5" }
    const expressao = req.body.expressao;

    if (!expressao) {
        return res.status(400).send("Por favor, forneça uma 'expressao'.");
    }

    try {
        // VULNERABILIDADE CRÍTICA (DESTINO PERIGOSO):
        // A função eval() executa qualquer string como código JavaScript válido.
        // O OpenGrep vai gerar um alerta imediato de injeção de código aqui.
        const resultado = eval(expressao);

        return res.json({ 
            mensagem: "Cálculo realizado com sucesso!",
            resultado: resultado 
        });
        
    } catch (erro) {
        return res.status(500).send("Erro ao processar a expressão.");
    }
});

app.listen(port, () => {
    console.log(`Servidor vulnerável rodando na porta ${port}`);
});