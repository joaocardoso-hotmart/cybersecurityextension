import express, { Request, Response } from 'express';
import mongoose from 'mongoose';

const app = express();
const port = 3000;

// Middleware para processar corpos de requisição em JSON
app.use(express.json());

// Definindo um modelo simples de Usuário
const User = mongoose.model('User', new mongoose.Schema({
    username: String,
    secretToken: String
}));

app.post('/recuperar-token', async (req: Request, res: Response) => {
    // FONTE: Dado vindo do usuário via corpo da requisição
    const { username } = req.body;

    if (!username) {
        return res.status(400).send("Por favor, forneça o username.");
    }

    try {
        // VULNERABILIDADE: O dado (username) é passado diretamente para a query.
        // Como app.use(express.json()) transforma a entrada em objetos JavaScript,
        // o usuário pode enviar um operador do MongoDB em vez de uma string simples.
        const user = await User.findOne({ username: username });

        if (user) {
            // DESTINO PERIGOSO: Retorna um dado sensível baseado em uma query manipulada
            return res.json({ token: user.secretToken });
        }
        
        return res.status(404).send("Usuário não encontrado.");
        
    } catch (error) {
        return res.status(500).send("Erro interno no servidor.");
    }
});

app.listen(port, () => {
    console.log(`Servidor rodando na porta ${port}`);
});