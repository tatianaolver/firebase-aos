admin.initializeApp({
    credential: admin.credential.cert(credentials)
});

const SECRET =

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/', (req, res) => {
    res.json({ info: 'Atividade de autenticação com Firebase. Rotas - /cadastro, /login' });
});

function authenticateAdmin(req, res, next) {
    const token = req.header('x-auth-token');
    if (!token) {
        return res.status(401).json({ message: 'Acesso não autorizado. Token não fornecido.' });
    }

    try {
        const decoded = jwt.verify(token, SECRET);
        if (decoded.isAdmin) {
            req.user = decoded;
            next();
        } else {
            return res.status(403).json({ message: 'Acesso não autorizado. Você não é um administrador.' });
        }
    } catch (error) {
        return res.status(401).json({ message: 'Token inválido ou expirado.' });
    }
}

app.post('/cadastro', async (req, res) => {
    try {
        const { email, password } = req.body;


        const userRecord = await admin.auth().createUser({
            email,
            password,
        });


        const token = jwt.sign({ uid: userRecord.uid, isAdmin: false }, SECRET, {
            expiresIn: '2h', // O Token deve expirar em 2 horas
        });

        res.status(200).json({
            statusCode: 200,
            message: 'Usuário criado com sucesso!',
            data: {
                uid: userRecord.uid,
                token: token,
            },
        });
    } catch (error) {
        console.error('Erro ao criar usuário:', error);
        res.status(500).json({
            statusCode: 500,
            message: 'Erro ao criar usuário.',
        });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Autenticando usuário no Firebase
        const user = await admin.auth().getUserByEmail(email);

        // Gerar um token JWT com o UID do usuário
        const token = jwt.sign({ uid: user.uid, isAdmin: false }, SECRET, {
            expiresIn: '2h', // O Token deve expirar em 2 horas
        });

        res.status(200).json({
            statusCode: 200,
            message: 'Login realizado com sucesso!',
            data: {
                token,
            },
        });
    } catch (error) {
        console.error('Erro ao fazer login:', error);
        res.status(401).json({
            statusCode: 401,
            message: 'Não autorizado! Usuário não encontrado ou senha incorreta.',
        });
    }
});

app.get('/admin', authenticateAdmin, (req, res) => {
    res.json({ message: 'Você é um administrador logado.' });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Server is running on PORT ${PORT}.`);
});
