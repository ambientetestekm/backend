const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcryptjs");

const app = express();
const port = 3000;

app.use(cors());
app.use(bodyParser.json());

// Conexão com o banco
const db = new sqlite3.Database("./AppCafeKM.db", (err) => {
  if (err) {
    console.error("Erro ao conectar no banco:", err.message);
  } else {
    console.log("Conectado ao banco AppCafeKM");
  }
});

// Rota de login
app.post("/login", (req, res) => {
  const login = req.body.login?.trim().toLowerCase();
  const senha = req.body.senha?.trim();
  const now = new Date();
  const today = now.toISOString().split("T")[0];

  const query = `SELECT * FROM usuario WHERE LOWER(login) = LOWER(?)`;

  db.get(query, [login], async (err, row) => {
    if (err) return res.status(500).json({ error: err.message });

    if (!row) return res.status(401).json({ message: "Credenciais inválidas" });

    const senhaCorreta = await bcrypt.compare(senha, row.senha);
    if (!senhaCorreta) return res.status(401).json({ message: "Credenciais inválidas" });

    const userId = row.idUsuario;
    const tipoUsuario = row.idTipoUsuario;

    // Se for ADMIN (tipo === 1), pula tudo e retorna
    if (tipoUsuario === 1) {
      return res.json({
        message: "Login realizado com sucesso!",
        user: {
          idUsuario: row.idUsuario,
          nome: row.nome,
          login: row.login,
          idTipoUsuario: row.idTipoUsuario,
        },
      });
    }

    // Restrição de horário (07:30 a 08:20)
    const allowedStartTime = new Date();
    allowedStartTime.setHours(7, 30, 0, 0);
    const allowedEndTime = new Date();
    allowedEndTime.setHours(18, 20, 0, 0); // ajustado corretamente

    if (now < allowedStartTime || now > allowedEndTime) {
      return res.status(403).json({
        message: "TCHUCO ERRO \n OPS! INFELIZMENTE VOCÊ NÃO \nCHEGOU A TEMPO.",
      });
    }

    // Verifica se já fez login hoje
   db.get(
  `SELECT * FROM login_records WHERE nome = ? AND data = ? AND hora BETWEEN '07:30:00' AND '08:20:00'`,
  [row.nome, now.toLocaleDateString("pt-BR")],
  (err, loginRecord) => {
    if (err) return res.status(500).json({ error: err.message });

    if (loginRecord) {
      return res.status(409).json({
        message: "Você já efetuou o login dentro do horário permitido hoje.",
      });
    }

    // Registra login normalmente
    const hora = now.toLocaleTimeString("pt-BR");
    const data = now.toLocaleDateString("pt-BR");

    db.run(
      `INSERT INTO login_records (nome, data, hora) VALUES (?, ?, ?)`,
      [row.nome, data, hora],
      (err) => {
        if (err) {
          console.error("Erro ao registrar login:", err.message);
          return res.status(500).json({ error: "Erro ao registrar login." });
        }

        res.json({
          message: "Login realizado com sucesso!",
          user: {
            idUsuario: row.idUsuario,
            nome: row.nome,
            login: row.login,
            idTipoUsuario: row.idTipoUsuario,
          },
        });
      }
    );
  }
);

  });
});

// Rota para listar todos os produtos
app.get("/produto", (req, res) => {
  const query = "SELECT idProduto AS id, descricao AS nome FROM produto";

  db.all(query, [], (err, rows) => {
    if (err) {
      console.error("Erro ao buscar produtos:", err.message);
      return res.status(500).json({ error: "Erro ao buscar produtos" });
    }

    res.json(rows);
  });
});

// Rota de cadastro de novo usuário com senha criptografada
app.post("/cadastro", async (req, res) => {
  const { nome, login, senha } = req.body;

  if (!nome || !login || !senha) {
    return res.status(400).json({ message: "Nome, login e senha são obrigatórios." });
  }

  db.get("SELECT * FROM usuario WHERE LOWER(login) = LOWER(?)", [login.trim()], async (err, row) => {
    if (err) {
      return res.status(500).json({ message: "Erro ao acessar o banco de dados." });
    }

    if (row) {
      return res.status(409).json({ message: "Usuário já cadastrado." });
    }

    const hashedPassword = await bcrypt.hash(senha.trim(), 10);

    db.run(
      "INSERT INTO usuario (nome, login, senha) VALUES (?, ?, ?)",
      [nome.trim(), login.trim(), hashedPassword],
      function (err) {
        if (err) {
          return res.status(500).json({ message: "Erro ao cadastrar usuário." });
        }

        res.status(201).json({
          message: "Usuário cadastrado com sucesso!",
          idUsuario: this.lastID,
        });
      }
    );
  });
});

// 🔍 Rota de relatório de login (SEM o campo id)
app.get("/api/login-report", (req, res) => {
  const query = `SELECT nome, data, hora FROM login_records ORDER BY data DESC, hora DESC`;

  db.all(query, [], (err, rows) => {
    if (err) {
      console.error("Erro ao buscar registros:", err.message);
      return res.status(500).json({ error: "Erro ao buscar registros" });
    }

    res.json(rows);
  });
});

// Inicializa o servidor
app.listen(port, () => {
  console.log(`Servidor rodando em http://192.168.100.126:${port}`);
});
