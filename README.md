# ⬡ TrackLab v2.0
### Plataforma Educacional de Análise Web

Sistema completo com backend Python/Flask, banco SQLite, API REST e frontend avançado.

---

## 🚀 Instalação Rápida

```bash
# 1. Instalar dependências
pip install -r requirements.txt

# 2. Iniciar o servidor
python backend/app.py

# 3. Acessar no navegador
http://localhost:5000

# Login padrão
# Usuário: admin
# Senha:   admin123
```

---

## 🗂 Estrutura do Projeto

```
tracklab/
├── backend/
│   ├── app.py            → Flask app + todas as rotas
│   └── database.py       → Schema SQLite + helpers
├── frontend/
│   └── templates/
│       ├── base.html     → Layout base (sidebar + topbar)
│       ├── index.html    → Landing page pública
│       ├── login.html    → Página de login
│       ├── capture.html  → Página de captura (pública)
│       ├── dashboard.html→ Painel com gráficos
│       ├── sessions.html → Lista de sessões
│       ├── photos.html   → Galeria de fotos
│       └── links.html    → Gerenciamento de links
├── database/
│   └── tracklab.db       → SQLite (criado automaticamente)
└── requirements.txt
```

---

## 🗄 Banco de Dados (7 tabelas)

| Tabela | Descrição |
|--------|-----------|
| `sessions` | Dados completos de cada sessão (30+ campos) |
| `photos` | Fotos capturadas (base64, tamanho) |
| `tracked_links` | Links rastreáveis com contadores |
| `link_hits` | Histórico de cada acesso por link |
| `users` | Usuários do sistema (admin/viewer) |
| `api_keys` | Chaves de API revogáveis |
| `alerts` | Notificações do sistema em tempo real |

---

## 🔌 API REST Completa

### Autenticação
```
POST /api/auth/login      → Login (retorna sessão)
GET  /api/auth/me         → Usuário atual
GET  /logout              → Encerrar sessão
```

### Sessões
```
POST /api/session         → Salvar nova sessão (público)
GET  /api/sessions        → Listar (paginado, busca)
GET  /api/sessions/:id    → Detalhes de uma sessão
DEL  /api/sessions/:id    → Deletar sessão
GET  /api/export/sessions → Exportar CSV
```

### Fotos
```
GET  /api/photos          → Listar fotos (paginado)
GET  /api/photos/:id      → Foto completa (base64)
DEL  /api/photos/:id      → Deletar foto
```

### Links
```
GET  /api/links           → Listar links
POST /api/links           → Criar link
DEL  /api/links/:id       → Deletar link
GET  /api/links/:id/hits  → Histórico de acessos
GET  /t/:id               → Redirect rastreado
```

### Sistema
```
GET  /api/stats           → Estatísticas gerais
GET  /api/alerts          → Alertas (lidos/não lidos)
POST /api/alerts/read     → Marcar todos como lidos
GET  /api/stream          → SSE stream (tempo real)
GET  /api/keys            → Listar API keys
POST /api/keys            → Criar API key
DEL  /api/keys/:id        → Revogar API key
```

---

## 📡 Dados Coletados pela Página de Captura

### Navegador & Sistema
- User-Agent completo + parser (browser, versão, OS, dispositivo)
- Idioma e lista de idiomas
- Plataforma (`navigator.platform`)
- Cookies habilitados
- Do Not Track
- Status online/offline

### Hardware
- Resolução de tela + profundidade de cor + pixel ratio
- Viewport (largura × altura)
- CPU cores (`navigator.hardwareConcurrency`)
- RAM disponível (`navigator.deviceMemory`)
- Pontos de toque (`navigator.maxTouchPoints`)

### Bateria (Battery API)
- Nível de carga (0–100%)
- Status de carregamento

### Rede (Network Info API)
- Tipo efetivo (4g, 3g, wifi...)
- Velocidade de download
- RTT (latência)

### Fingerprinting
- Canvas fingerprint (hash único)
- WebGL renderer (GPU info)
- Fontes instaladas detectadas
- Plugins do navegador
- Audio context sample rate
- Timezone offset

### Geolocalização (com permissão)
- Latitude / Longitude
- Precisão em metros

### Câmera (com permissão explícita)
- Captura de foto em JPEG
- Stored as base64

---

## 🔒 Segurança

- Senhas com hash SHA-256
- Sessão Flask com chave secreta aleatória
- Todas as rotas `/api/*` e `/admin/*` protegidas
- API Keys com hash armazenado (nunca o texto puro)
- Consentimento explícito na página de captura

---

## 🌐 Próximos Passos (Evolução)

- [ ] Registrar IP real via nginx/proxy (X-Forwarded-For)
- [ ] Integrar ipinfo.io para enriquecer dados de IP (país, cidade, ISP)
- [ ] Deploy com Gunicorn + nginx
- [ ] WebSockets (Socket.IO) para notificações push
- [ ] Geração de relatórios PDF
- [ ] Autenticação JWT para a API
- [ ] Rate limiting por IP
- [ ] Exportar fotos em ZIP
- [ ] Mapa de calor geográfico com Leaflet.js

---

## ⚖️ Uso Ético

Esta ferramenta existe para **fins educacionais**. Ao usar:
- Sempre informe os usuários que dados são coletados
- Obtenha consentimento explícito para câmera e localização
- Não use para espionar pessoas sem conhecimento
- Respeite a LGPD (Lei Geral de Proteção de Dados)
