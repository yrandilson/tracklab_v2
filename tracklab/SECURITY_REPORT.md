# Relatorio de Vulnerabilidades - TrackLab v2

Data base: 2026-04-04
Escopo: backend Flask, templates frontend e fluxo de coleta/captura
Status: em atualizacao continua

## Legenda
- Criticidade: Critica | Alta | Media | Baixa
- Estado: Aberta | Mitigada | Parcial

## Vulnerabilidades e riscos

### VULN-001 - Falta de controle de autorizacao por papel
- Criticidade: Alta
- Estado: Mitigada
- Onde: backend/app.py
- Descricao: rotas administrativas eram protegidas apenas por login, sem verificar papel do usuario.
- Risco: usuarios autenticados nao-admin poderiam acessar dados sensiveis e operacoes administrativas.
- Mitigacao aplicada:
  - criado decorator `admin_required`
  - aplicado nas rotas de dashboard, paginas /admin/* e APIs administrativas

### VULN-002 - Vazamento de conexao SQLite no fluxo de link de referencia
- Criticidade: Media
- Estado: Mitigada
- Onde: backend/app.py
- Descricao: a conexao aberta para contabilizar refLinkId podia ficar sem close quando o link nao existia.
- Risco: consumo gradual de recursos e degradacao sob carga.
- Mitigacao aplicada: bloco com `try/finally` para fechamento garantido.

### VULN-003 - Endpoint de miniatura inexistente e hack no frontend
- Criticidade: Media
- Estado: Mitigada
- Onde: backend/app.py e frontend/templates/photos.html
- Descricao: frontend tentava carregar `/api/photos/<id>/thumb` sem rota correspondente e mantinha hack de `window.fetch` que nao resolve imagens em `<img src=...>`.
- Risco: imagens quebradas, comportamento inconsistente e complexidade tecnica desnecessaria.
- Mitigacao aplicada:
  - criado endpoint real `/api/photos/<int:pid>/thumb`
  - removido hack de interceptacao no frontend

### VULN-004 - Hash de senha fraco (SHA-256 sem salt)
- Criticidade: Alta
- Estado: Aberta
- Onde: backend/database.py
- Descricao: senhas com hash rapido, inadequado para armazenamento de credenciais.
- Risco: brute force/offline cracking facilitado.
- Recomendacao: migrar para Argon2id ou bcrypt com custo configuravel e sal por senha.

### VULN-005 - Credencial padrao previsivel
- Criticidade: Alta
- Estado: Aberta
- Onde: backend/database.py
- Descricao: usuario admin padrao com senha conhecida em inicializacao.
- Risco: comprometimento imediato em ambiente exposto.
- Recomendacao: exigir definicao de senha inicial via ambiente/provisionamento.

### VULN-006 - Configuracao insegura para producao (debug e secret key volatil)
- Criticidade: Alta
- Estado: Aberta
- Onde: backend/app.py
- Descricao: `debug=True` e secret key gerada a cada boot.
- Risco: exposicao de informacoes em erro e invalidacao de sessoes entre reinicios.
- Recomendacao: usar variaveis de ambiente (`FLASK_DEBUG=0`, `SECRET_KEY` fixa por ambiente).

### VULN-007 - Superficie de XSS no frontend administrativo
- Criticidade: Alta
- Estado: Aberta
- Onde: templates com uso extensivo de `innerHTML`
- Descricao: dados potencialmente manipulaveis (ex.: user-agent) sao inseridos sem sanitizacao em pontos do admin.
- Risco: execucao de script no contexto do painel.
- Recomendacao: substituir por `textContent`/DOM seguro e/ou sanitizar com DOMPurify + CSP.

### VULN-008 - Ausencia de limitacao de taxa e protecao CSRF
- Criticidade: Media
- Estado: Aberta
- Onde: backend/app.py
- Descricao: endpoints sensiveis sem rate limiting e sem protecao anti-CSRF para operacoes autenticadas por cookie.
- Risco: brute force, abuso de API e acao forjada em sessao autenticada.
- Recomendacao: Flask-Limiter e tokens CSRF para POST/DELETE/PATCH.

## Proximas mitigacoes recomendadas (ordem)
1. Migrar senha para Argon2id/bcrypt e remover credencial padrao.
2. Endurecer sessao/cookies e desativar debug em producao.
3. Implementar CSRF + rate limiting.
4. Eliminar `innerHTML` inseguro nas views administrativas.
5. Definir politica de retencao e minimizacao de dados (LGPD).

## Implementacao do pacote de ferramentas defensivas (MVP)

Status geral: Implementado (MVP)

- IDS/IPS simples SSH: implementado em `security_tools/ids_ssh_monitor.py`
- Scanner de portas e servicos: implementado em `security_tools/port_service_scanner.py`
- FIM (integridade de arquivos): implementado em `security_tools/fim_monitor.py`
- Gerenciador de segredos local: implementado em `security_tools/secrets_cli.py`
- Scanner web defensivo (sinais basicos SQLi/XSS): implementado em `security_tools/web_vuln_scanner.py`
- SBOM + auditoria de dependencias: implementado em `security_tools/sbom_audit.py`
- Auditor cloud AWS (MVP): implementado em `security_tools/cloud_config_auditor.py`
- Criptografia automatica de arquivos: implementado em `security_tools/auto_encrypt_watcher.py`
- Dashboard de logs centralizados: implementado em `security_tools/log_analyzer_dashboard.py`
- Packet sniffer defensivo: implementado em `security_tools/packet_sniffer.py`

Observacoes de escopo MVP:
- Azure/GCP ainda nao implementados no auditor cloud.
- Deteccao web atual e heuristica, nao substitui DAST completo.
- IDS bloqueia por comando do sistema e deve iniciar em `--dry-run`.

## Expansao de ferramentas de SO (estilo Kali/Linux)

Status: Implementado

Ferramentas adicionadas:
- hardening de host (auditoria CIS-like)
- auditor de permissoes perigosas
- wrapper de rootkit scanner
- FIM de binarios de sistema
- monitor de processos anomalos
- detector de persistencia
- watchdog de portas em escuta
- detector de ARP spoofing
- detector de DNS tunneling
- coletor forense
- scanner YARA IOC
- auditor de compliance de logs
- honeypot SSH simples
- verificador de patch/CVE
- EDR-lite local

Manual dentro da aplicacao:
- rota web administrativa criada: `/admin/security-tools`
- objetivo: centralizar comandos e fluxo operacional para equipe.

Atualizacao cross-platform (Windows/Linux):
- IDS com suporte a eventos Windows (Security 4625) e bloqueio via firewall nativo.
- Auditor de permissoes com modo Windows dedicado.
- Wrapper de rootkit com modo Windows Defender.
- Compliance de logs com checks de canais Event Log no Windows.

## Plataforma de operacao defensiva (nova camada)

Status: Implementado

- Orquestrador central com perfis operacionais (`launcher.py`).
- Banco de eventos unificado com score de risco e severidade (`event_store.py`).
- Notificacao em tempo real para eventos criticos via webhook (`critical_notifier.py`).
- Dashboard expandido para visao de severidade, risco medio e criticos recentes.

Beneficio: reduz operacao manual e cria fluxo continuo de deteccao -> classificacao -> alerta -> visualizacao.

## Visibilidade e analise de rede

Status: Implementado

- Monitor avancado de portas em tempo real (`advanced_port_monitor.py`)
- Sniffer multi-camada (`network_sniffer.py`)
- Scanner de descoberta de hosts e servicos (`host_discovery_scanner.py`)
- Inteligencia de IP com enrichment opcional (`ip_intel_analyzer.py`)
- Perfil `rede` no launcher para execucao coordenada dessas funcoes
- Dashboard principal com graficos e tabela de eventos de rede alimentados pelo banco unificado

Objetivo: aproximar a plataforma de um stack de visibilidade operacional estilo Nmap/Wireshark, mantendo o foco defensivo.
