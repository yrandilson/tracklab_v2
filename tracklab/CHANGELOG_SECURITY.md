# Changelog de Seguranca e Correcoes

## 2026-04-04

### [Aplicado] Controle de autorizacao por perfil
- Arquivo: backend/app.py
- Mudanca:
  - adicionado decorator `admin_required`
  - rotas administrativas migradas de `login_required` para `admin_required`
- Objetivo: impedir acesso administrativo por usuarios nao-admin.

### [Aplicado] Fechamento garantido de conexao no fluxo de refLinkId
- Arquivo: backend/app.py
- Mudanca: bloco de contabilizacao de link refatorado com `try/finally`.
- Objetivo: evitar leak de conexao SQLite.

### [Aplicado] Endpoint real de miniatura
- Arquivo: backend/app.py
- Mudanca: criada rota `GET /api/photos/<int:pid>/thumb` com decode de data URL base64 e resposta binaria.
- Objetivo: suportar renderizacao de miniaturas no grid de fotos.

### [Aplicado] Remocao de hack de interceptacao fetch
- Arquivo: frontend/templates/photos.html
- Mudanca: removido override global de `window.fetch` para URLs com `/thumb`.
- Objetivo: simplificar frontend e evitar comportamento global inesperado.

### [Aplicado] Pacote MVP de ferramentas defensivas
- Arquivos:
  - security_tools/ids_ssh_monitor.py
  - security_tools/port_service_scanner.py
  - security_tools/fim_monitor.py
  - security_tools/secrets_cli.py
  - security_tools/web_vuln_scanner.py
  - security_tools/sbom_audit.py
  - security_tools/cloud_config_auditor.py
  - security_tools/auto_encrypt_watcher.py
  - security_tools/log_analyzer_dashboard.py
  - security_tools/packet_sniffer.py
- Objetivo: cobrir monitoramento, deteccao, integridade, segredos, auditoria e analise de rede/logs no escopo MVP.

### [Aplicado] Dependencias de seguranca adicionadas
- Arquivo: requirements.txt
- Mudanca: adicionadas libs para scanner web, criptografia, watcher, sniffing, auditoria cloud e SBOM.

### [Aplicado] Guia de uso das ferramentas
- Arquivo: SECURITY_TOOLS.md
- Mudanca: documentacao de operacao, exemplos e limites do MVP.

### [Aplicado] Ferramentas de SO estilo Kali/Linux (bloco completo)
- Arquivos adicionados em security_tools/:
  - host_hardening_audit.py
  - permissions_audit.py
  - rootkit_wrapper.py
  - system_binary_fim.py
  - process_anomaly_monitor.py
  - persistence_checker.py
  - port_watchdog.py
  - arp_spoof_detector.py
  - dns_tunnel_detector.py
  - forensic_collector.py
  - yara_ioc_scanner.py
  - log_compliance_audit.py
  - ssh_honeypot.py
  - patch_cve_checker.py
  - edr_lite.py
- Objetivo: ampliar cobertura de defesa, deteccao, forense e compliance em nivel de sistema operacional.

### [Aplicado] Manual dentro da aplicacao
- Arquivos:
  - frontend/templates/security_manual.html
  - backend/app.py
  - frontend/templates/base.html
- Mudanca: criada pagina `/admin/security-tools` e entrada no menu lateral para uso das ferramentas.

### [Aplicado] Dependencias adicionais para ferramentas de SO
- Arquivo: requirements.txt
- Mudanca: adicionados `psutil` e `yara-python`.

### [Aplicado] Adaptacao hibrida Windows/Linux em ferramentas criticas
- Arquivos:
  - security_tools/ids_ssh_monitor.py
  - security_tools/permissions_audit.py
  - security_tools/rootkit_wrapper.py
  - security_tools/log_compliance_audit.py
- Mudancas:
  - IDS com fonte `windows-event` (Event ID 4625) e bloqueio `windows-firewall`.
  - Auditor de permissoes com fluxo dedicado para Windows.
  - Wrapper de rootkit com modo `windows-defender`.
  - Compliance de logs com checks de Event Logs no Windows.

### [Aplicado] Manual da aplicacao atualizado para modos por SO
- Arquivo: frontend/templates/security_manual.html
- Mudanca: adicionados exemplos rapidos para Windows e Linux.

### [Aplicado] Manual markdown atualizado para modos por SO
- Arquivo: SECURITY_TOOLS.md
- Mudanca: novos exemplos cross-platform e orientacoes operacionais por ambiente.

### [Aplicado] Orquestrador central com perfis
- Arquivo: security_tools/launcher.py
- Mudanca: adicionado launcher com perfis `laboratorio`, `producao` e `forense`, consolidando resultados em eventos.

### [Aplicado] Banco de eventos unificado com score de risco
- Arquivo: security_tools/event_store.py
- Mudanca: normalizacao de evento, calculo de `risk_score` e `severity`, persistencia JSONL.

### [Aplicado] Notificacao em tempo real para eventos criticos
- Arquivo: security_tools/critical_notifier.py
- Mudanca: envio webhook para eventos `critical` a partir de `security_events.jsonl`.

### [Aplicado] Dashboard expandido para risco/severidade
- Arquivo: security_tools/log_analyzer_dashboard.py
- Mudanca: graficos de severidade, timeline de risco medio e lista de eventos criticos recentes.

### [Aplicado] Manual da aplicacao atualizado para operacao diaria
- Arquivo: frontend/templates/security_manual.html
- Mudanca: incluida secao de orquestracao, banco de eventos e notificacao critica.

### [Aplicado] Pacote de analise de rede e IPs
- Arquivos:
  - security_tools/advanced_port_monitor.py
  - security_tools/network_sniffer.py
  - security_tools/host_discovery_scanner.py
  - security_tools/ip_intel_analyzer.py
- Mudanca: adicionadas ferramentas de monitoramento de portas, sniffer multi-camada, discovery de hosts/servicos e inteligencia de IP.

### [Aplicado] Perfil de launcher focado em rede
- Arquivo: security_tools/launcher.py
- Mudanca: adicionado perfil `rede` para executar as novas ferramentas de visibilidade de rede.

### [Aplicado] Dashboard com visibilidade de rede
- Arquivos:
  - backend/app.py
  - frontend/templates/dashboard.html
- Mudanca: dashboard agora exibe eventos de rede, portas em evidência e lista dos ultimos eventos da camada de rede.

## Proximo bloco sugerido
- Migracao de hash de senha para Argon2id/bcrypt.
- Endurecimento de secret key/cookies para producao.
- CSRF + rate limiting.
- Sanitizacao de saida no frontend admin.
