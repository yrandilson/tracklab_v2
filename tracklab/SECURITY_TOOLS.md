# Security Tools MVP - TrackLab

Este pacote adiciona um conjunto de ferramentas defensivas de seguranca em `security_tools/`.

## Avisos
- Use apenas em ambientes autorizados.
- Algumas funcoes (sniffer, bloqueio de IP e cloud audit) exigem privilegios elevados.
- Ferramentas principais agora suportam modo hibrido Windows/Linux (veja exemplos por SO abaixo).

## Ferramentas implementadas

1. IDS/IPS simples SSH
- Arquivo: `security_tools/ids_ssh_monitor.py`
- Funcao: monitora falhas SSH em log Linux ou eventos Windows (ID 4625) e bloqueia IP por limiar.
- Exemplo:
  - `python security_tools/ids_ssh_monitor.py --log-file /var/log/auth.log --threshold 5 --window 300 --dry-run`
  - `python security_tools/ids_ssh_monitor.py --source windows-event --blocker windows-firewall --dry-run`

2. Scanner de portas e servicos
- Arquivo: `security_tools/port_service_scanner.py`
- Funcao: varre portas e destaca servicos nao autorizados.
- Exemplo:
  - `python security_tools/port_service_scanner.py --host 192.168.0.10 --ports 1-1024 --allow 22,80,443`

3. FIM (File Integrity Monitor)
- Arquivo: `security_tools/fim_monitor.py`
- Funcao: gera baseline de hashes e verifica alteracoes.
- Exemplo:
  - `python security_tools/fim_monitor.py baseline --paths backend frontend --output fim_baseline.json`
  - `python security_tools/fim_monitor.py verify --paths backend frontend --baseline fim_baseline.json`

4. Gerenciador local de segredos
- Arquivo: `security_tools/secrets_cli.py`
- Funcao: armazena segredos criptografados localmente.
- Variavel obrigatoria: `TRACKLAB_MASTER_PASSWORD`
- Exemplo:
  - `python security_tools/secrets_cli.py init`
  - `python security_tools/secrets_cli.py set db_password supersecreto`
  - `python security_tools/secrets_cli.py get db_password`

5. Scanner web defensivo (SQLi/XSS basico)
- Arquivo: `security_tools/web_vuln_scanner.py`
- Funcao: detecta sinais simples de reflexao e erro SQL em URL autorizada.
- Exemplo:
  - `python security_tools/web_vuln_scanner.py --url http://localhost:5000/capture`

6. SBOM + auditoria de dependencias
- Arquivo: `security_tools/sbom_audit.py`
- Funcao: gera inventario de dependencias e roda `pip-audit`.
- Exemplo:
  - `python security_tools/sbom_audit.py --requirements requirements.txt --output sbom.json`

7. Auditor de configuracao cloud (AWS MVP)
- Arquivo: `security_tools/cloud_config_auditor.py`
- Funcao: checa S3 publico, chaves IAM antigas e SG permissivos.
- Exemplo:
  - `python security_tools/cloud_config_auditor.py --provider aws`

8. Criptografia automatica de arquivos
- Arquivo: `security_tools/auto_encrypt_watcher.py`
- Funcao: monitora pasta e gera arquivos `.enc` para extensoes sensiveis.
- Variavel obrigatoria: `TRACKLAB_ENCRYPT_PASSWORD`
- Exemplo:
  - `python security_tools/auto_encrypt_watcher.py --watch ./sensitive`

9. Dashboard de logs centralizados
- Arquivo: `security_tools/log_analyzer_dashboard.py`
- Funcao: le JSONL de eventos e mostra graficos de tipos e top IPs.
- Exemplo:
  - `python security_tools/log_analyzer_dashboard.py --log-file security_events.jsonl --port 5055`

10. Packet sniffer defensivo
- Arquivo: `security_tools/packet_sniffer.py`
- Funcao: captura pacotes IP e resume protocolos.
- Exemplo:
  - `python security_tools/packet_sniffer.py --iface eth0 --count 50`

11. Auditor de hardening de host (CIS-like)
- Arquivo: `security_tools/host_hardening_audit.py`
- Exemplo:
  - `python security_tools/host_hardening_audit.py`

12. Auditor de permissoes perigosas
- Arquivo: `security_tools/permissions_audit.py`
- Exemplo:
  - `python security_tools/permissions_audit.py --root /`
  - `python security_tools/permissions_audit.py --root C:\\`

13. Wrapper de rootkit scanner
- Arquivo: `security_tools/rootkit_wrapper.py`
- Exemplo:
  - `python security_tools/rootkit_wrapper.py --tool rkhunter`
  - `python security_tools/rootkit_wrapper.py --tool windows-defender`

14. FIM de binarios de sistema
- Arquivo: `security_tools/system_binary_fim.py`
- Exemplo:
  - `python security_tools/system_binary_fim.py baseline --output system_bins_baseline.json`
  - `python security_tools/system_binary_fim.py verify --baseline system_bins_baseline.json`

15. Monitor de processos anomalos
- Arquivo: `security_tools/process_anomaly_monitor.py`
- Exemplo:
  - `python security_tools/process_anomaly_monitor.py --interval 5`

16. Detector de persistencia
- Arquivo: `security_tools/persistence_checker.py`
- Exemplo:
  - `python security_tools/persistence_checker.py`

17. Watchdog de portas em escuta
- Arquivo: `security_tools/port_watchdog.py`
- Exemplo:
  - `python security_tools/port_watchdog.py --interval 5`

18. Detector de ARP spoofing
- Arquivo: `security_tools/arp_spoof_detector.py`
- Exemplo:
  - `python security_tools/arp_spoof_detector.py --iface eth0`

19. Detector de DNS tunneling
- Arquivo: `security_tools/dns_tunnel_detector.py`
- Exemplo:
  - `python security_tools/dns_tunnel_detector.py --iface eth0`

20. Coletor forense
- Arquivo: `security_tools/forensic_collector.py`
- Exemplo:
  - `python security_tools/forensic_collector.py --output forensic_snapshot.json`

21. Scanner YARA para IOC
- Arquivo: `security_tools/yara_ioc_scanner.py`
- Exemplo:
  - `python security_tools/yara_ioc_scanner.py --rules rules.yar --path .`

22. Auditor de compliance de logs
- Arquivo: `security_tools/log_compliance_audit.py`
- Exemplo:
  - `python security_tools/log_compliance_audit.py`
  - (Windows) valida canais Security/System/Application via `wevtutil`

23. Honeypot SSH simples
- Arquivo: `security_tools/ssh_honeypot.py`
- Exemplo:
  - `python security_tools/ssh_honeypot.py --host 0.0.0.0 --port 2222`

24. Verificador de patch/CVE
- Arquivo: `security_tools/patch_cve_checker.py`
- Exemplo:
  - `python security_tools/patch_cve_checker.py --requirements requirements.txt`

25. EDR-lite local
- Arquivo: `security_tools/edr_lite.py`
- Exemplo:
  - `python security_tools/edr_lite.py --kill-suspicious`

26. Banco de eventos unificado com score
- Arquivo: `security_tools/event_store.py`
- Funcao: normaliza eventos, calcula `risk_score` (0-100) e `severity` (low/medium/high/critical), gravando em `security_events.jsonl`.

27. Orquestrador central com perfis
- Arquivo: `security_tools/launcher.py`
- Funcao: executa perfis (`laboratorio`, `producao`, `forense`), consolida saida e escreve no banco de eventos.
- Exemplo:
  - `python security_tools/launcher.py --profile laboratorio`
  - `python security_tools/launcher.py --profile producao --notify-critical`

28. Notificador em tempo real de eventos criticos
- Arquivo: `security_tools/critical_notifier.py`
- Funcao: observa `security_events.jsonl` e envia webhook para eventos `critical`.
- Variavel obrigatoria: `TRACKLAB_ALERT_WEBHOOK_URL`
- Exemplo:
  - `python security_tools/critical_notifier.py --log-file security_events.jsonl`

29. Monitor avancado de portas em tempo real
- Arquivo: `security_tools/advanced_port_monitor.py`
- Funcao: detecta novas portas em escuta, identifica processo dono e registra eventos.
- Exemplo:
  - `python security_tools/advanced_port_monitor.py --interval 5 --allow 22,80,443`

30. Sniffer multi-camada
- Arquivo: `security_tools/network_sniffer.py`
- Funcao: captura ARP/IP/TCP/UDP/DNS/HTTP e gera resumo de top talkers e flows.
- Exemplo:
  - `python security_tools/network_sniffer.py --iface eth0 --count 200`

31. Scanner de descoberta de hosts e servicos
- Arquivo: `security_tools/host_discovery_scanner.py`
- Funcao: faz discovery de hosts e servicos com fallback em TCP scan ou `nmap` quando disponivel.
- Exemplo:
  - `python security_tools/host_discovery_scanner.py --targets 192.168.0.0/24 --ports 22,80,443`

32. Analise de inteligencia de IP
- Arquivo: `security_tools/ip_intel_analyzer.py`
- Funcao: identifica IP privado/publico, reverse DNS e enrichment opcional com reputacao/geolocalizacao.
- Variaveis opcionais: `ABUSEIPDB_API_KEY`, `IPINFO_TOKEN`
- Exemplo:
  - `python security_tools/ip_intel_analyzer.py 8.8.8.8 1.1.1.1`

33. Dashboard de rede com filtros operacionais
- Area: `frontend/templates/dashboard.html`
- Funcao: filtra eventos de rede por protocolo/tipo, IP e severidade, com visao de top IPs, portas e atividade recente.
- Fonte de dados: `security_events.jsonl` consolidado pelo backend.

## Formato recomendado para eventos JSONL
Exemplo por linha:

{"type":"ssh_failed","ip":"203.0.113.10","ts":"2026-04-04T15:30:00Z","source":"auth.log"}

## Passos de uso rapido
1. `pip install -r requirements.txt`
2. Execute o IDS em `--dry-run` primeiro.
3. Gere baseline do FIM.
4. Rode scanner web apenas em ativos autorizados.
5. Gere SBOM antes de deploy.
6. Rode `launcher.py` para executar perfis padronizados e alimentar o banco de eventos.
7. Inicie `critical_notifier.py` em paralelo para alertas criticos em tempo real.
8. Use o perfil `rede` do `launcher.py` para varreduras e visibilidade de rede.
9. No dashboard interno, use os filtros de rede para isolar protocolo, IP e severidade.

## Exemplos por SO

Windows:
- `python security_tools/ids_ssh_monitor.py --source windows-event --blocker windows-firewall --dry-run`
- `python security_tools/rootkit_wrapper.py --tool windows-defender`
- `python security_tools/permissions_audit.py --root C:\\`

Linux:
- `python security_tools/ids_ssh_monitor.py --source file --log-file /var/log/auth.log --blocker ufw --dry-run`
- `python security_tools/rootkit_wrapper.py --tool rkhunter`
- `python security_tools/permissions_audit.py --root /`

## Manual dentro da aplicacao
- Rota administrativa: `/admin/security-tools`
- Template: `frontend/templates/security_manual.html`

## Fluxo recomendado (operacao diaria)
1. `python security_tools/launcher.py --profile producao --notify-critical`
2. `python security_tools/critical_notifier.py --log-file security_events.jsonl`
3. `python security_tools/log_analyzer_dashboard.py --log-file security_events.jsonl --port 5055`
4. `python security_tools/launcher.py --profile rede --notify-critical`
