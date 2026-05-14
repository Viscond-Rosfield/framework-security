<div align="center">

# 🔍 ThreatLens

**Meta-aggregator open-source para analise de malware.**

Combine VirusTotal, MetaDefender, Hybrid Analysis e analise local em uma unica interface.
Self-hospede, traga sua propria API key e tenha controle total.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED)](Dockerfile)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

</div>

---

## Por que ThreatLens?

Analistas de seguranca perdem tempo abrindo VirusTotal, MetaDefender e
Hybrid Analysis um por um, copiando hashes, comparando vereditos. ThreatLens
faz isso em uma so interface, com cache, historico e API para integracao.

- 🔒 **Privacidade primeiro** — arquivos sao deletados imediatamente apos analise
- 🔑 **BYOK** (Bring Your Own Key) — voce usa suas proprias API keys
- 🐳 **Self-hostavel** — `docker compose up` e voce esta no ar
- 🎯 **Open-source MIT** — auditavel, sem caixa-preta
- ⚡ **Cache inteligente** — mesmo hash nao re-consulta APIs por 24h
- 📊 **Historico** — toda analise fica registrada e pesquisavel
- 🔌 **API JSON** — integre com seu SIEM/SOAR

## Features

| Recurso | Status |
|---|---|
| Scanner local (hash conhecido, EICAR, magic bytes, double extension) | ✅ |
| Integracao com VirusTotal | ✅ |
| Integracao com MetaDefender (OPSWAT) | ✅ |
| Integracao com Hybrid Analysis | ✅ |
| Cache SQLite (TTL configuravel) | ✅ |
| Historico com busca | ✅ |
| HTTP Basic Auth | ✅ |
| API JSON (`/api/scan`) | ✅ |
| OpenAPI/Swagger docs (`/docs`) | ✅ |
| YARA rules locais | 🛣️ Roadmap |
| Upload automatico ao VT (quando hash desconhecido) | 🛣️ Roadmap |
| CLI distribuivel (`pip install threatlens`) | 🛣️ Roadmap |
| Webhooks (Slack/Discord/SIEM) | 🛣️ Roadmap |
| Analise de URLs/dominios | 🛣️ Roadmap |
| Rate limiting + captcha | 🛣️ Roadmap |
| BYOK na UI (cada user cola sua key) | 🛣️ Roadmap |

## Quick start

### Com Docker (recomendado)

```bash
git clone https://github.com/Viscond-Rosfield/framework-security.git
cd framework-security

cp .env.example .env
# Edite .env e coloque APP_PASSWORD e suas API keys

docker compose up -d
```

Acesse **http://localhost:8000**.

### Com Python local

```bash
git clone https://github.com/Viscond-Rosfield/framework-security.git
cd framework-security

python3 -m venv .venv
source .venv/bin/activate          # Linux/Mac
# .venv\Scripts\activate            # Windows

pip install -r requirements.txt
cp .env.example .env                # edite suas chaves

uvicorn app:app --reload
```

### Deploy 1-clique

| Plataforma | Botao |
|---|---|
| Render | [![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/Viscond-Rosfield/framework-security) |

> Outras plataformas (Railway, Fly.io) sao suportadas via Dockerfile, basta apontar pro repositorio.

## Variaveis de ambiente

| Variavel | Padrao | Descricao |
|---|---|---|
| `APP_USERNAME` | `admin` | Usuario do HTTP Basic Auth |
| `APP_PASSWORD` | _(vazio)_ | **OBRIGATORIO em producao**. Vazio = auth desabilitada |
| `VIRUSTOTAL_API_KEY` | _(vazio)_ | https://www.virustotal.com/gui/my-apikey |
| `METADEFENDER_API_KEY` | _(vazio)_ | https://metadefender.opswat.com/account |
| `HYBRID_ANALYSIS_API_KEY` | _(vazio)_ | https://www.hybrid-analysis.com/my-account?tab=%2Fapi-keys |
| `MAX_FILE_SIZE_MB` | `32` | Tamanho maximo de upload |
| `DATABASE_PATH` | `data/scans.db` | Caminho do SQLite (cache + historico) |
| `CACHE_TTL_HOURS` | `24` | Tempo de validade do cache (0 desabilita) |

## API

ThreatLens expoe um endpoint JSON e tem docs interativas em `/docs`.

### Scan via API

```bash
curl -u admin:SUA_SENHA \
     -X POST https://sua-instancia/api/scan \
     -F "file=@./eicar.txt"
```

Resposta:

```json
{
  "file": {
    "name": "eicar.txt",
    "size_bytes": 69,
    "md5": "44d88612fea8a8f36de82e1278abb02f",
    "sha1": "...",
    "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
  },
  "results": {
    "local": { "status": "ok", "detections": 1, "flags": ["EICAR detected"] },
    "virustotal": { "status": "ok", "detections": 63, "engines": 73 }
  },
  "verdict": {
    "level": "malicious",
    "total_detections": 64,
    "total_engines": 74,
    "flagged_by": ["local", "virustotal"]
  }
}
```

## Como funciona

```
Upload -> hash SHA256 -> cache hit? -> [SIM] retorna do banco
                                    -> [NAO] -> [VirusTotal API]
                                              -> [MetaDefender API]  (paralelo)
                                              -> [Hybrid Analysis API]
                                              -> [Scanner local]
                                    -> agrega resultados
                                    -> calcula veredito
                                    -> persiste no banco
                                    -> deleta arquivo
```

### Como o veredito e calculado

| Condicao | Veredito |
|---|---|
| Qualquer scanner reportou deteccao > 0 | `malicious` |
| Apenas suspeitas | `suspicious` |
| Nada sinalizado | `clean` |

## Estrutura

```
threatlens/
├── app.py                 # FastAPI - rotas web + JSON
├── config.py              # Carrega .env
├── core/
│   ├── aggregator.py      # Orquestra scanners + veredito
│   ├── database.py        # SQLite (cache + historico)
│   └── hasher.py
├── scanners/
│   ├── local_scanner.py   # Heuristicas offline
│   ├── virustotal.py
│   ├── metadefender.py
│   └── hybrid_analysis.py
├── templates/             # Jinja2 (web UI)
├── static/                # CSS
├── Dockerfile
├── docker-compose.yml
└── render.yaml            # Blueprint do Render
```

## Roadmap

Veja a lista completa de features planejadas em [issues com a label `roadmap`](https://github.com/Viscond-Rosfield/framework-security/labels/roadmap).

**Proximos marcos:**

- v0.3 — BYOK na UI + rate limit + tests
- v0.4 — YARA rules + upload automatico ao VT
- v0.5 — CLI (`pip install threatlens`) + webhooks
- v1.0 — Estavel, docs completos, feed publico de IOCs

## Contribuir

PRs sao muito bem-vindos! Leia o [CONTRIBUTING.md](CONTRIBUTING.md) antes.

Areas onde mais precisamos de ajuda:

- 🧪 **Testes** — coverage ainda baixo
- 🌍 **Traducao** — i18n para PT-EN-ES
- 📚 **Docs** — exemplos de uso, screenshots, video demo
- 🔌 **Novos scanners** — MalwareBazaar, ClamAV, YARA, etc.

## Aviso legal

ThreatLens e uma ferramenta **defensiva**. Use somente para:

- Analisar arquivos que voce tem o direito de analisar
- Pesquisa em seguranca
- Educacao

**NAO** use para auxiliar criacao, distribuicao ou execucao de malware. O uso
indevido e responsabilidade do usuario.

## Privacidade

- Arquivos sao **deletados imediatamente** apos a analise (sucesso ou erro)
- Apenas **hashes e metadados** sao salvos no banco
- Nada e enviado pra terceiros alem das APIs **que voce configurar** com sua chave
- Voce e dono da inflexao quando self-host

## Licenca

MIT. Veja [LICENSE](LICENSE).

## Reconhecimentos

Construido sobre o trabalho excelente de:

- [FastAPI](https://fastapi.tiangolo.com/)
- [VirusTotal API](https://docs.virustotal.com/)
- [OPSWAT MetaDefender](https://docs.opswat.com/mdcloud)
- [Hybrid Analysis](https://www.hybrid-analysis.com/docs/api/v2)
- O padrao [EICAR](https://www.eicar.org/) de teste antivirus

---

<div align="center">
Feito com 🛡️ por <a href="https://github.com/Viscond-Rosfield">Mateus Corcini</a> e <a href="https://github.com/Viscond-Rosfield/framework-security/graphs/contributors">contribuidores</a>.
</div>
