# Contribuindo com o ThreatLens

Obrigado por considerar contribuir! Este documento explica como participar.

## Codigo de Conduta

Este projeto adota o [Contributor Covenant](./CODE_OF_CONDUCT.md). Ao participar,
voce se compromete a manter um ambiente acolhedor e respeitoso.

## Como contribuir

### Reportar bugs

1. Verifique se ja existe uma [issue aberta](https://github.com/Viscond-Rosfield/framework-security/issues).
2. Se nao, abra uma usando o template **Bug Report**.
3. Inclua: versao, SO, passos pra reproduzir, log de erro.

### Sugerir features

1. Abra uma issue com o template **Feature Request**.
2. Descreva o problema que voce esta tentando resolver, nao so a solucao.
3. Aguarde discussao antes de implementar mudancas grandes.

### Reportar vulnerabilidades

**NAO abra issue publica.** Veja [SECURITY.md](./SECURITY.md) para o processo.

### Enviar Pull Requests

1. Faca fork do repositorio.
2. Crie uma branch a partir de `main`: `git checkout -b feat/minha-feature`.
3. Implemente as mudancas (siga o estilo existente).
4. Adicione/atualize testes se aplicavel.
5. Rode os testes localmente: `pytest`.
6. Commit com mensagens claras (ver convencao abaixo).
7. Push e abra um PR. Preencha o template.

## Setup local

```bash
git clone https://github.com/Viscond-Rosfield/framework-security.git
cd framework-security

python3 -m venv .venv
source .venv/bin/activate          # Linux/Mac
# .venv\Scripts\activate            # Windows

pip install -r requirements.txt
pip install -r requirements-dev.txt  # quando existir

cp .env.example .env                # edite com suas chaves de teste
uvicorn app:app --reload
```

Acesse http://localhost:8000.

## Convencao de commits

Usamos [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` nova funcionalidade
- `fix:` correcao de bug
- `docs:` so documentacao
- `refactor:` refactor sem mudanca de comportamento
- `test:` adicao/correcao de testes
- `chore:` build, CI, dependencias
- `perf:` melhoria de performance
- `security:` correcao com impacto de seguranca

Exemplos:
- `feat: adiciona scanner YARA local`
- `fix: trata HTTP 429 do VirusTotal sem quebrar`
- `docs: adiciona exemplo de deploy em Fly.io`

## Estilo de codigo

- Python 3.11+
- Type hints sempre que possivel
- Funcoes async para I/O
- Docstrings curtas em portugues ou ingles (consistente dentro do arquivo)
- Linha maxima ~100 caracteres

Antes de submeter um PR rode:

```bash
python -m py_compile app.py config.py core/*.py scanners/*.py
# pytest  (quando suite estiver disponivel)
```

## Estrutura do projeto

```
threatlens/
├── app.py                 # FastAPI - rotas web + JSON
├── config.py              # Carrega .env e expoe constantes
├── core/
│   ├── aggregator.py      # Orquestra scanners e gera veredito
│   ├── database.py        # Camada SQLite (cache + historico)
│   └── hasher.py          # Calculo de hashes
├── scanners/
│   ├── local_scanner.py   # Heuristicas offline
│   ├── virustotal.py
│   ├── metadefender.py
│   └── hybrid_analysis.py
├── templates/             # Jinja2 HTML
├── static/                # CSS
└── Dockerfile             # Build self-host
```

## Adicionando um novo scanner

1. Crie `scanners/seunome.py` seguindo o padrao dos existentes.
2. Implemente `async def scan_seunome(sha256: str) -> dict` retornando o
   schema esperado (veja outros scanners).
3. Registre no `core/aggregator.py`.
4. Adicione a env var em `config.py` e `.env.example`.
5. Documente o scanner no README.

## Licenca

Ao contribuir, voce concorda que sua contribuicao sera licenciada sob a
[MIT License](./LICENSE).
