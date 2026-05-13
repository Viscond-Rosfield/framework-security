# 🛡️ Framework de Segurança - Analisador de Arquivos

MVP de um framework em Python/FastAPI que recebe um arquivo via upload e o analisa contra múltiplos serviços de detecção de malware, consolidando um veredito único.

## Funcionalidades

- **Análise local** offline: hash SHA256/MD5/SHA1, base de hashes conhecidos (inclui EICAR), detecção de magic bytes, *double extension* e extensões perigosas.
- **VirusTotal**: consulta o hash em 70+ engines de AV.
- **MetaDefender (OPSWAT)**: consulta multi-engine.
- **Hybrid Analysis**: pesquisa de amostras analisadas em sandbox.
- Interface **web** (tema escuro) com formulário de upload + tela de relatório.
- Endpoint **JSON** (`POST /api/scan`) para integração programática.
- Os scanners rodam em paralelo (asyncio + httpx).

## Estrutura

```
Framework - Security/
├── app.py                 # FastAPI - rotas web + JSON
├── config.py              # Carrega .env e expõe constantes
├── requirements.txt
├── .env.example           # Modelo das variáveis de ambiente
├── core/
│   ├── hasher.py          # Cálculo de hashes
│   └── aggregator.py      # Orquestra scanners e gera veredito
├── scanners/
│   ├── local_scanner.py   # Heurísticas offline
│   ├── virustotal.py
│   ├── metadefender.py
│   └── hybrid_analysis.py
├── templates/
│   ├── index.html         # Página de upload
│   └── results.html       # Página de relatório
├── static/
│   └── style.css
└── uploads/               # Pasta temporária (arquivo é deletado após análise)
```

## Instalação

```bash
# 1. Crie um virtualenv (opcional)
python -m venv .venv
.venv\Scripts\activate            # Windows
# source .venv/bin/activate       # Linux/Mac

# 2. Instale as dependências
pip install -r requirements.txt

# 3. Configure as chaves de API
copy .env.example .env             # Windows
# cp .env.example .env             # Linux/Mac
# edite .env e preencha as chaves
```

### Onde obter as chaves de API

| Serviço | URL | Notas |
|---|---|---|
| VirusTotal | https://www.virustotal.com/gui/my-apikey | Free: 4 req/min, 500/dia |
| MetaDefender | https://metadefender.opswat.com/account | Free: ~1000 req/dia |
| Hybrid Analysis | https://www.hybrid-analysis.com/my-account?tab=%2Fapi-keys | Requer conta verificada |

> O scanner **local** funciona sem qualquer chave de API — útil para começar.

## Como rodar

```bash
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```

Abra **http://localhost:8000** no navegador.

### Teste rápido com EICAR

Crie um arquivo `eicar.txt` com o conteúdo abaixo (padrão internacional de teste, **não é vírus de verdade**):

```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

Faça upload — o scanner local deve sinalizar como malicioso pelo hash.

### Endpoint JSON

```bash
curl -X POST http://localhost:8000/api/scan \
     -F "file=@./eicar.txt"
```

Retorna um JSON com hashes, resultado de cada scanner e veredito consolidado.

## Como o veredito é calculado

| Condição | Veredito |
|---|---|
| Qualquer scanner reportou detecção > 0 | `malicious` |
| Apenas suspeitas | `suspicious` |
| Nenhuma detecção/suspeita | `clean` |

## Deploy no Render (gratuito)

A aplicação está preparada para deploy automático via Blueprint (`render.yaml`).

### 1. Subir no GitHub

```bash
cd ~/framework-security
git init
git add .
git commit -m "Initial commit"
# Crie um repositório PRIVADO em https://github.com/new
git branch -M main
git remote add origin https://github.com/SEU-USUARIO/framework-security.git
git push -u origin main
```

> ⚠️ **NUNCA commite o `.env`** — ele já está no `.gitignore`. Suas chaves de API vão direto no painel do Render.

### 2. Conectar no Render

1. Acesse https://render.com e faça login com GitHub
2. **New → Blueprint**
3. Selecione o repositório `framework-security`
4. Render lê o `render.yaml` automaticamente
5. Preencha as variáveis sensíveis (as marcadas com `sync: false`):
   - `VIRUSTOTAL_API_KEY`
   - `METADEFENDER_API_KEY`
   - `HYBRID_ANALYSIS_API_KEY`
6. Click **Apply**

Em ~2 minutos você terá uma URL `https://framework-security-xxxx.onrender.com`.

### 3. Recuperar a senha gerada

O Render gera automaticamente uma senha forte para `APP_PASSWORD`. Para vê-la:

1. Acesse seu service no painel do Render
2. **Environment** → procure `APP_PASSWORD` → click no olho 👁
3. Anote — você usará no prompt do navegador

Usuário padrão: `admin` (ou o que você definiu em `APP_USERNAME`).

### 4. Testar

Acesse a URL no navegador. O navegador vai pedir usuário/senha (HTTP Basic). Após autenticar, você cai na página de upload.

Para uso programático:

```bash
curl -u admin:SUA_SENHA -X POST https://sua-url.onrender.com/api/scan \
     -F "file=@./arquivo.exe"
```

### Notas sobre o free tier

- O serviço **dorme após 15 min** sem requisições. O primeiro acesso depois disso demora ~30s para acordar.
- Para evitar isso: upgrade para `Starter ($7/mês)` no `render.yaml` (campo `plan`).
- **Não** mantenha estado em disco — o filesystem do Render é efêmero. (Sua app já deleta uploads após análise, então tudo certo.)

### Atualizar a aplicação

Qualquer `git push` no `main` dispara um novo deploy automaticamente.

```bash
git add .
git commit -m "feat: ..."
git push
```

---

## Próximos passos sugeridos

- Adicionar **upload automático ao VirusTotal** quando o hash não for encontrado (endpoint `/files`).
- Cache de resultados (Redis ou SQLite) para evitar consultas repetidas.
- Suporte a **YARA** para regras customizadas (biblioteca `yara-python`).
- Autenticação e rate-limit por usuário.
- Exportar relatórios em PDF.
- Histórico de análises em banco.

## Segurança

- Arquivos são salvos com nome único (UUID) e **deletados imediatamente após a análise**.
- Limite de tamanho configurável via `MAX_FILE_SIZE_MB`.
- Para uso em produção, considere rodar atrás de um proxy reverso (nginx) com TLS e isolar a pasta de uploads em um diretório com permissões restritas.
# framework-security
