# Politica de Seguranca

## Reportar uma vulnerabilidade

Se voce descobriu uma vulnerabilidade no ThreatLens, **por favor NAO abra issue publica**.

Reporte de forma privada:

* **Email:** mateus.corcini@latamgateway.com (com `[SECURITY]` no assunto)
* **GitHub Security Advisory** (preferido): use a aba "Security" do repositorio
  para abrir um advisory privado.

### O que incluir

* Descricao da vulnerabilidade e impacto potencial
* Passos para reproduzir
* Versao afetada
* Sugestao de correcao (se tiver)

### O que esperar

* **Confirmacao** em ate **72 horas**
* **Triagem inicial** em ate **7 dias**
* **Correcao** ou plano publico em ate **30 dias** (vulnerabilidades criticas
  podem ser corrigidas mais rapido)
* **Credito** publico na release notes, a menos que voce prefira anonimato

## Escopo

| In-scope | Out-of-scope |
|---|---|
| Vulnerabilidades no codigo do ThreatLens (parsing, auth, etc.) | Vulnerabilidades em dependencias (reporte ao mantenedor da dependencia) |
| Bypass de autenticacao | Ataques que exigem acesso fisico ao servidor |
| Path traversal, RCE, SSRF | Spam ou DDoS |
| Vazamento de informacoes sensiveis | Engenharia social com mantenedores |

## Versoes suportadas

Apenas a versao mais recente recebe correcoes de seguranca.

| Versao | Suporte |
|---|---|
| 0.x | Em desenvolvimento (versao atual) |

## Hall of Fame

Pessoas que reportaram vulnerabilidades de forma responsavel serao listadas
aqui (com permissao delas):

_Vazio por enquanto. Seja o primeiro!_
