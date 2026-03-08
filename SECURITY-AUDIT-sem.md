# Security Audit Report — Ataraxy-Labs/sem

**Repositório:** https://github.com/Ataraxy-Labs/sem
**Data:** 2026-03-08
**Escopo:** Análise completa de segurança, incluindo roubo de chaves/credenciais, injeção de comandos, supply chain e vulnerabilidades gerais.

---

## Resumo Executivo

O repositório `sem` é uma ferramenta CLI de versionamento semântico que fornece diffs a nível de entidade sobre o Git. O projeto é implementado em **TypeScript** (Node.js) e **Rust**, com parsers baseados em tree-sitter.

### Resultado Geral

| Severidade | Quantidade |
|-----------|-----------|
| CRÍTICA    | 2         |
| ALTA       | 3         |
| MÉDIA      | 3         |
| BAIXA      | 2         |

**Roubo de chaves/credenciais:** Não foram encontrados vetores diretos de exfiltração de dados, backdoors, ou código malicioso para roubo de chaves. O projeto **não** lê variáveis de ambiente sensíveis, não faz requisições HTTP, não acessa arquivos de credenciais (SSH keys, wallets, .env), e não contém código ofuscado.

---

## Análise de Roubo de Chaves e Exfiltração

### Resultado: SEM EVIDÊNCIAS DE COMPORTAMENTO MALICIOSO

- **Nenhuma requisição de rede**: O código não contém `fetch`, `axios`, `http.request`, ou qualquer mecanismo de comunicação de rede. A única dependência de rede indireta é o `simple-git` que faz chamadas ao binário `git` local.
- **Nenhuma leitura de credenciais**: Não há leitura de `~/.ssh/`, `~/.aws/`, `~/.env`, wallets de criptomoedas, tokens de API, ou qualquer outro arquivo sensível.
- **Nenhuma variável de ambiente sensível**: O código não lê `process.env` para obter API keys, tokens, ou segredos. O uso de `process.env` é limitado a `process.cwd()`.
- **Nenhum código ofuscado**: Não há `eval()`, `Function()` constructor, base64 encoding suspeito, ou código dinâmico.
- **Nenhum script de instalação malicioso**: O `package.json` não contém scripts `preinstall`, `postinstall`, ou `prepare`.
- **Binários**: Nenhum binário compilado no repositório.

---

## Vulnerabilidades Encontradas

### CRÍTICA #1 — Injeção de Comando via `execSync` em `review.ts`

**Arquivo:** `src/cli/commands/review.ts:31-34`

```typescript
const { execSync } = await import('node:child_process');
const prJson = execSync(`gh pr view ${branchOrPR} --json headRefName,baseRefName,title,author`, {
  encoding: 'utf-8',
  cwd,
});
```

**Descrição:** O valor `branchOrPR` é interpolado diretamente numa string passada ao `execSync`, que executa via shell. Embora exista uma verificação `if (/^\d+$/.test(branchOrPR))` na linha 28 que limita essa branch de código apenas a strings numéricas (mitigando a injeção na prática), o padrão é perigoso por:

1. **Fragilidade**: Qualquer refatoração futura que relaxe o regex abre uma vulnerabilidade de injeção imediata
2. **Anti-pattern**: String interpolation com `execSync` é um anti-pattern de segurança reconhecido

**Impacto:** Execução arbitrária de comandos no sistema do usuário.

**Recomendação:** Usar `execFileSync('gh', ['pr', 'view', branchOrPR, '--json', '...'])` que evita interpretação pelo shell.

---

### CRÍTICA #2 — Execução Arbitrária de SQL via comando `query`

**Arquivos:** `src/cli/commands/query.ts:32`, `src/storage/database.ts:182-184`

```typescript
// query.ts
const results = db.query(sql);

// database.ts
query(sql: string): unknown[] {
    return this.db.prepare(sql).all();
}
```

**Descrição:** O comando `sem query <sql>` aceita SQL arbitrário do usuário e executa diretamente contra o banco SQLite sem qualquer sanitização ou restrição. Embora `better-sqlite3` `.all()` seja tipicamente para SELECT, `prepare()` aceita INSERT/UPDATE/DELETE.

**Impacto:**
- Leitura completa de todos os dados do banco
- Potencial para operações destrutivas (DELETE, DROP TABLE)
- Em contexto CI/CD onde `sem` é invocado com input não confiável, isso é um vetor de SQL injection direto

**Recomendação:**
- Ativar `PRAGMA query_only = ON` antes de executar queries do usuário
- Ou restringir apenas a statements SELECT com whitelist

---

### ALTA #1 — Path Traversal em `blame.ts` e `getFileContent`

**Arquivos:** `src/cli/commands/blame.ts:57`, `src/git/diff-reader.ts:74`

```typescript
// blame.ts
currentContent = await readFile(resolve(repoRoot, filePath), 'utf-8');

// diff-reader.ts
return await readFile(resolve(root, filePath), 'utf-8');
```

**Descrição:** O argumento `filePath` do comando `sem blame <file>` vem diretamente do input do usuário. `resolve(repoRoot, filePath)` resolve `../../etc/passwd` para `/etc/passwd` sem nenhuma verificação de limites do repositório.

**Impacto:** Leitura arbitrária de arquivos do sistema fora do repositório.

**Recomendação:** Após resolver o caminho, verificar que permanece dentro da raiz do repositório:
```typescript
const resolved = resolve(repoRoot, filePath);
if (!resolved.startsWith(repoRoot)) throw new Error('path outside repository');
```

---

### ALTA #2 — Git Refs Não Sanitizados Passados como Argumentos

**Arquivos:** `src/git/diff-reader.ts:28-34`, `src/git/bridge.ts:108-120`

```typescript
// diff-reader.ts
const diff = await git.diff([`${scope.sha}~1`, scope.sha, '--name-status']);
const diff = await git.diff([scope.from, scope.to, '--name-status']);
```

**Descrição:** Commit SHAs e refs fornecidos pelo usuário (via `--commit`, `--from`, `--to`) são passados diretamente para chamadas do `simple-git` sem validação. Embora `simple-git` use arrays de argumentos (não strings de shell), um ref malicioso como `--output=/tmp/exfil` poderia ser interpretado como flag do git. O separador `--` nunca é usado para delimitar opções de argumentos.

**Impacto:** Potencial manipulação de comportamento do git via argument injection.

**Recomendação:**
- Validar que SHAs correspondem a `/^[0-9a-f]{4,40}$/i`
- Validar que refs correspondem a padrões seguros
- Usar `--` antes de argumentos posicionais em todas as chamadas git

---

### ALTA #3 — File Paths do Usuário Interpolados em `git show`

**Arquivos:** `src/cli/commands/blame.ts:82,90`, `src/cli/commands/history.ts:86`

```typescript
contentAtCommit = await simpleGit.show([`${commit.sha}:${filePath}`]);
```

**Descrição:** O `filePath` em `blame.ts` e `history.ts` vem do input CLI do usuário e é interpolado diretamente no formato `ref:path` do `git show`.

**Impacto:** Potencial para comportamento inesperado com caminhos contendo caracteres especiais.

**Recomendação:** Validar o formato do filePath antes da interpolação.

---

### MÉDIA #1 — Nomes de Branch/Ref Não Sanitizados

**Arquivos:** `src/cli/commands/diff.ts:41-45`, `src/cli/commands/review.ts:47-50`

**Descrição:** As opções CLI `--from`, `--to`, e `--base` são passadas diretamente para comandos git sem validação. Um valor como `--exec=malicious` poderia ser mal interpretado pelo git como flag.

**Recomendação:** Validar padrões de refs e usar `--` como separador.

---

### MÉDIA #2 — Potencial ReDoS em Validação de Regras

**Arquivo:** `src/cli/commands/validate.ts:81-83`

```typescript
const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
if (!regex.test(change.filePath)) return false;
```

**Descrição:** Padrões glob de `.semrc` são convertidos em regex substituindo `*` por `.*`. Um `.semrc` malicioso poderia conter um padrão que causa catastrophic backtracking (ReDoS), como `*a*a*a*a*b`.

**Impacto:** Denial of Service em pipelines CI/CD onde um contribuidor submete um `.semrc` malicioso.

**Recomendação:** Usar uma biblioteca de glob adequada ao invés de conversão naive para regex.

---

### MÉDIA #3 — Banco de Dados sem Proteção Read-Only para Queries

**Arquivo:** `src/storage/database.ts:182-184`

**Descrição:** O método `query()` executa SQL arbitrário sem restrições. A conexão é aberta em modo WAL com acesso completo de leitura e escrita.

**Recomendação:** Usar `PRAGMA query_only = ON` para sessões de query do usuário.

---

### BAIXA #1 — Dependência Duplicada/Suspeita de SQL no package.json

**Arquivo:** `package.json:39-40`

```json
"sql-js": "^0.1.0",
"sql.js": "^1.12.0"
```

**Descrição:** Há duas dependências de SQL similares: `sql-js` (v0.1.0) e `sql.js` (v1.12.0). O pacote `sql-js@0.1.0` é um pacote obscuro (apenas 2 versões publicadas, pelo maintainer `alex030293`) e **não é** a biblioteca SQL.js legítima — é potencialmente um typosquat. Ambos estão em `devDependencies` e, crucialmente, **nenhum dos dois é importado em qualquer arquivo do código-fonte**. O projeto usa `better-sqlite3` para acesso a SQLite, tornando ambas as dependências completamente desnecessárias.

**Recomendação:** Remover `sql-js` imediatamente (potencial typosquat). Remover `sql.js` também, pois é igualmente não utilizado. Uma atualização futura de `sql-js` poderia introduzir código malicioso via install scripts.

---

### BAIXA #2 — Rust: `read_working_file` sem Validação de Limites

**Arquivo:** `crates/sem-core/src/git/bridge.rs:346-349`

```rust
fn read_working_file(&self, file_path: &str) -> Option<String> {
    let full_path = self.repo_root.join(file_path);
    fs::read_to_string(full_path).ok()
}
```

**Descrição:** No código Rust, `file_path` é concatenado com `repo_root` sem verificação de que o caminho resultante permanece dentro do repositório. Porém, neste caso o `file_path` vem do output do git (não diretamente do usuário), reduzindo o risco.

**Recomendação:** Adicionar canonicalização e verificação de limites.

---

## Análise de Supply Chain

### Dependências TypeScript (package.json)

| Pacote | Status |
|--------|--------|
| better-sqlite3 | Legítimo, amplamente usado |
| chalk | Legítimo |
| commander | Legítimo |
| csv-parse / csv-stringify | Legítimo |
| js-yaml | Legítimo |
| simple-git | Legítimo |
| smol-toml | Legítimo |
| tree-sitter + language grammars | Legítimo |
| **sql-js@0.1.0** | **INVESTIGAR** — versão muito antiga, possível typosquat |
| sql.js@1.12.0 | Legítimo |

### Dependências Rust (Cargo.toml)

Todas as dependências Rust são legítimas e amplamente usadas:
- `git2` — bindings para libgit2
- `tree-sitter` + grammars — parsing de código
- `serde` / `serde_json` / `serde_yaml` — serialização
- `zmij` — dependência transitiva de `serde_json`, mantida por dtolnay (autor do serde). Sucessor do crate `ryu` para conversão float-to-string. 18M+ downloads/mês. **Legítimo.**
- `unsafe-libyaml` — port oficial do C libyaml para Rust, mantido pelo time do serde. **Legítimo.**
- `toml`, `xxhash-rust`, `regex`, `thiserror`, `rayon` — todas legítimas

### Configurações de Build

- **Nenhum script pre/post install** no `package.json`
- **Nenhum arquivo de CI/CD** malicioso encontrado
- **Rust profile.release**: `strip = true` com LTO — normal para releases otimizadas
- **Nenhuma dependência git ou patch** nos Cargo.toml

---

## Análise do Código Rust (Segurança de Memória)

- **Nenhum bloco `unsafe`** em todo o código Rust
- **Nenhum `std::process::Command`** — usa `git2` (libgit2) como biblioteca, evitando injeção de comandos
- **Nenhuma comunicação de rede** — o código Rust é puramente local
- **Sem leitura de variáveis de ambiente** sensíveis
- O código Rust é significativamente mais seguro que a versão TypeScript por usar `git2` ao invés de shell commands

---

## Conclusão

### O repositório é malicioso? NÃO.

O `sem` **não contém** código malicioso, backdoors, ou mecanismos de roubo de chaves/credenciais. É uma ferramenta CLI legítima para análise semântica de diffs do git.

### Existem vulnerabilidades de segurança? SIM.

O projeto contém **2 vulnerabilidades críticas** e **3 altas** que poderiam ser exploradas em cenários específicos (especialmente em pipelines CI/CD onde a ferramenta é invocada com input não confiável):

1. **Command injection via `execSync`** — mitigado pelo regex check, mas frágil
2. **SQL injection no comando `query`** — permite execução arbitrária de SQL
3. **Path traversal** — permite leitura de arquivos fora do repositório
4. **Git argument injection** — refs não sanitizados podem manipular comportamento do git

### Prioridades de Correção

1. Substituir `execSync` por `execFileSync` em `review.ts`
2. Adicionar `PRAGMA query_only = ON` ao comando `query`
3. Adicionar validação de limites de path em `blame.ts` e `diff-reader.ts`
4. Validar e sanitizar todos os refs/SHAs antes de passá-los ao git
5. Remover `sql-js@0.1.0` de devDependencies (possível typosquat, não utilizado no código) e `sql.js` (igualmente não utilizado)
