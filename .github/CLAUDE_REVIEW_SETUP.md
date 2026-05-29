# Claude code review — setup

Этот репозиторий использует официальный
[Claude Code GitHub Action](https://code.claude.com/docs/en/github-actions)
для AI-ревью. Два workflow:

- `claude-review.yml` — автоматическое ревью на каждый pull request.
- `claude.yml` — ответ на упоминание `@claude` в комментариях issue/PR/ревью.

## Что нужно сделать один раз (вручную)

Workflow не заработают, пока не выполнены два шага — у них нужны права
и секрет, которые нельзя закоммитить в репозиторий.

### 1. Установить GitHub App «claude»

Проще всего из Claude Code CLI:

```
/install-github-app
```

…и пройти мастер. Либо вручную установить приложение на этот репозиторий:
<https://github.com/apps/claude>.

### 2. Добавить секрет `ANTHROPIC_API_KEY`

API-ключ берётся из Anthropic Console (<https://console.anthropic.com/>).
Затем:

```bash
gh secret set ANTHROPIC_API_KEY --repo sodazzzzzz/vpn.io
# вставить ключ по запросу (он не печатается на экран)
```

или через UI: **Settings → Secrets and variables → Actions → New repository secret**.

> Подписочный OAuth-токен Claude **не** подходит — нужен именно
> `ANTHROPIC_API_KEY`. Учти, что ревью расходует API-токены (биллинг Anthropic).

## Проверка

После обоих шагов открой тестовый PR — workflow «Claude Auto Review» должен
запуститься и оставить комментарии. В любом комментарии можно написать
`@claude ...` — ответит workflow «Claude Mention Handler».
