# Claude code review — setup

Этот репозиторий использует официальный
[Claude Code GitHub Action](https://code.claude.com/docs/en/github-actions)
для AI-ревью. Два workflow:

- `claude-review.yml` — автоматическое ревью на каждый pull request.
- `claude.yml` — ответ на упоминание `@claude` в комментариях issue/PR/ревью.

## Что нужно сделать один раз (вручную)

Workflow не заработают, пока не выполнены два шага — у них нужны права
и секрет, которые нельзя закоммитить в репозиторий.

### 1. Установить GitHub App «claude» + завести токен

Проще всего из Claude Code CLI:

```
/install-github-app
```

Мастер установит приложение на репозиторий и заведёт секрет
`CLAUDE_CODE_OAUTH_TOKEN` (токен от твоей подписки Claude — отдельный
API-биллинг не нужен). Альтернатива: установить приложение вручную с
<https://github.com/apps/claude> и сгенерировать токен через
`claude setup-token`.

### 2. Проверить, что секрет на месте

```bash
gh secret list --repo sodazzzzzz/vpn.io
# должен быть CLAUDE_CODE_OAUTH_TOKEN
```

Если токена нет — повтори `/install-github-app` или добавь вручную:

```bash
gh secret set CLAUDE_CODE_OAUTH_TOKEN --repo sodazzzzzz/vpn.io
```

> Workflow аутентифицируются параметром `claude_code_oauth_token`. Если
> предпочитаешь оплату по API-токенам Anthropic — можно заменить его на
> `anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}` в обоих файлах и
> завести секрет `ANTHROPIC_API_KEY` вместо OAuth-токена.

## Проверка

После настройки открой тестовый PR — workflow «Claude Auto Review» должен
запуститься и оставить комментарии. В любом комментарии можно написать
`@claude ...` — ответит workflow «Claude Mention Handler».
