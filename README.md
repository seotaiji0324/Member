# moa 회원가입 + Cloudflare D1

## 로컬 실행

```bash
npm install
npm run db:migrate:local
npm run dev
```

`http://127.0.0.1:4173`에서 가입하면 로컬 D1 `member-project`에 저장됩니다.

```bash
npx wrangler d1 execute member-project --local --command "SELECT id, name, email, status, created_at FROM users"
```

## Cloudflare 배포

```bash
npx wrangler login
npx wrangler d1 create member-project
```

생성 결과의 `database_id`를 `wrangler.jsonc`에 반영한 다음 실행합니다.

```bash
npm run db:migrate:remote
npm run deploy
```

비밀번호는 PBKDF2-SHA256 해시로만 저장됩니다.
