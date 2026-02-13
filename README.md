# School Admin API

Admin CMS backend for Al Hikmah Private School.

## Stack
- Node.js + Express
- MongoDB + Mongoose
- Session auth with token validation
- Cloudinary image upload
- Node test runner + Supertest API tests

## Local Setup
1. `npm install`
2. Copy `.env.example` to `.env`
3. Configure required environment variables
4. `npm run dev`

## Quality Gates
- Syntax check: `node --check server.js`
- Tests: `npm test`

## Environment Variables
- `MONGODB_URI` (required outside test mode)
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD` (required)
- `SESSION_SECRET` (required in production)
- `TOKEN_SECRET` (required in production)
- `FRONTEND_URL`
- `CLOUDINARY_CLOUD_NAME`
- `CLOUDINARY_API_KEY`
- `CLOUDINARY_API_SECRET`
- `PORT`

## Security Notes
- API rate limiting is enabled.
- Helmet headers are enabled.
- Login brute-force protection is enabled.
- Production rejects missing `SESSION_SECRET` and `TOKEN_SECRET`.

## CI
- GitHub Actions workflow: `.github/workflows/ci.yml`
