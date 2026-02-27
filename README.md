# E-Commerce API

A simple Flask-based REST API for an e-commerce platform.

## Endpoints

- `POST /api/auth/register` — Register a new user
- `POST /api/auth/login` — Login and get JWT token
- `POST /api/orders` — Create an order (auth required)
- `GET /api/orders` — List your orders (auth required)
- `GET /api/orders/:id` — Get order details (auth required)
- `GET /api/admin/users` — List users (admin only)
- `GET /api/admin/stats` — Platform stats (admin only)

## Running

```bash
pip install -r requirements.txt
flask run
```

(c) 2026
