headers = Rails.application.config.action_dispatch.default_headers
headers["X-Frame-Options"] = "SAMEORIGIN"
headers["Content-Security-Policy"] = "default-src 'self'"
headers["X-Content-Type-Options"] = "nosniff"
ActionDispatch::Response.default_headers = headers
