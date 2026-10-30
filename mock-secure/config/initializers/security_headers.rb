headers = Rails.application.config.action_dispatch.default_headers
headers["X-Frame-Options"] = "SAMEORIGIN"
headers["Content-Security-Policy"] = "default-src 'self'"
headers["X-Content-Type-Options"] = "nosniff"
ActionDispatch::Response.default_headers = headers

# Сторонній Origin не отримує дозвіл читати відповідь.
class ClosedCors
  STRIPPED = %w[access-control-allow-origin access-control-allow-credentials].freeze

  def initialize(app)
    @app = app
  end

  def call(env)
    status, headers, body = @app.call(env)
    safe_headers = {}
    headers.each do |key, value|
      next if STRIPPED.include?(key.to_s.downcase)

      safe_headers[key] = value
    end
    [status, safe_headers, body]
  end
end

Rails.application.config.middleware.insert_before ActionDispatch::Static, ClosedCors
