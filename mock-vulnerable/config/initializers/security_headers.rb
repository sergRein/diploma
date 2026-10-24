# Макет імітує сайт на Laravel: у відповідях є відбиток PHP,
# а єдина навмисна слабкість — файл public/.env, який віддає вебсервер.
class LaravelFingerprint
  STRIPPED = %w[x-frame-options content-security-policy x-content-type-options].freeze

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
    safe_headers["X-Powered-By"] = "PHP/8.3"
    [status, safe_headers, body]
  end
end


%w[X-Frame-Options Content-Security-Policy X-Content-Type-Options].each do |name|
  Rails.application.config.action_dispatch.default_headers.delete(name)
  ActionDispatch::Response.default_headers.delete(name)
end

Rails.application.config.middleware.insert_before ActionDispatch::Static, LaravelFingerprint
