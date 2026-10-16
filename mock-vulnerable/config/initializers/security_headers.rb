# Макет імітує сайт на Laravel: у відповідях є відбиток PHP,
# а єдина навмисна слабкість — файл public/.env, який віддає вебсервер.
class LaravelFingerprint
  def initialize(app)
    @app = app
  end

  def call(env)
    status, headers, body = @app.call(env)
    safe_headers = {}
    headers.each { |key, value| safe_headers[key] = value }
    safe_headers["X-Powered-By"] = "PHP/8.3"
    [status, safe_headers, body]
  end
end

Rails.application.config.middleware.insert_before ActionDispatch::Static, LaravelFingerprint
