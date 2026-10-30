
class LaravelFingerprint
  STRIPPED = %w[x-frame-options content-security-policy x-content-type-options].freeze

  def initialize(app)
    @app = app
  end

  def call(env)
    status, headers, body = @app.call(env)
    safe_headers = {}
    headers.each do |key, value|
      next if (STRIPPED + %w[server]).include?(key.to_s.downcase)

      safe_headers[key] = value
    end
    safe_headers["X-Powered-By"] = "PHP/8.3"
    safe_headers["Server"] = "Apache/2.4.62 (Debian)"
    reflect_cors(env, safe_headers)
    [status, safe_headers, body]
  end

  private

  def reflect_cors(env, headers)
    origin = env["HTTP_ORIGIN"].to_s.strip
    return if origin.empty?

    headers["Access-Control-Allow-Origin"] = origin
    headers["Access-Control-Allow-Credentials"] = "true"
  end
end


%w[X-Frame-Options Content-Security-Policy X-Content-Type-Options].each do |name|
  Rails.application.config.action_dispatch.default_headers.delete(name)
  ActionDispatch::Response.default_headers.delete(name)
end

Rails.application.config.middleware.insert_before ActionDispatch::Static, LaravelFingerprint
