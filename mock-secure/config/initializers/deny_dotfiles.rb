class DenyDotfiles
  def initialize(app)
    @app = app
  end

  def call(env)
    path = Rack::Utils.clean_path_info(Rack::Utils.unescape_path(env["PATH_INFO"].to_s))
    return not_found if sensitive?(path)

    @app.call(env)
  end

  private

  def sensitive?(path)
    path.match?(%r{\A/\.}i) || path.downcase.end_with?(".env")
  end

  def not_found
    body = File.binread(Rails.public_path.join("404.html"))
    [404, {
      "content-type" => "text/html; charset=utf-8",
      "content-length" => body.bytesize.to_s,
      "X-Frame-Options" => "SAMEORIGIN",
      "Content-Security-Policy" => "default-src 'self'",
      "X-Content-Type-Options" => "nosniff",
      "cache-control" => "no-store"
    }, [body]]
  end
end

Rails.application.config.middleware.insert_before ActionDispatch::Static, DenyDotfiles
