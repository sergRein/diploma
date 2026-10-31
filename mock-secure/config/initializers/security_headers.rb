headers = Rails.application.config.action_dispatch.default_headers
headers["X-Frame-Options"] = "SAMEORIGIN"
headers["Content-Security-Policy"] = "default-src 'self'"
headers["X-Content-Type-Options"] = "nosniff"
headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
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

# Після чотирьох швидких запитів на головну віддає 429. Інші адреси не лімітує,
# щоб решта перевірок стенду не отримувала відмову.
class BurstLimit
  LIMIT = 4
  WINDOW = 3

  def initialize(app)
    @app = app
    @hits = Hash.new { |hits, key| hits[key] = [] }
    @mutex = Mutex.new
  end

  def call(env)
    blocked = limit!(env)
    if blocked
      return [
        429,
        {
          "content-type" => "text/plain; charset=utf-8",
          "retry-after" => WINDOW.to_s,
          "x-ratelimit-limit" => "100",
          "x-ratelimit-remaining" => "0"
        },
        ["Забагато запитів"]
      ]
    end

    status, headers, body = @app.call(env)
    headers["X-RateLimit-Limit"] = "100"
    headers["X-RateLimit-Remaining"] = "5"
    [status, headers, body]
  end

  private

  def limit!(env)
    return false unless env["PATH_INFO"].to_s.empty? || env["PATH_INFO"] == "/"

    key = env["REMOTE_ADDR"].to_s
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    @mutex.synchronize do
      @hits[key].reject! { |stamp| now - stamp > WINDOW }
      if @hits[key].size >= LIMIT
        true
      else
        @hits[key] << now
        false
      end
    end
  end
end

Rails.application.config.middleware.insert_before ActionDispatch::Static, ClosedCors
Rails.application.config.middleware.insert_before ClosedCors, BurstLimit
