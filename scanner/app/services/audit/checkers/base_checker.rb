require "faraday"
require "socket"
require "uri"

module Audit
  module Checkers
    class BaseChecker
      TIMEOUT = 3
      MAX_BODY = 256 * 1024
      MAX_REDIRECTS = 2

      class FetchError < StandardError; end

      Response = Struct.new(:status, :headers, :body, keyword_init: true)

      def initialize(raw_url)
        @raw_url = raw_url.to_s.strip
      end

      def call
        perform
      rescue FetchError => error
        error_result(error.message)
      rescue Faraday::TimeoutError
        error_result("Сайт не відповів за #{TIMEOUT} секунди.")
      rescue Faraday::SSLError
        error_result("Захищене з'єднання з сайтом не склалося.")
      rescue Faraday::ConnectionFailed, SocketError
        error_result("Не вдалося з'єднатися з сайтом.")
      end

      private

      def perform
        raise NotImplementedError, "#{self.class} має реалізувати #perform"
      end

      def error_result(_message)
        raise NotImplementedError, "#{self.class} має реалізувати #error_result"
      end

      def fetch(path)
        current = build_uri(path)
        redirects = 0

        loop do
          response = request(current)
          location = redirect_target(response, current)
          return response if location.nil? || redirects >= MAX_REDIRECTS

          current = location
          redirects += 1
        end
      end

      def request(uri)
        raw = connection_for(uri).get(uri.to_s) do |req|
          req.headers["Accept"] = "text/plain,text/html;q=0.5,*/*;q=0.1"
          req.headers["User-Agent"] = "DASTLabScanner/1.0 (educational)"
        end

        Response.new(status: raw.status.to_i, headers: normalize_headers(raw.headers), body: scrub(raw.body))
      end

      def connection_for(uri)
        Faraday.new do |builder|
          builder.options.timeout = TIMEOUT
          builder.options.open_timeout = TIMEOUT
          builder.ssl.hostname = uri.host if uri.scheme == "https"
          builder.adapter Faraday.default_adapter
        end
      end

      def build_uri(path)
        base = origin
        copy = base.dup
        copy.path = path
        copy.query = nil
        copy.fragment = nil
        copy
      end

      def origin
        @origin ||= parse_user_url(@raw_url)
      end

      def parse_user_url(value)
        raise FetchError, "Вкажіть адресу сайту." if value.empty?
        raise FetchError, "Додайте http:// або https:// на початку адреси." unless value.match?(%r{\Ahttps?://}i)

        uri = URI.parse(value)
        raise FetchError, "Адреса має містити назву сайту." if uri.host.to_s.empty?
        raise FetchError, "Сканер відкриває лише адреси http та https." unless %w[http https].include?(uri.scheme&.downcase)
       
        uri.scheme = uri.scheme.downcase
        uri.fragment = nil
        uri.path = "/" if uri.path.to_s.empty?
        uri
      rescue URI::InvalidURIError
        raise FetchError, "Не вдалося прочитати адресу. Перевірте, чи немає в ній зайвих символів."
      end

      def redirect_target(response, current)
        return unless [301, 302, 303, 307, 308].include?(response.status)

        location = response.headers["location"].to_s.strip
        return if location.empty?

        URI.join(current.to_s, location)
      rescue URI::InvalidURIError
        raise FetchError, "Сайт надіслав незрозуміле перенаправлення."
      end

      def normalize_headers(headers)
        headers.each_with_object({}) do |(key, value), memo|
          memo[key.to_s.downcase] = Array(value).join(", ")
        end
      end

      def scrub(body)
        text = body.to_s.dup.byteslice(0, MAX_BODY).to_s
        text.force_encoding(Encoding::UTF_8)
        return text if text.valid_encoding?

        text.encode(Encoding::UTF_8, invalid: :replace, undef: :replace, replace: "")
      end
    end
  end
end
