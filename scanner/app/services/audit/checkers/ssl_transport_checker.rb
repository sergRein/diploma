module Audit
  module Checkers
    # Зелений статус лише для https із валідним HSTS. На відкритому http браузер
    # заголовок ігнорує, навіть якщо сервер його віддав (RFC 6797).
    class SslTransportChecker < BaseChecker
      CATEGORY = "A04:2025 – Cryptographic Failures"
      UPGRADE_STATUSES = [301, 302, 308].freeze

      def perform
        uri = origin
        response = request(uri)
        is_https = uri.scheme == "https"
        hsts_header = response.headers["strict-transport-security"].to_s.strip

        return full_protection(response, hsts_header) if is_https && hsts_valid?(hsts_header)
        return partial_protection(response, hsts_header) if !is_https && !hsts_header.empty?
        return missing_policy(response, hsts_header) if is_https

        open_transport(response, hsts_header)
      end

      def error_result(message)
        Result.new(
          category: CATEGORY,
          title: "Не вдалося перевірити шифрування з'єднання",
          status: :error,
          business_risk: "Перевірку не вдалося закінчити, тому вважати, що з'єднання примусово шифрується, не можна. Повторіть перевірку, коли сайт відповідає.",
          technical_lang: "Запит до сайту не завершився. Причина: #{message} Висновку про HSTS і перехід на https немає.",
          remediation_agency: "Завдання для виправлення не сформоване: сканер не отримав відповідь сайту.",
          remediation_ai_prompt: ""
        )
      end

      private

      def full_protection(response, header)
        Result.new(
          category: CATEGORY,
          title: title,
          status: :passed,
          business_risk: "Транспортний рівень повністю зашифровано (HTTPS) та захищено політикою HSTS.",
          technical_lang: technical_for(response, header, :passed),
          remediation_agency: "Адреса відкрита по https, а Strict-Transport-Security містить max-age більше нуля. Окреме завдання не потрібне.",
          remediation_ai_prompt: ""
        )
      end

      def partial_protection(response, header)
        Result.new(
          category: CATEGORY,
          title: title,
          status: :warning,
          business_risk: "Заголовок HSTS налаштовано, але з'єднання здійснено через незахищений протокол HTTP. За стандартами безпеки (RFC 6797) браузери ігноруватимуть цей заголовок, доки на сервері не буде активовано дійсний SSL-сертифікат та примусовий редірект на https://.",
          technical_lang: technical_for(response, header, :warning),
          remediation_agency: warning_agency(response),
          remediation_ai_prompt: prompt_for(response, :warning)
        )
      end

      def missing_policy(response, header)
        Result.new(
          category: CATEGORY,
          title: title,
          status: :warning,
          business_risk: "З'єднання йде через HTTPS, але валідної політики HSTS з max-age немає. Браузер не запам'ятовує заборону відкритого http, тож перший візит іще можна підмінити.",
          technical_lang: technical_for(response, header, :warning),
          remediation_agency: agency_for(response),
          remediation_ai_prompt: prompt_for(response, :warning)
        )
      end

      def open_transport(response, header)
        Result.new(
          category: CATEGORY,
          title: title,
          status: :failed,
          business_risk: "Сайт передає дані відкритим текстом без шифрування. Будь-хто в мережі може перехопити паролі або персональні дані клієнтів.",
          technical_lang: technical_for(response, header, :failed),
          remediation_agency: agency_for(response),
          remediation_ai_prompt: prompt_for(response, :failed)
        )
      end

      def hsts_valid?(header)
        age = max_age(header)
        age && age.positive?
      end

      def max_age(header)
        match = header.to_s.match(/max-age\s*=\s*"?(\d+)"?/i)
        return nil unless match

        match[1].to_i
      end

      def https_upgrade_target(response)
        return unless UPGRADE_STATUSES.include?(response.status)

        location = response.headers["location"].to_s.strip
        return if location.empty?

        target = URI.join(origin.to_s, location)
        return unless target.scheme == "https"
        return unless target.host.to_s.casecmp?(origin.host.to_s)

        target
      rescue URI::InvalidURIError
        nil
      end

      def title
        "Шифрування з'єднання та захист від перехоплення (SSL / HSTS)"
      end

      def technical_for(response, header, status)
        shown = header.to_s.empty? ? "немає" : header
        age = max_age(header)
        age_line = age.nil? ? "Директиви max-age немає." : "max-age #{age}."
        verdict = case status
        when :passed
          "Зелений статус: адреса https і max-age більше нуля."
        when :warning
          https? ? "Жовтий статус: канал https є, валідного HSTS немає." : "Жовтий статус: заголовок є, але схема http, тож браузер його не застосує."
        else
          "Червоний статус: відкритий http без заголовка HSTS."
        end

        <<~TEXT.strip
          GET #{origin} повернув HTTP #{response.status}. Схема адреси: #{origin.scheme}.
          Strict-Transport-Security: #{shown}.
          #{age_line}
          #{redirect_line(response)}
          #{verdict}
          Це OWASP Top 10 #{CATEGORY}.
          RFC 6797: браузер приймає Strict-Transport-Security лише з відповіді по https. Той самий заголовок на відкритому http ігнорується.
        TEXT
      end

      def redirect_line(response)
        target = https_upgrade_target(response)
        return "Переходу на https немає." unless target

        "Є перехід #{response.status} на #{target}."
      end

      def https?
        origin.scheme == "https"
      end

      def warning_agency(response)
        <<~TEXT.strip
          Підключіть SSL/TLS сертифікат та переконайтеся, що всі HTTP-запити перенаправляються на HTTPS.

          Платформа за відбитками відповіді: #{platform_name(app_platform(response), web_server(response))}.
          Заголовок на відповіді http браузер не зарахує. HSTS з max-age має віддавати вже відповідь https.

          Зробити:
          #{agency_steps(app_platform(response), web_server(response))}
        TEXT
      end

      def agency_for(response)
        <<~TEXT.strip
          Завдання: увімкніть заголовок Strict-Transport-Security (HSTS) у конфігурації веб-сервера та налаштуйте автоматичний редірект (HTTP 301) з протоколу http:// на https://.

          Платформа за відбитками відповіді: #{platform_name(app_platform(response), web_server(response))}.

          Зробити:
          #{agency_steps(app_platform(response), web_server(response))}
          Готово, коли відповідь по https містить Strict-Transport-Security з max-age більше нуля, а запит на http перенаправляє на https.
        TEXT
      end

      def agency_steps(platform, server)
        case platform
        when :laravel
          <<~TEXT.strip
            1. У AppServiceProvider викличте URL::forceScheme('https'). У TrustProxies довірте проксі, інакше Laravel за ним і далі бачить http.
            2. Редірект 301 і заголовок HSTS поставте на вебсервері. Заголовок лише у відповіді http браузер ігнорує.
            #{front_steps(server)}
            3. Конфіг Ruby on Rails не пропонуйте.
          TEXT
        when :symfony
          <<~TEXT.strip
            1. У config/packages/framework.yaml поставте cookie_secure: auto, trusted_headers з x-forwarded-proto і trusted_proxies для проксі.
            2. Редірект 301 і HSTS зробіть на вебсервері. Прапорець куки сам по собі з'єднання не шифрує.
            #{front_steps(server)}
            3. Конфіг Ruby on Rails не пропонуйте.
          TEXT
        when :yii
          <<~TEXT.strip
            1. У конфігу request увімкніть secure-куки. У beforeRequest перенаправляйте на https, якщо схема ще http.
            2. Той самий редірект 301 і HSTS продублюйте на вебсервері.
            #{front_steps(server)}
            3. Конфіг Ruby on Rails не пропонуйте.
          TEXT
        when :wordpress
          <<~TEXT.strip
            1. У загальних налаштуваннях адреси siteurl і home мають починатися з https://. У wp-config.php для адмінки: define('FORCE_SSL_ADMIN', true);
            2. Редірект усіх запитів http і заголовок HSTS зробіть на вебсервері. Плагін сертифікат не замінює.
            #{front_steps(server)}
            3. Конфіг Ruby on Rails не пропонуйте.
          TEXT
        when :php
          <<~TEXT.strip
            1. Точний фреймворк за головною не визначити, тому редірект і HSTS ставте на вебсервері:
            #{front_steps(server)}
            2. Якщо це Laravel, Yii або Symfony, продублюйте примусовий https у конфігу фреймворка. Конфіг Ruby on Rails не пропонуйте.
          TEXT
        when :django
          <<~TEXT.strip
            1. Поставте SECURE_SSL_REDIRECT = True, SECURE_HSTS_SECONDS = 31536000 і SECURE_HSTS_INCLUDE_SUBDOMAINS = True. За проксі додайте SECURE_PROXY_SSL_HEADER.
            2. Django віддає HSTS лише на https, тож редірект з http має спрацювати раніше. Продублюйте його на вебсервері:
            #{front_steps(server)}
          TEXT
        when :flask
          <<~TEXT.strip
            1. Поставте SESSION_COOKIE_SECURE = True. Окремого параметра SECURE_HSTS_SECONDS у Flask немає: редірект і HSTS зробіть на вебсервері або через Talisman.
            #{front_steps(server)}
          TEXT
        when :rails
          <<~TEXT.strip
            1. У config/environments/production.rb поставте config.force_ssl = true. Це і редірект на https, і заголовок HSTS.
            2. Якщо перед Rails стоїть вебсервер, продублюйте 301 і заголовок там, інакше його сторінки помилок лишаться без HSTS:
            #{front_steps(server)}
          TEXT
        else
          front_steps(server)
        end
      end

      def front_steps(server)
        case server
        when :apache
          apache_steps
        when :nginx
          nginx_steps
        else
          "#{apache_steps}\n#{nginx_steps}"
        end
      end

      def apache_steps
        [
          "Apache httpd, модулі mod_rewrite і mod_headers.",
          "На порту 80:",
          "   RewriteEngine On",
          "   RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]",
          "На порту 443:",
          "   Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\""
        ].join("\n")
      end

      def nginx_steps
        [
          "nginx:",
          "   return 301 https://$host$request_uri;",
          "   add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"
        ].join("\n")
      end

      def prompt_for(response, status)
        platform = app_platform(response)
        server = web_server(response)
        reason = if status == :warning && !https?
          "Заголовок Strict-Transport-Security прийшов по http. За RFC 6797 браузер його ігнорує, доки немає дійсного сертифіката і редіректу на https."
        elsif status == :warning
          "Сайт відкривається по https, але валідного Strict-Transport-Security з max-age немає."
        else
          "Сайт віддає дані відкритим http без шифрування і без політики HSTS."
        end

        <<~TEXT.strip
          #{reason}
          Потрібен редірект 301 з http на https і заголовок Strict-Transport-Security з max-age=31536000 та includeSubDomains саме на відповіді https.
          Схоже, що проєкт — #{platform_name(platform, server)}.
          #{prompt_steps(platform, server)}
          Не вимикай HSTS через max-age=0 і не залишай заголовок лише на http. Поясни простою мовою, що змінилось.
        TEXT
      end

      def prompt_steps(platform, server)
        front = case server
        when :apache
          "Вебсервер — Apache httpd. Напиши конфіг mod_rewrite (301 на https) і mod_headers: Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\". Конфіг nginx не пропонуй."
        when :nginx
          "Вебсервер — nginx. Напиши return 301 https://$host$request_uri і add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always."
        else
          "Вебсервер не визначити: дай варіант і для Apache (RewriteRule і Header always set), і для nginx (return 301 і add_header always)."
        end

        case platform
        when :laravel
          "Це Laravel. У AppServiceProvider додай URL::forceScheme('https') і налаштуй TrustProxies. #{front} Конфіг Rails не пропонуй."
        when :symfony
          "Це Symfony. У framework.yaml постав cookie_secure: auto, trusted_proxies і trusted_headers з x-forwarded-proto. #{front} Конфіг Rails не пропонуй."
        when :yii
          "Це Yii. Увімкни secure-куки і редірект на https у beforeRequest. #{front} Конфіг Rails не пропонуй."
        when :wordpress
          "Це WordPress. Постав адреси siteurl і home на https:// і define('FORCE_SSL_ADMIN', true) у wp-config.php. #{front} Конфіг Rails не пропонуй."
        when :php
          "Це PHP, точний фреймворк невідомий. #{front} Якщо це Laravel, Yii або Symfony, продублюй примусовий https у конфігу фреймворка. Конфіг Rails не пропонуй."
        when :django
          "Це Django. Увімкни SECURE_SSL_REDIRECT = True, SECURE_HSTS_SECONDS = 31536000 і SECURE_HSTS_INCLUDE_SUBDOMAINS = True. За проксі додай SECURE_PROXY_SSL_HEADER. #{front}"
        when :flask
          "Це Flask. Постав SESSION_COOKIE_SECURE = True. Окремого SECURE_HSTS_SECONDS у Flask немає, тож HSTS і редірект дай на вебсервері або через Talisman. #{front}"
        when :rails
          "Це Ruby on Rails. Увімкни config.force_ssl = true у production. #{front}"
        when :apache
          "Фреймворк за головною не визначити. #{front}"
        else
          front
        end
      end

      def app_platform(response)
        powered = response.headers["x-powered-by"].to_s
        server = response.headers["server"].to_s
        cookie = response.headers["set-cookie"].to_s
        body = response.body.to_s

        return :laravel if cookie.match?(/laravel_session/i) || powered.match?(/laravel/i)
        return :symfony if powered.match?(/symfony/i) || cookie.match?(/symfony/i) || response.headers.key?("x-debug-token")
        return :yii if cookie.match?(/YII_CSRF_TOKEN|_csrf-frontend|_csrf-backend/i)
        return :wordpress if cookie.match?(/wordpress_|wp-settings/i) || body.match?(/wp-content\/|wp-includes\//i)
        return :php if powered.match?(/php/i)
        return :django if powered.match?(/python|django|wsgi/i) || server.match?(/gunicorn|django/i)
        return :flask if powered.match?(/flask|werkzeug/i) || server.match?(/werkzeug/i)
        return :rails if powered.match?(/rails|phusion|passenger/i) || response.headers.key?("x-runtime")
        return :apache if server.match?(/apache/i) && !server.match?(/tomcat|coyote/i)
        return :nginx if server.match?(/nginx/i)

        nil
      end

      def web_server(response)
        server = response.headers["server"].to_s
        return :apache if server.match?(/apache/i) && !server.match?(/tomcat|coyote/i)
        return :nginx if server.match?(/nginx/i)

        nil
      end

      def platform_name(platform, server)
        front = { apache: " Попереду Apache httpd (заголовок Server)", nginx: " Попереду nginx (заголовок Server)" }.fetch(server, "")
        front = "" if %i[apache nginx].include?(platform)
        name = {
          laravel: "Laravel (PHP). На це вказує сесійна кука або підпис Laravel",
          symfony: "Symfony (PHP). На це вказує підпис Symfony або заголовок X-Debug-Token",
          yii: "Yii (PHP). На це вказує кука YII_CSRF_TOKEN або _csrf-frontend",
          wordpress: "WordPress. На це вказують куки wordpress_ або шляхи wp-content у сторінці",
          php: "PHP. На це вказує заголовок X-Powered-By. Точний фреймворк за головною не визначити",
          django: "Django (Python). На це вказують заголовки сервера або X-Powered-By",
          flask: "Flask (Python). На це вказує підпис Werkzeug",
          rails: "Ruby on Rails. На це вказує заголовок X-Runtime або підпис сервера застосунку",
          apache: "сайт за Apache httpd. Фреймворк за головною не визначити",
          nginx: "сайт за nginx. Фреймворк за головною не визначити"
        }.fetch(platform, "не визначено")

        return name if front.empty?

        "#{name}.#{front}"
      end
    end
  end
end
