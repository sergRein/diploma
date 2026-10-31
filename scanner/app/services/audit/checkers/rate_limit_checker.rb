module Audit
  module Checkers
 
    class RateLimitChecker < BaseChecker
      CATEGORY = "A07:2025 – Authentication Failures"
      ATTEMPTS = 7
      THROTTLE_HEADERS = %w[ratelimit-limit x-ratelimit-limit x-ratelimit-remaining retry-after].freeze

      def perform
        responses = Array.new(ATTEMPTS) { request(origin) }
        return limited(responses) if responses.any? { |response| limited?(response) }

        open_rate(responses)
      end

      def error_result(message)
        Result.new(
          category: CATEGORY,
          title: "Не вдалося перевірити обмеження частоти запитів",
          status: :error,
          business_risk: "Перевірку не вдалося закінчити, тому вважати, що сайт зупиняє лавину запитів, не можна. Повторіть перевірку, коли сайт відповідає.",
          technical_lang: "Серія запитів не завершилась. Причина: #{message} Висновку про обмеження частоти немає.",
          remediation_agency: "Завдання для виправлення не сформоване: сканер не отримав відповідь сайту.",
          remediation_ai_prompt: ""
        )
      end

      private

      def limited?(response)
        response.status == 429 || throttle_headers?(response)
      end

      def throttle_headers?(response)
        THROTTLE_HEADERS.any? { |name| response.headers[name].to_s.strip != "" }
      end

      def limited(responses)
        Result.new(
          category: CATEGORY,
          title: title,
          status: :passed,
          business_risk: "Сервер обмежує інтенсивність автоматичних запитів та захищає ресурси від перевантаження.",
          technical_lang: technical_for(responses, :passed),
          remediation_agency: "Серед #{ATTEMPTS} швидких запитів є 429 або заголовки обмеження частоти. Окреме завдання не потрібне.",
          remediation_ai_prompt: ""
        )
      end

      def open_rate(responses)
        Result.new(
          category: CATEGORY,
          title: title,
          status: :warning,
          business_risk: "Сервер не обмежує швидкість однотипних запитів з однієї IP-адреси. #{risk_detail}",
          technical_lang: technical_for(responses, :warning),
          remediation_agency: agency_for(responses.first),
          remediation_ai_prompt: prompt_for(responses.first)
        )
      end

      def title
        "Захист від масового підбору та перевантаження (Rate Limiting)"
      end

      def risk_detail
        "Сайт не обмежує частоту звернень від одного відвідувача або бота. " \
        "Це дозволяє зловмисникам підбирати паролі до облікових записів без зупинки, викачувати бази даних або спричинити зависання сервера через лавину автоматичних запитів."
      end

      def technical_for(responses, status)
        codes = responses.map(&:status).join(", ")
        found = THROTTLE_HEADERS.select { |name| responses.any? { |response| response.headers[name].to_s.strip != "" } }
        headers = found.empty? ? "немає" : found.join(", ")
        verdict = if status == :passed
          "Зелений статус: сервер показав ліміт або відповів 429."
        else
          "Жовтий статус: усі відповіді без 429 і без заголовків обмеження частоти."
        end

        <<~TEXT.strip
          Зроблено #{ATTEMPTS} запитів GET #{origin}.
          Статуси: #{codes}.
          Заголовки ліміту: #{headers}.
          #{verdict}
          Це OWASP Top 10 #{CATEGORY}.
          Запити однакові і без паролів. Сканер не підбирає облікові дані.
        TEXT
      end

      def agency_for(response)
        platform = app_platform(response)
        server = web_server(response)
        <<~TEXT.strip
          Завдання: налаштуйте обмеження частоти запитів з однієї IP-адреси. Після короткої серії однакових запитів сервер має відповідати 429.

          Платформа за відбитками відповіді: #{platform_name(platform, server)}.

          Зробити:
          #{agency_steps(platform, server)}
          Готово, коли кілька швидких запитів з однієї адреси отримують 429 або заголовки ліміту на кшталт X-RateLimit-Limit і Retry-After.
        TEXT
      end

      def agency_steps(platform, server)
        case platform
        when :laravel
          <<~TEXT.strip
            1. Увімкніть throttle у маршрутах Laravel, наприклад throttle:5,1 для входу. Не лишайте ліміт лише на одній сторінці.
            2. Продублюйте ліміт на вебсервері, інакше лавина дійде до PHP:
            #{front_steps(server)}
          TEXT
        when :symfony
          <<~TEXT.strip
            1. У framework.yaml увімкніть rate_limiter і повісьте його на вхід та форми. Ліміт має відповідати 429.
            2. Продублюйте ліміт на вебсервері:
            #{front_steps(server)}
          TEXT
        when :yii
          <<~TEXT.strip
            1. Увімкніть фільтр yii\\filters\\RateLimiter для входу і форм. Відповідь надлишку має бути 429.
            2. Продублюйте ліміт на вебсервері:
            #{front_steps(server)}
          TEXT
        when :wordpress
          <<~TEXT.strip
            1. Обмежте число спроб входу на wp-login.php. Не закривайте цим публічні сторінки для всіх відвідувачів.
            2. Загальний ліміт запитів з однієї IP поставте на вебсервері:
            #{front_steps(server)}
          TEXT
        when :php
          <<~TEXT.strip
            1. Фреймворк за головною не визначити. Ліміт поставте на вебсервері:
            #{front_steps(server)}
          TEXT
        when :django
          <<~TEXT.strip
            1. Обмежте частоту через django-ratelimit на вході і формах. У стандартному SecurityMiddleware ліміту запитів немає.
            2. Продублюйте ліміт на вебсервері:
            #{front_steps(server)}
          TEXT
        when :flask
          <<~TEXT.strip
            1. Підключіть Flask-Limiter: не більше кількох запитів з однієї IP за короткий інтервал, відповідь 429.
            2. Продублюйте ліміт на вебсервері:
            #{front_steps(server)}
          TEXT
        when :rails
          <<~TEXT.strip
            1. Підключіть Rack::Attack. Обмежте одну IP, наприклад не більше 5 запитів за 3 секунди, і відповідайте 429.
            2. Якщо перед Rails стоїть вебсервер, продублюйте ліміт там:
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
          "Apache httpd, модуль mod_evasive:",
          "   DOSPageCount 5",
          "   DOSPageInterval 1",
          "Надлишок запитів з однієї IP має отримувати 429, не тиху відмову без пояснення."
        ].join("\n")
      end

      def nginx_steps
        [
          "nginx:",
          "   limit_req_zone $binary_remote_addr zone=dast:10m rate=5r/s;",
          "   limit_req zone=dast burst=5 nodelay;",
          "   limit_req_status 429;"
        ].join("\n")
      end

      def prompt_for(response)
        platform = app_platform(response)
        server = web_server(response)
        <<~TEXT.strip
          Сайт не обмежує частоту однакових запитів з однієї IP-адреси. Після короткої серії сервер має відповідати HTTP 429.
          Схоже, що проєкт — #{platform_name(platform, server)}.
          #{prompt_steps(platform, server)}
          Не пропонуй підбір паролів. Поясни простою мовою, що змінилось.
        TEXT
      end

      def prompt_steps(platform, server)
        front = case server
        when :apache
          "Вебсервер — Apache httpd. Напиши фрагмент mod_evasive: DOSPageCount і DOSPageInterval, надлишок з однієї IP відповідає 429. Конфіг nginx не пропонуй."
        when :nginx
          "Вебсервер — nginx. Напиши limit_req_zone за $binary_remote_addr і limit_req_status 429."
        else
          "Вебсервер не визначити: дай варіант і для Apache (mod_evasive), і для nginx (limit_req_zone, код 429)."
        end

        case platform
        when :laravel
          "Це Laravel. Увімкни throttle на вході, наприклад 5 запитів за хвилину з однієї IP, відповідь 429. #{front} Конфіг Rails не пропонуй."
        when :symfony
          "Це Symfony. Налаштуй rate_limiter у framework.yaml на вхід і форми, відповідь 429. #{front} Конфіг Rails не пропонуй."
        when :yii
          "Це Yii. Увімкни yii\\filters\\RateLimiter на вході, відповідь 429. #{front} Конфіг Rails не пропонуй."
        when :wordpress
          "Це WordPress. Обмеж число спроб входу на wp-login.php і не закривай цим звичайні сторінки. #{front} Конфіг Rails не пропонуй."
        when :php
          "Це PHP, точний фреймворк невідомий. #{front} Якщо це Laravel, Symfony або Yii, продублюй ліміт у фреймворку. Конфіг Rails не пропонуй."
        when :django
          "Це Django. Обмеж частоту через django-ratelimit. У стандартному SecurityMiddleware такого ліміту немає. #{front}"
        when :flask
          "Це Flask. Підключи Flask-Limiter: кілька запитів з однієї IP за короткий інтервал і відповідь 429. #{front}"
        when :rails
          "Це Ruby on Rails. Налаштуй Rack::Attack: не більше 5 запитів за 3 секунди з однієї IP і відповідь HTTP 429. #{front}"
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
