module Audit
  module Checkers
    # Запит із чужим Origin. Дивимось, чи сервер пускає цей сайт читати відповідь.
    class CorsPolicyChecker < BaseChecker
      CATEGORY = "A01:2025 – Broken Access Control"
      PROBE_ORIGIN = "https://untrusted-external-domain.example"

      def perform
        response = fetch(page_path, headers: { "Origin" => PROBE_ORIGIN })
        allow_origin = response.headers["access-control-allow-origin"].to_s.strip
        credentials = credentials?(response)
        return exposed(response, allow_origin, credentials) if risky?(allow_origin)

        closed(response, allow_origin)
      end

      def error_result(message)
        Result.new(
          category: CATEGORY,
          title: "Не вдалося перевірити міждоменний доступ",
          status: :error,
          business_risk: "Перевірку не вдалося закінчити, тому вважати, що чужий сайт не читає відповіді ваших клієнтів, не можна. Повторіть перевірку, коли сайт відповідає.",
          technical_lang: "Запит із чужим Origin не завершився. Причина: #{message} Висновку про CORS немає.",
          remediation_agency: "Завдання для виправлення не сформоване: сканер не отримав відповідь сайту.",
          remediation_ai_prompt: ""
        )
      end

      private

      def page_path
        origin.path.to_s.empty? ? "/" : origin.path
      end

      def credentials?(response)
        response.headers["access-control-allow-credentials"].to_s.strip.casecmp?("true")
      end

      def risky?(allow_origin)
        wildcard?(allow_origin) || reflected?(allow_origin)
      end

      def wildcard?(allow_origin)
        allow_origin.split(",").any? { |part| part.strip == "*" }
      end

      def reflected?(allow_origin)
        allow_origin.casecmp?(PROBE_ORIGIN)
      end

      def exposed(response, allow_origin, credentials)
        Result.new(
          category: CATEGORY,
          title: title,
          status: failed_status(allow_origin, credentials),
          business_risk: business_risk,
          technical_lang: technical_for(response, allow_origin, credentials, open: true),
          remediation_agency: agency_for(response, allow_origin, credentials),
          remediation_ai_prompt: prompt_for(response, allow_origin, credentials)
        )
      end

      def closed(response, allow_origin)
        Result.new(
          category: CATEGORY,
          title: title,
          status: :passed,
          business_risk: "Чужий сайт не отримав дозволу читати відповіді цього сайту. Або заголовка доступу немає, або в ньому не той домен, з якого йшла перевірка.",
          technical_lang: technical_for(response, allow_origin, false, open: false),
          remediation_agency: "Запит із Origin #{PROBE_ORIGIN} не отримав небезпечного Access-Control-Allow-Origin. Окреме завдання не потрібне.",
          remediation_ai_prompt: ""
        )
      end

      def failed_status(allow_origin, credentials)
        return :warning if wildcard?(allow_origin) && !credentials
        return :warning if reflected?(allow_origin) && !credentials

        :failed
      end

      def title
        "Політика міждоменного доступу до даних (CORS)"
      end

      def business_risk
        "Сайт налаштований так, що сторонні веб-ресурси можуть відправляти фонові запити через браузер ваших клієнтів і зчитувати конфіденційні відповіді сервера. " \
          "Це дозволяє шахраям красти приватні дані користувачів або результати їхніх замовлень через сторонні сайти."
      end

      def technical_for(response, allow_origin, credentials, open:)
        shown = allow_origin.empty? ? "немає" : allow_origin
        verdict = if !open
          "Чужий Origin відхилено або дозвіл обмежений іншим доменом."
        elsif credentials
          "Червоний статус: чужий сайт може читати відповідь разом із куками клієнта."
        else
          "Жовтий статус: доступ відкритий широко, але без дозволу передавати куки."
        end

        <<~TEXT.strip
          GET #{origin} з заголовком Origin: #{PROBE_ORIGIN} повернув HTTP #{response.status}.
          Access-Control-Allow-Origin: #{shown}.
          Access-Control-Allow-Credentials: #{credentials ? "true" : "немає"}.
          #{verdict}
          Це OWASP Top 10 #{CATEGORY}.
          Сам вміст відповіді у звіт не копіюється.
        TEXT
      end

      def agency_for(response, allow_origin, credentials)
        <<~TEXT.strip
          Завдання: обмежте заголовок Access-Control-Allow-Origin. Дозвольте доступ лише довіреним доменам вашої компанії або повністю приберіть заголовок, якщо сайт не надає публічне відкрите API для сторонніх додатків.

          Зараз у відповіді: #{allow_origin}. Куки #{credentials ? "дозволені" : "не дозволені"}.
          Платформа за відбитками відповіді: #{platform_name(detect_platform(response), web_server(response))}.

          Зробити:
          #{agency_steps(detect_platform(response), web_server(response))}
          Готово, коли запит із чужим Origin не повертає ні *, ні цей чужий домен у Access-Control-Allow-Origin.
        TEXT
      end

      def agency_steps(platform, server)
        case platform
        when :laravel
          <<~TEXT.strip
            1. У config/cors.php Laravel не ставте allowed_origins => ['*'] разом із supports_credentials => true.
            2. Перелічіть лише домени компанії. Не копіюйте заголовок Origin із запиту назад у відповідь.
            3. #{front_cors_step(server)} Інакше вебсервер перекриє налаштування Laravel.
          TEXT
        when :php
          <<~TEXT.strip
            1. #{front_cors_step(server)}
            2. Якщо це Laravel або Yii, у конфігу CORS лишіть лише домени компанії. Не вмикайте credentials для зірочки.
            3. Конфіг Ruby on Rails для цього сайту не пропонуйте.
          TEXT
        when :rails
          <<~TEXT.strip
            1. У rack-cors або middleware перелічіть origins явним списком. Не використовуйте origins '*' разом із credentials: true.
            2. Не віддавайте request.origin назад без перевірки, що це ваш домен.
            3. #{front_cors_step(server)} якщо той самий заголовок додає ще й вебсервер перед Rails.
          TEXT
        when :django
          <<~TEXT.strip
            1. У django-cors-headers поставте CORS_ALLOW_ALL_ORIGINS = False і CORS_ALLOWED_ORIGINS зі списком доменів компанії.
            2. CORS_ALLOW_CREDENTIALS = True лише разом із цим списком, не з зірочкою.
            3. #{front_cors_step(server)} якщо заголовок дублює вебсервер.
          TEXT
        when :apache
          apache_cors_steps
        else
          server == :nginx ? nginx_cors_steps : apache_or_nginx_cors_steps
        end
      end

      def front_cors_step(server)
        case server
        when :apache
          "В Apache (mod_headers) приберіть Header set Access-Control-Allow-Origin \"*\" і копіювання %{HTTP_ORIGIN}e назад у відповідь."
        when :nginx
          "В nginx приберіть add_header Access-Control-Allow-Origin * і рядок, який підставляє $http_origin."
        else
          "У вебсервері приберіть зірочку і підстановку чужого Origin: для Apache це Header set, для nginx — add_header."
        end
      end

      def apache_cors_steps
        <<~TEXT.strip
          1. Увімкніть mod_headers. У віртуальному хості або в .htaccess приберіть Header set Access-Control-Allow-Origin "*" і будь-яке копіювання %{HTTP_ORIGIN}e.
          2. Якщо стороннім сайтам API не потрібне, ці заголовки приберіть. Якщо потрібне, лишіть лише домен компанії: Header always set Access-Control-Allow-Origin "https://shop.example".
          3. Access-Control-Allow-Credentials "true" ставте лише разом із явним доменом, ніколи із зірочкою.
        TEXT
      end

      def nginx_cors_steps
        <<~TEXT.strip
          1. У nginx приберіть Access-Control-Allow-Origin * і підстановку довільного Origin.
          2. Якщо API справді потрібне іншим сайтам, перелічіть їхні домени явно. Інакше заголовок приберіть зовсім.
        TEXT
      end

      def apache_or_nginx_cors_steps
        <<~TEXT.strip
          1. Вебсервер за головною не визначити. Приберіть зірочку і підстановку чужого Origin.
          2. Apache: Header set Access-Control-Allow-Origin "*" і %{HTTP_ORIGIN} прибрати. Дозвіл лише на домен компанії, або заголовок прибрати зовсім.
          3. nginx: те саме через add_header і $http_origin. Credentials не вмикайте разом із зірочкою.
        TEXT
      end

      def prompt_for(response, allow_origin, credentials)
        platform = detect_platform(response)
        server = web_server(response)
        <<~TEXT.strip
          Сайт віддає небезпечну політику CORS. Access-Control-Allow-Origin зараз #{allow_origin}, credentials: #{credentials ? "true" : "немає"}.
          Схоже, що проєкт — #{platform_name(platform, server)}.
          #{prompt_steps(platform, server)}
          Не пропонуй лишати зірочку. Поясни простою мовою, що змінилось.
        TEXT
      end

      def prompt_steps(platform, server)
        front = case server
        when :apache
          "Вебсервер — Apache httpd. Напиши фрагмент mod_headers: прибери Header set Access-Control-Allow-Origin \"*\" і копіювання %{HTTP_ORIGIN}e. Дозволь лише явний список доменів, або прибери заголовок. Credentials не став разом із зірочкою."
        when :nginx
          "Вебсервер — nginx. Прибери add_header Access-Control-Allow-Origin \"*\" і підстановку $http_origin. Дозволь лише явний список доменів."
        else
          "Вебсервер не визначити: дай варіант і для Apache (Header set, .htaccess, mod_headers), і для nginx (add_header)."
        end

        case platform
        when :laravel
          "Налаштуй CORS у Laravel: у config/cors.php прибери allowed_origins '*', вимкни віддзеркалення Origin і дозволь лише явний список доменів фронтенда. credentials увімкни лише для цього списку. #{front}"
        when :php
          "Це PHP, точний фреймворк невідомий. #{front} Якщо це Laravel, продублюй те саме в config/cors.php. Конфіг Rails не пропонуй."
        when :rails
          "Налаштуй безпечну політику CORS у Ruby on Rails: не став Access-Control-Allow-Origin '*' разом із credentials і дозволь лише явний список довірених доменів фронтенда. #{front}"
        when :django
          "Налаштуй django-cors-headers: CORS_ALLOW_ALL_ORIGINS = False, явний CORS_ALLOWED_ORIGINS, без зірочки при CORS_ALLOW_CREDENTIALS. #{front}"
        when :apache
          "Налаштуй безпечну політику CORS в Apache httpd через mod_headers: не став Access-Control-Allow-Origin \"*\" разом із credentials і дозволь лише явний список довірених доменів фронтенда. Не копіюй Origin із запиту."
        else
          front
        end
      end

      def detect_platform(response)
        powered = response.headers["x-powered-by"].to_s
        server = response.headers["server"].to_s
        cookie = response.headers["set-cookie"].to_s

        return :laravel if cookie.match?(/laravel_session/i) || powered.match?(/laravel/i)
        return :php if powered.match?(/php/i)
        return :django if powered.match?(/python|django|wsgi/i) || server.match?(/gunicorn|django/i)
        return :rails if powered.match?(/rails|phusion/i) || response.headers.key?("x-runtime")
        return :apache if apache_server?(server)
        return :nginx if server.match?(/nginx/i)

        :unknown
      end

      def web_server(response)
        server = response.headers["server"].to_s
        return :apache if apache_server?(server)
        return :nginx if server.match?(/nginx/i)

        nil
      end

      def apache_server?(server)
        server.match?(/apache/i) && !server.match?(/tomcat|coyote/i)
      end

      def platform_name(platform, server)
        front = { apache: " Попереду Apache httpd (заголовок Server)", nginx: " Попереду nginx (заголовок Server)" }.fetch(server, "")
        {
          laravel: "Laravel (PHP). На це вказує сесійна кука або підпис Laravel.#{front}",
          php: "PHP. На це вказує заголовок X-Powered-By. Точний фреймворк за головною не визначити.#{front}",
          rails: "Ruby on Rails. На це вказує заголовок X-Runtime або підпис сервера застосунку.#{front}",
          django: "Django (Python). На це вказують заголовки сервера або X-Powered-By.#{front}",
          apache: "сайт за Apache httpd. Фреймворк за головною не визначити",
          nginx: "сайт за nginx. Фреймворк за головною не визначити",
          unknown: "не визначено. Завдання нижче і для Apache, і для nginx"
        }.fetch(platform)
      end
    end
  end
end
