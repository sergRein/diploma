module Audit
  module Checkers
    # Заголовки сторінки: clickjacking, чужі скрипти, підміна типу файла.
    class SecurityHeadersChecker < BaseChecker
      CATEGORY = "A02:2025 – Security Misconfiguration"
      NGINX_HEADER = {
        "x-frame-options" => 'add_header X-Frame-Options "SAMEORIGIN" always;',
        "x-content-type-options" => 'add_header X-Content-Type-Options "nosniff" always;',
        "content-security-policy" => "add_header Content-Security-Policy \"default-src 'self'\" always;"
      }.freeze
      RAILS_HEADER = {
        "x-frame-options" => 'config.action_dispatch.default_headers["X-Frame-Options"] = "SAMEORIGIN"',
        "x-content-type-options" => 'config.action_dispatch.default_headers["X-Content-Type-Options"] = "nosniff"',
        "content-security-policy" => "config.action_dispatch.default_headers[\"Content-Security-Policy\"] = \"default-src 'self'\""
      }.freeze
      DJANGO_HEADER = {
        "x-frame-options" => 'X_FRAME_OPTIONS = "SAMEORIGIN"',
        "x-content-type-options" => "SECURE_CONTENT_TYPE_NOSNIFF = True",
        "content-security-policy" => "Content-Security-Policy у стандартному SecurityMiddleware немає: поставте його в nginx або через django-csp, політика default-src 'self'."
      }.freeze
      CHECKS = [
        {
          key: "x-frame-options",
          label: "X-Frame-Options",
          expect: "SAMEORIGIN або DENY"
        },
        {
          key: "content-security-policy",
          label: "Content-Security-Policy",
          expect: "непорожня політика, наприклад default-src 'self'"
        },
        {
          key: "x-content-type-options",
          label: "X-Content-Type-Options",
          expect: "nosniff"
        }
      ].freeze

      def perform
        response = fetch(origin.path.to_s.empty? ? "/" : origin.path)
        missing = CHECKS.reject { |check| present?(response, check) }
        return ok(response) if missing.empty?
        return partial(response, missing) if missing.size < CHECKS.size

        broken(response, missing)
      end

      def error_result(message)
        Result.new(
          category: CATEGORY,
          title: "Не вдалося перевірити заголовки безпеки",
          status: :error,
          business_risk: "Перевірку не вдалося закінчити, тому вважати, що захист від чужих вікон і сторонніх скриптів є, не можна. Повторіть перевірку, коли сайт відповідає.",
          technical_lang: "Запит на головну сторінку не завершився. Причина: #{message} Висновку про заголовки немає.",
          remediation_agency: "Завдання для виправлення не сформоване: сканер не отримав відповідь сайту.",
          remediation_ai_prompt: ""
        )
      end

      private

      def present?(response, check)
        value = response.headers[check[:key]].to_s.strip
        return false if value.empty?

        case check[:key]
        when "x-frame-options"
          value.match?(/\b(?:deny|sameorigin)\b/i) || value.match?(/allow-from\s+\S+/i)
        when "x-content-type-options"
          value.split(",").any? { |part| part.strip.casecmp?("nosniff") }
        else
          true
        end
      end

      def ok(response)
        Result.new(
          category: CATEGORY,
          title: title,
          status: :passed,
          business_risk: "Ці налаштування на місці. Чужий сайт не зможе показати ваш усередині своєї сторінки, а браузер не виконає сторонній скрипт лише тому, що його підсунули в сторінку.",
          technical_lang: technical_summary(response, []),
          remediation_agency: "Усі три заголовки на головній сторінці є, X-Content-Type-Options дорівнює nosniff. Окреме завдання не потрібне.",
          remediation_ai_prompt: ""
        )
      end

      def partial(response, missing)
        Result.new(
          category: CATEGORY,
          title: title,
          status: :warning,
          business_risk: business_risk,
          technical_lang: technical_summary(response, missing),
          remediation_agency: agency_for(response, missing),
          remediation_ai_prompt: prompt_for(response, missing)
        )
      end

      def broken(response, missing)
        Result.new(
          category: CATEGORY,
          title: title,
          status: :failed,
          business_risk: business_risk,
          technical_lang: technical_summary(response, missing),
          remediation_agency: agency_for(response, missing),
          remediation_ai_prompt: prompt_for(response, missing)
        )
      end

      def title
        "Захист від підміни інтерфейсу та сторонніх скриптів (Заголовки безпеки)"
      end

      def business_risk
        "Без цих налаштувань чужий сайт може показати ваш сайт усередині своєї сторінки. " \
          "Людина думає, що натискає кнопку у вас — оплатити, увійти, підтвердити — а клік забирає шахрай. " \
          "Окремо, якщо браузеру не заборонені сторонні скрипти, на сторінку можна підсунути чужий код. " \
          "Він прочитає те, що клієнт вводить: пароль, номер картки, телефон. " \
          "Для невеликого бізнесу це крадіжка кліків, оплат і довіри."
      end

      def technical_summary(response, missing)
        lines = CHECKS.map do |check|
          value = response.headers[check[:key]].to_s.strip
          state = if missing.include?(check)
            "немає або значення не захищає. Очікується: #{check[:expect]}."
          else
            "є: #{value}."
          end
          "#{check[:label]}: #{state}"
        end

        <<~TEXT.strip
          GET #{origin} повернув HTTP #{response.status}.
          #{lines.join("\n")}
          Відсутність X-Frame-Options — clickjacking, відсутність Content-Security-Policy — виконання чужого скрипта, X-Content-Type-Options не nosniff — браузер може вгадати тип файла і виконати його як скрипт.
          Це OWASP Top 10 #{CATEGORY}.
          #{verdict(missing)}
        TEXT
      end

      def verdict(missing)
        return "Усі три заголовки на місці." if missing.empty?
        return "Жовтий статус: частина заголовків уже є, решти немає." if missing.size < CHECKS.size

        "Червоний статус: немає жодного з трьох заголовків."
      end

      def agency_for(response, missing)
        names = missing.map { |check| check[:label] }.join(", ")
        platform = detect_platform(response)
        <<~TEXT.strip
          Завдання: додати відсутні захисні заголовки на всі HTML-відповіді сайту.

          Зараз немає або значення не захищає: #{names}.
          Платформа за відбитками відповіді: #{platform_name(platform)}.
          Заголовки, які вже стоять правильно, не знімайте.

          Зробити:
          #{agency_steps(platform, missing)}
          #{csp_note if missing.any? { |check| check[:key] == "content-security-policy" }}
          Готово, коли головна сторінка віддає всі три заголовки, а X-Content-Type-Options дорівнює nosniff.
        TEXT
      end

      def agency_steps(platform, missing)
        case platform
        when :laravel
          [
            "1. У nginx, у блоці server, додайте відсутні заголовки. Прапорець always потрібен, щоб вони були і на сторінках помилок:",
            nginx_lines(missing),
            "2. Продублюйте ті самі значення в middleware Laravel, не в одному екшені. Інакше наступний деплой без nginx їх затре."
          ]
        when :php
          [
            "1. У nginx, у блоці server. Точний фреймворк за головною не визначити, тому вебсервер — надійне місце:",
            nginx_lines(missing),
            "2. Якщо це Laravel або Yii, продублюйте заголовки в middleware фреймворка. У конфіг Ruby on Rails їх не додавайте."
          ]
        when :rails
          [
            "1. У config/application.rb або в ініціалізаторі, не в одному екшені:",
            rails_lines(missing),
            "2. Якщо перед Rails стоїть nginx, ті самі відсутні заголовки додайте і там з прапорцем always. Не змішуйте це з налаштуванням PHP."
          ]
        when :django
          [
            "1. Увімкніть django.middleware.security.SecurityMiddleware.",
            django_lines(missing),
            "2. Якщо перед Django стоїть nginx, продублюйте відсутні заголовки там:",
            nginx_lines(missing)
          ]
        when :nginx
          [
            "1. Фреймворк за головною не визначити. Додайте відсутні заголовки в nginx, у блоці server:",
            nginx_lines(missing)
          ]
        else
          [
            "1. Платформу не визначено. Додайте відсутні заголовки в nginx, у блоці server:",
            nginx_lines(missing),
            "2. Якщо відповідь збирає сам додаток, продублюйте їх у його конфігурації, а не в одному екшені. Не підставляйте чужий фреймворк навмання."
          ]
        end.join("\n")
      end

      def nginx_lines(missing)
        missing.map { |check| "   #{NGINX_HEADER.fetch(check[:key])}" }.join("\n")
      end

      def rails_lines(missing)
        missing.map { |check| "   #{RAILS_HEADER.fetch(check[:key])}" }.join("\n")
      end

      def django_lines(missing)
        lines = missing.filter_map { |check| DJANGO_HEADER[check[:key]] }
        return "   Заголовки X-Frame-Options і nosniff закриває SecurityMiddleware." if lines.empty?

        lines.map { |line| "   #{line}" }.join("\n")
      end

      def csp_note
        "Content-Security-Policy спочатку можна лишити default-src 'self'. Якщо пропадуть свої картинки чи скрипти з іншого домену, домен додають у політику явно, а не вимикають заголовок."
      end

      def prompt_for(response, missing)
        names = missing.map { |check| "#{check[:label]} (очікується #{check[:expect]})" }.join("; ")
        platform = detect_platform(response)

        <<~TEXT.strip
          На головній сторінці сайту немає захисних HTTP-заголовків: #{names}.
          Схоже, що проєкт — #{platform_name(platform)}.
          #{prompt_steps(platform)}
          Не вимикай заголовки, які вже є. Не додавай unsafe-inline і unsafe-eval, поки без них сторінка справді не працює. Поясни простою мовою, що змінилось.
        TEXT
      end

      def prompt_steps(platform)
        case platform
        when :laravel
          <<~TEXT.strip
            Це Laravel. Напиши фрагмент nginx із відсутніми заголовками: X-Frame-Options SAMEORIGIN, X-Content-Type-Options nosniff і сувора Content-Security-Policy. Продублюй їх у middleware Laravel, не в одному екшені.
          TEXT
        when :php
          <<~TEXT.strip
            Це PHP, точний фреймворк невідомий. Напиши фрагмент nginx із відсутніми заголовками: X-Frame-Options SAMEORIGIN, X-Content-Type-Options nosniff і сувора Content-Security-Policy. Якщо це Laravel або Yii, продублюй заголовки в middleware. Конфіг Ruby on Rails не пропонуй.
          TEXT
        when :rails
          <<~TEXT.strip
            Додай у Ruby on Rails ці заголовки в config.action_dispatch.default_headers (application.rb або initializer), а не в одному контролері: X-Frame-Options SAMEORIGIN, X-Content-Type-Options nosniff, Content-Security-Policy default-src 'self'.
          TEXT
        when :django
          <<~TEXT.strip
            Увімкни django.middleware.security.SecurityMiddleware: SECURE_CONTENT_TYPE_NOSNIFF = True і X_FRAME_OPTIONS = "SAMEORIGIN". Content-Security-Policy додай у nginx або через django-csp з default-src 'self': у стандартному SecurityMiddleware цього заголовка немає.
          TEXT
        else
          <<~TEXT.strip
            Напиши фрагмент конфігурації nginx зі стандартними захисними заголовками: X-Frame-Options SAMEORIGIN, X-Content-Type-Options nosniff і сувора Content-Security-Policy.
            Якщо додаток сам збирає відповідь (Rails, PHP, Python), постав ті самі заголовки і в коді, не лише в nginx.
          TEXT
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
        return :nginx if server.match?(/nginx/i)

        :unknown
      end

      def platform_name(platform)
        {
          laravel: "Laravel (PHP). На це вказує сесійна кука або підпис Laravel",
          php: "PHP. На це вказує заголовок X-Powered-By. Точний фреймворк за головною сторінкою не визначити, тому правку краще робити в nginx і продублювати в middleware",
          rails: "Ruby on Rails. На це вказує заголовок X-Runtime або підпис сервера застосунку",
          django: "Django (Python). На це вказують заголовки сервера або X-Powered-By",
          nginx: "сайт за nginx. Фреймворк за головною сторінкою не визначити",
          unknown: "не визначено. Завдання нижче універсальне: nginx і, за потреби, код додатка"
        }.fetch(platform)
      end
    end
  end
end
