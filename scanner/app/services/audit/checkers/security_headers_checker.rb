module Audit
  module Checkers
    # Заголовки сторінки: clickjacking, чужі скрипти, підміна типу файла.
    class SecurityHeadersChecker < BaseChecker
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
          Це OWASP Top 10 A05:2021 Security Misconfiguration.
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
        <<~TEXT.strip
          Завдання: додати відсутні захисні заголовки на всі HTML-відповіді сайту.

          Зараз немає або значення не захищає: #{names}.
          Платформа за відбитками відповіді: #{platform_name(detect_platform(response))}.

          Зробити в тому місці, де реально формується відповідь. Зазвичай це одне з двох:

          1. Nginx, у блоці server:
             add_header X-Frame-Options "SAMEORIGIN" always;
             add_header X-Content-Type-Options "nosniff" always;
             add_header Content-Security-Policy "default-src 'self'" always;
             Прапорець always потрібен, щоб заголовок був і на сторінках помилок.

          2. Ruby on Rails, у config/application.rb або в ініціалізаторі, не в одному екшені:
             config.action_dispatch.default_headers["X-Frame-Options"] = "SAMEORIGIN"
             config.action_dispatch.default_headers["X-Content-Type-Options"] = "nosniff"
             config.action_dispatch.default_headers["Content-Security-Policy"] = "default-src 'self'"

          Якщо сайт на PHP (Laravel, Yii), ті самі три рядки поставте в nginx або в middleware фреймворка, щоб їх не затер наступний деплой.
          Content-Security-Policy спочатку можна лишити default-src 'self'. Якщо пропадуть свої картинки чи скрипти з іншого домену, домен додають у політику явно, а не вимикають заголовок.
          Готово, коли головна сторінка віддає всі три заголовки, а X-Content-Type-Options дорівнює nosniff.
        TEXT
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
        when :laravel, :php
          <<~TEXT.strip
            Write Nginx configuration snippet to include standard HTTP security headers: X-Frame-Options SAMEORIGIN, X-Content-Type-Options nosniff, and a strict Content-Security-Policy.
            Якщо це Laravel, продублюй ті самі заголовки в middleware, щоб вони лишались навіть без nginx.
          TEXT
        when :rails
          <<~TEXT.strip
            Додай у Ruby on Rails ці заголовки в config.action_dispatch.default_headers (application.rb або initializer), а не в одному контролері: X-Frame-Options SAMEORIGIN, X-Content-Type-Options nosniff, Content-Security-Policy default-src 'self'.
          TEXT
        when :django
          <<~TEXT.strip
            Увімкни в Django SecurityMiddleware і вистав SECURE_CONTENT_TYPE_NOSNIFF = True, X_FRAME_OPTIONS = "SAMEORIGIN" і CONTENT_SECURITY_POLICY з default-src 'self'. Якщо перед Django стоїть nginx, додай ті самі заголовки і там.
          TEXT
        else
          <<~TEXT.strip
            Write Nginx configuration snippet to include standard HTTP security headers: X-Frame-Options SAMEORIGIN, X-Content-Type-Options nosniff, and a strict Content-Security-Policy.
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
