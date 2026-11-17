module Audit
  module Checkers
    # Дивиться лише атрибути кукі, самі значення у звіт не потраплять
    class CookieSecurityChecker < BaseChecker
      CATEGORY = "A08:2025 – Software or Data Integrity Failures"

      def perform
        response = homepage
        cookies = cookie_list(response.headers["set-cookie"])
        return none(response) if cookies.empty?

        parsed = cookies.map { |raw| { name: cookie_name(raw) }.merge(flags(raw)) }
        return unprotected(response, parsed) if parsed.any? { |cookie| !cookie[:httponly] || !cookie[:samesite] }
        return transport_only(response, parsed) if parsed.any? { |cookie| !cookie[:secure] }

        protected_cookies(response, parsed)
      end

      def error_result(message)
        Result.new(
          category: CATEGORY,
          title: "Не вдалося перевірити cookies",
          status: :error,
          business_risk: "Перевірку не вдалося закінчити, тому вважати, що cookies захищені, не можна. Повторіть перевірку, коли сайт відповідає.",
          technical_lang: "Запит на головну не завершився. Причина: #{message} Висновку про прапорці cookies немає.",
          remediation_agency: "Завдання для виправлення не сформоване: сканер не отримав відповідь сайту.",
          remediation_ai_prompt: ""
        )
      end

      private

      def homepage
        response = fetch("/")
        return response unless response.status == 429

        pause = response.headers["retry-after"].to_i
        pause = 3 if pause <= 0 || pause > 3
        sleep(pause)
        fetch("/")
      end

      def cookie_list(header)
        header.to_s.split(/,(?=\s*[^;,\s]+=)/).map(&:strip).reject(&:empty?)
      end

      def cookie_name(raw)
        raw.to_s.split("=", 2).first.to_s.strip
      end

      def flags(raw)
        {
          httponly: raw.match?(/;\s*httponly/i),
          samesite: raw.match?(/;\s*samesite=(lax|strict)/i),
          secure: raw.match?(/;\s*secure/i)
        }
      end

      def none(response)
        Result.new(
          category: CATEGORY,
          title: title,
          status: :passed,
          business_risk: "Сайт не встановлює cookies при первинному відкритті сторінки.",
          technical_lang: technical_for(response, [], :passed),
          remediation_agency: "При відкритті головної заголовка Set-Cookie немає. Окреме завдання не потрібне.",
          remediation_ai_prompt: ""
        )
      end

      def protected_cookies(response, cookies)
        Result.new(
          category: CATEGORY,
          title: title,
          status: :passed,
          business_risk: "Усі встановлені файли cookies захищені прапорцями HttpOnly, Secure та SameSite.",
          technical_lang: technical_for(response, cookies, :passed),
          remediation_agency: "У всіх cookies з головної є HttpOnly, Secure і SameSite=Lax або Strict. Окреме завдання не потрібне.",
          remediation_ai_prompt: ""
        )
      end

      def transport_only(response, cookies)
        Result.new(
          category: CATEGORY,
          title: title,
          status: :warning,
          business_risk: "Cookies захищені HttpOnly та SameSite, але відсутній прапорець Secure для передачі лише через HTTPS. Без нього браузер відправить cookie і звичайним http://, тож у відкритій мережі його можна прочитати.",
          technical_lang: technical_for(response, cookies, :warning),
          remediation_agency: agency_for(response, cookies, :warning),
          remediation_ai_prompt: prompt_for(response, cookies, :warning)
        )
      end

      def unprotected(response, cookies)
        Result.new(
          category: CATEGORY,
          title: title,
          status: :failed,
          business_risk: "#{fail_message} #{risk_detail}",
          technical_lang: technical_for(response, cookies, :failed),
          remediation_agency: agency_for(response, cookies, :failed),
          remediation_ai_prompt: prompt_for(response, cookies, :failed)
        )
      end

      def title
        "Захист та цілісність сесійних cookies (HttpOnly, Secure, SameSite)"
      end

      def fail_message
        "Виявлено cookies без критичних прапорців захисту HttpOnly або SameSite."
      end

      def risk_detail
        "Файли cookies, які відповідають за сесію та авторизацію відвідувачів, не захищені від перехоплення або підміни. " \
        "Зловмисники можуть викрасти активну сесію клієнта через сторонні скрипти, підробити запит від його імені " \
        "або перехопити токен доступу в публічній мережі."
      end

      def technical_for(response, cookies, status)
        body = if cookies.empty?
          "Заголовок Set-Cookie відсутній або порожній."
        else
          lines = cookies.map { |cookie| flag_line(cookie) }
          "Cookies: #{cookies.size}. Значення у звіт не входять, лише імена і прапорці.\n#{lines.join("\n")}"
        end
        verdict = case status
        when :failed
          "Червоний статус: немає HttpOnly або SameSite=Lax чи Strict. SameSite=None не рахується."
        when :warning
          "Жовтий статус: HttpOnly і SameSite є, прапорця Secure немає."
        else
          "Зелений статус: або cookies немає, або є всі три прапорці."
        end

        <<~TEXT.strip
          Зроблено безпечний GET #{origin}.
          Відповідь: HTTP #{response.status}.
          #{body}
          #{verdict}
          Це OWASP Top 10 #{CATEGORY}.
        TEXT
      end

      def flag_line(cookie)
        missing = []
        missing << "HttpOnly" unless cookie[:httponly]
        missing << "SameSite=Lax або Strict" unless cookie[:samesite]
        missing << "Secure" unless cookie[:secure]
        state = missing.empty? ? "HttpOnly, Secure, SameSite=Lax або Strict" : "немає #{missing.join(', ')}"
        "#{cookie[:name]}: #{state}."
      end

      def agency_for(response, cookies, status)
        platform = app_platform(response)
        server = web_server(response)
        task = if status == :warning
          "Завдання: додайте прапорець Secure до cookies, у яких уже є HttpOnly і SameSite=Lax або Strict. З ним браузер надсилає cookie лише через HTTPS."
        else
          "Завдання: для всіх сесійних cookies увімкніть HttpOnly (заборона читання з JavaScript), Secure (лише HTTPS) і SameSite=Lax або Strict (захист від підробки запиту з чужого сайту)."
        end

        <<~TEXT.strip
          #{task}
          Платформа за відбитками відповіді: #{platform_name(platform, server)}.
          #{flag_lines(cookies)}
          Зробити:
          #{agency_steps(platform, server)}
          Готово, коли в Set-Cookie є HttpOnly, Secure і SameSite=Lax або SameSite=Strict.
        TEXT
      end

      def flag_lines(cookies)
        cookies.map { |cookie| flag_line(cookie) }.join("\n")
      end

      def agency_steps(platform, server)
        case platform
        when :laravel
          <<~TEXT.strip
            1. У config/session.php виставте http_only => true, secure => true, same_site => 'lax'.
            2. Ті самі три прапорці додайте власним cookie, якщо вони створюються окремо від сесії.
            #{server_note(server)}
          TEXT
        when :symfony
          <<~TEXT.strip
            1. У framework.yaml для session задайте cookie_httponly: true, cookie_secure: true, cookie_samesite: lax.
            2. Ті самі прапорці додайте власним cookie поза сесією.
            #{server_note(server)}
          TEXT
        when :yii
          <<~TEXT.strip
            1. У конфігу session для cookieParams задайте httpOnly => true, secure => true, sameSite => 'Lax'.
            2. Ті самі прапорці передайте в setcookie, якщо cookie створюється окремо.
            #{server_note(server)}
          TEXT
        when :wordpress
          <<~TEXT.strip
            1. Перед завантаженням WordPress задайте session.cookie_httponly = 1, session.cookie_secure = 1, session.cookie_samesite = Lax.
            2. У власних викликах setcookie передайте httponly, secure і samesite Lax.
            #{server_note(server)}
          TEXT
        when :php
          <<~TEXT.strip
            1. У php.ini або .user.ini задайте session.cookie_httponly = 1, session.cookie_secure = 1, session.cookie_samesite = Lax.
            2. У setcookie передайте httponly true, secure true і samesite Lax.
            #{server_note(server)}
          TEXT
        when :django
          <<~TEXT.strip
            1. У settings.py задайте SESSION_COOKIE_HTTPONLY = True, SESSION_COOKIE_SECURE = True, SESSION_COOKIE_SAMESITE = 'Lax'.
            2. Те саме для CSRF_COOKIE_HTTPONLY, CSRF_COOKIE_SECURE і CSRF_COOKIE_SAMESITE.
            #{server_note(server)}
          TEXT
        when :flask
          <<~TEXT.strip
            1. У конфігу Flask задайте SESSION_COOKIE_HTTPONLY = True, SESSION_COOKIE_SECURE = True, SESSION_COOKIE_SAMESITE = 'Lax'.
            2. Ті самі прапорці додайте власним set_cookie поза сесією.
            #{server_note(server)}
          TEXT
        when :rails
          <<~TEXT.strip
            1. У config/initializers/session_store.rb задайте httponly: true, secure: true і same_site: :lax.
            2. Для cookies, створених через cookies[], передайте httponly: true, secure: true, same_site: :lax.
            #{server_note(server)}
          TEXT
        else
          <<~TEXT.strip
            1. Фреймворк за відповіддю не визначити. Прапорці HttpOnly, Secure і SameSite=Lax мають стояти в заголовку Set-Cookie.
            2. Їх виставляє код, який створює cookie.
            #{server_note(server)}
          TEXT
        end
      end

      def server_note(server)
        case server
        when :apache
          "3. Apache httpd сам ці прапорці до cookie не додає. Їх виставляє код застосунку."
        when :nginx
          "3. nginx сам ці прапорці до cookie не додає. Їх виставляє код застосунку."
        else
          "3. Вебсервер сам ці прапорці до cookie не додає. Їх виставляє код застосунку."
        end
      end

      def prompt_for(response, cookies, status)
        platform = app_platform(response)
        server = web_server(response)
        need = status == :warning ? "Додай відсутній прапорець Secure. HttpOnly і SameSite=Lax або Strict уже є." : "Увімкни HttpOnly, Secure і SameSite=Lax або Strict."
        <<~TEXT.strip
          Сесійні cookies на головній без повного набору прапорців. #{need}
          #{flag_lines(cookies)}
          Значення cookies не виводь і не вигадуй.
          Схоже, що проєкт — #{platform_name(platform, server)}.
          #{prompt_steps(platform, server)}
          Поясни простою мовою, що змінилось.
        TEXT
      end

      def prompt_steps(platform, server)
        front = case server
        when :apache
          "Вебсервер — Apache httpd. Прапорці задай у коді застосунку, не в конфігу сервера. Конфіг nginx не пропонуй."
        when :nginx
          "Вебсервер — nginx. Прапорці задай у коді застосунку, не в конфігу сервера."
        else
          "Вебсервер не визначити. Прапорці задай там, де створюється cookie."
        end

        case platform
        when :laravel
          "Це Laravel. У config/session.php вистав http_only true, secure true і same_site lax. #{front} Конфіг Rails не пропонуй."
        when :symfony
          "Це Symfony. У framework.yaml для session вистав cookie_httponly, cookie_secure і cookie_samesite lax. #{front} Конфіг Rails не пропонуй."
        when :yii
          "Це Yii. У cookieParams сесії вистав httpOnly, secure і sameSite Lax. #{front} Конфіг Rails не пропонуй."
        when :wordpress
          "Це WordPress. Задай session.cookie_httponly, session.cookie_secure і session.cookie_samesite Lax. У власних setcookie передай ті самі прапорці. #{front} Конфіг Rails не пропонуй."
        when :php
          "Це PHP, точний фреймворк невідомий. У php.ini задай session.cookie_httponly = 1, session.cookie_secure = 1, session.cookie_samesite = Lax. У setcookie передай ті самі прапорці. Якщо це Laravel, Symfony або Yii, зроби це їхніми налаштуваннями сесії. #{front} Конфіг Rails не пропонуй."
        when :django
          "Це Django. У settings.py вистав SESSION_COOKIE_HTTPONLY, SESSION_COOKIE_SECURE, SESSION_COOKIE_SAMESITE = 'Lax' і те саме для CSRF cookie. #{front}"
        when :flask
          "Це Flask. Вистав SESSION_COOKIE_HTTPONLY, SESSION_COOKIE_SECURE і SESSION_COOKIE_SAMESITE = 'Lax'. #{front}"
        when :rails
          "Це Ruby on Rails. У config/initializers/session_store.rb вистав httponly: true, secure: true і same_site: :lax для сесійного cookie. Для інших cookies[] передай ті самі параметри. #{front}"
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
