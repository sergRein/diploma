require "nokogiri"
require "uri"

module Audit
  module Checkers
    # Дивимся лише теги script з src на стороній домен
    class SriIntegrityChecker < BaseChecker
      CATEGORY = "A03:2025 – Software Supply Chain Failures"

      def perform
        response = homepage
        scripts = external_scripts(response.body)
        return none(response) if scripts.empty?
        missing = scripts.reject { |node| integrity?(node) }
        return protected_scripts(response, scripts) if missing.empty?

        unsigned(response, missing)
      end

      def error_result(message)
        Result.new(
          category: CATEGORY,
          title: "Не вдалося перевірити сторонні скрипти",
          status: :error,
          business_risk: "Перевірку не вдалося закінчити, тому вважати, що сторонні скрипти підписані, не можна. Повторіть перевірку, коли сайт відповідає.",
          technical_lang: "Запит на головну не завершився. Причина: #{message} Висновку про цілісність скриптів немає.",
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

      def external_scripts(body)
        page_host = origin.host.to_s.downcase
        Nokogiri::HTML(body.to_s).css("script[src]").select { |node| external?(node["src"], page_host) }
      end

      def external?(src, page_host)
        value = src.to_s.strip
        return false unless value.match?(%r{\Ahttps?://}i) || value.start_with?("//")

        absolute = value.start_with?("//") ? "http:#{value}" : value
        host = URI.parse(absolute).host.to_s.downcase
        return false if host.empty?

        host != page_host
      rescue URI::InvalidURIError
        false
      end

      def integrity?(node)
        node["integrity"].to_s.strip != ""
      end

      def none(response)
        Result.new(
          category: CATEGORY,
          title: title,
          status: :passed,
          business_risk: "Зовнішні скрипти зі сторонніх ресурсів на сторінці не використовуються.",
          technical_lang: technical_for(response, [], :passed),
          remediation_agency: "Сторонніх скриптів на головній немає. Окреме завдання не потрібне.",
          remediation_ai_prompt: ""
        )
      end

      def protected_scripts(response, scripts)
        Result.new(
          category: CATEGORY,
          title: title,
          status: :passed,
          business_risk: "Усі підключені зовнішні скрипти захищені перевіркою цілісності Subresource Integrity (SRI).",
          technical_lang: technical_for(response, scripts, :passed),
          remediation_agency: "У всіх зовнішніх скриптів на головній є непорожній атрибут integrity. Окреме завдання не потрібне.",
          remediation_ai_prompt: ""
        )
      end

      def unsigned(response, missing)
        Result.new(
          category: CATEGORY,
          title: title,
          status: :warning,
          business_risk: "#{warn_message} #{risk_detail}",
          technical_lang: technical_for(response, missing, :warning),
          remediation_agency: agency_for(response, missing),
          remediation_ai_prompt: prompt_for(response, missing)
        )
      end

      def title
        "Захист від підміни сторонніх скриптів та бібліотек (SRI)"
      end

      def warn_message
        "Виявлено зовнішні скрипти без криптографічного підпису цілісності (SRI)."
      end

      def risk_detail
        "Сайт завантажує JavaScript-файли зі сторонніх серверів без перевірки їхньої цілісності. " \
        "Якщо сторонній сервіс або бібліотеку зламають, зловмисники зможуть непомітно впровадити шкідливий код на ваш сайт " \
        "і викрадати платіжні чи особисті дані ваших клієнтів."
      end

      def technical_for(response, scripts, status)
        list = if scripts.empty?
          "Зовнішніх тегів script немає."
        elsif status == :warning
          "Без атрибута integrity:\n#{script_lines(scripts)}"
        else
          "З атрибутом integrity:\n#{script_lines(scripts)}"
        end
        verdict = status == :warning ? "Жовтий статус: хоча б один чужий скрипт без підпису." : "Зелений статус: непідписаних чужих скриптів немає."

        <<~TEXT.strip
          Зроблено безпечний GET #{origin}.
          Відповідь: HTTP #{response.status}.
          Чужим вважається src з http://, https:// або //, якщо хост не збігається з хостом сайту.
          Скрипти з цього ж хоста і без src не перевіряються. Вміст файлів не завантажується.
          #{list}
          #{verdict}
          Це OWASP Top 10 #{CATEGORY}.
        TEXT
      end

      def script_lines(scripts)
        scripts.map { |node| node["src"].to_s.strip }.uniq.join("\n")
      end

      def agency_for(response, scripts)
        platform = app_platform(response)
        server = web_server(response)
        <<~TEXT.strip
          Завдання: додайте атрибут integrity (хеш SHA-384 файлу) і crossorigin="anonymous" до кожного зовнішнього тега script зі стороннього CDN. Або покладіть ці бібліотеки на власний сервер і підключайте їх зі свого хоста.

          Платформа за відбитками відповіді: #{platform_name(platform, server)}.

          Скрипти без підпису:
          #{script_lines(scripts)}

          Зробити:
          #{agency_steps(platform, server)}
          Готово, коли в HTML кожного такого script є непорожній integrity і crossorigin="anonymous".
        TEXT
      end

      def agency_steps(platform, server)
        case platform
        when :laravel
          <<~TEXT.strip
            1. У Blade-шаблоні до зовнішнього script додайте integrity="sha384-..." і crossorigin="anonymous".
            2. Хеш порахуйте з байтів файлу, який віддає CDN, і підставте його в атрибут.
            #{server_note(server)}
          TEXT
        when :symfony
          <<~TEXT.strip
            1. У шаблоні Twig до зовнішнього script додайте integrity="sha384-..." і crossorigin="anonymous".
            2. Хеш порахуйте з байтів файлу, який віддає CDN.
            #{server_note(server)}
          TEXT
        when :yii
          <<~TEXT.strip
            1. У view до зовнішнього script додайте integrity="sha384-..." і crossorigin="anonymous".
            2. Хеш порахуйте з байтів файлу, який віддає CDN.
            #{server_note(server)}
          TEXT
        when :wordpress
          <<~TEXT.strip
            1. До тега script зі стороннього CDN додайте integrity="sha384-..." і crossorigin="anonymous".
            2. Якщо скрипт підключено через wp_enqueue_script, додайте ці атрибути у фільтрі script_loader_tag.
            #{server_note(server)}
          TEXT
        when :php
          <<~TEXT.strip
            1. У HTML-шаблоні до кожного зовнішнього script додайте integrity="sha384-..." і crossorigin="anonymous".
            2. Хеш порахуйте з байтів файлу на сторонній адресі. Для кожного скрипта зі списку він свій.
            #{server_note(server)}
          TEXT
        when :django
          <<~TEXT.strip
            1. У шаблоні Django до зовнішнього script додайте integrity="sha384-..." і crossorigin="anonymous".
            2. Хеш порахуйте з байтів файлу, який віддає CDN.
            #{server_note(server)}
          TEXT
        when :flask
          <<~TEXT.strip
            1. У шаблоні Jinja2 до зовнішнього script додайте integrity="sha384-..." і crossorigin="anonymous".
            2. Хеш порахуйте з байтів файлу, який віддає CDN.
            #{server_note(server)}
          TEXT
        when :rails
          <<~TEXT.strip
            1. У шаблоні ERB до зовнішнього script додайте integrity="sha384-..." і crossorigin="anonymous".
            2. Якщо скрипт підключено через javascript_include_tag, передайте integrity: і crossorigin: "anonymous".
            #{server_note(server)}
          TEXT
        else
          <<~TEXT.strip
            1. Фреймворк за відповіддю не визначити. Атрибути integrity і crossorigin="anonymous" ставляться в HTML, не в конфігу вебсервера.
            2. Хеш SHA-384 порахуйте з байтів файлу, який віддає CDN.
            #{server_note(server)}
          TEXT
        end
      end

      def server_note(server)
        case server
        when :apache
          "3. Apache httpd атрибут integrity не виставляє. Він має стояти в HTML."
        when :nginx
          "3. nginx атрибут integrity не виставляє. Він має стояти в HTML."
        else
          "3. Вебсервер атрибут integrity не виставляє. Він має стояти в HTML."
        end
      end

      def prompt_for(response, scripts)
        platform = app_platform(response)
        server = web_server(response)
        <<~TEXT.strip
          На головній є зовнішні скрипти без перевірки цілісності. Додай їм integrity з хешем SHA-384 вмісту файлу і crossorigin="anonymous". Або заміни адресу на файл зі свого хоста.
          Скрипти без підпису:
          #{script_lines(scripts)}
          Схоже, що проєкт — #{platform_name(platform, server)}.
          #{prompt_steps(platform, server)}
          Не пропонуй приклад шкідливого скрипта. Поясни простою мовою, що змінилось.
        TEXT
      end

      def prompt_steps(platform, server)
        front = case server
        when :apache
          "Вебсервер — Apache httpd. Атрибути пиши в HTML, не в конфігу сервера. Конфіг nginx не пропонуй."
        when :nginx
          "Вебсервер — nginx. Атрибути пиши в HTML, не в конфігу сервера."
        else
          "Вебсервер не визначити. Атрибути integrity і crossorigin пиши в HTML."
        end

        case platform
        when :laravel
          "Це Laravel. Додай атрибути в Blade-шаблоні на тег script. #{front} Конфіг Rails не пропонуй."
        when :symfony
          "Це Symfony. Додай атрибути в шаблоні Twig на тег script. #{front} Конфіг Rails не пропонуй."
        when :yii
          "Це Yii. Додай атрибути у view на тег script. #{front} Конфіг Rails не пропонуй."
        when :wordpress
          "Це WordPress. Додай integrity і crossorigin=\"anonymous\" через script_loader_tag або прямо в тегу script теми. #{front} Конфіг Rails не пропонуй."
        when :php
          "Це PHP, точний фреймворк невідомий. Додай integrity=\"sha384-...\" і crossorigin=\"anonymous\" у HTML-шаблоні. Якщо це Laravel, Symfony або Yii, атрибути став у їхньому шаблоні. #{front} Конфіг Rails не пропонуй."
        when :django
          "Це Django. Додай атрибути в шаблоні на тег script. #{front}"
        when :flask
          "Це Flask. Додай атрибути в шаблоні Jinja2 на тег script. #{front}"
        when :rails
          "Це Ruby on Rails. У шаблонах ERB до зовнішніх script додай integrity з SHA-384 і crossorigin=\"anonymous\". Для javascript_include_tag передай integrity: і crossorigin: \"anonymous\". #{front}"
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
