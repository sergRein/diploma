require "cgi"

module Audit
  module Checkers
    # Безпечний маркер без виконуваного коду. Червоний статус лише якщо
    # сервер віддзеркалює < > " ' як сиру розмітку.
    class ErrorXssChecker < BaseChecker
      CATEGORY = "A05:2025 – Injection"
      CANARY_TOKEN = 'dast_canary_<probe>"\''.freeze
      RAW_FRAGMENT = "dast_canary_<probe>".freeze
      PROBES = [
        ["/search", "q"],
        ["/", "q"],
        ["/", "s"],
        ["/search", "query"],
        ["/__dast_probe", "q"]
      ].freeze

      def perform
        hits = PROBES.map do |path, param|
          uri = probe_uri(path, param)
          response = request(uri)
          { uri: uri, response: response, raw: raw_reflection?(response.body) }
        end
        return leaked(hits) if hits.any? { |hit| hit[:raw] }

        sanitized(hits)
      end

      def error_result(message)
        Result.new(
          category: CATEGORY,
          title: "Не вдалося перевірити екранування вхідних даних",
          status: :error,
          business_risk: "Перевірку не вдалося закінчити, тому вважати, що сайт очищує символи з адреси, не можна. Повторіть перевірку, коли сайт відповідає.",
          technical_lang: "Запити на перевірочні адреси не завершились. Причина: #{message} Висновку про екранування немає.",
          remediation_agency: "Завдання для виправлення не сформоване: сканер не отримав відповідь сайту.",
          remediation_ai_prompt: ""
        )
      end

      private

      def probe_uri(path, param)
        uri = origin.dup
        uri.path = path
        uri.query = "#{param}=#{CGI.escape(CANARY_TOKEN)}"
        uri.fragment = nil
        uri
      end

      def raw_reflection?(body)
        text = body.to_s
        text.include?(CANARY_TOKEN) || text.include?(RAW_FRAGMENT)
      end

      def leaked(hits)
        response = hits.find { |hit| hit[:raw] }[:response]
        Result.new(
          category: CATEGORY,
          title: title,
          status: :failed,
          business_risk: "#{fail_message} #{risk_detail}",
          technical_lang: technical_for(hits, :failed),
          remediation_agency: agency_for(response),
          remediation_ai_prompt: prompt_for(response)
        )
      end

      def sanitized(hits)
        Result.new(
          category: CATEGORY,
          title: title,
          status: :passed,
          business_risk: "Вхідні параметри коректно екрануються або фільтруються сервером.",
          technical_lang: technical_for(hits, :passed),
          remediation_agency: "Сирий маркер у відповіді не з'явився. Окреме завдання не потрібне.",
          remediation_ai_prompt: ""
        )
      end

      def title
        "Захист від впровадження стороннього коду в сторінку (XSS / Санітизація)"
      end

      def fail_message
        "Сервер відображає вхідні символи розмітки (<, >, \", ') без HTML-екранування."
      end

      def risk_detail
        "Сайт виводить дані з адресного рядка або полів пошуку без їхнього попереднього очищення. " \
        "Зловмисники можуть сформувати спеціальне посилання від імені вашого сайту, " \
        "яке при відкритті відвідувачем підмінить вміст сторінки або викраде його авторизаційні дані."
      end

      def technical_for(hits, status)
        leaked_urls = hits.select { |hit| hit[:raw] }.map { |hit| hit[:uri].to_s }
        found = if leaked_urls.empty?
          "Сирого фрагмента #{RAW_FRAGMENT} немає на жодній адресі."
        else
          "Сирий фрагмент #{RAW_FRAGMENT} є на: #{leaked_urls.join(', ')}."
        end
        verdict = status == :failed ? "Червоний статус: вхідний текст виведено як розмітку." : "Зелений статус: сирої розмітки з маркера немає."

        <<~TEXT.strip
          Зроблено #{hits.size} безпечних GET з одним маркером. Маркер не містить виконуваного коду.
          #{found}
          #{hits.map { |hit| probe_line(hit) }.join("\n")}
          #{verdict}
          Це OWASP Top 10 #{CATEGORY}.
        TEXT
      end

      def probe_line(hit)
        body = hit[:response].body.to_s
        note = if hit[:raw]
          "сирий фрагмент без HTML-екранування"
        elsif body.include?("dast_canary_")
          "маркер є, дужки записані як HTML-сутності"
        else
          "маркер не віддзеркалюється"
        end
        "#{hit[:uri]} → HTTP #{hit[:response].status}, #{note}."
      end

      def agency_for(response)
        platform = app_platform(response)
        server = web_server(response)
        <<~TEXT.strip
          Завдання: перед виводом у HTML екрануйте всі дані від користувача: параметри адреси, поля пошуку і текст сторінок помилок. Символи < > " ' мають стати сутностями, а не розміткою.

          Платформа за відбитками відповіді: #{platform_name(platform, server)}.

          Зробити:
          #{agency_steps(platform, server)}
          Готово, коли той самий параметр пошуку видно на сторінці як звичайний текст, без сирих символів < і >.
        TEXT
      end

      def agency_steps(platform, server)
        case platform
        when :laravel
          <<~TEXT.strip
            1. У Blade виводьте параметр через {{ $q }}. Подвійні дужки екранують HTML самі.
            2. Приберіть {!! $q !!} з пошуку, параметрів адреси і сторінок помилок.
            #{server_note(server)}
          TEXT
        when :symfony
          <<~TEXT.strip
            1. У Twig виводьте параметр через {{ q }}. Автоекранування залиште увімкненим.
            2. Приберіть фільтр |raw з пошуку, параметрів адреси і сторінок помилок.
            #{server_note(server)}
          TEXT
        when :yii
          <<~TEXT.strip
            1. Виводьте параметр через Html::encode($q).
            2. Не друкуйте $_GET['q'] напряму в шаблоні.
            #{server_note(server)}
          TEXT
        when :wordpress
          <<~TEXT.strip
            1. Виводьте параметр пошуку через esc_html() або esc_attr(), якщо значення стоїть в атрибуті.
            2. Не друкуйте $_GET['q'] у HTML без цих функцій.
            #{server_note(server)}
          TEXT
        when :php
          <<~TEXT.strip
            1. Перед виводом параметра прогоніть його через htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8').
            2. Не друкуйте $_GET і $_POST напряму в HTML.
            #{server_note(server)}
          TEXT
        when :django
          <<~TEXT.strip
            1. Залиште автоекранування шаблонів Django увімкненим і виводьте параметр звичайним {{ q }}.
            2. Приберіть |safe і mark_safe з параметрів запиту, пошуку і сторінок помилок.
            #{server_note(server)}
          TEXT
        when :flask
          <<~TEXT.strip
            1. Залиште автоекранування Jinja2 увімкненим і виводьте параметр звичайним {{ q }}.
            2. Приберіть |safe і Markup() з request.args.
            #{server_note(server)}
          TEXT
        when :rails
          <<~TEXT.strip
            1. Виводьте параметр через <%= params[:q] %>. Такий вивід екранує HTML сам.
            2. Приберіть raw, html_safe і <%== %> з виводу параметрів адреси, пошуку і сторінок помилок.
            #{server_note(server)}
          TEXT
        else
          <<~TEXT.strip
            1. Фреймворк за відповіддю не визначити. Екранування робить шаблон сторінки.
            2. Перед виводом параметрів адреси і пошуку перетворюйте < > " ' на HTML-сутності.
            #{server_note(server)}
          TEXT
        end
      end

      def server_note(server)
        case server
        when :apache
          "3. Apache httpd сам HTML не екранує. Це має робити код сторінки."
        when :nginx
          "3. nginx сам HTML не екранує. Це має робити код сторінки."
        else
          "3. Вебсервер сам HTML не екранує. Це має робити код сторінки."
        end
      end

      def prompt_for(response)
        platform = app_platform(response)
        server = web_server(response)
        <<~TEXT.strip
          Сайт віддзеркалює параметр пошуку q без HTML-екранування. Символи < > " ' мають стати сутностями, а не розміткою.
          Схоже, що проєкт — #{platform_name(platform, server)}.
          #{prompt_steps(platform, server)}
          Маркер перевірки не містить виконуваного коду. Не пропонуй робочий приклад атаки. Поясни простою мовою, що змінилось.
        TEXT
      end

      def prompt_steps(platform, server)
        front = case server
        when :apache
          "Вебсервер — Apache httpd. Він HTML не екранує, тож правку роби в коді сторінки. Конфіг nginx не пропонуй."
        when :nginx
          "Вебсервер — nginx. Він HTML не екранує, тож правку роби в коді сторінки."
        else
          "Вебсервер не визначити. Екранування все одно робиться в шаблоні, не в конфігу вебсервера."
        end

        case platform
        when :laravel
          "Це Laravel. Виводь параметр через {{ $q }} і прибери {!! !! } з пошуку, параметрів адреси і сторінок помилок. #{front} Конфіг Rails не пропонуй."
        when :symfony
          "Це Symfony. Виводь параметр через {{ q }} у Twig і прибери фільтр |raw. #{front} Конфіг Rails не пропонуй."
        when :yii
          "Це Yii. Виводь параметр через Html::encode($q). Не друкуй $_GET напряму. #{front} Конфіг Rails не пропонуй."
        when :wordpress
          "Це WordPress. Виводь параметр через esc_html() або esc_attr(). #{front} Конфіг Rails не пропонуй."
        when :php
          "Це PHP, точний фреймворк невідомий. Перед виводом використай htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'). Якщо це Laravel, Symfony або Yii, екрануй засобами їхніх шаблонів, а не через raw. #{front} Конфіг Rails не пропонуй."
        when :django
          "Це Django. Залиш автоекранування шаблонів і прибери |safe та mark_safe з параметрів запиту. #{front}"
        when :flask
          "Це Flask. Залиш автоекранування Jinja2 і прибери |safe та Markup() з request.args. #{front}"
        when :rails
          "Це Ruby on Rails. Перевір шаблони ERB і контролери. Параметри запиту виводь через <%= %>, яке екранує HTML саме. Прибери raw() і html_safe з виводу параметрів адреси, пошуку і сторінок помилок. #{front}"
        when :apache
          "Фреймворк за головною не визначити. #{front} Перед виводом параметра перетворюй < > \" ' на HTML-сутності."
        else
          "#{front} Перед виводом параметра перетворюй < > \" ' на HTML-сутності."
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
