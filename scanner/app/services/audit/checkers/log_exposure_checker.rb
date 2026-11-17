module Audit
  module Checkers
    # Шукає лише типові адреси журналів. Рядки з файлу у звіт не копіює.
    class LogExposureChecker < BaseChecker
      CATEGORY = "A09:2025 – Security Logging and Alerting Failures"
      SAMPLE_BYTES = 8192
      OPEN_STATUSES = [200, 206].freeze
      LOG_PATHS = [
        "/log/production.log",
        "/log/development.log",
        "/storage/logs/laravel.log",
        "/wp-content/debug.log",
        "/debug.log",
        "/error.log",
        "/logs/error.log",
        "/logs/development.log",
        "/dev.log"
      ].freeze
      TIME_SIGNATURE = /\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}|\[\d{2}-[A-Za-z]{3}-\d{4}\s\d{2}:\d{2}:\d{2}/.freeze
      LEVEL_SIGNATURE = /\b(ERROR|FATAL|WARN|WARNING|INFO|DEBUG|CRITICAL|PHP Fatal error|PHP Notice|Started GET|Completed 200 OK|Stack trace:|Traceback)\b/.freeze

      def perform
        hits = LOG_PATHS.map { |path| probe(path) }
        open_hits = hits.select { |hit| hit[:open] }
        return exposed(hits, open_hits) if open_hits.any?

        closed(hits)
      end

      def error_result(message)
        Result.new(
          category: CATEGORY,
          title: "Не вдалося перевірити журнали",
          status: :error,
          business_risk: "Перевірку не вдалося закінчити, тому вважати, що журнали закриті від інтернету, не можна. Повторіть перевірку, коли сайт відповідає.",
          technical_lang: "Запити на типові адреси журналів не завершились. Причина: #{message} Висновку про публічний доступ немає.",
          remediation_agency: "Завдання для виправлення не сформоване: сканер не отримав відповідь сайту.",
          remediation_ai_prompt: ""
        )
      end

      private

      def probe(path)
        response = fetch(path, headers: { "Range" => "bytes=0-#{SAMPLE_BYTES - 1}" })
        text = response.body.to_s.byteslice(0, SAMPLE_BYTES).to_s
        html = html_page?(response, text)
        markers = html ? [] : log_markers(text)
        {
          path: path,
          status: response.status,
          open: OPEN_STATUSES.include?(response.status) && markers.any?,
          markers: markers,
          html: html,
          response: response
        }
      end

      def html_page?(response, text)
        type = response.headers["content-type"].to_s
        return true if type.match?(%r{text/html}i)

        text.match?(/<!doctype\s+html|<html/i)
      end

      def log_markers(text)
        markers = []
        markers << "мітка дати й часу" if text.match?(TIME_SIGNATURE)
        markers << "рівень або службовий маркер журналу" if text.match?(LEVEL_SIGNATURE)
        markers
      end

      def exposed(hits, open_hits)
        response = open_hits.first[:response]
        Result.new(
          category: CATEGORY,
          title: "Публічний доступ до системних та налагоджувальних журналів (Логів)",
          status: :failed,
          business_risk: risk_detail,
          technical_lang: technical_for(hits, :failed),
          remediation_agency: agency_for(response, open_hits),
          remediation_ai_prompt: prompt_for(response, open_hits)
        )
      end

      def closed(hits)
        Result.new(
          category: CATEGORY,
          title: "Захист журналів подій від публічного доступу та моніторинг",
          status: :passed,
          business_risk: closed_note,
          technical_lang: technical_for(hits, :passed),
          remediation_agency: "Типові адреси журналів не віддають файл. Окреме завдання не потрібне.",
          remediation_ai_prompt: ""
        )
      end

      def risk_detail
        "Журнали роботи сервера (зокрема логи розробки development.log або журнали помилок) відкриті для читання з інтернету. " \
        "У таких файлах часто зберігаються паролі, токени сесій, персональні дані та email-адреси клієнтів, " \
        "а також внутрішні шляхи коду, що допомагає зловмисникам зламати сайт."
      end

      def closed_note
        "Типові файли журналів (production.log, development.log, laravel.log, debug.log) не читаються з інтернету. " \
        "Однак зовнішній сканер не може перевірити, чи записуються всередині сервера невдалі спроби входу, помилки оплат та підозрілі запити, " \
        "як довго зберігаються логи і чи отримує адміністратор сповіщення про інциденти — це налаштовується безпосередньо на сервері."
      end

      def technical_for(hits, status)
        verdict = if status == :failed
          "Червоний статус: хоча б одна адреса віддала журнал."
        else
          "Зелений статус: жодна адреса не віддала журнал. #{closed_note}"
        end

        <<~TEXT.strip
          Перевірено #{hits.size} типових адрес. Запит просив лише перші #{SAMPLE_BYTES} байт (Range).
          Рядки журналу у звіт не копіюються.
          #{hits.map { |hit| path_line(hit) }.join("\n")}
          #{verdict}
          Це OWASP Top 10 #{CATEGORY}.
        TEXT
      end

      def path_line(hit)
        detail = if hit[:open]
          "журнал: #{hit[:markers].join(', ')}"
        elsif hit[:html] && OPEN_STATUSES.include?(hit[:status])
          "HTML-сторінка, не журнал"
        else
          "журналу немає"
        end
        "#{hit[:path]} → HTTP #{hit[:status]}, #{detail}."
      end

      def agency_for(response, open_hits)
        platform = app_platform(response)
        server = web_server(response)
        paths = open_hits.map { |hit| hit[:path] }.join("\n")
        <<~TEXT.strip
          Завдання: закрийте зовнішній доступ до журналів. Відвідувач має отримувати 403 або 404, а не текст журналу. Приберіть development.log і debug.log з сервера, який дивиться в інтернет. Корінь сайту має бути лише публічна тека.
          Платформа за відбитками відповіді: #{platform_name(platform, server)}.
          Відкриті адреси:
          #{paths}
          Зробити:
          #{agency_steps(platform, server)}
          Готово, коли ці адреси більше не містять рядків журналу.
        TEXT
      end

      def agency_steps(platform, server)
        case platform
        when :laravel
          <<~TEXT.strip
            1. Журнали лишайте в storage/logs. Ця тека не має відкриватися з інтернету.
            2. Приберіть development-журнали з робочого сервера.
            #{server_deny(server)}
          TEXT
        when :symfony
          <<~TEXT.strip
            1. Журнали лишайте у var/log. Корінь сайту для відвідувачів — public.
            2. Приберіть журнали розробки з робочого сервера.
            #{server_deny(server)}
          TEXT
        when :yii
          <<~TEXT.strip
            1. Журнали лишайте у runtime/logs, не у вебкорені.
            2. Приберіть журнали розробки з робочого сервера.
            #{server_deny(server)}
          TEXT
        when :wordpress
          <<~TEXT.strip
            1. Файл wp-content/debug.log не має віддаватися з інтернету. Після діагностики приберіть його з робочого сервера.
            2. Закрийте віддачу файлів .log на вебсервері:
            #{server_deny(server)}
          TEXT
        when :php
          <<~TEXT.strip
            1. Корінь сайту для відвідувачів має бути лише публічна тека, не вся тека проєкту. Журнали туди не кладіть.
            2. Приберіть development.log і debug.log з робочого сервера.
            #{server_deny(server)}
          TEXT
        when :django
          <<~TEXT.strip
            1. Не кладіть debug.log у теку, з якої сайт віддає файли.
            2. Приберіть журнали розробки з робочого сервера.
            #{server_deny(server)}
          TEXT
        when :flask
          <<~TEXT.strip
            1. Не кладіть журнали в теку, з якої сайт віддає файли.
            2. Приберіть журнали розробки з робочого сервера.
            #{server_deny(server)}
          TEXT
        when :rails
          <<~TEXT.strip
            1. Журнали лишайте в теці log поруч із застосунком, не всередині public.
            2. Видаліть public/log і будь-які файли .log з публічної теки.
            #{server_deny(server)}
          TEXT
        else
          <<~TEXT.strip
            1. Фреймворк за відповіддю не визначити. Журнали не тримайте в теці, з якої сайт віддає файли.
            2. Приберіть development.log і debug.log з робочого сервера.
            #{server_deny(server)}
          TEXT
        end
      end

      def server_deny(server)
        case server
        when :apache
          apache_deny
        when :nginx
          nginx_deny
        else
          "#{apache_deny}\n#{nginx_deny}"
        end
      end

      def apache_deny
        [
          "3. Apache httpd, відповідь 403:",
          "   <FilesMatch \"\\.log$\">",
          "     Require all denied",
          "   </FilesMatch>",
          "   <LocationMatch \"^/(log|logs|storage/logs)/\">",
          "     Require all denied",
          "   </LocationMatch>"
        ].join("\n")
      end

      def nginx_deny
        [
          "3. nginx, відповідь 403:",
          "   location ~* \\.log$ { deny all; }",
          "   location ^~ /log/ { deny all; }",
          "   location ^~ /logs/ { deny all; }",
          "   location ^~ /storage/logs/ { deny all; }"
        ].join("\n")
      end

      def prompt_for(response, open_hits)
        platform = app_platform(response)
        server = web_server(response)
        paths = open_hits.map { |hit| hit[:path] }.join("\n")
        <<~TEXT.strip
          З інтернету читаються журнали сайту. Закрий їх: відвідувач має отримувати 403 або 404, а не текст журналу. Прибери development.log і debug.log з робочого сервера. Корінь сайту лиши лише публічною текою.
          Відкриті адреси:
          #{paths}
          Не цитуй рядки журналу і не виводь токени, паролі чи адреси пошти з файлу.
          Схоже, що проєкт — #{platform_name(platform, server)}.
          #{prompt_steps(platform, server)}
          Поясни простою мовою, що змінилось.
        TEXT
      end

      def prompt_steps(platform, server)
        front = case server
        when :apache
          "Вебсервер — Apache httpd. Дай FilesMatch для .log і LocationMatch для /log/, /logs/ і /storage/logs/ з Require all denied. Конфіг nginx не пропонуй."
        when :nginx
          "Вебсервер — nginx. Дай location для .log, /log/, /logs/ і /storage/logs/ з deny all."
        else
          "Вебсервер не визначити: дай варіант і для Apache (Require all denied), і для nginx (deny all)."
        end

        case platform
        when :laravel
          "Це Laravel. Журнали лишай у storage/logs, не в public. #{front} Конфіг Rails не пропонуй."
        when :symfony
          "Це Symfony. Журнали лишай у var/log, корінь сайту — public. #{front} Конфіг Rails не пропонуй."
        when :yii
          "Це Yii. Журнали лишай у runtime/logs, не у вебкорені. #{front} Конфіг Rails не пропонуй."
        when :wordpress
          "Це WordPress. wp-content/debug.log не має віддаватися з інтернету. Після діагностики прибери файл. #{front} Конфіг Rails не пропонуй."
        when :php
          "Це PHP, точний фреймворк невідомий. Корінь сайту зроби лише публічною текою. Якщо це Laravel, Symfony або Yii, журнали лишай у їхніх службових теках, не в public. #{front} Конфіг Rails не пропонуй."
        when :django
          "Це Django. Не клади debug.log у теку, з якої сайт віддає файли. #{front}"
        when :flask
          "Це Flask. Не клади журнали в теку, з якої сайт віддає файли. #{front}"
        when :rails
          "Це Ruby on Rails. Журнали лишай у теці log поруч із застосунком і прибери їх із public. #{front}"
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
