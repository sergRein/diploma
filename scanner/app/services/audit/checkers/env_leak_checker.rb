module Audit
  module Checkers
    # ENV leak
    class EnvLeakChecker < BaseChecker
      PATH = "/.env"

      # ENV names list
      SECRET_LINE = /
        (?:\A|[\r\n])
        \s*(?:export\s+)?
        (?<key>
          APP_KEY |
          APP_SECRET |
          DB_PASSWORD |
          DATABASE_URL |
          SECRET_KEY_BASE |
          RAILS_MASTER_KEY |
          DJANGO_SECRET_KEY |
          AUTH_SECRET |
          SESSION_SECRET |
          AUTH_KEY |
          SECURE_AUTH_KEY |
          LOGGED_IN_KEY |
          NONCE_KEY |
          AUTH_SALT |
          COOKIE_VALIDATION_KEY |
          HASH_SALT |
          DRUPAL_HASH_SALT |
          AWS_SECRET_ACCESS_KEY |
          AWS_ACCESS_KEY_ID |
          [A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY)
        )
        \s*=\s*\S
      /ix

      def perform
        response = fetch(PATH)
        keys = secret_keys(response.body)
        return leaked(response, keys) if keys.any?

        closed(response)
      end

      def error_result(message)
        Result.new(
          title: "Не вдалося перевірити файл зі змінними",
          status: :error,
          business_risk: "Перевірку не вдалося закінчити, тому вважати що 'все добре»' або 'паролі відкриті' не можна. Повторіть перевірку, коли сайт парцює.",
          technical_lang: "Запит до .env не завершився. Причина: #{message} Висновку про витік немає.",
          remediation_agency: "Завдання для виправлення не сформоване: сканер не отримав відповідь сайту",
          remediation_ai_prompt: ""
        )
      end

      private

      def secret_keys(body)
        keys = []
        body.to_s.scan(SECRET_LINE) { keys << Regexp.last_match[:key].upcase }
        keys.uniq
      end

      def leaked(response, keys)
        platform = detect_platform(response, keys)
        Result.new(
          title: "Паролі сайту можна прочитати з інтернету",
          status: :failed,
          business_risk: business_risk_for_leak,
          technical_lang: technical_for_leak(response, keys, platform),
          remediation_agency: agency_for(platform, keys),
          remediation_ai_prompt: prompt_for(platform, keys)
        )
      end

      def closed(response)
        Result.new(
          title: "Файл із паролями з інтернету не відкривається",
          status: :passed,
          business_risk: "Зараз цей файл з паролями з інтернету не читається. Відвідувач не отримує ні пароль від бази клієнтів, ні секретний ключ самої програми.",
          technical_lang: technical_for_closed(response),
          remediation_agency: "Запит до .env не показав секретних присвоєнь на кшталт DB_PASSWORD= або APP_KEY=.",
          remediation_ai_prompt: ""
        )
      end

      def business_risk_for_leak
        "Будь-хто в інтернеті може відкрити службовий файл сайту і прочитати пароль від бази та секретний ключ програми. " \
        "З паролем можна забрати базу клієнтів: телефони, замовлення, листи. " \
        "З секретним ключем можна підробити вхід до панелі керування. " \
        "Для невеликого бізнесу це витік даних, зупинка роботи і необхідність пояснювати це клієнтам."
      end

      def technical_for_leak(response, keys, platform)
        <<~TEXT.strip
          GET /.env повернув HTTP #{response.status} і тіло, схоже на файл середовища, а не на звичайну сторінку.
          Знайдені присвоєння: #{keys.join(', ')}. Самі значення у звіт не копіюються і вважаються вже розкритими.
          Платформа за відбитками відповіді: #{platform_name(platform)}.
          Для фахівця це OWASP Top 10 A05:2021 Security Misconfiguration, CWE-538 (відкритий службовий файл) і CWE-312 (секрети у відкритому вигляді).
          Очікувана поведінка: HTTP 404 або 403, без рядків DB_PASSWORD=, APP_KEY= та інших секретних присвоєнь.
          Код 200 сам по собі не є доказом: якщо тіло — звичайна HTML-сторінка без таких рядків, сканер вважає це хибним 200 і витік не ставить.
        TEXT
      end

      def technical_for_closed(response)
        reason = if [401, 403, 404].include?(response.status)
          "Сервер відмовив у доступі до файлу."
        elsif html_page?(response.body)
          "Відповідь схожа на звичайну HTML-сторінку (хибний код 200 або м'яка сторінка «не знайдено»), секретних присвоєнь у ній немає."
        else
          "У тілі відповіді немає секретних присвоєнь."
        end

        "GET /.env повернув HTTP #{response.status}. #{reason} Сигнатур DB_PASSWORD=, APP_KEY= та подібних немає."
      end

      def html_page?(body)
        body.to_s.lstrip.match?(/\A(?:<!doctype html|<html\b)/i)
      end

      def detect_platform(response, keys)
        powered = response.headers["x-powered-by"].to_s
        server = response.headers["server"].to_s
        cookie = response.headers["set-cookie"].to_s

        return :laravel if keys.include?("APP_KEY") || cookie.match?(/laravel_session/i)
        return :symfony if keys.include?("APP_SECRET")
        return :wordpress if (keys & %w[AUTH_KEY SECURE_AUTH_KEY LOGGED_IN_KEY NONCE_KEY AUTH_SALT]).any?
        return :yii if keys.include?("COOKIE_VALIDATION_KEY")
        return :drupal if (keys & %w[HASH_SALT DRUPAL_HASH_SALT]).any?
        return :rails if (keys & %w[SECRET_KEY_BASE RAILS_MASTER_KEY]).any?
        return :next if (keys & %w[NEXTAUTH_SECRET AUTH_SECRET]).any?
        return :django if keys.include?("DJANGO_SECRET_KEY") || (keys.include?("SECRET_KEY") && powered.match?(/python|django|wsgi/i))
        return :node if keys.include?("SESSION_SECRET") || powered.match?(/express/i) || server.match?(/node/i)
        return :php if powered.match?(/php/i) || server.match?(/php/i)
        return :python if powered.match?(/python|wsgi/i)

        :unknown
      end

      def platform_name(platform)
        {
          laravel: "Laravel (PHP). На це вказує APP_KEY",
          symfony: "Symfony (PHP). На це вказує APP_SECRET",
          wordpress: "WordPress. На це вказують солі AUTH_KEY або SECURE_AUTH_KEY у файлі середовища",
          yii: "Yii (PHP). На це вказує COOKIE_VALIDATION_KEY",
          drupal: "Drupal. На це вказує HASH_SALT",
          rails: "Ruby on Rails. На це вказують SECRET_KEY_BASE або RAILS_MASTER_KEY",
          next: "Next.js. На це вказує NEXTAUTH_SECRET або AUTH_SECRET",
          django: "Django (Python). На це вказує DJANGO_SECRET_KEY",
          node: "Node.js. На це вказує SESSION_SECRET або заголовок сервера",
          php: "PHP. Точний фреймворк за іменами змінних не визначити",
          python: "Python. Точний фреймворк за іменами змінних не визначити",
          unknown: "не визначено. Завдання нижче універсальне"
        }.fetch(platform)
      end

      def agency_for(platform, keys)
        <<~TEXT.strip
          Завдання: закрити публічний доступ до файлу .env.

          Що знайдено: GET /.env віддає файл середовища. Є присвоєння: #{keys.join(', ')}.
          Платформа: #{platform_name(platform)}.
          Значення секретів у це завдання не копіюються. Їх треба вважати відомими чужим людям.

          Зробити:
          #{steps_for(platform)}
          Готово, коли GET /.env повертає 404 або 403, а в тілі немає рядків на кшталт DB_PASSWORD= і APP_KEY=.
        TEXT
      end

      def prompt_for(platform, keys)
        <<~TEXT.strip
          На сайті відкритий файл середовища: GET /.env повертає секрети (знайдені імена: #{keys.join(', ')}). Значення не повторюй і не вигадуй.
          Схоже, що проєкт — #{platform_name(platform)}.
          Закрий витік саме для цієї платформи:
          #{steps_for(platform)}
          Після правок поясни простою мовою, що змінилось і чому старі паролі треба замінити.
        TEXT
      end

      def steps_for(platform)
        close_file = "Запит до /.env має давати 404 або 403, без рядків із секретами. Заборони вебсерверу віддавати файли, що починаються з крапки."

        case platform
        when :laravel
          <<~TEXT.strip
            1. Прибери .env з public/. #{close_file}
            2. Зміни пароль бази.
            3. Згенеруй новий ключ: php artisan key:generate. Старий APP_KEY уже розкритий.
            4. Не копіюй .env у public/ під час деплою і не клади його в git.
          TEXT
        when :symfony
          <<~TEXT.strip
            1. Прибери .env з public/. #{close_file}
            2. Згенеруй новий APP_SECRET. Старий уже розкритий. Пароль бази теж заміни.
            3. Секрети тримай у змінних оточення або в Symfony secrets, не у файлі, який віддає nginx.
          TEXT
        when :wordpress
          <<~TEXT.strip
            1. #{close_file} Для звичайного WordPress секрети мають жити у wp-config.php поза вебкоренем, не в /.env.
            2. Згенеруй нові солі AUTH_KEY, SECURE_AUTH_KEY, LOGGED_IN_KEY, NONCE_KEY і AUTH_SALT. Старі вже розкриті.
            3. Зміни пароль бази.
          TEXT
        when :yii
          <<~TEXT.strip
            1. Прибери .env з теки, яку віддає вебсервер. #{close_file}
            2. Згенеруй новий cookieValidationKey. Старий уже розкритий.
            3. Зміни пароль бази.
          TEXT
        when :drupal
          <<~TEXT.strip
            1. #{close_file}
            2. Заміни hash_salt у settings.php. Старий HASH_SALT уже розкритий.
            3. Зміни пароль бази. Секрети читай з оточення, не з файла в корені сайту.
          TEXT
        when :rails
          <<~TEXT.strip
            1. Прибери .env з public/. #{close_file}
            2. Зміни пароль бази, secret_key_base і RAILS_MASTER_KEY. Старі значення вже розкриті.
            3. Секрети лиши у змінних оточення на сервері.
          TEXT
        when :next
          <<~TEXT.strip
            1. Прибери .env з public/ і зі статичного експорту. #{close_file}
            2. Згенеруй новий NEXTAUTH_SECRET або AUTH_SECRET. Старий уже розкритий.
            3. Зміни пароль бази. На хостингу поклади секрети в змінні оточення, не в файл поруч із сайтом.
          TEXT
        when :django
          <<~TEXT.strip
            1. Прибери .env зі static/ і з кореня, з якого nginx роздає файли. #{close_file}
            2. Зміни SECRET_KEY у налаштуваннях Django і пароль бази. Старі значення вже розкриті.
            3. Читай секрети з оточення процесу.
          TEXT
        when :node
          <<~TEXT.strip
            1. Прибери .env з папки, яку віддає express.static або nginx. #{close_file}
            2. Зміни SESSION_SECRET і пароль бази. Старі значення вже розкриті.
            3. Секрети читай з оточення процесу, не з файла в документ-руті.
          TEXT
        else
          <<~TEXT.strip
            1. Прибери .env з публічної теки сайту. #{close_file}
            2. Зміни пароль бази і секретні ключі додатка: старі значення вже розкриті.
            3. Зберігай секрети лише в оточенні сервера, поза вебкоренем.
          TEXT
        end
      end
    end
  end
end
