module Audit
  module Checkers
    # Неіснуюча адреса. Якщо у відповіді є стектрейс або забули про режим налагодження
    class DebugModeChecker < BaseChecker
      PATH = "/__dast_debug_probe_404_test"

      DEBUG_SIGNATURES = [
        "ActionController::RoutingError",
        "Routes match in",
        "Rails.root:",
        "Whoops\\Exception",
        "Traceback (most recent call last)",
        "DJANGO_SETTINGS_MODULE",
        "Stack trace:",
        "ActiveRecord::StatementInvalid",
        "vendor/bundle"
      ].freeze

      RAILS_SIGNATURES = [
        "ActionController::RoutingError",
        "Routes match in",
        "Rails.root:",
        "ActiveRecord::StatementInvalid",
        "vendor/bundle"
      ].freeze

      def perform
        response = fetch(PATH)
        found = signatures_in(response.body)
        return leaked(response, found) if found.any?

        clean(response)
      end

      def error_result(message)
        Result.new(
          title: "Не вдалося перевірити сторінку помилки",
          status: :error,
          business_risk: "Перевірку не вдалося закінчити, тому вважати, що відвідувач не бачить внутрішніх шляхів і стек-трейсів, не можна. Повторіть перевірку, коли сайт відповідає.",
          technical_lang: "Запит на неіснуючу адресу не завершився. Причина: #{message} Висновку про режим налагодження немає.",
          remediation_agency: "Завдання для виправлення не сформоване: сканер не отримав відповідь сайту.",
          remediation_ai_prompt: ""
        )
      end

      private

      def signatures_in(body)
        text = body.to_s
        DEBUG_SIGNATURES.select { |signature| text.include?(signature) }
      end

      def leaked(response, found)
        platform = detect_platform(found)
        Result.new(
          title: title,
          status: :failed,
          business_risk: business_risk,
          technical_lang: technical_for_leak(response, found, platform),
          remediation_agency: agency_for(platform),
          remediation_ai_prompt: prompt_for(platform)
        )
      end

      def clean(response)
        Result.new(
          title: title,
          status: :passed,
          business_risk: "На неіснуючій адресі сайт не показує внутрішні шляхи, список файлів і текст помилки для розробника. Відвідувач бачить звичайну відмову або перенаправлення.",
          technical_lang: technical_for_clean(response),
          remediation_agency: "У відповіді немає сигнатур режиму налагодження. Окреме завдання не потрібне.",
          remediation_ai_prompt: ""
        )
      end

      def title
        "Режим налагодження та витік технічних помилок (Debug Mode)"
      end

      def business_risk
        "Сайт показує стороннім відвідувачам внутрішню структуру сервера, шляхи до файлів та системні помилки розробки. " \
          "Це дає зловмисникам детальну карту технічного влаштування сайту для підбору точкових атак."
      end

      def technical_for_leak(response, found, platform)
        <<~TEXT.strip
          GET #{PATH} повернув HTTP #{response.status}. У тілі є ознаки сторінки для розробника, а не звичайної відмови.
          Знайдені сигнатури: #{found.join(', ')}. Сам стек-трейс у звіт не копіюється.
          Платформа за цими ознаками: #{platform_name(platform)}.
          OWASP Top 10 A05:2021 Security Misconfiguration: consider_all_requests_local, APP_DEBUG або аналог увімкнений для зовнішніх запитів.
          Очікувана поведінка: HTTP 404 або короткий редірект без назв класів винятків, Rails.root, Whoops і шляхів на кшталт vendor/bundle.
        TEXT
      end

      def technical_for_clean(response)
        kind = if [301, 302, 303, 307, 308].include?(response.status)
          "Це перенаправлення без тексту внутрішньої помилки."
        elsif response.status == 404
          "Це звичайна відмова 404 без стек-трейса."
        else
          "Сигнатур режиму налагодження в тілі немає."
        end

        "GET #{PATH} повернув HTTP #{response.status}. #{kind}"
      end

      def agency_for(platform)
        <<~TEXT.strip
          Завдання: вимкнути режим налагодження на боці веб-додатка (встановити оточення production, вимкнути детальний вивід помилок клієнту) та налаштувати кастомну лаконічну сторінку 404 без виводу стек-трейсів.

          Платформа за відбитками відповіді: #{platform_name(platform)}.

          Зробити:
          #{steps_for(platform)}
          Готово, коли запит на неіснуючу адресу повертає коротку сторінку або редірект, а в тілі немає ActionController::RoutingError, Rails.root, Whoops і шляхів до файлів проєкту.
        TEXT
      end

      def prompt_for(platform)
        case platform
        when :rails
          "Configure production error handling in Ruby on Rails to serve static 404/500 error pages without rendering ActionController traces or environment paths."
        when :php
          "Вимкни показ помилок відвідувачам у PHP (display_errors=Off, APP_DEBUG=false). Неіснуюча адреса має віддавати коротку сторінку 404 без Whoops і без шляхів до файлів. Поясни простою мовою, що змінилось."
        when :django
          "Постав Django DEBUG=False і власні шаблони 404/500. Сторінка помилки не має містити Traceback і DJANGO_SETTINGS_MODULE. Поясни простою мовою, що змінилось."
        else
          "Вимкни детальні сторінки помилок для зовнішніх відвідувачів і віддавай коротку статичну 404/500 без стек-трейса і шляхів до файлів. Поясни простою мовою, що змінилось."
        end
      end

      def steps_for(platform)
        case platform
        when :rails
          <<~TEXT.strip
            1. На сервері лишіть RAILS_ENV=production. У production.rb має бути config.consider_all_requests_local = false.
            2. Не вмикайте показ винятків клієнту. Невідомий маршрут має брати public/404.html, а не сторінку ActionController::RoutingError.
            3. Сторінка 404 — короткий текст без шляхів до файлів, списку маршрутів і gem-ів.
          TEXT
        when :php
          <<~TEXT.strip
            1. Вимкніть Whoops і display_errors на production сайті. Для Laravel це APP_DEBUG=false в оточенні, не у файлі, який віддає вебсервер.
            2. Невідома адреса має віддавати коротку сторінку 404 без класу винятку і без шляху до проєкту.
          TEXT
        when :django
          <<~TEXT.strip
            1. Поставте DEBUG=False у production налаштуваннях.
            2. Підключіть власні шаблони 404 і 500 без трейсбека і без DJANGO_SETTINGS_MODULE.
          TEXT
        else
          <<~TEXT.strip
            1. Вимкніть детальний вивід помилок для запитів з інтернету.
            2. Віддавайте коротку сторінку 404 без назв внутрішніх класів і без шляхів на диску.
          TEXT
        end
      end

      def detect_platform(found)
        return :rails if (found & RAILS_SIGNATURES).any?
        return :php if found.any? { |signature| signature.include?("Whoops") }
        return :django if (found & ["Traceback (most recent call last)", "DJANGO_SETTINGS_MODULE"]).any?

        :unknown
      end

      def platform_name(platform)
        {
          rails: "Ruby on Rails. На це вказують ActionController, Rails.root, ActiveRecord або шлях vendor/bundle",
          php: "PHP зі сторінкою Whoops. Типово це Laravel або інший фреймворк, який лишив показ винятків увімкненим",
          django: "Django або Python. На це вказують трейсбек або DJANGO_SETTINGS_MODULE",
          unknown: "не визначено. Завдання нижче універсальне: вимкнути детальні помилки і лишити коротку сторінку 404"
        }.fetch(platform)
      end
    end
  end
end
