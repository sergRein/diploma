module Audit
  module Checkers
    # Неіснуюча адреса. Якщо у відповіді є стектрейс або забули про режим налагодження
    class DebugModeChecker < BaseChecker
      PATH = "/__dast_debug_probe_404_test"

      DEBUG_SIGNATURES = [
        "ActionController::RoutingError",
        "Routes match in",
        "Rails.root:",
        "ActiveRecord::StatementInvalid",
        "vendor/bundle",
        "Whoops\\Exception",
        "Spatie\\LaravelIgnition",
        "vendor/laravel",
        "Symfony\\Component\\HttpKernel\\Exception",
        "Symfony\\Component\\ErrorHandler",
        "yii\\web\\NotFoundHttpException",
        "CodeIgniter\\Exceptions\\",
        "DJANGO_SETTINGS_MODULE",
        "Werkzeug Debugger",
        "Traceback (most recent call last)",
        "Whitelabel Error Page",
        "Server Error in '/' Application",
        "Sinatra doesn't know this ditty",
        "Phoenix.Router.NoRouteError",
        "Exception Report",
        "Stack trace:"
      ].freeze

      PLATFORM_SIGNATURES = {
        rails: ["ActionController::RoutingError", "Routes match in", "Rails.root:", "ActiveRecord::StatementInvalid", "vendor/bundle"],
        laravel: ["Whoops\\Exception", "Spatie\\LaravelIgnition", "vendor/laravel"],
        symfony: ["Symfony\\Component\\HttpKernel\\Exception", "Symfony\\Component\\ErrorHandler"],
        yii: ["yii\\web\\NotFoundHttpException"],
        codeigniter: ["CodeIgniter\\Exceptions\\"],
        django: ["DJANGO_SETTINGS_MODULE"],
        flask: ["Werkzeug Debugger"],
        python: ["Traceback (most recent call last)"],
        spring: ["Whitelabel Error Page"],
        dotnet: ["Server Error in '/' Application"],
        sinatra: ["Sinatra doesn't know this ditty"],
        phoenix: ["Phoenix.Router.NoRouteError"],
        tomcat: ["Exception Report"]
      }.freeze

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
        found = DEBUG_SIGNATURES.select { |signature| text.include?(signature) }
        found << "PHP display_errors" if text.include?("Fatal error") && text.include?(".php on line")
        found << "Express default 404" if text.include?("Cannot GET #{PATH}")
        found
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
        <<~TEXT.strip
          На неіснуючій адресі сайт показує сторінку для розробника. Схоже, що це #{platform_name(platform)}.
          #{prompt_steps(platform)}
          Стек-трейс і шляхи до файлів у відповідь не копіюй. Поясни простою мовою, що змінилось.
        TEXT
      end

      def prompt_steps(platform)
        case platform
        when :rails
          "Налаштуй обробку помилок Ruby on Rails для production: віддавай статичні сторінки 404 і 500, без трас ActionController і без шляхів до файлів середовища. config.consider_all_requests_local має бути false."
        when :laravel
          "Для Laravel вимкни Ignition і Whoops для відвідувачів: APP_DEBUG=false у змінних оточення, не у файлі, який віддає сайт. Невідома адреса має віддавати коротку 404 без Illuminate і без шляхів vendor/laravel."
        when :symfony
          "Для Symfony вимкни показ винятків на production: APP_DEBUG=0 і APP_ENV=prod. Сторінка 404 має бути власним шаблоном, без Symfony\\Component\\HttpKernel і без панелі профайлера."
        when :yii
          "Для Yii вимкни YII_DEBUG і YII_ENV=dev на бойовому сайті. Невідома адреса не має показувати yii\\web\\NotFoundHttpException і шлях до проєкту."
        when :codeigniter
          "Для CodeIgniter постав CI_ENVIRONMENT=production. Сторінка 404 не має містити CodeIgniter\\Exceptions і шляхів до файлів."
        when :php
          "У PHP вимкни показ помилок відвідувачам: display_errors=Off. Якщо це Laravel, додатково APP_DEBUG=false. Неіснуюча адреса має віддавати коротку 404 без Fatal error і без рядка .php on line."
        when :django
          "Постав Django DEBUG=False і власні шаблони 404/500. Сторінка не має містити Traceback і DJANGO_SETTINGS_MODULE."
        when :flask
          "Вимкни інтерактивний дебагер Werkzeug на бойовому сайті: debug=False у app.run і FLASK_DEBUG=0. Сторінка помилки не має містити консоль дебагера."
        when :python
          "Вимкни показ трейсбека відвідувачам. Віддавай коротку сторінку 404/500 без Traceback (most recent call last)."
        when :spring
          "Для Spring Boot вимкни Whitelabel Error Page: server.error.whitelabel.enabled=false і server.error.include-stacktrace=never. Віддавай коротку статичну сторінку помилки."
        when :dotnet
          "Для ASP.NET вимкни детальні помилки для зовнішніх запитів: customErrors mode=On або ASPNETCORE_ENVIRONMENT=Production. Не показуй Server Error in '/' Application і стек."
        when :sinatra
          "Для Sinatra вимкни показ розробницької сторінки: set :show_exceptions, false і set :environment, :production. Прибери текст Sinatra doesn't know this ditty."
        when :phoenix
          "Для Phoenix збери реліз з MIX_ENV=prod. Невідомий маршрут не має показувати Phoenix.Router.NoRouteError і шляхи до файлів."
        when :express
          "Для Express постав NODE_ENV=production і власний обробник 404. Прибери типову відповідь Cannot GET із назвою маршруту."
        when :tomcat
          "Для Tomcat вимкни показ Exception Report відвідувачам: у web.xml error-page на 404 і 500, без стека java. Не лишай сторінку Apache Tomcat з трасою."
        else
          "Вимкни детальні сторінки помилок для зовнішніх відвідувачів і віддавай коротку статичну 404/500 без стек-трейса і шляхів до файлів."
        end
      end

      def steps_for(platform)
        case platform
        when :rails
          <<~TEXT.strip
            1. На сервері лишіть RAILS_ENV=production. У production.rb має бути config.consider_all_requests_local = false.
            2. Невідомий маршрут має брати public/404.html, а не сторінку ActionController::RoutingError.
            3. Сторінка 404 — короткий текст без шляхів до файлів, списку маршрутів і gem-ів.
          TEXT
        when :laravel
          <<~TEXT.strip
            1. Поставте APP_DEBUG=false у змінних оточення на сервері, не у файлі з public/.
            2. Невідома адреса має віддавати коротку 404, без Ignition, Whoops і шляхів vendor/laravel.
          TEXT
        when :symfony
          <<~TEXT.strip
            1. Поставте APP_ENV=prod і APP_DEBUG=0.
            2. Підключіть власний шаблон помилки. Приберіть панель профайлера Symfony з відповідей відвідувачам.
          TEXT
        when :yii
          <<~TEXT.strip
            1. Вимкніть YII_DEBUG на бойовому сайті, YII_ENV не має бути dev.
            2. Невідома адреса не має показувати клас yii\\web і шлях до проєкту.
          TEXT
        when :codeigniter
          <<~TEXT.strip
            1. Поставте CI_ENVIRONMENT=production.
            2. Сторінка 404 без класу CodeIgniter\\Exceptions і без шляхів до файлів.
          TEXT
        when :php
          <<~TEXT.strip
            1. Вимкніть display_errors для відвідувачів. Якщо це Laravel, ще й APP_DEBUG=false.
            2. Невідома адреса має віддавати коротку 404 без Fatal error і без рядка з ім'ям .php.
          TEXT
        when :django
          <<~TEXT.strip
            1. Поставте DEBUG=False у бойових налаштуваннях.
            2. Підключіть власні шаблони 404 і 500 без трейсбека і без DJANGO_SETTINGS_MODULE.
          TEXT
        when :flask
          <<~TEXT.strip
            1. Вимкніть дебагер: debug=False і FLASK_DEBUG=0.
            2. Сторінка помилки без консолі Werkzeug.
          TEXT
        when :python
          <<~TEXT.strip
            1. Не віддавайте трейсбек у відповіді для інтернету.
            2. Короткі шаблони 404 і 500 без тексту Traceback.
          TEXT
        when :spring
          <<~TEXT.strip
            1. Вимкніть Whitelabel: server.error.whitelabel.enabled=false, server.error.include-stacktrace=never.
            2. Віддавайте власну коротку сторінку 404 і 500.
          TEXT
        when :dotnet
          <<~TEXT.strip
            1. Для зовнішніх запитів вимкніть детальні помилки: customErrors mode=On або ASPNETCORE_ENVIRONMENT=Production.
            2. Не показуйте жовту сторінку Server Error і стек.
          TEXT
        when :sinatra
          <<~TEXT.strip
            1. set :show_exceptions, false і оточення production.
            2. Приберіть сторінку Sinatra doesn't know this ditty.
          TEXT
        when :phoenix
          <<~TEXT.strip
            1. Зберіть реліз з MIX_ENV=prod.
            2. Невідомий маршрут без Phoenix.Router.NoRouteError і без шляхів до файлів.
          TEXT
        when :express
          <<~TEXT.strip
            1. NODE_ENV=production і власний обробник відсутнього маршруту.
            2. Не віддавайте текст Cannot GET з адресою запиту.
          TEXT
        when :tomcat
          <<~TEXT.strip
            1. У web.xml задайте error-page для 404 і 500.
            2. Відвідувач не має бачити Exception Report і стек Java.
          TEXT
        else
          <<~TEXT.strip
            1. Вимкніть детальний вивід помилок для запитів з інтернету.
            2. Віддавайте коротку сторінку 404 без назв внутрішніх класів і без шляхів на диску.
          TEXT
        end
      end

      def detect_platform(found)
        order = %i[laravel symfony yii codeigniter rails django flask spring dotnet sinatra phoenix express tomcat php python]
        order.each do |platform|
          signatures = platform == :php ? ["PHP display_errors"] : PLATFORM_SIGNATURES[platform]
          signatures = ["Express default 404"] if platform == :express
          return platform if signatures && (found & signatures).any?
        end

        :unknown
      end

      def platform_name(platform)
        {
          rails: "Ruby on Rails. На це вказують ActionController, Rails.root або vendor/bundle",
          laravel: "Laravel. На це вказують Whoops, Ignition або шлях vendor/laravel",
          symfony: "Symfony. На це вказує клас Symfony\\Component у сторінці помилки",
          yii: "Yii. На це вказує yii\\web\\NotFoundHttpException",
          codeigniter: "CodeIgniter. На це вказує CodeIgniter\\Exceptions",
          php: "PHP із увімкненим display_errors. Точний фреймворк за сторінкою не визначити",
          django: "Django. На це вказує DJANGO_SETTINGS_MODULE",
          flask: "Flask. На це вказує дебагер Werkzeug",
          python: "Python. На це вказує Traceback. Точний фреймворк за сторінкою не визначити",
          spring: "Spring Boot. На це вказує Whitelabel Error Page",
          dotnet: "ASP.NET. На це вказує Server Error in '/' Application",
          sinatra: "Sinatra. На це вказує сторінка Sinatra doesn't know this ditty",
          phoenix: "Phoenix. На це вказує Phoenix.Router.NoRouteError",
          express: "Express. На це вказує типова відповідь Cannot GET",
          tomcat: "Apache Tomcat. На це вказує Exception Report",
          unknown: "не визначено. Завдання нижче універсальне: вимкнути детальні помилки і лишити коротку сторінку 404"
        }.fetch(platform)
      end
    end
  end
end
