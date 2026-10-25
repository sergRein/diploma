module Audit
  module Checkers
    # Типові адреси панелей. Відкритою вважається лише сторінка 200 з ознакою входу, не будь-яка 200.
    class AdminPanelsChecker < BaseChecker
      # kind керує підстановкою в ТЗ і промпт: база, адмінка CMS, публічний вхід, черга, сервер.
      PANELS = [
        { path: "/admin", name: "типова адреса адмінки", kind: :generic },
        { path: "/wp-login.php", name: "WordPress", kind: :cms_login },
        { path: "/wp-admin", name: "WordPress", kind: :cms_admin },
        { path: "/administrator", name: "Joomla", kind: :cms_admin },
        { path: "/user/login", name: "Drupal", kind: :cms_login },
        { path: "/bitrix/admin", name: "1C-Bitrix", kind: :cms_admin },
        { path: "/typo3", name: "TYPO3", kind: :cms_admin },
        { path: "/adminer", name: "Adminer", kind: :database },
        { path: "/adminer.php", name: "Adminer", kind: :database },
        { path: "/phpmyadmin", name: "phpMyAdmin", kind: :database },
        { path: "/phpMyAdmin", name: "phpMyAdmin", kind: :database },
        { path: "/pma", name: "phpMyAdmin", kind: :database },
        { path: "/manager/html", name: "Apache Tomcat", kind: :server },
        { path: "/webmail", name: "веб-пошта", kind: :mail },
        { path: "/horizon", name: "Laravel Horizon", kind: :queue },
        { path: "/sidekiq", name: "Sidekiq", kind: :queue }
      ].freeze

      TARGET_PATHS = PANELS.map { |panel| panel[:path] }.freeze
      CLOSED_STATUSES = [401, 403, 404].freeze
      MARKERS = [
        "adminer", "phpmyadmin", "admin login", "password",
        "wordpress", "joomla", "drupal", "bitrix", "typo3",
        "tomcat", "horizon", "sidekiq", "roundcube"
      ].freeze

      def perform
        rows = TARGET_PATHS.map { |path| probe(path) }
        hits = rows.select { |row| row[:open] }
        return exposed(hits, rows) if hits.any?

        clean(rows)
      end

      def error_result(message)
        Result.new(
          title: "Не вдалося перевірити службові панелі",
          status: :error,
          business_risk: "Перевірку не вдалося закінчити, тому вважати, що панелі керування закриті від інтернету, не можна. Повторіть перевірку, коли сайт відповідає.",
          technical_lang: "Запити до типових адрес панелей не завершились. Причина: #{message} Висновку про відкритий вхід немає.",
          remediation_agency: "Завдання для виправлення не сформоване: сканер не отримав відповідь сайту.",
          remediation_ai_prompt: ""
        )
      end

      private

      def probe(path)
        response = fetch(path)
        markers = markers_in(response.body)
        open = response.status == 200 && markers.any?

        { path: path, status: response.status, markers: markers, open: open, response: response, panel: panel_for(path) }
      end

      def panel_for(path)
        PANELS.find { |panel| panel[:path] == path }
      end

      def markers_in(body)
        text = body.to_s.downcase
        MARKERS.select { |marker| text.include?(marker) }
      end

      def exposed(hits, rows)
        serious = hits.reject { |row| row[:panel][:kind] == :generic }
        Result.new(
          title: title,
          status: serious.any? ? :failed : :warning,
          business_risk: business_risk,
          technical_lang: technical_for(rows, hits),
          remediation_agency: agency_for(hits),
          remediation_ai_prompt: prompt_for(hits)
        )
      end

      def clean(rows)
        Result.new(
          title: title,
          status: :passed,
          business_risk: "Ці типові адреси панелей з інтернету не відкриваються. Відвідувач не бачить форми входу до керування сайтом чи базою.",
          technical_lang: technical_for(rows, []),
          remediation_agency: "Жодна з перевірених адрес не віддала сторінку входу. Окреме завдання не потрібне.",
          remediation_ai_prompt: ""
        )
      end

      def title
        "Публічний доступ до панелей адміністрування"
      end

      def business_risk
        "Службові інтерфейси керування сайтом або базою даних виставлені у відкритий доступ для всього інтернету. " \
          "Будь-який зловмисник може запустити масовий підбір паролів або використати відомі вразливості панелі для захоплення управління сервером."
      end

      def technical_for(rows, hits)
        lines = rows.map do |row|
          detail = if row[:open]
            "сторінка входу. Ознаки: #{row[:markers].join(', ')}."
          elsif CLOSED_STATUSES.include?(row[:status])
            "закрито."
          else
            "ознак форми входу немає."
          end
          "#{row[:path]} (#{row[:panel][:name]}) → HTTP #{row[:status]}, #{detail}"
        end

        verdict = if hits.empty?
          "Відкритих форм входу немає."
        elsif hits.all? { |row| row[:panel][:kind] == :generic }
          "Жовтий статус: відкрито лише типову адресу /admin. За нею систему не визначити."
        else
          "Червоний статус: відкрито #{system_list(hits)}."
        end

        <<~TEXT.strip
          Перевірені адреси:
          #{lines.join("\n")}
          #{verdict}
          Для фахівця відкрита панель бази чи CMS — це OWASP Top 10 A05:2021 Security Misconfiguration: інтерфейс адміністрування доступний з інтернету без окремого шару доступу.
          Сам вміст сторінки у звіт не копіюється.
        TEXT
      end

      def agency_for(hits)
        groups = groups_for(hits)
        <<~TEXT.strip
          Завдання: обмежити доступ до службових маршрутів (#{hits.map { |row| row[:path] }.join(', ')}) на рівні веб-сервера. Дозвольте вхід лише з корпоративних IP-адрес, закрийте їх базовою HTTP-автентифікацією або переведіть доступ у закриту VPN-мережу.

          Знайдено: #{groups.map { |group| "#{group[:name]} (#{group[:paths].join(', ')})" }.join('; ')}.

          #{groups.map { |group| agency_steps(group) }.join("\n\n")}

          Фрагмент nginx лише для знайдених адрес. 203.0.113.10 замініть на адресу офісу:
          location ~ ^/(#{nginx_pattern(hits)}) {
            allow 203.0.113.10;
            deny all;
          }
          Готово, коли ці адреси відповідають 401, 403 або 404 і не показують форму пароля. Публічний вхід для клієнтів (якщо він серед знайдених) не закривайте deny all для всіх.
        TEXT
      end

      def agency_steps(group)
        paths = group[:paths].join(", ")
        case group[:kind]
        when :database
          "#{group[:name]} (#{paths}): це панель бази. Приберіть її з сервера, якщо нею не користуються. Якщо ще потрібна, лишіть лише з офісної IP-адреси або за VPN, не на публічному сайті."
        when :cms_admin
          "#{group[:name]} (#{paths}): це вхід працівників, не клієнтів. Закрийте адресу allow/deny в nginx або базовою автентифікацією перед формою входу."
        when :cms_login
          "#{group[:name]} (#{paths}): це може бути звичайний вхід користувачів, не лише адмінка. Не ставте deny all на всіх відвідувачів. Обмежте частоту спроб пароля. Якщо сюди входять лише працівники, тоді вже закрийте адресу за IP."
        when :mail
          "#{group[:name]} (#{paths}): це пошта для людей, не панель бази. Не вимикайте її для всіх. Винесіть на окрему адресу і обмежте число спроб входу."
        when :queue
          "#{group[:name]} (#{paths}): черга і фонові задачі не мають відкриватися з інтернету. Закрийте маршрут в додатку і продублюйте заборону в nginx."
        when :server
          "#{group[:name]} (#{paths}): керування сервером застосунків. Вимкніть Manager з публічного сайту або пустіть лише з офісної мережі."
        else
          "#{group[:name]} (#{paths}): за самою адресою /admin систему не видно. Закрийте її так само, як решту службових маршрутів, після того як розробник підтвердить, що це не вхід для клієнтів."
        end
      end

      def prompt_for(hits)
        groups = groups_for(hits)
        <<~TEXT.strip
          На сайті з інтернету відкриваються службові сторінки: #{groups.map { |group| "#{group[:name]} — #{group[:paths].join(', ')}" }.join('; ')}.
          #{groups.map { |group| prompt_steps(group) }.join("\n")}
          Не пропонуй підбір паролів. Поясни простою мовою, що змінилось.
        TEXT
      end

      def prompt_steps(group)
        list = group[:paths].join(", ")
        nginx = "Напиши фрагмент конфігурації nginx, який закриває доступ до #{list}: список дозволених IP через allow/deny або базова HTTP-автентифікація."

        case group[:kind]
        when :database
          "Знайдено #{group[:name]} (#{list}). Це панель бази даних: її треба прибрати з публічного сайту або лишити тільки з офісної мережі. #{nginx}"
        when :cms_admin
          "Знайдено адмінку #{group[:name]} (#{list}). Це вхід для працівників. #{nginx} Якщо це #{group[:name]}, не чіпай публічні сторінки магазину, лише цю адресу."
        when :cms_login
          "Знайдено форму входу #{group[:name]} (#{list}). Якщо сюди входять клієнти або автори, не закривай адресу для всіх: додай обмеження числа спроб. Якщо це лише працівники, тоді #{nginx}"
        when :mail
          "Знайдено веб-пошту (#{list}). Не став deny all на всіх людей, яким потрібна пошта. Обмеж число спроб входу і, якщо панель службова, #{nginx}"
        when :queue
          "Знайдено #{group[:name]} (#{list}). Черга не має бути публічною. Закрий маршрут у застосунку (Rails для Sidekiq, Laravel для Horizon) і #{nginx}"
        when :server
          "Знайдено #{group[:name]} (#{list}). Manager не має висіти на публічному сайті. Вимкни його або #{nginx}"
        else
          "Знайдено лише #{list}. Система за цією адресою не визначається. #{nginx} Уточни в розробника, чи це не вхід для клієнтів, перш ніж закривати всіх."
        end
      end

      def groups_for(hits)
        hits.group_by { |row| row[:panel][:name] }.map do |name, grouped|
          {
            name: name,
            kind: grouped.first[:panel][:kind],
            paths: grouped.map { |row| row[:path] }
          }
        end
      end

      def system_list(hits)
        groups_for(hits).map { |group| "#{group[:name]} (#{group[:paths].join(', ')})" }.join(", ")
      end

      def nginx_pattern(hits)
        hits.map { |row| row[:path].delete_prefix("/").gsub(".", "\\.") }.join("|")
      end
    end
  end
end
