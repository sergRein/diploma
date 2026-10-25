require "nokogiri"

module Audit
  module Checkers
    class FormProtectionChecker < BaseChecker
      CATEGORY = "A06:2025 – Insecure Design"

      BOT_SIGNATURES = [
        "challenges.cloudflare.com",
        "cf-turnstile",
        "google.com/recaptcha",
        "g-recaptcha",
        "hcaptcha.com",
        "h-captcha"
      ].freeze

      DATA_FIELDS = 'input[type="text"], input[type="email"], input[type="tel"], textarea'
      SEARCH_NAMES = %w[q s query search].freeze

      def perform
        response = fetch(origin.path.to_s.empty? ? "/" : origin.path)
        document = Nokogiri::HTML(response.body)
        forms = data_forms(document)
        return none(response) if forms.empty?
        return protected_forms(response, forms) if protected?(response.body)

        unprotected(response, forms)
      end

      def error_result(message)
        Result.new(
          category: CATEGORY,
          title: "Не вдалося перевірити форми",
          status: :error,
          business_risk: "Перевірку не вдалося закінчити, тому вважати, що форми закриті від ботів, не можна. Повторіть перевірку, коли сайт відповідає.",
          technical_lang: "Запит на головну сторінку не завершився. Причина: #{message} Висновку про захист форм немає.",
          remediation_agency: "Завдання для виправлення не сформоване: сканер не отримав відповідь сайту.",
          remediation_ai_prompt: ""
        )
      end

      private

      def data_forms(document)
        document.css("form").select { |form| collects_data?(form) }
      end

      def collects_data?(form)
        return false if form["role"].to_s.casecmp?("search")
        return false if form.at_css('input[type="search"]')

        fields = form.css(DATA_FIELDS)
        return false if fields.empty?

        personal = form.css('input[type="email"], input[type="tel"], textarea')
        return false if personal.empty? && fields.all? { |field| SEARCH_NAMES.include?(field["name"].to_s.downcase) }

        true
      end

      def protected?(body)
        text = body.to_s.downcase
        BOT_SIGNATURES.any? { |signature| text.include?(signature) }
      end

      def none(response)
        Result.new(
          category: CATEGORY,
          title: title,
          status: :passed,
          business_risk: "Інтерактивних форм збору даних не виявлено.",
          technical_lang: "GET #{origin} повернув HTTP #{response.status}. Форм із полями text, email, tel або textarea немає. Пошукові поля не рахуються. #{category_line}",
          remediation_agency: "Форм для заявок на головній немає. Окреме завдання не потрібне.",
          remediation_ai_prompt: ""
        )
      end

      def protected_forms(response, forms)
        Result.new(
          category: CATEGORY,
          title: title,
          status: :passed,
          business_risk: "Форми захищені механізмами верифікації від ботів.",
          technical_lang: "#{form_line(response, forms)} Є сигнатура антибот-захисту. #{category_line}",
          remediation_agency: "На формі вже є перевірка від ботів. Окреме завдання не потрібне.",
          remediation_ai_prompt: ""
        )
      end

      def unprotected(response, forms)
        Result.new(
          category: CATEGORY,
          title: title,
          status: :failed,
          business_risk: business_risk,
          technical_lang: "#{form_line(response, forms)} Сигнатур Cloudflare Turnstile, reCAPTCHA або hCaptcha немає. #{category_line}",
          remediation_agency: agency_text(forms),
          remediation_ai_prompt: prompt_text
        )
      end

      def title
        "Захист форм від спам-ботів та масових атак"
      end

      def business_risk
        "Форми замовлень або зворотного зв'язку не захищені від ботів. " \
        "Зловмисники можуть автоматично надсилати сотні підроблених заявок на хвилину, блокуючи роботу менеджерів, " \
        "засмічуючи базу даних та наражаючи корпоративну пошту на блокування спам-фільтрами."
      end

      def form_line(response, forms)
        actions = forms.map { |form| form["action"].to_s.empty? ? "(поточна адреса)" : form["action"] }.uniq.join(", ")
        "GET #{origin} повернув HTTP #{response.status}. Форм збору даних: #{forms.size}. Адреси відправки: #{actions}."
      end

      def category_line
        "Категорія OWASP Top 10: #{CATEGORY}."
      end

      def agency_text(forms)
        actions = forms.map { |form| form["action"].to_s }.reject(&:empty?).uniq
        where = actions.any? ? actions.join(", ") : "усі форми збору даних на головній"
        <<~TEXT.strip
          Завдання: встановити сучасний невидимий захист від ботів (Cloudflare Turnstile або Google reCAPTCHA v3) на всі форми реєстрації, оформлення замовлення та зворотного зв'язку.

          Зараз без захисту: #{where}.
          Поставте віджет у кожну таку форму і перевіряйте токен на сервері, перш ніж зберігати заявку. Пошук по сайту чіпати не потрібно.
          Готово, коли в HTML форми є cf-turnstile, g-recaptcha або h-captcha, а сервер відхиляє відправку без дійсного токена.
        TEXT
      end

      def prompt_text
        <<~TEXT.strip
          На головній сторінці є форма збору даних без захисту від ботів.
          Напиши фрагмент інтеграції Cloudflare Turnstile у контактну форму на HTML або Ruby on Rails: контейнер на сторінці і перевірку токена на сервері.
          Не пропонуй вимикати перевірку. Поясни простою мовою, що змінилось.
        TEXT
      end
    end
  end
end
