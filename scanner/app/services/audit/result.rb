module Audit
  class Result
    attr_reader :title, :category, :status, :business_risk, :technical_lang,
                :remediation_agency, :remediation_ai_prompt

    def initialize(title:, category:, status:, business_risk:, technical_lang:, remediation_agency:, remediation_ai_prompt:)
      @title = title
      @category = category
      @status = status
      @business_risk = business_risk
      @technical_lang = technical_lang
      @remediation_agency = remediation_agency
      @remediation_ai_prompt = remediation_ai_prompt
    end

    def passed?
      status == :passed
    end

    def failed?
      status == :failed
    end

    def error?
      status == :error
    end

    def warning?
      status == :warning
    end
  end
end
