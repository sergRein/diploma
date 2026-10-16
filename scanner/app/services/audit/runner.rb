module Audit
  class Runner
    def initialize(raw_url)
      @raw_url = raw_url
    end

    def call
      Checkers::EnvLeakChecker.new(@raw_url).call
    end
  end
end
