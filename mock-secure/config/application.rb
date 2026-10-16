require_relative "boot"

require "rails"
require "active_model/railtie"
require "active_job/railtie"
require "action_controller/railtie"
require "action_view/railtie"

Bundler.require(*Rails.groups)

module MockSecure
  class Application < Rails::Application
    config.load_defaults 7.2
    config.secret_key_base = ENV.fetch("SECRET_KEY_BASE") { "secure-lab-#{'c' * 96}" }
    config.time_zone = "Europe/Kyiv"
    config.encoding = "utf-8"
    config.log_level = :info
  end
end
