require "active_support/core_ext/integer/time"

Rails.application.configure do
  config.enable_reloading = false
  config.eager_load = true
  config.consider_all_requests_local = false
  config.action_controller.perform_caching = true
  config.cache_store = :memory_store
  config.action_dispatch.show_exceptions = :all
  config.active_support.deprecation = :notify
  config.log_level = :info
  config.public_file_server.enabled = true
  config.require_master_key = false
  config.force_ssl = false

  config.hosts.clear
  config.host_authorization = { exclude: ->(_request) { true } }

  if ENV["RAILS_LOG_TO_STDOUT"].present?
    logger = ActiveSupport::Logger.new($stdout)
    logger.formatter = config.log_formatter
    config.logger = ActiveSupport::TaggedLogging.new(logger)
  end
end
