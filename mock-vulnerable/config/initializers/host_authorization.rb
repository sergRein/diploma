Rails.application.config.hosts.clear
Rails.application.config.host_authorization = { exclude: ->(_request) { true } }
