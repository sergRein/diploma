Rails.application.config.filter_parameters += [
  :password, :passw, :secret, :token, :_key, :otp, :app_key, :db_password
]
