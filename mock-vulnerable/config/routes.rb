Rails.application.routes.draw do
  root "pages#home"
  get "/.env", to: "pages#exposed_env"
end
