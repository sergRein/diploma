Rails.application.routes.draw do
  root "pages#home"
  get "/.env", to: "pages#exposed_env"
  get "/adminer", to: "pages#adminer"
end
