Rails.application.routes.draw do
  root "pages#home"
  get "/search", to: "pages#search"
  post "/submit", to: "pages#submit"
end
