Rails.application.routes.draw do
  root "pages#home"
  post "/submit", to: "pages#submit"
end
