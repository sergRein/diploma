Rails.application.routes.draw do
  root "audits#new"
  post "/audits", to: "audits#do_audit"
end
