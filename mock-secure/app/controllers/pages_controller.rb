class PagesController < ApplicationController
  def home
    response.set_header("Set-Cookie", "dast_demo_session=secure_token_456; Path=/; HttpOnly; SameSite=Lax; Secure")
  end

  def search
  end

  def submit
    render plain: "Прийнято"
  end
end
