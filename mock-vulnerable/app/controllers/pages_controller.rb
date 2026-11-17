class PagesController < ApplicationController
  def home
    response.set_header("Set-Cookie", "dast_demo_session=vulnerable_token_123; Path=/")
  end

  def exposed_env
    render plain: File.read(Rails.root.join("public/.env"), encoding: "UTF-8"),
           content_type: "text/plain"
  end

  def adminer
    render :adminer, layout: false
  end

  def search
  end

  def submit
    render plain: "Прийнято"
  end
end
