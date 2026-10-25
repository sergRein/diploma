class PagesController < ApplicationController
  def home
  end

  def submit
    render plain: "Прийнято"
  end
end
