class AuditsController < ApplicationController
  def new
    
  end

  def do_audit
    @url = audit_url
    if @url.blank?
      @error = "Вкажіть адресу сайту."
      render :new, status: :unprocessable_entity
      return
    end

    @results = Audit::Runner.new(@url).call
    render :new
  end

  private

  def audit_url
    source = params[:audit]
    return "" unless source.respond_to?(:permit)

    source.permit(:url)[:url].to_s.strip
  end
end
