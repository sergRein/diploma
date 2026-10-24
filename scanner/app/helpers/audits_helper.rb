module AuditsHelper
  STATUS_LABELS = {
    "passed" => "Зелений",
    "failed" => "Червоний",
    "warning" => "Жовтий",
    "error" => "Немає відповіді"
  }.freeze

  def status_label(status)
    STATUS_LABELS.fetch(status.to_s, status.to_s)
  end

  def status_color(status)
    return "green" if status.to_s == "passed"
    return "red" if status.to_s == "failed"
    return "yellow" if status.to_s == "warning"

    "yellow"
  end
end
