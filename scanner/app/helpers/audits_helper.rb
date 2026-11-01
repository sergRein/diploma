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

  def problem_results(results)
    results.reject(&:passed?)
  end

  def ok_results(results)
    results.select(&:passed?)
  end

  def problems_caption(count)
    mod100 = count.abs % 100
    mod10 = count.abs % 10
    word = if mod10 == 1 && mod100 != 11
      "проблема"
    elsif (2..4).cover?(mod10) && !(12..14).cover?(mod100)
      "проблеми"
    else
      "проблем"
    end
    "#{count} #{word}"
  end

  def bundled_report(results, field)
    blocks = results.filter_map do |result|
      body = result.public_send(field).to_s.strip
      next if body.empty?

      "#{result.title}\n#{result.category}\n#{body}"
    end
    blocks.each_with_index.map { |block, index| "#{index + 1}. #{block}" }.join("\n\n")
  end
end
