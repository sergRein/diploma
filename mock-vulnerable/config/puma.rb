max_threads_count = ENV.fetch("RAILS_MAX_THREADS", 3)
min_threads_count = ENV.fetch("RAILS_MIN_THREADS", 1)
threads min_threads_count, max_threads_count

bind "tcp://0.0.0.0:#{ENV.fetch('PORT', 8222)}"
environment ENV.fetch("RAILS_ENV", "development")
pidfile ENV.fetch("PIDFILE", "tmp/pids/server.pid")
plugin :tmp_restart
