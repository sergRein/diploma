FROM ruby:3.3-slim

ENV BUNDLE_PATH=/usr/local/bundle \
    BUNDLE_WITHOUT="" \
    RAILS_LOG_TO_STDOUT=true \
    RAILS_ENV=development \
    LANG=C.UTF-8 \
    PORT=8223

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends build-essential libyaml-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Gemfile ./
RUN bundle install

COPY . .
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh && mkdir -p tmp/pids tmp/cache tmp/sockets log

EXPOSE 8223
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
