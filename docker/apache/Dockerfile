FROM ubuntu:22.04

# Avoid prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install apache2 and clean cache
RUN apt-get update && apt-get install -y \
    apache2 \
    && rm -rf /var/lib/apt/lists/*

# Copy configuration
COPY apache2.conf /etc/apache2/apache2.conf

# Copy simple index.html
RUN echo '<html><body><h1>Apache SOC Target Server</h1></body></html>' > /var/www/html/index.html

# Set up log and run dirs
RUN mkdir -p /var/log/apache2 /var/run/apache2 && \
    chown -R www-data:www-data /var/log/apache2 /var/run/apache2 /var/www/html

EXPOSE 80

CMD ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]
