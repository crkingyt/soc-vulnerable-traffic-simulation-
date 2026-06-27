FROM nginx:alpine

# Copy Nginx config
COPY nginx.conf /etc/nginx/nginx.conf

# Copy custom index page
RUN echo '<html><body><h1>IIS-Nginx SOC Target Server</h1></body></html>' > /usr/share/nginx/html/index.html

EXPOSE 80
