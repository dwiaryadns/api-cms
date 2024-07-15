# Use the specified PHP-FPM image with Alpine Linux
FROM php:8.2.0-fpm-alpine

# Install npm
RUN apk add --update npm

# Install PostgreSQL development libraries
RUN set -ex \
    && apk --no-cache add postgresql-dev

# Install necessary libraries for PHP extensions
RUN apk add --no-cache \
    zlib-dev \
    libpng-dev \
    libzip-dev

# Configure and install PHP extensions
RUN docker-php-ext-configure zip
RUN docker-php-ext-install \
    gd \
    zip \
    pdo \
    pdo_pgsql

# Install Composer globally
RUN curl -sS https://getcomposer.org/installer | php -- \
    --install-dir=/usr/local/bin --filename=composer

# Set working directory
WORKDIR /var/www/

# Copy application files
COPY . .

# Install PHP dependencies using Composer
RUN composer install

# Install Node.js dependencies
RUN npm install

# Optimize the Laravel application
RUN php artisan optimize
RUN php artisan config:clear
RUN php artisan route:clear
RUN php artisan storage:link

# Expose port 9000 for PHP-FPM
EXPOSE 9000

# Set the volume for persistent storage
VOLUME /var/www/storage/app/public

# Run PHP-FPM
CMD ["php-fpm"]
