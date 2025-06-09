FROM nginx:alpine

# Copier la configuration nginx personnalisée
COPY docker/web/nginx.conf /etc/nginx/conf.d/default.conf

# Copier les fichiers de build Angular
COPY web_interface/epirootkit-web/dist/epirootkit-web/ /usr/share/nginx/html/

# Exposer le port 80
EXPOSE 80

# Démarrer nginx
CMD ["nginx", "-g", "daemon off;"]
