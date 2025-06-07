import { Injectable } from '@angular/core';
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor
} from '@angular/common/http';
import { Observable } from 'rxjs';
import { AuthService } from '../services/auth.service';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  constructor(private authService: AuthService) {}

  intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    const token = this.authService.getAuthToken();
    
    // Quand c'est une requête de connexion, ne pas ajouter le token
    if (request.url.includes('/auth/login')) {
      return next.handle(request);
    }

    // Quand c'est une requête API, ajouter le token d'authentification
    if (token) {
      request = request.clone({
        setHeaders: {
          Authorization: `Bearer ${token}`
        }
      });
    }

    // On passe la requête au prochain gestionnaire
    return next.handle(request);
  }
}
