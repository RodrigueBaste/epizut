import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, of } from 'rxjs';
import { map, catchError } from 'rxjs/operators';
import { Router } from '@angular/router';

interface User {
  username: string;
  token: string;
}

interface AuthState {
  isAuthenticated: boolean;
  user: User | null;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private static readonly STORAGE_KEYS = {
    AUTH_TOKEN: 'auth_token',
    CURRENT_USER: 'currentUser'
  };

  // Endpoints de l'API pour l'authentification
  private static readonly API_ENDPOINTS = {
    LOGIN: '/auth/login'
  };

  // URL de base de l'API, à adapter selon notre configuration
  private readonly apiBaseUrl = 'http://localhost:3000/api';
  private readonly authStateSubject = new BehaviorSubject<AuthState>({
    isAuthenticated: false,
    user: null
  });

  constructor(
    private readonly http: HttpClient,
    private readonly router: Router
  ) {
    this.initializeAuthState();
  }

  // On expose les observables pour que les composants puissent s'abonner
  public get currentUser(): Observable<User | null> {
    return this.authStateSubject.pipe(
      map(state => state.user)
    );
  }

  // On expose un observable pour savoir si l'utilisateur est authentifié
  public get isAuthenticated(): Observable<boolean> {
    return this.authStateSubject.pipe(
      map(state => state.isAuthenticated)
    );
  }

  // On initialise l'état d'authentification en vérifiant le localStorage
  private initializeAuthState(): void {
    if (this.isLocalStorageAvailable()) {
      const storedUser = this.getStoredUser();
      const storedToken = localStorage.getItem(AuthService.STORAGE_KEYS.AUTH_TOKEN);
      
      this.authStateSubject.next({
        isAuthenticated: !!storedToken && !!storedUser,
        user: storedUser
      });
    }
  }

  // Vérifie si le localStorage est disponible dans l'environnement actuel
  private isLocalStorageAvailable(): boolean {
    return typeof window !== 'undefined' && !!window.localStorage;
  }

  // On récupère l'utilisateur stocké dans le localStorage
  private getStoredUser(): User | null {
    try {
      const storedUser = localStorage.getItem(AuthService.STORAGE_KEYS.CURRENT_USER);
      return storedUser ? JSON.parse(storedUser) : null;
    } catch {
      return null;
    }
  }

  login(username: string, password: string): Observable<boolean> {
    // Utilise la vraie authentification côté serveur
    return this.realLogin(username, password);
  }

  private realLogin(username: string, password: string): Observable<boolean> {
    return this.http.post<User>(`${this.apiBaseUrl}${AuthService.API_ENDPOINTS.LOGIN}`, { username, password })
      .pipe(
        map(user => {
          this.updateAuthState(user);
          return true;
        }),
        catchError(error => {
          console.error('Erreur de connexion:', error);
          throw error;
        })
      );
  }

  private updateAuthState(user: User): void {
    if (this.isLocalStorageAvailable()) {
      localStorage.setItem(AuthService.STORAGE_KEYS.CURRENT_USER, JSON.stringify(user));
      localStorage.setItem(AuthService.STORAGE_KEYS.AUTH_TOKEN, user.token);
    }

    this.authStateSubject.next({
      isAuthenticated: true,
      user
    });
  }

  logout(): void {
    if (this.isLocalStorageAvailable()) {
      localStorage.removeItem(AuthService.STORAGE_KEYS.CURRENT_USER);
      localStorage.removeItem(AuthService.STORAGE_KEYS.AUTH_TOKEN);
    }

    this.authStateSubject.next({
      isAuthenticated: false,
      user: null
    });

    this.router.navigate(['/login']);
  }

  getAuthToken(): string | null {
    return this.isLocalStorageAvailable() 
      ? localStorage.getItem(AuthService.STORAGE_KEYS.AUTH_TOKEN)
      : null;
  }
}