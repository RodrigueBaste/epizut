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

  private static readonly API_ENDPOINTS = {
    LOGIN: '/auth/login'
  };

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

  public get currentUser(): Observable<User | null> {
    return this.authStateSubject.pipe(
      map(state => state.user)
    );
  }

  public get isAuthenticated(): Observable<boolean> {
    return this.authStateSubject.pipe(
      map(state => state.isAuthenticated)
    );
  }

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

  private isLocalStorageAvailable(): boolean {
    return typeof window !== 'undefined' && !!window.localStorage;
  }

  private getStoredUser(): User | null {
    try {
      const storedUser = localStorage.getItem(AuthService.STORAGE_KEYS.CURRENT_USER);
      return storedUser ? JSON.parse(storedUser) : null;
    } catch {
      return null;
    }
  }

  login(username: string, password: string): Observable<boolean> {
    // TODO: Remplacer par la vraie authentification quand le serveur sera prêt
    return this.mockLogin(username);
  }

  private mockLogin(username: string): Observable<boolean> {
    const mockUser: User = {
      username,
      token: 'mock-jwt-token'
    };

    this.updateAuthState(mockUser);
    return of(true);
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