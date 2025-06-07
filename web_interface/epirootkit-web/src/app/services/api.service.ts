import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, of } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { environment } from '@environments/environment';

@Injectable({
  providedIn: 'root'
})
export class ApiService {
  private apiUrl = 'http://localhost:4444';
  private disableApiCalls = environment.disableApiCalls;

  constructor(private http: HttpClient) {}

  private handleError<T>(operation = 'operation', result?: T) {
    return (error: any): Observable<T> => {
      console.error(`${operation} failed: ${error.message}`);
      return of(result as T);
    };
  }

  getLogs(): Observable<any> {
    if (this.disableApiCalls) {
      return of([]);
    }
    return this.http.get(`${this.apiUrl}/logs`)
      .pipe(catchError(this.handleError('getLogs', [])));
  }

  getStats(): Observable<any> {
    if (this.disableApiCalls) {
      return of({ total: 0, errors: 0, warnings: 0 });
    }
    return this.http.get(`${this.apiUrl}/logs/stats`)
      .pipe(catchError(this.handleError('getStats', {})));
  }

  getFiles(): Observable<any> {
    if (this.disableApiCalls) {
      return of([]);
    }
    return this.http.get(`${this.apiUrl}/files`)
      .pipe(catchError(this.handleError('getFiles', [])));
  }

  getRedirects(): Observable<any> {
    if (this.disableApiCalls) {
      return of([]);
    }
    return this.http.get(`${this.apiUrl}/redirect/list`)
      .pipe(catchError(this.handleError('getRedirects', [])));
  }
} 