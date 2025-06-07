import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface LogEntry {
  timestamp: string;
  level: 'INFO' | 'WARNING' | 'ERROR';
  message: string;
  source: string;
}

@Injectable({
  providedIn: 'root'
})
export class LogService {
  private apiUrl = 'http://localhost:4444';

  constructor(private http: HttpClient) { }

  getLogs(): Observable<LogEntry[]> {
    return this.http.get<LogEntry[]>(`${this.apiUrl}/logs`);
  }

  clearLogs(): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/logs`);
  }

  getLogStats(): Observable<any> {
    return this.http.get<any>(`${this.apiUrl}/logs/stats`);
  }
} 