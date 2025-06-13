import { Component, OnInit } from '@angular/core';
import { CommonModule, DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { LogService, LogEntry } from '../../services/log.service';

@Component({
  selector: 'app-logs',
  standalone: true,
  imports: [CommonModule, FormsModule, DatePipe],
  templateUrl: './logs.component.html',
  styleUrls: ['./logs.component.scss']
})
export class LogsComponent implements OnInit {
  logs: LogEntry[] = [];
  stats: any = null;
  filter: string = '';

  constructor(private logService: LogService) { }

  ngOnInit(): void {
    this.loadLogs();
    this.loadStats();
    setInterval(() => {
      this.loadLogs();
      this.loadStats();
    }, 5000);
  }

  loadLogs(): void {
    this.logService.getLogs().subscribe({
      next: (logs) => {
        this.logs = logs;
      },
      error: (err) => {
        console.error('Erreur lors du chargement des logs:', err);
      }
    });
  }

  loadStats(): void {
    this.logService.getLogStats().subscribe({
      next: (stats) => {
        this.stats = stats;
      },
      error: (err) => {
        console.error('Erreur lors du chargement des statistiques:', err);
      }
    });
  }

  clearLogs(): void {
    this.logService.clearLogs().subscribe({
      next: () => {
        this.loadLogs();
        this.loadStats();
      },
      error: (err) => {
        console.error('Erreur lors de la suppression des logs:', err);
      }
    });
  }

  getFilteredLogs(): LogEntry[] {
    if (!this.filter) return this.logs;
    const filterLower = this.filter.toLowerCase();
    return this.logs.filter(log => 
      log.message.toLowerCase().includes(filterLower) ||
      log.source.toLowerCase().includes(filterLower) ||
      log.level.toLowerCase().includes(filterLower)
    );
  }
} 