import * as vscode from 'vscode';
import { Range as CoreRange, Position as CorePosition, Severity } from '../core';

export const toPosition = (p: CorePosition) => new vscode.Position(p.line, p.character);
export const toRange = (r: CoreRange) => new vscode.Range(toPosition(r.start), toPosition(r.end));

export function toSeverity(s: Exclude<Severity, 'off'>): vscode.DiagnosticSeverity {
  switch (s) {
    case 'error':
      return vscode.DiagnosticSeverity.Error;
    case 'warning':
      return vscode.DiagnosticSeverity.Warning;
    case 'info':
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

export const isYaral = (d: vscode.TextDocument) => d.languageId === 'yaral';
