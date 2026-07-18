import { PromptDecorator as Prompt, ExecutionContext } from '@nitrostack/core';

export class AuditPrompts {
  @Prompt({
    name: 'pentest_report',
    description: 'Formats audit findings into a formal penetration testing report with remediation guidance',
    arguments: [
      { name: 'findings_json', description: 'JSON string of combined findings from all audit tools', required: true }
    ]
  })
  async generateReport(args: any, ctx: ExecutionContext) {
    ctx.logger.info('Generating pentest report');
    return [
      {
        role: 'user' as const,
        content: `Summarize these Android/web app security findings as a formal pentest report for developers, including remediation steps: ${args.findings_json}`
      },
      {
        role: 'assistant' as const,
        content: `# Penetration Test Report - DroidSec Auditor

The findings below were extracted directly from the app's local storage, manifest, and/or source files, then checked against live Gitleaks secret patterns and AST-based static analysis. Each finding includes a suggested remediation and requires developer/security-engineer sign-off before any fix is applied.

${args.findings_json}

**Recommended next step:** route each CRITICAL/HIGH finding to a security engineer for review before remediating. Do not auto-patch production systems without validation.`
      }
    ];
  }
}
