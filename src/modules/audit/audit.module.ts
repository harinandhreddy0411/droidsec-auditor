import { Module } from '@nitrostack/core';
import { AuditTools } from './audit.tools.js';
import { AuditResources } from './audit.resources.js';
import { AuditPrompts } from './audit.prompts.js';

@Module({
  name: 'audit',
  description: 'Android and web security auditing tools',
  controllers: [AuditTools, AuditResources, AuditPrompts]
})
export class AuditModule {}