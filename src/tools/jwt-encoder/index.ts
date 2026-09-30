import { Signature } from '@vicons/tabler';
import { defineTool } from '../tool';
import { translate } from '@/plugins/i18n.plugin';

export const tool = defineTool({
  name: translate('tools.jwt-encoder.title'),
  path: '/jwt-encoder',
  description: translate('tools.jwt-encoder.description'),
  keywords: ['jwt', 'encoder', 'encode', 'generator', 'sign', 'signature', 'hs256', 'rs256', 'es256', 'json', 'web', 'token'],
  component: () => import('./jwt-encoder.vue'),
  icon: Signature,
  createdAt: new Date('2026-09-30'),
});
