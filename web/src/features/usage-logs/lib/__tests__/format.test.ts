/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/
import { describe, expect, test, vi } from 'vitest'

import en from '@/i18n/locales/en.json'
import fr from '@/i18n/locales/fr.json'
import ja from '@/i18n/locales/ja.json'
import ru from '@/i18n/locales/ru.json'
import viLocale from '@/i18n/locales/vi.json'
import zhTW from '@/i18n/locales/zh-TW.json'
import zh from '@/i18n/locales/zh.json'

import type { LogOtherData } from '../../types'
import { renderAuditContent } from '../format'

describe('renderAuditContent', () => {
  const auditCases: Array<{
    action: string
    params: NonNullable<NonNullable<LogOtherData['op']>['params']>
    template: string
  }> = [
    {
      action: 'user.access_policy_update',
      params: { target_user_id: 12 },
      template: 'Updated access policy for user {{target_user_id}}',
    },
    {
      action: 'user.device_status_update',
      params: { device_id: 34, target_user_id: 12 },
      template: 'Updated device {{device_id}} for user {{target_user_id}}',
    },
    {
      action: 'user.device_fingerprint_status_update',
      params: { short_id: 'abc123def456', target_user_id: 12 },
      template:
        'Updated device fingerprint {{short_id}} for user {{target_user_id}}',
    },
  ]

  test.each(auditCases)(
    'localizes the $action audit action with its structured parameters',
    ({ action, params, template }) => {
      const translate = vi.fn((key: string) => key)

      expect(renderAuditContent({ op: { action, params } }, translate)).toBe(
        template
      )
      expect(translate).toHaveBeenCalledWith(template, params)
    }
  )

  test('provides every access-control audit template in all supported locales', () => {
    const locales = [en, zh, zhTW, fr, ja, ru, viLocale]

    for (const locale of locales) {
      for (const auditCase of auditCases) {
        expect(locale.translation).toHaveProperty(auditCase.template)
      }
    }
  })
})
