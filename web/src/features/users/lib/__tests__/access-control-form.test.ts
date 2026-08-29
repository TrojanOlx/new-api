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
import { describe, expect, test } from 'vitest'

import {
  accessPolicyFormToUpdate,
  splitAccessPolicyAllowlist,
  userAccessPolicyFormSchema,
} from '../access-control-form'

const formValues = {
  ip_mode: 'allowlist' as const,
  ip_allowlist_text: ' 203.0.113.10 \n\n 2001:db8::/32 ',
  device_mode: 'observe' as const,
}

describe('administrator access-control form', () => {
  test('builds a PATCH payload from dirty fields only', () => {
    expect(
      accessPolicyFormToUpdate(formValues, {
        ip_mode: true,
        ip_allowlist_text: true,
      })
    ).toEqual({
      ip_mode: 'allowlist',
      ip_allowlist: ['203.0.113.10', '2001:db8::/32'],
    })
  })

  test('rejects an empty allowlist and more than 64 normalized entries', () => {
    expect(
      userAccessPolicyFormSchema.safeParse({
        ...formValues,
        ip_allowlist_text: '\n  ',
      }).success
    ).toBe(false)

    expect(
      userAccessPolicyFormSchema.safeParse({
        ...formValues,
        ip_allowlist_text: Array.from(
          { length: 65 },
          (_, index) => `192.0.2.${index}`
        ).join('\n'),
      }).success
    ).toBe(false)
  })

  test('rejects invalid entries and counts duplicate entries once', () => {
    const invalidResult = userAccessPolicyFormSchema.safeParse({
      ...formValues,
      ip_allowlist_text: 'not-an-ip',
    })
    const duplicateInput = Array.from(
      { length: 65 },
      () => '203.0.113.10'
    ).join('\n')

    expect(invalidResult.success).toBe(false)
    expect(invalidResult.error?.issues[0]?.message).toBe(
      'Enter a valid IPv4, IPv6, or CIDR on each line'
    )
    expect(
      userAccessPolicyFormSchema.safeParse({
        ...formValues,
        ip_allowlist_text: duplicateInput,
      }).success
    ).toBe(true)
    expect(splitAccessPolicyAllowlist(duplicateInput)).toEqual(['203.0.113.10'])
  })

  test.each(['0.0.0.0/0', '::/0'])('rejects default-route CIDR %s', (cidr) => {
    expect(
      userAccessPolicyFormSchema.safeParse({
        ...formValues,
        ip_allowlist_text: cidr,
      }).success
    ).toBe(false)
  })
})
