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
import { z } from 'zod'

import {
  type UserAccessPolicy,
  type UserAccessPolicyUpdate,
  userDevicePolicyModeSchema,
  userIPPolicyModeSchema,
} from '../types'

const accessPolicyIPEntrySchema = z
  .union([z.ipv4(), z.ipv6(), z.cidrv4(), z.cidrv6()])
  .refine((value) => !value.endsWith('/0'))

export const userAccessPolicyFormSchema = z
  .object({
    ip_mode: userIPPolicyModeSchema,
    ip_allowlist_text: z.string(),
    device_mode: userDevicePolicyModeSchema,
  })
  .superRefine((value, context) => {
    const entries = splitAccessPolicyAllowlist(value.ip_allowlist_text)
    if (value.ip_mode === 'allowlist' && entries.length === 0) {
      context.addIssue({
        code: 'custom',
        path: ['ip_allowlist_text'],
        message: 'Add at least one IP address or CIDR',
      })
    }
    if (entries.length > 64) {
      context.addIssue({
        code: 'custom',
        path: ['ip_allowlist_text'],
        message: 'Enter no more than 64 IP addresses or CIDRs',
      })
    }
    if (
      entries.some(
        (entry) => !accessPolicyIPEntrySchema.safeParse(entry).success
      )
    ) {
      context.addIssue({
        code: 'custom',
        path: ['ip_allowlist_text'],
        message: 'Enter a valid IPv4, IPv6, or CIDR on each line',
      })
    }
  })

export type UserAccessPolicyFormValues = z.infer<
  typeof userAccessPolicyFormSchema
>

export type UserAccessPolicyDirtyFields = Partial<
  Record<keyof UserAccessPolicyFormValues, boolean>
>

export function splitAccessPolicyAllowlist(value: string): string[] {
  return [
    ...new Set(
      value
        .split(/\r?\n/)
        .map((entry) => entry.trim())
        .filter(Boolean)
    ),
  ]
}

export function accessPolicyToFormValues(
  policy: UserAccessPolicy
): UserAccessPolicyFormValues {
  return {
    ip_mode: policy.ip_mode,
    ip_allowlist_text: policy.ip_allowlist.join('\n'),
    device_mode: policy.device_mode,
  }
}

export function accessPolicyFormToUpdate(
  values: UserAccessPolicyFormValues,
  dirtyFields: UserAccessPolicyDirtyFields
): UserAccessPolicyUpdate {
  const update: UserAccessPolicyUpdate = {}
  if (dirtyFields.ip_mode) {
    update.ip_mode = values.ip_mode
  }
  if (dirtyFields.ip_allowlist_text) {
    update.ip_allowlist = splitAccessPolicyAllowlist(values.ip_allowlist_text)
  }
  if (dirtyFields.device_mode) {
    update.device_mode = values.device_mode
  }
  return update
}
