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

import { getUserModels } from '@/features/users/api'
import {
  userDeviceDetailSchema,
  userDeviceSchema,
  userDeviceSummarySchema,
  userDeviceUpdateSchema,
} from '@/features/users/types'
import { api } from '@/lib/api'

import { userAccessPolicyQueryKeys } from '../access-control-query-keys'

const deviceFields = {
  id: 101,
  user_id: 12,
  status: 'pending' as const,
  client_family: 'Codex',
  os_family: 'Windows',
  architecture: 'x64',
  originator: 'codex',
  confidence: 'high' as const,
  first_seen_at: 1_700_000_000,
  last_seen_at: 1_700_000_100,
  first_ip: '203.0.113.10',
  last_ip: '203.0.113.10',
  observed_ip_count: 1,
  request_count: 4,
  denied_count: 0,
  last_client_version: '1.2.3',
  remark: '',
  created_at: 1_700_000_000,
  updated_at: 1_700_000_100,
}

const device = {
  ...deviceFields,
  rate_limit_rpm: 240,
  blocked_models: ['gpt-5.6-sol', 'image-model'],
}

const summary = {
  ...deviceFields,
  rate_limit_rpm: 240,
  blocked_model_count: 2,
  fingerprint_count: 1,
  recent_ip_count: 1,
}

describe('administrator device control DTOs', () => {
  test('parses rate limiting and the full blocked-model list on a device detail', () => {
    expect(userDeviceSchema.safeParse(device).success).toBe(true)
    expect(
      userDeviceDetailSchema.safeParse({
        device,
        fingerprints: [],
        recent_ips: [],
      }).success
    ).toBe(true)
  })

  test('parses only the control summary fields on a device list item', () => {
    expect(userDeviceSummarySchema.safeParse(summary).success).toBe(true)
    expect(
      userDeviceSummarySchema.safeParse({
        ...summary,
        blocked_models: device.blocked_models,
      }).success
    ).toBe(false)
  })

  test('accepts zero RPM and an empty blocked-model list when patching controls', () => {
    const result = userDeviceUpdateSchema.safeParse({
      rate_limit_rpm: 0,
      blocked_models: [],
    })

    expect(result.success).toBe(true)
  })

  test.each([-1, 60001])(
    'rejects RPM %d outside the supported range',
    (rpm) => {
      expect(
        userDeviceUpdateSchema.safeParse({ rate_limit_rpm: rpm }).success
      ).toBe(false)
    }
  )

  test('normalizes blocked model IDs by trimming, removing duplicates, and sorting', () => {
    const result = userDeviceUpdateSchema.safeParse({
      blocked_models: [' zeta-model ', 'alpha-model', 'zeta-model', '  '],
    })

    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data.blocked_models).toEqual(['alpha-model', 'zeta-model'])
    }
  })

  test('rejects more than 128 blocked model IDs', () => {
    const blockedModels = Array.from(
      { length: 129 },
      (_, index) => `model-${index}`
    )

    expect(
      userDeviceUpdateSchema.safeParse({ blocked_models: blockedModels })
        .success
    ).toBe(false)
  })

  test('enforces the 128-byte limit for each blocked model ID', () => {
    expect(
      userDeviceUpdateSchema.safeParse({
        blocked_models: ['x'.repeat(128)],
      }).success
    ).toBe(true)
    expect(
      userDeviceUpdateSchema.safeParse({
        blocked_models: ['x'.repeat(129)],
      }).success
    ).toBe(false)
    expect(
      userDeviceUpdateSchema.safeParse({
        blocked_models: ['中'.repeat(43)],
      }).success
    ).toBe(false)
  })
})

describe('administrator device model API', () => {
  test('gets the target user model options from the user-scoped endpoint', async () => {
    const get = vi.spyOn(api, 'get').mockResolvedValue({
      data: {
        success: true,
        message: '',
        data: ['gpt-5.6-sol', 'gpt-5.6-terra'],
      },
    } as never)

    await expect(getUserModels(12)).resolves.toEqual({
      success: true,
      message: '',
      data: ['gpt-5.6-sol', 'gpt-5.6-terra'],
    })
    expect(get).toHaveBeenCalledWith('/api/user/12/models')
  })

  test('rejects an administrator model response containing a non-string option', async () => {
    vi.spyOn(api, 'get').mockResolvedValue({
      data: {
        success: true,
        data: ['gpt-5.6-terra', 5],
      },
    } as never)

    await expect(getUserModels(12)).rejects.toThrow()
  })
})

describe('administrator device control query keys', () => {
  test('keeps model options in a stable user-scoped key', () => {
    expect(userAccessPolicyQueryKeys.models(12)).toEqual([
      'users',
      12,
      'models',
    ])
    expect(userAccessPolicyQueryKeys.models(12)).not.toEqual(
      userAccessPolicyQueryKeys.models(13)
    )
  })
})
