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

import {
  getUserAccessPolicy,
  getUserDevice,
  getUserDevices,
  updateUserAccessPolicy,
  updateUserDevice,
  updateUserDeviceFingerprint,
} from '@/features/users/api'
import {
  userAccessPolicySchema,
  userDeviceDetailSchema,
  userDeviceFingerprintSchema,
  userDeviceSchema,
  userDeviceUpdateSchema,
  userAccessPolicyUpdateSchema,
  userDeviceFingerprintUpdateSchema,
} from '@/features/users/types'
import { api } from '@/lib/api'

import { userAccessPolicyQueryKeys } from '../access-control-query-keys'

const policy = {
  user_id: 12,
  ip_mode: 'unrestricted' as const,
  ip_allowlist: [],
  device_mode: 'off' as const,
  access_policy_version: 1,
  fingerprint_ready: true,
  upgrade_grace_hours: 48,
  active_network_window_minutes: 15,
}

const device = {
  id: 101,
  user_id: 12,
  status: 'pending' as const,
  client_family: 'Codex',
  os_family: 'Windows',
  architecture: 'x64',
  originator: 'codex',
  confidence: 'high',
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

const deviceSummary = {
  ...device,
  fingerprint_count: 1,
  recent_ip_count: 1,
}

const fingerprint = {
  id: 202,
  user_id: 12,
  device_id: 101,
  status: 'trusted' as const,
  grace_until: 0,
  client_version: '1.2.3',
  short_id: 'abcdef123456',
  first_seen_at: 1_700_000_000,
  last_seen_at: 1_700_000_100,
  request_count: 4,
  created_at: 1_700_000_000,
  updated_at: 1_700_000_100,
}

const recentIP = {
  id: 303,
  user_id: 12,
  device_id: 101,
  ip: '203.0.113.10',
  first_seen_at: 1_700_000_000,
  last_seen_at: 1_700_000_100,
  request_count: 4,
}

const detail = {
  device: { ...device },
  fingerprints: [fingerprint],
  recent_ips: [recentIP],
}

function apiResponse<T>(data: T) {
  return { data: { success: true, message: '', data } }
}

describe('administrator access-control API contracts', () => {
  test('accepts only the documented access-control DTO shapes', () => {
    expect(userAccessPolicySchema.safeParse(policy).success).toBe(true)
    expect(userDeviceSchema.safeParse(device).success).toBe(true)
    expect(userDeviceFingerprintSchema.safeParse(fingerprint).success).toBe(
      true
    )
    expect(userDeviceDetailSchema.safeParse(detail).success).toBe(true)
    expect(
      userAccessPolicySchema.safeParse({ ...policy, unknown: true }).success
    ).toBe(false)
    expect(
      userAccessPolicyUpdateSchema.safeParse({
        ip_mode: 'invalid',
      }).success
    ).toBe(false)
    expect(
      userDeviceUpdateSchema.safeParse({ status: 'invalid' }).success
    ).toBe(false)
    expect(
      userDeviceSchema.safeParse({ ...device, confidence: 'unknown' }).success
    ).toBe(false)
    expect(
      userDeviceFingerprintUpdateSchema.safeParse({ status: 'grace' }).success
    ).toBe(false)
  })

  test('gets and parses a user access policy', async () => {
    const get = vi
      .spyOn(api, 'get')
      .mockResolvedValue(apiResponse(policy) as never)

    await expect(getUserAccessPolicy(12)).resolves.toMatchObject({
      success: true,
      data: policy,
    })
    expect(get).toHaveBeenCalledWith('/api/user/12/access-policy')
  })

  test('patches only supplied policy fields and parses the response', async () => {
    const patch = vi
      .spyOn(api, 'patch')
      .mockResolvedValue(apiResponse(policy) as never)
    const payload = { device_mode: 'observe' as const }

    await expect(updateUserAccessPolicy(12, payload)).resolves.toMatchObject({
      success: true,
      data: policy,
    })
    expect(patch).toHaveBeenCalledWith('/api/user/12/access-policy', payload)
  })

  test('parses the paginated device envelope', async () => {
    const get = vi.spyOn(api, 'get').mockResolvedValue(
      apiResponse({
        page: 2,
        page_size: 20,
        total: 1,
        items: [deviceSummary],
      }) as never
    )

    await expect(
      getUserDevices(12, { p: 2, page_size: 20, status: 'pending' })
    ).resolves.toMatchObject({
      data: { page: 2, page_size: 20, total: 1, items: [device] },
    })
    expect(get).toHaveBeenCalledWith('/api/user/12/devices', {
      params: { p: 2, page_size: 20, status: 'pending' },
    })
  })

  test('gets a device detail with fingerprints and recent IPs', async () => {
    const get = vi
      .spyOn(api, 'get')
      .mockResolvedValue(apiResponse(detail) as never)

    await expect(getUserDevice(12, 101)).resolves.toMatchObject({
      success: true,
      data: detail,
    })
    expect(get).toHaveBeenCalledWith('/api/user/12/devices/101')
  })

  test('patches a device and parses the refreshed detail', async () => {
    const patch = vi
      .spyOn(api, 'patch')
      .mockResolvedValue(apiResponse(detail) as never)
    const payload = { status: 'allowed' as const, remark: 'Office device' }

    await expect(updateUserDevice(12, 101, payload)).resolves.toMatchObject({
      success: true,
      data: detail,
    })
    expect(patch).toHaveBeenCalledWith('/api/user/12/devices/101', payload)
  })

  test('patches a fingerprint status and parses the refreshed detail', async () => {
    const patch = vi
      .spyOn(api, 'patch')
      .mockResolvedValue(apiResponse(detail) as never)
    const payload = { status: 'blocked' as const }

    await expect(
      updateUserDeviceFingerprint(12, 101, 202, payload)
    ).resolves.toMatchObject({
      success: true,
      data: detail,
    })
    expect(patch).toHaveBeenCalledWith(
      '/api/user/12/devices/101/fingerprints/202',
      payload
    )
  })

  test('rejects malformed API responses instead of returning untyped data', async () => {
    vi.spyOn(api, 'get').mockResolvedValue(
      apiResponse({ ...policy, access_policy_version: '1' }) as never
    )

    await expect(getUserAccessPolicy(12)).rejects.toThrow()
  })
})

describe('administrator access-control query keys', () => {
  test('keeps policy, list, and detail keys in stable user-scoped layers', () => {
    const filters = { p: 1, page_size: 20, status: 'pending' as const }

    expect(userAccessPolicyQueryKeys.policy(12)).toEqual([
      'users',
      12,
      'access-policy',
    ])
    expect(userAccessPolicyQueryKeys.deviceLists(12)).toEqual([
      'users',
      12,
      'devices',
    ])
    expect(userAccessPolicyQueryKeys.devices(12, filters)).toEqual([
      'users',
      12,
      'devices',
      filters,
    ])
    expect(userAccessPolicyQueryKeys.device(12, 101)).toEqual([
      'users',
      12,
      'devices',
      101,
    ])
    expect(userAccessPolicyQueryKeys.devices(12, filters)).not.toEqual(
      userAccessPolicyQueryKeys.devices(13, filters)
    )
  })
})
