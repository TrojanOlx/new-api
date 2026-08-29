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
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import { toast } from 'sonner'
import { afterEach, describe, expect, test, vi } from 'vitest'

import { api } from '@/lib/api'

import { UserAccessControlDialog } from '../dialogs/user-access-control-dialog'

vi.mock('sonner', () => ({
  toast: {
    error: vi.fn(),
    success: vi.fn(),
  },
}))

type ApiCall = {
  url: string
  data?: unknown
}

type MockableApi = {
  get: (url: string, config?: unknown) => Promise<{ data: unknown }>
  patch: (url: string, data?: unknown) => Promise<{ data: unknown }>
}

const apiClient = api as unknown as MockableApi
const originalGet = apiClient.get
const originalPatch = apiClient.patch
let queryClient: QueryClient | null = null

const policy = {
  user_id: 7,
  ip_mode: 'unrestricted',
  ip_allowlist: [],
  device_mode: 'observe',
  access_policy_version: 2,
  fingerprint_ready: true,
  upgrade_grace_hours: 48,
  active_network_window_minutes: 30,
}

const device = {
  id: 31,
  user_id: 7,
  status: 'pending',
  client_family: 'Codex Desktop',
  os_family: 'Windows',
  architecture: 'amd64',
  originator: 'codex',
  confidence: 'low',
  first_seen_at: 1_787_990_000,
  last_seen_at: 1_787_990_100,
  first_ip: '203.0.113.10',
  last_ip: '203.0.113.11',
  observed_ip_count: 2,
  request_count: 12,
  denied_count: 1,
  last_client_version: '1.2.3',
  remark: '',
  created_at: 1_787_990_000,
  updated_at: 1_787_990_100,
  fingerprint_count: 1,
  recent_ip_count: 2,
}

const detail = {
  device: {
    id: device.id,
    user_id: device.user_id,
    status: device.status,
    client_family: device.client_family,
    os_family: device.os_family,
    architecture: device.architecture,
    originator: device.originator,
    confidence: device.confidence,
    first_seen_at: device.first_seen_at,
    last_seen_at: device.last_seen_at,
    first_ip: device.first_ip,
    last_ip: device.last_ip,
    observed_ip_count: device.observed_ip_count,
    request_count: device.request_count,
    denied_count: device.denied_count,
    last_client_version: device.last_client_version,
    remark: device.remark,
    created_at: device.created_at,
    updated_at: device.updated_at,
  },
  fingerprints: [
    {
      id: 41,
      user_id: 7,
      device_id: 31,
      status: 'pending',
      grace_until: 0,
      client_version: '1.2.3',
      short_id: 'fp-short-001',
      first_seen_at: 1_787_990_000,
      last_seen_at: 1_787_990_100,
      request_count: 12,
      created_at: 1_787_990_000,
      updated_at: 1_787_990_100,
    },
    {
      id: 42,
      user_id: 7,
      device_id: 31,
      status: 'grace',
      grace_until: 1_788_162_900,
      client_version: '1.2.4',
      short_id: 'fp-grace-002',
      first_seen_at: 1_787_990_100,
      last_seen_at: 1_787_990_200,
      request_count: 2,
      created_at: 1_787_990_100,
      updated_at: 1_787_990_200,
    },
  ],
  recent_ips: [
    {
      id: 51,
      user_id: 7,
      device_id: 31,
      ip: '203.0.113.11',
      first_seen_at: 1_787_990_000,
      last_seen_at: 1_787_990_100,
      request_count: 8,
    },
  ],
}

function installApiFixtures(patchCalls: ApiCall[], getCalls?: ApiCall[]): void {
  apiClient.get = async (url, config) => {
    getCalls?.push({ url, data: config })
    if (url === '/api/user/7/access-policy') {
      return { data: { success: true, data: policy } }
    }
    if (url === '/api/user/7/devices') {
      return {
        data: {
          success: true,
          data: { page: 1, page_size: 20, total: 1, items: [device] },
        },
      }
    }
    if (url === '/api/user/7/devices/31') {
      return { data: { success: true, data: detail } }
    }
    throw new Error(`Unexpected GET ${url}`)
  }
  apiClient.patch = async (url, data) => {
    patchCalls.push({ url, data })
    if (url.endsWith('/access-policy')) {
      const request = data as { ip_mode?: string; ip_allowlist?: string[] }
      return {
        data: {
          success: true,
          data: {
            ...policy,
            ip_mode: request.ip_mode ?? policy.ip_mode,
            ip_allowlist: request.ip_allowlist ?? policy.ip_allowlist,
            access_policy_version: 3,
          },
        },
      }
    }
    if (url.endsWith('/fingerprints/41')) {
      return {
        data: {
          success: true,
          data: {
            ...detail,
            fingerprints: [{ ...detail.fingerprints[0], status: 'blocked' }],
          },
        },
      }
    }
    return { data: { success: true, data: detail } }
  }
}

function renderDialog(open = true): void {
  queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <UserAccessControlDialog
        open={open}
        onOpenChange={() => undefined}
        user={{ id: 7, username: 'alice' }}
      />
    </QueryClientProvider>
  )
}

afterEach(() => {
  apiClient.get = originalGet
  apiClient.patch = originalPatch
  vi.clearAllMocks()
  queryClient?.clear()
  queryClient = null
})

describe('UserAccessControlDialog', () => {
  test('does not request administrator data while closed', async () => {
    const getCalls: ApiCall[] = []
    installApiFixtures([], getCalls)

    renderDialog(false)

    await Promise.resolve()
    expect(getCalls).toHaveLength(0)
  })

  test('shows the policy error state when the administrator request fails', async () => {
    apiClient.get = async () => {
      throw new Error('policy unavailable')
    }

    renderDialog()

    expect(
      await screen.findByText('Failed to load access policy')
    ).toBeInTheDocument()
  })

  test('shows an empty state when no device profiles exist', async () => {
    installApiFixtures([])
    apiClient.get = async (url) => {
      if (url === '/api/user/7/access-policy') {
        return { data: { success: true, data: policy } }
      }
      if (url === '/api/user/7/devices') {
        return {
          data: {
            success: true,
            data: { page: 1, page_size: 20, total: 0, items: [] },
          },
        }
      }
      throw new Error(`Unexpected GET ${url}`)
    }
    renderDialog()

    fireEvent.click(await screen.findByRole('tab', { name: 'Devices' }))

    expect(await screen.findByText('No device profiles')).toBeInTheDocument()
  })

  test('sends the selected device status filter', async () => {
    const getCalls: ApiCall[] = []
    installApiFixtures([], getCalls)
    renderDialog()

    fireEvent.click(await screen.findByRole('tab', { name: 'Devices' }))
    expect(await screen.findByText('Codex Desktop')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('tab', { name: 'Pending' }))

    await waitFor(() =>
      expect(getCalls).toContainEqual({
        url: '/api/user/7/devices',
        data: { params: { p: 1, page_size: 20, status: 'pending' } },
      })
    )
  })

  test('shows an error toast when a policy update fails', async () => {
    installApiFixtures([])
    apiClient.patch = async () => {
      throw new Error('update rejected')
    }
    renderDialog()

    const deviceModeField = (
      await screen.findByText('Device policy mode')
    ).closest('[data-slot="field"]')
    expect(deviceModeField).not.toBeNull()
    fireEvent.click(
      within(deviceModeField as HTMLElement).getByRole('button', {
        name: 'Off',
      })
    )
    fireEvent.click(screen.getByRole('button', { name: 'Save policy' }))

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith('Failed to save access policy')
    )
  })

  test('requires confirmation before blocking a device from the list', async () => {
    const patchCalls: ApiCall[] = []
    installApiFixtures(patchCalls)
    renderDialog()

    fireEvent.click(await screen.findByRole('tab', { name: 'Devices' }))
    expect(await screen.findByText('Codex Desktop')).toBeInTheDocument()
    fireEvent.click(
      screen.getByRole('button', { name: 'Actions for device 31' })
    )
    fireEvent.click(await screen.findByRole('menuitem', { name: 'Block' }))
    expect(patchCalls).not.toContainEqual({
      url: '/api/user/7/devices/31',
      data: { status: 'blocked' },
    })

    fireEvent.click(await screen.findByRole('button', { name: 'Block device' }))

    await waitFor(() =>
      expect(patchCalls).toContainEqual({
        url: '/api/user/7/devices/31',
        data: { status: 'blocked' },
      })
    )
  })

  test('submits trimmed IP entries while preserving the selected policy modes', async () => {
    const patchCalls: ApiCall[] = []
    installApiFixtures(patchCalls)
    renderDialog()

    expect(
      await screen.findByRole('heading', { name: 'Access control for alice' })
    ).toBeInTheDocument()
    const ipModeField = (await screen.findByText('IP policy mode')).closest(
      '[data-slot="field"]'
    )
    expect(ipModeField).not.toBeNull()
    fireEvent.click(
      within(ipModeField as HTMLElement).getByRole('button', {
        name: 'Allowlist',
      })
    )
    const allowlistInput = screen.getByLabelText('Allowed IPs and CIDRs')
    await waitFor(() => expect(allowlistInput).toBeEnabled())
    fireEvent.change(allowlistInput, {
      target: { value: ' 203.0.113.10 \n\n 2001:db8::/32 ' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save policy' }))

    await waitFor(() => expect(patchCalls).toHaveLength(1))
    expect(patchCalls[0]).toEqual({
      url: '/api/user/7/access-policy',
      data: {
        ip_mode: 'allowlist',
        ip_allowlist: ['203.0.113.10', '2001:db8::/32'],
      },
    })
  })

  test('blocks device allowlist save until a trusted allowed device exists', async () => {
    const patchCalls: ApiCall[] = []
    installApiFixtures(patchCalls)
    renderDialog()

    const deviceModeField = (
      await screen.findByText('Device policy mode')
    ).closest('[data-slot="field"]')
    expect(deviceModeField).not.toBeNull()
    fireEvent.click(
      within(deviceModeField as HTMLElement).getByRole('button', {
        name: 'Allowlist',
      })
    )

    expect(
      await screen.findByText(
        'At least one allowed device with a trusted fingerprint is required'
      )
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save policy' })).toBeDisabled()
    expect(patchCalls).toHaveLength(0)
  })

  test('keeps the device table scrollable and exposes low-confidence fingerprint review', async () => {
    const patchCalls: ApiCall[] = []
    installApiFixtures(patchCalls)
    renderDialog()

    fireEvent.click(await screen.findByRole('tab', { name: 'Devices' }))
    expect(await screen.findByText('Codex Desktop')).toBeInTheDocument()
    expect(
      screen.getByText('Low-confidence device profiles may collide')
    ).toBeInTheDocument()
    expect(screen.getByLabelText('Device table')).toHaveClass('overflow-x-auto')
    expect(screen.getByRole('tab', { name: 'Pending' })).toBeInTheDocument()
    expect(
      screen.getByRole('columnheader', { name: 'Device ID' })
    ).toBeInTheDocument()
    expect(
      screen.getByRole('columnheader', { name: 'Client version' })
    ).toBeInTheDocument()
    expect(
      screen.getByRole('columnheader', { name: 'IP count' })
    ).toBeInTheDocument()
    expect(
      screen.getByRole('columnheader', { name: 'Requests' })
    ).toBeInTheDocument()
    expect(screen.getByText('#31')).toBeInTheDocument()

    fireEvent.click(
      screen.getByRole('button', { name: 'Actions for device 31' })
    )
    fireEvent.click(await screen.findByRole('menuitem', { name: 'View' }))
    expect(await screen.findByText('fp-short-001')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.11')).toBeInTheDocument()
    expect(screen.getByText('Upgrade grace until')).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('Administrator remark'), {
      target: { value: 'reviewed locally' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save device' }))
    await waitFor(() =>
      expect(patchCalls).toContainEqual({
        url: '/api/user/7/devices/31',
        data: { remark: 'reviewed locally' },
      })
    )

    const deviceStatusField = screen
      .getByText('Device status')
      .closest('[data-slot="field"]')
    expect(deviceStatusField).not.toBeNull()
    fireEvent.click(
      within(deviceStatusField as HTMLElement).getByRole('button', {
        name: 'blocked',
      })
    )
    fireEvent.click(screen.getByRole('button', { name: 'Save device' }))
    expect(patchCalls).not.toContainEqual({
      url: '/api/user/7/devices/31',
      data: { status: 'blocked' },
    })
    fireEvent.click(
      await screen.findByRole('button', { name: 'Confirm status change' })
    )
    await waitFor(() =>
      expect(patchCalls).toContainEqual({
        url: '/api/user/7/devices/31',
        data: { status: 'blocked' },
      })
    )

    fireEvent.click(
      screen.getByRole('button', { name: 'Block fingerprint fp-short-001' })
    )
    expect(patchCalls).not.toContainEqual({
      url: '/api/user/7/devices/31/fingerprints/41',
      data: { status: 'blocked' },
    })
    fireEvent.click(
      await screen.findByRole('button', { name: 'Block fingerprint' })
    )
    await waitFor(() =>
      expect(patchCalls).toContainEqual({
        url: '/api/user/7/devices/31/fingerprints/41',
        data: { status: 'blocked' },
      })
    )
  })
})
