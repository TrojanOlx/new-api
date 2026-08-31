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
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'

import { UserAccessControlDialog } from '../user-access-control-dialog'

const apiMocks = vi.hoisted(() => ({
  getUserAccessPolicy: vi.fn(),
  getUserDevice: vi.fn(),
  getUserDevices: vi.fn(),
  getUserModels: vi.fn(),
  updateUserDevice: vi.fn(),
  updateUserDeviceFingerprint: vi.fn(),
}))

vi.mock('@/features/users/api', () => apiMocks)

const availableModels = ['gpt-5.6-sol', 'gpt-5.6-terra', 'gpt-4o-mini']

const baseDevice = {
  id: 31,
  user_id: 7,
  status: 'allowed',
  client_family: 'Codex Desktop',
  os_family: 'Windows',
  architecture: 'amd64',
  originator: 'codex',
  confidence: 'high',
  first_seen_at: 1_787_990_000,
  last_seen_at: 1_787_990_100,
  first_ip: '203.0.113.10',
  last_ip: '203.0.113.11',
  observed_ip_count: 2,
  request_count: 12,
  denied_count: 1,
  last_client_version: '1.2.3',
  remark: '',
  rate_limit_rpm: 120,
  blocked_models: ['gpt-5.6-sol'],
  created_at: 1_787_990_000,
  updated_at: 1_787_990_100,
}

const basePolicy = {
  user_id: 7,
  ip_mode: 'unrestricted',
  ip_allowlist: [],
  device_mode: 'observe',
  access_policy_version: 2,
  fingerprint_ready: true,
  upgrade_grace_hours: 48,
  active_network_window_minutes: 30,
}

function deviceResponse(overrides: Record<string, unknown> = {}) {
  const device = { ...baseDevice, ...overrides }
  return {
    success: true,
    message: '',
    data: {
      device,
      fingerprints: [],
      recent_ips: [],
    },
  }
}

function deviceListResponse(overrides: Record<string, unknown> = {}) {
  const device = { ...baseDevice, ...overrides }
  return {
    success: true,
    message: '',
    data: {
      page: 1,
      page_size: 20,
      total: 1,
      items: [
        {
          ...device,
          fingerprint_count: 0,
          recent_ip_count: device.observed_ip_count,
          blocked_model_count: device.blocked_models.length,
        },
      ],
    },
  }
}

function installApiFixtures(
  policyOverrides: Record<string, unknown> = {},
  deviceOverrides: Record<string, unknown> = {}
): void {
  apiMocks.getUserAccessPolicy.mockResolvedValue({
    success: true,
    message: '',
    data: { ...basePolicy, ...policyOverrides },
  })
  apiMocks.getUserDevices.mockResolvedValue(deviceListResponse(deviceOverrides))
  apiMocks.getUserDevice.mockResolvedValue(deviceResponse(deviceOverrides))
  apiMocks.getUserModels.mockResolvedValue({
    success: true,
    message: '',
    data: availableModels,
  })
  apiMocks.updateUserDevice.mockResolvedValue(deviceResponse(deviceOverrides))
  apiMocks.updateUserDeviceFingerprint.mockResolvedValue(
    deviceResponse(deviceOverrides)
  )
}

function renderDialog(): QueryClient {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <UserAccessControlDialog
        open
        onOpenChange={() => undefined}
        user={{ id: 7, username: 'alice' }}
      />
    </QueryClientProvider>
  )
  return queryClient
}

async function openDeviceDetail(
  user: ReturnType<typeof userEvent.setup>
): Promise<void> {
  await user.click(await screen.findByRole('tab', { name: 'Devices' }))
  await user.click(
    await screen.findByRole('button', { name: 'Actions for device 31' })
  )
  await user.click(await screen.findByRole('menuitem', { name: 'View' }))
  await screen.findByRole('heading', { name: 'Device controls' })
}

beforeEach(() => {
  installApiFixtures()
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('administrator device request controls', () => {
  test('shows rate controls and searches or creates exact blocked model IDs', async () => {
    const user = userEvent.setup()
    renderDialog()
    await openDeviceDetail(user)

    const rateLimitSwitch = screen.getByRole('switch', {
      name: /rate limit/i,
    })
    expect(rateLimitSwitch).toHaveAttribute('aria-checked', 'true')
    expect(
      screen.getByRole('spinbutton', { name: /requests per minute/i })
    ).toHaveValue(120)

    const modelInput = screen.getByRole('combobox', {
      name: /blocked models/i,
    })
    await user.click(modelInput)
    await user.type(modelInput, 'gpt-5.6-terra')
    await user.click(await screen.findByText('gpt-5.6-terra'))
    expect(screen.getByText('gpt-5.6-terra')).toBeVisible()

    await user.keyboard('{Escape}')
    await user.click(modelInput)
    await user.type(modelInput, 'vendor/private-model')
    expect(modelInput).toHaveValue('vendor/private-model')
    await user.keyboard('{Enter}')
    expect(await screen.findByText('vendor/private-model')).toBeVisible()
  })

  test('saves explicit zero RPM and an empty blocked-model list', async () => {
    const user = userEvent.setup()
    renderDialog()
    await openDeviceDetail(user)

    await user.click(
      screen.getByRole('switch', {
        name: /rate limit/i,
      })
    )
    const rpmInput = screen.getByRole('spinbutton', {
      name: /requests per minute/i,
    })
    fireEvent.change(rpmInput, { target: { value: '0' } })

    const modelInput = screen.getByRole('combobox', {
      name: /blocked models/i,
    })
    await user.click(modelInput)
    await user.keyboard('{Backspace}')
    await user.keyboard('{Escape}')

    await user.click(
      screen.getByRole('button', { name: /save device controls/i })
    )

    await waitFor(() =>
      expect(apiMocks.updateUserDevice).toHaveBeenCalledWith(7, 31, {
        rate_limit_rpm: 0,
        blocked_models: [],
      })
    )
  })

  test('preserves an unsaved device remark after saving request controls', async () => {
    const user = userEvent.setup()
    let resolveUpdate:
      | ((response: ReturnType<typeof deviceResponse>) => void)
      | undefined
    apiMocks.updateUserDevice.mockImplementation(
      () =>
        new Promise<ReturnType<typeof deviceResponse>>((resolve) => {
          resolveUpdate = resolve
        })
    )
    const queryClient = renderDialog()
    await openDeviceDetail(user)

    const remark = screen.getByLabelText('Administrator remark')
    await user.type(remark, 'keep this draft')
    fireEvent.change(
      screen.getByRole('spinbutton', { name: /requests per minute/i }),
      { target: { value: '240' } }
    )
    await user.click(
      screen.getByRole('button', { name: /save device controls/i })
    )

    await waitFor(() =>
      expect(apiMocks.updateUserDevice).toHaveBeenCalledWith(7, 31, {
        rate_limit_rpm: 240,
        blocked_models: ['gpt-5.6-sol'],
      })
    )
    await act(async () => {
      if (!resolveUpdate) throw new Error('Device control update did not start')
      const response = deviceResponse({
        rate_limit_rpm: 240,
        blocked_models: ['gpt-5.6-sol'],
        updated_at: baseDevice.updated_at + 1,
      })
      apiMocks.getUserDevice.mockResolvedValue(response)
      resolveUpdate(response)
    })
    await waitFor(() => {
      expect(queryClient.isMutating()).toBe(0)
      expect(queryClient.isFetching()).toBe(0)
    })
    expect(screen.getByLabelText('Administrator remark')).toHaveValue(
      'keep this draft'
    )
  })

  test('preserves unsaved request controls after saving a device remark', async () => {
    const user = userEvent.setup()
    let resolveUpdate:
      | ((response: ReturnType<typeof deviceResponse>) => void)
      | undefined
    apiMocks.updateUserDevice.mockImplementation(
      () =>
        new Promise<ReturnType<typeof deviceResponse>>((resolve) => {
          resolveUpdate = resolve
        })
    )
    const queryClient = renderDialog()
    await openDeviceDetail(user)

    const rpmInput = screen.getByRole('spinbutton', {
      name: /requests per minute/i,
    })
    fireEvent.change(rpmInput, { target: { value: '240' } })
    await user.type(
      screen.getByLabelText('Administrator remark'),
      'saved remark'
    )
    await user.click(screen.getByRole('button', { name: 'Save device' }))

    await waitFor(() =>
      expect(apiMocks.updateUserDevice).toHaveBeenCalledWith(7, 31, {
        remark: 'saved remark',
      })
    )
    await act(async () => {
      if (!resolveUpdate) throw new Error('Device remark update did not start')
      const response = deviceResponse({
        remark: 'saved remark',
        updated_at: baseDevice.updated_at + 1,
      })
      apiMocks.getUserDevice.mockResolvedValue(response)
      resolveUpdate(response)
    })
    await waitFor(() => {
      expect(queryClient.isMutating()).toBe(0)
      expect(queryClient.isFetching()).toBe(0)
    })
    expect(
      screen.getByRole('spinbutton', { name: /requests per minute/i })
    ).toHaveValue(240)
  })

  test('disables request controls while device mode is off', async () => {
    const user = userEvent.setup()
    installApiFixtures(
      { device_mode: 'off' },
      {
        rate_limit_rpm: 0,
        blocked_models: [],
      }
    )
    renderDialog()
    await openDeviceDetail(user)

    expect(
      await screen.findByText(/enable.*observe.*stricter device mode/i)
    ).toBeVisible()
    expect(screen.getByRole('switch', { name: /rate limit/i })).toHaveAttribute(
      'aria-disabled',
      'true'
    )
    expect(
      screen.getByRole('spinbutton', { name: /requests per minute/i })
    ).toBeDisabled()
    expect(
      screen.getByRole('combobox', { name: /blocked models/i })
    ).toBeDisabled()
    expect(
      screen.queryByRole('button', { name: /clear device controls/i })
    ).not.toBeInTheDocument()
  })

  test('offers a clear-only recovery action when off mode has active controls', async () => {
    const user = userEvent.setup()
    installApiFixtures(
      { device_mode: 'off' },
      {
        rate_limit_rpm: 120,
        blocked_models: ['gpt-5.6-sol'],
      }
    )
    renderDialog()
    await openDeviceDetail(user)

    const clearButton = await screen.findByRole('button', {
      name: /clear device controls/i,
    })
    expect(clearButton).toBeVisible()
    expect(screen.getByRole('switch', { name: /rate limit/i })).toHaveAttribute(
      'aria-disabled',
      'true'
    )
    expect(
      screen.getByRole('spinbutton', { name: /requests per minute/i })
    ).toBeDisabled()
    expect(
      screen.getByRole('combobox', { name: /blocked models/i })
    ).toBeDisabled()
    expect(
      screen.getByRole('button', { name: /save device controls/i })
    ).toBeDisabled()

    await user.click(clearButton)

    await waitFor(() =>
      expect(apiMocks.updateUserDevice).toHaveBeenCalledWith(7, 31, {
        rate_limit_rpm: 0,
        blocked_models: [],
      })
    )
  })

  test('shows device controls under their matching list columns', async () => {
    const user = userEvent.setup()
    installApiFixtures({}, { rate_limit_rpm: 120 })
    renderDialog()

    await user.click(await screen.findByRole('tab', { name: 'Devices' }))
    const row = await screen.findByRole('row', { name: /#31/ })

    expect(
      screen.getByRole('columnheader', { name: /RPM/i })
    ).toBeInTheDocument()
    expect(
      screen.getByRole('columnheader', { name: /Blocked models/i })
    ).toBeInTheDocument()
    const cells = within(row).getAllByRole('cell')
    expect(cells).toHaveLength(9)
    expect(cells[1]).toHaveTextContent('Codex Desktop')
    expect(cells[2]).toHaveTextContent('Windows / amd64')
    expect(cells[4]).toHaveTextContent('120')
    expect(cells[5]).toHaveTextContent('1')
  })
})
