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
import type { PermissionCatalog } from '@/lib/admin-permissions'
import { api } from '@/lib/api'
import type { CustomOAuthBinding } from '@/lib/oauth'

import {
  userAccessPolicyApiResponseSchema,
  userDeviceDetailApiResponseSchema,
  userDeviceFingerprintUpdateSchema,
  userDeviceListApiResponseSchema,
  userDeviceUpdateSchema,
  userAccessPolicyUpdateSchema,
  type ApiResponse,
  type GetUserDevicesParams,
  type User,
  type GetUsersParams,
  type GetUsersResponse,
  type SearchUsersParams,
  type UserFormData,
  type ManageUserAction,
  type ManageUserQuotaPayload,
  type UserAccessPolicyApiResponse,
  type UserAccessPolicyUpdate,
  type UserDeviceDetailApiResponse,
  type UserDeviceFingerprintUpdate,
  type UserDeviceListApiResponse,
  type UserDeviceUpdate,
} from './types'

// ============================================================================
// User Management APIs
// ============================================================================

/**
 * Get paginated users list
 */
export async function getUsers(
  params: GetUsersParams = {}
): Promise<GetUsersResponse> {
  const { p = 1, page_size = 10, sort_by, sort_order } = params
  const res = await api.get('/api/user/', {
    params: {
      p,
      page_size,
      sort_by,
      sort_order,
    },
  })
  return res.data
}

/**
 * Search users by keyword or group
 */
export async function searchUsers(
  params: SearchUsersParams
): Promise<GetUsersResponse> {
  const {
    keyword = '',
    group = '',
    role = '',
    status = '',
    p = 1,
    page_size = 10,
    sort_by,
    sort_order,
  } = params
  const queryParams = new URLSearchParams()
  queryParams.set('keyword', keyword)
  queryParams.set('group', group)
  if (role) queryParams.set('role', role)
  if (status) queryParams.set('status', status)
  queryParams.set('p', String(p))
  queryParams.set('page_size', String(page_size))
  if (sort_by) queryParams.set('sort_by', sort_by)
  if (sort_order) queryParams.set('sort_order', sort_order)
  const res = await api.get(`/api/user/search?${queryParams.toString()}`)
  return res.data
}

/**
 * Get single user by ID
 */
export async function getUser(id: number): Promise<ApiResponse<User>> {
  const res = await api.get(`/api/user/${id}`)
  return res.data
}

/**
 * Create a new user
 */
export async function createUser(
  data: UserFormData
): Promise<ApiResponse<User>> {
  const res = await api.post('/api/user/', data)
  return res.data
}

/**
 * Update an existing user
 */
export async function updateUser(
  data: UserFormData & { id: number }
): Promise<ApiResponse<Partial<User>>> {
  const res = await api.put('/api/user/', data)
  return res.data
}

/**
 * Delete a single user (hard delete)
 */
export async function deleteUser(id: number): Promise<ApiResponse> {
  const res = await api.delete(`/api/user/${id}/`)
  return res.data
}

/**
 * Manage user (promote, demote, enable, disable, delete)
 */
export async function manageUser(
  id: number,
  action: ManageUserAction
): Promise<ApiResponse<Partial<User>>> {
  const res = await api.post('/api/user/manage', { id, action })
  return res.data
}

/**
 * Adjust user quota atomically (add/subtract/override)
 */
export async function adjustUserQuota(
  payload: ManageUserQuotaPayload
): Promise<ApiResponse<Partial<User>>> {
  const res = await api.post('/api/user/manage', payload)
  return res.data
}

/**
 * Reset user's Passkey registration
 */
export async function resetUserPasskey(id: number): Promise<ApiResponse> {
  const res = await api.delete(`/api/user/${id}/reset_passkey`)
  return res.data
}

/**
 * Reset user's Two-Factor Authentication setup
 */
export async function resetUserTwoFA(id: number): Promise<ApiResponse> {
  const res = await api.delete(`/api/user/${id}/2fa`)
  return res.data
}

/**
 * Get all available groups
 */
export async function getGroups(): Promise<ApiResponse<string[]>> {
  const res = await api.get('/api/group/')
  return res.data
}

/**
 * Get the permission catalog (resources, actions, and role baselines).
 * Source of truth lives in the backend authz package.
 */
export async function getPermissionCatalog(): Promise<PermissionCatalog> {
  const res = await api.get('/api/authz/catalog')
  return {
    resources: res.data?.data?.resources ?? [],
    roles: res.data?.data?.roles ?? [],
  }
}

// ============================================================================
// Administrator Access-Control APIs
// ============================================================================

/**
 * Get a user's normalized access policy.
 */
export async function getUserAccessPolicy(
  userId: number
): Promise<UserAccessPolicyApiResponse> {
  const res = await api.get(`/api/user/${userId}/access-policy`)
  return userAccessPolicyApiResponseSchema.parse(res.data)
}

/**
 * Partially update a user's access policy. Omitted fields are preserved by the
 * backend; an explicit empty allowlist remains distinguishable from omission.
 */
export async function updateUserAccessPolicy(
  userId: number,
  payload: UserAccessPolicyUpdate
): Promise<UserAccessPolicyApiResponse> {
  const validatedPayload = userAccessPolicyUpdateSchema.parse(payload)
  const res = await api.patch(
    `/api/user/${userId}/access-policy`,
    validatedPayload
  )
  return userAccessPolicyApiResponseSchema.parse(res.data)
}

/**
 * Get a paginated list of safe device projections for a user.
 */
export async function getUserDevices(
  userId: number,
  params: GetUserDevicesParams = {}
): Promise<UserDeviceListApiResponse> {
  const res = await api.get(`/api/user/${userId}/devices`, { params })
  return userDeviceListApiResponseSchema.parse(res.data)
}

/** Alias matching the backend's list operation name. */
export const listUserDevices = getUserDevices

/**
 * Get one device, its fingerprint aliases, and its recent IP history.
 */
export async function getUserDevice(
  userId: number,
  deviceId: number
): Promise<UserDeviceDetailApiResponse> {
  const res = await api.get(`/api/user/${userId}/devices/${deviceId}`)
  return userDeviceDetailApiResponseSchema.parse(res.data)
}

/**
 * Update administrator-editable device fields and return refreshed detail.
 */
export async function updateUserDevice(
  userId: number,
  deviceId: number,
  payload: UserDeviceUpdate
): Promise<UserDeviceDetailApiResponse> {
  const validatedPayload = userDeviceUpdateSchema.parse(payload)
  const res = await api.patch(
    `/api/user/${userId}/devices/${deviceId}`,
    validatedPayload
  )
  return userDeviceDetailApiResponseSchema.parse(res.data)
}

/**
 * Update one fingerprint alias status and return refreshed device detail.
 */
export async function updateUserDeviceFingerprint(
  userId: number,
  deviceId: number,
  fingerprintId: number,
  payload: UserDeviceFingerprintUpdate
): Promise<UserDeviceDetailApiResponse> {
  const validatedPayload = userDeviceFingerprintUpdateSchema.parse(payload)
  const res = await api.patch(
    `/api/user/${userId}/devices/${deviceId}/fingerprints/${fingerprintId}`,
    validatedPayload
  )
  return userDeviceDetailApiResponseSchema.parse(res.data)
}

// ============================================================================
// Admin Binding Management APIs
// ============================================================================

/**
 * Get user's custom OAuth bindings (admin)
 */
export async function getUserOAuthBindings(
  userId: number
): Promise<ApiResponse<CustomOAuthBinding[]>> {
  const res = await api.get(`/api/user/${userId}/oauth/bindings`)
  return res.data
}

/**
 * Clear a user's built-in binding (admin)
 */
export async function adminClearUserBinding(
  userId: number,
  bindingType: string
): Promise<ApiResponse> {
  const res = await api.delete(`/api/user/${userId}/bindings/${bindingType}`)
  return res.data
}

/**
 * Unbind custom OAuth for a user (admin)
 */
export async function adminUnbindCustomOAuth(
  userId: number,
  providerId: number
): Promise<ApiResponse> {
  const res = await api.delete(
    `/api/user/${userId}/oauth/bindings/${providerId}`
  )
  return res.data
}
