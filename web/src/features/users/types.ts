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

import type { AdminPermissionMatrix } from '@/lib/admin-permissions'

// ============================================================================
// User Schema & Types
// ============================================================================

/** User status: 1 = enabled, 2 = disabled, 3+ = other states */
export const userStatusSchema = z.number()
export type UserStatus = z.infer<typeof userStatusSchema>

/** User role: 1 = common user, 10 = admin, 100 = root */
export const userRoleSchema = z.number()
export type UserRole = z.infer<typeof userRoleSchema>

export const userSchema = z.object({
  id: z.number(),
  username: z.string(),
  display_name: z.string(),
  password: z.string().optional(),
  github_id: z.string().optional(),
  oidc_id: z.string().optional(),
  wechat_id: z.string().optional(),
  telegram_id: z.string().optional(),
  email: z.string().optional(),
  quota: z.number(),
  used_quota: z.number(),
  request_count: z.number(),
  group: z.string(),
  aff_code: z.string().optional(),
  aff_count: z.number().optional(),
  aff_quota: z.number().optional(),
  aff_history_quota: z.number().optional(),
  inviter_id: z.number().optional(),
  linux_do_id: z.string().optional(),
  status: userStatusSchema,
  role: userRoleSchema,
  created_at: z.number().optional(),
  updated_at: z.number().optional(),
  last_login_at: z.number().optional(),
  DeletedAt: z.any().nullable().optional(),
  remark: z.string().optional(),
  admin_permissions: z
    .record(z.string(), z.record(z.string(), z.boolean()))
    .optional(),
})
export type User = z.infer<typeof userSchema>

export const userListSchema = z.array(userSchema)

// ============================================================================
// API Request/Response Types
// ============================================================================

/** Generic API response */
export interface ApiResponse<T = unknown> {
  success: boolean
  message?: string
  data?: T
}

export type UserSortBy =
  | 'id'
  | 'username'
  | 'quota'
  | 'group'
  | 'created_at'
  | 'last_login_at'

export type UserSortOrder = 'asc' | 'desc'

export interface GetUsersParams {
  p?: number
  page_size?: number
  sort_by?: UserSortBy
  sort_order?: UserSortOrder
}

export interface GetUsersResponse {
  success: boolean
  message?: string
  data?: {
    items: User[]
    total: number
    page: number
    page_size: number
  }
}

export interface SearchUsersParams {
  keyword?: string
  group?: string
  role?: string
  status?: string
  p?: number
  page_size?: number
  sort_by?: UserSortBy
  sort_order?: UserSortOrder
}

export interface UserFormData {
  username: string
  display_name: string
  password?: string
  role?: number // Only used when creating user
  quota?: number // Only used when updating user
  group?: string // Only used when updating user
  remark?: string // Only used when updating user
  admin_permissions?: AdminPermissionMatrix
}

export type ManageUserAction =
  | 'promote'
  | 'demote'
  | 'enable'
  | 'disable'
  | 'delete'
  | 'add_quota'

export type QuotaAdjustMode = 'add' | 'subtract' | 'override'

export interface ManageUserQuotaPayload {
  id: number
  action: 'add_quota'
  mode: QuotaAdjustMode
  value: number
}

// ============================================================================
// Administrator Access-Control Schemas & Types
// ============================================================================

const nonNegativeIntegerSchema = z.number().int().nonnegative()
const userDeviceRateLimitRPMSchema = z.number().int().min(0).max(60_000)

const userDeviceModelIdSchema = z
  .string()
  .trim()
  .min(1)
  .refine((value) => new TextEncoder().encode(value).length <= 128)

export const userDeviceBlockedModelsSchema = z
  .array(z.string())
  .transform((models) =>
    [...new Set(models.map((model) => model.trim()).filter(Boolean))].sort()
  )
  .pipe(z.array(userDeviceModelIdSchema).max(128))

export const userIPPolicyModeSchema = z.enum(['unrestricted', 'allowlist'])
export type UserIPPolicyMode = z.infer<typeof userIPPolicyModeSchema>

export const userDevicePolicyModeSchema = z.enum([
  'off',
  'observe',
  'allowlist',
  'blacklist',
])
export type UserDevicePolicyMode = z.infer<typeof userDevicePolicyModeSchema>

export const userDeviceStatusSchema = z.enum(['pending', 'allowed', 'blocked'])
export type UserDeviceStatus = z.infer<typeof userDeviceStatusSchema>

export const userDeviceConfidenceSchema = z.enum(['low', 'medium', 'high'])
export type UserDeviceConfidence = z.infer<typeof userDeviceConfidenceSchema>

export const userDeviceFingerprintStatusSchema = z.enum([
  'pending',
  'trusted',
  'grace',
  'blocked',
])
export type UserDeviceFingerprintStatus = z.infer<
  typeof userDeviceFingerprintStatusSchema
>

export const userDeviceFingerprintUpdateStatusSchema = z.enum([
  'pending',
  'trusted',
  'blocked',
])
export type UserDeviceFingerprintUpdateStatus = z.infer<
  typeof userDeviceFingerprintUpdateStatusSchema
>

export const userAccessPolicySchema = z
  .object({
    user_id: z.number().int().positive(),
    ip_mode: userIPPolicyModeSchema,
    ip_allowlist: z.array(z.string()).max(64),
    device_mode: userDevicePolicyModeSchema,
    access_policy_version: z.number().int().positive(),
    fingerprint_ready: z.boolean(),
    upgrade_grace_hours: nonNegativeIntegerSchema,
    active_network_window_minutes: nonNegativeIntegerSchema,
  })
  .strict()
export type UserAccessPolicy = z.infer<typeof userAccessPolicySchema>

export const userAccessPolicyUpdateSchema = z
  .object({
    ip_mode: userIPPolicyModeSchema.optional(),
    ip_allowlist: z.array(z.string()).max(64).optional(),
    device_mode: userDevicePolicyModeSchema.optional(),
  })
  .strict()
export type UserAccessPolicyUpdate = z.infer<
  typeof userAccessPolicyUpdateSchema
>
export type UserAccessPolicyPatch = UserAccessPolicyUpdate

const userDeviceFields = {
  id: z.number().int().positive(),
  user_id: z.number().int().positive(),
  status: userDeviceStatusSchema,
  client_family: z.string(),
  os_family: z.string(),
  architecture: z.string(),
  originator: z.string(),
  confidence: userDeviceConfidenceSchema,
  first_seen_at: nonNegativeIntegerSchema,
  last_seen_at: nonNegativeIntegerSchema,
  first_ip: z.string().max(45),
  last_ip: z.string().max(45),
  observed_ip_count: nonNegativeIntegerSchema,
  request_count: nonNegativeIntegerSchema,
  denied_count: nonNegativeIntegerSchema,
  last_client_version: z.string().max(64),
  remark: z.string().max(255),
  rate_limit_rpm: userDeviceRateLimitRPMSchema,
  created_at: nonNegativeIntegerSchema,
  updated_at: nonNegativeIntegerSchema,
}

export const userDeviceSchema = z
  .object({
    ...userDeviceFields,
    blocked_models: userDeviceBlockedModelsSchema,
  })
  .strict()
export type UserDevice = z.infer<typeof userDeviceSchema>

export const userDeviceSummarySchema = z
  .object({
    ...userDeviceFields,
    fingerprint_count: nonNegativeIntegerSchema,
    recent_ip_count: nonNegativeIntegerSchema,
    blocked_model_count: nonNegativeIntegerSchema,
  })
  .strict()
export type UserDeviceSummary = z.infer<typeof userDeviceSummarySchema>

export const userDeviceFingerprintSchema = z
  .object({
    id: z.number().int().positive(),
    user_id: z.number().int().positive(),
    device_id: z.number().int().positive(),
    status: userDeviceFingerprintStatusSchema,
    grace_until: nonNegativeIntegerSchema,
    client_version: z.string().max(64),
    runtime_family: z.string().max(32).nullable(),
    installation_id_present: z.boolean().nullable(),
    window_id_present: z.boolean().nullable(),
    user_agent_present: z.boolean(),
    ja4_present: z.boolean(),
    http2_present: z.boolean(),
    short_id: z.string().max(12),
    first_seen_at: nonNegativeIntegerSchema,
    last_seen_at: nonNegativeIntegerSchema,
    request_count: nonNegativeIntegerSchema,
    created_at: nonNegativeIntegerSchema,
    updated_at: nonNegativeIntegerSchema,
  })
  .strict()
export type UserDeviceFingerprint = z.infer<typeof userDeviceFingerprintSchema>

export const userDeviceIPSchema = z
  .object({
    id: z.number().int().positive(),
    user_id: z.number().int().positive(),
    device_id: z.number().int().positive(),
    ip: z.string().max(45),
    first_seen_at: nonNegativeIntegerSchema,
    last_seen_at: nonNegativeIntegerSchema,
    request_count: nonNegativeIntegerSchema,
  })
  .strict()
export type UserDeviceIP = z.infer<typeof userDeviceIPSchema>

export const userDeviceDetailSchema = z
  .object({
    device: userDeviceSchema,
    fingerprints: z.array(userDeviceFingerprintSchema),
    recent_ips: z.array(userDeviceIPSchema).max(10),
  })
  .strict()
export type UserDeviceDetail = z.infer<typeof userDeviceDetailSchema>

export const userDeviceUpdateSchema = z
  .object({
    status: userDeviceStatusSchema.optional(),
    remark: z.string().max(255).optional(),
    rate_limit_rpm: userDeviceRateLimitRPMSchema.optional(),
    blocked_models: userDeviceBlockedModelsSchema.optional(),
  })
  .strict()
export type UserDeviceUpdate = z.infer<typeof userDeviceUpdateSchema>
export type UserDevicePatch = UserDeviceUpdate

export const userDeviceFingerprintUpdateSchema = z
  .object({
    status: userDeviceFingerprintUpdateStatusSchema,
  })
  .strict()
export type UserDeviceFingerprintUpdate = z.infer<
  typeof userDeviceFingerprintUpdateSchema
>
export type UserDeviceFingerprintPatch = UserDeviceFingerprintUpdate

export interface GetUserDevicesParams {
  p?: number
  page_size?: number
  status?: UserDeviceStatus
}

export type ListUserDevicesParams = GetUserDevicesParams

export const userDeviceListDataSchema = z
  .object({
    items: z.array(userDeviceSummarySchema),
    total: nonNegativeIntegerSchema,
    page: z.number().int().positive(),
    page_size: z.number().int().positive(),
  })
  .strict()
export type UserDeviceListData = z.infer<typeof userDeviceListDataSchema>

export const userAccessPolicyApiResponseSchema = z
  .object({
    success: z.literal(true),
    message: z.string().optional(),
    data: userAccessPolicySchema,
  })
  .strict()
export type UserAccessPolicyApiResponse = z.infer<
  typeof userAccessPolicyApiResponseSchema
>
export type GetUserAccessPolicyResponse = UserAccessPolicyApiResponse

export const userDeviceListApiResponseSchema = z
  .object({
    success: z.literal(true),
    message: z.string().optional(),
    data: userDeviceListDataSchema,
  })
  .strict()
export type UserDeviceListApiResponse = z.infer<
  typeof userDeviceListApiResponseSchema
>
export type GetUserDevicesResponse = UserDeviceListApiResponse

export const userDeviceDetailApiResponseSchema = z
  .object({
    success: z.literal(true),
    message: z.string().optional(),
    data: userDeviceDetailSchema,
  })
  .strict()
export type UserDeviceDetailApiResponse = z.infer<
  typeof userDeviceDetailApiResponseSchema
>
export type GetUserDeviceResponse = UserDeviceDetailApiResponse
export type UpdateUserAccessPolicyResponse = UserAccessPolicyApiResponse
export type UpdateUserDeviceResponse = UserDeviceDetailApiResponse
export type UpdateUserDeviceFingerprintResponse = UserDeviceDetailApiResponse

export const userModelsApiResponseSchema = z
  .object({
    success: z.literal(true),
    message: z.string().optional(),
    data: z.array(z.string()),
  })
  .strict()
export type UserModelsApiResponse = z.infer<typeof userModelsApiResponseSchema>

// ============================================================================
// Dialog Types
// ============================================================================

export type UsersDialogType = 'create' | 'update' | 'delete'
