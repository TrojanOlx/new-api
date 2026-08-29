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
import { zodResolver } from '@hookform/resolvers/zod'
import { FloppyDiskIcon } from '@hugeicons/core-free-icons'
import { HugeiconsIcon } from '@hugeicons/react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Controller, useForm } from 'react-hook-form'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
  FieldTitle,
} from '@/components/ui/field'
import { Spinner } from '@/components/ui/spinner'
import { Textarea } from '@/components/ui/textarea'
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group'

import {
  getUserDevice,
  getUserDevices,
  updateUserAccessPolicy,
} from '../../api'
import {
  type UserAccessPolicyDirtyFields,
  type UserAccessPolicyFormValues,
  accessPolicyFormToUpdate,
  accessPolicyToFormValues,
  userAccessPolicyFormSchema,
} from '../../lib/access-control-form'
import { userAccessPolicyQueryKeys } from '../../lib/access-control-query-keys'
import type {
  UserAccessPolicy,
  UserDevicePolicyMode,
  UserIPPolicyMode,
} from '../../types'

const IP_MODES: ReadonlyArray<{ value: UserIPPolicyMode; label: string }> = [
  { value: 'unrestricted', label: 'Unrestricted' },
  { value: 'allowlist', label: 'Allowlist' },
]

const DEVICE_MODES: ReadonlyArray<{
  value: UserDevicePolicyMode
  label: string
}> = [
  { value: 'off', label: 'Off' },
  { value: 'observe', label: 'Observe' },
  { value: 'allowlist', label: 'Allowlist' },
  { value: 'blacklist', label: 'Blocklist' },
]

interface UserAccessPolicyFormProps {
  userId: number
  policy: UserAccessPolicy
}

function nextToggleValue<T extends string>(
  values: readonly string[],
  current: T
): T {
  return (values.find((value) => value !== current) ?? current) as T
}

export function UserAccessPolicyForm(props: UserAccessPolicyFormProps) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const form = useForm<UserAccessPolicyFormValues>({
    resolver: zodResolver(userAccessPolicyFormSchema),
    defaultValues: accessPolicyToFormValues(props.policy),
  })
  const mutation = useMutation({
    mutationFn: (input: {
      values: UserAccessPolicyFormValues
      dirtyFields: UserAccessPolicyDirtyFields
    }) =>
      updateUserAccessPolicy(
        props.userId,
        accessPolicyFormToUpdate(input.values, input.dirtyFields)
      ),
    onSuccess: (response) => {
      queryClient.setQueryData(
        userAccessPolicyQueryKeys.policy(props.userId),
        response
      )
      form.reset(accessPolicyToFormValues(response.data))
      toast.success(t('Access policy saved'))
    },
    onError: () => toast.error(t('Failed to save access policy')),
  })

  const selectedIPMode = form.watch('ip_mode')
  const selectedDeviceMode = form.watch('device_mode')
  const { dirtyFields, isDirty } = form.formState
  const trustedDeviceQuery = useQuery({
    queryKey: userAccessPolicyQueryKeys.trustedDevicePrerequisite(props.userId),
    queryFn: async () => {
      const response = await getUserDevices(props.userId, {
        p: 1,
        page_size: 100,
        status: 'allowed',
      })
      for (const device of response.data.items) {
        if (device.status !== 'allowed') continue
        const detail = await getUserDevice(props.userId, device.id)
        if (
          detail.data.fingerprints.some(
            (fingerprint) => fingerprint.status === 'trusted'
          )
        ) {
          return true
        }
      }
      return false
    },
    enabled:
      selectedDeviceMode === 'allowlist' && props.policy.fingerprint_ready,
  })
  const trustedDeviceUnavailable =
    selectedDeviceMode === 'allowlist' &&
    (!props.policy.fingerprint_ready || trustedDeviceQuery.data !== true)
  let trustedDeviceError: string | undefined
  if (selectedDeviceMode === 'allowlist' && props.policy.fingerprint_ready) {
    if (trustedDeviceQuery.isError) {
      trustedDeviceError = 'Failed to verify trusted devices'
    } else if (trustedDeviceQuery.isPending) {
      trustedDeviceError = 'Checking trusted devices'
    } else if (!trustedDeviceQuery.data) {
      trustedDeviceError =
        'At least one allowed device with a trusted fingerprint is required'
    }
  }

  return (
    <form
      className='flex min-h-0 flex-col gap-4'
      onSubmit={form.handleSubmit((values) =>
        mutation.mutate({
          values,
          dirtyFields,
        })
      )}
    >
      <FieldGroup>
        <Controller
          control={form.control}
          name='ip_mode'
          render={({ field }) => (
            <Field>
              <FieldTitle id='user-ip-policy-mode'>
                {t('IP policy mode')}
              </FieldTitle>
              <ToggleGroup
                aria-labelledby='user-ip-policy-mode'
                value={[field.value]}
                onValueChange={(values) =>
                  field.onChange(nextToggleValue(values, field.value))
                }
                variant='outline'
                spacing={2}
                className='grid w-full grid-cols-2'
              >
                {IP_MODES.map((mode) => (
                  <ToggleGroupItem key={mode.value} value={mode.value}>
                    {t(mode.label)}
                  </ToggleGroupItem>
                ))}
              </ToggleGroup>
              <FieldDescription>
                {t('Token IP restrictions can only narrow this policy.')}
              </FieldDescription>
            </Field>
          )}
        />

        <Controller
          control={form.control}
          name='ip_allowlist_text'
          render={({ field, fieldState }) => (
            <Field data-invalid={fieldState.invalid || undefined}>
              <FieldLabel htmlFor='user-ip-allowlist'>
                {t('Allowed IPs and CIDRs')}
              </FieldLabel>
              <Textarea
                {...field}
                id='user-ip-allowlist'
                rows={4}
                disabled={selectedIPMode !== 'allowlist'}
                aria-invalid={fieldState.invalid || undefined}
                placeholder={'203.0.113.10\n2001:db8::/32'}
              />
              <FieldDescription>
                {t('Enter one IPv4, IPv6, or CIDR per line. Maximum 64.')}
              </FieldDescription>
              <FieldError
                errors={
                  fieldState.error?.message
                    ? [{ message: t(fieldState.error.message) }]
                    : undefined
                }
              />
            </Field>
          )}
        />

        <Controller
          control={form.control}
          name='device_mode'
          render={({ field }) => (
            <Field>
              <FieldTitle id='user-device-policy-mode'>
                {t('Device policy mode')}
              </FieldTitle>
              <ToggleGroup
                aria-labelledby='user-device-policy-mode'
                value={[field.value]}
                onValueChange={(values) =>
                  field.onChange(nextToggleValue(values, field.value))
                }
                variant='outline'
                spacing={2}
                className='grid w-full grid-cols-2 sm:grid-cols-4'
              >
                {DEVICE_MODES.map((mode) => (
                  <ToggleGroupItem
                    key={mode.value}
                    value={mode.value}
                    disabled={
                      mode.value === 'allowlist' &&
                      !props.policy.fingerprint_ready
                    }
                  >
                    {t(mode.label)}
                  </ToggleGroupItem>
                ))}
              </ToggleGroup>
              <FieldError
                errors={
                  trustedDeviceError
                    ? [{ message: t(trustedDeviceError) }]
                    : undefined
                }
              />
            </Field>
          )}
        />
      </FieldGroup>

      {!props.policy.fingerprint_ready && (
        <Alert variant='destructive'>
          <AlertTitle>{t('Device fingerprinting unavailable')}</AlertTitle>
          <AlertDescription>
            {t('Configure the fingerprint secret before enabling allowlist.')}
          </AlertDescription>
        </Alert>
      )}

      <div className='flex flex-wrap items-center gap-2'>
        <Badge variant='outline'>
          {t('{{hours}} hour upgrade grace', {
            hours: props.policy.upgrade_grace_hours,
          })}
        </Badge>
        <Badge variant='outline'>
          {t('{{minutes}} minute active network window', {
            minutes: props.policy.active_network_window_minutes,
          })}
        </Badge>
        <Badge variant='secondary'>
          {t('Policy version {{version}}', {
            version: props.policy.access_policy_version,
          })}
        </Badge>
      </div>

      <div className='flex justify-end'>
        <Button
          type='submit'
          disabled={mutation.isPending || !isDirty || trustedDeviceUnavailable}
        >
          {mutation.isPending ? (
            <Spinner data-icon='inline-start' />
          ) : (
            <HugeiconsIcon icon={FloppyDiskIcon} data-icon='inline-start' />
          )}
          {t('Save policy')}
        </Button>
      </div>
    </form>
  )
}
