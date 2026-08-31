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
import { Delete02Icon, FloppyDiskIcon } from '@hugeicons/core-free-icons'
import { HugeiconsIcon } from '@hugeicons/react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import { MultiSelect } from '@/components/multi-select'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
  FieldTitle,
} from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Spinner } from '@/components/ui/spinner'
import { Switch } from '@/components/ui/switch'

import { getUserModels, updateUserDevice } from '../../api'
import { userAccessPolicyQueryKeys } from '../../lib/access-control-query-keys'
import {
  userDeviceBlockedModelsSchema,
  userDeviceUpdateSchema,
  type UserDevice,
  type UserDevicePolicyMode,
  type UserDeviceUpdate,
} from '../../types'

interface UserDeviceControlsFormProps {
  userId: number
  deviceId: number
  deviceMode: UserDevicePolicyMode
  device: Pick<UserDevice, 'rate_limit_rpm' | 'blocked_models'>
}

function sameModels(
  left: readonly string[],
  right: readonly string[]
): boolean {
  return (
    left.length === right.length &&
    left.every((model, index) => model === right[index])
  )
}

export function UserDeviceControlsForm(props: UserDeviceControlsFormProps) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [rateLimitEnabled, setRateLimitEnabled] = useState(
    props.device.rate_limit_rpm > 0
  )
  const [rateLimitRPM, setRateLimitRPM] = useState(
    props.device.rate_limit_rpm > 0 ? props.device.rate_limit_rpm : 60
  )
  const [blockedModels, setBlockedModels] = useState(
    props.device.blocked_models
  )
  const controlsDisabled = props.deviceMode === 'off'
  const hasActiveControls =
    props.device.rate_limit_rpm > 0 || props.device.blocked_models.length > 0
  const effectiveRPM = rateLimitEnabled ? rateLimitRPM : 0
  const blockedModelsResult =
    userDeviceBlockedModelsSchema.safeParse(blockedModels)
  const normalizedBlockedModels = blockedModelsResult.success
    ? blockedModelsResult.data
    : blockedModels
  const rateLimitInvalid =
    rateLimitEnabled &&
    (!Number.isInteger(rateLimitRPM) ||
      rateLimitRPM < 1 ||
      rateLimitRPM > 60_000)
  const controlsChanged =
    effectiveRPM !== props.device.rate_limit_rpm ||
    !sameModels(normalizedBlockedModels, props.device.blocked_models)
  const detailKey = userAccessPolicyQueryKeys.device(
    props.userId,
    props.deviceId
  )
  const modelsQuery = useQuery({
    queryKey: userAccessPolicyQueryKeys.models(props.userId),
    queryFn: () => getUserModels(props.userId),
    enabled: !controlsDisabled,
  })
  const modelOptions = useMemo(() => {
    const models = new Set(modelsQuery.data?.data ?? [])
    for (const model of blockedModels) models.add(model)
    return [...models].sort().map((model) => ({ label: model, value: model }))
  }, [blockedModels, modelsQuery.data?.data])
  const mutation = useMutation({
    mutationFn: (payload: UserDeviceUpdate) =>
      updateUserDevice(props.userId, props.deviceId, payload),
    onSuccess: async (response) => {
      queryClient.setQueryData(detailKey, response)
      setRateLimitEnabled(response.data.device.rate_limit_rpm > 0)
      setRateLimitRPM(
        response.data.device.rate_limit_rpm > 0
          ? response.data.device.rate_limit_rpm
          : 60
      )
      setBlockedModels(response.data.device.blocked_models)
      await Promise.all([
        queryClient.invalidateQueries({
          queryKey: userAccessPolicyQueryKeys.deviceLists(props.userId),
        }),
        queryClient.invalidateQueries({
          queryKey: userAccessPolicyQueryKeys.policy(props.userId),
        }),
      ])
      toast.success(t('Device controls updated'))
    },
    onError: () => toast.error(t('Failed to update device controls')),
  })

  const saveControls = () => {
    const result = userDeviceUpdateSchema.safeParse({
      rate_limit_rpm: effectiveRPM,
      blocked_models: normalizedBlockedModels,
    })
    if (!result.success) return
    mutation.mutate(result.data)
  }

  const clearControls = () => {
    mutation.mutate({ rate_limit_rpm: 0, blocked_models: [] })
  }

  return (
    <section
      className='flex flex-col gap-3'
      aria-labelledby='device-controls-title'
    >
      <h3 id='device-controls-title' className='text-sm font-medium'>
        {t('Device controls')}
      </h3>

      {controlsDisabled && (
        <Alert>
          <AlertTitle>{t('Device controls are unavailable')}</AlertTitle>
          <AlertDescription>
            {t(
              'Enable Observe or a stricter device mode before configuring controls.'
            )}
          </AlertDescription>
          {hasActiveControls && (
            <div className='mt-3 flex justify-end'>
              <Button
                type='button'
                variant='outline'
                size='sm'
                disabled={mutation.isPending}
                onClick={clearControls}
              >
                {mutation.isPending ? (
                  <Spinner data-icon='inline-start' />
                ) : (
                  <HugeiconsIcon icon={Delete02Icon} data-icon='inline-start' />
                )}
                {t('Clear device controls')}
              </Button>
            </div>
          )}
        </Alert>
      )}

      <FieldGroup>
        <Field
          orientation='horizontal'
          data-disabled={controlsDisabled || undefined}
        >
          <FieldContent>
            <FieldTitle id='device-rate-limit-title'>
              {t('Enable rate limiting')}
            </FieldTitle>
            <FieldDescription>
              {t('Limit this logical device by requests per minute.')}
            </FieldDescription>
          </FieldContent>
          <Switch
            aria-labelledby='device-rate-limit-title'
            checked={rateLimitEnabled}
            disabled={controlsDisabled || mutation.isPending}
            onCheckedChange={(checked) => {
              setRateLimitEnabled(checked)
              if (checked && rateLimitRPM < 1) setRateLimitRPM(60)
            }}
          />
        </Field>

        <Field
          data-disabled={
            controlsDisabled ||
            !rateLimitEnabled ||
            mutation.isPending ||
            undefined
          }
          data-invalid={rateLimitInvalid || undefined}
        >
          <FieldLabel htmlFor='device-rate-limit-rpm'>
            {t('Requests per minute')}
          </FieldLabel>
          <Input
            id='device-rate-limit-rpm'
            type='number'
            min={1}
            max={60_000}
            step={1}
            value={rateLimitRPM}
            disabled={
              controlsDisabled || !rateLimitEnabled || mutation.isPending
            }
            aria-invalid={rateLimitInvalid || undefined}
            onChange={(event) => {
              const value = event.currentTarget.valueAsNumber
              setRateLimitRPM(Number.isNaN(value) ? 0 : value)
            }}
          />
          {rateLimitInvalid && (
            <FieldError>
              {t('RPM must be a whole number between 1 and 60000.')}
            </FieldError>
          )}
        </Field>

        <Field
          data-disabled={controlsDisabled || mutation.isPending || undefined}
          data-invalid={!blockedModelsResult.success || undefined}
        >
          <FieldLabel htmlFor='device-blocked-models'>
            {t('Blocked models')}
          </FieldLabel>
          <MultiSelect
            id='device-blocked-models'
            options={modelOptions}
            selected={blockedModels}
            onChange={setBlockedModels}
            placeholder={t('Blocked models')}
            emptyText={t('No models found')}
            allowCreate
            disabled={controlsDisabled || mutation.isPending}
            maxVisibleChips={6}
          />
          <FieldDescription>
            {t(
              'Model IDs are matched exactly. Add aliases as separate entries.'
            )}
          </FieldDescription>
          {!blockedModelsResult.success && (
            <FieldError>
              {t('Use no more than 128 model IDs, each at most 128 bytes.')}
            </FieldError>
          )}
        </Field>
      </FieldGroup>

      <div className='flex justify-end'>
        <Button
          type='button'
          disabled={
            controlsDisabled ||
            mutation.isPending ||
            rateLimitInvalid ||
            !blockedModelsResult.success ||
            !controlsChanged
          }
          onClick={saveControls}
        >
          {mutation.isPending ? (
            <Spinner data-icon='inline-start' />
          ) : (
            <HugeiconsIcon icon={FloppyDiskIcon} data-icon='inline-start' />
          )}
          {t('Save device controls')}
        </Button>
      </div>
    </section>
  )
}
