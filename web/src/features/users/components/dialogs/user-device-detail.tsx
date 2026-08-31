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
import {
  ArrowLeft01Icon,
  BlockedIcon,
  CheckmarkCircle02Icon,
  FloppyDiskIcon,
} from '@hugeicons/core-free-icons'
import { HugeiconsIcon } from '@hugeicons/react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Field,
  FieldGroup,
  FieldLabel,
  FieldTitle,
} from '@/components/ui/field'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Textarea } from '@/components/ui/textarea'
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group'
import { formatTimestampToDate } from '@/lib/format'

import {
  getUserDevice,
  updateUserDevice,
  updateUserDeviceFingerprint,
} from '../../api'
import { userAccessPolicyQueryKeys } from '../../lib/access-control-query-keys'
import type {
  UserDeviceDetail,
  UserDeviceFingerprintUpdateStatus,
  UserDevicePolicyMode,
  UserDeviceStatus,
  UserDeviceUpdate,
} from '../../types'
import { UserDeviceControlsForm } from './user-device-controls-form'

const DEVICE_STATUSES: ReadonlyArray<UserDeviceStatus> = [
  'pending',
  'allowed',
  'blocked',
]

interface UserDeviceDetailPanelProps {
  userId: number
  deviceId: number
  deviceMode: UserDevicePolicyMode
  onBack: () => void
}

interface LoadedDeviceDetailProps extends UserDeviceDetailPanelProps {
  detail: UserDeviceDetail
}

interface DetailItemProps {
  label: string
  children: ReactNode
  mono?: boolean
}

interface EvidenceStateProps {
  value: boolean | null
}

function DetailItem(props: DetailItemProps) {
  return (
    <div className='min-w-0'>
      <dt className='text-muted-foreground text-xs'>{props.label}</dt>
      <dd
        className={props.mono ? 'font-mono text-xs break-all' : 'break-words'}
      >
        {props.children}
      </dd>
    </div>
  )
}

function EvidenceState(props: EvidenceStateProps) {
  const { t } = useTranslation()
  let label = t('Unknown')
  if (props.value === true) label = t('Present')
  if (props.value === false) label = t('Missing')
  return <Badge variant='outline'>{label}</Badge>
}

function optionalTimestamp(value: number): string {
  return value > 0 ? formatTimestampToDate(value) : '-'
}

function nextDeviceStatus(
  values: readonly string[],
  current: UserDeviceStatus
): UserDeviceStatus {
  const next = values.find((value) => value !== current)
  return (next ?? current) as UserDeviceStatus
}

function LoadedDeviceDetail(props: LoadedDeviceDetailProps) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [status, setStatus] = useState<UserDeviceStatus>(
    props.detail.device.status
  )
  const [remark, setRemark] = useState(props.detail.device.remark)
  const [pendingDeviceUpdate, setPendingDeviceUpdate] =
    useState<UserDeviceUpdate | null>(null)
  const [pendingFingerprintUpdate, setPendingFingerprintUpdate] = useState<{
    fingerprintId: number
    shortId: string
    status: UserDeviceFingerprintUpdateStatus
  } | null>(null)
  const detailKey = userAccessPolicyQueryKeys.device(
    props.userId,
    props.deviceId
  )
  const deviceMutation = useMutation({
    mutationFn: (payload: UserDeviceUpdate) =>
      updateUserDevice(props.userId, props.deviceId, payload),
    onSuccess: (response, payload) => {
      queryClient.setQueryData(detailKey, response)
      setStatus(response.data.device.status)
      setRemark(response.data.device.remark)
      setPendingDeviceUpdate(null)
      queryClient.invalidateQueries({
        queryKey: userAccessPolicyQueryKeys.deviceLists(props.userId),
      })
      if (payload.status) {
        queryClient.invalidateQueries({
          queryKey: userAccessPolicyQueryKeys.policy(props.userId),
        })
        queryClient.invalidateQueries({
          queryKey: userAccessPolicyQueryKeys.trustedDevicePrerequisite(
            props.userId
          ),
        })
      }
      toast.success(t('Device updated'))
    },
    onError: () => toast.error(t('Failed to update device')),
  })
  const fingerprintMutation = useMutation({
    mutationFn: (input: {
      fingerprintId: number
      status: UserDeviceFingerprintUpdateStatus
    }) =>
      updateUserDeviceFingerprint(
        props.userId,
        props.deviceId,
        input.fingerprintId,
        { status: input.status }
      ),
    onSuccess: (response) => {
      queryClient.setQueryData(detailKey, response)
      setPendingFingerprintUpdate(null)
      queryClient.invalidateQueries({
        queryKey: userAccessPolicyQueryKeys.deviceLists(props.userId),
      })
      queryClient.invalidateQueries({
        queryKey: userAccessPolicyQueryKeys.policy(props.userId),
      })
      queryClient.invalidateQueries({
        queryKey: userAccessPolicyQueryKeys.trustedDevicePrerequisite(
          props.userId
        ),
      })
      toast.success(t('Fingerprint updated'))
    },
    onError: () => toast.error(t('Failed to update fingerprint')),
  })
  const statusChanged = status !== props.detail.device.status
  const remarkChanged = remark !== props.detail.device.remark

  const saveDevice = () => {
    const payload: UserDeviceUpdate = {}
    if (statusChanged) payload.status = status
    if (remarkChanged) payload.remark = remark
    if (statusChanged) {
      setPendingDeviceUpdate(payload)
      return
    }
    deviceMutation.mutate(payload)
  }

  return (
    <div className='flex flex-col gap-4'>
      <div className='flex items-center justify-between gap-2'>
        <Button type='button' variant='ghost' size='sm' onClick={props.onBack}>
          <HugeiconsIcon icon={ArrowLeft01Icon} data-icon='inline-start' />
          {t('Devices')}
        </Button>
        <Badge variant='outline'>#{props.deviceId}</Badge>
      </div>

      {props.detail.device.confidence === 'low' && (
        <Alert>
          <AlertTitle>{t('Low-confidence device profile')}</AlertTitle>
          <AlertDescription>
            {t(
              'Header evidence is limited, so another client may share this profile.'
            )}
          </AlertDescription>
        </Alert>
      )}

      <section
        className='flex flex-col gap-2'
        aria-labelledby='device-information-title'
      >
        <h3 id='device-information-title' className='text-sm font-medium'>
          {t('Device information')}
        </h3>
        <dl className='grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-3 lg:grid-cols-4'>
          <DetailItem label={t('Client')}>
            {props.detail.device.client_family || '-'}
          </DetailItem>
          <DetailItem label={t('Originator')}>
            {props.detail.device.originator || '-'}
          </DetailItem>
          <DetailItem label={t('Client version')}>
            {props.detail.device.last_client_version || '-'}
          </DetailItem>
          <DetailItem label={t('Operating system')}>
            {props.detail.device.os_family || '-'}
          </DetailItem>
          <DetailItem label={t('Architecture')}>
            {props.detail.device.architecture || '-'}
          </DetailItem>
          <DetailItem label={t('Confidence')}>
            <Badge variant='outline'>{t(props.detail.device.confidence)}</Badge>
          </DetailItem>
          <DetailItem label={t('First IP')} mono>
            {props.detail.device.first_ip || '-'}
          </DetailItem>
          <DetailItem label={t('Last IP')} mono>
            {props.detail.device.last_ip || '-'}
          </DetailItem>
          <DetailItem label={t('IP count')}>
            {props.detail.device.observed_ip_count}
          </DetailItem>
          <DetailItem label={t('First seen')}>
            {optionalTimestamp(props.detail.device.first_seen_at)}
          </DetailItem>
          <DetailItem label={t('Last seen')}>
            {optionalTimestamp(props.detail.device.last_seen_at)}
          </DetailItem>
          <DetailItem label={t('Requests')}>
            {props.detail.device.request_count}
          </DetailItem>
          <DetailItem label={t('Denied requests')}>
            {props.detail.device.denied_count}
          </DetailItem>
          <DetailItem label={t('Fingerprint count')}>
            {props.detail.fingerprints.length}
          </DetailItem>
          <DetailItem label={t('Created at')}>
            {optionalTimestamp(props.detail.device.created_at)}
          </DetailItem>
          <DetailItem label={t('Updated at')}>
            {optionalTimestamp(props.detail.device.updated_at)}
          </DetailItem>
        </dl>
      </section>

      <UserDeviceControlsForm
        userId={props.userId}
        deviceId={props.deviceId}
        deviceMode={props.deviceMode}
        device={props.detail.device}
      />

      <FieldGroup>
        <Field>
          <FieldTitle id='device-review-status'>
            {t('Device status')}
          </FieldTitle>
          <ToggleGroup
            aria-labelledby='device-review-status'
            value={[status]}
            onValueChange={(values) =>
              setStatus(nextDeviceStatus(values, status))
            }
            variant='outline'
            spacing={2}
            className='grid w-full grid-cols-3'
          >
            {DEVICE_STATUSES.map((value) => (
              <ToggleGroupItem key={value} value={value}>
                {t(value)}
              </ToggleGroupItem>
            ))}
          </ToggleGroup>
        </Field>
        <Field>
          <FieldLabel htmlFor='device-admin-remark'>
            {t('Administrator remark')}
          </FieldLabel>
          <Textarea
            id='device-admin-remark'
            value={remark}
            maxLength={255}
            rows={2}
            onChange={(event) => setRemark(event.target.value)}
          />
        </Field>
      </FieldGroup>

      <div className='flex justify-end'>
        <Button
          type='button'
          disabled={
            deviceMutation.isPending || (!statusChanged && !remarkChanged)
          }
          onClick={saveDevice}
        >
          {deviceMutation.isPending ? (
            <Spinner data-icon='inline-start' />
          ) : (
            <HugeiconsIcon icon={FloppyDiskIcon} data-icon='inline-start' />
          )}
          {t('Save device')}
        </Button>
      </div>

      <section
        className='flex flex-col gap-2'
        aria-labelledby='fingerprints-title'
      >
        <h3 id='fingerprints-title' className='text-sm font-medium'>
          {t('Fingerprint aliases')}
        </h3>
        <div className='divide-y rounded-md border'>
          {props.detail.fingerprints.map((fingerprint) => (
            <div
              key={fingerprint.id}
              role='group'
              aria-label={t('Fingerprint {{shortId}}', {
                shortId: fingerprint.short_id,
              })}
              className='flex flex-col gap-3 p-3'
            >
              <div className='flex flex-wrap items-center justify-between gap-2'>
                <div className='flex items-center gap-2'>
                  <span className='font-mono text-xs'>
                    {fingerprint.short_id}
                  </span>
                  <Badge variant='outline'>{t(fingerprint.status)}</Badge>
                </div>
                <div className='flex flex-wrap justify-end gap-1'>
                  {fingerprint.status !== 'trusted' && (
                    <Button
                      type='button'
                      variant='outline'
                      size='sm'
                      disabled={fingerprintMutation.isPending}
                      aria-label={t('Trust fingerprint {{shortId}}', {
                        shortId: fingerprint.short_id,
                      })}
                      onClick={() =>
                        setPendingFingerprintUpdate({
                          fingerprintId: fingerprint.id,
                          shortId: fingerprint.short_id,
                          status: 'trusted',
                        })
                      }
                    >
                      <HugeiconsIcon
                        icon={CheckmarkCircle02Icon}
                        data-icon='inline-start'
                      />
                      {t('Trust')}
                    </Button>
                  )}
                  {fingerprint.status !== 'blocked' && (
                    <Button
                      type='button'
                      variant='destructive'
                      size='sm'
                      disabled={fingerprintMutation.isPending}
                      aria-label={t('Block fingerprint {{shortId}}', {
                        shortId: fingerprint.short_id,
                      })}
                      onClick={() =>
                        setPendingFingerprintUpdate({
                          fingerprintId: fingerprint.id,
                          shortId: fingerprint.short_id,
                          status: 'blocked',
                        })
                      }
                    >
                      <HugeiconsIcon
                        icon={BlockedIcon}
                        data-icon='inline-start'
                      />
                      {t('Block')}
                    </Button>
                  )}
                </div>
              </div>
              <dl className='grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-3 lg:grid-cols-4'>
                <DetailItem label={t('Client version')}>
                  {fingerprint.client_version || '-'}
                </DetailItem>
                <DetailItem label={t('Runtime')}>
                  {fingerprint.runtime_family === null
                    ? t('Unknown')
                    : fingerprint.runtime_family || t('Missing')}
                </DetailItem>
                <DetailItem label={t('First seen')}>
                  {optionalTimestamp(fingerprint.first_seen_at)}
                </DetailItem>
                <DetailItem label={t('Last seen')}>
                  {optionalTimestamp(fingerprint.last_seen_at)}
                </DetailItem>
                <DetailItem label={t('Requests')}>
                  {fingerprint.request_count}
                </DetailItem>
                <DetailItem label={t('Created at')}>
                  {optionalTimestamp(fingerprint.created_at)}
                </DetailItem>
                <DetailItem label={t('Updated at')}>
                  {optionalTimestamp(fingerprint.updated_at)}
                </DetailItem>
                <DetailItem label={t('Upgrade grace until')}>
                  {optionalTimestamp(fingerprint.grace_until)}
                </DetailItem>
                <DetailItem label={t('Installation ID')}>
                  <EvidenceState value={fingerprint.installation_id_present} />
                </DetailItem>
                <DetailItem label={t('Window ID')}>
                  <EvidenceState value={fingerprint.window_id_present} />
                </DetailItem>
                <DetailItem label={t('User-Agent')}>
                  <EvidenceState value={fingerprint.user_agent_present} />
                </DetailItem>
                <DetailItem label={t('JA4')}>
                  <EvidenceState value={fingerprint.ja4_present} />
                </DetailItem>
                <DetailItem label={t('HTTP/2')}>
                  <EvidenceState value={fingerprint.http2_present} />
                </DetailItem>
              </dl>
            </div>
          ))}
        </div>
      </section>

      <section
        className='flex flex-col gap-2'
        aria-labelledby='recent-ips-title'
      >
        <h3 id='recent-ips-title' className='text-sm font-medium'>
          {t('Recent IPs')}
        </h3>
        <div className='overflow-x-auto'>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('IP address')}</TableHead>
                <TableHead>{t('First seen')}</TableHead>
                <TableHead>{t('Last seen')}</TableHead>
                <TableHead className='text-right'>{t('Requests')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {props.detail.recent_ips.map((recentIP) => (
                <TableRow key={recentIP.id}>
                  <TableCell className='font-mono text-xs'>
                    {recentIP.ip}
                  </TableCell>
                  <TableCell>
                    {optionalTimestamp(recentIP.first_seen_at)}
                  </TableCell>
                  <TableCell>
                    {formatTimestampToDate(recentIP.last_seen_at)}
                  </TableCell>
                  <TableCell className='text-right'>
                    {recentIP.request_count}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </section>

      <ConfirmDialog
        open={pendingDeviceUpdate !== null}
        onOpenChange={(open) => {
          if (!open && !deviceMutation.isPending) setPendingDeviceUpdate(null)
        }}
        title={t('Change device status')}
        desc={t('Change device {{id}} status to {{status}}?', {
          id: props.deviceId,
          status: t(status),
        })}
        confirmText={t('Confirm status change')}
        destructive={status === 'blocked'}
        isLoading={deviceMutation.isPending}
        handleConfirm={() => {
          if (pendingDeviceUpdate) deviceMutation.mutate(pendingDeviceUpdate)
        }}
      />

      <ConfirmDialog
        open={pendingFingerprintUpdate !== null}
        onOpenChange={(open) => {
          if (!open && !fingerprintMutation.isPending) {
            setPendingFingerprintUpdate(null)
          }
        }}
        title={
          pendingFingerprintUpdate?.status === 'trusted'
            ? t('Trust fingerprint')
            : t('Block fingerprint')
        }
        desc={t('Confirm {{action}} for fingerprint {{shortId}}?', {
          action: t(
            pendingFingerprintUpdate?.status === 'trusted' ? 'trust' : 'block'
          ),
          shortId: pendingFingerprintUpdate?.shortId ?? '',
        })}
        confirmText={
          pendingFingerprintUpdate?.status === 'trusted'
            ? t('Trust fingerprint')
            : t('Block fingerprint')
        }
        destructive={pendingFingerprintUpdate?.status === 'blocked'}
        isLoading={fingerprintMutation.isPending}
        handleConfirm={() => {
          if (pendingFingerprintUpdate) {
            fingerprintMutation.mutate(pendingFingerprintUpdate)
          }
        }}
      />
    </div>
  )
}

export function UserDeviceDetailPanel(props: UserDeviceDetailPanelProps) {
  const { t } = useTranslation()
  const detailQuery = useQuery({
    queryKey: userAccessPolicyQueryKeys.device(props.userId, props.deviceId),
    queryFn: () => getUserDevice(props.userId, props.deviceId),
  })

  if (detailQuery.isLoading) {
    return (
      <Skeleton
        className='h-72 w-full'
        aria-label={t('Loading device details')}
      />
    )
  }
  if (detailQuery.isError || !detailQuery.data?.data) {
    return (
      <Alert variant='destructive'>
        <AlertTitle>{t('Failed to load device details')}</AlertTitle>
        <AlertDescription>
          {t('Return to the device list and try again.')}
        </AlertDescription>
      </Alert>
    )
  }

  return <LoadedDeviceDetail {...props} detail={detailQuery.data.data} />
}
