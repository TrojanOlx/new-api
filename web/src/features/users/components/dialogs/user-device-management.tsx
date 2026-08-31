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
  BlockedIcon,
  CheckmarkCircle02Icon,
  ViewIcon,
} from '@hugeicons/core-free-icons'
import { HugeiconsIcon } from '@hugeicons/react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { DataTableRowActionMenu } from '@/components/data-table/core/row-action-menu'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
} from '@/components/ui/dropdown-menu'
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyTitle,
} from '@/components/ui/empty'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { formatTimestampToDate } from '@/lib/format'

import { getUserDevices, updateUserDevice } from '../../api'
import { userAccessPolicyQueryKeys } from '../../lib/access-control-query-keys'
import type { GetUserDevicesParams, UserDevicePolicyMode } from '../../types'
import { UserDeviceDetailPanel } from './user-device-detail'

const DEVICE_PAGE_SIZE = 20
const DEVICE_STATUS_FILTERS = ['all', 'pending', 'allowed', 'blocked'] as const

type DeviceStatusFilter = (typeof DEVICE_STATUS_FILTERS)[number]
type DeviceStatusAction = Exclude<DeviceStatusFilter, 'all' | 'pending'>

interface PendingDeviceAction {
  deviceId: number
  status: DeviceStatusAction
}

interface UserDeviceManagementProps {
  userId: number
  deviceMode: UserDevicePolicyMode
}

export function UserDeviceManagement(props: UserDeviceManagementProps) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [page, setPage] = useState(1)
  const [statusFilter, setStatusFilter] = useState<DeviceStatusFilter>('all')
  const [selectedDeviceId, setSelectedDeviceId] = useState<number | null>(null)
  const [pendingAction, setPendingAction] =
    useState<PendingDeviceAction | null>(null)
  const params = useMemo<GetUserDevicesParams>(() => {
    const nextParams: GetUserDevicesParams = {
      p: page,
      page_size: DEVICE_PAGE_SIZE,
    }
    if (statusFilter !== 'all') {
      nextParams.status = statusFilter
    }
    return nextParams
  }, [page, statusFilter])

  const deviceMutation = useMutation({
    mutationFn: (action: PendingDeviceAction) =>
      updateUserDevice(props.userId, action.deviceId, {
        status: action.status,
      }),
    onSuccess: async (_response, action) => {
      await Promise.all([
        queryClient.invalidateQueries({
          queryKey: userAccessPolicyQueryKeys.deviceLists(props.userId),
        }),
        queryClient.invalidateQueries({
          queryKey: userAccessPolicyQueryKeys.device(
            props.userId,
            action.deviceId
          ),
        }),
        queryClient.invalidateQueries({
          queryKey: userAccessPolicyQueryKeys.policy(props.userId),
        }),
        queryClient.invalidateQueries({
          queryKey: userAccessPolicyQueryKeys.trustedDevicePrerequisite(
            props.userId
          ),
        }),
      ])
      setPendingAction(null)
      toast.success(
        t(action.status === 'allowed' ? 'Device allowed' : 'Device blocked')
      )
    },
    onError: () => {
      toast.error(t('Failed to update device'))
    },
  })
  const devicesQuery = useQuery({
    queryKey: userAccessPolicyQueryKeys.devices(props.userId, params),
    queryFn: () => getUserDevices(props.userId, params),
    placeholderData: (previousData) => previousData,
  })

  if (selectedDeviceId !== null) {
    return (
      <UserDeviceDetailPanel
        userId={props.userId}
        deviceId={selectedDeviceId}
        deviceMode={props.deviceMode}
        onBack={() => setSelectedDeviceId(null)}
      />
    )
  }

  const data = devicesQuery.data?.data
  const devices = data?.items ?? []
  const hasLowConfidence = devices.some((item) => item.confidence === 'low')
  const pageSize = data?.page_size ?? DEVICE_PAGE_SIZE
  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / pageSize))

  return (
    <div className='flex flex-col gap-3'>
      <Tabs
        value={statusFilter}
        onValueChange={(value) => {
          if (!DEVICE_STATUS_FILTERS.includes(value as DeviceStatusFilter)) {
            return
          }
          setStatusFilter(value as DeviceStatusFilter)
          setPage(1)
        }}
      >
        <TabsList className='max-w-full flex-wrap justify-start group-data-horizontal/tabs:h-auto'>
          <TabsTrigger value='all'>{t('All')}</TabsTrigger>
          <TabsTrigger value='pending'>{t('Pending')}</TabsTrigger>
          <TabsTrigger value='allowed'>{t('Allowed')}</TabsTrigger>
          <TabsTrigger value='blocked'>{t('Blocked')}</TabsTrigger>
        </TabsList>
      </Tabs>

      {devicesQuery.isLoading && (
        <div className='flex flex-col gap-3' aria-label={t('Loading devices')}>
          <Skeleton className='h-9 w-full' />
          <Skeleton className='h-36 w-full' />
        </div>
      )}

      {devicesQuery.isError && (
        <Alert variant='destructive'>
          <AlertTitle>{t('Failed to load devices')}</AlertTitle>
          <AlertDescription>
            {t('Close the dialog and try again.')}
          </AlertDescription>
        </Alert>
      )}

      {!devicesQuery.isLoading &&
        !devicesQuery.isError &&
        devices.length === 0 && (
          <Empty>
            <EmptyHeader>
              <EmptyTitle>{t('No device profiles')}</EmptyTitle>
              <EmptyDescription>
                {t('Profiles appear after this user sends API requests.')}
              </EmptyDescription>
            </EmptyHeader>
          </Empty>
        )}

      {hasLowConfidence && (
        <Alert>
          <AlertTitle>
            {t('Low-confidence device profiles may collide')}
          </AlertTitle>
          <AlertDescription>
            {t('Review client details before allowing these profiles.')}
          </AlertDescription>
        </Alert>
      )}

      {devices.length > 0 && !devicesQuery.isError && (
        <>
          <div aria-label={t('Device table')} className='overflow-x-auto'>
            <Table className='min-w-[920px] table-fixed'>
              <colgroup>
                <col className='w-16' />
                <col className='w-36' />
                <col className='w-28' />
                <col className='w-24' />
                <col className='w-36' />
                <col className='w-20' />
                <col className='w-28' />
                <col className='w-36' />
                <col className='w-16' />
              </colgroup>
              <TableHeader>
                <TableRow>
                  <TableHead>{t('Device ID')}</TableHead>
                  <TableHead>{t('Client')}</TableHead>
                  <TableHead>{t('OS/Architecture')}</TableHead>
                  <TableHead>
                    <div className='flex flex-col gap-0.5'>
                      <span>{t('Confidence')}</span>
                      <span className='text-muted-foreground text-xs'>
                        {t('Status')}
                      </span>
                    </div>
                  </TableHead>
                  <TableHead>{t('RPM')}</TableHead>
                  <TableHead>{t('Blocked models')}</TableHead>
                  <TableHead>
                    <div className='flex flex-col gap-0.5'>
                      <span>{t('Last IP')}</span>
                      <span className='text-muted-foreground text-xs'>
                        {t('IP count')}
                      </span>
                    </div>
                  </TableHead>
                  <TableHead>
                    <div className='flex flex-col gap-0.5'>
                      <span>{t('Requests')}</span>
                      <span className='text-muted-foreground text-xs'>
                        {t('Last seen')}
                      </span>
                    </div>
                  </TableHead>
                  <TableHead className='text-right'>{t('Actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {devices.map((item) => (
                  <TableRow key={item.id}>
                    <TableCell className='font-mono text-xs'>
                      #{item.id}
                    </TableCell>
                    <TableCell>
                      <div className='flex flex-col gap-0.5'>
                        <span className='font-medium'>
                          {item.client_family || t('Unknown client')}
                        </span>
                        <span className='text-muted-foreground text-xs'>
                          {item.originator || '-'}
                        </span>
                        <span className='text-muted-foreground text-xs'>
                          {t('Client version')}:{' '}
                          {item.last_client_version || '-'}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      {[item.os_family, item.architecture]
                        .filter(Boolean)
                        .join(' / ') || '-'}
                    </TableCell>
                    <TableCell>
                      <div className='flex flex-col items-start gap-1'>
                        <Badge
                          variant={
                            item.confidence === 'low' ? 'warning' : 'secondary'
                          }
                        >
                          {t(item.confidence)}
                        </Badge>
                        <Badge
                          variant={
                            item.status === 'blocked'
                              ? 'destructive'
                              : 'outline'
                          }
                        >
                          {t(item.status)}
                        </Badge>
                      </div>
                    </TableCell>
                    <TableCell>{item.rate_limit_rpm}</TableCell>
                    <TableCell>{item.blocked_model_count}</TableCell>
                    <TableCell>
                      <div className='flex flex-col gap-0.5'>
                        <span className='font-mono text-xs'>
                          {item.last_ip || '-'}
                        </span>
                        <span className='text-muted-foreground text-xs'>
                          {t('IP count')}: {item.observed_ip_count}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className='flex flex-col gap-0.5'>
                        <span>
                          {t('Requests')}: {item.request_count}
                        </span>
                        <span className='text-muted-foreground text-xs'>
                          {formatTimestampToDate(item.last_seen_at)}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className='text-right'>
                      <DataTableRowActionMenu
                        ariaLabel={t('Actions for device {{id}}', {
                          id: item.id,
                        })}
                        contentClassName='w-40'
                      >
                        <DropdownMenuItem
                          onClick={() => setSelectedDeviceId(item.id)}
                        >
                          {t('View')}
                          <DropdownMenuShortcut>
                            <HugeiconsIcon icon={ViewIcon} size={16} />
                          </DropdownMenuShortcut>
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          disabled={
                            item.status === 'allowed' ||
                            deviceMutation.isPending
                          }
                          onSelect={(event) => {
                            event.preventDefault()
                            setPendingAction({
                              deviceId: item.id,
                              status: 'allowed',
                            })
                          }}
                        >
                          {t('Allow')}
                          <DropdownMenuShortcut>
                            <HugeiconsIcon
                              icon={CheckmarkCircle02Icon}
                              size={16}
                            />
                          </DropdownMenuShortcut>
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          variant='destructive'
                          disabled={
                            item.status === 'blocked' ||
                            deviceMutation.isPending
                          }
                          onSelect={(event) => {
                            event.preventDefault()
                            setPendingAction({
                              deviceId: item.id,
                              status: 'blocked',
                            })
                          }}
                        >
                          {t('Block')}
                          <DropdownMenuShortcut>
                            <HugeiconsIcon icon={BlockedIcon} size={16} />
                          </DropdownMenuShortcut>
                        </DropdownMenuItem>
                      </DataTableRowActionMenu>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          <div className='flex items-center justify-between gap-2'>
            <span className='text-muted-foreground text-sm'>
              {t('Page {{page}} of {{total}}', { page, total: totalPages })}
            </span>
            <div className='flex gap-2'>
              <Button
                type='button'
                variant='outline'
                size='sm'
                disabled={page <= 1 || devicesQuery.isFetching}
                onClick={() => setPage((current) => Math.max(1, current - 1))}
              >
                {t('Previous')}
              </Button>
              <Button
                type='button'
                variant='outline'
                size='sm'
                disabled={page >= totalPages || devicesQuery.isFetching}
                onClick={() => setPage((current) => current + 1)}
              >
                {t('Next')}
              </Button>
            </div>
          </div>
        </>
      )}

      {pendingAction && (
        <ConfirmDialog
          open
          onOpenChange={(open) => {
            if (!open && !deviceMutation.isPending) {
              setPendingAction(null)
            }
          }}
          title={
            pendingAction.status === 'allowed'
              ? t('Allow device')
              : t('Block device')
          }
          desc={t(
            pendingAction.status === 'allowed'
              ? 'Allow device #{{id}}? Requests matching this profile will be accepted.'
              : 'Block device #{{id}}? Requests matching this profile will be denied.',
            { id: pendingAction.deviceId }
          )}
          confirmText={
            pendingAction.status === 'allowed'
              ? t('Allow device')
              : t('Block device')
          }
          destructive={pendingAction.status === 'blocked'}
          isLoading={deviceMutation.isPending}
          handleConfirm={() => deviceMutation.mutate(pendingAction)}
        />
      )}
    </div>
  )
}
