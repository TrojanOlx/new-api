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
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'

import { getUserAccessPolicy } from '../../api'
import { userAccessPolicyQueryKeys } from '../../lib/access-control-query-keys'
import type { User } from '../../types'
import { UserAccessPolicyForm } from './user-access-policy-form'
import { UserDeviceManagement } from './user-device-management'

interface UserAccessControlDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  user: Pick<User, 'id' | 'username'> | null
}

export function UserAccessControlDialog(props: UserAccessControlDialogProps) {
  const { t } = useTranslation()
  const userId = props.user?.id ?? 0
  const policyQuery = useQuery({
    queryKey: userAccessPolicyQueryKeys.policy(userId),
    queryFn: () => getUserAccessPolicy(userId),
    enabled: props.open && userId > 0,
  })

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent className='max-h-[calc(100dvh-2rem)] grid-cols-[minmax(0,1fr)] overflow-hidden sm:max-w-5xl'>
        <DialogHeader>
          <DialogTitle>
            {t('Access control for {{username}}', {
              username: props.user?.username ?? '',
            })}
          </DialogTitle>
          <DialogDescription>
            {t('Manage IP rules and privacy-preserving device profiles.')}
          </DialogDescription>
        </DialogHeader>

        <Tabs defaultValue='policy' className='min-h-0'>
          <TabsList>
            <TabsTrigger value='policy'>{t('Policy')}</TabsTrigger>
            <TabsTrigger value='devices'>{t('Devices')}</TabsTrigger>
          </TabsList>
          <TabsContent
            value='policy'
            className='max-h-[calc(100dvh-12rem)] min-w-0 overflow-y-auto pr-1'
          >
            {policyQuery.isLoading && (
              <div
                className='flex flex-col gap-3'
                aria-label={t('Loading policy')}
              >
                <Skeleton className='h-20 w-full' />
                <Skeleton className='h-28 w-full' />
                <Skeleton className='h-20 w-full' />
              </div>
            )}
            {policyQuery.isError && (
              <Alert variant='destructive'>
                <AlertTitle>{t('Failed to load access policy')}</AlertTitle>
                <AlertDescription>
                  {t('Close the dialog and try again.')}
                </AlertDescription>
              </Alert>
            )}
            {policyQuery.data?.data && (
              <UserAccessPolicyForm
                key={policyQuery.data.data.access_policy_version}
                userId={userId}
                policy={policyQuery.data.data}
              />
            )}
          </TabsContent>
          <TabsContent
            value='devices'
            className='max-h-[calc(100dvh-12rem)] min-w-0 overflow-y-auto pr-1'
          >
            {userId > 0 && (
              <UserDeviceManagement
                userId={userId}
                deviceMode={policyQuery.data?.data.device_mode ?? 'off'}
              />
            )}
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  )
}
