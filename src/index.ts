import * as core from '@actions/core'
import { isEmpty, isError, isString } from 'lodash-es'
import { fetch } from 'undici'
import { z } from 'zod'

const SchemaTailscaleGetAuthKey = z.object({
  id: z.string(),
  expires: z.string().datetime(),
  capabilities: z.object({
    devices: z.object({
      create: z.object({
        reusable: z.boolean(),
        ephemeral: z.boolean(),
        preauthorized: z.boolean(),
        tags: z.array(z.string())
      })
    })
  })
})

const SchemaTailscaleCreateAuthKey = z
  .object({
    key: z.string(),
    expirySeconds: z.number().optional()
  })
  .merge(SchemaTailscaleGetAuthKey)

const run = async () => {
  const tailnet = core.getInput('tailnet', { required: true })
  const clientId = core.getInput('client-id', { required: true })
  const clientSecret = core.getInput('client-secret', {
    required: true
  })
  const tags = core.getMultilineInput('tags', { required: true })

  const reusable = core.getBooleanInput('reusable', { required: false })
  const ephemeral = core.getBooleanInput('ephemeral', { required: false })
  const preauthorized = core.getBooleanInput('preauthorized', {
    required: false
  })

  const expirySecondsInput = core.getInput('expiry-seconds', {
    required: false
  })
  const expirySeconds = isEmpty(expirySecondsInput)
    ? 3600
    : parseInt(expirySecondsInput, 10)

  const credentialsFlow = await fetch(
    'https://api.tailscale.com/api/v2/oauth/token',
    {
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      method: 'POST',
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: clientSecret
      })
    }
  )

  if (credentialsFlow.status !== 200) {
    throw new Error(
      'Unable to authenticate with the Tailscale OAuth token endpoint.'
    )
  }

  const { access_token: tailscaleAccessToken } = z
    .object({
      access_token: z.string(),
      token_type: z.literal('Bearer'),
      expires_in: z.number(),
      scope: z.string()
    })
    .parse(await credentialsFlow.json())

  core.info(`Creating Tailscale auth key.`)

  const body: Pick<
    z.input<typeof SchemaTailscaleCreateAuthKey>,
    'capabilities' | 'expirySeconds'
  > = {
    capabilities: {
      devices: {
        create: {
          reusable,
          ephemeral,
          preauthorized,
          tags
        }
      }
    },
    expirySeconds
  }

  const response = await fetch(
    `https://api.tailscale.com/api/v2/tailnet/${tailnet}/keys`,
    {
      body: JSON.stringify(body),
      method: 'POST',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${tailscaleAccessToken}`
      }
    }
  )

  core.info(`Tailscale responed with ${response.status} status code.`)

  if (response.status === 200) {
    const { key } = SchemaTailscaleCreateAuthKey.parse(await response.json())

    core.setSecret(key)
    core.setOutput('authkey', key)
  } else {
    throw new Error('Unable to create tailscale auth key(s).')
  }
}

function handleError(err: unknown): void {
  const message = isError(err)
    ? err.message
    : isString(err)
    ? err
    : 'Unknown Error'

  core.setFailed(message)
}

process.on('unhandledRejection', handleError)
run().catch(handleError)
