import { setUp } from './setUp'
import { SocialDkgClient } from '../artifacts/contracts/SocialDkg.client'

async function main() {
  // create wallet
  const { cc: client, wallet } = await setUp()
  const accounts = await wallet.getAccounts()
  const owner = accounts[0].address

  const social_client = new SocialDkgClient(
    client,
    owner,
    'orai18vpey4w8qg5lvv3jj9sz5ae36s7fq49clerlj6rgzsuz93623ads9mqvmx'
  )

  let response = await social_client.verifyMember({
    email: 'email',
    pubKeys: [
      'A3AjmGDD983N5k/qfXtChZK+Ui0EP4TJITHPumkXseJT',
      'Ag3seh7SjeBrmirodgosnRN6iOVV5cb94dV5lo6Nv4+N',
      'A2nAcpcjB/r4GqcA3ujDYNHwrfwgxSUIFnmQgRMd5S5F',
    ],
    sigs: [
      '4gV8ENVy0BfeV0ak/29Qu3QTjKhZJpqSvsy9CkBzbCkvARhe/2O3Z29bN+fIx7FhfzzhcIniw+k4wKM81cCOrA==',
      '9Rg2BBxh29PfsIOR1wsowe2KfHLTrCD8tV6EjFk3LPsBp2C8ukUQdmkHNF40jMXe9WZGN5P/N1cETWq3Ov8F5g==',
      'y/zD3zpCoXUWGbpDmyLsqMjE6p7xHp7Xh8vqpaitzQdJWjtn5zakQQfRJQYapsk1Bt9kFQtfHy5uUukmCDoO3Q==',
    ],
  })
  console.log(response)
}

main().catch((err: any) => {
  console.error(err)
  process.exit(1)
})
