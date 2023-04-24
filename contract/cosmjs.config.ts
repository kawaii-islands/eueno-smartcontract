type NetworkConfig = {
  rpc: string
  chainId: string
  prefix: string
  gasPrice: string
  faucetUrl?: string
  denom: string
}

type networks = {
  [key: string]: NetworkConfig
}

type Config = {
  networks: networks
}

export const config: Config = {
  networks: {
    oraichain_testnet: {
      rpc: 'https://testnet-rpc.orai.io',
      chainId: 'Oraichain-testnet',
      denom: 'orai',
      prefix: 'orai',
      gasPrice: '0.024orai',
    },
    oraichain: {
      rpc: ' https://rpc.orai.io',
      chainId: 'Oraichain',
      denom: 'orai',
      prefix: 'orai',
      gasPrice: '0.024orai',
    },
  },
}
