import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify} from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'

const cert = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIJNe9z8IWdIIYBMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNV
BAMTGWRldi10eXUxZmxkcy51cy5hdXRoMC5jb20wHhcNMjExMTEzMjA0NTAwWhcN
MzUwNzIzMjA0NTAwWjAkMSIwIAYDVQQDExlkZXYtdHl1MWZsZHMudXMuYXV0aDAu
Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnJ+UB5aIASp87BsC
A8bxj+0cZdJTsAfqZ/zHqB92w0a7uB9EkciBoFIlpMwVpgFAzkQ6jcTKn3KnsM/9
rZVPArswJhn52shZ3aAe6jmgJXkTfYwX2N+uQDnQwRo/azle9dIC4R1osCg7pGfj
9dKKNORUJgmeOkj3F1B7jkTzu8lL5W0ezaOr0si69o2a1CcAKT73xDRLfraXNtxX
WxpPTG3djrri6F7mDeMqUdSoJOorhadpSrYwwdzb6lj1RLrOuF3AvlTazftasq60
RADNsrcboCwSGAigOtHkwujRe9FDwtqdnvnBV4GmP0B/h2z9yiKmzVxk1Ha7zk8l
9atF8QIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTygaBt++Av
RMlytMSJ42TiBRSc5TAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEB
AFLpJnlGvdYllb0lA5g1108WcNKsYNY+hB7CrA2BasN+uMJWIuV8L9QJJrZCdoPd
TcTqntv/wgqry2+XJIV36vYAVqxX2lZjA4DzNj0QgWPBeT5SLD/NUqXpiftyhbzy
n+sqSJOvCAHQVA3ZimZa88yMcR11KVznWth/Ggv+oq17XncdDH+JzswuDZgvkavt
qlDf1WAmm1NUynyY+K36Hk3R4Ox3sptKQx1bj+Fs5bgj5I5sVwZIc8JVGvTc8uhy
oAVRDTFSiLDKWW34JC+78Smkwh/to50DomN9PTnr3yi1GSJ1eZNipnkm9k4n1Sfu
hgM48CQKr0eArolEarWeXiY=
-----END CERTIFICATE-----`

export const handler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  try{
    const jwtToken = verifyToken(event.authorizationToken)
    console.log('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    console.log('User was not authorized', e.message)

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

function verifyToken(authHeader: string): JwtToken {
  if (!authHeader)
    throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return verify(token, cert, { algorithms: ['RS256'] }) as JwtToken
}