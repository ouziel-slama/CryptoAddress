from cryptoaddress import CryptoAddress

private_key_A = '18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725'
public_key_A = '0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6'

private_key_B = 'B18427B169E86DE681A1A62588E1D02AE4A7E83C1B413849989A76282A7B562F'
public_key_B ='049C95E0949E397FACCECF0FE8EAD247E6FD082717E4A4A876049FB34A9ADED110DFEA2EF691CC4A1410498F4C312F3A94318CD5B6F0E8E92051064876751C8404'

private_key_AB = 'CA65722CD418ED28EC369E36CFE3B7F3CC1CD035BFBF6469CE759FCA30AD6D54'
public_key_AB = '0436970CE32E14DC06AC50217CDCF53E628B32810707080D6848D9C8D4BE9FE461E100E705CCA9854436A1283210CCEFBB6B16CB9A86B009488922A8F302A27487'
address_AB = '166ev9JXn2rFqiPSQAwM7qJYpNL1JrNf3h'

pkwiki256bit = 'E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262'
pkwikibase58 = '5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF'


addr = CryptoAddress(privkey=pkwikibase58)
#addr = CryptoAddress(passphrase='Satoshi Nakamoto')
print addr.get_private_key(format='256-bit')
print addr.get_private_key()
print addr.get_public_key()
print addr.get_address()

print addr.to_json()

#print CryptoAddress.passphrase_to_private_key('Satoshi Nakamoto').encode('hex')

print "---------------------------------"

msg = "JahPowerBit"
addr = "137bY9admEPMGmqCjU1VUe9Gx2cwkfUtT9"
sig = "IKHMe2wtSSyX6d/+zqgAqzu+NrxJAdkCTqTVW6lhvkFha1epNM6mNzWluLhyDLrsbiZMp6r6pJskMT+SqNCcEKc="

print "verify_message:" + str(CryptoAddress.verify_message(addr, sig, msg))

print "---------------------------------"

print CryptoAddress.verify_address(addr)
addr = "137bY9admEPMGmqCjU1VUe9Gx2cwkfUtT8"
print CryptoAddress.verify_address(addr)

print "---------------------------------"

print CryptoAddress.verify_public_key("046EA50633BEC0ACA4E86C2E44968281F548190E28CA1DC572389DEA28641A028232B07AFDA7476EF289882F19B41B119138279932DFC2B4F58C375A97107A310F", version=48)