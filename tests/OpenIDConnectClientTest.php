<?php

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jumbojett\OpenIDConnectClient;
use Jumbojett\OpenIDConnectClientException;
use Jumbojett\Response;
use PHPUnit\Framework\TestCase;

class OpenIDConnectClientTest extends TestCase
{
    protected \Faker\Generator $faker;

    protected function setUp(): void
    {
        $this->faker = Faker\Factory::create();
    }

    /**
     * @covers       Jumbojett\\OpenIDConnectClient::verifyIdTokenClaims
     * @dataProvider provideTestVerifyIdTokenClaimsData
     * @return void
     */
    public function testVerifyIdTokenClaims($claims, $idToken, $accessToken, $expectedResult)
    {
        $client = new OpenIDConnectClient(
            'https://example.org',
            'fake-client-id',
            'fake-client-secret',
        );


        $_SESSION['openid_connect_nonce'] = 'nonce-123';

        $client->setIdToken($idToken);
        $client->setAccessToken($accessToken);

        $actualResult = $client->verifyIdTokenClaims($claims);

        $this->assertEquals($expectedResult, $actualResult);
    }
    /**
     * @return array
     */
    public function provideTestVerifyIdTokenClaimsData(): array
    {
        // Token and access token from https://openid.net/specs/openid-connect-core-1_0.html#id_token-tokenExample
        $idToken = "eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ.
    ewogImlzcyI6ICJodHRwczovL3NlcnZlci5leGFtcGxlLmNvbSIsCiAic3ViIjog
    IjI0ODI4OTc2MTAwMSIsCiAiYXVkIjogInM2QmhkUmtxdDMiLAogIm5vbmNlIjog
    Im4tMFM2X1d6QTJNaiIsCiAiZXhwIjogMTMxMTI4MTk3MCwKICJpYXQiOiAxMzEx
    MjgwOTcwLAogImF0X2hhc2giOiAiNzdRbVVQdGpQZnpXdEYyQW5wSzlSUSIKfQ.
    kdqTmftlaXg5WBYBr1wkxhkqCGZPc0k8vTiV5g2jj67jQ7XkrDamYx2bOkZLdZrp
    MPIzkdYB1nZI_G8vQGQuamRhJcEIt21kblGPZ-yhEhdkAiZIZLu38rChalDS2Mh0
    glE_rke5XXRhmqqoEFFdziFdnO3p61-7y51co84OEAZvARSINQaOWIzvioRfs4zw
    IFOaT33Vpxfqr8HDyh31zo9eBW2dSQuCa071z0ENWChWoPliK1JCo_Bk9eDg2uwo
    2ZwhsvHzj6TMQ0lYOTzufSlSmXIKfjlOsb3nftQeR697_hA-nMZyAdL8_NRfaC37
    XnAbW8WB9wCfECp7cuNuOg";
        $accessToken = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";

        return [
            'valid-single-aud' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => 'fake-client-id',
                    'sub' => 'fake-client-sub',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'nonce' => 'nonce-123',
                ],
                $idToken,
                $accessToken,
                true
            ],
            'valid-multiple-auds' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'sid' => 'fake-client-sid',
                    'sub' => 'fake-client-sub',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'nonce' => 'nonce-123',
                ],
                $idToken,
                $accessToken,
                true
            ],
            'invalid-no-sub' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => 'fake-client-id',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'nonce' => 'nonce-123',
                ],
                $idToken,
                $accessToken,
                false
            ],
            'invalid-without-nonce' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => 'fake-client-id',
                    'sub' => 'fake-client-sub',
                    'iat' => time(),
                    'exp' => time() + 300
                ],
                $idToken,
                $accessToken,
                false
            ],
            'invalid-bad-nonce' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => 'fake-client-id',
                    'sub' => 'fake-client-sub',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'nonce' => 'nonce-567',
                ],
                $idToken,
                $accessToken,
                false
            ],
            'invalid-no-iat' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => 'fake-client-id',
                    'sub' => 'fake-client-sub',
                    'exp' => time() + 300,
                    'nonce' => 'nonce-123',
                ],
                $idToken,
                $accessToken,
                false
            ],
            'valid-at_hash' =>  [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => 'fake-client-id',
                    'sub' => 'fake-client-sub',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'nonce' => 'nonce-123',
                    'at_hash' => '77QmUPtjPfzWtF2AnpK9RQ',
                ],
                $idToken,
                $accessToken,
                true
            ],
            'invalid-at_hash' =>  [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => 'fake-client-id',
                    'sub' => 'fake-client-sub',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'nonce' => 'nonce-123',
                    'at_hash' => 'invalid-at-hash',
                ],
                $idToken,
                $accessToken,
                false
            ],
            'invalid-bad-iat' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => 'fake-client-id',
                    'sub' => 'fake-client-sub',
                    'iat' => time() + 400,
                    'exp' => time() + 300,
                    'nonce' => 'nonce-123',
                ],
                $idToken,
                $accessToken,
                false
            ],
            'invalid-no-exp' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => 'fake-client-id',
                    'sub' => 'fake-client-sub',
                    'iat' => time(),
                    'nonce' => 'nonce-123',
                ],
                $idToken,
                $accessToken,
                false
            ],
            'invalid-bad-exp' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => 'fake-client-id',
                    'sub' => 'fake-client-sub',
                    'iat' => time(),
                    'exp' => time() - 400,
                    'nonce' => 'nonce-123',
                ],
                $idToken,
                $accessToken,
                false
            ],

        ];
    }

    public function testJWTDecode()
    {
        $client = new OpenIDConnectClient();
        # access token
        $client->setAccessToken('');
        $header = $client->getAccessTokenHeader();
        self::assertEquals('', $header);
        $payload = $client->getAccessTokenPayload();
        self::assertEquals('', $payload);

        # id token
        $client->setIdToken('');
        $header = $client->getIdTokenHeader();
        self::assertEquals('', $header);
        $payload = $client->getIdTokenPayload();
        self::assertEquals('', $payload);
    }

    public function testGetNull()
    {
        $client = new OpenIDConnectClient();
        self::assertNull($client->getAccessToken());
        self::assertNull($client->getRefreshToken());
        self::assertNull($client->getIdToken());
        self::assertNull($client->getClientName());
        self::assertNull($client->getClientID());
        self::assertNull($client->getClientSecret());
        self::assertNull($client->getCertPath());
    }

    public function testResponseTypes()
    {
        $client = new OpenIDConnectClient();
        self::assertEquals([], $client->getResponseTypes());

        $client->setResponseTypes('foo');
        self::assertEquals(['foo'], $client->getResponseTypes());

        $client->setResponseTypes(['bar', 'ipsum']);
        self::assertEquals(['foo', 'bar', 'ipsum'], $client->getResponseTypes());
    }

    public function testGetRedirectURL()
    {
        $client = new OpenIDConnectClient();

        self::assertSame('http:///', $client->getRedirectURL());

        $_SERVER['SERVER_NAME'] = 'domain.test';
        $_SERVER['REQUEST_URI'] = '/path/index.php?foo=bar&baz#fragment';
        $_SERVER['SERVER_PORT'] = '443';
        self::assertSame('http://domain.test/path/index.php', $client->getRedirectURL());

        $_SERVER['SERVER_PORT'] = '8888';
        self::assertSame('http://domain.test:8888/path/index.php', $client->getRedirectURL());

        // Use fixed redirect URL if set
        $client->setRedirectURL('https://example.com/callback');
        self::assertSame('https://example.com/callback', $client->getRedirectURL());
    }

    public function testSerialize()
    {
        $client = new OpenIDConnectClient('https://example.com', 'foo', 'bar', 'baz');
        $serialized = serialize($client);
        $this->assertInstanceOf(OpenIDConnectClient::class, unserialize($serialized));
    }

    /**
     * @dataProvider provider
     */
    public function testAuthMethodSupport($expected, $authMethod, $clientAuthMethods, $idpAuthMethods)
    {
        $client = new OpenIDConnectClient();
        if ($clientAuthMethods !== null) {
            $client->setTokenEndpointAuthMethodsSupported($clientAuthMethods);
        }
        $this->assertEquals($expected, $client->supportsAuthMethod($authMethod, $idpAuthMethods));
    }

    public function provider(): array
    {
        return [
            'client_secret_basic - default config' => [true, 'client_secret_basic', null, ['client_secret_basic']],

            'client_secret_jwt - default config' => [false, 'client_secret_jwt', null, ['client_secret_basic', 'client_secret_jwt']],
            'client_secret_jwt - explicitly enabled' => [true, 'client_secret_jwt', ['client_secret_jwt'], ['client_secret_basic', 'client_secret_jwt']],

            'private_key_jwt - default config' => [false, 'private_key_jwt', null, ['client_secret_basic', 'client_secret_jwt', 'private_key_jwt']],
            'private_key_jwt - explicitly enabled' => [true, 'private_key_jwt', ['private_key_jwt'], ['client_secret_basic', 'client_secret_jwt', 'private_key_jwt']],

        ];
    }

    /**
     * @covers       Jumbojett\\OpenIDConnectClient::verifyLogoutTokenClaims
     * @dataProvider provideTestVerifyLogoutTokenClaimsData
     * @throws OpenIDConnectClientException
     */
    public function testVerifyLogoutTokenClaims($claims, $expectedResult)
    {
        // Mock the OpenIDConnectClient, only mocking the fetchURL method
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setConstructorArgs([
                'https://example.org',
                'fake-client-id',
                'fake-client-secret',
            ])
            ->onlyMethods(['fetchURL'])
            ->getMock();

        $client->expects($this->any())
            ->method('fetchURL')
            ->with($this->anything())
            ->will($this->returnCallback(function ($url) {
                switch ($url) {
                    case 'https://example.org/.well-known/openid-configuration':
                        return new Response(
                            200,
                            'application/json',
                            json_encode([
                                'issuer' => 'https://example.org/',
                                'authorization_endpoint' => 'https://example.org/authorize',
                                'token_endpoint' => 'https://example.org/token',
                                'userinfo_endpoint' => 'https://example.org/userinfo',
                                'jwks_uri' => 'https://example.org/jwks',
                                'response_types_supported' => ['code', 'id_token'],
                                'subject_types_supported' => ['public'],
                                'id_token_signing_alg_values_supported' => ['RS256'],
                            ])
                        );
                    default:
                        throw new Exception("Unexpected request: $url");
                }
            }));

        $actualResult = $client->verifyLogoutTokenClaims($claims);

        $this->assertEquals($expectedResult, $actualResult);
    }

    /**
     * @return array
     */
    public function provideTestVerifyLogoutTokenClaimsData(): array
    {
        return [
            'valid-single-aud' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => 'fake-client-id',
                    'sid' => 'fake-client-sid',
                    'sub' => 'fake-client-sub',
                    'jti' => 'fake-client-jti',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ],
                ],
                true
            ],
            'valid-multiple-auds' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'sid' => 'fake-client-sid',
                    'sub' => 'fake-client-sub',
                    'jti' => 'fake-client-jti',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ],
                ],
                true
            ],
            'invalid-no-sid-and-no-sub' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'jti' => 'fake-client-jti',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ],
                ],
                false
            ],
            'valid-no-sid' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'sub' => 'fake-client-sub',
                    'jti' => 'fake-client-jti',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ],
                ],
                true
            ],
            'valid-no-sub' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'sid' => 'fake-client-sid',
                    'jti' => 'fake-client-jti',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ],
                ],
                true
            ],
            'invalid-with-nonce' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'sid' => 'fake-client-sid',
                    'jti' => 'fake-client-jti',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ],
                    'nonce' => 'must-not-be-set',
                ],
                false
            ],
            'invalid-no-events' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'sid' => 'fake-client-sid',
                    'jti' => 'fake-client-jti',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'nonce' => 'must-not-be-set',
                ],
                false
            ],
            'invalid-no-backchannel-event' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'sid' => 'fake-client-sid',
                    'jti' => 'fake-client-jti',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'events' => (object) [],
                    'nonce' => 'must-not-be-set',
                ],
                false
            ],
            'invalid-no-iat' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'sid' => 'fake-client-sid',
                    'jti' => 'fake-client-jti',
                    'exp' => time() + 300,
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ],
                ],
                false
            ],
            'invalid-bad-iat' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'sid' => 'fake-client-sid',
                    'jti' => 'fake-client-jti',
                    'iat' => time() + 400,
                    'exp' => time() + 300,
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ],
                ],
                false
            ],
            'invalid-no-exp' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'sid' => 'fake-client-sid',
                    'jti' => 'fake-client-jti',
                    'iat' => time(),
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ],
                ],
                false
            ],
            'invalid-bad-exp' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => [ 'fake-client-id', 'some-other-aud' ],
                    'sid' => 'fake-client-sid',
                    'jti' => 'fake-client-jti',
                    'iat' => time(),
                    'exp' => time() - 301,
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ],
                ],
                false
            ],
            'valid-missing-jti' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => 'fake-client-id',
                    'sid' => 'fake-client-sid',
                    'sub' => 'fake-client-sub',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ],
                ],
                false
            ],
            'valid-single-aud' => [
                (object)[
                    'iss' => 'https://example.org',
                    'aud' => 'fake-client-id',
                    'sid' => 'fake-client-sid',
                    'sub' => 'fake-client-sub',
                    'jti' => 'fake-client-jti',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ],
                ],
                true
            ],
            'invalid-no-iss' => [
                (object)[
                    'aud' => 'fake-client-id',
                    'sid' => 'fake-client-sid',
                    'sub' => 'fake-client-sub',
                    'jti' => 'fake-client-jti',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ],
                ],
                false
            ],
            'invalid-bad-iss' => [
                (object)[
                    'iss' => 'https://bad-issuer.org',
                    'aud' => 'fake-client-id',
                    'sid' => 'fake-client-sid',
                    'sub' => 'fake-client-sub',
                    'jti' => 'fake-client-jti',
                    'iat' => time(),
                    'exp' => time() + 300,
                    'events' => (object) [
                        'http://schemas.openid.net/event/backchannel-logout' => (object)[]
                    ],
                ],
                false
            ],
        ];
    }

    public function testLeeway()
    {
        // Default leeway is 300
        $client = new OpenIDConnectClient();
        $this->assertEquals(300, $client->getLeeway());

        // Set leeway to 100
        $client->setLeeway(100);
        $this->assertEquals(100, $client->getLeeway());
    }

    public function testVerifyJWSWithRSASSA()
    {
        // Create a new RSA key pairs for signing the ID token
        $pkRS256 = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'RS256',
                'use' => 'sig'
            ]
        );
        $kidRS256 = bin2hex(random_bytes(6));

        $pkRS384 = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'RS384',
                'use' => 'sig'
            ]
        );
        $kidRS384 = bin2hex(random_bytes(6));

        $pkRS512 = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'RS512',
                'use' => 'sig'
            ]
        );
        $kidRS512 = bin2hex(random_bytes(6));

        // List of JWKs to be returned by the JWKS endpoint
        $jwks = [
            [
                'kid' => $kidRS256,
                ...$pkRS256->toPublic()->jsonSerialize()
            ],
            [
                'kid' => $kidRS384,
                ...$pkRS384->toPublic()->jsonSerialize()
            ],
            [
                'kid' => $kidRS512,
                ...$pkRS512->toPublic()->jsonSerialize()
            ]
        ];

        // Mock the OpenIDConnectClient, only mocking the fetchURL method
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setConstructorArgs([
                'https://example.org',
                'fake-client-id',
                'fake-client-secret',
            ])
            ->onlyMethods(['fetchURL'])
            ->getMock();

        $client->expects($this->any())
            ->method('fetchURL')
            ->with($this->anything())
            ->will($this->returnCallback(function ($url) use ($jwks) {
                switch ($url) {
                    case 'https://example.org/.well-known/openid-configuration':
                        return new Response(200, 'application/json', json_encode([
                            'issuer' => 'https://example.org/',
                            'authorization_endpoint' => 'https://example.org/authorize',
                            'token_endpoint' => 'https://example.org/token',
                            'userinfo_endpoint' => 'https://example.org/userinfo',
                            'jwks_uri' => 'https://example.org/jwks',
                            'response_types_supported' => ['code', 'id_token'],
                            'subject_types_supported' => ['public'],
                            'id_token_signing_alg_values_supported' => ['RS256'],
                        ]));
                    case 'https://example.org/jwks':
                        return new Response(200, 'application/json', json_encode([
                            'keys' => $jwks
                        ]));
                    default:
                        throw new Exception("Unexpected request: $url");
                }
            }));

        // RS256
        $this->assertTrue($client->verifyJWS($this->createJWS(['sub' => 'test'], $pkRS256, 'RS256', ['kid' => $kidRS256])));

        // RS384
        $this->assertTrue($client->verifyJWS($this->createJWS(['sub' => 'test'], $pkRS384, 'RS384', ['kid' => $kidRS384])));

        // RS512
        $this->assertTrue($client->verifyJWS($this->createJWS(['sub' => 'test'], $pkRS512, 'RS512', ['kid' => $kidRS512])));

        // Without kid
        $this->assertTrue($client->verifyJWS($this->createJWS(['sub' => 'test'], $pkRS256, 'RS256')));

        // With wrong kid
        $this->expectException(OpenIDConnectClientException::class);
        $this->assertFalse($client->verifyJWS($this->createJWS(['sub' => 'test'], $pkRS256, 'RS256', ['kid' => 'wrong-kid'])));
    }
    public function testVerifyJWSWithRSASSA_PSS()
    {
        // Create a new RSA key pairs for signing the ID token
        $pkPS256 = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'PS256',
                'use' => 'sig'
            ]
        );
        $kidPS256 = bin2hex(random_bytes(6));

        $pkPS384 = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'PS384',
                'use' => 'sig'
            ]
        );
        $kidPS384 = bin2hex(random_bytes(6));

        $pkPS512 = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'PS512',
                'use' => 'sig'
            ]
        );
        $kidPS512 = bin2hex(random_bytes(6));

        // List of JWKs to be returned by the JWKS endpoint
        $jwks = [
            [
                'kid' => $kidPS256,
                ...$pkPS256->toPublic()->jsonSerialize()
            ],
            [
                'kid' => $kidPS384,
                ...$pkPS384->toPublic()->jsonSerialize()
            ],
            [
                'kid' => $kidPS512,
                ...$pkPS512->toPublic()->jsonSerialize()
            ]
        ];

        // Mock the OpenIDConnectClient, only mocking the fetchURL method
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setConstructorArgs([
                'https://example.org',
                'fake-client-id',
                'fake-client-secret',
            ])
            ->onlyMethods(['fetchURL'])
            ->getMock();

        $client->expects($this->any())
            ->method('fetchURL')
            ->with($this->anything())
            ->will($this->returnCallback(function ($url) use ($jwks) {
                switch ($url) {
                    case 'https://example.org/.well-known/openid-configuration':
                        return new Response(200, 'application/json', json_encode([
                            'issuer' => 'https://example.org/',
                            'authorization_endpoint' => 'https://example.org/authorize',
                            'token_endpoint' => 'https://example.org/token',
                            'userinfo_endpoint' => 'https://example.org/userinfo',
                            'jwks_uri' => 'https://example.org/jwks',
                            'response_types_supported' => ['code', 'id_token'],
                            'subject_types_supported' => ['public'],
                            'id_token_signing_alg_values_supported' => ['RS256'],
                        ]));
                    case 'https://example.org/jwks':
                        return new Response(200, 'application/json', json_encode([
                            'keys' => $jwks
                        ]));
                    default:
                        throw new Exception("Unexpected request: $url");
                }
            }));

        // PS256
        $this->assertTrue($client->verifyJWS($this->createJWS(['sub' => 'test'], $pkPS256, 'PS256', ['kid' => $kidPS256])));

        // PS384
        $this->assertTrue($client->verifyJWS($this->createJWS(['sub' => 'test'], $pkPS384, 'PS384', ['kid' => $kidPS384])));

        // PS512
        $this->assertTrue($client->verifyJWS($this->createJWS(['sub' => 'test'], $pkPS512, 'PS512', ['kid' => $kidPS512])));

        // Without kid
        $this->assertTrue($client->verifyJWS($this->createJWS(['sub' => 'test'], $pkPS256, 'PS256')));

        // With wrong kid
        $this->expectException(OpenIDConnectClientException::class);
        $this->assertFalse($client->verifyJWS($this->createJWS(['sub' => 'test'], $pkPS256, 'PS256', ['kid' => 'wrong-kid'])));
    }

    public function testVerifyJWSWithECDSA()
    {
        // Create a new elliptic curve key pairs for signing the ID token
        $pkES256 = JWKFactory::createECKey('P-256');
        $kidES256 = bin2hex(random_bytes(6));

        $pkES384 = JWKFactory::createECKey('P-384');
        $kidES384 = bin2hex(random_bytes(6));

        $pkES512 = JWKFactory::createECKey('P-521');
        $kidES512 = bin2hex(random_bytes(6));

        // List of JWKs to be returned by the JWKS endpoint
        $jwks = [
            [
                'kid' => $kidES256,
                ...$pkES256->toPublic()->jsonSerialize()
            ],
            [
                'kid' => $kidES384,
                ...$pkES384->toPublic()->jsonSerialize()
            ],
            [
                'kid' => $kidES512,
                ...$pkES512->toPublic()->jsonSerialize()
            ]
        ];

        // Mock the OpenIDConnectClient, only mocking the fetchURL method
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setConstructorArgs([
                'https://example.org',
                'fake-client-id',
                'fake-client-secret',
            ])
            ->onlyMethods(['fetchURL'])
            ->getMock();

        $client->expects($this->any())
            ->method('fetchURL')
            ->with($this->anything())
            ->will($this->returnCallback(function ($url) use ($jwks) {
                switch ($url) {
                    case 'https://example.org/.well-known/openid-configuration':
                        return new Response(200, 'application/json', json_encode([
                            'issuer' => 'https://example.org/',
                            'authorization_endpoint' => 'https://example.org/authorize',
                            'token_endpoint' => 'https://example.org/token',
                            'userinfo_endpoint' => 'https://example.org/userinfo',
                            'jwks_uri' => 'https://example.org/jwks',
                            'response_types_supported' => ['code', 'id_token'],
                            'subject_types_supported' => ['public'],
                            'id_token_signing_alg_values_supported' => ['RS256'],
                        ]));
                    case 'https://example.org/jwks':
                        return new Response(200, 'application/json', json_encode([
                            'keys' => $jwks
                        ]));
                    default:
                        throw new Exception("Unexpected request: $url");
                }
            }));

        // ES256
        $this->assertTrue($client->verifyJWS($this->createJWS(['sub' => 'test'], $pkES256, 'ES256', ['kid' => $kidES256])));

        // ES384
        $this->assertTrue($client->verifyJWS($this->createJWS(['sub' => 'test'], $pkES384, 'ES384', ['kid' => $kidES384])));

        // ES512
        $this->assertTrue($client->verifyJWS($this->createJWS(['sub' => 'test'], $pkES512, 'ES512', ['kid' => $kidES512])));

        // Without kid
        $this->assertTrue($client->verifyJWS($this->createJWS(['sub' => 'test'], $pkES256, 'ES256')));

        // With wrong kid
        $this->expectException(OpenIDConnectClientException::class);
        $this->assertFalse($client->verifyJWS($this->createJWS(['sub' => 'test'], $pkES256, 'ES256', ['kid' => 'wrong-kid'])));
    }

    public function testVerifyJWSWithEdDSA()
    {
        // Create octet key pair for signing the ID token
        $pkEd25519 = JWKFactory::createOKPKey('Ed25519');
        $kidEd25519 = bin2hex(random_bytes(6));

        // List of JWKs to be returned by the JWKS endpoint
        $jwks = [
            [
                'kid' => $kidEd25519,
                ...$pkEd25519->toPublic()->jsonSerialize()
            ]
        ];

        // Mock the OpenIDConnectClient, only mocking the fetchURL method
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setConstructorArgs([
                'https://example.org',
                'fake-client-id',
                'fake-client-secret',
            ])
            ->onlyMethods(['fetchURL'])
            ->getMock();

        $client->expects($this->any())
            ->method('fetchURL')
            ->with($this->anything())
            ->will($this->returnCallback(function ($url) use ($jwks) {
                switch ($url) {
                    case 'https://example.org/.well-known/openid-configuration':
                        return new Response(200, 'application/json', json_encode([
                            'issuer' => 'https://example.org/',
                            'authorization_endpoint' => 'https://example.org/authorize',
                            'token_endpoint' => 'https://example.org/token',
                            'userinfo_endpoint' => 'https://example.org/userinfo',
                            'jwks_uri' => 'https://example.org/jwks',
                            'response_types_supported' => ['code', 'id_token'],
                            'subject_types_supported' => ['public'],
                            'id_token_signing_alg_values_supported' => ['RS256'],
                        ]));
                    case 'https://example.org/jwks':
                        return new Response(200, 'application/json', json_encode([
                            'keys' => $jwks
                        ]));
                    default:
                        throw new Exception("Unexpected request: $url");
                }
            }));

        // Ed25519
        $this->assertTrue($client->verifyJWS($this->createJWS(['sub' => 'test'], $pkEd25519, 'EdDSA', ['kid' => $kidEd25519])));

        // Without kid
        $this->assertTrue($client->verifyJWS($this->createJWS(['sub' => 'test'], $pkEd25519, 'EdDSA')));

        // With wrong kid
        $this->expectException(OpenIDConnectClientException::class);
        $this->assertFalse($client->verifyJWS($this->createJWS(['sub' => 'test'], $pkEd25519, 'EdDSA', ['kid' => 'wrong-kid'])));
    }

    public function testVerifyJWSWithHMAC()
    {

        $clientSecret = bin2hex(random_bytes(32));

        $keyHS256 = JWKFactory::createFromSecret(
            $clientSecret,
            [
                'alg' => 'HS256',
                'use' => 'sig'
            ]
        );
        $keyHS384 = JWKFactory::createFromSecret(
            $clientSecret,
            [
                'alg' => 'HS384',
                'use' => 'sig'
            ]
        );
        $keyHS512 = JWKFactory::createFromSecret(
            $clientSecret,
            [
                'alg' => 'HS512',
                'use' => 'sig'
            ]
        );

        // Mock the OpenIDConnectClient, only mocking the fetchURL method
        $client = new OpenIDConnectClient(
            'https://example.org',
            'fake-client-id',
            $clientSecret,
        );

        // HS256
        $this->assertTrue($client->verifyJWS($this->createJWS(['sub' => 'test'], $keyHS256, 'HS256')));

        // HS384
        $this->assertTrue($client->verifyJWS($this->createJWS(['sub' => 'test'], $keyHS384, 'HS384')));

        // HS512
        $this->assertTrue($client->verifyJWS($this->createJWS(['sub' => 'test'], $keyHS512, 'HS512')));


        // Create wrong key
        $wrongKeyHS256 = JWKFactory::createFromSecret(
            bin2hex(random_bytes(32)),
            [
                'alg' => 'HS256',
                'use' => 'sig'
            ]
        );

        $this->assertFalse($client->verifyJWS($this->createJWS(['sub' => 'test'], $wrongKeyHS256, 'HS256')));
    }
    public function testVerifyJWSWExceptionThrowsExceptionKeyNotFound()
    {
        // Create a new RSA key pair for signing the ID token
        $pkRS256 = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'RS256',
                'use' => 'sig'
            ]
        );
        $kidRS256 = bin2hex(random_bytes(6));

        $pkRS256Other = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'RS256',
                'use' => 'sig'
            ]
        );
        $kidRS256Other = bin2hex(random_bytes(6));

        // List of JWKs to be returned by the JWKS endpoint
        $jwks = [
            [
                'kid' => $kidRS256,
                ...$pkRS256->toPublic()->jsonSerialize()
            ],
        ];

        // Mock the OpenIDConnectClient, only mocking the fetchURL method
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setConstructorArgs([
                'https://example.org',
                'fake-client-id',
                'fake-client-secret',
            ])
            ->onlyMethods(['fetchURL'])
            ->getMock();

        $client->expects($this->any())
            ->method('fetchURL')
            ->with($this->anything())
            ->will($this->returnCallback(function ($url) use ($jwks) {
                switch ($url) {
                    case 'https://example.org/.well-known/openid-configuration':
                        return new Response(200, 'application/json', json_encode([
                            'issuer' => 'https://example.org/',
                            'authorization_endpoint' => 'https://example.org/authorize',
                            'token_endpoint' => 'https://example.org/token',
                            'userinfo_endpoint' => 'https://example.org/userinfo',
                            'jwks_uri' => 'https://example.org/jwks',
                            'response_types_supported' => ['code', 'id_token'],
                            'subject_types_supported' => ['public'],
                            'id_token_signing_alg_values_supported' => ['RS256'],
                        ]));
                    case 'https://example.org/jwks':
                        return new Response(200, 'application/json', json_encode([
                            'keys' => $jwks
                        ]));
                    default:
                        throw new Exception("Unexpected request: $url");
                }
            }));

        // RS256, without listing the used key in the JWKS
        $this->expectException(OpenIDConnectClientException::class);
        $this->expectException($client->verifyJWS($this->createJWS(['sub' => 'test'], $pkRS256Other, 'RS256', ['kid' => $kidRS256Other])));
    }

    public function testVerifyJWSWUsesAdditionalJWKs()
    {
        // Create a new RSA key pair for signing the ID token
        $pkRS256 = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'RS256',
                'use' => 'sig'
            ]
        );
        $kidRS256 = bin2hex(random_bytes(6));

        $pkRS256Other = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'RS256',
                'use' => 'sig'
            ]
        );
        $kidRS256Other = bin2hex(random_bytes(6));

        // List of JWKs to be returned by the JWKS endpoint
        $jwks = [
            [
                'kid' => $kidRS256,
                ...$pkRS256->toPublic()->jsonSerialize()
            ],
        ];

        // Mock the OpenIDConnectClient, only mocking the fetchURL method
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setConstructorArgs([
                'https://example.org',
                'fake-client-id',
                'fake-client-secret',
            ])
            ->onlyMethods(['fetchURL'])
            ->getMock();

        $client->expects($this->any())
            ->method('fetchURL')
            ->with($this->anything())
            ->will($this->returnCallback(function ($url) use ($jwks) {
                switch ($url) {
                    case 'https://example.org/.well-known/openid-configuration':
                        return new Response(200, 'application/json', json_encode([
                            'issuer' => 'https://example.org/',
                            'authorization_endpoint' => 'https://example.org/authorize',
                            'token_endpoint' => 'https://example.org/token',
                            'userinfo_endpoint' => 'https://example.org/userinfo',
                            'jwks_uri' => 'https://example.org/jwks',
                            'response_types_supported' => ['code', 'id_token'],
                            'subject_types_supported' => ['public'],
                            'id_token_signing_alg_values_supported' => ['RS256'],
                        ]));
                    case 'https://example.org/jwks':
                        return new Response(200, 'application/json', json_encode([
                            'keys' => $jwks
                        ]));
                    default:
                        throw new Exception("Unexpected request: $url");
                }
            }));

        // Add the additional JWKs
        $client->addAdditionalJwk((object)[
            'kid' => $kidRS256Other,
            ...$pkRS256Other->toPublic()->jsonSerialize()
        ]);

        // RS256, with listing the used key in the JWKS
        $this->assertTrue($client->verifyJWS($this->createJWS(['sub' => 'test'], $pkRS256Other, 'RS256', ['kid' => $kidRS256Other])));

    }

    public function createJWS(array $claims, JWK $privateKey, string $alg, array $additionalHeaders = []): JWS
    {
        $algorithmManager = new AlgorithmManager([
            new RS256(),
            new RS384(),
            new RS512(),

            new PS256(),
            new PS384(),
            new PS512(),

            new ES256(),
            new ES384(),
            new ES512(),

            new EdDSA(),

            new HS256(),
            new HS384(),
            new HS512(),
        ]);

        $jwsBuilder = new JWSBuilder($algorithmManager);

        $payload = json_encode($claims);

        return $jwsBuilder
            ->create()
            ->withPayload($payload)
            ->addSignature($privateKey, ['alg' => $alg, ...$additionalHeaders])
            ->build();
    }

    public function signClaims(array $claims, JWK $privateKey, string $alg, array $additionalHeaders = []): string
    {
        $jws = $this->createJWS($claims, $privateKey, $alg, $additionalHeaders);

        $serializer = new CompactSerializer();
        return $serializer->serialize($jws, 0);
    }

    /** Integration tests */
    public function testAuthenticateImplicitFlow()
    {
        // Create a new RSA key pair for signing the ID token
        $private_key = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'RS256',
                'use' => 'sig'
            ]
        );
        $public_key = $private_key->toPublic();

        // Generate random values for the ID token
        $kid = bin2hex(random_bytes(6));
        $nonce = bin2hex(random_bytes(6));
        $state = bin2hex(random_bytes(6));
        $firstName = $this->faker->firstName();
        $lastName = $this->faker->lastName();
        $email = $this->faker->email();
        $sub = $this->faker->uuid();
        $sid = $this->faker->uuid();

        // Create claims for the ID token
        $claims = [
            'exp' => time() + 60,
            'iat' => time(),
            'iss' => 'https://example.org',
            'aud' => 'fake-client-id',
            'sub' => $sub,
            'sid' => $sid,
            'given_name' => $firstName,
            'family_name' => $lastName,
            'email' => $email,
            'nonce' => $nonce
        ];

        // Create id token
        $idToken = $this->signClaims($claims, $private_key, 'RS256', ['kid' => $kid]);

        // List of JWKs to be returned by the JWKS endpoint
        $jwks = [[
            'kid' => $kid,
            ...$public_key->jsonSerialize()
        ]];

        // Mock the OpenIDConnectClient, only mocking the fetchURL method
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setConstructorArgs([
                'https://example.org',
                'fake-client-id',
                'fake-client-secret',
            ])
            ->onlyMethods(['fetchURL'])
            ->getMock();

        $client->expects($this->any())
            ->method('fetchURL')
            ->with($this->anything())
            ->will($this->returnCallback(function ($url) use ($jwks) {
                switch ($url) {
                    case 'https://example.org/.well-known/openid-configuration':
                        return new Response(
                            200,
                            'application/json',
                            json_encode([
                            'issuer' => 'https://example.org/',
                            'authorization_endpoint' => 'https://example.org/authorize',
                            'token_endpoint' => 'https://example.org/token',
                            'userinfo_endpoint' => 'https://example.org/userinfo',
                            'jwks_uri' => 'https://example.org/jwks',
                            'response_types_supported' => ['code', 'id_token'],
                            'subject_types_supported' => ['public'],
                            'id_token_signing_alg_values_supported' => ['RS256'],
                        ])
                        );
                    case 'https://example.org/jwks':
                        return new Response(
                            200,
                            'application/json',
                            json_encode([
                            'keys' => $jwks
                        ])
                        );
                    default:
                        throw new Exception("Unexpected request: $url");
                }
            }));

        // Allow implicit flow
        $client->setAllowImplicitFlow(true);

        // Simulate the state and nonce have been set in the session
        $_SESSION['openid_connect_state'] = $state;
        $_SESSION['openid_connect_nonce'] = $nonce;

        // Simulate incoming request with ID token and state
        $_REQUEST['id_token'] = $idToken;
        $_REQUEST['state'] = $state;

        // Call the authenticate method to handle the request
        $client->authenticate();

        // Verify call claims are correctly set
        $this->assertEquals($firstName, $client->getVerifiedClaims('given_name'));
        $this->assertEquals($lastName, $client->getVerifiedClaims('family_name'));
        $this->assertEquals($email, $client->getVerifiedClaims('email'));
        $this->assertEquals($sub, $client->getVerifiedClaims('sub'));
        $this->assertEquals($sid, $client->getVerifiedClaims('sid'));

        // Check if the ID token is set
        $this->assertEquals($idToken, $client->getIdToken());
    }

    public function testAuthenticateImplicitFlowInvalidSignature()
    {
        // Create a new RSA key pair for signing the ID token
        $private_key = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'RS256',
                'use' => 'sig'
            ]
        );
        $public_key = $private_key->toPublic();

        // False RSA key for testing invalid signature
        $invalid_private_key = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'RS256',
                'use' => 'sig'
            ]
        );

        // Generate random values for the ID token
        $kid = bin2hex(random_bytes(6));
        $nonce = bin2hex(random_bytes(6));
        $state = bin2hex(random_bytes(6));
        $firstName = $this->faker->firstName();
        $lastName = $this->faker->lastName();
        $email = $this->faker->email();
        $sub = $this->faker->uuid();
        $sid = $this->faker->uuid();

        // Create claims for the ID token
        $claims = [
            'exp' => time() + 60,
            'iat' => time(),
            'iss' => 'https://example.org',
            'aud' => 'fake-client-id',
            'sub' => $sub,
            'sid' => $sid,
            'given_name' => $firstName,
            'family_name' => $lastName,
            'email' => $email,
            'nonce' => $nonce
        ];

        // Create id token
        $idToken = $this->signClaims($claims, $invalid_private_key, 'RS256', ['kid' => $kid]);

        // List of JWKs to be returned by the JWKS endpoint
        $jwks = [[
            'kid' => $kid,
            ...$public_key->jsonSerialize()
        ]];

        // Mock the OpenIDConnectClient, only mocking the fetchURL method
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setConstructorArgs([
                'https://example.org',
                'fake-client-id',
                'fake-client-secret',
            ])
            ->onlyMethods(['fetchURL'])
            ->getMock();

        $client->expects($this->any())
            ->method('fetchURL')
            ->with($this->anything())
            ->will($this->returnCallback(function ($url) use ($jwks) {
                switch ($url) {
                    case 'https://example.org/.well-known/openid-configuration':
                        return new Response(200, 'application/json', json_encode([
                            'issuer' => 'https://example.org/',
                            'authorization_endpoint' => 'https://example.org/authorize',
                            'token_endpoint' => 'https://example.org/token',
                            'userinfo_endpoint' => 'https://example.org/userinfo',
                            'jwks_uri' => 'https://example.org/jwks',
                            'response_types_supported' => ['code', 'id_token'],
                            'subject_types_supported' => ['public'],
                            'id_token_signing_alg_values_supported' => ['RS256'],
                        ]));
                    case 'https://example.org/jwks':
                        return new Response(200, 'application/json', json_encode([
                            'keys' => $jwks
                        ]));
                    default:
                        throw new Exception("Unexpected request: $url");
                }
            }));

        // Allow implicit flow
        $client->setAllowImplicitFlow(true);

        // Simulate the state and nonce have been set in the session
        $_SESSION['openid_connect_state'] = $state;
        $_SESSION['openid_connect_nonce'] = $nonce;

        // Simulate incoming request with ID token and state
        $_REQUEST['id_token'] = $idToken;
        $_REQUEST['state'] = $state;

        // Call the authenticate method to handle the request
        $this->expectException(OpenIDConnectClientException::class);

        $client->authenticate();
    }

    public function testAuthenticateImplicitFlowEncrypted()
    {
        // Create a new RSA key pair for signing the ID token
        $private_key = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'RS256',
                'use' => 'sig'
            ]
        );
        $public_key = $private_key->toPublic();

        // Create a new RSA key pair for encrypting the ID token
        $encryption_key = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'RSA-OAEP-256',
                'use' => 'enc'
            ]
        );

        // Generate random values for the ID token
        $kid = bin2hex(random_bytes(6));
        $nonce = bin2hex(random_bytes(6));
        $state = bin2hex(random_bytes(6));
        $firstName = $this->faker->firstName();
        $lastName = $this->faker->lastName();
        $email = $this->faker->email();
        $sub = $this->faker->uuid();
        $sid = $this->faker->uuid();

        // Create claims for the ID token
        $claims = [
            'exp' => time() + 60,
            'iat' => time(),
            'iss' => 'https://example.org',
            'aud' => 'fake-client-id',
            'sub' => $sub,
            'sid' => $sid,
            'given_name' => $firstName,
            'family_name' => $lastName,
            'email' => $email,
            'nonce' => $nonce
        ];

        // Create id token
        $idToken = $this->signClaims($claims, $private_key, 'RS256', ['kid' => $kid]);

        // List of JWKs to be returned by the JWKS endpoint
        $jwks = [[
            'kid' => $kid,
            ...$public_key->jsonSerialize()
        ]];

        $keyEncryptionAlgorithmManager = new AlgorithmManager([
            new RSAOAEP256(),
        ]);
        $contentEncryptionAlgorithmManager = new AlgorithmManager([
            new A128CBCHS256(),
        ]);

        $jweBuilder = new JWEBuilder(
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
        );

        $jwe = $jweBuilder
            ->create()
            ->withPayload($idToken)
            ->withSharedProtectedHeader([
                'alg' => 'RSA-OAEP-256',
                'enc' => 'A128CBC-HS256'
            ])
            ->addRecipient($encryption_key->toPublic())
            ->build();

        $serializer = new \Jose\Component\Encryption\Serializer\CompactSerializer();

        $encryptedIdToken = $serializer->serialize($jwe, 0);

        // Mock the OpenIDConnectClient, only mocking the fetchURL method
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setConstructorArgs([
                'https://example.org',
                'fake-client-id',
                'fake-client-secret',
            ])
            ->onlyMethods(['fetchURL', 'handleJweResponse'])
            ->getMock();

        $client->expects($this->any())
            ->method('fetchURL')
            ->with($this->anything())
            ->will($this->returnCallback(function ($url) use ($jwks) {
                switch ($url) {
                    case 'https://example.org/.well-known/openid-configuration':
                        return new Response(
                            200,
                            'application/json',
                            json_encode([
                                'issuer' => 'https://example.org/',
                                'authorization_endpoint' => 'https://example.org/authorize',
                                'token_endpoint' => 'https://example.org/token',
                                'userinfo_endpoint' => 'https://example.org/userinfo',
                                'jwks_uri' => 'https://example.org/jwks',
                                'response_types_supported' => ['code', 'id_token'],
                                'subject_types_supported' => ['public'],
                                'id_token_signing_alg_values_supported' => ['RS256'],
                            ])
                        );
                    case 'https://example.org/jwks':
                        return new Response(
                            200,
                            'application/json',
                            json_encode([
                                'keys' => $jwks
                            ])
                        );
                    default:
                        throw new Exception("Unexpected request: $url");
                }
            }));

        $client->expects($this->once())
            ->method('handleJweResponse')
            ->with($encryptedIdToken)
            ->willReturn($idToken);

        // Allow implicit flow
        $client->setAllowImplicitFlow(true);

        // Simulate the state and nonce have been set in the session
        $_SESSION['openid_connect_state'] = $state;
        $_SESSION['openid_connect_nonce'] = $nonce;

        // Simulate incoming request with ID token and state
        $_REQUEST['id_token'] = $encryptedIdToken;
        $_REQUEST['state'] = $state;

        // Call the authenticate method to handle the request
        $client->authenticate();

        // Verify call claims are correctly set
        $this->assertEquals($firstName, $client->getVerifiedClaims('given_name'));
        $this->assertEquals($lastName, $client->getVerifiedClaims('family_name'));
        $this->assertEquals($email, $client->getVerifiedClaims('email'));
        $this->assertEquals($sub, $client->getVerifiedClaims('sub'));
        $this->assertEquals($sid, $client->getVerifiedClaims('sid'));

        // Check if the ID token is set
        $this->assertEquals($idToken, $client->getIdToken());
    }

    public function testAuthenticateAuthorizationCodeFlow()
    {
        // Create a new RSA key pair for signing the ID token
        $private_key = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'RS256',
                'use' => 'sig'
            ]
        );
        $public_key = $private_key->toPublic();

        // Generate random values for the ID token
        $kid = bin2hex(random_bytes(6));
        $code = bin2hex(random_bytes(6));
        $nonce = bin2hex(random_bytes(6));
        $state = bin2hex(random_bytes(6));
        $firstName = $this->faker->firstName();
        $lastName = $this->faker->lastName();
        $email = $this->faker->email();
        $sub = $this->faker->uuid();
        $sid = $this->faker->uuid();

        // Create claims for the ID token
        $claims = [
            'exp' => time() + 60,
            'iat' => time(),
            'iss' => 'https://example.org',
            'aud' => 'fake-client-id',
            'sub' => $sub,
            'sid' => $sid,
            'given_name' => $firstName,
            'family_name' => $lastName,
            'email' => $email,
            'nonce' => $nonce
        ];

        // Create id token
        $idToken = $this->signClaims($claims, $private_key, 'RS256', ['kid' => $kid]);

        // List of JWKs to be returned by the JWKS endpoint
        $jwks = [[
            'kid' => $kid,
            ...$public_key->jsonSerialize()
        ]];

        $tokenResponse = [
            'access_token' => 'fake-access-token',
            'token_type' => 'Bearer',
            'id_token' => $idToken,
        ];

        // Mock the OpenIDConnectClient, only mocking the fetchURL method
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setConstructorArgs([
                'https://example.org',
                'fake-client-id',
                'fake-client-secret',
            ])
            ->onlyMethods(['fetchURL'])
            ->getMock();

        $client->expects($this->any())
            ->method('fetchURL')
            ->with($this->anything())
            ->will($this->returnCallback(function (string$url, ?string $post_body = null, array $headers = []) use ($tokenResponse, $code, $jwks) {
                switch ($url) {
                    case 'https://example.org/.well-known/openid-configuration':
                        return new Response(200, 'application/json', json_encode([
                            'issuer' => 'https://example.org/',
                            'authorization_endpoint' => 'https://example.org/authorize',
                            'token_endpoint' => 'https://example.org/token',
                            'userinfo_endpoint' => 'https://example.org/userinfo',
                            'jwks_uri' => 'https://example.org/jwks',
                            'response_types_supported' => ['code', 'id_token'],
                            'subject_types_supported' => ['public'],
                            'id_token_signing_alg_values_supported' => ['RS256'],
                        ]));
                    case 'https://example.org/jwks':
                        return new Response(200, 'application/json', json_encode([
                            'keys' => $jwks
                        ]));
                    case 'https://example.org/token':
                        parse_str($post_body, $params);
                        $this->assertEquals('authorization_code', $params['grant_type']);
                        $this->assertEquals($code, $params['code']);
                        return new Response(200, 'application/json', json_encode($tokenResponse));
                    default:
                        throw new Exception("Unexpected request: $url");
                }
            }));

        // Simulate the state and nonce have been set in the session
        $_SESSION['openid_connect_state'] = $state;
        $_SESSION['openid_connect_nonce'] = $nonce;

        // Simulate incoming request with code and state
        $_REQUEST['code'] = $code;
        $_REQUEST['state'] = $state;

        // Call the authenticate method to handle the request
        $client->authenticate();

        // Verify call claims are correctly set
        $this->assertEquals($firstName, $client->getVerifiedClaims('given_name'));
        $this->assertEquals($lastName, $client->getVerifiedClaims('family_name'));
        $this->assertEquals($email, $client->getVerifiedClaims('email'));
        $this->assertEquals($sub, $client->getVerifiedClaims('sub'));
        $this->assertEquals($sid, $client->getVerifiedClaims('sid'));

        // Check if the access token is set
        $this->assertEquals('fake-access-token', $client->getAccessToken());

        // Check if the ID token is set
        $this->assertEquals($idToken, $client->getIdToken());
    }

    public function testAuthenticateAuthorizationCodeFlowEncrypted()
    {
        // Create a new RSA key pair for signing the ID token
        $private_key = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'RS256',
                'use' => 'sig'
            ]
        );
        $public_key = $private_key->toPublic();

        // Create a new RSA key pair for encrypting the ID token
        $encryption_key = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'RSA-OAEP-256',
                'use' => 'enc'
            ]
        );

        // Generate random values for the ID token
        $kid = bin2hex(random_bytes(6));
        $code = bin2hex(random_bytes(6));
        $nonce = bin2hex(random_bytes(6));
        $state = bin2hex(random_bytes(6));
        $firstName = $this->faker->firstName();
        $lastName = $this->faker->lastName();
        $email = $this->faker->email();
        $sub = $this->faker->uuid();
        $sid = $this->faker->uuid();

        // Create claims for the ID token
        $claims = [
            'exp' => time() + 60,
            'iat' => time(),
            'iss' => 'https://example.org',
            'aud' => 'fake-client-id',
            'sub' => $sub,
            'sid' => $sid,
            'given_name' => $firstName,
            'family_name' => $lastName,
            'email' => $email,
            'nonce' => $nonce
        ];

        // Create id token
        $idToken = $this->signClaims($claims, $private_key, 'RS256', ['kid' => $kid]);

        // List of JWKs to be returned by the JWKS endpoint
        $jwks = [[
            'kid' => $kid,
            ...$public_key->jsonSerialize()
        ]];

        $keyEncryptionAlgorithmManager = new AlgorithmManager([
            new RSAOAEP256(),
        ]);
        $contentEncryptionAlgorithmManager = new AlgorithmManager([
            new A128CBCHS256(),
        ]);

        $jweBuilder = new JWEBuilder(
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
        );

        $jwe = $jweBuilder
            ->create()
            ->withPayload($idToken)
            ->withSharedProtectedHeader([
                'alg' => 'RSA-OAEP-256',
                'enc' => 'A128CBC-HS256'
            ])
            ->addRecipient($encryption_key->toPublic())
            ->build();

        $serializer = new \Jose\Component\Encryption\Serializer\CompactSerializer();

        $encryptedIdToken = $serializer->serialize($jwe, 0);

        $tokenResponse = [
            'access_token' => 'fake-access-token',
            'token_type' => 'Bearer',
            'id_token' => $encryptedIdToken,
        ];

        // Mock the OpenIDConnectClient, only mocking the fetchURL method
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setConstructorArgs([
                'https://example.org',
                'fake-client-id',
                'fake-client-secret',
            ])
            ->onlyMethods(['fetchURL', 'handleJweResponse'])
            ->getMock();

        $client->expects($this->any())
            ->method('fetchURL')
            ->with($this->anything())
            ->will($this->returnCallback(function (string$url, ?string $post_body = null, array $headers = []) use ($tokenResponse, $code, $jwks) {
                switch ($url) {
                    case 'https://example.org/.well-known/openid-configuration':
                        return new Response(200, 'application/json', json_encode([
                            'issuer' => 'https://example.org/',
                            'authorization_endpoint' => 'https://example.org/authorize',
                            'token_endpoint' => 'https://example.org/token',
                            'userinfo_endpoint' => 'https://example.org/userinfo',
                            'jwks_uri' => 'https://example.org/jwks',
                            'response_types_supported' => ['code', 'id_token'],
                            'subject_types_supported' => ['public'],
                            'id_token_signing_alg_values_supported' => ['RS256'],
                        ]));
                    case 'https://example.org/jwks':
                        return new Response(200, 'application/json', json_encode([
                            'keys' => $jwks
                        ]));
                    case 'https://example.org/token':
                        parse_str($post_body, $params);
                        $this->assertEquals('authorization_code', $params['grant_type']);
                        $this->assertEquals($code, $params['code']);
                        return new Response(200, 'application/json', json_encode($tokenResponse));
                    default:
                        throw new Exception("Unexpected request: $url");
                }
            }));

        $client->expects($this->once())
            ->method('handleJweResponse')
            ->with($encryptedIdToken)
            ->willReturn($idToken);

        // Simulate the state and nonce have been set in the session
        $_SESSION['openid_connect_state'] = $state;
        $_SESSION['openid_connect_nonce'] = $nonce;

        // Simulate incoming request with code and state
        $_REQUEST['code'] = $code;
        $_REQUEST['state'] = $state;

        // Call the authenticate method to handle the request
        $client->authenticate();

        // Verify call claims are correctly set
        $this->assertEquals($firstName, $client->getVerifiedClaims('given_name'));
        $this->assertEquals($lastName, $client->getVerifiedClaims('family_name'));
        $this->assertEquals($email, $client->getVerifiedClaims('email'));
        $this->assertEquals($sub, $client->getVerifiedClaims('sub'));
        $this->assertEquals($sid, $client->getVerifiedClaims('sid'));

        // Check if the access token is set
        $this->assertEquals('fake-access-token', $client->getAccessToken());

        // Check if the ID token is set
        $this->assertEquals($idToken, $client->getIdToken());
    }

    public function testRequestUserInfoUnsignedUnencrypted()
    {
        // Create a new RSA key pair for signing the ID token
        $private_key = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'RS256',
                'use' => 'sig'
            ]
        );
        $public_key = $private_key->toPublic();

        // Generate random values for the ID token
        $kid = bin2hex(random_bytes(6));
        $code = bin2hex(random_bytes(6));
        $nonce = bin2hex(random_bytes(6));
        $state = bin2hex(random_bytes(6));
        $firstName = $this->faker->firstName();
        $lastName = $this->faker->lastName();
        $email = $this->faker->email();
        $sub = $this->faker->uuid();
        $sid = $this->faker->uuid();

        $accessToken = 'fake-access-token';

        // Create claims for the ID token
        $idTokenClaims = [
            'exp' => time() + 60,
            'iat' => time(),
            'iss' => 'https://example.org',
            'aud' => 'fake-client-id',
            'sub' => $sub,
            'sid' => $sid,
            'nonce' => $nonce
        ];

        $userInfoClaims = [
            'sub' => $sub,
            'given_name' => $firstName,
            'family_name' => $lastName,
            'email' => $email,
        ];

        // Create id token
        $idToken = $this->signClaims($idTokenClaims, $private_key, 'RS256', ['kid' => $kid]);

        // List of JWKs to be returned by the JWKS endpoint
        $jwks = [[
            'kid' => $kid,
            ...$public_key->jsonSerialize()
        ]];

        $userInfoResponse = $userInfoClaims;

        // Mock the OpenIDConnectClient, only mocking the fetchURL method
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setConstructorArgs([
                'https://example.org',
                'fake-client-id',
                'fake-client-secret',
            ])
            ->onlyMethods(['fetchURL'])
            ->getMock();

        $client->expects($this->any())
            ->method('fetchURL')
            ->with($this->anything())
            ->will($this->returnCallback(function (string$url, ?string $post_body = null, array $headers = []) use ($userInfoResponse, $accessToken, $jwks, $client) {
                switch ($url) {
                    case 'https://example.org/.well-known/openid-configuration':
                        return new Response(200, 'application/json', json_encode([
                            'issuer' => 'https://example.org/',
                            'authorization_endpoint' => 'https://example.org/authorize',
                            'token_endpoint' => 'https://example.org/token',
                            'userinfo_endpoint' => 'https://example.org/userinfo',
                            'jwks_uri' => 'https://example.org/jwks',
                            'response_types_supported' => ['code', 'id_token'],
                            'subject_types_supported' => ['public'],
                            'id_token_signing_alg_values_supported' => ['RS256'],
                        ]));
                    case 'https://example.org/jwks':
                        return new Response(200, 'application/json', json_encode([
                            'keys' => $jwks
                        ]));
                    case 'https://example.org/userinfo':
                        $this->assertEquals('Authorization: Bearer '.$accessToken, $headers[0]);
                        return new Response(200, 'application/json', json_encode($userInfoResponse));
                    default:
                        throw new Exception("Unexpected request: $url");
                }
            }));

        // Simulate the state and nonce have been set in the session
        $_SESSION['openid_connect_state'] = $state;
        $_SESSION['openid_connect_nonce'] = $nonce;

        // Simulate incoming request with code and state
        $_REQUEST['code'] = $code;
        $_REQUEST['state'] = $state;

        $client->setAccessToken($accessToken);
        $client->setIdToken($idToken);

        // Get user info
        $userData = $client->requestUserInfo();

        // Verify call claims are correctly retrieved
        $this->assertEquals($firstName, $userData->given_name);
        $this->assertEquals($lastName, $userData->family_name);
        $this->assertEquals($email, $userData->email);
    }

    public function testRequestUserInfoUnsignedEncrypted()
    {
        // Create a new RSA key pair for signing the ID token
        $private_key = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'RS256',
                'use' => 'sig'
            ]
        );
        $public_key = $private_key->toPublic();

        // Create a new RSA key pair for encrypting the user info response
        $encryption_key = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'RSA-OAEP-256',
                'use' => 'enc'
            ]
        );


        // Generate random values for the ID token
        $kid = bin2hex(random_bytes(6));
        $code = bin2hex(random_bytes(6));
        $nonce = bin2hex(random_bytes(6));
        $state = bin2hex(random_bytes(6));
        $firstName = $this->faker->firstName();
        $lastName = $this->faker->lastName();
        $email = $this->faker->email();
        $sub = $this->faker->uuid();
        $sid = $this->faker->uuid();

        $accessToken = 'fake-access-token';

        // Create claims for the ID token
        $idTokenClaims = [
            'exp' => time() + 60,
            'iat' => time(),
            'iss' => 'https://example.org',
            'aud' => 'fake-client-id',
            'sub' => $sub,
            'sid' => $sid,
            'nonce' => $nonce
        ];

        $userInfoClaims = [
            'iss' => 'https://example.org',
            'aud' => 'fake-client-id',
            'sub' => $sub,
            'given_name' => $firstName,
            'family_name' => $lastName,
            'email' => $email,
        ];

        // Create id token
        $idToken = $this->signClaims($idTokenClaims, $private_key, 'RS256', ['kid' => $kid]);

        // List of JWKs to be returned by the JWKS endpoint
        $jwks = [[
            'kid' => $kid,
            ...$public_key->jsonSerialize()
        ]];

        $keyEncryptionAlgorithmManager = new AlgorithmManager([
            new RSAOAEP256(),
        ]);
        $contentEncryptionAlgorithmManager = new AlgorithmManager([
            new A128CBCHS256(),
        ]);

        $jweBuilder = new JWEBuilder(
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
        );

        $jwe = $jweBuilder
            ->create()
            ->withPayload(json_encode($userInfoClaims))
            ->withSharedProtectedHeader([
                'alg' => 'RSA-OAEP-256',
                'enc' => 'A128CBC-HS256'
            ])
            ->addRecipient($encryption_key->toPublic())
            ->build();

        $serializer = new \Jose\Component\Encryption\Serializer\CompactSerializer();

        $userInfoResponse = $serializer->serialize($jwe, 0);

        // Mock the OpenIDConnectClient, only mocking the fetchURL method
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setConstructorArgs([
                'https://example.org',
                'fake-client-id',
                'fake-client-secret',
            ])
            ->onlyMethods(['fetchURL', 'handleJweResponse'])
            ->getMock();

        $client->expects($this->any())
            ->method('fetchURL')
            ->with($this->anything())
            ->will($this->returnCallback(function (string$url, ?string $post_body = null, array $headers = []) use ($userInfoResponse, $accessToken, $jwks, $client) {
                switch ($url) {
                    case 'https://example.org/.well-known/openid-configuration':
                        return new Response(200, 'application/json', json_encode([
                            'issuer' => 'https://example.org/',
                            'authorization_endpoint' => 'https://example.org/authorize',
                            'token_endpoint' => 'https://example.org/token',
                            'userinfo_endpoint' => 'https://example.org/userinfo',
                            'jwks_uri' => 'https://example.org/jwks',
                            'response_types_supported' => ['code', 'id_token'],
                            'subject_types_supported' => ['public'],
                            'id_token_signing_alg_values_supported' => ['RS256'],
                        ]));
                    case 'https://example.org/jwks':
                        return new Response(200, 'application/json', json_encode([
                            'keys' => $jwks
                        ]));
                    case 'https://example.org/userinfo':
                        $this->assertEquals('Authorization: Bearer '.$accessToken, $headers[0]);
                        return new Response(200, 'application/jwt', $userInfoResponse);
                    default:
                        throw new Exception("Unexpected request: $url");
                }
            }));

        $client->expects($this->any())
            ->method('handleJweResponse')
            ->with($userInfoResponse)
            ->willReturn(json_encode($userInfoClaims));

        // Simulate the state and nonce have been set in the session
        $_SESSION['openid_connect_state'] = $state;
        $_SESSION['openid_connect_nonce'] = $nonce;

        // Simulate incoming request with code and state
        $_REQUEST['code'] = $code;
        $_REQUEST['state'] = $state;

        $client->setAccessToken($accessToken);
        $client->setIdToken($idToken);

        // Get user info
        $userData = $client->requestUserInfo();

        // Verify call claims are correctly retrieved
        $this->assertEquals($firstName, $userData->given_name);
        $this->assertEquals($lastName, $userData->family_name);
        $this->assertEquals($email, $userData->email);
    }

    public function testRequestUserInfoSignedUnencrypted()
    {
        // Create a new RSA key pair for signing the ID token
        $private_key = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'RS256',
                'use' => 'sig'
            ]
        );
        $public_key = $private_key->toPublic();

        // Generate random values for the ID token
        $kid = bin2hex(random_bytes(6));
        $code = bin2hex(random_bytes(6));
        $nonce = bin2hex(random_bytes(6));
        $state = bin2hex(random_bytes(6));
        $firstName = $this->faker->firstName();
        $lastName = $this->faker->lastName();
        $email = $this->faker->email();
        $sub = $this->faker->uuid();
        $sid = $this->faker->uuid();

        $accessToken = 'fake-access-token';

        // Create claims for the ID token
        $idTokenClaims = [
            'exp' => time() + 60,
            'iat' => time(),
            'iss' => 'https://example.org',
            'aud' => 'fake-client-id',
            'sub' => $sub,
            'sid' => $sid,
            'nonce' => $nonce
        ];

        $userInfoClaims = [
            'iss' => 'https://example.org',
            'aud' => 'fake-client-id',
            'sub' => $sub,
            'given_name' => $firstName,
            'family_name' => $lastName,
            'email' => $email,
        ];

        // Create id token
        $idToken = $this->signClaims($idTokenClaims, $private_key, 'RS256', ['kid' => $kid]);

        // List of JWKs to be returned by the JWKS endpoint
        $jwks = [[
            'kid' => $kid,
            ...$public_key->jsonSerialize()
        ]];

        $userInfoResponse = $this->signClaims($userInfoClaims, $private_key, 'RS256', ['kid' => $kid]);

        // Mock the OpenIDConnectClient, only mocking the fetchURL method
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setConstructorArgs([
                'https://example.org',
                'fake-client-id',
                'fake-client-secret',
            ])
            ->onlyMethods(['fetchURL'])
            ->getMock();

        $client->expects($this->any())
            ->method('fetchURL')
            ->with($this->anything())
            ->will($this->returnCallback(function (string$url, ?string $post_body = null, array $headers = []) use ($userInfoResponse, $accessToken, $jwks, $client) {
                switch ($url) {
                    case 'https://example.org/.well-known/openid-configuration':
                        return new Response(200, 'application/json', json_encode([
                            'issuer' => 'https://example.org/',
                            'authorization_endpoint' => 'https://example.org/authorize',
                            'token_endpoint' => 'https://example.org/token',
                            'userinfo_endpoint' => 'https://example.org/userinfo',
                            'jwks_uri' => 'https://example.org/jwks',
                            'response_types_supported' => ['code', 'id_token'],
                            'subject_types_supported' => ['public'],
                            'id_token_signing_alg_values_supported' => ['RS256'],
                        ]));
                    case 'https://example.org/jwks':
                        return new Response(200, 'application/json', json_encode([
                            'keys' => $jwks
                        ]));
                    case 'https://example.org/userinfo':
                        $this->assertEquals('Authorization: Bearer '.$accessToken, $headers[0]);
                        return new Response(200, 'application/jwt', $userInfoResponse);
                    default:
                        throw new Exception("Unexpected request: $url");
                }
            }));

        // Simulate the state and nonce have been set in the session
        $_SESSION['openid_connect_state'] = $state;
        $_SESSION['openid_connect_nonce'] = $nonce;

        // Simulate incoming request with code and state
        $_REQUEST['code'] = $code;
        $_REQUEST['state'] = $state;

        $client->setAccessToken($accessToken);
        $client->setIdToken($idToken);

        // Get user info
        $userData = $client->requestUserInfo();

        // Verify call claims are correctly retrieved
        $this->assertEquals($firstName, $userData->given_name);
        $this->assertEquals($lastName, $userData->family_name);
        $this->assertEquals($email, $userData->email);
    }

    public function testRequestUserInfoSignedEncrypted()
    {
        // Create a new RSA key pair for signing the ID token
        $private_key = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'RS256',
                'use' => 'sig'
            ]
        );
        $public_key = $private_key->toPublic();

        // Create a new RSA key pair for encrypting the user info response
        $encryption_key = JWKFactory::createRSAKey(
            4096,
            [
                'alg' => 'RSA-OAEP-256',
                'use' => 'enc'
            ]
        );


        // Generate random values for the ID token
        $kid = bin2hex(random_bytes(6));
        $code = bin2hex(random_bytes(6));
        $nonce = bin2hex(random_bytes(6));
        $state = bin2hex(random_bytes(6));
        $firstName = $this->faker->firstName();
        $lastName = $this->faker->lastName();
        $email = $this->faker->email();
        $sub = $this->faker->uuid();
        $sid = $this->faker->uuid();

        $accessToken = 'fake-access-token';

        // Create claims for the ID token
        $idTokenClaims = [
            'exp' => time() + 60,
            'iat' => time(),
            'iss' => 'https://example.org',
            'aud' => 'fake-client-id',
            'sub' => $sub,
            'sid' => $sid,
            'nonce' => $nonce
        ];

        $userInfoClaims = [
            'iss' => 'https://example.org',
            'aud' => 'fake-client-id',
            'sub' => $sub,
            'given_name' => $firstName,
            'family_name' => $lastName,
            'email' => $email,
        ];

        // Create id token
        $idToken = $this->signClaims($idTokenClaims, $private_key, 'RS256', ['kid' => $kid]);

        // List of JWKs to be returned by the JWKS endpoint
        $jwks = [[
            'kid' => $kid,
            ...$public_key->jsonSerialize()
        ]];


        $keyEncryptionAlgorithmManager = new AlgorithmManager([
            new RSAOAEP256(),
        ]);
        $contentEncryptionAlgorithmManager = new AlgorithmManager([
            new A128CBCHS256(),
        ]);

        $jweBuilder = new JWEBuilder(
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
        );

        $jws = $this->signClaims($userInfoClaims, $private_key, 'RS256', ['kid' => $kid]);

        $jwe = $jweBuilder
            ->create()
            ->withPayload($jws)
            ->withSharedProtectedHeader([
                'alg' => 'RSA-OAEP-256',
                'enc' => 'A128CBC-HS256',
                'cty' => 'JWT',
            ])
            ->addRecipient($encryption_key->toPublic())
            ->build();

        $serializer = new \Jose\Component\Encryption\Serializer\CompactSerializer();

        $userInfoResponse = $serializer->serialize($jwe, 0);

        // Mock the OpenIDConnectClient, only mocking the fetchURL method
        $client = $this->getMockBuilder(OpenIDConnectClient::class)
            ->setConstructorArgs([
                'https://example.org',
                'fake-client-id',
                'fake-client-secret',
            ])
            ->onlyMethods(['fetchURL', 'handleJweResponse'])
            ->getMock();

        $client->expects($this->any())
            ->method('fetchURL')
            ->with($this->anything())
            ->will($this->returnCallback(function (string$url, ?string $post_body = null, array $headers = []) use ($userInfoResponse, $accessToken, $jwks, $client) {
                switch ($url) {
                    case 'https://example.org/.well-known/openid-configuration':
                        return new Response(200, 'application/json', json_encode([
                            'issuer' => 'https://example.org/',
                            'authorization_endpoint' => 'https://example.org/authorize',
                            'token_endpoint' => 'https://example.org/token',
                            'userinfo_endpoint' => 'https://example.org/userinfo',
                            'jwks_uri' => 'https://example.org/jwks',
                            'response_types_supported' => ['code', 'id_token'],
                            'subject_types_supported' => ['public'],
                            'id_token_signing_alg_values_supported' => ['RS256'],
                        ]));
                    case 'https://example.org/jwks':
                        return new Response(200, 'application/json', json_encode([
                            'keys' => $jwks
                        ]));
                    case 'https://example.org/userinfo':
                        $this->assertEquals('Authorization: Bearer '.$accessToken, $headers[0]);
                        return new Response(200, 'application/jwt', $userInfoResponse);
                    default:
                        throw new Exception("Unexpected request: $url");
                }
            }));

        $client->expects($this->any())
            ->method('handleJweResponse')
            ->with($userInfoResponse)
            ->willReturn($jws);

        // Simulate the state and nonce have been set in the session
        $_SESSION['openid_connect_state'] = $state;
        $_SESSION['openid_connect_nonce'] = $nonce;

        // Simulate incoming request with code and state
        $_REQUEST['code'] = $code;
        $_REQUEST['state'] = $state;

        $client->setAccessToken($accessToken);
        $client->setIdToken($idToken);

        // Get user info
        $userData = $client->requestUserInfo();

        // Verify call claims are correctly retrieved
        $this->assertEquals($firstName, $userData->given_name);
        $this->assertEquals($lastName, $userData->family_name);
        $this->assertEquals($email, $userData->email);
    }


}
