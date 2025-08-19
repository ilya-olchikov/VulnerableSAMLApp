import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('POST /update', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'bopla', 'broken_saml_auth', 'secret_tokens'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: {
        user_roles: [
          'admin',
          'users',
          'administrators',
          'administratorsbutnot',
          'PlatformConfiguration'
        ]
      }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/update`,
      body: {
        wantMessagesSigned: 'true',
        wantAssertionsSigned: 'false',
        signMetadata: 'true',
        validMessage: 'true',
        validAssertion: 'false',
        'cve-2017-11427': 'true'
      },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
});
