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

test('GET /complaints', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'id_enumeration', 'stored_xss', 'sqli', 'full_path_disclosure'],
      attackParamLocations: [AttackParamLocation.PATH, AttackParamLocation.QUERY],
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
      method: HttpMethod.GET,
      url: `${baseUrl}/complaints`
    });
});
