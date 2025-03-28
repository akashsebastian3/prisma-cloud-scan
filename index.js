const fs = require('fs');
const axios = require('axios');
const core = require('@actions/core');
const { exec } = require('@actions/exec');
const tc = require('@actions/tool-cache');

const TRUE_VALUES = ['true', 'yes', 'y', '1'];

function toSentenceCase(string) {
  return string[0].toUpperCase() + string.slice(1).toLowerCase();
}

function joinUrlPath(...parts) {
  return '/' + parts.filter(part => part !== '/').map(part => part.replace(/(^\/|\/$)/g, '')).join('/');
}

async function authenticate(url, user, pass) {
  const parsedUrl = new URL(url);
  parsedUrl.pathname = joinUrlPath(parsedUrl.pathname, '/api/v1/authenticate');
  const res = await axios.post(parsedUrl.toString(), { username: user, password: pass }, {
    headers: { 'Content-Type': 'application/json' }
  });
  return res.data.token;
}

async function getVersion(url, token) {
  const parsedUrl = new URL(url);
  parsedUrl.pathname = joinUrlPath(parsedUrl.pathname, '/api/v1/version');
  const res = await axios.get(parsedUrl.toString(), {
    headers: { Authorization: `Bearer ${token}` }
  });
  return res.data;
}

async function getTwistcli(version, url, token) {
  const parsedUrl = new URL(url);
  parsedUrl.pathname = joinUrlPath(parsedUrl.pathname, '/api/v1/util/twistcli');
  let twistcli = tc.find('twistcli', version);
  if (!twistcli) {
    const twistcliPath = await tc.downloadTool(parsedUrl.toString(), undefined, `Bearer ${token}`);
    await exec(`chmod a+x ${twistcliPath}`);
    twistcli = await tc.cacheFile(twistcliPath, 'twistcli', 'twistcli', version);
  }
  core.addPath(twistcli);
}

function convertPrismaSeverity(severity) {
  switch (severity) {
    case "critical": return "error";
    case "high": return "warning";
    case "medium": return "note";
    case "low": return "none";
    default: throw new Error(`Unknown severity: ${severity}`);
  }
}

function formatSarifToolDriverRules(results) {
  const result = results[0];
  const vulns = (result.vulnerabilities || []).map(v => ({
    id: v.id,
    shortDescription: { text: `[Prisma Cloud] ${v.id} in ${v.packageName} (${v.severity})` },
    fullDescription: { text: `${toSentenceCase(v.severity)} severity ${v.id} found in ${v.packageName} version ${v.packageVersion}` },
    help: {
      text: '',
      markdown: `| CVE | Severity | CVSS | Package | Version | Fix Status | Published | Discovered |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [${v.id}](${v.link}) | ${v.severity} | ${v.cvss || 'N/A'} | ${v.packageName} | ${v.packageVersion} | ${v.status || 'not fixed'} | ${v.publishedDate} | ${v.discoveredDate} |`
    }
  }));

  const comps = (result.compliances || []).map(c => ({
    id: c.id,
    shortDescription: { text: `[Prisma Cloud] Compliance check ${c.id} violated (${c.severity})` },
    fullDescription: { text: `${toSentenceCase(c.severity)} severity compliance check "${c.title}" violated` },
    help: {
      text: '',
      markdown: `| Compliance Check | Severity | Title |
| --- | --- | --- |
| ${c.id} | ${c.severity} | ${c.title} |`
    }
  }));

  return [...vulns, ...comps];
}

function formatSarifResults(results) {
  const result = results[0];
  const findings = [...(result.vulnerabilities || []), ...(result.compliances || [])];
  return findings.map(f => ({
    ruleId: f.id,
    level: convertPrismaSeverity(f.severity),
    message: { text: `Description:\n${f.description}` },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: result.name },
        region: { startLine: 1, startColumn: 1, endLine: 1, endColumn: 1 }
      }
    }]
  }));
}

function formatSarif(version, resultsFile) {
  const scan = JSON.parse(fs.readFileSync(resultsFile, 'utf8'));
  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'Prisma Cloud (twistcli)',
          version,
          rules: formatSarifToolDriverRules(scan.results)
        }
      },
      results: formatSarifResults(scan.results)
    }]
  };
}

async function scan() {
  const consoleUrl = core.getInput('pcc_console_url');
  const username = core.getInput('pcc_user');
  const password = core.getInput('pcc_pass');
  const imageName = core.getInput('image_name');
  const containerized = core.getInput('containerized')?.toLowerCase();
  const dockerAddress = core.getInput('docker_address');
  const dockerTlsCaCert = core.getInput('docker_tlscacert');
  const dockerTlsCert = core.getInput('docker_tlscert');
  const dockerTlsKey = core.getInput('docker_tlskey');
  const resultsFile = core.getInput('results_file');
  const sarifFile = core.getInput('sarif_file');

  const token = await authenticate(consoleUrl, username, password);
  const version = (await getVersion(consoleUrl, token)).replace(/"/g, '');
  await getTwistcli(version, consoleUrl, token);

  let twistcliCmd = ['twistcli', 'images', 'scan',
    `--address ${consoleUrl}`,
    `--user ${username}`,
    `--password ${password}`,
    `--output-file ${resultsFile}`,
    '--details',
    '--custom-label traceable'
  ];

  if (dockerAddress) twistcliCmd.push(`--docker-address ${dockerAddress}`);
  if (dockerTlsCaCert) twistcliCmd.push(`--docker-tlscacert ${dockerTlsCaCert}`);
  if (dockerTlsCert) twistcliCmd.push(`--docker-tlscert ${dockerTlsCert}`);
  if (dockerTlsKey) twistcliCmd.push(`--docker-tlskey ${dockerTlsKey}`);
  if (TRUE_VALUES.includes(containerized)) twistcliCmd.push('--containerized');

  twistcliCmd.push(imageName);

  const exitCode = await exec(twistcliCmd.join(' '), undefined, { ignoreReturnCode: true });
  if (exitCode > 0) core.setFailed('Image scan failed');

  fs.writeFileSync(sarifFile, JSON.stringify(formatSarif(version, resultsFile)));
  core.setOutput('results_file', resultsFile);
  core.setOutput('sarif_file', sarifFile);
}

if (require.main === module) {
  scan().catch(err => core.setFailed(err.message));
}
