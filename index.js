#!/usr/bin/env node
import { readFile, readdir } from 'fs/promises';
import { join } from 'path';
import chalk from 'chalk';
import { parse } from '@babel/parser';
import traverse from '@babel/traverse';
import { promisify } from 'util';
import { exec } from 'child_process';
import https from 'https';
const execAsync = promisify(exec);
const includeDev = process.argv[process.argv.length - 1] === '--dev';
async function findFiles(dir, extensions) {
    const files = [];
    async function scan(directory) {
        const entries = await readdir(directory, { withFileTypes: true });
        for (const entry of entries) {
            const path = join(directory, entry.name);
            if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
                await scan(path);
            }
            else if (entry.isFile() && extensions.some(ext => entry.name.endsWith(ext))) {
                files.push(path);
            }
        }
    }
    await scan(dir);
    return files;
}
async function extractImports(filePath) {
    const imports = new Set();
    const content = await readFile(filePath, 'utf-8');
    try {
        const ast = parse(content, {
            sourceType: 'module',
            plugins: ['typescript', 'jsx'],
        });
        traverse.default(ast, {
            ImportDeclaration({ node }) {
                const moduleName = node.source.value;
                if (!moduleName.startsWith('.') && !moduleName.startsWith('/')) {
                    imports.add(moduleName.split('/')[0]);
                }
            },
            CallExpression({ node }) {
                if (node.callee.type === 'Identifier' &&
                    node.callee.name === 'require' &&
                    node.arguments[0]?.type === 'StringLiteral') {
                    const moduleName = node.arguments[0].value;
                    if (!moduleName.startsWith('.') && !moduleName.startsWith('/')) {
                        imports.add(moduleName.split('/')[0]);
                    }
                }
            },
        });
    }
    catch (error) {
        console.error(error);
        console.error(chalk.yellow(`Warning: Could not parse ${filePath}`));
    }
    return imports;
}
async function getLatestVersion(packageName) {
    try {
        const { stdout } = await execAsync(`npm view ${packageName} version`);
        return stdout.trim();
    }
    catch (error) {
        return 'unknown';
    }
}
function checkVulnerabilities(packageName, version) {
    return new Promise((resolve) => {
        const requestBody = JSON.stringify({ [packageName]: [version] });
        const options = {
            hostname: 'registry.npmjs.org',
            path: '/-/npm/v1/security/advisories/bulk',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': requestBody.length
            }
        };
        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                try {
                    const response = JSON.parse(data);
                    if (response.error) {
                        resolve([]);
                        return;
                    }
                    let vulns = [];
                    Object.entries(response)
                        .forEach(([key, advisories]) => {
                        vulns = [
                            ...vulns,
                            ...(advisories ?? []).map(adv => ({
                                package: key,
                                ...adv,
                            })),
                        ];
                    });
                    vulns = vulns
                        .filter(adv => {
                        return adv.vulnerable_versions.includes(version);
                    })
                        .map(adv => ({
                        package: adv.package,
                        title: adv.title,
                        severity: adv.severity,
                        cwe: adv.cwe,
                        cvss: adv.cvss,
                        advisory: adv.url
                    }));
                    resolve(vulns);
                }
                catch (error) {
                    resolve([]);
                }
            });
        });
        req.on('error', () => resolve([]));
        req.write(requestBody);
        req.end();
    });
}
async function checkDependencies(maxConcurrent = 5) {
    console.log(chalk.blue('📦 Analyzing dependencies...'));
    // Read package.json
    const packageJson = JSON.parse(await readFile('package.json', 'utf-8'));
    let allDependencies = packageJson.dependencies;
    if (includeDev) {
        allDependencies = {
            ...allDependencies,
            ...packageJson.devDependencies,
        };
    }
    // Find all JS/TS files
    const files = await findFiles(process.cwd(), ['.js', '.jsx', '.ts', '.tsx']);
    console.log(chalk.gray(`Found ${files.length} files to analyze`));
    // Extract all imports
    const usedDependencies = new Set();
    for (const file of files) {
        const imports = await extractImports(file);
        imports.forEach(imp => usedDependencies.add(imp));
    }
    // Create dependency info map
    const dependencyMap = new Map();
    for (const [name, version] of Object.entries(allDependencies)) {
        dependencyMap.set(name, {
            name,
            version: version?.replace(/[^0-9.]/g, '') || 'unknown',
            isUsed: usedDependencies.has(name),
        });
    }
    // Check latest versions and vulnerabilities concurrently
    const chunks = Array.from(dependencyMap.keys())
        .reduce((acc, _, i, arr) => {
        if (i % maxConcurrent === 0) {
            acc.push(arr.slice(i, i + maxConcurrent));
        }
        return acc;
    }, []);
    console.log(chalk.blue('🔍 Checking latest versions and vulnerabilities...'));
    for (const chunk of chunks) {
        await Promise.all(chunk.map(async (name) => {
            const info = dependencyMap.get(name);
            const [latestVersion, vulnerabilities] = await Promise.all([
                getLatestVersion(name),
                checkVulnerabilities(name, info.version)
            ]);
            info.latestVersion = latestVersion;
            info.vulnerabilities = vulnerabilities;
        }));
    }
    // Output results
    console.log('\n' + chalk.bold('📊 Analysis Results:\n'));
    // Unused dependencies
    const unused = Array.from(dependencyMap.values()).filter(dep => !dep.isUsed);
    if (unused.length > 0) {
        console.log(chalk.red('❌ Unused Dependencies:'));
        unused.forEach(dep => {
            console.log(`  ${chalk.yellow(dep.name)} @ ${dep.version}`);
        });
    }
    else {
        console.log(chalk.green('✅ All dependencies are being used!'));
    }
    // Version comparison
    console.log('\n' + chalk.bold('📈 Potential Updates:'));
    for (const dep of dependencyMap.values()) {
        if (dep.latestVersion && dep.latestVersion !== 'unknown' && dep.latestVersion !== dep.version) {
            console.log(`  ${chalk.cyan(dep.name)}: ${chalk.yellow(dep.version)} → ${chalk.green(dep.latestVersion)}`);
        }
    }
    // Security vulnerabilities
    console.log('\n' + chalk.bold('🔒 Security Analysis:'));
    let hasVulnerabilities = false;
    for (const dep of dependencyMap.values()) {
        if (dep.vulnerabilities && dep.vulnerabilities.length > 0) {
            hasVulnerabilities = true;
            console.log(`\n  ${chalk.red('⚠️')} ${chalk.bold(dep.name)} @ ${dep.version}:`);
            dep.vulnerabilities.forEach(vuln => {
                console.log(`    ${chalk.red('•')} ${vuln.title}`);
                console.log(`      Severity: ${getSeverityColor(vuln.severity)(vuln.severity)}`);
                console.log(`      CVSS Score: ${getCVSSColor(vuln.cvss.score)(vuln.cvss.score)}`);
                console.log(`      Advisory: ${chalk.blue(vuln.advisory)}`);
            });
        }
    }
    if (!hasVulnerabilities) {
        console.log(chalk.green('✅ No known vulnerabilities found!'));
    }
}
function getSeverityColor(severity) {
    switch (severity.toLowerCase()) {
        case 'critical': return chalk.red.bold;
        case 'high': return chalk.red;
        case 'moderate': return chalk.yellow;
        case 'low': return chalk.gray;
        default: return chalk.white;
    }
}
function getCVSSColor(score) {
    if (score >= 9.0)
        return chalk.red.bold;
    if (score >= 7.0)
        return chalk.red;
    if (score >= 4.0)
        return chalk.yellow;
    return chalk.gray;
}
// Run the analysis
checkDependencies().catch(error => {
    console.error(chalk.red('Error:'), error);
    process.exit(1);
});
