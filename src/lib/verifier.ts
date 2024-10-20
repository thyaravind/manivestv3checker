import JSZip from 'jszip';

interface VerificationResult {
  totalFiles: number;
  checks: Array<{ name: string; status: 'pending' | 'success' | 'warning' | 'error'; filesWithIssues?: number }>;
  warnings: string[];
  errors: string[];
  manifestVersion: number;
  description: string;
  permissions: string[];
  hostPermissions: string[];
}

export async function verifyExtension(file: File): Promise<VerificationResult> {
  const result: VerificationResult = {
    totalFiles: 0,
    checks: [
      { name: 'Load ZIP file', status: 'pending' },
      { name: 'Find manifest.json', status: 'pending' },
      { name: 'Check manifest version', status: 'pending' },
      { name: 'Analyze JavaScript files', status: 'pending' },
      { name: 'Check content security policy', status: 'pending' },
      { name: 'Review permissions', status: 'pending' },
      { name: 'Check description length', status: 'pending' },
    ],
    warnings: [],
    errors: [],
    manifestVersion: 0,
    description: '',
    permissions: [],
    hostPermissions: [],
  };

  const zip = new JSZip();
  let contents;

  try {
    contents = await zip.loadAsync(file);
    result.checks[0].status = 'success';
  } catch (error) {
    result.checks[0].status = 'error';
    result.errors.push(`Unable to load the zip file. ${error.message}`);
    return result;
  }

  result.totalFiles = Object.keys(contents.files).length;

  // Find manifest.json
  const manifestFile = Object.values(contents.files).find(file => file.name.endsWith('manifest.json'));
  if (!manifestFile) {
    result.checks[1].status = 'error';
    result.errors.push('manifest.json not found in the zip file.');
    return result;
  }
  result.checks[1].status = 'success';

  let manifest;
  try {
    const manifestContent = await manifestFile.async('string');
    manifest = JSON.parse(manifestContent);
  } catch (error) {
    result.checks[1].status = 'error';
    result.errors.push(`Invalid manifest.json file. ${error.message}`);
    return result;
  }

  // Check manifest version
  result.manifestVersion = manifest.manifest_version;
  if (manifest.manifest_version !== 3) {
    result.checks[2].status = 'warning';
    result.warnings.push(`The extension is not using Manifest V3. Found: "manifest_version": ${manifest.manifest_version}`);
  } else {
    result.checks[2].status = 'success';
  }

  // Set description and check its length
  result.description = manifest.description || 'No description provided';
  if (result.description.length > 150) {
    result.checks[6].status = 'warning';
    result.warnings.push(`The description exceeds 150 characters (current length: ${result.description.length}). Chrome Web Store requires descriptions to be 150 characters or less.`);
  } else {
    result.checks[6].status = 'success';
  }

  // Check for remote code and potential policy violations
  const jsFiles = Object.values(contents.files).filter(file => file.name.endsWith('.js'));
  let jsViolationsFound = 0;
  for (const file of jsFiles) {
    const content = await file.async('string');
    const violations = checkJSFileForViolations(file.name, content);
    if (violations.length > 0) {
      jsViolationsFound++;
      result.warnings.push(`The file ${file.name} may contain policy violations:\n${violations.join('\n')}`);
    }
  }
  result.checks[3].status = jsViolationsFound > 0 ? 'warning' : 'success';
  if (jsViolationsFound > 0) {
    result.checks[3].filesWithIssues = jsViolationsFound;
  }

  // Check for content_security_policy
  if (manifest.content_security_policy) {
    result.checks[4].status = 'warning';
    result.warnings.push(`The extension uses a custom content security policy: ${JSON.stringify(manifest.content_security_policy)}`);
    
    // Check for disallowed CSP directives
    const extensionPages = manifest.content_security_policy.extension_pages;
    if (extensionPages) {
      const disallowedDirectives = ['script-src', 'object-src', 'worker-src']
        .filter(directive => {
          const value = extensionPages.match(new RegExp(`${directive}[^;]+`));
          return value && !value[0].includes("'self'") && !value[0].includes("'none'") && !value[0].includes("'wasm-unsafe-eval'");
        });
      
      if (disallowedDirectives.length > 0) {
        result.warnings.push(`The following CSP directives may have disallowed values: ${disallowedDirectives.join(', ')}`);
      }
    }
  } else {
    result.checks[4].status = 'success';
  }

  // Check permissions
  result.permissions = manifest.permissions || [];
  result.hostPermissions = manifest.host_permissions || [];

  if (result.hostPermissions.length > 0) {
    result.checks[5].status = 'warning';
    result.warnings.push('The extension requests host permissions, which may result in longer review times.');
    result.checks[5].filesWithIssues = 1;
  } else if (result.permissions.length > 0) {
    result.checks[5].status = 'warning';
    result.warnings.push(`Permissions requested: ${result.permissions.join(', ')}`);
    result.checks[5].filesWithIssues = 1;
  } else {
    result.checks[5].status = 'success';
  }

  return result;
}

function checkJSFileForViolations(fileName: string, content: string): string[] {
  const violations: string[] = [];
  const lines = content.split('\n');

  lines.forEach((line, index) => {
    const lineNumber = index + 1;
    const trimmedLine = line.trim();

    // Check for eval() or new Function()
    const evalMatch = trimmedLine.match(/\b(eval|new\s+Function)\s*\(/);
    if (evalMatch) {
      violations.push(`Line ${lineNumber}: Potential arbitrary code execution: "${evalMatch[0]}"`);
    }

    // Check for chrome.scripting.executeScript or chrome.tabs.executeScript
    const scriptInjectionMatch = trimmedLine.match(/chrome\.(scripting|tabs)\.executeScript/);
    if (scriptInjectionMatch) {
      violations.push(`Line ${lineNumber}: Uses script injection: "${scriptInjectionMatch[0]}"`);
    }

    // Check for potential remote code loading
    const remoteCodeMatch = trimmedLine.match(/\b(import|require)\s*\(\s*['"]https?:/);
    if (remoteCodeMatch) {
      violations.push(`Line ${lineNumber}: Potential remote code loading: "${remoteCodeMatch[0]}"`);
    }

    // Check for potential use of Service Workers
    const serviceWorkerMatch = trimmedLine.match(/navigator\.serviceWorker\.register/);
    if (serviceWorkerMatch) {
      violations.push(`Line ${lineNumber}: Service Worker registration (potential remote code channel): "${serviceWorkerMatch[0]}"`);
    }

    // Check for loading remote scripts
    const remoteScriptMatch = trimmedLine.match(/\.loadScript\s*\(\s*['"]|src\s*=\s*['"]https?:/);
    if (remoteScriptMatch) {
      violations.push(`Line ${lineNumber}: Potential remote script loading: "${remoteScriptMatch[0]}"`);
    }
  });

  return violations;
}