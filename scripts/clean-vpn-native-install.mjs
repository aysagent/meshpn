#!/usr/bin/env node
import { installNative } from './lib/native-install.mjs';
const options = {};
try {
  for (const arg of process.argv.slice(2)) {
    if (arg === '--apply' && !options.apply) { options.apply = true; continue; }
    const m = /^--(root|name|binary|config|network-unit|guard-unit|site-profile)=(.+)$/.exec(arg);
    if (!m) throw Error('usage');
    const key = ({ 'network-unit': 'networkUnit', 'guard-unit': 'guardUnit', 'site-profile': 'siteProfile' })[m[1]] ?? m[1];
    if (key in options) throw Error('duplicate_option'); options[key] = m[2];
  }
  if (options.apply && (options.root ?? '/') === '/' && process.getuid() !== 0) throw Error('root_required');
  console.log(JSON.stringify(installNative(options)));
} catch (error) {
  const known = ['usage', 'duplicate_option', 'root_required', 'unsafe_path', 'symlink_source', 'unsafe_source', 'unsafe_parent',
    'unsafe_destination', 'symlink_destination', 'invalid_instance', 'invalid_apply', 'self_dependency', 'instance_already_present',
    'not_native_service_engine', 'native_service_absolute_safe_path_required', 'native_service_protection_dependency_required',
    'native_service_distinct_dependencies_required'];
  const code = known.includes(error.message) ? error.message : ['ENOENT', 'EACCES', 'EEXIST', 'ENOSPC'].includes(error.code) ? error.code : 'validation_or_publication_failed';
  console.error(JSON.stringify({ status: 'refused-or-incomplete', code, note: 'No overwrite or blind cleanup. Inspect target/units; no services were started by this installer.' }));
  process.exitCode = 1;
}
