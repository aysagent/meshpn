#!/usr/bin/env node
import {inspectNativeUsb} from './lib/native-usb-preflight.mjs';
if(process.argv.length!==2){console.error('Usage: node scripts/clean-vpn-native-usb-preflight.mjs');process.exitCode=1;}
else {const report=inspectNativeUsb();console.log(JSON.stringify(report,null,2));if(report.status!=='passed')process.exitCode=1;}
