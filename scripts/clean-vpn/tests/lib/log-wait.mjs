/**
 * @param {import('stream').Readable} stream
 * @param {RegExp} re
 * @param {number} timeoutMs
 */
export function waitForLog(stream, re, timeoutMs) {
  return new Promise((resolve, reject) => {
    /** @type {string} */
    let buf = '';
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`timeout ${timeoutMs}ms waiting for ${re}`));
    }, timeoutMs);

    const onData = (chunk) => {
      buf += chunk.toString();
      if (buf.length > 256_000) buf = buf.slice(-128_000);
      if (re.test(buf)) {
        cleanup();
        resolve(buf);
      }
    };

    const onErr = (err) => {
      cleanup();
      reject(err);
    };

    const cleanup = () => {
      clearTimeout(timer);
      stream.off('data', onData);
      stream.off('error', onErr);
    };

    stream.on('data', onData);
    stream.on('error', onErr);
    if (re.test(buf)) {
      cleanup();
      resolve(buf);
    }
  });
}
