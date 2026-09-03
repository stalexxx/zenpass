export const redactedPaths = [
  'req.headers.authorization', 'req.headers.cookie', 'req.body', 'res.headers["set-cookie"]',
  '*.password', '*.masterPassword', '*.recoveryKey', '*.clientMessage', '*.ciphertext', '*.bundle', '*.recoveryProof'
];

export function loggerOptions(level = 'info') {
  return {
    level,
    redact: { paths: redactedPaths, censor: '[REDACTED]' },
    serializers: {
      req: (req) => ({ method: req.method, url: req.url, requestId: req.id }),
      res: (res) => ({ statusCode: res.statusCode })
    }
  };
}
