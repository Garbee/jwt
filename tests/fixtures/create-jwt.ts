const createMockJwt = function(payload: object, secret = 'mock-secret') {
  const base64Encode = (obj: object | string) => {
    return Buffer.from(
      JSON.stringify(obj),
    )
    .toString('base64')
    .replaceAll('=', '');
  };

  const header = {
    alg: 'HS256',
    typ: 'JWT',
  };

  const encodedHeader = base64Encode(header);
  const encodedPayload = base64Encode(payload);
  const signature = base64Encode(secret);

  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

export {
  createMockJwt,
};
