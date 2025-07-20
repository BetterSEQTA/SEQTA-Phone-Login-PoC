interface SeqtaSSOPayload {
  t: string;  // JWT token
  u: string;  // Server URL
  n: string;  // User number
}

interface SeqtaJWT {
  sub: string;    // Subject (user ID)
  exp: number;    // Expiration timestamp
  t: string;      // Type/role
  scope: string;  // Permission scope
}

export class SeqtaAuth {
  private static readonly DEEPLINK_PREFIX = 'seqtalearn://sso/';
  private static readonly JWT_HEADER = 'eyJhbGciOiJIUzI1NiJ9.';

  /**
   * Parses a Seqta Learn SSO deeplink into its components
   * @param deeplink The full deeplink URL
   * @returns Parsed SSO payload
   */
  static parseDeeplink(deeplink: string): SeqtaSSOPayload {
    if (!deeplink.startsWith(this.DEEPLINK_PREFIX)) {
      throw new Error('Invalid Seqta Learn deeplink format');
    }

    const encodedPayload = deeplink.slice(this.DEEPLINK_PREFIX.length);
    // First decode the URL encoding
    const urlDecoded = decodeURIComponent(encodedPayload);
    // Then decode the base64
    const decodedPayload = Buffer.from(urlDecoded, 'base64').toString('utf-8');
    return JSON.parse(decodedPayload) as SeqtaSSOPayload;
  }

  /**
   * Decodes a JWT token into its payload
   * @param token The JWT token
   * @returns Decoded JWT payload
   */
  static decodeJWT(token: string): SeqtaJWT {
    if (!token.startsWith(this.JWT_HEADER)) {
      throw new Error('Invalid JWT format');
    }

    const payload = token.split('.')[1];
    const decodedPayload = Buffer.from(payload, 'base64').toString('utf-8');
    return JSON.parse(decodedPayload) as SeqtaJWT;
  }

  /**
   * Validates a JWT token
   * @param token The JWT token to validate
   * @returns Whether the token is valid
   */
  static validateToken(token: string): boolean {
    try {
      const decoded = this.decodeJWT(token);
      const now = Math.floor(Date.now() / 1000);
      return decoded.exp > now;
    } catch {
      return false;
    }
  }

  /**
   * Creates a login request to the Seqta server
   * @param ssoPayload The SSO payload from the deeplink
   * @returns Login request configuration
   */
  static createLoginRequest(ssoPayload: SeqtaSSOPayload) {
    return {
      url: `${ssoPayload.u}/seqta/student/login`,
      headers: {
        'Content-Type': 'application/json',
        'X-User-Number': ssoPayload.n,
        'Accept': 'application/json',
        'Authorization': `Bearer ${ssoPayload.t}`
      },
      token: ssoPayload.t
    };
  }

  /**
   * Handles a Seqta Learn SSO deeplink
   * @param deeplink The full deeplink URL
   * @returns Login request configuration if valid
   */
  static handleDeeplink(deeplink: string) {
    try {
      const ssoPayload = this.parseDeeplink(deeplink);
      
      if (!this.validateToken(ssoPayload.t)) {
        throw new Error('JWT token has expired');
      }

      return this.createLoginRequest(ssoPayload);
    } catch (error) {
      console.error('Failed to handle Seqta Learn deeplink:', error);
      throw error;
    }
  }
} 
