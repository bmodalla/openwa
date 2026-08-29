import { AuthValidateController } from './auth-validate.controller';
import { ApiKeyRole } from './entities/api-key.entity';
import { AuthService } from './auth.service';
import { UnauthorizedException } from '@nestjs/common';

describe('AuthValidateController', () => {
  let mockAuthService: Partial<AuthService>;
  let controller: AuthValidateController;

  beforeEach(() => {
    mockAuthService = {
      validateCredentials: jest.fn().mockImplementation((username?: string, password?: string) => {
        if (username === 'admin' && password === 'admin') {
          return Promise.resolve({ valid: true, role: ApiKeyRole.ADMIN, apiKey: 'mock_admin_key' });
        }
        return Promise.reject(new UnauthorizedException('Invalid username or password'));
      }),
      validateApiKey: jest.fn().mockImplementation((key: string) => {
        if (key === 'valid-session-key') {
          return Promise.resolve({ id: 'k1', role: ApiKeyRole.ADMIN, isActive: true } as any);
        }
        return Promise.reject(new UnauthorizedException('Invalid API key'));
      }),
    };
    controller = new AuthValidateController(mockAuthService as AuthService);
  });

  it('validates valid username and password credentials (admin / admin)', async () => {
    const result = await controller.validate({ username: 'admin', password: 'admin' });
    expect(result).toEqual({
      valid: true,
      role: ApiKeyRole.ADMIN,
      apiKey: 'mock_admin_key',
    });
    expect(mockAuthService.validateCredentials).toHaveBeenCalledWith('admin', 'admin');
  });

  it('rejects invalid username and password credentials', async () => {
    await expect(controller.validate({ username: 'admin', password: 'wrong' })).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('rejects when username or password is missing', async () => {
    await expect(controller.validate({ username: '', password: '' })).rejects.toThrow(
      UnauthorizedException,
    );
    await expect(controller.validate(undefined)).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('validates existing session key in header on page reload', async () => {
    const mockReq = { headers: { 'x-api-key': 'valid-session-key' } } as any;
    const result = await controller.validate(undefined, mockReq);
    expect(result).toEqual({
      valid: true,
      role: ApiKeyRole.ADMIN,
    });
  });
});


