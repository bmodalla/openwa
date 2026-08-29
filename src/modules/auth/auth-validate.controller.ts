import { Controller, Post, HttpCode, HttpStatus, Body, Req, UnauthorizedException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import type { Request } from 'express';
import { Public } from './decorators/auth.decorators';
import { ValidateApiKeyResponseDto, LoginDto } from './dto';
import { AuthService } from './auth.service';

@ApiTags('auth')
@Public()
@Controller('auth')
export class AuthValidateController {
  constructor(private readonly authService?: AuthService) {}

  @Public()
  @Post('validate')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login using username and password' })
  @ApiResponse({ status: 200, description: 'Authentication is valid', type: ValidateApiKeyResponseDto })
  @ApiResponse({ status: 401, description: 'Invalid username or password' })
  async validate(
    @Body() body?: LoginDto,
    @Req() req?: Request,
  ): Promise<{ valid: boolean; role?: string; apiKey?: string }> {
    // 1. Primary path: username & password authentication
    if (body && (body.username !== undefined || body.password !== undefined)) {
      if (!body.username || !body.password) {
        throw new UnauthorizedException('Username and password are required');
      }
      if (this.authService) {
        return this.authService.validateCredentials(body.username, body.password);
      }
      const expectedUser = process.env.ADMIN_USERNAME || 'admin';
      const expectedPass = process.env.ADMIN_PASSWORD || 'admin';
      if (body.username === expectedUser && body.password === expectedPass) {
        return { valid: true, role: 'admin' };
      }
      throw new UnauthorizedException('Invalid username or password');
    }

    // 2. Session refresh path: existing session token / key in headers on page reload
    const headerKey = req ? this.extractApiKey(req) : undefined;
    if (headerKey && this.authService) {
      const validated = await this.authService.validateApiKey(headerKey);
      return { valid: true, role: validated.role };
    }

    throw new UnauthorizedException('Invalid username or password');
  }

  private extractApiKey(request: Request): string | undefined {
    const xApiKey = request.headers?.['x-api-key'] as string;
    if (xApiKey) return xApiKey;

    const authHeader = request.headers?.['authorization'];
    if (authHeader?.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }

    return undefined;
  }
}


