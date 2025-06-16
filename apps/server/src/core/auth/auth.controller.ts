import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { LoginDto } from './dto/login.dto';
import { AuthService } from './services/auth.service';
import { SetupGuard } from './guards/setup.guard';
import { EnvironmentService } from '../../integrations/environment/environment.service';
import { CreateAdminUserDto } from './dto/create-admin-user.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { AuthUser } from '../../common/decorators/auth-user.decorator';
import { User, Workspace } from '@docmost/db/types/entity.types';
import { AuthWorkspace } from '../../common/decorators/auth-workspace.decorator';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { PasswordResetDto } from './dto/password-reset.dto';
import { VerifyUserTokenDto } from './dto/verify-user-token.dto';
import { WorkspaceService } from '../workspace/services/workspace.service';
import { FastifyReply, FastifyRequest } from 'fastify';
import { Issuer } from 'openid-client';
import { addDays } from 'date-fns';
import { validateSsoEnforcement } from './auth.util';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly workspaceService: WorkspaceService,
    private authService: AuthService,
    private environmentService: EnvironmentService,
  ) {}

  @HttpCode(HttpStatus.OK)
  @Post('login')
  async login(
    @AuthWorkspace() workspace: Workspace,
    @Res({ passthrough: true }) res: FastifyReply,
    @Body() loginInput: LoginDto,
  ) {
    validateSsoEnforcement(workspace);

    const authToken = await this.authService.login(loginInput, workspace.id);
    this.setAuthCookie(res, authToken);
  }

  @Get('cb')
  @HttpCode(HttpStatus.TEMPORARY_REDIRECT)
  async callback(@Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    const token = await this.authService.oidcLogin(req);

    this.setAuthCookie(reply, token);

    return reply.redirect(`${this.environmentService.getWebUrl()}/home`);
  }

  @Get('oauth-redirect')
  @HttpCode(HttpStatus.TEMPORARY_REDIRECT)
  async oauthRedirect(
    @AuthWorkspace() workspace: Workspace,
    @Res() reply: FastifyReply,
  ) {
    const redirectUri = `${this.environmentService.getAppUrl()}/api/auth/cb`;

    const workspacePublicData = this.workspaceService.getWorkspacePublicData(workspace.id);
    const authProvider = (await workspacePublicData).authProviders.find((provider) => provider.type === 'oidc');

    if (!authProvider.oidcIssuer) {
      return reply.redirect(`${this.environmentService.getAppUrl()}/login`);
    }

    // const issuer = await Issuer.discover(authProvider.oidcIssuer);
    const issuerUrl = authProvider.oidcIssuer;
    const issuer = new Issuer({
      issuer: issuerUrl,
      authorization_endpoint: issuerUrl + '/oauth/authorize',
      token_endpoint: issuerUrl + '/oauth/token',
      userinfo_endpoint: issuerUrl + '/oauth/userinfo',
      jwks_uri: issuerUrl + '/oauth/discovery/keys',
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      id_token_signing_alg_values_supported: ['RS256'],
    });
    console.log("========= issuer111 ========="+JSON.stringify(issuer));
    
    if (!issuer.metadata.authorization_endpoint || !authProvider.oidcClientId) {
      return reply.redirect(`${this.environmentService.getAppUrl()}/login`);
    }

    const authRedirect =
      `${issuer.metadata.authorization_endpoint}` +
      `?response_type=code` +
      `&client_id=${authProvider.oidcClientId}` +
      `&redirect_uri=${redirectUri}` +
      `&scope=openid profile email` +
      `&state=${workspace.id}` +
      `&prompt=login`;

    return reply.redirect(authRedirect);
  }

  @UseGuards(SetupGuard)
  @HttpCode(HttpStatus.OK)
  @Post('setup')
  async setupWorkspace(
    @Res({ passthrough: true }) res: FastifyReply,
    @Body() createAdminUserDto: CreateAdminUserDto,
  ) {
    const { workspace, authToken } =
      await this.authService.setup(createAdminUserDto);

    this.setAuthCookie(res, authToken);
    return workspace;
  }

  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('change-password')
  async changePassword(
    @Body() dto: ChangePasswordDto,
    @AuthUser() user: User,
    @AuthWorkspace() workspace: Workspace,
  ) {
    return this.authService.changePassword(dto, user.id, workspace.id);
  }

  @HttpCode(HttpStatus.OK)
  @Post('forgot-password')
  async forgotPassword(
    @Body() forgotPasswordDto: ForgotPasswordDto,
    @AuthWorkspace() workspace: Workspace,
  ) {
    validateSsoEnforcement(workspace);
    return this.authService.forgotPassword(forgotPasswordDto, workspace);
  }

  @HttpCode(HttpStatus.OK)
  @Post('password-reset')
  async passwordReset(
    @Res({ passthrough: true }) res: FastifyReply,
    @Body() passwordResetDto: PasswordResetDto,
    @AuthWorkspace() workspace: Workspace,
  ) {
    const authToken = await this.authService.passwordReset(
      passwordResetDto,
      workspace.id,
    );
    this.setAuthCookie(res, authToken);
  }

  @HttpCode(HttpStatus.OK)
  @Post('verify-token')
  async verifyResetToken(
    @Body() verifyUserTokenDto: VerifyUserTokenDto,
    @AuthWorkspace() workspace: Workspace,
  ) {
    return this.authService.verifyUserToken(verifyUserTokenDto, workspace.id);
  }

  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('collab-token')
  async collabToken(
    @AuthUser() user: User,
    @AuthWorkspace() workspace: Workspace,
  ) {
    return this.authService.getCollabToken(user.id, workspace.id);
  }

  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Post('logout')
  async logout(@Res({ passthrough: true }) res: FastifyReply) {
    this.clearAuthCookie(res);
  }

  setAuthCookie(res: FastifyReply, token: string) {
    res.setCookie('authToken', token, {
      httpOnly: true,
      path: '/',
      expires: addDays(new Date(), 30),
      secure: this.environmentService.isHttps(),
    });
  }

  clearAuthCookie(res: FastifyReply) {
    res.clearCookie('authToken', {
        path: '/',
        secure: this.environmentService.isHttps(),
    });
  }
}
