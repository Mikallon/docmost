import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { LoginDto } from '../dto/login.dto';
import { CreateUserDto } from '../dto/create-user.dto';
import { TokenService } from './token.service';
import { SignupService } from './signup.service';
import { CreateAdminUserDto } from '../dto/create-admin-user.dto';
import { UserRepo } from '@docmost/db/repos/user/user.repo';
import {
  comparePasswordHash,
  hashPassword,
  nanoIdGen,
} from '../../../common/helpers';
import { ChangePasswordDto } from '../dto/change-password.dto';
import { MailService } from '../../../integrations/mail/mail.service';
import ChangePasswordEmail from '@docmost/transactional/emails/change-password-email';
import { ForgotPasswordDto } from '../dto/forgot-password.dto';
import ForgotPasswordEmail from '@docmost/transactional/emails/forgot-password-email';
import { UserTokenRepo } from '@docmost/db/repos/user-token/user-token.repo';
import { PasswordResetDto } from '../dto/password-reset.dto';
import { FastifyRequest } from 'fastify';
import { Issuer } from 'openid-client';
import { WorkspaceRepo } from '@docmost/db/repos/workspace/workspace.repo';
import { UserRole } from 'src/common/helpers/types/permission';
import { WorkspaceService } from 'src/core/workspace/services/workspace.service';
import { GroupUserRepo } from '@docmost/db/repos/group/group-user.repo';
import { EnvironmentService } from 'src/integrations/environment/environment.service';
import { UserToken, Workspace } from '@docmost/db/types/entity.types';
import { UserTokenType } from '../auth.constants';
import { KyselyDB } from '@docmost/db/types/kysely.types';
import { InjectKysely } from 'nestjs-kysely';
import { executeTx } from '@docmost/db/utils';
import { VerifyUserTokenDto } from '../dto/verify-user-token.dto';
import { DomainService } from '../../../integrations/environment/domain.service';

@Injectable()
export class AuthService {
  constructor(
    private signupService: SignupService,
    private tokenService: TokenService,
    private userRepo: UserRepo,
    private userTokenRepo: UserTokenRepo,
    private mailService: MailService,
    private workspaceRepo: WorkspaceRepo,
    private groupUserRepo: GroupUserRepo,
    private workspaceService: WorkspaceService,
    private environmentService: EnvironmentService,
    private domainService: DomainService,
    @InjectKysely() private readonly db: KyselyDB,
  ) {}

  async login(loginDto: LoginDto, workspaceId: string) {
    const user = await this.userRepo.findByEmail(loginDto.email, workspaceId, {
      includePassword: true,
    });

    const errorMessage = 'email or password does not match';
    if (!user || user?.deletedAt) {
      throw new UnauthorizedException(errorMessage);
    }

    const isPasswordMatch = await comparePasswordHash(
      loginDto.password,
      user.password,
    );

    if (!isPasswordMatch) {
      throw new UnauthorizedException(errorMessage);
    }

    user.lastLoginAt = new Date();
    await this.userRepo.updateLastLogin(user.id, workspaceId);

    return this.tokenService.generateAccessToken(user);
  }

  async oidcLogin(req: FastifyRequest) {
    type QueryParams = {
      code: string;
      state: string;
    };

    function validateQuery(query: any): { success: true; data: QueryParams } | { success: false; error: string } {
      if (typeof query.code !== 'string') {
        return { success: false, error: 'Missing or invalid "code" parameter' };
      }
      if (typeof query.state !== 'string') {
        return { success: false, error: 'Missing or invalid "state" parameter' };
      }

      return { success: true, data: { code: query.code, state: query.state } };
    }
    
    const result = validateQuery(req.query);

    if (!result.success) {
      console.log("Missing or invalid parameters: " + JSON.stringify(result));
      throw new UnauthorizedException();
    }

    const query = result.data;

    if (!query) {
      throw new UnauthorizedException();
    }

    // const workspace = await this.workspaceRepo.findById(query.state);
    const workspaceId = query.state;
    const workspacePublicData = this.workspaceService.getWorkspacePublicData(workspaceId);
    const authProvider = (await workspacePublicData).authProviders.find((provider) => provider.type === 'oidc');

    if (
      !authProvider ||
      !authProvider.oidcIssuer ||
      !authProvider.oidcClientId ||
      !authProvider.oidcClientSecret
    ) {
      throw new UnauthorizedException();
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
    console.log("========= issuer222 ========="+JSON.stringify(issuer));

    const client = new issuer.Client({
      client_id: authProvider.oidcClientId,
      client_secret: authProvider.oidcClientSecret,
    });

    const redirectUri = `${this.environmentService.getAppUrl()}/api/auth/cb`;

    const params = client.callbackParams(req.raw);
    const tokenSet = await client.callback(redirectUri, params, {
      state: workspaceId,
    });

    const name = tokenSet.claims().name;
    const email = tokenSet.claims().email;

    if (!email) {
      throw new UnauthorizedException();
    }

    const user = await this.userRepo.findByEmail(email, workspaceId);

    if (!user) {
      // TODO: The rules for this should be confirmed where they are configured
      // if (
      //   workspace.oidcJITEnabled &&
      //   workspace.oidcDomains.includes(email.split('@')[1])
      // ) {
        const user = await this.userRepo.insertUser({
          name,
          email,
          role: UserRole.MEMBER,
          workspaceId: workspaceId,
          emailVerifiedAt: new Date(),
        });

        // TODO: This should really all happen in one function under the UserService
        await this.workspaceService.addUserToWorkspace(user.id, workspaceId);
        await this.groupUserRepo.addUserToDefaultGroup(user.id, workspaceId);

        return this.tokenService.generateAccessToken(user);
      // }

      // throw new UnauthorizedException();
    }

    return this.tokenService.generateAccessToken(user);
  }

  async register(createUserDto: CreateUserDto, workspaceId: string) {
    const user = await this.signupService.signup(createUserDto, workspaceId);
    return this.tokenService.generateAccessToken(user);
  }

  async setup(createAdminUserDto: CreateAdminUserDto) {
    const { workspace, user } =
      await this.signupService.initialSetup(createAdminUserDto);

    const authToken = await this.tokenService.generateAccessToken(user);
    return { workspace, authToken };
  }

  async changePassword(
    dto: ChangePasswordDto,
    userId: string,
    workspaceId: string,
  ): Promise<void> {
    const user = await this.userRepo.findById(userId, workspaceId, {
      includePassword: true,
    });

    if (!user || user.deletedAt) {
      throw new NotFoundException('User not found');
    }

    const comparePasswords = await comparePasswordHash(
      dto.oldPassword,
      user.password,
    );

    if (!comparePasswords) {
      throw new BadRequestException('Current password is incorrect');
    }

    const newPasswordHash = await hashPassword(dto.newPassword);
    await this.userRepo.updateUser(
      {
        password: newPasswordHash,
      },
      userId,
      workspaceId,
    );

    const emailTemplate = ChangePasswordEmail({ username: user.name });
    await this.mailService.sendToQueue({
      to: user.email,
      subject: 'Your password has been changed',
      template: emailTemplate,
    });
  }

  async forgotPassword(
    forgotPasswordDto: ForgotPasswordDto,
    workspace: Workspace,
  ): Promise<void> {
    const user = await this.userRepo.findByEmail(
      forgotPasswordDto.email,
      workspace.id,
    );

    if (!user || user.deletedAt) {
      return;
    }

    const token = nanoIdGen(16);

    const resetLink = `${this.domainService.getUrl(workspace.hostname)}/password-reset?token=${token}`;

    await this.userTokenRepo.insertUserToken({
      token: token,
      userId: user.id,
      workspaceId: user.workspaceId,
      expiresAt: new Date(new Date().getTime() + 60 * 60 * 1000), // 1 hour
      type: UserTokenType.FORGOT_PASSWORD,
    });

    const emailTemplate = ForgotPasswordEmail({
      username: user.name,
      resetLink: resetLink,
    });

    await this.mailService.sendToQueue({
      to: user.email,
      subject: 'Reset your password',
      template: emailTemplate,
    });
  }

  async passwordReset(passwordResetDto: PasswordResetDto, workspaceId: string) {
    const userToken = await this.userTokenRepo.findById(
      passwordResetDto.token,
      workspaceId,
    );

    if (
      !userToken ||
      userToken.type !== UserTokenType.FORGOT_PASSWORD ||
      userToken.expiresAt < new Date()
    ) {
      throw new BadRequestException('Invalid or expired token');
    }

    const user = await this.userRepo.findById(userToken.userId, workspaceId);
    if (!user || user.deletedAt) {
      throw new NotFoundException('User not found');
    }

    const newPasswordHash = await hashPassword(passwordResetDto.newPassword);

    await executeTx(this.db, async (trx) => {
      await this.userRepo.updateUser(
        {
          password: newPasswordHash,
        },
        user.id,
        workspaceId,
        trx,
      );

      await trx
        .deleteFrom('userTokens')
        .where('userId', '=', user.id)
        .where('type', '=', UserTokenType.FORGOT_PASSWORD)
        .execute();
    });

    const emailTemplate = ChangePasswordEmail({ username: user.name });
    await this.mailService.sendToQueue({
      to: user.email,
      subject: 'Your password has been changed',
      template: emailTemplate,
    });

    return this.tokenService.generateAccessToken(user);
  }

  async verifyUserToken(
    userTokenDto: VerifyUserTokenDto,
    workspaceId: string,
  ): Promise<void> {
    const userToken: UserToken = await this.userTokenRepo.findById(
      userTokenDto.token,
      workspaceId,
    );

    if (
      !userToken ||
      userToken.type !== userTokenDto.type ||
      userToken.expiresAt < new Date()
    ) {
      throw new BadRequestException('Invalid or expired token');
    }
  }

  async getCollabToken(userId: string, workspaceId: string) {
    const token = await this.tokenService.generateCollabToken(
      userId,
      workspaceId,
    );
    return { token };
  }
}
