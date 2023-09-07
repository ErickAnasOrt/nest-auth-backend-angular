import { AuthService } from './../auth.service';
import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { jwtpayload } from '../interfaces/jwt-payload';

@Injectable()
export class AuthGuard implements CanActivate {
  //authService: any;


  constructor(
    private JwtService: JwtService,
    private authService:AuthService,

  ){}



  async canActivate(context: ExecutionContext):  Promise<boolean>  {


    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    if (!token){
      throw new UnauthorizedException('there is no bearer tokrn');
    }

    try{
      const payload = await this.JwtService.verifyAsync<jwtpayload>(
    token,
    {
      secret: process.env.JWT_SEED
    }
    );

    const user = await  this.authService.findUserById( payload.id);
    if ( !user ) throw new UnauthorizedException('User does not exists');
    if ( !user.isActive ) throw new UnauthorizedException('User is not active');



    request['user']= user;

    }catch(error){
      throw new UnauthorizedException();
    }
    
    
    
    return true;
  }
  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
