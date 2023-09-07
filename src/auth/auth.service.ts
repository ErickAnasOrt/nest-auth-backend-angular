import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import * as bcryptjs from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { jwtpayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterUserDto, CreateUserDto, UpdateAuthDto, loginDto,  } from './dto';

@Injectable()
export class AuthService {
  
 
  //findUserById(id: string) {
   // throw new Error('Method not implemented.');
  //}

   constructor(
    @InjectModel(User.name)
     private userModel: Model<User>,
     private jwtService: JwtService,
   ){}


async  create(CreateUserDto: CreateUserDto):Promise<User> {
    
    try{
      //console.log(CreateUserDto.name);
      const{ password , ...userData} = CreateUserDto;
      const newUser = new this.userModel({                  //encriptacion de la contraseña
        password: bcryptjs.hashSync(password,10),
        ...userData
      });

       //const newUser= new this.userModel(CreateUserDto.name);
        await newUser.save();
        const {password:_, ...user}= newUser.toJSON();

        return user;


    }catch(error){
      if(error.code === 11000){
        throw new BadRequestException(`${ CreateUserDto.email } already exists!`)
      }
      throw new InternalServerErrorException('something terribe happen!!!')
    }

  }
  async register(registerDto:RegisterUserDto): Promise<LoginResponse>{
    const user = await this.create(registerDto);
    console.log({user});
    return{
      user: user ,
      token: this.getjwtToken({ id: user._id})
    }
  }
  async login (loginDto: loginDto): Promise<LoginResponse>{
    //console.log({loginDto});
    const {email,password} = loginDto;

    const user = await this.userModel.findOne({email});
    if (!user){
      throw new UnauthorizedException('no valido credenciales- email');
    }
    if (!bcryptjs.compareSync(password, user.password)){
      throw new UnauthorizedException('no valido credenciales- password');
    }

    const{password:_, ...rest} = user.toJSON();

    return{
      user: rest,
      token: this.getjwtToken({ id: user.id}),
    }
    
  }

  findAll(): Promise<User[]> {
    return this.userModel.find()
  }

  async findUserById(id : string ){
    const user = await this.userModel.findById(id);
    const{ password, ...rest} = user.toJSON();
    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
  getjwtToken(payload: jwtpayload){

    const token = this.jwtService.sign(payload);
    return token;

  }
}
