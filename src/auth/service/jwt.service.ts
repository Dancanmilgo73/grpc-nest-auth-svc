import { Injectable } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Auth } from "../auth.entity";
import { Repository } from "typeorm";
import { JwtService as Jwt } from "@nestjs/jwt";
import * as bcrypt from 'bcryptjs';

@Injectable()
export class JwtService{
    @InjectRepository(Auth)
    private readonly repository: Repository<Auth>;

    private readonly jwt: Jwt;

    constructor (jwt: Jwt) {
        this.jwt = jwt;
    }

    // decoding
    public async decode(token: string): Promise<unknown>{
        return this.jwt.decode(token, null);
    }


    // UserId from token
    public async validateUser(decoded: any): Promise<Auth>{
        return this.repository.findOne({ where: { id: decoded.id } });
    }

    // Genereate token
    public generateToken(auth: Auth): string{
        return this.jwt.sign({id: auth.id, email: auth.email});
    }

    // Validate User's pass
    public isPasswordValid(password: string, userPassword: string): boolean{
        return bcrypt.compareSync(password, userPassword);
    }

    // Encode user's password
    public encodepassword(password: string): string{
        const salt: string = bcrypt.genSaltSync(10);
        return bcrypt.hashSync(password, salt);
    }

    // validate JWt token, throw forbidden error if JWT token is invalid
    public async verify(token: string): Promise<any>{
        try {
            return this.jwt.verify(token);
        }catch(err){}
    }

}
