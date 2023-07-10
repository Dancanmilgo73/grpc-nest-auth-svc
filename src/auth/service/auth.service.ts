import { HttpStatus, Inject, Injectable } from "@nestjs/common";
import { Repository } from "typeorm";
import { Auth } from "../auth.entity";
import { InjectRepository } from "@nestjs/typeorm";
import { JwtService } from "./jwt.service";
import { LoginRequest, LoginResponse, RegisterRequest, RegisterResponse, ValidateResponse } from "../auth.pb";
import { ValidateRequestDto } from "../auth.dto";

@Injectable()
export class AuthService {
    @InjectRepository(Auth)
    private readonly repository: Repository<Auth>;

    @Inject(JwtService)
    private readonly jwtService: JwtService;   
    
    public async register({ email, password }: RegisterRequest): Promise<RegisterResponse>{
        let auth = await this.repository.findOne({ where: { email } });
        if (auth) {
            return { status: HttpStatus.CONFLICT, error: ['E-mail already exists'] };
        };
        auth = new Auth();
        auth.email = email;
        auth.password = this.jwtService.encodepassword(password);

        await this.repository.save(auth);
        return { status: HttpStatus.CREATED, error: null };

    };

    public async login({ email, password }: LoginRequest): Promise<LoginResponse>{
        const auth: Auth = await this.repository.findOne({ where: { email } });
        if (!auth) {
            return { status: HttpStatus.NOT_FOUND, error: ['Wrong email or password'], token: null };
        };

        const isPasswordValid: boolean = this.jwtService.isPasswordValid(password, auth.password);
        if (!isPasswordValid) {
            return { status: HttpStatus.NOT_FOUND, error: ['Wrong email or password'], token: null };
        };

        const token: string = this.jwtService.generateToken(auth);

        return { token, status: HttpStatus.OK, error: null };
    };

    public async validate({ token }: ValidateRequestDto): Promise<ValidateResponse> {
        
        const decoded: Auth = await this.jwtService.verify(token);

        if (!decoded) {
            return { status: HttpStatus.FORBIDDEN, error: ['Invalid token'], userId: null };
        };

        const auth: Auth = await this.jwtService.validateUser(decoded);

        if (!auth) {
            return { status: HttpStatus.CONFLICT, error: ['User not found'], userId: null };
        };

        return { status: HttpStatus.OK, error: null, userId: decoded.id };
    }
}