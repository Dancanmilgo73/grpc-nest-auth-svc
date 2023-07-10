import { Exclude } from "class-transformer";
import { BaseEntity, Column, Entity, PrimaryGeneratedColumn } from "typeorm";

@Entity()
export class Auth extends BaseEntity {
    @PrimaryGeneratedColumn()
    public id: number;

    @Column()
    public email: string;

    @Exclude()
    @Column({type: 'varchar'})
    public password: string;
}