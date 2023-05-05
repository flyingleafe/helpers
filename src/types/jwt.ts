import { KeyLike } from "jose";

export interface payload {
  [key: string]: any;
}

export interface verify {
  secret: KeyLike;
  token: string;
}

export interface generate {
  payload: payload;
  expiresIn?: string;
  secret: KeyLike;
}
