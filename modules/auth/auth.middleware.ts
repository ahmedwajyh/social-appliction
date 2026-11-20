import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { KEY_ACCESS } from "../../config/config.service.js";
import { UnauthorizedException } from "../../common/exception/app.exception.js";

export const authentication = async (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    const { authorization } = req.headers;

    if (!authorization) {
        throw new UnauthorizedException("Token is required");
    }

    const [bearer, token] = authorization.split(" ");

    if (bearer !== "Bearer" || !token) {
        throw new UnauthorizedException("Invalid token format");
    }

    const decoded = jwt.verify(token, String(KEY_ACCESS));

    req.user= decoded;

    next();
};