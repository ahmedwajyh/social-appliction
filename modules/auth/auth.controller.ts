import express from "express";
import { Request, Response, NextFunction } from "express";
import AuthService from "./auth.service.js";
import { responseFormatter } from "../../middleware/response.middleware.js";
import { Validation } from "../../middleware/validation.middleware.js";
import { UnauthorizedException } from "../../common/exception/index.js";
import {
    signupSchema,
    verifyOtpSchema,
    loginSchema,
    refreshTokenSchema,
    forgetPasswordSchema,
    resetPasswordSchema
} from "./auth.validation.js";
import { authentication } from "./auth.middleware.js";

const router = express.Router({
    strict: true,
    mergeParams: true,
    caseSensitive: true
});

// Signup
router.post(
    "/signup",
    Validation(signupSchema),
    responseFormatter(async (req: Request, res: Response, next: NextFunction) => {
        const data = await AuthService.signup(req.body);

        return {
            status: 201,
            message: true,
            data,
            extra: "user signup successfully"
        };
    })
);

// Verify Email
router.post(
    "/verify-email",
    Validation(verifyOtpSchema),
    responseFormatter(async (req: Request, res: Response, next: NextFunction) => {
        const { email, otp } = req.body;

        const data = await AuthService.verifyEmail(email, otp);

        return {
            status: 200,
            message: true,
            data,
            extra: "email verified successfully"
        };
    })
);

// Login
router.post(
    "/login",
    Validation(loginSchema),
    responseFormatter(async (req: Request, res: Response, next: NextFunction) => {
        const data = await AuthService.login(req.body);

        return {
            status: 200,
            message: true,
            data,
            extra: "login successfully"
        };
    })
);

// Refresh Token
router.post(
    "/refresh-token",
    Validation(refreshTokenSchema),
    responseFormatter(async (req: Request, res: Response, next: NextFunction) => {
        const { refreshToken } = req.body;

        const data = await AuthService.refreshToken(refreshToken);

        return {
            status: 200,
            message: true,
            data,
            extra: "token refreshed successfully"
        };
    })
);

// Logout
router.post(
    "/logout",
    authentication,
    responseFormatter(async (req: Request, res: Response, next: NextFunction) => {

        const user = req.user;

        if (!user || typeof user === "string" || typeof user.id !== "string") {
            throw new UnauthorizedException("Invalid token payload");
        }

        const data = await AuthService.logout(user.id);

        return {
            status: 200,
            message: true,
            data,
            extra: "logout successfully"
        };
    })
);
// Forget Password
router.post(
    "/forget-password",
    Validation(forgetPasswordSchema),
    responseFormatter(async (req: Request, res: Response, next: NextFunction) => {

        const { email } = req.body;

        const data = await AuthService.forgetPassword(email);

        return {
            status: 200,
            message: true,
            data,
            extra: "OTP sent successfully"
        };
    })
);
  // Reset Password
router.post(
    "/reset-password",
    Validation(resetPasswordSchema),
    responseFormatter(async (req: Request, res: Response, next: NextFunction) => {

        const { email, otp, newPassword } = req.body;

        const data = await AuthService.resetPassword(
            email,
            otp,
            newPassword
        );

        return {
            status: 200,
            message: true,
            data,
            extra: "password reset successfully"
        };
    })
);
// Profile
router.get(
    "/profile",
    authentication,
    (req, res) => {
        return res.status(200).json({
            message: "Authentication successful",
            user: req.user
        });
    }
);

export default router;