import { Iuser, userModel } from "../../DB/models/user.model.js";
import {
    ConflictException,
    NotFoundException,
    BadRequestException,
    UnauthorizedException
} from "../../common/exception/index.js";
import { otpEmailService } from "../../common/sevice/OTPEmail.service.js";
import jwt from "jsonwebtoken";
import { KEY_ACCESS, KEY_REFRESH } from "../../config/config.service.js";

class AuthService {

    signup = async (body: Iuser) => {

        const {
            age,
            email,
            fName,
            gender,
            lName,
            password,
            phone
        } = body;

        const userExist = await userModel.findOne({ email });

        if (userExist) {
            throw new ConflictException("User already exists", userExist);
        }

        await userModel.create({
            age,
            email,
            fName,
            lName,
            password,
            gender,
            phone
        });

        await otpEmailService.sendOTP(email, fName);

        return {
            message: "Signup successful. OTP sent to your email."
        };
    };

    verifyEmail = async (email: string, otp: string) => {

        const user = await userModel.findOne({ email });

        if (!user) {
            throw new NotFoundException("User not found");
        }

        if (user.isEmailVerified) {
            throw new ConflictException("Email already verified", user);
        }

        const isValid = await otpEmailService.verifyOTP(email, otp);

        if (!isValid) {
            throw new BadRequestException("Invalid or expired OTP");
        }

        await userModel.updateOne(
            { email },
            { $set: { isEmailVerified: true } }
        );

        return {
            message: "Email verified successfully"
        };
    };

    login = async (body: { email: string; password: string }) => {

        const { email, password } = body;

        const user = await userModel.findOne({ email });

        if (!user) {
            throw new NotFoundException("User not found");
        }

        if (!user.isEmailVerified) {
            throw new UnauthorizedException("Please verify your email first");
        }

        // Temporary password comparison
        const isPasswordMatch = user.password === password;

        if (!isPasswordMatch) {
            throw new UnauthorizedException("Invalid email or password");
        }

        // Generate Access Token
        const accessToken = jwt.sign(
            {
                id: user._id.toString(),
                email: user.email
            },
            String(KEY_ACCESS),
            { expiresIn: "15m" }
        );

        // Generate Refresh Token
        const refreshToken = jwt.sign(
            {
                id: user._id.toString(),
                email: user.email
            },
            String(KEY_REFRESH),
            { expiresIn: "7d" }
        );

        // Save Refresh Token in Database
        await userModel.updateOne(
            { _id: user._id },
            { $set: { refreshToken } }
        );

        return {
            accessToken,
            refreshToken
        };
    };

    refreshToken = async (token: string) => {

        // Verify Refresh Token
        let decoded: jwt.JwtPayload;

        try {
            const result = jwt.verify(token, String(KEY_REFRESH));

            if (typeof result === "string" || !result.id) {
                throw new Error("Invalid payload");
            }

            decoded = result;

        } catch {
            throw new UnauthorizedException("Invalid or expired refresh token");
        }

        // Find User
        const user = await userModel.findById(decoded.id);

        if (!user) {
            throw new NotFoundException("User not found");
        }

        // Check Refresh Token
        if (user.refreshToken !== token) {
            throw new UnauthorizedException("Refresh token is invalid");
        }

        // Generate New Access Token
        const accessToken = jwt.sign(
            {
                id: user._id.toString(),
                email: user.email
            },
            String(KEY_ACCESS),
            { expiresIn: "15m" }
        );

        // Generate New Refresh Token
        const refreshToken = jwt.sign(
            {
                id: user._id.toString(),
                email: user.email
            },
            String(KEY_REFRESH),
            { expiresIn: "7d" }
        );

        // Update Refresh Token
        await userModel.updateOne(
            { _id: user._id },
            { $set: { refreshToken } }
        );

        return {
            accessToken,
            refreshToken
        };
    };

    logout = async (userId: string) => {

        const user = await userModel.findById(userId);

        if (!user) {
            throw new NotFoundException("User not found");
        }

        // Remove Refresh Token
        await userModel.updateOne(
            { _id: userId },
            {
                $unset: {
                    refreshToken: 1
                }
            }
        );

        return {
            message: "Logout successful"
        };
    };
forgetPassword = async (email: string) => {

    const user = await userModel.findOne({ email });

    if (!user) {
        throw new NotFoundException("User not found");
    }

    await otpEmailService.sendOTP(email, user.fName);

    return {
        message: "OTP sent to your email"
    };
};

resetPassword = async (
    email: string,
    otp: string,
    newPassword: string
) => {

    const user = await userModel.findOne({ email });

    if (!user) {
        throw new NotFoundException("User not found");
    }

    const isValid = await otpEmailService.verifyOTP(email, otp);

    if (!isValid) {
        throw new BadRequestException("Invalid or expired OTP");
    }

    await userModel.updateOne(
    { email },
    {
        $set: {
            password: newPassword
        },
        $unset: {
            refreshToken: 1
        }
    }
);

    return {
        message: "Password reset successfully"
    };
};
}

export default new AuthService();