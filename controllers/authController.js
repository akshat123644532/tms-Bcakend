const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const userModel = require("../models/userModel");
const companyModel = require("../models/companyModel");
const refreshTokenModel = require("../models/refreshTokenModel");
const revokedTokenModel = require("../models/revokedTokenModel");
const { sendError, HttpError } = require("../utils/httpError");

const ACCESS_TOKEN_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "1h";
const REFRESH_TOKEN_DAYS = Number(process.env.REFRESH_TOKEN_DAYS || 7);

const isRequestSecure = (req) =>
    req.secure || req.headers["x-forwarded-proto"] === "https";

const signAccessToken = (user) => {
    const jti = crypto.randomBytes(16).toString("hex");

    const token = jwt.sign(
        {
            id: user.id,
            company_id: user.company_id,
            user_type: user.user_type,
            email: user.email,
            token_version: user.token_version || 1,
            jti
        },
        process.env.JWT_SECRET,
        {
            expiresIn: ACCESS_TOKEN_EXPIRES_IN
        }
    );

    return { token, jti };
};

const issueRefreshToken = async (userId) => {
    const token = crypto.randomBytes(48).toString("hex");
    const expiresAt = new Date(
        Date.now() + REFRESH_TOKEN_DAYS * 24 * 60 * 60 * 1000
    );

    await refreshTokenModel.create(userId, token, expiresAt);

    return { token, expiresAt };
};

const publicUser = (user) => ({
    id: user.id,
    company_id: user.company_id,
    user_type: user.user_type,
    name: user.name,
    mobile: user.mobile,
    email: user.email,
    last_login_at: user.last_login_at || null
});

const login = async (req, res) => {
    try {
        if (process.env.NODE_ENV === "production" && !isRequestSecure(req)) {
            throw new HttpError(403, "Login requires HTTPS");
        }

        const { email, password } = req.body;

        if (!email || !password) {
            throw new HttpError(400, "Email and password are required");
        }

        const user = await userModel.findUserByEmail(email);

        if (!user) {
            throw new HttpError(401, "Invalid email or password");
        }

        if (user.status !== 1) {
            throw new HttpError(403, "User account is not active");
        }

        const passwordMatch = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!passwordMatch) {
            throw new HttpError(401, "Invalid email or password");
        }

        await userModel.updateLastLogin(user.id);
        user.last_login_at = new Date();

        const { token } = signAccessToken(user);
        const refresh = await issueRefreshToken(user.id);

        return res.status(200).json({
            success: true,
            message: "Login successful",
            token,
            refresh_token: refresh.token,
            expires_in: ACCESS_TOKEN_EXPIRES_IN,
            user: publicUser(user)
        });
    } catch (error) {
        return sendError(res, error);
    }
};

const refresh = async (req, res) => {
    try {
        const refreshToken = req.body.refresh_token;

        if (!refreshToken) {
            throw new HttpError(400, "refresh_token is required");
        }

        const stored = await refreshTokenModel.findByToken(refreshToken);

        if (!stored) {
            throw new HttpError(401, "Invalid refresh token");
        }

        if (stored.revoked_at) {
            await refreshTokenModel.revokeAllForUser(stored.user_id);
            await userModel.bumpTokenVersion(stored.user_id);
            throw new HttpError(401, "Refresh token has been revoked");
        }

        if (new Date(stored.expires_at) <= new Date()) {
            throw new HttpError(401, "Refresh token has expired");
        }

        const user = await userModel.findUserById(stored.user_id);

        if (!user || user.status !== 1) {
            throw new HttpError(401, "User account is not active");
        }

        await refreshTokenModel.revokeByToken(refreshToken);

        const { token } = signAccessToken(user);
        const nextRefresh = await issueRefreshToken(user.id);

        return res.status(200).json({
            success: true,
            message: "Token refreshed",
            token,
            refresh_token: nextRefresh.token,
            expires_in: ACCESS_TOKEN_EXPIRES_IN
        });
    } catch (error) {
        return sendError(res, error);
    }
};

const logout = async (req, res) => {
    try {
        if (req.tokenPayload?.jti && req.tokenPayload?.exp) {
            await revokedTokenModel.revoke({
                jti: req.tokenPayload.jti,
                userId: req.user.id,
                expiresAt: new Date(req.tokenPayload.exp * 1000)
            });
        }

        if (req.body?.refresh_token) {
            await refreshTokenModel.revokeByToken(req.body.refresh_token);
        }

        return res.status(200).json({
            success: true,
            message: "Logged out successfully"
        });
    } catch (error) {
        return sendError(res, error);
    }
};

const listCompanies = async (req, res) => {
    try {
        const companies = await companyModel.listActive();

        return res.status(200).json({
            success: true,
            companies
        });
    } catch (error) {
        return sendError(res, error);
    }
};

const register = async (req, res) => {
    try {
        if (process.env.NODE_ENV === "production" && !isRequestSecure(req)) {
            throw new HttpError(403, "Signup requires HTTPS");
        }

        const name = String(req.body.name || "").trim();
        const mobile = String(req.body.mobile || "").trim();
        const email = String(req.body.email || "").trim().toLowerCase();
        const password = req.body.password || "";
        const companyId = Number(req.body.company_id);

        if (!name || !mobile || !email || !password || !companyId) {
            throw new HttpError(400, "Name, mobile, email, password and company are required");
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            throw new HttpError(400, "Enter a valid email");
        }

        if (mobile.replace(/\D/g, "").length < 10) {
            throw new HttpError(400, "Enter a valid mobile number");
        }

        if (String(password).length < 6) {
            throw new HttpError(400, "Password must be at least 6 characters");
        }

        const company = await companyModel.findActiveById(companyId);

        if (!company) {
            throw new HttpError(400, "Select an active company");
        }

        const existingEmail = await userModel.findUserByEmail(email);

        if (existingEmail) {
            throw new HttpError(409, "An account with this email already exists");
        }

        const existingMobile = await userModel.findUserByMobile(mobile);

        if (existingMobile) {
            throw new HttpError(409, "An account with this mobile number already exists");
        }

        const passwordHash = await bcrypt.hash(password, 10);

        await userModel.createUser({
            companyId,
            name,
            mobile,
            email,
            passwordHash
        });

        return res.status(201).json({
            success: true,
            message: "Account created. Sign in to continue."
        });
    } catch (error) {
        return sendError(res, error);
    }
};

const profile = async (req, res) => {
    try {
        const user = await userModel.findUserById(req.user.id);

        if (!user) {
            throw new HttpError(404, "User not found");
        }

        return res.status(200).json({
            success: true,
            user: publicUser(user)
        });
    } catch (error) {
        return sendError(res, error);
    }
};

module.exports = {
    login,
    refresh,
    logout,
    profile,
    register,
    listCompanies
};
