const jwt = require("jsonwebtoken");
const cookie = require("cookie");
const { v4: uuid4 } = require("uuid");
const Account = require("../../models/account");
const hashPassword = require("../password/hash");
require("dotenv").config("../../../.env");

const getAccountByEmail = async (email) => Account.findOne({
    email,
});

module.exports = async ({ email, userid, name }) => {
    const errors = [];

    if (Object.keys(errors).length !== 0) {
        return [
            null,
            {
                message: Object.values(errors).join("\n"),
                code: 400,
            },
        ];
    }

    let account = await getAccountByEmail(email);
    if (!account) {
        account = new Account({
            id: userid,
            username: name,
            password: hashPassword(uuid4()),
            email,
            role: "standard",
            secret: null,
            allowAutomaticLogin: false,
            twoFactorAuthentication: {
                enabled: false,
                totp: {
                    secret: "",
                    verified: false,
                },
            },
        });

        await account.save();
    }

    const expiresIn = process.env.DEMO === "true" ? "1h" : "7d";

    const token = jwt.sign(
        {
            id: account.id,
        },
        process.env.JWT_KEY,
        {
            algorithm: "HS256",
            expiresIn,
        },
    );

    const serialized = cookie.serialize("token", token, {
        httpOnly: true,
        secure: process.env.USE_HTTPS === "true",
        sameSite: "strict",
        maxAge: process.env.DEMO ? 3600 * 1000 : 86400 * 1000 * 7,
        path: "/",
    });

    return [
        {
            serialized,
            account,
        },
        null,
    ];
};
