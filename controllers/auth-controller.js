import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import "dotenv/config";
import path from "path";
import fs from "fs/promises";
import User from "../models/user.js";
import gravatar from "gravatar";
import { HttpError, sendMail } from "../helpers/index.js";
import ctrlWrapper from "../decorators/ctrlWrapper.js";
import { nanoid } from "nanoid";

const { JWT_SECRET, BASE_URL } = process.env;
const avatarDir = path.resolve("public", "avatars");

const register = async (req, res) => {
	const { email, password } = req.body;
	const user = await User.findOne({ email });
	if (user) {
		throw HttpError(409, "Email in use");
	}

	const hashPassword = await bcrypt.hash(password, 10);
	const avatarURL = gravatar.url(email);
	const verificationToken = nanoid();

	const newUser = await User.create({
		...req.body,
		password: hashPassword,
		avatarURL,
		verificationToken,
	});

	const veryfyEmail = {
		to: email,
		subject: "Verify email",
		html: `<a target="_blank" href="${BASE_URL}/api/auth/users/verify/${verificationToken}"> Click verify email</a>`,
	};
	await sendMail(veryfyEmail);

	res.status(201).json({
		password: newUser.password,
		email: newUser.email,
	});
};
const verifyEmail = async (req, res) => {
	const { verificationToken } = req.params;
	const user = await User.findOne({ verificationToken });
	if (!user) {
		throw HttpError(404, "User not found");
	}
	await User.findByIdAndUpdate(user._id, {
		verify: true,
		verificationToken: null,
	});
	res.json({ message: "Verification successful" });
};
const resendVerifyEmail = async (req, res) => {
	const { email } = req.body;
	const user = await User.findOne({ email });
	if (!user) {
		throw HttpError(400, "missing required field email");
	}
	if (user.verify) {
		throw HttpError(400, "Verification has already been passed");
	}
	const veryfyEmail = {
		to: email,
		subject: "Verify email",
		html: `<a target="_blank" href="${BASE_URL}/api/auth/users/verify/${user.verificationToken}"> Click verify email</a>`,
	};
	await sendMail(veryfyEmail);
	res.json({ message: "Verification email sent" });
};
const login = async (req, res) => {
	const { email, password } = req.body;
	const user = await User.findOne({ email });
	if (!user) {
		throw HttpError(401, "email or password is wrong");
	}
	if (!user.verify) {
		throw HttpError(401, "email not verified");
	}

	const passwordCompare = await bcrypt.compare(password, user.password);
	if (!passwordCompare) {
		throw HttpError(401, "email or password is wrong");
	}

	const payload = {
		id: user._id,
	};

	const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "23h" });
	await User.findByIdAndUpdate(user._id, { token });

	res.json({ token });
};
const getCurrent = (req, res) => {
	const { subscription, email } = req.user;

	res.json({
		email,
		subscription,
	});
};
const logout = async (req, res) => {
	const { _id } = req.user;
	await User.findByIdAndUpdate(_id, { token: "" });

	res.status(204);
};
const updateAvatar = async (req, res) => {
	const { _id } = req.user;
	const { path: tempUpload, filename } = req.file;
	const resultUpload = path.join(avatarDir, filename);
	await fs.rename(tempUpload, resultUpload);
	const avatarURL = path.join("avatars", filename);
	await User.findByIdAndUpdate(_id, { avatarURL });

	res.json({ avatarURL });
};
export default {
	register: ctrlWrapper(register),
	verifyEmail: ctrlWrapper(verifyEmail),
	resendVerifyEmail: ctrlWrapper(resendVerifyEmail),
	login: ctrlWrapper(login),
	getCurrent: ctrlWrapper(getCurrent),
	logout: ctrlWrapper(logout),
	updateAvatar: ctrlWrapper(updateAvatar),
};
