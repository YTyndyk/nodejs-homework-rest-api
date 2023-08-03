import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import "dotenv/config";
import path from "path";
import fs from "fs/promises";
import User from "../models/user.js";
import gravatar from "gravatar";
import { HttpError } from "../helpers/index.js";
import ctrlWrapper from "../decorators/ctrlWrapper.js";

const { JWT_SECRET } = process.env;
const avatarDir = path.resolve("public", "avatars");

const register = async (req, res) => {
	const { email, password } = req.body;
	const user = await User.findOne({ email });
	if (user) {
		throw HttpError(409, "Email in use");
	}

	const hashPassword = await bcrypt.hash(password, 10);
	const avatarURL = gravatar.url(email);

	const newUser = await User.create({
		...req.body,
		password: hashPassword,
		avatarURL,
	});

	res.status(201).json({
		password: newUser.password,
		email: newUser.email,
	});
};

const login = async (req, res) => {
	const { email, password } = req.body;
	const user = await User.findOne({ email });
	if (!user) {
		throw HttpError(401, "email or password is wrong");
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
	login: ctrlWrapper(login),
	getCurrent: ctrlWrapper(getCurrent),
	logout: ctrlWrapper(logout),
	updateAvatar: ctrlWrapper(updateAvatar),
};
