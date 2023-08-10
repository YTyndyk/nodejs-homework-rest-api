import sgMail from "@sendgrid/mail";
import "dotenv/config";

const { SENDGRID_API_KEY } = process.env;

sgMail.setApiKey(SENDGRID_API_KEY);

const sendMail = async (data) => {
	const email = { ...data, from: "Utyndyk@gmail.com" };
	await sgMail.send(email);
	return true;
};
export default sendMail;
