const jwt = require("jsonwebtoken");
const Users = require("../users/users-model");
const { JWT_SECRET } = require("../secrets"); // use this secret!

const restricted = (req, res, next) => {
	const token = req.headers.authorization;

	if (!token) return next({ status: 401, message: "Token required" });

	jwt.verify(token, JWT_SECRET, (err, decoded) => {
		if (err) return next({ status: 401, message: "Token invalid" });

		req.decoded = decoded;
		next();
	});
};

const only = (role_name) => (req, res, next) => {
	if (req.decoded.role_name !== role_name)
		return next({ status: 403, message: "This is not for you" });

	next();
};

const checkUsernameExists = async (req, res, next) => {
	const [user] = await Users.findBy({username: req.body.username});
	if (user) {
		req.user = user;
		return next();
	}

	return next({ status: 401, message: "Invalid credentials" });
};

const validateRoleName = (req, res, next) => {
	try {
		req.role_name = req.body.role_name.trim();

		if (req.role_name.length > 32)
			return next({ status: 422, message: "Role name can not be longer than 32 chars" });
		
    else if (req.role_name === "admin")
			return next({ status: 422, message: "Role name can not be admin" });
		
    else if (req.role_name === "") 
      req.role_name = "student";

		return next();
	} catch {
		req.role_name = "student";
		next();
	}
};

const buildToken = ({ user_id, username, role_name }) => {
	const payload = {
		subject: user_id,
		username,
		role_name,
	};
	const options = {
		expiresIn: "1d",
	};

	return jwt.sign(payload, JWT_SECRET, options);
};

module.exports = {
	restricted,
	checkUsernameExists,
	validateRoleName,
	only,
	buildToken,
};
