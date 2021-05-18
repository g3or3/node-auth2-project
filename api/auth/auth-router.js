const router = require("express").Router();
const bcrypt = require("bcryptjs");
const {
	checkUsernameExists,
	validateRoleName,
	buildToken,
} = require("./auth-middleware");
const Users = require("../users/users-model");

router.post("/register", validateRoleName, async (req, res) => {
	let { username, password } = req.body;

	password = await bcrypt.hash(password, 8);

  try {
    res.status(201).json(await Users.add({ username, password, role_name: req.role_name }));
  } catch (err) {
    res.json({message: "Username already exists"})
  }
});

router.post("/login", checkUsernameExists, async (req, res) => {
	if (await bcrypt.compare(req.body.password, req.user.password)) {
		res.json({ message: `${req.user.username} is back!`, token: buildToken(req.user) });
	} else {
		res.status(401).json({ message: "Invalid credentials" });
	}
});

module.exports = router;
