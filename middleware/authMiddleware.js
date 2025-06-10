const jwt = require("jsonwebtoken");

const verifyToken = (req, res, next) => {
    const token = req.cookies.token;
    
    if (!token) {
        return res.status(403).send("Access Denied. No Token Provided.");
    }

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send("Invalid Token");
    }
};

module.exports = verifyToken;
