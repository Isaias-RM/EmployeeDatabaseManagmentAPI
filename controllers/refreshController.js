const usersDB = {
    users: require('../model/users.json'),
    setUsers: function (data) { this.users = data }
}
const jwt = require('jsonwebtoken');
require('dotenv').config();

const handleRefreshToken = (req, res) => {
    const cookies = req.cookies
    if (!cookies?.jwt) return res.sendStatus(401)
    const refreshToken = cookies.jwt;

    //check if user's refresh token exists and matches
    const foundUser = usersDB.users.find(person => person.refreshToken === refreshToken)
    if (!foundUser) return res.sendStatus(401); //Unauthorized
    //compares client submitted jwt to jwt data in foundUser
    jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        (err, decoded) => {
            if (err || foundUser.username !== decoded.username) return res.sendStatus(403);
            const accessToken = jwt.sign(
                { "username": decoded.username },
                process.env.ACCESS_TOKEN_SECRET,
                { expiresIn: '30s' }
            );
            res.json({ accessToken })
        }
    )
}

module.exports = { handleRefreshToken };