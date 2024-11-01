const uuid = require('uuid');
const express = require('express');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const path = require('path');
const port = 3000;
const fs = require('fs');
const axios = require('axios');
const jwt = require('jsonwebtoken');


const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SESSION_KEY = 'Authorization';

class Session {
    #sessions = {}

    constructor() {
        try {
            this.#sessions = fs.readFileSync('./sessions.json', 'utf8');
            this.#sessions = JSON.parse(this.#sessions.trim());

            console.log(this.#sessions);
        } catch(e) {
            this.#sessions = {};
        }
    }

    #storeSessions() {
        fs.writeFileSync('./sessions.json', JSON.stringify(this.#sessions), 'utf-8');
    }

    set(key, value) {
        if (!value) {
            value = {};
        }
        this.#sessions[key] = value;
        this.#storeSessions();
    }

    get(key) {
        return this.#sessions[key];
    }

    init(res) {
        const sessionId = uuid.v4();
        this.set(sessionId);

        return sessionId;
    }

    destroy(req, res) {
        const sessionId = req.sessionId;
        delete this.#sessions[sessionId];
        this.#storeSessions();
    }
}

const sessions = new Session();

app.use((req, res, next) => {
    let currentSession = {};
    let sessionId = req.get(SESSION_KEY);

    if (sessionId) {
        currentSession = sessions.get(sessionId);
        if (!currentSession) {
            currentSession = {};
            sessionId = sessions.init(res);
        }
    } else {
        sessionId = sessions.init(res);
    }

    req.session = currentSession;
    req.sessionId = sessionId;

    onFinished(req, () => {
        const currentSession = req.session;
        const sessionId = req.sessionId;
        sessions.set(sessionId, currentSession);
    });

    next();
});

app.get('/', (req, res) => {
    if (req.session.username) {
        return res.json({
            username: req.session.username,
            logout: 'http://localhost:3000/logout'
        })
    }
    res.sendFile(path.join(__dirname+'/index.html'));
})

app.get('/logout', (req, res) => {
    sessions.destroy(req, res);
    res.redirect('/');
});

app.post('/api/login', (req, res) => {
    const { login, password } = req.body;

    const data = new URLSearchParams();
    data.append('grant_type', 'password');
    data.append('username', login);
    data.append('password', password);
    data.append('audience', 'https://dev-c0ba8hehzswou2jj.eu.auth0.com/api/v2/');
    data.append('scope', 'offline_access');
    data.append('client_id', 'NmknH1Rym8Bt2wIgf2G1PkCK5aFIu3KM');
    data.append('client_secret', 'TkKLHtoeic8dKAlSEobN2owlVLkGbM35SMRrkQz0lQNcPZGhTxK48JyM17dkyGRI');

    axios({
        method: 'post',
        url: 'https://dev-c0ba8hehzswou2jj.eu.auth0.com/oauth/token',
        data: data,
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
    })
        .then(response => {
            req.session.username = login;
            req.session.login = login;

            const accessToken = response.data.access_token;
            const publicKey = fs.readFileSync('./dev-c0ba8hehzswou2jj.pem', 'utf8');
            const verifyOptions = {
                issuer: 'https://dev-c0ba8hehzswou2jj.eu.auth0.com/',
                audience: 'https://dev-c0ba8hehzswou2jj.eu.auth0.com/api/v2/',
                algorithms: ['RS256']
            }

            const decoded = jwt.verify(accessToken, publicKey, verifyOptions);

            if (decoded) {
                console.log(decoded);
                res.json({ token: req.sessionId,
                    access_token: response.data.access_token,
                    refresh_token: response.data.refresh_token
                });
            } else {
                res.status(401).send();
            }

            console.log(response.data);
        })
        .catch(error => {
            let status = 400;
            if (error.response) {
                status = error.response.status;
            }

            res.status(status).send();

            if (error.response) {
                console.log(error.response.data);
                console.log(error.response.status);
            }
        });
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
