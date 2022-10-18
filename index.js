/* Objectif :
    L’objectif de ce TP est de créer un service d’accès à des posts (contenu textuel) avec contrôle 
    d’accès

    Utilisateurs :
        - ID : 777  PSEUDO : admin  ADMIN : true    MDP : admin
        - ID : 123  PSEUDO : bob    ADMIN : false   MDP : coucou
        - ID : 321  PSEUDO : alice  ADMIN : false   MDP : coucou

    Spécifications fonctionnelles :

        JWT :
            Le service doit exposer un moyen de générer et obtenir un JWT.
            Le JWT doit avoir une durée de validité de 1 jour;
            (Seul un utilisateur authentifié peut demander la génération et l'obtention de son token)

        Accès au ressources :
            On doit pouvoir consulter des posts (ressources) :
            - ID : 456  AUTEUR : 123 (bob)      CONTENU : Je suis un bob.
            - ID : 654  AUTEUR : 321 (alice)    CONTENU : Je suis au pays des merveilles.
            - ID : 555  AUTEUR : 777 (admin)    CONTENU : Je suis tout puissant.

            Les utilisateurs non-admin n’ont accès qu’aux posts dont ils sont l’auteur.
            Par exemple, bob n’a accès qu’au post 456 et alice qu’au post 654.
            
            Les utilisateurs admin ont accès à tous les posts.

        Toutes les réponses doivent être en application/json
*/


// readFileSync lis les données de façon synchrone
const fs = require('fs');
let userFile = fs.readFileSync('users.json');
let users = JSON.parse(userFile);
// console.log(users);

let postFile = fs.readFileSync('posts.json');
let posts = JSON.parse(postFile);
// console.log(posts);

const jwt = require('jsonwebtoken');
require('dotenv').config();


const express = require('express');
const app = express();
const port = 8080;
app.use(express.json());
app.use(express.urlencoded({ extended: true}));

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '1d'});
}

function generateRefreshToken(user) {
  return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, {expiresIn: '1y'});
}
function authenticateToken(req, res, next) {
    let index = localStorage.getItem('id');
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.sendStatus(401);
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
        return res.sendStatus(401);
        }
        req.user = user;
        next();
    });
}

function getPost(userId){
    for (const post of posts) {
        if(post.auteur == userId) return post
    }
    return -1
}

function getUserIndex(username){
    for (const index in users) {
        let tempUser = users[index];
        if(tempUser.pseudo == username) return index
    }
    return -1
}

app.post('/login', (req, res) => {
    let index = getUserIndex(req.body.username);
    let user;
    
   if(index > -1){
     if (req.body.password !== users[index].password) {
       res.status(401).send('invalid credentials');
       return ;
     }
     user = users[index]
   }else{
     res.status(401).send('invalid credentials');
     return ;
   }
 
   const accessToken = generateAccessToken(user);
   const refreshToken = generateRefreshToken(user);
   res.send({
     accessToken,
     refreshToken,
   });
 
 });

app.post('/refreshToken', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.sendStatus(401);
    }

    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) {
        return res.sendStatus(401);
        }
        // TODO : check en bdd que le user a toujours les droit et qu'il existe toujours
        delete user.iat;
        delete user.exp;
        const refreshedToken = generateAccessToken(user);
        res.send({
            accessToken: refreshedToken,
        });
    });
});


app.get('/me', authenticateToken, (req, res) => {
    res.send(req.user);
});
app.get('/posts', (req, res) => {
    let token = (req.headers.authorization).split(' ')[1];
    let user = jwt.decode(token, process.env.ACCESS_TOKEN_SECRET)
    if(user.admin){
        res.send(posts);
    }
    res.send(getPost(user.id))
});

app.listen(port, () => {console.log('Server running on port ' + port)});