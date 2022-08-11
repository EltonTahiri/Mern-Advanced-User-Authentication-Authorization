const User = require('../model/userModel');
const bcrypt = require('bcryptjs');
const jwt = require ('jsonwebtoken');



const signUp = async (req,res, next) => {
    const {name, email,password} = req.body;
    
    let userExists;

    try {
        userExists = await User.findOne({email});
    } catch (error) {
        console.log(err)
    }
    if(userExists){
        return res.status(400).json({message: "User already exists. Login Instead"});
    }

    const hashedPassword = bcrypt.hashSync(password);
    const user = new User({
       name, 
       email,
       password: hashedPassword
        
    });

    try{
        await user.save();
    }catch (err) {
        console.log(err);
    }

    return res.status(201).json({message:user})
};


const logIn = async (req, res, next) => {
    const {email,password} = req.body;

    let userExists;
    try {
        userExists = await User.findOne({email});
    } catch (error) {
        return new Error(err);
    }

    if(!userExists) {
        return res.status(400).json({message: 'User not found. Signup!'})
    }
    
    const isPasswordCorrect = bcrypt.compareSync(password, userExists.password);
    if(!isPasswordCorrect){
        return res.status(400).json({message: "Invalid Email / Password"})
    }
    const token = jwt.sign({id: userExists._id,}, process.env.JWT_SECRET_KEY,{
        expiresIn: "35s"
    });

    console.log("Generated Token\n", token);

    if(req.cookies[`${userExists._id}`]) {
        req.cookies[`${userExists._id}`] = ""
    }

    res.cookie(String(userExists._id),token,{
        path: '/',
        expires: new Date(Date.now() + 1000 * 30), //expires in 30 seconds
        httpOnly: true,
        sameSite: 'lax'
    })
    return res.status(200).json({message: "Successfully Logged in", user:userExists})
};

const verifyToken = (req, res, next) => {
    const cookies = req.headers.cookie;
    const token = cookies.split("=")[1];
    console.log(token)
     if(!token) {
         res.status(404).json({message: "No token found"})
     }
     jwt.verify(String(token),process.env.JWT_SECRET_KEY,(err,user) => {
         if(err) {
           return  res.status(400).json({message: "Invalid Token"})
         }
         console.log(user.id);
         req.id = user.id;
     })
     next();
};


const getUser = async (req, res, next) => {
    const userId = req.id;
    let user;
    
    try{
        user = await User.findById(userId,"-password");
    }catch(err){
        return new Error(err)
    }
    if(!user){
        return res.status(404).json({message: "User not Found"})
    }
    return res.status(200).json({user})
}

const refreshToken = (req, res, next) => {
    const cookies = req.headers.cookie;
    const prevToken = cookies.split("=")[1];

    if(!prevToken) {
        return res.status(400).json({message: "Couldn't find Token!"})
    }
    jwt.verify(String(prevToken), process.env.JWT_SECRET_KEY,(err,user)=> {
        if(err){
            console.log(err);
            return res.status(403).json({message: "Authentication failed"})
        }
        res.clearCookie(`${user.id}`);
        req.cookies[`${user.id}`] = "";

        const token = jwt.sign({id:user.id}, process.env.JWT_SECRET_KEY,{
            expiresIn: "35s"
        })
        console.log("Regenerated Token\n", token)
        res.cookie(String(user.id), token,{
            path: '/',
            expires: new Date(Date.now() + 1000 * 30), //expires in 30 seconds
            httpOnly: true,
            sameSite: 'lax'
        });

        req.id = user.id;
        next();

    })
}


const logout = (req,res) => {
    const cookies = req.headers.cookie;
    const prevToken = cookies.split("=")[1];
    if(!prevToken) {
        return res.status(400).json({message: "Couldn't find Token!"})
    }
    jwt.verify(String(prevToken), process.env.JWT_SECRET_KEY,(err,user)=> {
        if(err){
            console.log(err);
            return res.status(403).json({message: "Authentication failed"})
        }
        res.clearCookie(`${user.id}`);
        req.cookies[`${user.id}`] = "";
        return res.status(200).json({message:"Successfully Logged Out!"})
    })
}

module.exports = {signUp, logIn, verifyToken,getUser, refreshToken, logout};