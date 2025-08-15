import User from "../models/user.model.js";
import jwt from 'jsonwebtoken';
import {redis} from '../lib/redis.js'

const generateTokens = (userId) =>{
    const accessToken = jwt.sign({userId}, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: '15m'
    });

    const refereshToken = jwt.sign({userId}, process.env.REFERESH_TOKEN_SECRET, {
        expiresIn: '7d',
    });

    return {accessToken, refereshToken};
}


const storeRefereshToken = async (userId, refereshToken) =>{
    await redis.set(`referesh_token:${userId}`, refereshToken, "EX", 7*24*60*60);
}

const setCookies = (res, accessToken, refereshToken) =>{
    res.cookie("accessToken", accessToken, {
        httpOnly: true, //prevents xss attacks, cross site scripting attacks
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict', //prevents CSRF attack, cross site request forgery attack
        maxAge: 15*60*1000,
    })

    res.cookie("refereshToken", refereshToken, {
        httpOnly: true, //prevents xss attacks, cross site scripting attacks
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict', //prevents CSRF attack, cross site request forgery attack
        maxAge: 7*24*60*60*1000,
    })
}

export const signup = async (req, res) => {
    const {email, password, name} = req.body;
    try {
        const userExists = await User.findOne({email});
        if(userExists){
            return res.status(400).json({message: "User already exists"});
        }
        const user = await User.create({name, email, password});
        const {accessToken, refereshToken} = generateTokens(user._id);
        await storeRefereshToken(user._id, refereshToken);
        setCookies(res, accessToken, refereshToken);
        res.status(201).json({
            _id:user._id,
            name: user.name,
            email: user.email,
            role: user.role
        });
    } catch (error) {
        console.log("Error in signup controller", error.message);
        res.status(500).json({message: error.message});
    }
}

export const login = async (req, res) => {
    try{
        const {email, password} = req.body;
        const user = await User.findOne({email});
        if(user && (await user.comparePassword(password))){
            const {accessToken, refereshToken} = generateTokens(user._id);
            await storeRefereshToken(user._id, refereshToken)
            setCookies(res, accessToken, refereshToken);
            res.json({
                _id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            })
        }else{
            res.status(401).json({message: 'Invalid email or password'});
        }
    }catch(error ){
        console.log("Error in login controller", error.message);
        res.status(500).json({message: error.message});
    }
}

export const logout = async (req, res) => {
    try {
        const refereshToken = req.cookies.refereshToken;
        if(refereshToken){
            const decoded = jwt.verify(refereshToken, process.env.REFERESH_TOKEN_SECRET);
            await redis.del(`referesh_token:${decoded.userId}`);
        }
        res.clearCookie('accessToken');
        res.clearCookie('refereshToken');
        res.json({message:"Logged out successfully"});
    } catch (error) {
        console.log("Error in logout controller", error.message);
        res.status(500).json({message:'server error', error: error.message});
    }
}

export const refereshToken = async (req, res) =>{
    try{
        const refereshToken = req.cookies.refereshToken;
        if(!refereshToken){
            return res.status(401).json({message:"No referesh token provided"});
        }
        const decoded = jwt.verify(refereshToken, process.env.REFERESH_TOKEN_SECRET);
        const storedToken = await redis.get(`referesh_token:${decoded.userId}`);
        if(storedToken !== refereshToken){
            return res.status(401).json({message: "Invalid referesh token"});
        }
        const accessToken = jwt.sign({userId: decoded.userId}, process.env.ACCESS_TOKEN_SECRET, {expiresIn:'15m'});

        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 15*60*1000
        })
        res.json({message: 'Token refereshed successfully'});
    }catch(error){
        console.log('Error in refereshToken controller', error.message);
        res.status(500).json({message:"Server error", error: error.message})
    }
}

export const getProfile = async (req, res) =>{
    try {
        res.json(req.user);
    } catch (error) {
        res.status(500).json({message: "Server error", error: error.message});
    }
}