import { generateToken } from "../lib/utils.js";
import User from "../models/usermodel.js"
import bcrypt from "bcryptjs"
import cloudinary from "../lib/cloudinary.js";
export const signup = async ( req , res) => {
     const { fullName , email , password } = req.body;

     try{
          if(!fullName ||!email ||!password){
               return res.status(400).json({message:"all field must be required"});

          }
          if (password.length<6){
               return res.status(400).json({message:"password must be at least 6 character"});

     }
     const user= await User.findOne({email})
     if(user) return res.status(400).json({message:"email is already exist"});
     const salt= await bcrypt.genSalt(10);
     const hashedPassword= await bcrypt.hash(password,salt)
     const newUser= new User({
          fullName,
          email,
          password:hashedPassword
     })
     if(newUser){
          generateToken(newUser._id,res);
          await newUser.save();

          res.status(201).json({
               _id:newUser._id,
               fullName:newUser.fullName,
               email:newUser.email,
               profilePic:newUser.profilePic,
               
          })

     }
     else{
          return  res.status(400).json({message:"Invalid user data!"});
     }
}
     catch(error){
          console.log("error in SignUp controller :", error.message);
          res.status(500).json({message:"Internal server error!"});

     }
};


export const login = async (req,res)=>{
     try {
         const {email,password}= req.body;
         const user = await User.findOne({email})
         if(!user){
          return res.status(400).json({message:"Invalid credentials"});
         }
         const isPasswordCorrect=await bcrypt.compare(password,user.password);
         if(!isPasswordCorrect){
          return res.status(400).json({message:"Invalid credentials"});
         }
         else{
          generateToken(user._id,res)
          res.status(200).json({
               _id:user._id,
               fullName:user.fullName,
               email:user.email,
               profilePic:user.profilePic,
               
          })

         }
          
     } catch (error) {
          console.log("error in Login controller :", error.message);
          res.status(500).json({message:"Internal server error!"});
          
     }
};


export const logout=(req,res)=>{
     try {
          res.cookie("jwt","", { maxAge: 0 } );
          res.status(200).json({message:"log out Succesfully"});
     } catch (error) {
          console.log("error in Logout controller :", error.message);
          res.status(500).json({message:"Internal server error!"});
          
     }
};

export const updateProfile = async (req,res)=>{
  try {
     const {profilePic}=req.body;
     const userId=req.user._id;
     if(!profilePic){
          return res.status(400).json({message:"profile pic is required"});
     }
     const uploadResponce= await cloudinary.uploader.upload(profilePic);
     const updatedUser =await User.findByIdAndUpdate(
          userId,
          {profilePic:uploadResponce.secure_url},
          {new:true});
          return res.status(200).json(updatedUser);
  } catch (error) {
     console.log("error in update profile :", error.message);
     res.status(500).json({message:"Internal server error!"});
     
     
  }

};

export const checkAuth = (req,res)=>{
     try {
          res.status(200).json(req.user);
     } catch (error) {
          console.log("error in checkAuth controller :", error.message);
          res.status(500).json({message:"Internal server error!"});
     }
}