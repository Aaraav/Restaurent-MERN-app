const mongoose=require('mongoose');

mongoose.connect('mongodb+srv://aaraav:aaraav@cluster0.kyxqnj3.mongodb.net/blog');

const userSchema = new mongoose.Schema({
    username:{ 
      type: String,
     unique:true,
       required: true
       },
    email: { type: String,
       required: true,
       unique:true },
       
    password:{
        type:String,
        required:true,
        
    },
   
    
  });

  module.exports=mongoose.model('User',userSchema);
  