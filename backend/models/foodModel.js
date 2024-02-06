const mongoose=require('mongoose');

mongoose.connect('mongodb+srv://aaraav:aaraav@cluster0.kyxqnj3.mongodb.net/blog');

const foodSchema = new mongoose.Schema({
    image:{ 
      type: String,
     unique:true,
       required: true
       },
   
       
    description:{
        type:String,
        required:true,
        
    },
    price:{
        type:Number,
        required:true
    }
   
    
  });

  module.exports=mongoose.model('food',foodSchema);
  