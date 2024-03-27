
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const userSchema = new mongoose.Schema({
    email: {
        type: String,
        unique: true,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    phoneNumber: {
        type: String,
        validate: {
            validator: function (value) {
                // Custom validation logic for phone number
                return /^\d{10}$/.test(value); // Validate if value is a 10-digit number
            },
            message: 'Phone number must be a 10-digit number'
        }
    },
    name: {
        type: String,
        minlength: [2, 'Name must be at least 2 characters long'], // Minimum length validation
        maxlength: [50, 'Name cannot exceed 50 characters'] // Maximum length validation
    }
});
userSchema.pre('save',function(next){
    const user=this;
    if(!user.isModified('password')){
        return next();
    }
    bcrypt.genSalt(10,(err,salt)=>{
        if(err){
            return next(err);
        }
        bcrypt.hash(user.password,salt,(err,hash)=>{
            if(err){
                return next(err);
            }
            user.password=hash;
            next();
        })
    })
})

userSchema.methods.comparePassword=function(candidatePassword){
    const user=this;
    return new Promise((resolve,reject)=>{
        bcrypt.compare(candidatePassword,user.password,(err,isMatch)=>{
            if(err){
                return reject(err);
            }
            if(!isMatch){
                return reject(false);
            }
            resolve(true);
        })
    })
}

module.exports = mongoose.model('User', userSchema);
