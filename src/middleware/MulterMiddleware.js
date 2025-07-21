import multer from "multer";
//in js we dont have a file system
const storage = multer.diskStorage({
     //two objects of functions
     //this middle ware was used in post
     destination: function (req, file, cb) {
          //where to store
          //cb is callback
          //first param is error hanling second is path, where path is stored
          //the following path is presend in our folder structure
          cb(null, "./public/temp");
     },
     filename: function (req, file, cb) {
          //second one is filename
          //we want the origial name of the file
          cb(null, file.originalname);
     },
});

export const upload = multer({
     storage,
});



