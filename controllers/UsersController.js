const Users = require(`../models/users`)
const apiResponse = require(`../helpers/apiResponse`)

const getAllUser = async(req,res) => {

    
    const allUsers = await Users.find({}).select(`-refreshToken -_id -password -createdAt -__v`);

    return apiResponse.successResponseWithData(res,"All users List",allUsers);

}


module.exports = {getAllUser}