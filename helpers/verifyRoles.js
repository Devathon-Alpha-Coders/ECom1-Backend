const jwt = require(`jsonwebtoken`)
const apiResponse = require(`./apiResponse`)

function verifyRoles(allowedRoles){
    
    return (req, res, next) => {

        if(!req.user || !req.user.roles){
            return apiResponse.unauthorizedResponse(res,"Access denied")
        }
        if (!Array.isArray(allowedRoles)) {
            throw new Error('allowedRoles should be an array of strings');
          }
      
          if (!Array.isArray(req.user.roles)) {
            throw new Error('req.user.roles should be an array of strings');
          }

          const hasAllowedRole = allowedRoles.some(role => req.user.roles.includes(role));

          if (!hasAllowedRole) {
            return apiResponse.unauthorizedResponse(res,"Access denied")
          }
      
          next();
  
   }
}
 

 module.exports = verifyRoles

