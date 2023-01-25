const {sequelize} = require('./db');
const {Kitten, User} = require('./');
const {kittens, users} = require('./seedData');

const seed = async () => {
  await sequelize.sync({ force: true }); // recreate db
  await Kitten.bulkCreate(kittens);
  await User.bulkCreate(users);
};

module.exports = seed;
