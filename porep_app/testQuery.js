const crypto = require("crypto");
const {seal, setup} = require("../porep_app");
const {query} = require("./orai");

const filePath = `${__dirname}/test.txt`;
console.log(filePath);

const run = async () => {

    let listUser = await query({
        query_list_user: {
            limit: 10,
        },
    });
    console.log("resultVerify", listUser);
    let listReward = await query({
        query_user_reward: {
            user: listUser[0],
        },

    });
    console.log(`listReward`, listReward);


};

run();
