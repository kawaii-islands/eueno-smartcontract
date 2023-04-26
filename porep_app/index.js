const {setup, seal} = require('./dist');

module.exports = {
    setup: (args) => {
        return JSON.parse(setup(args));
    },
    seal: (args) => {
        return JSON.parse(
            seal({
                ...args,
                setup_params: JSON.stringify({
                    ...args.setup_params,
                }),
            }),
        );
    },
};
