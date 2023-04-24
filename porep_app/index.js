const { setup, seal } = require('./dist');

module.exports = {
  setup: (args) => {
    args.porep_id = args.porep_id.replace(/=/g, '');
    const ret = JSON.parse(setup(args));
    ret.setup_params.porep_id = Buffer.from(ret.setup_params.porep_id).toString('base64').replace(/=/g, '');
    ret.setup_params.api_version = ret.setup_params.api_version === 'V1_0_0' ? '1.0.0' : '1.1.0';
    return ret;
  },
  seal: (args) => {
    const setup_params = {
      ...args.setup_params,
      api_version: args.setup_params.api_version === '1.0.0' ? 'V1_0_0' : 'V1_1_0',
      porep_id: [...Buffer.from(args.setup_params.porep_id, 'base64')]
    };
    args.setup_params = JSON.stringify(setup_params);
    return JSON.parse(seal(args));
  }
};
