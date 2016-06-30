// create a webpack configuration with all common parts included here
var createWebpackConfig = function(options) {
  return {
    entry: options.entry,
    output: options.output,
    plugins: options.plugins,
    node: {
      fs: 'empty' // Because of jsrsasign usage of fs
    },
    module: {
      loaders: [
        {
          test: /.tsx?$/,
          loaders: ['ts-loader'],
          exclude: /node_modules/,
          include: __dirname
        }
      ]
    },
    // this is for the sourcemaps
    devtool: options.devtool
  };
};

module.exports = createWebpackConfig;
