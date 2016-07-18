module.exports = function(grunt) {
    'use strict';

    var requirejs   = grunt.config('requirejs') || {};
    var clean       = grunt.config('clean') || {};
    var copy        = grunt.config('copy') || {};

    var root        = grunt.option('root');
    var libs        = grunt.option('mainlibs');
    var ext         = require(root + '/tao/views/build/tasks/helpers/extensions')(grunt, root);
    var out         = 'output';

    /**
     * Remove bundled and bundling files
     */
    clean.taodeliverybundle = [out];

    /**
     * Compile tao files into a bundle
     */
    requirejs.taodeliverybundle = {
        options: {
            baseUrl : '../js',
            dir : out,
            mainConfigFile : './config/requirejs.build.js',
            paths : { 'taoDelivery' : root + '/taoDelivery/views/js' },
            modules : [{
                name: 'taoDelivery/controller/routes',
                include : ext.getExtensionsControllers(['taoDelivery']),
                exclude : ['mathJax', 'taoDelivery/controller/DeliveryServer/index'].concat(libs)
            }, {
                name: 'taoDelivery/controller/DeliveryServer/index',
                include: ['lib/require', 'loader/bootstrap'],
                exclude : ['json!i18ntr/messages.json']
            }]
        }
    };

    /**
     * copy the bundles to the right place
     */
    copy.taodeliverybundle = {
        files: [
            { src: [out + '/taoDelivery/controller/routes.js'],      dest: root + '/taoDelivery/views/js/controllers.min.js' },
            { src: [out + '/taoDelivery/controller/routes.js.map'],  dest: root + '/taoDelivery/views/js/controllers.min.js.map' },
            { src: [out + '/taoDelivery/controller/DeliveryServer/index.js'],       dest: root + '/taoDelivery/views/js/loader/index.min.js' },
            { src: [out + '/taoDelivery/controller/DeliveryServer/index.js.map'],   dest: root + '/taoDelivery/views/js/loader/index.min.js.map' }
        ]
    };

    grunt.config('clean', clean);
    grunt.config('requirejs', requirejs);
    grunt.config('copy', copy);

    // bundle task
    grunt.registerTask('taodeliverybundle', ['clean:taodeliverybundle', 'requirejs:taodeliverybundle', 'copy:taodeliverybundle']);
};
