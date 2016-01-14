/**
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; under version 2
 * of the License (non-upgradable).
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (c) 2016 (original work) Open Assessment Technologies SA ;
 */
/**
 * @author Jean-Sébastien Conan <jean-sebastien.conan@vesperiagroup.com>
 */
define([
    'jquery',
    'lodash',
    'helpers'
], function ($, _, helpers) {
    'use strict';

    return {
        start: function (options) {
            $('.test-runner').html('<h1>NEW TEST RUNNER</h1>');

            // test runner service check
            $.ajax({
                url: helpers._url('init', 'Runner', 'taoQtiTest', {
                    testDefinition: options.testDefinition,
                    testCompilation: options.testCompilation,
                    serviceCallId: options.serviceCallId
                })
            });
        }
    }
});
