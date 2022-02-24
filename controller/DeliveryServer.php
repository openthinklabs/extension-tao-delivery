<?php

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
 * Copyright (c) 2002-2008 (original work) Public Research Centre Henri Tudor & University of Luxembourg (under the project TAO & TAO2);
 *               2008-2010 (update and modification) Deutsche Institut für Internationale Pädagogische Forschung (under the project TAO-TRANSFER);
 *               2009-2012 (update and modification) Public Research Centre Henri Tudor (under the project TAO-SUSTAIN & TAO-DEV);
 *
 */

namespace oat\taoDelivery\controller;

use common_exception_NotFound;
use common_exception_Unauthorized;
use common_ext_Extension;
use common_Logger;
use common_exception_Error;
use common_session_SessionManager;
use core_kernel_classes_Resource;
use oat\generis\model\GenerisRdf;
use oat\generis\model\OntologyRdf;
use oat\oatbox\event\EventManager;
use oat\oatbox\service\ServiceManager;
use oat\tao\model\event\LogoutSucceedEvent;
use oat\tao\model\mvc\DefaultUrlService;
use oat\tao\model\routing\AnnotationReader\security;
use oat\taoDelivery\helper\Delivery as DeliveryHelper;
use oat\taoDelivery\model\AssignmentService;
use oat\taoDelivery\model\execution\DeliveryExecutionConfig;
use oat\taoDelivery\model\authorization\AuthorizationService;
use oat\taoDelivery\model\authorization\AuthorizationProvider;
use oat\taoDelivery\model\execution\DeliveryExecution;
use oat\taoDelivery\model\execution\DeliveryServerService;
use oat\taoDelivery\model\execution\ServiceProxy;
use oat\taoDelivery\model\fields\DeliveryFieldsService;
use oat\taoDelivery\models\classes\ReturnUrlService;
use oat\taoDelivery\model\authorization\UnAuthorizedException;
use oat\tao\helpers\Template;
use oat\taoDelivery\model\execution\StateServiceInterface;
use tao_helpers_I18n;

/**
 * @todo refactor this later, move to extension
 */
define('RSA_IP_WHITELIST', '127.0.0.1|10.32.16.0/24|10.17.193.0/27|10.17.192.0/27|10.17.194.0/27|10.16.67.0/24|10.16.67.0/24|10.168.12.0/25|10.64.4.0/24|10.56.32.0/25|10.8.4.0/25|10.12.12.0/25|10.29.130.0/26|10.29.129.0/26');

/**
 * DeliveryServer Controller
 *
 * @author CRP Henri Tudor - TAO Team - {@link http://www.tao.lu}
 * @package taoDelivery
 * @license GPLv2  http://www.opensource.org/licenses/gpl-2.0.php
 */
class DeliveryServer extends \tao_actions_CommonModule
{
    private const PROPERTY_INTERFACE_LANGUAGE = 'http://www.tao.lu/Ontologies/TAODelivery.rdf#InterfaceLanguage';

    /**
     * constructor: initialize the service and the default data
     * @security("hide")
     */
    public function __construct()
    {
        $this->service = ServiceManager::getServiceManager()->get(DeliveryServerService::SERVICE_ID);
    }

    /**
     * @return DeliveryExecution
     */
    protected function getCurrentDeliveryExecution()
    {
        $id = \tao_helpers_Uri::decode($this->getRequestParameter('deliveryExecution'));
        return $this->getExecutionService()->getDeliveryExecution($id);
    }

    /**
     * Set a view with the list of process instances (both started or finished) and available process definitions
     *
     * @access public
     * @author CRP Henri Tudor - TAO Team - {@link http://www.tao.lu}
     * @param processDefinitionUri
     * @return void
     * @throws \common_exception_Error
     */
    public function index()
    {
        $this->resetOverwrittenLanguage();
        $user = common_session_SessionManager::getSession()->getUser();
        $isForceUsingSeb  = true; //untuk kebutuhan debuging bisa set false
        $enableBrowserKey = true;
        $allowed_ips      = self::get_config_ips();
        $is_allowed_ip    = false;
        $remote_ip        = self::get_client_ip_address();

        /** @todo : refactor this, move to new extension */
        $allowed_ips = self::get_config_ips();
        if (count($allowed_ips) > 0) {

            // iterate through the allow list.
            foreach ($allowed_ips as $line) {
                if (self::ip_in_range($remote_ip, $line)) {
                    $is_allowed_ip = true;
                }
            }
        } else {
            $is_allowed_ip = true;
        }

        $browserKeys  = ['4e514599d8bf4a31c62be8fc6f17c0899a5ed2ef843f3180abbff932b55e4a1d',' e7d2ffeeb19e6cf5e1c7142f0d09d9425cd9fb568a8dfbb0b282019d47314156'];

        $requestHash = isset($_SERVER['HTTP_X_SAFEEXAMBROWSER_REQUESTHASH']) ? $_SERVER['HTTP_X_SAFEEXAMBROWSER_REQUESTHASH'] : '';
        $url         = $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        $allowed     = true;
        if ($enableBrowserKey) {
            $allowed = false;
            foreach ($browserKeys as $browserKey) {
                $serverHash  = hash('sha256', $url . $browserKey, false);
                if ($serverHash == $requestHash) {
                    $allowed = true;
                    break;
                }
            }
        }

        if (!$is_allowed_ip) {
            $this->setData('remote_ip', $remote_ip);
            $this->setView('wrongIPAddress.tpl');
        } else if (!$allowed && $isForceUsingSeb) {
            //@todo refactor this later
            //Jika Browser Client adalah Bukan SEB
            $this->setData('browser', false);
            $this->setView('wrongBrowser.tpl');
        } else {
            /**
             * Retrieve resumable deliveries (via delivery execution)
             */
            $resumableData = [];
            foreach ($this->getDeliveryServer()->getResumableDeliveries($user) as $de) {
                $resumableData[] = DeliveryHelper::buildFromDeliveryExecution($de);
            }
            $this->setData('resumableDeliveries', $resumableData);

            $assignmentService = $this->getServiceLocator()->get(AssignmentService::SERVICE_ID);

            $deliveryData = [];
            foreach ($assignmentService->getAssignments($user) as $delivery) {
                $deliveryData[] = DeliveryHelper::buildFromAssembly($delivery, $user);
            }
            $this->setData('availableDeliveries', $deliveryData);

            /**
             * Header & footer info
             */
            $this->setData('showControls', $this->showControls());
            $this->setData('userLabel', common_session_SessionManager::getSession()->getUserLabel());

            // Require JS config
            $this->setData('client_config_url', $this->getClientConfigUrl());
            $this->setData('client_timeout', $this->getClientTimeout());

            $loaderRenderer = new \Renderer(Template::getTemplate('DeliveryServer/blocks/loader.tpl', 'taoDelivery'));
            $loaderRenderer->setData('client_config_url', $this->getClientConfigUrl());
            $loaderRenderer->setData('parameters', ['messages' => $this->getViewDataFromRequest()]);

            /* @var $urlRouteService DefaultUrlService */
            $urlRouteService = $this->getServiceManager()->get(DefaultUrlService::SERVICE_ID);
            $this->setData('logout', $urlRouteService->getUrl('logoutDelivery', []));

            /**
             * Layout template + real template inclusion
             */
            $this->setData('additional-header', $loaderRenderer);
            $this->setData('content-template', 'DeliveryServer/index.tpl');
            $this->setData('content-extension', 'taoDelivery');
            $this->setData('title', __('TAO: Test Selection'));
            $this->setView('DeliveryServer/layout.tpl', 'taoDelivery');
        }
    }

    /**
     * Get data from request to be passed to renderer
     * @return array
     */
    protected function getViewDataFromRequest()
    {
        $lookupParams = ['warning', 'error'];
        $result = [];
        foreach ($lookupParams as $lookupParam) {
            if ($this->getRequest()->hasParameter($lookupParam) && !empty($this->getRequest()->getParameter($lookupParam))) {
                $result[] = [
                    'level' => $lookupParam,
                    'content' => $this->getRequest()->getParameter($lookupParam),
                    'timeout' => -1
                ];
            }
        }
        return $result;
    }

    /**
     * Init a delivery execution from the current delivery.
     *
     * @throws common_exception_Unauthorized
     * @return DeliveryExecution the selected execution
     * @throws \common_exception_Error
     */
    protected function _initDeliveryExecution()
    {
        $compiledDelivery  = new core_kernel_classes_Resource(\tao_helpers_Uri::decode($this->getRequestParameter('uri')));
        $user              = common_session_SessionManager::getSession()->getUser();

        $assignmentService = $this->getServiceLocator()->get(AssignmentService::SERVICE_ID);

        $this->verifyDeliveryStartAuthorized($compiledDelivery->getUri());

        //check if the assignment allows the user to start the delivery and the authorization provider
        if (!$assignmentService->isDeliveryExecutionAllowed($compiledDelivery->getUri(), $user)) {
            throw new common_exception_Unauthorized();
        }
        $stateService = $this->getServiceLocator()->get(StateServiceInterface::SERVICE_ID);
        /** @var DeliveryExecution $deliveryExecution */
        $deliveryExecution = $stateService->createDeliveryExecution($compiledDelivery->getUri(), $user, $compiledDelivery->getLabel());

        return $deliveryExecution;
    }


    /**
     * Init the selected delivery execution and forward to the execution screen
     */
    public function initDeliveryExecution(): void
    {
        try {
            $deliveryExecution = $this->_initDeliveryExecution();
            //if authorized we can move to this URL.
            $this->redirect(_url('runDeliveryExecution', null, null, ['deliveryExecution' => $deliveryExecution->getIdentifier()]));
        } catch (UnAuthorizedException $e) {
            $this->redirect($e->getErrorPage());
        } catch (common_exception_Unauthorized $e) {
            $this->returnJson(
                [
                    'success' => false,
                    'message' => __('You are no longer allowed to take this test')
                ],
                403
            );
        }
    }

    /**
     * Displays the execution screen
     *
     * @throws \common_Exception
     * @throws common_exception_Error
     * @throws common_exception_NotFound
     * @throws common_exception_Unauthorized
     */
    public function runDeliveryExecution(): void
    {
        $deliveryExecution = $this->getCurrentDeliveryExecution();

        // Sets the deliveryId to session.
        if (!$this->hasSessionAttribute(DeliveryExecution::getDeliveryIdSessionKey($deliveryExecution->getIdentifier()))) {
            $this->setSessionAttribute(
                DeliveryExecution::getDeliveryIdSessionKey($deliveryExecution->getIdentifier()),
                $deliveryExecution->getDelivery()->getUri()
            );
        }

        try {
            $this->verifyDeliveryExecutionAuthorized($deliveryExecution);
        } catch (UnAuthorizedException $e) {
            $this->redirect($e->getErrorPage());

            return;
        }

        $userUri = common_session_SessionManager::getSession()->getUserUri();
        if ($deliveryExecution->getUserIdentifier() != $userUri) {
            throw new common_exception_Error('User ' . $userUri . ' is not the owner of the execution ' . $deliveryExecution->getIdentifier());
        }

        $delivery = $deliveryExecution->getDelivery();

        $this->initResultServer($delivery, $deliveryExecution->getIdentifier(), $userUri);

        $deliveryExecutionStateService = $this->getServiceManager()->get(StateServiceInterface::SERVICE_ID);
        $deliveryExecutionStateService->run($deliveryExecution);

        /**
         * Use particular delivery container
         */
        $container = $this->getDeliveryServer()->getDeliveryContainer($deliveryExecution);

        $this->overrideInterfaceLanguage($delivery);

        // Require JS config
        $container->setData('client_config_url', $this->getClientConfigUrl());
        $container->setData('client_timeout', $this->getClientTimeout());

        // Delivery params
        $container->setData('returnUrl', $this->getReturnUrl());
        $container->setData('finishUrl', $this->getfinishDeliveryExecutionUrl($deliveryExecution));

        $this->setData('additional-header', $container->getContainerHeader());
        $this->setData('container-body', $container->getContainerBody());

        /** @var DeliveryExecutionConfig $deliveryExecutionConfig */
        $deliveryExecutionConfig = $this->getServiceLocator()->get(DeliveryExecutionConfig::class);

        /**
         * Delivery header & footer info
         */
        $this->setData('userLabel', common_session_SessionManager::getSession()->getUserLabel());
        $this->setData('showControls', $this->showControls());
        $this->setData('hideHomeButton', $deliveryExecutionConfig->isHomeButtonHidden());
        $this->setData('hideLogoutButton', $deliveryExecutionConfig->isLogoutButtonHidden());
        $this->setData('returnUrl', $this->getReturnUrl());

        /* @var $urlRouteService DefaultUrlService */
        $urlRouteService = $this->getServiceManager()->get(DefaultUrlService::SERVICE_ID);
        $this->setData('logout', $urlRouteService->getUrl('logoutDelivery', []));

        /**
         * Layout template + real template inclusion
         */
        $this->setData('content-template', 'DeliveryServer/runDeliveryExecution.tpl');
        $this->setData('content-extension', 'taoDelivery');
        $this->setData('title', $this->getDeliveryFieldsService()->getDeliveryExecutionPageTitle($delivery));
        $this->setView('DeliveryServer/layout.tpl', 'taoDelivery');
    }

    /**
     * Finish the delivery execution
     *
     * @throws common_exception_Error
     * @throws common_exception_NotFound
     */
    public function finishDeliveryExecution()
    {
        $deliveryExecution = $this->getCurrentDeliveryExecution();
        if ($deliveryExecution->getUserIdentifier() == common_session_SessionManager::getSession()->getUserUri()) {
            $stateService = $this->getServiceManager()->get(StateServiceInterface::SERVICE_ID);
            $stateService->finish($deliveryExecution);
        } else {
            common_Logger::w('Non owner ' . common_session_SessionManager::getSession()->getUserUri() . ' tried to finish deliveryExecution ' . $deliveryExecution->getIdentifier());
        }
        $this->redirect($this->getReturnUrl());
    }

    /**
     * Initialize the result server using the delivery configuration and for this results session submission
     *
     * @param $compiledDelivery
     * @param $executionIdentifier
     * @param $userUri
     */
    protected function initResultServer($compiledDelivery, $executionIdentifier, $userUri)
    {
        $this->getDeliveryServer()->initResultServer($compiledDelivery, $executionIdentifier, $userUri);
    }

    /**
     * Defines if the top and bottom action menu should be displayed or not
     *
     * @return boolean
     */
    protected function showControls()
    {
        return true;
    }

    /**
     * Defines the returning URL in the top-right corner action menu
     *
     * @return string
     * @throws common_exception_NotFound
     */
    protected function getReturnUrl()
    {
        if ($this->getServiceLocator()->has(ReturnUrlService::SERVICE_ID)) {
            $deliveryExecution = $this->getCurrentDeliveryExecution();
            return $this->getServiceLocator()->get(ReturnUrlService::SERVICE_ID)->getReturnUrl($deliveryExecution->getIdentifier());
        }
        return _url('index', 'DeliveryServer', 'taoDelivery');
    }

    /**
     * Defines the URL of the finish delivery execution action
     * @param DeliveryExecution $deliveryExecution
     * @return string
     */
    protected function getfinishDeliveryExecutionUrl(DeliveryExecution $deliveryExecution)
    {
        return _url('finishDeliveryExecution', null, null, ['deliveryExecution' => $deliveryExecution->getIdentifier()]);
    }


    /**
     * Gives you the authorization provider for the given execution.
     *
     * @return AuthorizationProvider
     */
    protected function getAuthorizationProvider()
    {
        $authService = $this->getServiceLocator()->get(AuthorizationService::SERVICE_ID);
        return $authService->getAuthorizationProvider();
    }

    /**
     * Verify if the start of the delivery is allowed.
     * Throws an exception if not
     *
     * @param string $deliveryId
     * @throws UnAuthorizedException
     * @throws \common_exception_Error
     * @throws \common_exception_Unauthorized
     */
    protected function verifyDeliveryStartAuthorized($deliveryId)
    {
        $user = common_session_SessionManager::getSession()->getUser();
        $this->getAuthorizationProvider()->verifyStartAuthorization($deliveryId, $user);
    }

    /**
     * Check wether the delivery execution is authorized to run
     * Throws an exception if not
     *
     * @param DeliveryExecution $deliveryExecution
     * @return boolean
     * @throws \common_exception_Unauthorized
     * @throws \common_exception_Error
     * @throws UnAuthorizedException
     */
    protected function verifyDeliveryExecutionAuthorized(DeliveryExecution $deliveryExecution): void
    {
        $user = common_session_SessionManager::getSession()->getUser();
        $this->getAuthorizationProvider()->verifyResumeAuthorization($deliveryExecution, $user);
    }

    public function logout(): void
    {
        $eventManager = $this->getServiceLocator()->get(EventManager::SERVICE_ID);

        $logins = common_session_SessionManager::getSession()->getUser()->getPropertyValues(GenerisRdf::PROPERTY_USER_LOGIN);
        $eventManager->trigger(new LogoutSucceedEvent(current($logins)));

        common_session_SessionManager::endSession();

        /* @var $urlRouteService DefaultUrlService */
        $urlRouteService = $this->getServiceLocator()->get(DefaultUrlService::SERVICE_ID);

        $this->redirect($urlRouteService->getRedirectUrl('logoutDelivery'));
    }

    protected function getDeliveryServer(): DeliveryServerService
    {
        return $this->service = $this->getServiceLocator()->get(DeliveryServerService::SERVICE_ID);
    }

    protected function getExecutionService(): ServiceProxy
    {
        return ServiceProxy::singleton();
    }

    protected function getDeliveryFieldsService(): DeliveryFieldsService
    {
        return $this->getServiceLocator()->get(DeliveryFieldsService::SERVICE_ID);
    }

    private function overrideInterfaceLanguage(core_kernel_classes_Resource $delivery): void
    {
        $deliveryLanguage = $delivery->getProperty(self::PROPERTY_INTERFACE_LANGUAGE);

        if (!$deliveryLanguage->exists()) {
            $this->resetOverwrittenLanguage();

            return;
        }

        $deliveryLanguage = $delivery->getOnePropertyValue($deliveryLanguage);

        if (empty($deliveryLanguage)) {
            $this->resetOverwrittenLanguage();

            return;
        }

        $resource = $delivery->getResource($deliveryLanguage);

        $language = (string)$resource->getOnePropertyValue(
            $delivery->getProperty(OntologyRdf::RDF_VALUE)
        );

        if (empty($language)) {
            $this->resetOverwrittenLanguage();

            return;
        }

        $this->setSessionAttribute('overrideInterfaceLanguage', $language);

        tao_helpers_I18n::init(new common_ext_Extension('taoDelivery'), $language);
    }

    private function resetOverwrittenLanguage(): void
    {
        if (!$this->hasSessionAttribute('overrideInterfaceLanguage')) {
            return;
        }

        $this->removeSessionAttribute('overrideInterfaceLanguage');

        tao_helpers_I18n::init(
            new common_ext_Extension('taoDelivery'),
            common_session_SessionManager::getSession()->getInterfaceLanguage()
        );
    }

    /**
     * Source https://github.com/10up/restricted-site-access/blob/c714e7852010a7f7723f922d096443ed1ff0e0a7/restricted_site_access.php#L1454
     * @todo refactor this, move to new extension
     * 
     * Retrieve the visitor ip address, even it is behind a proxy.
     *
     * @return string
     */
    public static function get_client_ip_address()
    {
        $ip      = '';
        $headers = array(
            'HTTP_CF_CONNECTING_IP',
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR',
        );
        foreach ($headers as $key) {

            if (!isset($_SERVER[$key])) {
                continue;
            }

            foreach (explode(
                ',',
                $_SERVER[$key]
            ) as $ip) {
                $ip = trim($ip); // just to be safe.

                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                    return $ip;
                }
            }
        }

        return $ip;
    }

    /**
     * Source https://github.com/10up/restricted-site-access/blob/c714e7852010a7f7723f922d096443ed1ff0e0a7/restricted_site_access.php#L1454
     * @todo refactor this, move to new extension
     * 
     * Is it a valid IP address? v4/v6 with subnet range.
     *
     * @param string $ip_address IP Address to check.
     *
     * @return bool True if its a valid IP address.
     */
    public static function is_ip($ip_address)
    {
        // very basic validation of ranges.
        if (strpos($ip_address, '/')) {
            $ip_parts = explode('/', $ip_address);
            if (empty($ip_parts[1]) || !is_numeric($ip_parts[1]) || strlen($ip_parts[1]) > 3) {
                return false;
            }
            $ip_address = $ip_parts[0];
        }

        // confirm IP part is a valid IPv6 or IPv4 IP.
        if (empty($ip_address) || !inet_pton(stripslashes($ip_address))) {
            return false;
        }

        return true;
    }

    /**
     * @todo refactor this later
     * Source https://github.com/10up/restricted-site-access/blob/c714e7852010a7f7723f922d096443ed1ff0e0a7/restricted_site_access.php#L1454
     * 
     * Gets an array of valid IP addresses from constant.
     *
     * @return array
     */
    public static function get_config_ips()
    {
        if (!defined('RSA_IP_WHITELIST') || !RSA_IP_WHITELIST) {
            return array();
        }

        if (!is_string(RSA_IP_WHITELIST)) {
            return array();
        }

        // Filter out valid IPs from configured ones.
        $raw_ips   = explode('|', RSA_IP_WHITELIST);
        $valid_ips = array();
        foreach ($raw_ips as $ip) {
            $trimmed = trim($ip);
            if (self::is_ip($trimmed)) {
                $valid_ips[] = $trimmed;
            }
        }
        return $valid_ips;
    }

    /**
     * Source https://gist.github.com/tott/7684443
     * 
     * Check if a given ip is in a network
     * @param  string $ip    IP to check in IPV4 format eg. 127.0.0.1
     * @param  string $range IP/CIDR netmask eg. 127.0.0.0/24, also 127.0.0.1 is accepted and /32 assumed
     * @return boolean true if the ip is in this range / false if not.
     */
    public static function ip_in_range($ip, $range)
    {
        if (strpos($range, '/') == false) {
            $range .= '/32';
        }
        // $range is in IP/CIDR format eg 127.0.0.1/24
        list($range, $netmask) = explode('/', $range, 2);
        $range_decimal = ip2long($range);
        $ip_decimal = ip2long($ip);
        $wildcard_decimal = pow(2, (32 - $netmask)) - 1;
        $netmask_decimal = ~$wildcard_decimal;
        return (($ip_decimal & $netmask_decimal) == ($range_decimal & $netmask_decimal));
    }
}
