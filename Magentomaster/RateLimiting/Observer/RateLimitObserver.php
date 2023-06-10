<?php
namespace Magentomaster\RateLimiting\Observer;

use Magento\Framework\Event\Observer;
use Magento\Framework\Event\ObserverInterface;
use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\App\Response\Http as HttpResponse;
use Magento\Framework\HTTP\PhpEnvironment\RemoteAddress;
use Magento\Framework\Message\ManagerInterface;
use Magento\Framework\App\Request\Http as HttpRequest;
use Psr\Log\LoggerInterface;

class RateLimitObserver implements ObserverInterface
{
    protected $scopeConfig;
    protected $response;
    protected $remoteAddress;
    protected $messageManager;
    protected $request;
    protected $logger;

    public function __construct(
        ScopeConfigInterface $scopeConfig,
        HttpResponse $response,
        RemoteAddress $remoteAddress,
        ManagerInterface $messageManager,
        HttpRequest $request,
        LoggerInterface $logger
    ) {
        $this->scopeConfig = $scopeConfig;
        $this->response = $response;
        $this->remoteAddress = $remoteAddress;
        $this->messageManager = $messageManager;
        $this->request = $request;
        $this->logger = $logger;
    }

    public function execute(Observer $observer)
    {
        $isEnabled = $this->scopeConfig->getValue('rate_limiting/general/enabled');
        $requestsPerMinute = (int) $this->scopeConfig->getValue('rate_limiting/general/requests_per_minute');
        $ipAddress = $this->remoteAddress->getRemoteAddress();
        
        if ($isEnabled && $requestsPerMinute > 0) {
             //check if searched url is correct
            $query = $this->request->getParam('q');
            $pattern = '/^[A-Za-z0-9!@#$%^&*()\-_=+{};:,.<>?[\]\'"\/\\|~` ]+$/';
            if(!empty($query)){
                if (!preg_match($pattern, $query))
                {
                    $this->logger->info('Search is from other language from IP: ' . $ipAddress);
                    $this->response->setHttpResponseCode(429); // Too Many Requests
                    $this->response->setBody('Stop Spamming');
                    $this->response->sendResponse();
                    exit();
                }
            }
            //end here
            
            $cacheKey = 'rate_limiting_' . md5($ipAddress);

            $cache = \Magento\Framework\App\ObjectManager::getInstance()->get(\Magento\Framework\App\CacheInterface::class);
            $rateLimitData = $cache->load($cacheKey);
            $rateLimitData = $rateLimitData ? unserialize($rateLimitData) : [];

            $currentTime = time();
            $rateLimitData[] = $currentTime;

            // Remove expired requests
            $rateLimitData = array_filter($rateLimitData, function ($timestamp) use ($currentTime, $requestsPerMinute) {
                return $timestamp >= ($currentTime - 60) && $timestamp <= $currentTime;
            });

            if (count($rateLimitData) > $requestsPerMinute) {
                $this->logger->info('Rate limit exceeded for IP: ' . $ipAddress);
                $this->response->setHttpResponseCode(429); // Too Many Requests
                $this->response->setBody('Rate limit exceeded. Please try again later.');
                $this->response->sendResponse();
                exit();
            }

            $cache->save(serialize($rateLimitData), $cacheKey, [], 60);
        }
    }
}
