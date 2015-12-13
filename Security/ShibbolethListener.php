<?php

namespace KULeuven\ShibbolethBundle\Security;

use KULeuven\ShibbolethBundle\Service\Shibboleth;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;

class ShibbolethListener extends AbstractAuthenticationListener
{
    private $shibboleth;

    public function __construct($securityContext, AuthenticationManagerInterface $authenticationManager, SessionAuthenticationStrategyInterface $sessionStrategy, HttpUtils $httpUtils, $providerKey, AuthenticationSuccessHandlerInterface $successHandler, AuthenticationFailureHandlerInterface $failureHandler, array $options = array(), LoggerInterface $logger = null, EventDispatcherInterface $dispatcher = null, Shibboleth $shibboleth = null)
    {
        if ($shibboleth === null)
            throw new \InvalidArgumentException('Shibboleth service missing.');
        parent::__construct($securityContext, $authenticationManager, $sessionStrategy, $httpUtils, $providerKey, $successHandler, $failureHandler, $options, $logger, $dispatcher);
        $this->shibboleth = $shibboleth;
    }

    /**
     * Performs authentication.
     *
     * @param Request $request A Request instance
     *
     * @return TokenInterface|Response|null The authenticated token, null if full authentication is not possible, or a
     *                                      Response
     *
     * @throws AuthenticationException if the authentication fails
     */
    protected function attemptAuthentication(Request $request)
    {
        if (!$this->shibboleth->isAuthenticated($request))
            return RedirectResponse::create($this->shibboleth->getLoginUrl($request));
        $username = $this->shibboleth->getUser($request);

        $attributes = $this->shibboleth->getAttributes($request);

        if ($this->logger !== null) $this->logger->debug(sprintf('Shibboleth returned attributes from: %s', @$attributes['identityProvider']));

        return $this->authenticationManager->authenticate(new ShibbolethUserToken($username, $attributes));
    }

}