<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\Routing\Annotation\Route;

class GithubController extends AbstractController
{
    /**
     * @Route("/github", name="github_connect")
     */
    public function connect(ParameterBagInterface $parameterBag)
    {
        $clientId = $parameterBag->get('client_id');

        return $this->redirect('https://github.com/login/oauth/authorize?scope=user:email&client_id=' . $clientId);
    }
}
