<?php
/**
 * Created by PhpStorm.
 * User: jeffe
 * Date: 03/09/2018
 * Time: 18:54
 */

namespace Hcode;


class PageAdmin extends Page
{

    public function __construct(array $opts = array(), $tpl_dir = "/views/admin/")
    {
        parent::__construct($opts, $tpl_dir);
    }

}