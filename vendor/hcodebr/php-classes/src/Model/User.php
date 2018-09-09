<?php
/**
 * Created by PhpStorm.
 * User: jeffe
 * Date: 03/09/2018
 * Time: 20:58
 */

namespace Hcode\Model;


use Hcode\DB\Sql;
use Hcode\Mailer;
use Hcode\Model;


class User extends Model
{

    const SESSION = "User";
    const KEY = "qe7KrpwTQTee6IeSsAVuktlXhnn/tHIHBbADuDUwfgY";

    public static function login($login, $password)
    {

        $sql = new Sql();
        $results = $sql->select("SELECT * FROM tb_users WHERE deslogin = :LOGIN", array(
            ":LOGIN"=>$login
        ));

        if (count($results) === 0){
            throw new \Exception("Usuário inexistente ou senha inválida.");
        }

        $data = $results[0];

        if(password_verify($password, $data["despassword"])){

            $user  = new  User();
            $user->setData($data);

            $_SESSION[User::SESSION] = $user->getValues();

//            Debug
//            var_dump($user);
//            exit;
        }
        else{
            throw new \Exception("Usuário inexistente ou senha inválida.");
        }

    }

    public static function verifyLogin($inadmin = true){

        if(
            !isset($_SESSION[User::SESSION])
            ||
            !$_SESSION[User::SESSION]
            ||
            !(int)$_SESSION[User::SESSION]["iduser"] > 0
            ||
            (bool)$_SESSION[User::SESSION]["inadmin"] !== $inadmin
        ){
            header("Location: /admin/login");
            exit;
        }

    }

    public static function logout(){
        $_SESSION[User::SESSION] = null;
    }

    public static function listAll(){

        $sql = new Sql();
        return $sql->select("SELECT * FROM tb_users a INNER JOIN tb_persons b USING(idperson) ORDER BY b.desperson");

    }

    public function Save(){

        $sql = new Sql();

        $results = $sql->select("CALL sp_users_save(:desperson, :deslogin, :despassword, :desemail, :nrphone, :inadmin)", array(
            ":desperson" => $this->getdesperson(),
            ":deslogin" => $this->getdeslogin(),
            ":despassword" => $this->getdespassword(),
            ":desemail" => $this->getdesemail(),
            ":nrphone" => $this->getnrphone(),
            ":inadmin" => $this->getinadmin(),
        ));

        $this->setData($results[0]);

    }

    public function get($iduser){
        $sql = new Sql();
        $results = $sql->select("SELECT * FROM tb_users a 
                                INNER JOIN tb_persons b 
                                USING(idperson)
                                WHERE a.iduser = :iduser",
            array(
                ":iduser"=>$iduser
            ));

         $this->setData($results[0]);
    }

    public function update(){
        $sql = new Sql();
        $results = $sql->select("CALL sp_usersupdate_save(:iduser ,:desperson, :deslogin, :despassword, :desemail, :nrphone, :inadmin)", array(
            ":iduser" => $this->getiduser(),
            ":desperson" => $this->getdesperson(),
            ":deslogin" => $this->getdeslogin(),
            ":despassword" => $this->getdespassword(),
            ":desemail" => $this->getdesemail(),
            ":nrphone" => $this->getnrphone(),
            ":inadmin" => $this->getinadmin(),
        ));

        $this->setData($results[0]);
    }

    public function delete(){
        $sql = new Sql();
        $sql->select("CALL sp_users_delete(:iduser)", array(
            ":iduser"=>$this->getiduser()
        ));
    }

    public static function getForgot($email){


        $sql = new Sql();
        $results = $sql->select("
          SELECT * FROM tb_persons a
	      INNER JOIN tb_users b USING(idperson) 
	      WHERE a.desemail = :desemail", array(
            ":desemail"=> $email
        ));

        if(count($results) === 0){
            throw new \Exception("Não foi possível recuperar a senha!");
        }
        else {
            $sql1 = new Sql();
            $data = $results[0];
            $results2 = $sql->select("CALL sp_usersrecoveries_create (:iduser, :desip)", array(
                ":iduser"=>$data["iduser"],
                ":desip"=>$_SERVER["REMOTE_ADDR"]
            ));

            if(count($results2)=== 0){
                throw new \Exception("Não foi possível recuperar a senha!");
            }
            else{
                $dataRecovery = $results2[0];


                $encryption_key = base64_decode(User::KEY);
                // Generate an initialization vector
                $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
                // Encrypt the data using AES 256 encryption in CBC mode using our encryption key and initialization vector.
                $encrypted = openssl_encrypt($dataRecovery['idrecovery'], 'aes-256-cbc', $encryption_key, 0, $iv);
                // The $iv is just as important as the key for decrypting, so save it with our encrypted data using a unique separator (::)
                $code = base64_encode($encrypted . '::' . $iv);


                $link = "http://www.ecommerc.com.br/admin/forgot/reset?code=$code";

                $mailer = new Mailer($data["desemail"],$data["desperson"], "Redefinir senha loja", "forgot", array(
                    "name"=>$data["desperson"],
                    "link"=>$link
                ));

                $mailer->send();

                return $data;

            }

        }

    }

    public static function validForgotDecrypt($code){
        $code = str_replace(" ", "+", $code);

        $encryption_key = base64_decode(User::KEY);
        // To decrypt, split the encrypted data from our IV - our unique separator used was "::"
        list($encrypted_data, $iv) = explode('::', base64_decode($code), 2);

        $idrecovery = openssl_decrypt($encrypted_data, 'aes-256-cbc', $encryption_key, 0, $iv);

        //($idrecovery);
        //exit;

        $sql = new Sql();
        $results = $sql->select("
                SELECT * FROM tb_userspasswordsrecoveries a
                INNER JOIN tb_users b USING (iduser)
                INNER JOIN tb_persons c USING (idperson)
                WHERE 
                a.idrecovery = :idrecovery
                AND 
                a.dtrecovery is null
                and
                date_add(a.dtregister, interval 1 hour) >= now()", array(
                    ":idrecovery"=>$idrecovery
        ));

        if(count($results) === 0){
            throw new \Exception("Não foi possível recuperar a senha!");
        }
        else{
            return $results[0];
        }
    }

    public static function setForgotUsed($idRecovery){

        $sql = new Sql();
        $sql->query("UPDATE tb_userspasswordsrecoveries SET dtrecovery = NOW() WHERE idrecovery = :idrecovery", array(
            ":idrecovery"=>$idRecovery
        ));
    }

    public function setPassword($password){

        $sql = new Sql();

        $sql->query("UPDATE tb_users SET despassword = :despassword WHERE iduser = :iduser", array(
            ":despassword"=>$password,
            ":iduser"=>$this->getiduser()
        ));

    }
}