<?php

$servername="localhost";
$username="root";
$password="";
$databaseName="driverrentalsystem";

//create connection.....
$conn=mysqli_connect($servername,$username,$password,$databaseName);

if(!$conn)
{
  echo ("Connection Failed.....".mysqli_connect_error());
}
 ?>
