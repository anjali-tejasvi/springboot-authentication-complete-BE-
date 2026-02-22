package com.substring.auth.auth_app.exceptions;



public class ResourceNotFoundException extends RuntimeException {

     public  ResourceNotFoundException(String message){
         super(message);
     }

     public ResourceNotFoundException(){
         super("resource not found !");
     }
}
