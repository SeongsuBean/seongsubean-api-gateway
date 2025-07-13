package com.example.seongsubeanapigateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class SeongsubeanApiGatewayApplication {

  public static void main(String[] args) {
    SpringApplication.run(SeongsubeanApiGatewayApplication.class, args);
  }

}
