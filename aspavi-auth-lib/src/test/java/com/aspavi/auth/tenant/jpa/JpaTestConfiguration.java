package com.aspavi.auth.tenant.jpa;

import org.springframework.boot.autoconfigure.AutoConfigurationPackage;
import org.springframework.context.annotation.Configuration;

/** Like a service's {@code @SpringBootApplication}: entities and repositories of this package. */
@Configuration(proxyBeanMethods = false)
@AutoConfigurationPackage
public class JpaTestConfiguration {
}
