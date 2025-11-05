package com.autosolutions.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.HiddenHttpMethodFilter;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    /**
     * Mapea WebJars y recursos estáticos con cache razonable.
     * Nota: Spring Boot ya sirve /static/** por defecto; aquí reforzamos WebJars.
     */
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        // WebJars (Bootstrap, bootstrap-icons, etc.)
        registry.addResourceHandler("/webjars/**")
                .addResourceLocations("classpath:/META-INF/resources/webjars/")
                .setCachePeriod(3600);

        // Si quieres ser explícito con estáticos (opcional, Boot ya lo hace)
        registry.addResourceHandler("/css/**")
                .addResourceLocations("classpath:/static/css/")
                .setCachePeriod(3600);

        registry.addResourceHandler("/js/**")
                .addResourceLocations("classpath:/static/js/")
                .setCachePeriod(3600);

        registry.addResourceHandler("/images/**")
                .addResourceLocations("classpath:/static/images/")
                .setCachePeriod(3600);
    }

    /**
     * Permite usar <input type="hidden" name="_method" value="PUT|DELETE">
     * en formularios Thymeleaf para simular métodos HTTP.
     */
    @Bean
    public HiddenHttpMethodFilter hiddenHttpMethodFilter() {
        return new HiddenHttpMethodFilter();
    }
}
