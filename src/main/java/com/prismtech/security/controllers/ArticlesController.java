package com.prismtech.security.controllers;

import com.prismtech.security.model.Articles;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;

@RestController
public class ArticlesController {

    @GetMapping("/resource-apis/articles-user")
    @PreAuthorize("hasAnyAuthority('user.read')")
    public Articles getArticlesForUser() {
        System.out.println("auth: " + SecurityContextHolder.getContext().getAuthentication().toString());
        System.out.println("principal: " + SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        jwt.getClaims().forEach((k, v) -> System.out.println("claim key: " + k + ", claim value: " + v));
        jwt.getHeaders().forEach((k, v) -> System.out.println("header key: " + k + ", header value: " + v));
        Articles articles = new Articles();
        articles.setArticles(Arrays.asList("Article 1", "Article 2", "Article 3"));
        return articles;
    }

    @GetMapping("/resource-apis/articles-system")
    @PreAuthorize("hasAnyAuthority('system.read')")
    public String[] getArticlesForSystem() {
        System.out.println("auth system: " + SecurityContextHolder.getContext().getAuthentication().toString());
        System.out.println("principal: " + SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
        Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        jwt.getClaims().forEach((k, v) -> System.out.println("claim key: " + k + ", claim value: " + v));
        jwt.getHeaders().forEach((k, v) -> System.out.println("header key: " + k + ", header value: " + v));

        return new String[] { "Article 5", "Article 6", "Article 7" };
    }
}
