package com.seo.jwt.filter;

import javax.servlet.*;
import java.io.IOException;

public class MyFilter1 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
//        System.out.println("필터 1");
       chain.doFilter(request, response);

    }
}
