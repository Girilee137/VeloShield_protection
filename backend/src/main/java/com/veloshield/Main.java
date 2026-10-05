package com.veloshield;

import com.veloshield.config.DatabaseManager;
import com.veloshield.filter.CorsFilter;
import com.veloshield.servlet.AuthServlet;
import com.veloshield.servlet.MitigationServlet;
import com.veloshield.servlet.TargetServlet;
import com.veloshield.servlet.TestServlet;
import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;

import java.io.File;

public class Main {

    public static void main(String[] args) throws LifecycleException {
        // Initialize database
        System.out.println("[VeloShield] Initializing database...");
        DatabaseManager.initialize();
        System.out.println("[VeloShield] Database initialized.");

        // Read port from environment
        String portEnv = System.getenv("PORT");
        int port = (portEnv != null && !portEnv.isBlank()) ? Integer.parseInt(portEnv.trim()) : 8080;

        // Create embedded Tomcat
        Tomcat tomcat = new Tomcat();
        tomcat.setBaseDir(System.getProperty("java.io.tmpdir"));

        // Configure connector
        Connector connector = new Connector();
        connector.setPort(port);
        connector.setProperty("relaxedQueryChars", "[]|{}^&#x5C;&#x60;&quot;&lt;&gt;");
        tomcat.getService().addConnector(connector);
        tomcat.setConnector(connector);

        // Create context
        Context ctx = tomcat.addContext("", new File(".").getAbsolutePath());

        // Add CORS filter
        FilterDef corsFilterDef = new FilterDef();
        corsFilterDef.setFilterName("CorsFilter");
        corsFilterDef.setFilterClass(CorsFilter.class.getName());
        ctx.addFilterDef(corsFilterDef);

        FilterMap corsFilterMap = new FilterMap();
        corsFilterMap.setFilterName("CorsFilter");
        corsFilterMap.addURLPattern("/*");
        ctx.addFilterMap(corsFilterMap);

        // Register servlets
        Tomcat.addServlet(ctx, "AuthServlet", new AuthServlet());
        ctx.addServletMappingDecoded("/api/auth/*", "AuthServlet");

        Tomcat.addServlet(ctx, "TargetServlet", new TargetServlet());
        ctx.addServletMappingDecoded("/api/targets", "TargetServlet");
        ctx.addServletMappingDecoded("/api/targets/*", "TargetServlet");

        Tomcat.addServlet(ctx, "TestServlet", new TestServlet());
        ctx.addServletMappingDecoded("/api/tests", "TestServlet");
        ctx.addServletMappingDecoded("/api/tests/*", "TestServlet");

        Tomcat.addServlet(ctx, "MitigationServlet", new MitigationServlet());
        ctx.addServletMappingDecoded("/api/mitigation/*", "MitigationServlet");

        Tomcat.addServlet(ctx, "PreDeploymentServlet", new com.veloshield.servlet.PreDeploymentServlet());
        ctx.addServletMappingDecoded("/api/predeployment/*", "PreDeploymentServlet");

        Tomcat.addServlet(ctx, "PostDeploymentServlet", new com.veloshield.servlet.PostDeploymentServlet());
        ctx.addServletMappingDecoded("/api/postdeployment/*", "PostDeploymentServlet");

        Tomcat.addServlet(ctx, "AssessmentServlet", new com.veloshield.servlet.AssessmentServlet());
        ctx.addServletMappingDecoded("/api/assessments", "AssessmentServlet");
        ctx.addServletMappingDecoded("/api/assessments/*", "AssessmentServlet");

        // Static files (serves frontend HTML, CSS, JS from classpath /static or local disk)
        Tomcat.addServlet(ctx, "StaticServlet", new com.veloshield.servlet.StaticServlet());
        ctx.addServletMappingDecoded("/", "StaticServlet");

        // Start Tomcat
        tomcat.start();
        System.out.println("[VeloShield] Server started on port " + port);
        tomcat.getServer().await();
    }
}
