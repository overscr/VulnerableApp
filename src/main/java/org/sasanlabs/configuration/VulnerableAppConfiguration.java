package org.sasanlabs.configuration;

import com.zaxxer.hikari.HikariDataSource;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import org.sasanlabs.internal.utility.LevelConstants;
import org.sasanlabs.service.vulnerability.fileupload.UnrestrictedFileUpload;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Primary;
import org.springframework.context.support.ReloadableResourceBundleMessageSource;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.io.support.PropertiesLoaderUtils;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.init.DataSourceInitializer;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.multipart.MultipartResolver;
import org.springframework.web.multipart.commons.CommonsMultipartResolver;
import org.springframework.web.multipart.support.MultipartFilter;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;

/**
 * This is the Configuration Class for Injecting Configurations into the Context.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
@Configuration
public class VulnerableAppConfiguration {

    private static final String I18N_MESSAGE_FILE_LOCATION = "classpath:i18n/messages";
    private static final String ATTACK_VECTOR_PAYLOAD_PROPERTY_FILES_LOCATION_PATTERN =
            "classpath:/attackvectors/*.properties";
    private static final List<String> MAX_FILE_UPLOAD_SIZE_OVERRIDE_PATHS =
            Arrays.asList(
                    "/" + UnrestrictedFileUpload.CONTROLLER_PATH + "/" + LevelConstants.LEVEL_9);

    /** Paths whose handler already sets its own framing headers, so the filter must not repeat them. */
    private static final String CLICKJACKING_CONTROLLER_PATH = "/ClickjackingVulnerability";

    /**
     * Will Inject MessageBundle into messageSource bean.
     *
     * @return resourceBundle
     */
    @Bean
    public ReloadableResourceBundleMessageSource messageSource() {
        ReloadableResourceBundleMessageSource messageSource =
                new ReloadableResourceBundleMessageSource();
        messageSource.setBasename(I18N_MESSAGE_FILE_LOCATION);
        messageSource.setCacheSeconds(100);
        messageSource.setDefaultEncoding("UTF-8");
        return messageSource;
    }

    @Bean
    public AcceptHeaderLocaleResolver localeResolver() {
        final AcceptHeaderLocaleResolver resolver = new AcceptHeaderLocaleResolver();
        resolver.setDefaultLocale(Locale.US);
        return resolver;
    }

    /**
     * This method reads all the property which are useful for vulnerableApp and then injects them
     * into the context so that entire application can use it.
     *
     * @param resourceLoader
     * @return {@link VulnerableAppProperties} which is injected in spring context.
     * @throws IOException
     */
    @Bean
    public VulnerableAppProperties propertyLoader(ResourceLoader resourceLoader)
            throws IOException {
        Resource[] attackVectorsResources =
                new PathMatchingResourcePatternResolver()
                        .getResources(ATTACK_VECTOR_PAYLOAD_PROPERTY_FILES_LOCATION_PATTERN);
        Properties attackVectorProperties = new Properties();
        for (Resource attackVectorResource : attackVectorsResources) {
            PropertiesLoaderUtils.fillProperties(attackVectorProperties, attackVectorResource);
        }
        VulnerableAppProperties vulnerableAppProperties =
                new VulnerableAppProperties(attackVectorProperties);
        return vulnerableAppProperties;
    }

    /**
     * DB Configuration Below configuration is done to restrict the Application user rights and not
     * to give admin access rights to it. This is quite important because in case of any
     * Vulnerability in application it reduces the impact of the destruction because of the
     * vulnerability.
     */
    @Bean
    @Primary
    @ConfigurationProperties("spring.datasource.admin")
    public DataSourceProperties adminDataSourceProperties() {
        return new DataSourceProperties();
    }

    @Bean
    @Primary
    @ConfigurationProperties("spring.datasource.admin.configuration")
    public DataSource adminDataSource(
            @Qualifier("adminDataSourceProperties")
                    DataSourceProperties adminDataSourceProperties) {
        return adminDataSourceProperties
                .initializeDataSourceBuilder()
                .type(HikariDataSource.class)
                .build();
    }

    /**
     * Initializes the admin DataSource by running schema and data SQL scripts. This creates tables,
     * the 'application' H2 DB user, and grants permissions. Must run before the
     * applicationDataSource bean tries to connect.
     */
    @Bean
    public DataSourceInitializer adminDataSourceInitializer(
            @Qualifier("adminDataSource") DataSource adminDataSource,
            @Value("${spring.datasource.application.password}") String appPassword) {
        ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
        JdbcTemplate adminJdbcTemplate = new JdbcTemplate(adminDataSource);
        adminJdbcTemplate.execute(
                String.format("CREATE USER application PASSWORD '%s'", appPassword));
        populator.addScript(new ClassPathResource("scripts/SQLInjection/db/schema.sql"));
        populator.addScript(new ClassPathResource("scripts/xss/PersistentXSS/db/schema.sql"));
        populator.addScript(new ClassPathResource("scripts/XXEVulnerability/schema.sql"));
        populator.addScript(new ClassPathResource("scripts/SQLInjection/db/data.sql"));
        populator.addScript(new ClassPathResource("scripts/IDOR/db/schema.sql"));
        populator.addScript(new ClassPathResource("scripts/IDOR/db/data.sql"));
        populator.addScript(new ClassPathResource("scripts/Authentication/db/schema.sql"));
        populator.addScript(new ClassPathResource("scripts/Authentication/db/data.sql"));
        populator.addScript(new ClassPathResource("scripts/PasswordReset/db/schema.sql"));
        populator.addScript(new ClassPathResource("scripts/CryptographicFailures/db/schema.sql"));
        populator.addScript(new ClassPathResource("scripts/SessionManagement/db/schema.sql"));
        populator.addScript(new ClassPathResource("scripts/SessionManagement/db/data.sql"));
        populator.setSeparator(";");

        DataSourceInitializer initializer = new DataSourceInitializer();
        initializer.setDataSource(adminDataSource);
        initializer.setDatabasePopulator(populator);
        return initializer;
    }

    @Bean
    @Lazy
    @ConfigurationProperties("spring.datasource.application")
    public DataSourceProperties applicationDataSourceProperties() {
        return new DataSourceProperties();
    }

    @Bean
    @Lazy
    @DependsOn("adminDataSourceInitializer")
    @ConfigurationProperties("spring.datasource.application.configuration")
    public DataSource applicationDataSource(
            @Qualifier("applicationDataSourceProperties")
                    DataSourceProperties applicationDataSourceProperties) {
        return applicationDataSourceProperties
                .initializeDataSourceBuilder()
                .type(HikariDataSource.class)
                .build();
    }

    @Bean
    @Lazy
    public JdbcTemplate applicationJdbcTemplate(
            @Qualifier("applicationDataSource") DataSource applicationDataSource) {
        return new JdbcTemplate(applicationDataSource);
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Fixed: this used to be -1 (unlimited), which meant the resource-consumption DoS this
    // path is meant to defend against (LEVEL_9's UNCONTROLLED_RESOURCE_CONSUMPTION challenge)
    // could never actually be stopped by an application-level size check alone - the multipart
    // resolver would already have fully buffered/spooled an arbitrarily large request body to
    // memory/disk before the controller method (and its file.getSize() check) ever runs. Bound
    // it at the same 10MB ceiling enforced in UnrestrictedFileUpload#getVulnerablePayloadLevel9
    // so oversized uploads are rejected during parsing instead of only after being persisted.
    private static final long MAX_UPLOAD_SIZE_OVERRIDE_PATH_BYTES = 10L * 1024 * 1024;

    /**
     * Customized MultipartFilter bean disables default max upload size for multipart files and
     * their overall requests, for select paths. See {@link
     * UnrestrictedFileUpload#getVulnerablePayloadLevel10()} for usage.
     */
    @Bean
    @Order(0)
    public MultipartFilter multipartFilter() {
        class MaxUploadSizeOverrideMultipartFilter extends MultipartFilter {
            @Override
            protected MultipartResolver lookupMultipartResolver(HttpServletRequest request) {
                if (MAX_FILE_UPLOAD_SIZE_OVERRIDE_PATHS.contains(request.getServletPath())) {
                    CommonsMultipartResolver multipart = new CommonsMultipartResolver();
                    multipart.setMaxUploadSize(MAX_UPLOAD_SIZE_OVERRIDE_PATH_BYTES);
                    multipart.setMaxUploadSizePerFile(MAX_UPLOAD_SIZE_OVERRIDE_PATH_BYTES);
                    return multipart;
                } else {
                    // returns default implementation
                    return lookupMultipartResolver();
                }
            }
        }
        ;
        return new MaxUploadSizeOverrideMultipartFilter();
    }

    /**
     * Sends framing protection on every response, not only on the JSON answers the clickjacking
     * levels' controller methods produce.
     *
     * <p>A clickjacking attack frames whatever a victim's browser actually renders, and the level
     * pages themselves are plain HTML/JS served straight out of {@code static/} by the default
     * resource handler - no controller in this application ever touches them. Setting {@code
     * X-Frame-Options}/{@code Content-Security-Policy} only on the API JSON response therefore left
     * the page the victim is tricked into visiting (and everything else served by this app) fully
     * embeddable. This filter runs before that resource handler and adds the headers to every
     * response so the whole application - not just one JSON endpoint - refuses to be framed.
     * {@code DENY} is used rather than {@code SAMEORIGIN} because a same-origin attacker page is
     * already enough to mount a UI-redress/overlay attack.
     */
    @Bean
    @Order(1)
    public OncePerRequestFilter framingProtectionFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(
                    HttpServletRequest request,
                    HttpServletResponse response,
                    FilterChain filterChain)
                    throws ServletException, IOException {
                // The clickjacking controller sets these headers itself (with level-specific
                // values for the levels that demonstrate a particular header configuration), and
                // headers set here are appended rather than replacing what the handler sets.
                // Browsers ignore a header entirely once it appears twice, which would silently
                // disable the very protection those levels set out to demonstrate. Only paths the
                // controller does not own get the header from this filter.
                String path = request.getServletPath();
                if (path == null || !path.startsWith(CLICKJACKING_CONTROLLER_PATH)) {
                    response.setHeader("X-Frame-Options", "DENY");
                    response.setHeader("Content-Security-Policy", "frame-ancestors 'none'");
                }
                filterChain.doFilter(request, response);
            }
        };
    }
}
