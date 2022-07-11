package bg.softuni.pathfinder.config;

import bg.softuni.pathfinder.repository.UserRepository;
import bg.softuni.pathfinder.service.PathfinderUserDetailsService;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.PathResource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class PathfinderSecurityConfiguration {

    private UserRepository userRepository;

    public PathfinderSecurityConfiguration(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        //grants access to all users to the
        // static resource folder
        httpSecurity.authorizeRequests()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                //opens to home login and
                // register to all users
                .antMatchers("/").permitAll()
                .antMatchers("/users" +
                "/login", "/users/register").anonymous()
                .and()
                .formLogin()
                .loginPage("/users/login")
                .usernameParameter("username")
                .passwordParameter("password")
                .defaultSuccessUrl("/")
                .failureForwardUrl("/users" +
                        "/login?error=true")
                .and()
                .csrf().disable();

        //build the configuration and adds it
        // to the spring context so Pring can
        // undertand it
        return httpSecurity.build();
    }

    @Bean

    public PasswordEncoder passwordEncoder() {

        return new Pbkdf2PasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new PathfinderUserDetailsService(userRepository);
    }
}
