package bg.softuni.pathfinder.service;

import bg.softuni.pathfinder.model.User;
import bg.softuni.pathfinder.model.dto.UserRegistrationDTO;
import bg.softuni.pathfinder.repository.UserRepository;
import org.hibernate.usertype.UserVersionType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {

    private UserRepository userRepository;

    private PasswordEncoder passwordEncoder;

    @Autowired
    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }


    public void register(UserRegistrationDTO registrationDTO) {
        if (!registrationDTO.getPassword().equals(registrationDTO.getConfirmPassword())) {
            throw new RuntimeException("passwords.match");
        }

        Optional<User> byEmail = this.userRepository.findByEmail(registrationDTO.getEmail());

        if (byEmail.isPresent()) {
            throw new RuntimeException("email.used");
        }

        User user = new User(
            registrationDTO.getUsername(),
            passwordEncoder.encode(registrationDTO.getPassword()),
            registrationDTO.getEmail(),
            registrationDTO.getFullname(),
            registrationDTO.getAge()
        );

        this.userRepository.save(user);
    }
}
