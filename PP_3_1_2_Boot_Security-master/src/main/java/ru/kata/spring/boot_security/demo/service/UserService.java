package ru.kata.spring.boot_security.demo.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.repository.RoleRepository;
import ru.kata.spring.boot_security.demo.repository.UserRepository;

import javax.annotation.PostConstruct;
import java.util.List;
import java.util.Optional;

@Service
@Transactional
public class UserService implements UserDetailsService {

    private final Logger logger = LoggerFactory.getLogger(UserService.class);
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public void saveUser(User user) {

        if (user.getEmail() == null || user.getEmail().isBlank()) {
            throw new IllegalArgumentException("Необходим email");
        }

        if (userRepository.existsByEmail(user.getEmail())) {
            throw new IllegalArgumentException("Email уже используется");
        }

        if (user.getPassword() == null || user.getPassword().isEmpty()) {
            throw new IllegalArgumentException("Необходим пароль");
        }
        String encodedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);

        validateUser(user);

        userRepository.save(user);
        logger.info("Сохраненный пользователь: {}", user.getEmail());
    }

    @Transactional
    public void updateUser(Long id, User updatedUserData, List<Long> roleIds) {
        User existingUser = userRepository.findWithRolesById(id)
                .orElseThrow(() -> new RuntimeException("Пользователь не найден"));

        existingUser.setName(updatedUserData.getName());
        existingUser.setSurname(updatedUserData.getSurname());
        existingUser.setEmail(updatedUserData.getEmail());

        String newPassword = updatedUserData.getPassword();
        if (newPassword != null && !newPassword.isEmpty() &&
                !newPassword.startsWith("$2a$") && !newPassword.startsWith("$2b$")) {
            existingUser.setPassword(passwordEncoder.encode(newPassword));
        }

        updateUserRoles(existingUser, roleIds);

        userRepository.save(existingUser);
        logger.info("Обновленный пользователь id={}", id);
    }

    @Transactional
    public void updateUserRoles(User user, List<Long> roleIds) {
        user.getRoles().clear();

        if (roleIds != null) {
            roleIds.forEach(roleId -> {
                Role role = roleRepository.findById(roleId)
                        .orElseThrow(() -> new RuntimeException("Роль не найдена: " + roleId));
                user.addRole(role);
            });
        }
    }

    @Transactional
    public void deleteUser(Long id) {
        userRepository.deleteById(id);
        logger.info("Удаленный пользователь id={}", id);
    }

    @Transactional(readOnly = true)
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Transactional(readOnly = true)
    public List<User> getAllUsersWithRoles() {
        return userRepository.findAll();
    }

    @Transactional(readOnly = true)
    public User getUserById(Long id) {
        return userRepository.findById(id).orElse(null);
    }

    @Transactional(readOnly = true)
    public User getUserByIdWithRoles(Long id) {
        return userRepository.findWithRolesById(id).orElse(null);
    }

    @Transactional(readOnly = true)
    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email).orElse(null);
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Пользователь не найден"));
    }


    @Transactional(readOnly = true)
    public Optional<Role> getRoleById(Long id) {
        return roleRepository.findById(id);
    }

    @Transactional(readOnly = true)
    public List<Role> getAllRoles() {
        return roleRepository.findAll();
    }

    @Transactional
    public void initDefaultUsers() {
        if (roleRepository.count() == 0) {
            Role adminRole = new Role("ROLE_ADMIN");
            Role userRole = new Role("ROLE_USER");
            roleRepository.save(adminRole);
            roleRepository.save(userRole);

            User admin = new User("Admin", "Adminov", "admin@mail.ru", "admin");
            admin.addRole(adminRole);
            admin.addRole(userRole);
            saveUser(admin);

            User user = new User("User", "Userov", "user@mail.ru", "user");
            user.addRole(userRole);
            saveUser(user);
        }
    }

    private void validateUser(User user) {
        if (user.getEmail() == null || user.getEmail().isEmpty()) {
            throw new IllegalArgumentException("Необходим email");
        }
    }

    @PostConstruct
    public void init() {
        initDefaultUsers();
    }
}
