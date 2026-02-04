package ru.kata.spring.boot_security.demo.service;

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

@Service
@Transactional
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserService(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public void saveUser(User user) {
        String encodedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);

        validateUser(user);

        userRepository.save(user);
    }

    @Transactional
    public void updateUser(Long id, User updatedUserData, List<Long> roleIds) {
        User existingUser = userRepository.findWithRolesById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        existingUser.setName(updatedUserData.getName());
        existingUser.setSurname(updatedUserData.getSurname());
        existingUser.setEmail(updatedUserData.getEmail());

        String newPassword = updatedUserData.getPassword();
        if (newPassword != null && !newPassword.isEmpty() &&
                !newPassword.startsWith("$2a$")) {
            existingUser.setPassword(passwordEncoder.encode(newPassword));
        }

        updateUserRoles(existingUser, roleIds);

        userRepository.save(existingUser);
    }

    @Transactional
    public void updateUserRoles(User user, List<Long> roleIds) {
        user.getRoles().clear();

        roleIds.forEach(roleId -> {
            Role role = roleRepository.findById(roleId)
                    .orElseThrow(() -> new RuntimeException("Role not found: " + roleId));
            user.addRole(role);
        });
    }

    @Transactional
    public void deleteUser(Long id) {

        userRepository.deleteById(id);
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
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
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
            throw new IllegalArgumentException("Email is required");
        }
        if (user.getPassword() == null || user.getPassword().isEmpty()) {
            throw new IllegalArgumentException("Password is required");
        }
    }

    @PostConstruct
    public void init() {
        initDefaultUsers();
    }
}
