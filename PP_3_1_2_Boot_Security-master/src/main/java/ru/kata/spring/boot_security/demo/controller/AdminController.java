package ru.kata.spring.boot_security.demo.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.service.UserService;

import java.util.List;

@Controller
@RequestMapping("/admin")
public class AdminController {

    private final UserService userService;
    private final Logger logger = LoggerFactory.getLogger(AdminController.class);

    @Autowired
    public AdminController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    public String adminPage(Model model) {
        List<User> users = userService.getAllUsersWithRoles();
        model.addAttribute("users", users);
        model.addAttribute("newUser", new User());
        model.addAttribute("allRoles", userService.getAllRoles());

        return "admin";
    }

    @PostMapping("/add")
    public String addUser(@ModelAttribute("newUser") User user,
                          @RequestParam("roles") List<Long> roleIds) {
        roleIds.forEach(roleId -> userService.getRoleById(roleId).ifPresent(user::addRole));

        userService.saveUser(user);

        return "redirect:/admin";
    }

    @PostMapping("/update")
    public String updateUser(@RequestParam("id") Long id,
                             @RequestParam("name") String name,
                             @RequestParam("surname") String surname,
                             @RequestParam("email") String email,
                             @RequestParam(value = "password", required = false) String password,
                             @RequestParam("roles") List<Long> roleIds,
                             Model model) {

        if (email == null || email.isBlank()) {
            model.addAttribute("error", "Email обязателен");
            model.addAttribute("users", userService.getAllUsersWithRoles());
            model.addAttribute("allRoles", userService.getAllRoles());
            return "admin";
        }

        User updatedUser = new User(name, surname, email, password);
        userService.updateUser(id, updatedUser, roleIds);
        logger.info("Обновлен пользователь с id={}", id);

        return "redirect:/admin";
    }

    @PostMapping("/delete")
    public String deleteUser(@RequestParam("id") Long id) {
        userService.deleteUser(id);

        return "redirect:/admin";
    }
}
