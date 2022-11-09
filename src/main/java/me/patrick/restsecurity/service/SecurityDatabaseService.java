package me.patrick.restsecurity.service;

import lombok.RequiredArgsConstructor;
import me.patrick.restsecurity.model.UserModel;
import me.patrick.restsecurity.repository.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class SecurityDatabaseService  implements UserDetailsService {

    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) {
        UserModel userEntity = userRepository.findByUsername(username); // retornar usuario pelo username
        if (userEntity == null) {
            throw new UsernameNotFoundException(username);
        }
        // Válidar caracteristicas de segurança
        Set<GrantedAuthority> authorities = new HashSet<>();

        userEntity.getRoles().forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
        UserDetails user = new User(userEntity.getUsername(),
                userEntity.getPassword(),
                authorities);
        return user;
    }
}