package com.thebestadso.innovation.service;

import java.util.Optional;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.thebestadso.innovation.dto.HttpGlobalResponseDTO;
import com.thebestadso.innovation.dto.LoginRequestDTO;
import com.thebestadso.innovation.dto.LoginResponseDTO;
import com.thebestadso.innovation.dto.RegisterRequestDTO;
import com.thebestadso.innovation.dto.UserDTO;
import com.thebestadso.innovation.entity.Roles;
import com.thebestadso.innovation.entity.Users;
import com.thebestadso.innovation.repository.RolRepository;
import com.thebestadso.innovation.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    /**
     * Repositorio de jwt
     */
    private final JwtService jwtService;

    /**
     * Repositorio de usuario
     */
    private final UserRepository userRepository;

    /**
     * Repositorio de rol
     */
    private final RolRepository rolRepository;

    /**
     * Encriptación
     */
    private final PasswordEncoder passwordEncoder;

    /**
     * Método para iniciar sesión
     *
     * @param request usuario y contraseña
     * @return jwt si las credenciales son correctas, de lo contrario data null
     */
    public HttpGlobalResponseDTO<LoginResponseDTO> login(LoginRequestDTO request) {
        HttpGlobalResponseDTO<LoginResponseDTO> response = new HttpGlobalResponseDTO<>();

        if (request.getUsername() == null || request.getPassword() == null) {
            response.setMessage("Usuario y contraseña son obligatorios");
            return response;
        }

        Optional<Users> userFound = userRepository.findByUsername(request.getUsername());

        // Mismo mensaje si falla el usuario o la clave, para no dar pistas
        if (userFound.isEmpty()
                || !passwordEncoder.matches(request.getPassword(), userFound.get().getPassword())) {
            response.setMessage("Usuario o contraseña incorrectos");
            return response;
        }

        Users user = userFound.get();
        String jwt = jwtService.generateToken(user.getId(), user.getUsername(), user.getRolId());

        LoginResponseDTO login = new LoginResponseDTO();
        login.setJwt(jwt);

        response.setMessage("Login exitoso");
        response.setData(login);
        return response;
    }

    /**
     * Método para refresco del token
     *
     * @param token
     * @return
     * @throws Exception
     */
    public HttpGlobalResponseDTO<LoginResponseDTO> refreshToken(String token) throws Exception {
        HttpGlobalResponseDTO<LoginResponseDTO> response = new HttpGlobalResponseDTO<>();
        LoginResponseDTO refresh = new LoginResponseDTO();

        String jwt = jwtService.refreshToken(token);

        refresh.setJwt(jwt);
        response.setMessage("Token refrescado correctamente");
        response.setData(refresh);

        return response;
    }

    public HttpGlobalResponseDTO<UserDTO> register(RegisterRequestDTO request) {
        HttpGlobalResponseDTO<UserDTO> response = new HttpGlobalResponseDTO<>();
        UserDTO userDTO = new UserDTO();

        Optional<Users> userFound = userRepository.findByUsername(request.getUsername());
        Optional<Users> emailFound = userRepository.findByEmail(request.getEmail());
        Optional<Roles> rol = rolRepository.findById(request.getRolId());

        if (userFound.isPresent()) {
            response.setMessage("Nombre de usuario en uso");
            return response;
        }


        if (emailFound.isPresent()) {
            response.setMessage("correo en uso");
            return response;
        }


        if (rol.isEmpty()) {
            response.setMessage("Rol no existe");
            return response;
        }

        Users user = new Users();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setRolId(request.getRolId());
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        userRepository.save(user);

        userDTO.setId(user.getId());
        userDTO.setUsername(user.getUsername());
        userDTO.setEmail(user.getEmail());
        userDTO.setRolId(user.getRolId());

        response.setMessage("usuario registrado correctamente");
        response.setData(userDTO);
        return response;
    }
}