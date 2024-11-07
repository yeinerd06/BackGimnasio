package co.edu.ufps.gimnasio.controller;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import co.edu.ufps.gimnasio.model.dto.LoginDTO;
import co.edu.ufps.gimnasio.model.entity.Usuario;
import co.edu.ufps.gimnasio.repository.UsuarioReporitory;
import co.edu.ufps.gimnasio.security.JWTAuthResonseDTO;
import co.edu.ufps.gimnasio.security.JwtTokenProvider;





@RestController
@RequestMapping("/user")
@CrossOrigin
public class LoginController {
	@Autowired
	 AuthenticationManager authenticationManager;
	
	@Autowired
	private UsuarioReporitory usuarioRepositorio;
	
	
	
	@Autowired
	private JwtTokenProvider jwtTokenProvider;
	
	@PostMapping("/login")
public ResponseEntity<?> authenticateUser(@RequestBody LoginDTO loginDTO) {

    Map<String, String> response = new HashMap<>();
    
    Optional<Usuario> usuario = usuarioRepositorio.findByEmail(loginDTO.getEmail());
    if (!usuario.isPresent()) {
        response.put("message", "Usuario no encontrado");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    if (!usuario.get().isEstado()) {
        response.put("message", "Usuario no está activo");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    try {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginDTO.getEmail(), loginDTO.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Genera el token
        String token = jwtTokenProvider.generarToken(authentication);
        HttpHeaders headers = new HttpHeaders();
        headers.add("Access-Control-Expose-Headers", "Authorization, Bearer");
        headers.add("Authorization", "Bearer " + token);

        return ResponseEntity.ok().headers(headers).build();
    } catch (Exception e) {
        // Devuelve un mensaje de error si la autenticación falla
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                             .body(Collections.singletonMap("message", "Contraseña o Email incorrecto"));
    }
}

	/*
	@PostMapping("/registrar")
	public ResponseEntity<?> registrarUsuario(@RequestBody RegistroDTO registroDTO){
		if(usuarioRepositorio.existsByUsername(registroDTO.getUsername())) {
			return new ResponseEntity<>("Ese nombre de usuario ya existe",HttpStatus.BAD_REQUEST);
		}
		
		if(usuarioRepositorio.existsByEmail(registroDTO.getEmail())) {
			return new ResponseEntity<>("Ese email de usuario ya existe",HttpStatus.BAD_REQUEST);
		}
		
		Usuario usuario = new Usuario();
		usuario.setNombre(registroDTO.getNombre());
		usuario.setUsername(registroDTO.getUsername());
		usuario.setEmail(registroDTO.getEmail());
		usuario.setPassword(passwordEncoder.encode(registroDTO.getPassword()));
		
		Rol roles = rolRepositorio.findByNombre("ROLE_ADMIN").get();
		usuario.setRoles(Collections.singleton(roles));
		
		usuarioRepositorio.save(usuario);
		return new ResponseEntity<>("Usuario registrado exitosamente",HttpStatus.OK);
	}
	*/
}
