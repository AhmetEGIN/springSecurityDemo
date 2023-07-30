package com.egin.springSecurityDemo.auth;

import com.egin.springSecurityDemo.user.Role;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.lang.annotation.Documented;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Schema(
        name = "Register Request",
        description = "Kullanıcıların kayıt olabilmesi için gereke field'ları içerir."
)
public class RegisterRequest {

    private String firstname;
    private String lastname;
    private String email;
    private String password;

    private Role role;

}
