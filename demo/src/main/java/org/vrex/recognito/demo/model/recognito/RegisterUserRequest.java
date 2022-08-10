package org.vrex.recognito.demo.model.recognito;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@JsonInclude(JsonInclude.Include.NON_NULL)
@AllArgsConstructor
@NoArgsConstructor
@Data
public class RegisterUserRequest implements Serializable {

    private String username;
    private String email;
    private String role;
    private String appIdentifier;
    private String appInvite;
}
