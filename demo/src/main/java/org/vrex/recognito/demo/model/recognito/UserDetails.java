package org.vrex.recognito.demo.model.recognito;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;

@JsonInclude(JsonInclude.Include.NON_NULL)
@AllArgsConstructor
@NoArgsConstructor
@Data
public class UserDetails implements Serializable {

    private String username;
    private String email;
    private String role;
    private String appUUID;
    private String appName;
    private String version;
    private LocalDateTime onboardedOn;
    private LocalDateTime updatedOn;
    private boolean resourcesEnabled;


}
