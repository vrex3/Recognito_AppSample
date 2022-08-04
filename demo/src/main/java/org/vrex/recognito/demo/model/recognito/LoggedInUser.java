package org.vrex.recognito.demo.model.recognito;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.web.client.RestTemplate;

import java.io.Serializable;

@JsonInclude(JsonInclude.Include.NON_NULL)
@AllArgsConstructor
@NoArgsConstructor
@Data
public class LoggedInUser implements Serializable {

    private UserDetails userDetails;
    private String token;

    private RestTemplate restTemplate;
    private String jsessionID;


}
