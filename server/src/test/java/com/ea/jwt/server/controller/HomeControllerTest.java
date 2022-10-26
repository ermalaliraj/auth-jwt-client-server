package com.ea.jwt.server.controller;

import com.ea.jwt.server.config.SecurityConfig;
import com.ea.jwt.server.dto.JsonTokenResponse;
import com.ea.jwt.server.service.TokenService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest({HomeController.class, AuthController.class})
@Import({SecurityConfig.class, TokenService.class})
public class HomeControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    void rootWhenUnAuthenticatedThen401() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rootWhenAuthenticatedThenSayHello() throws Exception {
        MvcResult result = mockMvc.perform(post("/token")
                                    .with(httpBasic("ermal", "ermal")))
                .andExpect(status().isOk())
                .andReturn();

        String response = result.getResponse().getContentAsString();
        JsonTokenResponse tokenResponse = new ObjectMapper()
                .disable(FAIL_ON_UNKNOWN_PROPERTIES)
                .readValue(response, JsonTokenResponse.class);

        mockMvc.perform(get("/")
                            .header("Authorization", "Bearer " + tokenResponse.getAccessToken() ))
            .andExpect(content().string("Hello JWT! User: ermal"));

    }

    @Test
    @WithMockUser
    void rootWithMockUserStatusIsOk() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isOk());
    }

}
